"""Live-bundle black-box crypto + decryption CLI.

Unlike ``KeyFetcher`` (which tries to materialise the AES master keys), this
module never needs the raw key: it loads the *current* hsj.js / hsw.js in a
JS sandbox and drives their own ``encrypt`` / ``decrypt`` entry points. It is
the fully-automatic path for decrypting hCaptcha traffic when the bundle has
been restructured too heavily to extract keys from.

Public API
----------
    from hcaptcha.live import LiveDecryptor
    d = LiveDecryptor()                 # loads the latest bundles
    pt = d.hsj_decrypt(ciphertext)      # server response -> plaintext
    pt = d.hsw_decrypt(ciphertext)
    ct = d.hsj_encrypt(plaintext)
    tok = d.hsj_n_token(sitekey_json)   # fingerprint n-token
    tok = d.hsw_solve(req_jwt)          # proof-of-work token

CLI
---
    python -m hcaptcha.live fetch
    python -m hcaptcha.live selftest
    python -m hcaptcha.live decrypt --scheme hsw --in ct.bin --out pt.bin
    python -m hcaptcha.live encrypt --scheme hsj --in pt.bin
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import time

import requests

from .log import Logger
from .tools.js_runtime import JsRuntime
from . import version as _v
from .timeutil import beijing_now_iso, beijing_now_str


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _wait(rt: JsRuntime, flag: str, seconds: float = 25.0) -> None:
    for _ in range(int(seconds / 0.2)):
        if rt.eval(f"globalThis.{flag}"):
            return
        time.sleep(0.2)
    raise TimeoutError(f"live bundle: {flag} timed out")


def _to_js_bytes(data: bytes) -> str:
    return ",".join(str(b) for b in data)


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# hsj
# ---------------------------------------------------------------------------
class LiveHSJ:
    """hsj.js driven as a black-box encrypt/decrypt service."""

    def __init__(self, version: str | None = None, log: Logger | None = None,
                 source: str | None = None):
        self.log = log or Logger()
        self.version = version or _v.latest_version()
        self.runtime = JsRuntime()
        if source is None:
            r = requests.get(_v.asset_url(self.version, "hsj.js"), timeout=60)
            r.encoding = "utf-8"
            source = r.text
        # warm-up: the bundle installs `window.hsj` synchronously; just load it.
        self.runtime.eval(source, suppress=True)
        if self.runtime.eval("typeof window !== 'undefined' && typeof window.hsj") != "function":
            # some builds attach to globalThis
            if self.runtime.eval("typeof hsj") != "function":
                raise RuntimeError("hsj bundle did not expose `hsj`")

    def _await_expr(self, expr: str, seconds: float = 25.0):
        self.runtime.eval(
            f"""
            globalThis.__lr=null; globalThis.__le=null; globalThis.__ld=0;
            (async()=>{{ try {{
                let o = await ({expr});
                if (o && o.buffer && !(o instanceof Uint8Array))
                    o = new Uint8Array(o.buffer, o.byteOffset||0, o.byteLength||o.length);
                if (o instanceof Uint8Array) {{
                    let h=''; for (let i=0;i<o.length;i++) h+=o[i].toString(16).padStart(2,'0');
                    globalThis.__lr = {{kind:'hex', v:h}};
                }} else {{
                    globalThis.__lr = {{kind:'json', v:(typeof o==='string'?o:JSON.stringify(o))}};
                }}
            }} catch(e) {{ globalThis.__le=String(e); }}
            globalThis.__ld=1; }})();
            """,
            suppress=True,
        )
        _wait(self.runtime, "__ld", seconds)
        err = self.runtime.eval("globalThis.__le || ''")
        if err:
            raise RuntimeError(f"hsj call failed: {err}")
        res = self.runtime.eval("globalThis.__lr")
        if not res:
            return None
        return bytes.fromhex(res["v"]) if res["kind"] == "hex" else res["v"]

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._await_expr(
            f"window.hsj(1, new Uint8Array([{_to_js_bytes(plaintext)}]))")

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._await_expr(
            f"window.hsj(0, new Uint8Array([{_to_js_bytes(ciphertext)}]))")

    def n_token(self, sitekey_json: str) -> str:
        tok = sitekey_json.replace("\\", "\\\\").replace("'", "\\'")
        return self._await_expr(f"window.hsj('{tok}')")

    def close(self):
        try:
            self.runtime.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ---------------------------------------------------------------------------
# hsw
# ---------------------------------------------------------------------------
class LiveHSW:
    """hsw.js driven as a black-box encrypt/decrypt/solve service."""

    def __init__(self, version: str | None = None, log: Logger | None = None,
                 source: str | None = None):
        self.log = log or Logger()
        self.version = version or _v.latest_version()
        self.runtime = JsRuntime()
        # reuse the verified capture hook so `__hsw_memory` etc. are available
        from .hsw_bridge import _install_wasm_capture, _load_hsw, _wait_done
        self._wait_done = _wait_done
        _install_wasm_capture(self.runtime)
        if source is not None:
            self.runtime.eval(source, suppress=True)
        else:
            _load_hsw(self.runtime, self.version)
        self.runtime.eval(
            r"""
            globalThis.__bridge_ready = 0;
            (async () => { try { await window.hsw(1, new Uint8Array(0)); }
                            catch (_) {} globalThis.__bridge_ready = 1; })();
            """,
            suppress=True,
        )
        self._wait_done(self.runtime, "__bridge_ready")

    def _call(self, mode: int, payload: bytes) -> bytes:
        self.runtime.eval(
            f"""
            globalThis.__r=null; globalThis.__rerr=null; globalThis.__rdone=0;
            (async() => {{ try {{
                const o = await window.hsw({mode}, new Uint8Array([{_to_js_bytes(payload)}]));
                const u8 = o instanceof Uint8Array ? o : new Uint8Array(o.buffer || o);
                let h=''; for (let i=0;i<u8.length;i++) h+=u8[i].toString(16).padStart(2,'0');
                globalThis.__r = h;
            }} catch(e) {{ globalThis.__rerr = String(e); }}
            globalThis.__rdone = 1; }})();
            """,
            suppress=True,
        )
        self._wait_done(self.runtime, "__rdone")
        err = self.runtime.eval("globalThis.__rerr || ''")
        if err:
            raise RuntimeError(f"hsw mode-{mode} failed: {err}")
        return bytes.fromhex(self.runtime.eval("globalThis.__r") or "")

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._call(1, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._call(0, ciphertext)

    def solve(self, req_jwt: str) -> str:
        tok = req_jwt.replace("\\", "\\\\").replace("'", "\\'")
        self.runtime.eval(
            f"""
            globalThis.__r=null; globalThis.__rerr=null; globalThis.__rdone=0;
            (async() => {{ try {{
                const o = await window.hsw('{tok}');
                globalThis.__r = typeof o === 'string' ? o : JSON.stringify(o);
            }} catch(e) {{ globalThis.__rerr = String(e); }}
            globalThis.__rdone = 1; }})();
            """,
            suppress=True,
        )
        self._wait_done(self.runtime, "__rdone", max_seconds=40.0)
        err = self.runtime.eval("globalThis.__rerr || ''")
        if err:
            raise RuntimeError(f"hsw solve failed: {err}")
        return self.runtime.eval("globalThis.__r") or ""

    def close(self):
        try:
            self.runtime.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ---------------------------------------------------------------------------
# facade
# ---------------------------------------------------------------------------
class LiveDecryptor:
    """Lazily boots either/both live bundles and exposes black-box crypto."""

    def __init__(self, version: str | None = None, log: Logger | None = None):
        self.version = version or _v.latest_version()
        self.log = log or Logger()
        self._hsj = None
        self._hsw = None

    @property
    def hsj(self) -> LiveHSJ:
        if self._hsj is None:
            self._hsj = LiveHSJ(self.version, self.log)
        return self._hsj

    @property
    def hsw(self) -> LiveHSW:
        if self._hsw is None:
            self._hsw = LiveHSW(self.version, self.log)
        return self._hsw

    def hsj_encrypt(self, pt: bytes) -> bytes:
        return self.hsj.encrypt(pt)

    def hsj_decrypt(self, ct: bytes) -> bytes:
        return self.hsj.decrypt(ct)

    def hsj_n_token(self, sitekey_json: str) -> str:
        return self.hsj.n_token(sitekey_json)

    def hsw_encrypt(self, pt: bytes) -> bytes:
        return self.hsw.encrypt(pt)

    def hsw_decrypt(self, ct: bytes) -> bytes:
        return self.hsw.decrypt(ct)

    def hsw_solve(self, jwt: str) -> str:
        return self.hsw.solve(jwt)

    def close(self):
        if self._hsj:
            self._hsj.close()
        if self._hsw:
            self._hsw.close()
        self._hsj = self._hsw = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ---------------------------------------------------------------------------
# cache + selftest
# ---------------------------------------------------------------------------
def fetch_and_cache(cache_dir: str = "data/live",
                    version: str | None = None) -> dict:
    """Download the current hsj.js + hsw.js into ``cache_dir`` and write a
    manifest. Returns the manifest dict."""
    version = version or _v.latest_version()
    os.makedirs(cache_dir, exist_ok=True)
    manifest = {"version": version,
                "fetched_at": int(time.time()),
                "fetched_at_beijing": beijing_now_iso(),
                "files": {}}
    for name in ("hsj.js", "hsw.js"):
        r = requests.get(_v.asset_url(version, name), timeout=90)
        r.raise_for_status()
        r.encoding = "utf-8"
        path = os.path.join(cache_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(r.text)
        manifest["files"][name] = {"path": path, "bytes": len(r.text)}
    with open(os.path.join(cache_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def selftest(version: str | None = None) -> dict:
    """Load both bundles and run an encrypt round-trip through each.

    Returns a status dict (never raises for a failed scheme — reports it)."""
    version = version or _v.latest_version()
    out = {"version": version, "checked_at": int(time.time()),
           "generated_at_beijing": beijing_now_iso(),
           "generated_at_readable": beijing_now_str(),
           "hsj": {}, "hsw": {}, "ok": False}
    try:
        hsj = LiveHSJ(version)
        ct = hsj.encrypt(b"live-selftest")
        out["hsj"] = {"ok": isinstance(ct, (bytes, bytearray)) and len(ct) > 0,
                      "ciphertext_bytes": len(ct) if ct else 0}
        hsj.close()
    except Exception as e:
        out["hsj"] = {"ok": False, "error": str(e)[:300]}
    try:
        hsw = LiveHSW(version)
        ct = hsw.encrypt(b"live-selftest")
        out["hsw"] = {"ok": isinstance(ct, (bytes, bytearray)) and len(ct) > 0,
                      "ciphertext_bytes": len(ct) if ct else 0}
        hsw.close()
    except Exception as e:
        out["hsw"] = {"ok": False, "error": str(e)[:300]}
    out["ok"] = bool(out["hsj"].get("ok") and out["hsw"].get("ok"))
    return out


def _read_input(args) -> bytes:
    if args.hex:
        return _hex_to_bytes(args.hex)
    if args.b64:
        return base64.b64decode(args.b64)
    if args.infile:
        data = open(args.infile, "rb").read()
        if args.in_encoding == "hex":
            return _hex_to_bytes(data.decode().strip())
        if args.in_encoding == "base64":
            return base64.b64decode(data.decode().strip())
        return data
    data = sys.stdin.buffer.read()
    if args.in_encoding == "hex":
        return _hex_to_bytes(data.decode().strip())
    if args.in_encoding == "base64":
        return base64.b64decode(data.decode().strip())
    return data


def _write_output(args, data: bytes) -> None:
    if getattr(args, "outfile", None):
        if getattr(args, "out_encoding", "raw") == "hex":
            open(args.outfile, "w").write(data.hex())
        else:
            open(args.outfile, "wb").write(data)
    else:
        if getattr(args, "out_encoding", "raw") == "hex":
            sys.stdout.write(data.hex() + "\n")
        else:
            try:
                sys.stdout.write(data.decode("utf-8") + "\n")
            except UnicodeDecodeError:
                sys.stdout.write(data.hex() + "\n")


def _main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hcaptcha.live",
                                description="Live hsj/hsw black-box crypto")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("fetch", help="download + cache the current bundles")
    sp.add_argument("--cache-dir", default="data/live")
    sp.add_argument("--version", default=None)

    sp = sub.add_parser("selftest", help="load both bundles and run a round-trip")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--out", default=None, help="write status JSON to this path")
    sp.add_argument("--version", default=None)

    for scheme in ("hsj", "hsw"):
        for op in ("encrypt", "decrypt"):
            sp = sub.add_parser(f"{op}-{scheme}",
                                help=f"{op} via the live {scheme} bundle")
            sp.add_argument("--hex", default=None)
            sp.add_argument("--b64", default=None)
            sp.add_argument("--in", dest="infile", default=None)
            sp.add_argument("--in-encoding", choices=["raw", "hex", "base64"],
                            default="hex")
            sp.add_argument("--out", dest="outfile", default=None)
            sp.add_argument("--out-encoding", choices=["raw", "hex"],
                            default="hex")
            sp.add_argument("--version", default=None)

    sp = sub.add_parser("n-token", help="hsj fingerprint n-token from a sitekey JSON")
    sp.add_argument("payload", help="the sitekey/data JSON string")
    sp.add_argument("--version", default=None)

    sp = sub.add_parser("solve", help="hsw proof-of-work token from a req JWT")
    sp.add_argument("jwt")
    sp.add_argument("--version", default=None)

    args = p.parse_args(argv)

    if args.cmd == "fetch":
        m = fetch_and_cache(args.cache_dir, args.version)
        print(json.dumps(m, indent=2))
        return 0
    if args.cmd == "selftest":
        st = selftest(args.version)
        if args.out:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(st, f, indent=2)
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"version {st['version']}")
            print(f"  hsj: {st['hsj']}")
            print(f"  hsw: {st['hsw']}")
            print(f"  ok : {st['ok']}")
        return 0 if st["ok"] else 1
    if args.cmd == "n-token":
        with LiveHSJ(args.version) as h:
            print(h.n_token(args.payload) or "")
        return 0
    if args.cmd == "solve":
        with LiveHSW(args.version) as h:
            print(h.solve(args.jwt) or "")
        return 0

    # encrypt-*/decrypt-*
    data = _read_input(args)
    with LiveDecryptor(args.version) as d:
        if args.cmd == "encrypt-hsj":
            out = d.hsj_encrypt(data)
        elif args.cmd == "decrypt-hsj":
            out = d.hsj_decrypt(data)
        elif args.cmd == "encrypt-hsw":
            out = d.hsw_encrypt(data)
        else:
            out = d.hsw_decrypt(data)
    if out is None:
        sys.stderr.write("call returned no result\n")
        return 1
    _write_output(args, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
