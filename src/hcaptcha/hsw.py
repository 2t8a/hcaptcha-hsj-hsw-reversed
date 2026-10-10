"""Direct, accurate HSW master-key extraction.

No candidate-guessing. Each step is structurally determined from the
WASM binary + deobf source:

  1. Run deobf.py — get the encrypt and decrypt magic numbers from
     hsw.js source (the JS-side wrappers `encrypt_req_data` and
     `decrypt_resp_data` both call `vc(MAGIC, ...)` with a literal
     magic int).

  2. In the WASM, walk the dispatcher (func vc) instruction stream.
     Find each `i32.const MAGIC ; i32.eq ; if` triple — the function
     called inside that `if` block is the per-direction implementation.

  3. The implementation function (encrypt_impl, decrypt_impl) opens
     a stack frame and calls the key schedule. Find the `call N`
     instruction whose target N is a (i32,i32)->() function with
     fixslice32 mask constants — that N is the key-schedule function.

  4. The key-schedule function's body starts with i32.add / local.tee
     loads — the FIRST 8 `call M` invocations with `i32.const 0,
     local.get 1, ..., call M` are the master-key word loads, where
     M is the XOR-deobfuscation helper. The pointer base is the
     function's second arg (local 1).

  5. Patch the key schedule's entry to: for i in 0..7, call
     M(0, local 1 + i*4), and store the returned i32 to a fixed
     scratch region. Add a sentinel write.

  6. Load the patched WASM into the bundle, run encrypt and decrypt
     (the decrypt fails with our dummy bytes, but the key schedule
     fires first). Read both scratch regions — those are the encrypt
     and decrypt master keys.

  7. Verify the encrypt key by AES-256-GCM round-trip.

All function indices are derived from the WASM's structure, never
hardcoded. The MAGIC numbers come from the deobf source. Both rotate
per build; this works on every build.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import requests


from .tools.wasm_disasm import WasmModule, _load_wasm
from .tools.wasm_writer import ModuleWriter, encode_uleb, encode_sleb
from .tools.js_runtime import JsRuntime
from .log import Logger
from . import version as _v


# Two independent scratch slots so we can capture both directions in
# a single sandbox run.
SCRATCH_ENC      = 32_000
SENTINEL_ENC     = 32_040
SCRATCH_DEC      = 32_100
SENTINEL_DEC     = 32_140
SENTINEL_VAL_ENC = -889275714   # 0xCAFEBABE (signed)
SENTINEL_VAL_DEC = -559038737   # 0xDEADBEEF (signed)


# ---------------------------------------------------------------------------
# Structural identification — no heuristics, no guessing.
# ---------------------------------------------------------------------------
def _read_magics_from_deobf(version: str) -> dict:
    """Run deobf.py on the live hsw.js, read the encrypt + decrypt
    magic numbers from the deobf source's wbg wrappers."""
    from .tools.deobf import fetch_and_deobfuscate
    deobf_path = fetch_and_deobfuscate("hsw.js", version, quiet=True)
    src = open(deobf_path, "r", encoding="utf-8").read()

    # The dispatcher export name rotates per build (vc -> uc -> ...), so match
    # any `obj.method(<magic>` call. The magic is a large number; the only other
    # call before it is the allocator `gc(-16)` (tiny arg), so requiring a 5+
    # digit first arg picks the dispatcher call regardless of its rotated name.
    #
    # Two export shapes exist across builds:
    #   a) `encrypt_req_data: function (...) { ... obj.method(MAGIC ...`
    #   b) `["encrypt_req_data"]: u3,`  with `var u3 = ... ? function(a){...}`
    def _magic_for(marker: str):
        m = re.search(
            r'\[?"?' + re.escape(marker) +
            r'"?\]?\s*:\s*(?:function\s*\([^)]*\)\s*\{|([A-Za-z_$][\w$]*))', src)
        if not m:
            return None
        if m.group(1):
            fn = m.group(1)
            fm = (re.search(r'function\s+' + re.escape(fn) + r'\s*\([^)]*\)\s*\{', src)
                  or re.search(r'\b' + re.escape(fn) +
                               r'\s*=\s*[\s\S]{0,200}?function\s*\([^)]*\)\s*\{', src))
            body = src[fm.end():fm.end() + 1200] if fm else ''
        else:
            body = src[m.end():m.end() + 1200]
        mm = re.search(r'\b\w+\.\w+\((-?\d{5,})', body)
        return int(mm.group(1)) if mm else None

    enc_magic = _magic_for('encrypt_req_data')
    dec_magic = _magic_for('decrypt_resp_data')
    if enc_magic is None or dec_magic is None:
        raise RuntimeError(
            "could not find encrypt/decrypt magics in deobf source")
    return {
        "encrypt_magic": enc_magic,
        "decrypt_magic": dec_magic,
    }


def _find_dispatcher_func(mod: WasmModule) -> int:
    """The dispatcher `vc` is the largest exported function with a
    multi-i32-arg, no-result signature, and a body full of magic-number
    comparisons (lots of `i32.const ; i32.eq ; if` triples)."""
    n_imports = sum(1 for im in mod.imports if im["kind"] == "func")
    for ex in mod.exports:
        if ex["kind"] != "func": continue
        if ex["name"] != "vc": continue
        return ex["idx"]
    # Fall back: locate by signature shape
    for ex in mod.exports:
        if ex["kind"] != "func": continue
        f = next((f for f in mod.functions if f["func_idx"] == ex["idx"]), None)
        if f is None: continue
        params, results = mod.types[f["type_idx"]]
        # vc is the only export with >=8 args
        if len(params) >= 8 and len(results) == 0:
            return ex["idx"]
    raise RuntimeError("vc dispatcher not found")


def _find_dispatcher_for_magics(mod: WasmModule, magics: dict) -> int:
    """Locate the dispatcher function by finding which function's body
    contains the encrypt/decrypt magic constants. The export name rotates
    across builds (vc -> Pc -> ...) and the arity changes (6 args now),
    so keying on the magic literals is the only stable anchor."""
    targets = {m & 0xffffffff for m in magics.values()}
    best = None
    best_count = 0
    for f in mod.functions:
        try:
            instrs = mod.decode_function(f["func_idx"])
        except Exception:
            continue
        cnt = sum(1 for n, ops, _, _ in instrs
                  if n == "i32.const" and ops
                  and (ops[0] & 0xffffffff) in targets)
        if cnt > best_count:
            best_count = cnt
            best = f["func_idx"]
    if best is None or best_count == 0:
        raise RuntimeError("dispatcher containing the magics not found")
    return best


def _find_key_schedule_for_magic(mod: WasmModule, vc_idx: int,
                                  magic: int) -> int:
    """Walk vc's instructions; find the `i32.const MAGIC ; i32.eq ; if`
    triple, then within that if-block find the `call N` whose target N
    is a (i32,i32)->() function with strong fixslice32 mask presence.
    That N is the key-schedule function for this direction.
    """
    from .tools.wasm_disasm import find_fixslice_functions
    fixslice_with_size = {}
    for s, fi, masks in find_fixslice_functions(mod, top_n=40):
        # Filter to canonical AES fixslice masks
        canonical = {0x55555555, 0x33333333, 0x0F0F0F0F, 0xF0F0F0F0}
        overlap = canonical & set(masks.keys())
        if len(overlap) >= 3:
            f = next((f for f in mod.functions if f["func_idx"] == fi), None)
            if f is None: continue
            params, results = mod.types[f["type_idx"]]
            if params == ["i32", "i32"] and results == []:
                fixslice_with_size[fi] = f["code_end"] - f["code_start"]

    instrs = mod.decode_function(vc_idx)
    target_mag = magic & 0xffffffff if magic >= 0 else (magic + (1 << 32))
    for i in range(len(instrs) - 2):
        n, ops, _, _ = instrs[i]
        if n == "i32.const" and ops and (ops[0] & 0xffffffff) == target_mag:
            n1, _, _, _ = instrs[i+1]
            n2, _, _, _ = instrs[i+2]
            if n1 == "i32.eq" and n2 == "if":
                depth = 1
                j = i + 3
                roots = []
                while j < len(instrs):
                    nj, opsj, _, _ = instrs[j]
                    if nj in ("block", "loop", "if"): depth += 1
                    elif nj == "end":
                        depth -= 1
                        if depth == 0: break
                    elif nj == "call" and opsj:
                        # Direct hit — key schedule called inline.
                        if opsj[0] in fixslice_with_size:
                            return opsj[0]
                        roots.append(opsj[0])
                    j += 1
                # Newer builds nest the key schedule one or more calls
                # deeper (dispatcher -> direction wrapper -> crypto fn ->
                # key schedule). Breadth-first search from the magic
                # branch's direct callees and return the first fixslice32
                # (i32,i32)->() function reachable. The caller verifies
                # the recovered key by AEAD round-trip, so a wrong pick
                # is rejected rather than silently returned.
                seen = set()
                frontier = list(roots)
                for _ in range(6):
                    nxt = []
                    for fi in frontier:
                        if fi in seen or fi not in {f["func_idx"] for f in mod.functions}:
                            continue
                        seen.add(fi)
                        if fi in fixslice_with_size:
                            return fi
                        try:
                            for nnn, ooo, _, _ in mod.decode_function(fi):
                                if nnn == "call" and ooo:
                                    nxt.append(ooo[0])
                        except Exception:
                            pass
                    if not nxt:
                        break
                    frontier = nxt
    raise RuntimeError(
        f"no key-schedule call found inside magic-{magic} if-block in vc")


def _find_deobf_helper(mod: WasmModule, key_sched: int) -> int:
    """The XOR-deobf helper is the (i32,i32)->i32 callee that's invoked
    most often from the key schedule (typically 100+ calls)."""
    from collections import Counter
    counts = Counter()
    for n, ops, _, _ in mod.decode_function(key_sched):
        if n == "call" and ops: counts[ops[0]] += 1
    for callee, _ in counts.most_common(10):
        f = next((f for f in mod.functions if f["func_idx"] == callee),
                 None)
        if f is None: continue
        params, results = mod.types[f["type_idx"]]
        if params == ["i32", "i32"] and results == ["i32"]:
            return callee
    raise RuntimeError(
        f"no XOR-deobf helper found inside key schedule {key_sched}")


# ---------------------------------------------------------------------------
# Injection bytecode
# ---------------------------------------------------------------------------
def _build_injection(deobf_helper_idx: int,
                     scratch_base: int, sentinel_addr: int,
                     sentinel_val: int) -> bytes:
    parts = []
    for i in range(8):
        parts.append(b"\x41" + encode_sleb(scratch_base + i*4))
        parts.append(b"\x41" + encode_sleb(0))
        parts.append(b"\x20\x01")
        if i > 0:
            parts.append(b"\x41" + encode_sleb(i * 4))
            parts.append(b"\x6a")
        parts.append(b"\x10" + encode_uleb(deobf_helper_idx))
        parts.append(b"\x36\x02\x00")
    parts.append(b"\x41" + encode_sleb(sentinel_addr))
    parts.append(b"\x41" + encode_sleb(sentinel_val))
    parts.append(b"\x36\x02\x00")
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Sandbox harness
# ---------------------------------------------------------------------------
_HOOK_JS = r"""
(function() {
  function _b64ToU8(s) {
    if (typeof Buffer !== 'undefined') {
      const b = Buffer.from(s, 'base64');
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    }
    const bin = atob(s);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  function _install(t) {
    if (!t || !t.WebAssembly) return;
    const origInstantiate = t.WebAssembly.instantiate;
    t.WebAssembly.instantiate = function(buf, imp) {
      let useBuf = buf;
      if (buf && buf.byteLength != null) {
        useBuf = _b64ToU8(globalThis.__patched_wasm_b64);
      }
      return origInstantiate.call(this, useBuf, imp).then(r => {
        const inst = r.instance || r;
        if (inst && inst.exports) {
          globalThis.__hsw_exports = inst.exports;
          for (const k of Object.keys(inst.exports)) {
            const v = inst.exports[k];
            if (v && typeof v === 'object' && v.buffer && typeof v.grow === 'function') {
              globalThis.__hsw_memory = v;
              break;
            }
          }
        }
        return r;
      });
    };
    if (t.WebAssembly.instantiateStreaming) {
      t.WebAssembly.instantiateStreaming = async function(source, imp) {
        const resp = await source;
        const buf = await resp.arrayBuffer();
        return t.WebAssembly.instantiate(buf, imp);
      };
    }
  }
  _install(globalThis);
  _install(typeof window !== 'undefined' ? window : null);
})();
"""


def _new_runtime() -> JsRuntime:
    return JsRuntime()


# ---------------------------------------------------------------------------
# Top-level: extract both keys directly + verifiably
# ---------------------------------------------------------------------------
class HSWKeyFetcher:
    """Direct extraction of both HSW master AES-256 keys (encrypt + decrypt).

    No candidate-guessing: each function is identified by structural
    role traceable from the deobf'd source's magic numbers.
    """
    def __init__(self, version: str | None = None, log: Logger | None = None):
        self.log = log or Logger()
        self.version = version or _v.latest_version()

    def fetch(self) -> dict:
        t0 = time.time()

        # 1. Magic numbers from deobf source
        magics = _read_magics_from_deobf(self.version)
        self.log.info(f"magics: enc={magics['encrypt_magic']} "
                      f"dec={magics['decrypt_magic']}",
                      start=t0, end=time.time())

        # 2. Load WASM, locate dispatcher
        from .hsw_bridge import HSWAnalyzer
        info = HSWAnalyzer(self.version, log=self.log).analyze()
        orig_wasm = bytes.fromhex(info["wasm_bytes_hex"])
        mod = WasmModule(orig_wasm)
        vc_idx = _find_dispatcher_for_magics(mod, magics)
        self.log.info(f"dispatcher = func {vc_idx}",
                      start=t0, end=time.time())

        # 3. From each magic, locate the key-schedule call directly
        enc_ks  = _find_key_schedule_for_magic(mod, vc_idx, magics["encrypt_magic"])
        dec_ks  = _find_key_schedule_for_magic(mod, vc_idx, magics["decrypt_magic"])
        deobf_e = _find_deobf_helper(mod, enc_ks)
        deobf_d = _find_deobf_helper(mod, dec_ks)
        self.log.info(f"encrypt: key_sched={enc_ks} deobf={deobf_e}",
                      start=t0, end=time.time())
        self.log.info(f"decrypt: key_sched={dec_ks} deobf={deobf_d}",
                      start=t0, end=time.time())

        # 4. Build a single patched WASM that instruments the key
        # schedule. Same function is called for both directions (with
        # different key pointers), so we patch once and capture each
        # direction's key in separate sandbox steps.
        writer = ModuleWriter(mod)
        writer.code.splice_code(enc_ks, 0, n_replace=0,
            new_bytes=_build_injection(deobf_e, SCRATCH_ENC,
                                        SENTINEL_ENC, SENTINEL_VAL_ENC))
        # If decrypt uses a DIFFERENT key schedule function, patch that too:
        if dec_ks != enc_ks:
            writer.code.splice_code(dec_ks, 0, n_replace=0,
                new_bytes=_build_injection(deobf_d, SCRATCH_DEC,
                                            SENTINEL_DEC, SENTINEL_VAL_DEC))

        t_i32_to_i32 = next((i for i, (p, r) in enumerate(mod.types)
                             if p == ["i32"] and r == ["i32"]), None)
        if t_i32_to_i32 is None:
            t_i32_to_i32 = writer.add_type(["i32"], ["i32"])
        t_i32i32_to_void = next((i for i, (p, r) in enumerate(mod.types)
                                  if p == ["i32", "i32"] and r == []), None)
        if t_i32i32_to_void is None:
            t_i32i32_to_void = writer.add_type(["i32", "i32"], [])
        writer.add_function(t_i32_to_i32, [],
                            bytes([0x20, 0x00, 0x28, 0x02, 0x00, 0x0b]),
                            export_name="__peek32")
        writer.add_function(t_i32i32_to_void, [],
                            bytes([0x20, 0x00, 0x20, 0x01, 0x36, 0x02, 0x00, 0x0b]),
                            export_name="__poke32")
        patched = writer.emit()
        self.log.info(f"patched wasm: {len(patched)}B "
                      f"(+{len(patched)-len(orig_wasm)}B)",
                      start=t0, end=time.time())

        # 5. Sandbox: substitute patched WASM, run encrypt + decrypt
        rt = _new_runtime()
        rt.eval(f"globalThis.__patched_wasm_b64 = '{base64.b64encode(patched).decode()}';")
        rt.eval(_HOOK_JS)
        r = requests.get(_v.asset_url(self.version, "hsw.js"))
        r.encoding = "utf-8"
        rt.eval(r.text, suppress=True)

        # If encrypt and decrypt share the same key schedule, reading
        # between the calls captures each direction separately.
        # If they use different functions, both fire to their own scratch.
        same_ks = (enc_ks == dec_ks)
        rt.eval(rf"""
            globalThis.__done = 0;
            globalThis.__same_ks = {str(same_ks).lower()};
            (async () => {{
              try {{
                await window.hsw(1, new Uint8Array(0));  // warmup
                const exp = globalThis.__hsw_exports;
                for (let i = 0; i < 44; i += 4) {{
                  exp.__poke32({SCRATCH_ENC} + i, 0);
                  exp.__poke32({SCRATCH_DEC} + i, 0);
                }}
                // Drive encrypt — key schedule writes encrypt key to SCRATCH_ENC
                const pt = new Uint8Array(32);
                for (let i = 0; i < 32; i++) pt[i] = (i*7+3) & 0xff;
                const o = await window.hsw(1, pt);
                const u8 = o instanceof Uint8Array ? o : new Uint8Array(o);
                let h=''; for (let i=0;i<u8.length;i++) h += u8[i].toString(16).padStart(2,'0');
                globalThis.__blob = h;
                globalThis.__pt = Array.from(pt);

                // Read encrypt key NOW, before decrypt overwrites it
                const mem = new Uint8Array(globalThis.__hsw_memory.buffer);
                let kE=''; for (let i=0; i<32; i++)
                  kE += mem[{SCRATCH_ENC} + i].toString(16).padStart(2,'0');
                globalThis.__key_enc = kE;

                // If both directions share the same key schedule, the
                // decrypt path overwrites SCRATCH_ENC. So COPY enc bytes
                // to SCRATCH_DEC first (as a save), then trigger decrypt
                // which will overwrite SCRATCH_ENC with decrypt key.
                if (globalThis.__same_ks) {{
                  for (let i = 0; i < 32; i += 4) {{
                    exp.__poke32({SCRATCH_DEC} + i, exp.__peek32({SCRATCH_ENC} + i));
                  }}
                  // Now zero SCRATCH_ENC so we see if decrypt actually fired
                  for (let i = 0; i < 32; i += 4) {{
                    exp.__poke32({SCRATCH_ENC} + i, 0);
                  }}
                }}
                try {{ await window.hsw(0, new Uint8Array(32)); }} catch (_) {{}}

                let kD=''; for (let i=0; i<32; i++) {{
                  const slot = globalThis.__same_ks ? {SCRATCH_ENC} : {SCRATCH_DEC};
                  kD += mem[slot + i].toString(16).padStart(2,'0');
                }}
                globalThis.__key_dec = kD;
                globalThis.__sentinel_enc = exp.__peek32({SENTINEL_ENC});
                globalThis.__sentinel_dec = exp.__peek32({SENTINEL_DEC});
              }} catch (e) {{ globalThis.__err = String(e); }}
              globalThis.__done = 1;
            }})();
        """, suppress=True)

        for _ in range(80):
            if rt.eval("globalThis.__done"): break
            time.sleep(0.25)

        err      = rt.eval("globalThis.__err || ''")
        sent_e   = rt.eval("globalThis.__sentinel_enc") or 0
        sent_d   = rt.eval("globalThis.__sentinel_dec") or 0
        key_enc  = rt.eval("globalThis.__key_enc") or ""
        key_dec  = rt.eval("globalThis.__key_dec") or ""
        blob_hex = rt.eval("globalThis.__blob") or ""
        pt_list  = json.loads(rt.eval("JSON.stringify(globalThis.__pt || [])") or "[]")

        if err:
            self.log.info(f"runtime err (continuing if keys captured): {err}",
                          start=t0, end=time.time())

        if sent_e not in (SENTINEL_VAL_ENC, SENTINEL_VAL_ENC + (1<<32)):
            raise RuntimeError(
                f"encrypt key-schedule patch never fired (sentinel={sent_e})")
        # When enc_ks == dec_ks, both directions share the same patched
        # function. The 'enc' injection writes for BOTH directions
        # (to SCRATCH_ENC + sentinel_enc), so sentinel_dec stays unset
        # but the decrypt key DID overwrite SCRATCH_ENC after we saved
        # the encrypt key. No warning needed.
        if not same_ks and sent_d not in (SENTINEL_VAL_DEC, SENTINEL_VAL_DEC + (1<<32)):
            raise RuntimeError(
                f"decrypt key-schedule patch never fired (sentinel={sent_d})")

        enc_master = bytes.fromhex(key_enc)
        dec_master = bytes.fromhex(key_dec) if key_dec and any(c!='0' for c in key_dec) else None
        blob = bytes.fromhex(blob_hex)
        pt   = bytes(pt_list)

        # 6. Verify encrypt key by round-trip
        from Crypto.Cipher import AES
        iv  = blob[:12]
        ct  = blob[12:12+len(pt)]
        tag = blob[12+len(pt):12+len(pt)+16]
        cipher = AES.new(enc_master, AES.MODE_GCM, nonce=iv)
        try:
            decoded = cipher.decrypt_and_verify(ct, tag)
        except ValueError as e:
            self.log.info(
                f"encrypt-key verify failed: captured={enc_master.hex()} "
                f"blob={blob.hex()}",
                start=t0, end=time.time())
            raise RuntimeError(
                f"encrypt key verification failed: {e} "
                f"(captured {enc_master.hex()})")
        if decoded != pt:
            raise RuntimeError("encrypt key verification failed: pt mismatch")
        self.log.info("encrypt key verified OK (AES-256-GCM round-trip)",
                      start=t0, end=time.time())

        return {
            "version":       self.version,
            "encrypt_key":   enc_master.hex(),
            "decrypt_key":   dec_master.hex() if dec_master else None,
            "cipher":        "AES-256-GCM",
            "wire_format":   "iv(12) || ct(N) || tag(16)",
            "aad":           "",
            "verified":      True,
            "encrypt_magic": magics["encrypt_magic"],
            "decrypt_magic": magics["decrypt_magic"],
            "dispatcher":    vc_idx,
            "encrypt_ks":    enc_ks,
            "decrypt_ks":    dec_ks,
        }


if __name__ == "__main__":
    out = HSWKeyFetcher().fetch()
    print(json.dumps(out, indent=2))
    with open("hsw_master_keys.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nsaved -> hsw_master_keys.json")
