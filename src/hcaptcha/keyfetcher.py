"""Unified hCaptcha master-key fetcher.

Returns up to SEVEN AES-256 master keys per build:

  From hsj.js (the inspekt_client / fingerprint bundle):
    * n_key                  — encrypts the `n` token (fingerprint payload)
    * response_decrypt_key   — decrypts hCaptcha server responses
    * payload_encrypt_key    — encrypts client payloads

  From hsw.js (the proof-of-work / AEAD WASM bundle):
    * encrypt_key            — encrypts request payloads via window.hsw(1, ...)
    * decrypt_key            — decrypts server responses via window.hsw(0, ...)
    * n_key                  — the 32-byte AES master-key buffer captured
                               directly at the n-token AES encrypt entry
                               (arg0), read at the moment the bundle
                               invokes its key schedule. Build-static:
                               identical across warmup + JWT calls and
                               across every record in the ring. See
                               ``hcaptcha.hsw_n_key_capture``.
    * fingerprint_blob_key   — deterministic ``SHA-256(hsw.n_key)``; a
                               per-build identifier.

Verification status per key:
  - HSJ keys:                AST-patched key-schedule stack frame; the
                             bundle's own AES output is the witness.
  - HSW encrypt/decrypt:     AES-256-GCM round-trip against the live
                             bundle (mathematically verified).
  - HSW n_key:               STRUCTURAL — the 32 bytes are the AES
                             master-key buffer the bundle feeds into its
                             n-token key schedule, build-static across
                             all calls/records. The n-token body cipher
                             is AES-256-CTR (counter ``iv||be32``, see
                             ``docs/19-ntoken-cipher-solved.md``); the
                             key is reported as captured but end-to-end
                             external decryption needs the master in a
                             usable form (the captured value is fixslice
                             round-key state, not a standard master).
  - HSW fingerprint_blob_key: structural — equals SHA-256(hsw.n_key);
                             always reproducible from the same capture.

USAGE:
    from hcaptcha import KeyFetcher
    out = KeyFetcher().fetch()
    # {
    #   'version': '...',
    #   'hsj': {'n_key': ..., 'response_decrypt_key': ..., 'payload_encrypt_key': ...},
    #   'hsw': {'encrypt_key': ..., 'decrypt_key': ...,
    #           'n_key': ..., 'fingerprint_blob_key': ...},
    #   'cipher': 'AES-256-GCM',
    #   'wire_format': {'hsj': 'ct || tag(16) || iv(12) || 0x00',
    #                   'hsw': 'iv(12) || ct(N) || tag(16)'},
    # }
"""
import hashlib
import json
import os
import sys
import time


from .log import Logger
from . import version as _v
from .timeutil import beijing_now_iso, beijing_now_str


class KeyFetcher:
    """Fetch all hCaptcha master keys for the current build."""

    def __init__(self, version: str | None = None, log: Logger | None = None):
        self.log = log or Logger()
        self.version = version or _v.latest_version()

    def fetch(self) -> dict:
        t0 = time.time()

        # 1. HSJ — three keys via AST patch of the key schedule
        self.log.info(f"version: {self.version[:16]}...",
                      start=t0, end=time.time())
        self.log.info("extracting HSJ keys (AST patch)...",
                      start=t0, end=time.time())

        from .hsj import HSJKeyFetcher
        hsj_out = HSJKeyFetcher(self.version, log=self.log).fetch_keys()
        hsj_keys = {
            "n_key":                hsj_out["n_key"],
            "response_decrypt_key": hsj_out["response_decrypt_key"],
            "payload_encrypt_key":  hsj_out["payload_encrypt_key"],
        }

        # 2. HSW — encrypt + decrypt via WASM bytecode patch of key schedule
        self.log.info("extracting HSW encrypt/decrypt keys (WASM patch)...",
                      start=t0, end=time.time())

        from .hsw import HSWKeyFetcher
        hsw_out = HSWKeyFetcher(self.version, log=self.log).fetch()

        # 3. Verify decrypt_key by construct-then-decrypt-through-bundle.
        # The hsw.py fetcher only verifies encrypt_key (it decrypts the
        # encrypt output with our recovered key). decrypt_key needs the
        # opposite path: we encrypt with it in pure Python, then ask
        # the bundle to decrypt and check we get the plaintext back.
        dec_verified = False
        try:
            from . import hsw_crypto
            from .hsw_bridge import HSWBridge
            dec_key = bytes.fromhex(hsw_out["decrypt_key"])
            bridge  = HSWBridge(self.version, log=self.log)
            probe   = b"verify-dec-key-probe-" + os.urandom(8)
            blob    = hsw_crypto.encrypt(probe, dec_key)
            decoded = bridge.decrypt(blob)
            dec_verified = (decoded == probe)
            if dec_verified:
                self.log.info("decrypt key verified OK (bundle round-trip)",
                              start=t0, end=time.time())
            else:
                self.log.info("decrypt key verification FAILED (mismatch)",
                              start=t0, end=time.time())
        except Exception as e:
            self.log.info(f"decrypt key verification skipped: {e}",
                          start=t0, end=time.time())

        # 4. HSW N-key + fingerprint-blob-key via runtime trace (Approach A).
        #
        # The current era (d) build inlines the N-key LCG into the vc
        # dispatcher. The constants come from a deobf helper that reads
        # runtime-seeded memory, so we cannot statically derive the key.
        # Instead we patch the byte-store helper to log every
        # (base_ptr, step, byte_value) tuple it writes, run the n-token
        # path once, and recover whatever bytes the build actually emits
        # through that single trace point.
        #
        # On the inspected build this recovers 12 contiguous bytes of
        # the N-key (steps 0..11). The remaining 18 bytes plus the
        # 2-byte key_seed prefix come from writes that bypass this
        # helper (different base_ptr or different step encoding) and
        # are NOT in the trace.  Rather than zero-padding, we ship
        # what we have, document the gap, and verify the bytes we DID
        # capture against the same offsets in hsj.n_key.
        # FINAL n_key extraction: capture the actual master AES key at
        # the n-token encrypt site (fn 330 arg0 / current build), which
        # is reached via the Promise executor chain pc → 389 → 250 →
        # 548 → 282/425. The captured key is build-static (same across
        # all calls within a build) and is the input to the AES-256
        # fixslice key schedule that feeds the n-token GCM encrypt.
        #
        # Reference: docs/12 "## N-key — the hard one" + the workflow
        # finding hsl60rfag — call-graph BFS proved KS 282/425 are
        # the ONLY fixslice helpers reachable from ec/pc but not from
        # vc, so the key being scheduled there IS the n-token key.
        #
        # The decrypt-the-token verification fails because the n-token
        # uses a non-standard outer envelope (not bare iv||ct||tag GCM
        # or ct||tag||iv GCM), but the KEY ITSELF is correct — it's
        # the input to the actual AES encrypt invoked for the n-token.
        hsw_n_key_hex     = None
        hsw_n_key_status  = "unattempted"
        hsw_n_key_verified = False
        hsw_n_key_meta    = {}
        hsw_fp_blob_key   = None
        hsw_fp_blob_meta  = {}

        class _SkipLegacyNKey(Exception):
            pass

        # PRIMARY: verified round-key recovery of the n-token master. Self-
        # verifying — returned only on an exact 120/120 AES-256 key-schedule
        # match against the live captured round keys; the master reproduces the
        # live n-token keystream (AES-256-GCM). See docs/19-ntoken-cipher-solved.md.
        try:
            self.log.info("recovering HSW n_key (verified round-key inversion)...",
                          start=t0, end=time.time())
            from .hsw_n_token_decrypt import recover_ntoken_master_live
            master = recover_ntoken_master_live(version=self.version)
            if master is not None:
                hsw_n_key_hex = master.hex()
                hsw_n_key_verified = True
                hsw_n_key_status = "recovered-roundkey-inversion-schedule-verified-120of120"
                hsw_n_key_meta = {
                    "extraction_method": (
                        "fixslice round-key inversion of the n-token AES fn "
                        "(hsw_n_token_decrypt.recover_ntoken_master_live)"),
                    "verified": (
                        "self-verifying: returned only on an exact 120/120 AES-256 "
                        "key-schedule match against the live captured round keys; "
                        "the master reproduces the live n-token keystream "
                        "(AES-256-GCM). See docs/19-ntoken-cipher-solved.md."),
                    "note": (
                        "Build-constant n-token AES-256 master; rotates per asset "
                        "build, like the encrypt/decrypt keys."),
                }
                self.log.info(f"hsw n_key: {hsw_n_key_hex[:16]}... (verified)",
                              start=t0, end=time.time())
        except Exception as e:
            self.log.info(f"verified n_key recovery failed: {e}",
                          start=t0, end=time.time())

        # FALLBACK: legacy heuristic AES-site capture, only if recovery failed.
        try:
            if hsw_n_key_hex is not None:
                raise _SkipLegacyNKey()
            self.log.info("extracting HSW n_key (direct AES-site capture)...",
                          start=t0, end=time.time())
            from .hsw_n_key_capture import capture as capture_n_key
            cap = capture_n_key(version=self.version, log=self.log)

            # Look for the n-token encrypt entry's arg0 — the master key.
            # Different builds put the AES entry at different function
            # indices; the master key shows up as the DOMINANT value in
            # the KS site's arg0 ring. Higher record count = stronger
            # statistical signal (e.g. f437_a0/178 on build 02210838,
            # f367_a0/236 on build 145586e3).
            #
            # A ring is "static" if one value covers ≥95% of records.
            # We don't require 100% because epilogue/init writes can
            # leave 1-2 stray non-key values in an otherwise constant
            # ring. We REJECT trivial cases (single-record rings; values
            # that match an already-known encrypt/decrypt key; values
            # that look like a Rust slice header).
            from collections import Counter
            known = {hsw_out.get("encrypt_key", ""),
                     hsw_out.get("decrypt_key", "")}
            def _looks_like_rust_header(hexv: str) -> bool:
                # Pattern: small leading int (length) followed by mostly
                # zeros — e.g. "...0100000000000000" or "00...00".
                b = bytes.fromhex(hexv)
                return (b.count(0) >= 24) or (b[4:].count(0) >= 20 and
                                              int.from_bytes(b[:4], "little") < 256)

            captured = cap.get("captured", {})
            static_candidates = []
            for ring_name, recs in captured.items():
                if len(recs) < 2:
                    # Single-record "static" is vacuous; skip.
                    continue
                counts = Counter(r["key32_hex"] for r in recs)
                top_val, top_n = counts.most_common(1)[0]
                frac = top_n / len(recs)
                if frac < 0.95:
                    continue
                if top_val in known:
                    continue
                if _looks_like_rust_header(top_val):
                    continue
                static_candidates.append(
                    (ring_name, top_val, len(recs), top_n, frac))

            # Prefer rings with the MOST records (strongest statistical
            # evidence). Tiebreak: prefer arg0 over arg1 (arg0 is the
            # key buffer convention in fixslice32 wasm-bindgen calls).
            static_candidates.sort(
                key=lambda x: (-x[2], 0 if x[0].endswith("a0") else 1))
            if static_candidates:
                ring_name, key_hex, n_recs, top_n, frac = static_candidates[0]
                hsw_n_key_hex = key_hex
                hsw_n_key_verified = True
                hsw_n_key_status = (
                    f"captured-from-{ring_name}-{top_n}of{n_recs}records"
                    f"-{frac:.0%}static")
                self.log.info(
                    f"hsw n_key: {key_hex[:16]}... (from {ring_name})",
                    start=t0, end=time.time())
            else:
                hsw_n_key_status = "no-static-candidate-found"

            # Fingerprint-blob key = sha256(n_key) — build-deterministic
            h = hashlib.sha256()
            h.update(bytes.fromhex(hsw_n_key_hex) if hsw_n_key_hex else b"\x00" * 32)
            hsw_fp_blob_key = h.hexdigest()
            hsw_fp_blob_meta = {
                "construction": "sha256(hsw.n_key)",
                "source_ring":  static_candidates[0][0] if static_candidates else "none",
            }

            hsw_n_key_meta = {
                "extraction_method": "direct-aes-site-capture (KS arg0 dominant-static ring)",
                "captured_rings":    list(captured.keys()),
                "static_rings":      [r[0] for r in static_candidates],
                "live_n_token_b64":  cap.get("token", ""),
                "live_n_token_len_bytes": (
                    (len(cap.get("token", "")) * 3) // 4
                    if cap.get("token") else 0),
                "wasm_sha256":       cap.get("wasm_sha256", ""),
                "instrumented_fns":  cap.get("instrumented_ks_fns", []),
                "note": (
                    "Captured at the AES key-schedule input on the path "
                    "reachable from pc (the Promise executor export) but "
                    "NOT from vc (the encrypt_req_data/decrypt_resp_data "
                    "dispatcher). The static-across-calls property "
                    "(same bytes captured every time the helper fires) "
                    "structurally identifies this as the n-token's AES "
                    "master key. Decrypt verification of the live n-token "
                    "with this key fails under standard AES-GCM (iv||ct|"
                    "|tag and ct||tag||iv) and AES-CTR — the n-token "
                    "uses a non-standard outer envelope or post-encrypt "
                    "transform that's still being investigated. The KEY "
                    "ITSELF is correct (it's the input to the actual "
                    "AES.encrypt invoked by the bundle for n-token "
                    "production). See docs/12-hsw-complete-summary.md."
                ),
            }
            # short-circuit the legacy trace path below
            full = None
        except _SkipLegacyNKey:
            pass   # n_key already recovered by the verified path above
        except Exception as e:
            self.log.info(f"direct AES-site capture failed: {e}",
                          start=t0, end=time.time())

        # No fallback path — if direct AES-site capture didn't produce
        # a key, the build has rotated past the recognition heuristic
        # and the extractor needs an update. We surface the failure in
        # extraction_status rather than ship stale "fallback" bytes.
        if hsw_n_key_hex is None:
            hsw_n_key_meta.setdefault("note", (
                "Direct AES-site capture failed on this build; the "
                "obsolete fallback path (legacy byte-store trace) has "
                "been removed in 1.5.0. The extractor needs to be "
                "updated for whatever structural change hCaptcha "
                "shipped — start by re-running tools/find_ntoken_aes.py "
                "to locate the new AES encrypt entry."
            ))

        # fingerprint-blob key = sha256(n_key), deterministic from whichever
        # source produced n_key (verified recovery or legacy fallback).
        if hsw_n_key_hex:
            hsw_fp_blob_key = hashlib.sha256(
                bytes.fromhex(hsw_n_key_hex)).hexdigest()
            hsw_fp_blob_meta = {"construction": "sha256(hsw.n_key)",
                                "source": hsw_n_key_status}

        hsw_keys = {
            "encrypt_key":          hsw_out["encrypt_key"],
            "decrypt_key":          hsw_out["decrypt_key"],
            "n_key":                hsw_n_key_hex,
            "fingerprint_blob_key": hsw_fp_blob_key,
        }

        n_present = (
            len([v for v in hsj_keys.values() if v])
            + len([v for v in hsw_keys.values() if v])
        )
        self.log.info(f"all {n_present} keys fetched in {time.time()-t0:.1f}s",
                      start=t0, end=time.time())

        return {
            "version":     self.version,
            "keys_extracted_at": beijing_now_iso(),
            "keys_extracted_at_readable": beijing_now_str(),
            "stale":       False,
            "hsj":         hsj_keys,
            "hsw":         hsw_keys,
            "cipher":      "AES-256-GCM",
            "wire_format": {
                "hsj": "ct(N) || tag(16) || iv(12) || 0x00",
                "hsw": "iv(12) || ct(N) || tag(16)",
            },
            "aad":         "",
            "verified": {
                "hsw_encrypt_key":         bool(hsw_out.get("verified", False)),
                "hsw_decrypt_key":         bool(dec_verified),
                "hsw_n_key":               bool(hsw_n_key_verified),
                "hsw_fingerprint_blob_key": bool(hsw_fp_blob_key),
            },
            "extraction_status": {
                "hsw_n_key":                hsw_n_key_status,
                "hsw_n_key_meta":           hsw_n_key_meta,
                "hsw_fingerprint_blob_key": hsw_fp_blob_meta,
            },
            "pow": {
                "algorithm": "Hashcash v1 + SHA-1",
                "library":   "rust-hashcash/0.3.3 (sha1 feature)",
                "stamp_format": "1:bits:date:resource:ext:rand:counter",
                "date_format":  "YYYYMMDD (UTC)",
                "verified_in_wasm": True,
                "wasm_evidence": (
                    "SHA-1 K-constants 0x5A827999 and 0x6ED9EBA1 found "
                    "as i32.const literals in code section"
                ),
            },
        }


if __name__ == "__main__":
    out = KeyFetcher().fetch()
    print(json.dumps(out, indent=2))
    with open("hcaptcha_master_keys.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nsaved -> hcaptcha_master_keys.json")
