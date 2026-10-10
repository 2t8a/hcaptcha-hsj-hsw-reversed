# 2026 bundle rebuild — extraction status

This note records the state of the extractors against the **2026 hCaptcha
bundle rebuild** (first seen on build `bd19e571…`, hsj.js ≈ 2.5 MB,
hsw.js ≈ 1.3 MB). The rebuild is a full obfuscator/architecture change,
not a routine rotation.

## What changed

| | pre-2026 | 2026 rebuild |
|---|---|---|
| String decoders | `void 0 === NAME.prop` marker | `NAME = function(arg){ … if (void 0 !== CACHE[arg]) return CACHE[arg]; … }` |
| hsj.js size | ~657 KB | ~2.5 MB |
| hsj key schedule | standalone fn, `- 480` stack frame, raw key pointer | inlined into `UG`/`bbv`; key assembled from XOR constants |
| hsw.js export shape | `encrypt_req_data: function (…)` | `["encrypt_req_data"]: fn` |
| hsw WASM dispatcher | export `vc` (≥8 args) | export `Pc` (6 args), found by magic literals |
| hsw WASM key schedule | called directly in the magic `if`-block | nested: `Pc → 427/963 → 336/771 → fixslice` |

## Fixed and verified

1. **`tools/deobf.js` decoder detection.** Now recognises the memoised
   decoder shape in addition to the legacy marker. Result on the rebuild:
   - `hsj.js`: detects `aYO` (and the legacy `window` false positive),
     decodes **891 strings**, extracts 7 blobs.
   - `hsw.js`: detects `aok`, decodes **414 strings**, extracts 16 blobs
     (the 864 764-byte WASM).
2. **`hsw.py` magic extraction.** Handles the `["encrypt_req_data"]: fn`
   export shape and resolves the referenced function. Verified on the
   rebuild: `encrypt_magic` / `decrypt_magic` are read correctly.
3. **`hsw.py` dispatcher location.** New `_find_dispatcher_for_magics`
   finds the dispatcher by the function that actually contains the magic
   constants (export name/arity rotates). Verified: dispatcher = func 1027.
4. **`hsw.py` key-schedule search.** `_find_key_schedule_for_magic` now
   breadth-first walks the magic branch's call graph and returns the first
   reachable fixslice32 `(i32,i32)->()` function; the AEAD round-trip then
   rejects a wrong pick.
5. **`hsj.py` failure mode.** Raises an explicit, actionable error instead
   of a bare `IndexError` when the key-schedule pattern is absent.

## Remaining work (precise pointers)

### HSJ — three keys
Oracle: `hsj(1, pt)` returns `iv(12) || ct(len(pt)) || tag(16)`, AES-256-GCM,
empty AAD. (Validated on the pre-rebuild bundle with its known key.)

The master key is materialised inside the inlined fixslice key schedule in
the raw functions `UG` (encrypt) / `bbv` (decrypt). The fixslice transform
`t24`/`aoO` is **not** the standard RustCrypto `bitslice` (`tools/fixslice_inverse.py`
does not invert it), so the captured `3c0ff033…` / `b0e090fd…` values are not
the key. The key is assembled from XOR constants (see the deobf source
around the `v12()` function) and never appears as a plain 32-byte window in
the asm.js heap at the key-schedule call.

Next step: port the deobf `t24` bit transform to Python (or enumerate its
output over the captured 32-byte inputs) and/or trace the XOR-constant
assembly to the buffer it writes, then confirm with the GCM oracle.

### HSW — two keys
Oracle: `HSWBridge.encrypt(pt)` returns `iv(12) || ct(len(pt)) || tag(16)`,
AES-256-GCM, empty AAD.

The dispatcher `Pc` (func 1027) routes:
```
Pc(encrypt_magic) → func 427 → func 336 → fixslice {799, 540, 291}
Pc(decrypt_magic) → func 963 → func 771 → fixslice {…}
```
`fn 799` is the first reachable `(i32,i32)->()` fixslice function, but its
`arg1` is a small-integer structure, **not** the key (capturing it yields
`24 00 00 00 99 00 00 00 …` and fails the GCM tag check). The 2026 WASM uses
a segmented 320-byte-page heap; `fn 951` / `fn 545` are the read accessors.

Next step: identify the function that receives the master-key pointer (likely
`fn 291` or `fn 540`, 3-arg fixslice) and the argument that points at the key;
or instrument `local.set` sites inside the key schedule to capture the key
words directly.

## How to run the analysis

```bash
python - <<'PY'
from hcaptcha.tools.deobf import fetch_and_deobfuscate
from hcaptcha import version as _v
v = _v.latest_version()
print(fetch_and_deobfuscate("hsj.js", v, out_dir="deobfuscated"))
print(fetch_and_deobfuscate("hsw.js", v, out_dir="deobfuscated"))
PY
```

The refresh workflow (`refresh-keys.yml`) keeps the last known-good keys and
files an `auto-repair` issue when extraction fails, so this gap is visible
and non-destructive until the extractors are updated.
