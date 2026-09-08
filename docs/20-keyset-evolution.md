# hsw crypto-surface evolution — the n-token + fingerprint-blob + PoW addition

`docs/10` tracks the **WASM dispatch** architecture (how `hsw.js` exports
its crypto functions — eras a→d). This note tracks the orthogonal axis:
the **crypto surface itself** — which keys each build ships and whether a
proof-of-work stage is present. It is derived purely from the captured
[`data/archive/`](../data/archive) snapshots, not from any single build.

## What the archive shows

Across **48 archived builds** there are exactly **two structural
signatures**. The AES cipher (`AES-256-GCM`, empty AAD) and the wire
formats are identical in both; what differs is the `hsw` key-set and the
presence of a PoW stage.

| Shape | Builds | `hsj` keys | `hsw` keys | PoW |
| --- | --- | --- | --- | --- |
| **Current** | 45 | `n_key`, `response_decrypt_key`, `payload_encrypt_key` | `encrypt_key`, `decrypt_key`, **`n_key`**, **`fingerprint_blob_key`** | **Hashcash v1 + SHA-1** (`rust-hashcash/0.3.3`) |
| **Legacy** | 3 | (same) | `encrypt_key`, `decrypt_key` | none |

So the newer generation added, to the `hsw` bundle specifically:

1. **`hsw.n_key`** — the AES-256 master for the **n-token** cipher. It is
   recovered by fixslice round-key inversion and self-verifies against the
   live keystream (120/120 key-schedule match); see
   [`docs/19-ntoken-cipher-solved.md`](19-ntoken-cipher-solved.md).
2. **`hsw.fingerprint_blob_key`** — not an independent secret but a
   **derivation**: `sha256(hsw.n_key)`. Recovering `n_key` yields it for
   free.
3. **A Hashcash-v1 proof-of-work** over SHA-1
   (`1:bits:date:resource:ext:rand:counter`, date `YYYYMMDD` UTC),
   confirmed in-WASM by the SHA-1 round constants
   `0x5A827999` / `0x6ED9EBA1` present as `i32.const` literals.

The legacy 3-build shape (encrypt/decrypt only, no PoW) predates that
hardening and lines up with the earlier dispatch eras in `docs/10`
(pre-`vc`, before the n-token/PoW work landed).

## What did *not* change

- **Cipher:** `AES-256-GCM` with empty AAD, all 48 builds.
- **Wire format:** `hsj = ct‖tag(16)‖iv(12)‖0x00`, `hsw = iv(12)‖ct‖tag(16)`, unchanged.
- **`hsj` key-set:** `n_key` / `response_decrypt_key` / `payload_encrypt_key`, present in every build.

## Key rotation

The AES masters are **build-constant but rotate every build** — across the
48 snapshots there are **46 distinct `hsw.n_key` values** (effectively one
per build). This is why the repo re-extracts on every new asset hash
(the `refresh-keys` workflow) rather than pinning a static key: the
extraction *method* is stable, the *values* are not.

## Takeaway for solver implementations

If you are targeting the current hCaptcha, you must handle **four** `hsw`
keys plus the SHA-1 Hashcash stage — an implementation that only pulls
`encrypt_key`/`decrypt_key` (the legacy shape) will fail the n-token and
PoW checks on every current build. Re-derive per asset hash; do not cache
keys across builds.
