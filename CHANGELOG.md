# Changelog

Key *values* rotate per hCaptcha asset build and are refreshed automatically
by the [`refresh-keys`](.github/workflows/refresh-keys.yml) workflow. This log
records **structural findings** and doc/tooling changes, not individual key
refreshes.

## 2026-09-08

### Added
- **`docs/20-keyset-evolution.md`** — crypto-surface evolution across the
  48-build archive. The current era's `hsw` bundle carries **four** keys
  (`encrypt_key`, `decrypt_key`, `n_key`, `fingerprint_blob_key`) plus a
  **Hashcash-v1 / SHA-1 proof-of-work**; a legacy shape (3 builds) shipped only
  `encrypt_key` + `decrypt_key` with no PoW. Cipher (`AES-256-GCM`, empty AAD)
  and both wire formats are **stable across all 48 builds**; the AES masters
  are build-constant but **rotate every build** (46 distinct `hsw.n_key`
  across 48 snapshots). Complements `docs/10` (WASM dispatch eras) on the
  orthogonal crypto axis.

### Fixed
- **README:** corrected the stale Peak pricing line to the current
  **$0.35 – $1.00 / 1K** (was `$0.50 – $1.20`).
