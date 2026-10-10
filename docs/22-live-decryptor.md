# Live decryptor (black-box, no key extraction)

The 2026 hCaptcha rebuild keeps the AES master keys entirely inside the
WASM/JS binaries — they never appear as plaintext in observable memory — so
`KeyFetcher` cannot materialise them. This module takes a different route:
it loads the **current** `hsj.js` / `hsw.js` and drives their own
`encrypt` / `decrypt` entry points. Decryption is therefore fully automatic
and never needs a raw key.

## Usage

```python
from hcaptcha.live import LiveDecryptor

with LiveDecryptor() as d:                 # loads the latest bundles
    pt = d.hsj_decrypt(ciphertext)         # server response -> plaintext
    pt = d.hsw_decrypt(ciphertext)
    ct = d.hsj_encrypt(plaintext)
    ct = d.hsw_encrypt(plaintext)
    tok = d.hsj_n_token(sitekey_json)      # fingerprint n-token
    tok = d.hsw_solve(req_jwt)             # proof-of-work token
```

The first call for each scheme boots a Node + jsdom sandbox and keeps it
alive, so subsequent calls are fast. Use it as a context manager or call
`.close()` when done.

## CLI

```bash
# liveness / status
python -m hcaptcha.live selftest --json --out data/live_status.json
python -m hcaptcha.live fetch --cache-dir data/live

# decrypt a server response (hex in, hex out)
python -m hcaptcha.live decrypt-hsw --hex 3a9f... --out pt.bin --out-encoding raw
python -m hcaptcha.live decrypt-hsj --in ct.bin --in-encoding raw

# encrypt a request payload
python -m hcaptcha.live encrypt-hsj --hex 68656c6c6f

# tokens
python -m hcaptcha.live n-token '<sitekey-json>'
python -m hcaptcha.live solve '<req-jwt>'
```

Input can come from `--hex`, `--b64`, `--in <file>` or stdin. Output goes to
`--out <file>` or stdout, as raw bytes or hex.

## Automation

`.github/workflows/live-bundle.yml` runs every 10 minutes:

1. loads the current bundles and drives one encrypt through each,
2. writes `data/live_status.json` + `data/live_version.txt`,
3. commits only when the live version or status changes,
4. files/updates an `auto-repair` issue if the bundles stop loading.

Because the asset build rotates roughly every 10 minutes, the decryptor
always fetches the bundle it is about to use — it never depends on a stale
snapshot.

## Why not extract the keys?

See `docs/21-2026-rebuild-status.md` for the full investigation. In short:
the master AES key lives in WASM locals / is assembled from XOR constants at
runtime, is never written to linear memory, and the fixslice transform in the
rebuild is a two-input AddRoundKey rather than a plain invertible bit
permutation. Every memory/locals/static scan performed finds no key. The
black-box path sidesteps the problem entirely.
