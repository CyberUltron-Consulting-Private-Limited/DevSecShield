# CBOM benchmark — oracle false-positive triage

Every `cbomkit-theia` finding that the diff (`diff.py`) does **not** count as a
true miss, with a grep-verified reason. Three machine-applied reconciliations
plus the explicit `fp-exclusions.json` rules. Nothing here suppresses a real
source-code gap in our crypto scanner.

## Machine-applied reconciliations (in `diff.py` / `ci_gate.py`)

1. **detected_under_different_class** — the oracle lists a name under one
   asset_class, we inventory it under another (e.g. the oracle lists a cert's RSA
   key as `related-crypto-material`; we list `RSA-2048` as an `algorithm`).
2. **algorithm_family_detected** — the oracle picks a bare family (`RSA`); we
   inventory the same family at finer granularity (`RSA-2048` / `RSA-1024`).
3. **cert_key_decomposition** — the oracle's finding is evidenced **entirely** in
   binary cert/key files (`.cer`/`.pem`/`.priv`/…). A filesystem oracle
   decomposes the binary into its embedded algorithm + key material; our
   source-code lane inventories that file as a `certificate` / key asset instead.
   Reconciled only when ours actually inventories a certificate or key asset.

## Explicit rules (`fp-exclusions.json`)

| name | asset_class | why it is an oracle FP |
|------|-------------|------------------------|
| `SHA256-RSA` | algorithm | The cert's COMPOSITE signature algorithm (`sha256WithRSAEncryption`). We inventory its two real primitives separately — SHA-256 (hash) + RSA-2048 (pke). |
| `generic-api-key` | related-crypto-material | cbomkit's **secrets** plugin regex on source/test files. Generic secret detection is the AIBOM `HARDCODED_SECRET` lane (story A1), not the CBOM crypto-asset inventory. |
| `jwt` | related-crypto-material | cbomkit's token detector matching the prose word "JWT" in `.rst` docs / test prose. JWT is a token CONTAINER, not a crypto primitive; we inventory its underlying algorithms (RS256 → RSA+SHA-256). |

## Per-repo notes

- **00-synthetic** — 3 raw misses: `RSA` (algorithm, family-reconciled to our
  RSA-2048/RSA-1024), `RSA-2048` (related-crypto-material, cert-key-decomposition
  of `cert.pem`), `SHA256-RSA` (explicit FP). 0 true misses.
- **01-pyjwt** — 7 raw misses: `jwt` ×N (prose FP), `generic-api-key` ×N (secrets
  FP), `RSA` + `RSA-2048` (cert-key-decomposition of `tests/keys/testkey_rsa.cer`
  / `.priv`, which we inventory as the `testkey-rsa.cer` certificate +
  private/public key material), `SHA256-RSA` (explicit FP). 0 true misses.
  our-unique = 11 (DSA, ECDSA, Ed25519, Ed448, HMAC, SHA-384/512, SSH, TLS …).
  - *Transparency note:* pyjwt's source also exercises RSA via the JWT `RS256`
    family; the oracle only evidences RSA from the bundled cert binary, so vs
    this filesystem oracle there is no RSA source-miss to gate on. Broadening our
    JWT-alias → RSA source coverage is tracked separately (crypto-scanner C1
    backlog), not gated here.
- **02-pyopenssl** — the oracle finds 0 committed crypto assets (pyOpenSSL
  generates its test certs at test-time; none are committed at the scanned root).
  A degenerate-but-honest data point: ours still inventories 10 source-code
  crypto assets the oracle cannot see. 0 misses by construction.
