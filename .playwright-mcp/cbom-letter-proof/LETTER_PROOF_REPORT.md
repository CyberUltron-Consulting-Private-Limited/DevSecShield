# Code & Dependency Scanner — E2E Letter Proof

Generated: 2026-10-29T07:25:50.877592Z
Evidence dir: `/tmp/cbom-letter-proof-20261029071808`

## Verdict
**PROVEN** end-to-end via CLI + staging CI plugin + CbomResults UI + GitHub Actions.

## Claim → Evidence

| Claim | Mechanism | Proof |
|---|---|---|
| Agentless / read-only / nothing installed on servers | CLI help + action.yml + airgap tests; scans checkout/zip only | clean_exit=0 vuln_exit=1; `aibom cbom` help: 'Nothing is installed there'; GHA Allow/Block on AnshSinghal/cbom-actions-proof |
| Runs as CLI | `aibom cbom PATH` | local: clean exit 0 / vuln exit 1; GHA Allow `# cbom: no high findings`; Block `# cbom: 7 high finding(s)` |
| Runs as CI plugin | POST /cicd/cbom/scan + GitHub Action | staging 52749: vuln finding_count=9 (log 6ae2f430…), crypto=13 (6ae2f43e…), misuse=17 (6ae2f46e…); GHA run 40832675587 success finding_count=3 via devsec-staging-api.zeroshield.ai |
| crypto API calls | algorithm_scan/detect | CI crypto log: 3DES-CBC, AES-ECB, AES-GCM, MD5, RC4, RSA-1024/2048, SHA-256; UI charts Algorithm distribution |
| hard-coded keys and IVs | crypto_misuse_scan | CI misuse: HARDCODED_KEY, STATIC_IV, REUSED_NONCE; UI: Weak RNG / Hardcoded key / Reused nonce / Static IV |
| cipher modes, padding, RNG | weakness + misuse + padding | CI: WEAK_CIPHER_MODE (AES-ECB), WEAK_RNG×3; CLI padding fixture: pkcs1v15/oaep+encrypt/sign props |
| custom crypto + cert-validation logic | custom_crypto_scan + posture_verification | CI vuln: CUSTOM_CRYPTO (custom_aes.py), TLS_VERIFICATION_DISABLED (tlscheck.py) |
| direct + transitive vulnerable crypto libs | advisories + crypto_advisory_scan | CI vuln: 6× VULNERABLE_CRYPTO_LIBRARY (direct pyjwt/bouncycastle + transitive node-forge/golang.org/x/crypto/ed25519-dalek) |
| IaC before deployment | posture_iac_scan in same scan_crypto | CI vuln: UNENCRYPTED_AT_REST on aws_db_instance.plain from main.tf; CLI IaC fixture emits crypto-cfg_ infra facts |

## UI Results Pages (full CbomResults)

- deps+IaC+custom+TLS: http://127.0.0.1:52741/1/ci_cd/2/sast/results?log_id=6ae2f4304eeed521a43fe955
  public: http://devsec-staging.zeroshield.ai/1/ci_cd/2/sast/results?log_id=6ae2f4304eeed521a43fe955
- crypto APIs: http://127.0.0.1:52741/1/ci_cd/2/sast/results?log_id=6ae2f43e4eeed521a43fe959
  public: http://devsec-staging.zeroshield.ai/1/ci_cd/2/sast/results?log_id=6ae2f43e4eeed521a43fe959
- keys/IVs/RNG: http://127.0.0.1:52741/1/ci_cd/2/sast/results?log_id=6ae2f46e4eeed521a43fe95d
  public: http://devsec-staging.zeroshield.ai/1/ci_cd/2/sast/results?log_id=6ae2f46e4eeed521a43fe95d

## GitHub Actions

- Repo: https://github.com/AnshSinghal/cbom-actions-proof
- Product CI success: https://github.com/AnshSinghal/cbom-actions-proof/actions/runs/40832675587
- Allow (CLI clean): https://github.com/AnshSinghal/cbom-actions-proof/actions/runs/40832675555
- Block (CLI vuln, expected failure): https://github.com/AnshSinghal/cbom-actions-proof/actions/runs/40832675647

## Staging health

- API http://127.0.0.1:52749/docs → 200 (also :52749 public / DNS)
- Web http://127.0.0.1:52741/login → 200
- DNS: devsec-staging-api.zeroshield.ai / devsec-staging.zeroshield.ai → 13.234.69.238
