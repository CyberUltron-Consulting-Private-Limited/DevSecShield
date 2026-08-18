# Master Issues Plan — CBOM Certificate Expiry empty chart

Updated: 2026-08-09 (runtime evidence)

## Executive summary

The empty state **"No certificates detected"** in `CbomCryptoCharts.CertificateExpiry` is shown when `cbom_distributions.certificates` is empty/`undefined`. Live API evidence shows **card `total_certificates` == `len(certificates)`** on recent success scans — no metadata surfacing mismatch found.

| Scan | Title | card certs | dist certs |
|------|-------|------------|------------|
| 94 | OWASP chart fix verify 3 (pyjwt) | 1 | 1 |
| 80 | mitmproxy | 32 | 32 |
| 79 | pyca/cryptography | 136 | 136 |
| 78 | pyopenssl | 0 | 0 |
| 81 | paramiko | 0 | 0 |

Normalize + fixture path healthy: `synthetic-crypto-app` → 1 cert row with `not_valid_after`, `expired`, `self_signed`.

## Ranked issues

### ISS-1 — Honest empty on zero-cert repos (Likely what user saw)
- **Severity:** Low (UX) / Medium if product expectation is "always show certs"
- **Root cause:** Scanner only inventories real X.509 files / PEM blocks. Repos like pyopenssl/paramiko can have crypto algorithms without checked-in certs → empty chart is correct.
- **Evidence:** scans 78/81 card=0 dist=0 while algorithms/protocols may still populate other charts.
- **Confidence:** High

### ISS-2 — Chart under-uses normalize payload (UX gap)
- **Severity:** Medium (UX)
- **Root cause:** FE only buckets Valid/Expired/Self-signed; ignores `near_expiry`, `name`, `not_valid_after`, weak-sig/key already emitted by `_certificate_expiry`.
- **Evidence:** normalize.py lines 188–219; FE CertificateExpiry ~508–549.
- **Confidence:** High

### ISS-3 — Empty copy is absolute / confusing
- **Severity:** Low
- **Root cause:** Message "No certificates detected" reads like a scanner failure when other crypto charts have data.
- **Confidence:** High

### ISS-4 — FE data-path drop (REFUTED for current success scans)
- **Severity:** would be High
- **Status:** Unconfirmed / contradicted by API equality card==dist
- **Note:** Headless Playwright currently stuck on layout spinner (0 API hits) — separate local-dev auth issue; not the empty-chart message path.

## Dependency map

- Fix ISS-3/ISS-2 (FE) needs no worker restart.
- Detection expansion (if user wants pyopenssl-style certs) is a separate CBOM scanner story — do **not** fold into chart UX without evidence of missed `.pem`/`.crt` on disk.

## Recommended direction (awaiting user confirm)

Prefer **FE-only**: clearer empty state + per-certificate expiry list when rows exist; verify live on scan **#80** (32 certs) and a **0-cert** scan for empty copy. No normalize/adapter change unless we prove a detection miss.
