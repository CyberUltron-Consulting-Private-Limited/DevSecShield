# Crypto knowledge base

`crypto_kb.json` explains every CBOM finding code without a language model or network access: what it is, how it is
attacked, CWE, OWASP Top 10 (2021 and 2025), CVEs, regulatory references (NIST, CNSA 2.0, CERT-In, SEBI CSCRF, RBI),
step-by-step remediation per platform, and safe read-only commands that prove the exposure.

The same file ships in two places and a test keeps them identical:

- `aibom/src/aibom/cbom/data/crypto_kb.json` (code scans and uploaded CBOM files, in the worker)
- `backend/utilities/cbom_sources/data/crypto_kb.json` (scan-node runs and finding detail, in the API)

## Where each fact comes from

| Data | Source file | Origin |
|---|---|---|
| CVE text, CVSS, CWE, affected versions | `sources/nvd_cves.json` | NVD CVE API 2.0 (`nvd_fetch.py`) |
| Affected versions NVD has not analysed | `sources/cna_<CVE>.json` | CVE record from the CNA (cveawg.mitre.org) |
| CWE names | `sources/cwe_names.json` | MITRE CWE REST API |
| OWASP categories and mapped CWEs, NIST, CNSA 2.0, CERT-In, SEBI, RBI, Mosca | `sources/compliance.json` | quotes with clause numbers and URLs |
| OpenSSL end-of-life dates | `build_kb.py` (`OPENSSL_EOL`) | openssl-library.org release strategy, endoflife.date |
| Descriptions, attack scenarios, remediation, verify commands | `kb_text.py` | written for this product |
| Crypto-agility fix class per code (`fix_class`: class, capability, basis) | `sources/fix_class.json` | reviewed hand table (CB-24), a basis and sources per row; `build_kb.py` fails on a missing or extra row |
| VEX default per code (`vex_default`: basis, reason) and per mapped CVE (`vex_inherent`) | `sources/vex_default.json` | reviewed hand table (CB-22), a reason and sources per row; `build_kb.py` fails on a missing or extra row, a quantum-only entry not marked `quantum_only`, or `observed` on a code-scan code |

OWASP categories come from OWASP's own "List of Mapped CWEs" for each category; a finding also gets the category it
obviously belongs to, marked `basis: category of the finding`. Library CVE matches are reported as *in triage*:
distributions back-port fixes without changing the upstream version, so a version match is not proof.

## Rebuild

```bash
python scripts/crypto_kb/build_kb.py 2026.11.15.1 /tmp/crypto_kb.json   # version must sort after the shipped one
cp /tmp/crypto_kb.json aibom/src/aibom/cbom/data/crypto_kb.json
cp /tmp/crypto_kb.json backend/utilities/cbom_sources/data/crypto_kb.json
```

The build refuses to finish if an entry names a CWE, CVE or compliance key that has no source record.
To add CVEs: `python scripts/crypto_kb/nvd_fetch.py CVE-2026-1234,CVE-2026-5678` (needs internet; run it on a
connected machine, never on the air-gapped install).

## Updating an air-gapped install without a new release

1. On a connected machine, build the new file and sign it:
   `python scripts/crypto_kb/sign.py keygen kb-signing.pem` (once; prints the public key)
   `python scripts/crypto_kb/sign.py sign kb-signing.pem crypto_kb.json` (writes `crypto_kb.json.sig`)
2. Copy `crypto_kb.json` and `crypto_kb.json.sig` to the install (removable media).
3. Set on the API and worker containers:
   `CBOM_KB_BUNDLE=/path/crypto_kb.json`, `CBOM_KB_PUBKEYS=<public key>` (comma-separate several keys),
   optionally `CBOM_KB_BUNDLE_SIG=/path/crypto_kb.json.sig`.

The bundle is used only when the signature is valid, the schema matches and its version is newer than the built-in
file; otherwise the built-in file stays in force and the log says why.
