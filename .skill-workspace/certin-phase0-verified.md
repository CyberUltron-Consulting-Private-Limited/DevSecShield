# CERT-In Phase 0 — verification evidence

Date: 2026-08-09

## A. Contract / unit
- `cd aibom && uv run pytest tests/test_certin_ledger_sync.py tests/test_certin_common.py -q` → 13 passed
- Ledger ID set: 113 (LEDGER.md ↔ ledger.yaml)
- Floors: T5 data 21; 7.1.* 15; 8.4.1.* 13; 9.4.1.* 13; T9/T10 present; no T8-*

## B. Isolation / regression
- No `cert_in_` in CBOM_FRAMEWORKS / engine.FRAMEWORKS / SBOM_FRAMEWORKS
- `pytest -k "cbom_chart_data_contract or sbom_rbi or rbi_free_ai_compliance"` → 26 passed
- `npx tsc --noEmit` → 0
- Scoped eslint on changed FE → 0 errors

## C. Live stack
- GET /docs 200; /login 200
- CBOM/AIBOM/SBOM scan metadata: prior `*_compliance` present; `cert_in_*` absent
- Worker import `aibom.compliance.cert_in.common` → OK (113 requirements)

## D. Browser (localhost Playwright)
- CBOM results: Crypto compliance readiness; All chip; no India; no QBOM; refresh OK
- AIBOM results: Regulatory Compliance Readiness; Attach attestation after drilldown; no QBOM; refresh OK
- SBOM results: compliance section renders; no QBOM; refresh OK
  - Note: demo findings lacked title/description → defensive `.get` in `findings.py` sbom branch unblocked GET scan

## E. PDF fidelity
- Scope cites CERT-In TG Version 2.0 dated 09.07.2025
- Table 8 QBOM / Table 11 HBOM out of product scope

## F. Defense-in-depth
- Import common → no `aibom.cbom.scanners` leak
- Anti-tautology: removing YAML ID fails sync test; restore → green

Ruflo: `memory_store` key `certin-phase0-verified` namespace `certin-compliance`
