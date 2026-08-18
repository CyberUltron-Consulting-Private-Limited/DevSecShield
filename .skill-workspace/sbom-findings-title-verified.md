# SBOM findings title/description — verification evidence

Date: 2026-08-09

## A. Unit
- `pytest tests/test_sbom_findings_normalize.py -q` → 8 passed
- Anti-tautology: break normalize → fail; restore → pass

## B. Isolation
- `normalize_sbom_finding_data` only on `sbom_sca` branch in `create_findings.py`
- IAC/DAST remain passthrough (unit lock)
- Peer `-k "sbom_rbi or bom_export or bom_api"`: 18 passed; 2 pre-existing IDOR attacker-401 fails (unrelated)

## C. Live API
- Repaired 5 demo Mongo docs for scan_id=3 via same normalize helper
- `GET /1/sbom_sca/scan/3` → 200; 5 findings; all non-empty titles; `description` key present; `sbom_compliance` present

## D. Browser
- Playwright `/1/sbom_sca/3/results`: titles visible, compliance section present, scan API 200, no console errors, refresh OK

## E. Defense
- Reader sparse unit: missing status/title → soft defaults, never raises

Ruflo: `sbom-findings-title-verified` @ `certin-compliance`
