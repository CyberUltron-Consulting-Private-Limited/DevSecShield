# BOM Unknown Elimination — Verification

**Status:** ACCEPTED (remap + emit ≥3/type)  
**Date:** 2026-08-09  
**Locked defaults:** `not_declared` residual · no live PyPI · read-time + emit-time · `UNKNOWN` → `NOT_DECLARED`

---

## Memory / artifact checklist

| Key / file | Result |
|------------|--------|
| Ruflo `bom-unknowns-diagnosis` | Present (plan-time evidence; before unknown=820) |
| Ruflo `bom-unknowns-sbom-fixed` | Written on accept |
| Ruflo `bom-unknowns-zero-verified` | Written on accept |
| `.skill-workspace/bom-unknowns-plan.md` | Exists |
| `backend/utilities/dashboard/sbom_license.py` | Exists |
| `.skill-workspace/bom-unknowns-verify.md` | This file |

---

## Before / after (team 1 SBOM licenses)

| Metric | Before (diagnosis) | After (verify) |
|--------|--------------------|----------------|
| `licenses_distribution.unknown` | **820** | **0** (key removed) |
| `licenses_distribution.not_declared` | 0 | **721** |
| `licenses_distribution.permissive` | 130 | **394** |
| Example scan `#91` inventory `license_type=unknown` | 97/102 | N/A (legacy remapped on read) |

AIBOM / CBOM team charts: **0** `unknown` buckets before and after (CBOM was already live-clean; AIBOM charts were already remapped).

---

## Remap proof (all existing success scans)

API: `GET /1/{type}/scans` + `GET /1/{type}/scan/{id}` with JWT for `cbom-demo@cyberultron.com`.

| Type | Success checked | Scans with in-scope `unknown` | Team unknown buckets |
|------|-----------------|-------------------------------|----------------------|
| `sbom_sca` | 22 | **0** | none (`not_declared` present) |
| `ai_bom` | 18 | **0** | none |
| `cbom` | 18 | **0** | none |

Artifact: `/tmp/bom_unknowns_remap_proof.json`

In-scope fields asserted:
- SBOM: `dashboard.licenses_distribution` keys; findings/data `license_type`
- AIBOM: license/provider distributions; findings/data `license`/`source`/`provider`/`license_type`
- CBOM: strength/algorithm/quantum_readiness; findings/data `crypto_strength`/`algorithm_type`

---

## Emit-path proof (≥3 new success scans per BOM)

| Type | Scan IDs | Status | Unknown issues |
|------|----------|--------|----------------|
| `cbom` | **104**, **105**, **106** | success | none |
| `ai_bom` | **107**, **108**, **109** | success | none |
| `sbom_sca` | **113**, **114**, **115** | success | none |

Fresh SBOM license charts (emit-time `not_declared`, never `unknown`):

| Scan | Repo | permissive | not_declared | unknown |
|------|------|------------|--------------|---------|
| 113 | pallets/click | 25 | 76 | 0 |
| 114 | psf/requests | 6 | 23 | 0 |
| 115 | encode/httpx | 10 | 9 | 0 |

Artifact: `/tmp/bom_unk_emit_report.json` · `ALL_EMIT_OK=true`

Note: earlier emit attempts `#101–103` stuck in `started` after worker death mid-Syft (cannot re-start); replaced by `#113–115`.

---

## Groups A–E completion

| Group | Status | Evidence |
|-------|--------|----------|
| A SBOM taxonomy + mapper | done | `backend/utilities/dashboard/sbom_license.py` + worker twin; `LicenseCategory.NOT_DECLARED`; FE labels |
| B SBOM emit enrichment | done | `merge_inventory.py` → `resolve_emit_license`; curated map only |
| C SBOM read-time remap | done | `scan.py` / `scan_list.py` / `findings.py` / `scans.py` GET data |
| D AIBOM emit + read parity | done | `devsecshield.py` licenses; GET remaps `source`/`license` |
| E CBOM defensive | done | adapter `other`; normalize `other`; FE `—`; GET remaps |

Unit: `backend/tests/test_sbom_license.py` → **8 passed**.

---

## Files touched (implementation)

- `backend/utilities/dashboard/sbom_license.py` (new)
- `backend/tests/test_sbom_license.py` (new)
- `backend/utilities/dashboard/scan.py`, `scan_list.py`
- `backend/utilities/db/findings.py`
- `backend/routers/scans.py`
- `RabbitMQ/worker/helpers/tools/sca_sbom_agent/sbom_license.py` (new)
- `RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py`
- `RabbitMQ/worker/helpers/tools/sca_sbom_agent/test_empty_matches.py`
- `RabbitMQ/worker/helpers/context/enums.py`, `schema.py`
- `frontend/components/SbomResults.tsx`, `frontend/app/[team_id]/sbom_sca/page.tsx`
- `frontend/components/CbomResults.tsx`
- `aibom/src/aibom/integrations/devsecshield.py`, `cbom_devsecshield.py`
- `aibom/src/aibom/cbom/normalize.py`
- `.skill-workspace/bom-unknowns-plan.md`, `bom-unknowns-verify.md`

---

## Blockers / residual

1. **Stack churn:** concurrent agents repeatedly `pkill`’d backend/scan_worker during verification; caused SBOM `#101–103` to strand in `started`. Mitigated by fresh `#113–115`.
2. **Full 10×10×10 re-scan** not required for accept under “if slow → remap all success + ≥3 new/type”; remap covered 58 success scans + 9 emit scans.
3. Stuck scans `#97–103` may need manual DB cleanup / cancel UI — out of acceptance scope.
4. No git commit/push (per constraints).
