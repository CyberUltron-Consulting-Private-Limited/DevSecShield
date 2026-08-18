# RBI CSF findings transparency — verification

**Date:** 2026-08-09  
**Option shipped:** A + C (enriched drilldown + related-findings filter; no B-persist)  
**Ruflo key:** `rbi-csf-findings-transparency-verified`

## Files changed

| Path | Change |
|------|--------|
| `backend/utilities/dashboard/rbi_posture.py` | `_resolve_hint` + `_rollup_pillar` passthrough of `source`/`evidence`/`refs`(≤50)/`attestable`/`resolve_hint`/`_scanner` |
| `backend/tests/test_rbi_csf_rollup.py` | Field carry-through, NBE hint, refs cap tests |
| `frontend/components/rbi/RbiCsfRequirementDrilldown.tsx` | **New** separate RBI drilldown (CERT-In style; not a rename) |
| `frontend/components/rbi/RbiCsfRollup.tsx` | Uses drilldown; optional `onAttest` / `onViewFindings` |
| `frontend/components/CbomResults.tsx` | Wire handlers into `RbiCsfRollup` |
| `frontend/components/AiBomResults.tsx` | Wire handlers into `RbiCsfRollup` |
| `frontend/components/SbomResults.tsx` | Wire handlers into `RbiCsfRollup` |
| `frontend/utils/backend_api.ts` | Widen `RbiCsfRollupPayload` requirement shape |

Team dashboard (`app/[team_id]/page.tsx`) unchanged — still mounts rollup **without** attest (readonly enriched drilldown).

## Hermetic

```
cd backend && uv run python -m pytest tests/test_rbi_csf_rollup.py -q
→ 6 passed

cd frontend && npx tsc --noEmit
→ exit 0

npx eslint components/rbi/RbiCsfRollup.tsx components/rbi/RbiCsfRequirementDrilldown.tsx --max-warnings 0
→ exit 0
```

## Live API (team 1, cbom-demo JWT → GET `/{type}/scan/{id}`)

Posture is **read-time recomputed** from compliance blobs, so existing SUCCESS scans pick up enrichment without rescan.

| Scan | Type | Req count | All have evidence+resolve_hint+source+_scanner+attestable | Fail w/ refs sample | NBE sample |
|------|------|-----------|------------------------------------------------------------|---------------------|------------|
| **#91** | sbom_sca | 6 | yes (6/6) | `FREEAI-SUPPLY-1` — 7 deps lack name/version; 7 refs; hint “Fix related assets / findings”; `_scanner=sbom` | `FREEAI-SUPPLY-6` — attestable; hint “Upload process attestation…”; 0 refs |
| **#94** | cbom | 8 | yes (8/8) | `FREEAI-PROT-3` — 59 hardcoded keys; refs capped **50**; `_scanner=cbom` | `FREEAI-PROT-7` / `PROT-8` — attestable NBE; `_scanner=cbom` |
| **#95** | ai_bom | 25 | yes (25/25) | `FREEAI-16-1` — 86 models lack model-card; refs capped 50; `_scanner=ai_bom` | `FREEAI-1` / `FREEAI-2` — attestable NBE |

### Related-findings matcher (`relatedFindingMatch`)

Same filter used by CERT-In “View related findings”:

| Scan | Fail req | Refs | Findings total | Matcher hits |
|------|----------|------|----------------|--------------|
| #91 | FREEAI-SUPPLY-1 | 7 | 102 | **7** |
| #94 | FREEAI-PROT-3 | 50 | 91 | **58** |
| #95 | FREEAI-16-1 | 50 | 49 | **5** |

All ≥1. Findings table inventory counts unchanged (no synthetic rows persisted into `results`).

Artifacts: `/tmp/rbi_csf_live_verify.json`, `/tmp/rbi_csf_match_verify.json`.

## Constraints honored

- No B-persist / no KPI pollution  
- Team page readonly (no `onAttest`)  
- Separate `RbiCsfRequirementDrilldown` (not CertIn rename)  
- `_scanner` passthrough for team merge badges  
- No git stash / push / commit  
