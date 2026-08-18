# RBI FREE-AI + CERT-In AIBOM finding detail — verification

**Date:** 2026-08-09  
**Ruflo:** `rbi-freeai-finding-detail-verified`, `certin-aibom-oos-finding-detail-verified`

## Root cause (confirmed)

1. Team posture picked **latest SUCCESS AI BOM #109** (14 ML frameworks, **0 models**) → entire `rbi_free_ai` + `cert_in_aibom` **out_of_scope** (“no AI model…”).
2. Older in-scope scans (**#108 / #95**) already had FREEAI-16-1 **fail** + T10-Model-Version **fail** with real evidence — never reached the team drilldown.
3. AIBOM findings lacked `bom_ref` → related-findings join under-counted.

**Product policy:** OOS remains correct on a framework-only scan (#109 alone). No applicability broadening.

## Before / after — FREEAI-16-1 (team 1 posture)

| | Before | After |
|--|--------|-------|
| Verdict | out_of_scope | **fail** |
| Evidence | RBI FREE-AI applies… no AI model | **86 model(s) lack technical model-card documentation** |
| resolve_hint | Not applicable to this scan | **Fix related assets / findings** |
| Source scan | #109 (OOS) | in-scope blob (e.g. #108) |

## Before / after — T10-Model-Version (team 1)

| | Before | After |
|--|--------|-------|
| Verdict | out_of_scope | **fail** |
| Evidence | no AI models detected… | **148/148 model(s) lack required field** |

## Files changed

| Path | Change |
|------|--------|
| `backend/utilities/dashboard/bom_team_pick.py` | **New** — prefer in-scope compliance blob |
| `backend/utilities/dashboard/rbi_posture.py` | Team pick via helper (`rbi_free_ai`) |
| `backend/utilities/dashboard/certin_posture.py` | Team pick via helper (`cert_in_aibom`) |
| `backend/tests/test_rbi_csf_rollup.py` | Prefer-in-scope test |
| `backend/tests/test_certin_posture.py` | Prefer-in-scope T10 test |
| `aibom/src/aibom/integrations/devsecshield.py` | Emit `bom_ref` + finding-centric model descriptions |
| `aibom/tests/test_integration_devsecshield.py` | Lock `bom_ref` in finding schema |
| `frontend/components/compliance/RequirementFindingDetail.tsx` | **New** — Issue/Description samples |
| `frontend/components/rbi/RbiCsfRequirementDrilldown.tsx` | Use finding detail |
| `frontend/components/certin/CertInRequirementDrilldown.tsx` | Use finding detail |
| `.skill-workspace/rbi-freeai-finding-detail-plan.md` | Plan |
| `.skill-workspace/rbi-freeai-finding-detail-verify.md` | This file |
| `.skill-workspace/certin-aibom-oos-finding-detail-verify.md` | CERT-In twin note |

## Hermetic

```
cd backend && uv run pytest tests/test_rbi_csf_rollup.py tests/test_certin_posture.py -q
→ 17 passed

cd aibom && .venv/bin/python -m pytest tests/test_integration_devsecshield.py::test_every_finding_matches_the_locked_finding_schema -q
→ passed

cd frontend && npx tsc --noEmit && npx eslint components/rbi/RbiCsfRequirementDrilldown.tsx components/certin/CertInRequirementDrilldown.tsx components/compliance/RequirementFindingDetail.tsx --max-warnings 0
→ exit 0
```

## Live (team 1)

- Team RBI governance FREEAI-16-1 → fail + model-card evidence + refs capped 50
- Team CERT aibom_ai_assets T10-Model-Version → fail (not OOS)
- Scan #108 single-scan posture unchanged (already fail)

Note: existing SUCCESS rows keep old finding JSON until rescan; posture enrichment is read-time. New scans get `bom_ref` on findings.
