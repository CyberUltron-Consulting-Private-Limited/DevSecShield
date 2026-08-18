# CERT-In AIBOM OOS → finding detail — verification

**Date:** 2026-08-09  
**Ruflo:** `certin-aibom-oos-finding-detail-verified`  
**Peer plan:** `.skill-workspace/rbi-freeai-finding-detail-plan.md`  
**Peer verify:** `.skill-workspace/rbi-freeai-finding-detail-verify.md`

## Symptom

T10-Model-Name/Version/Type/Developer/Licensing showed **out of scope** with “no AI models detected; CERT-In AIBOM guidelines do not apply”.

## Cause

Same as FREE-AI: team posture selected latest AI BOM **#109** (frameworks only). Scan **#108/#95** already had in-scope T10 verdicts.

## Fix

Shared `bom_team_pick.pick_latest_bom_compliance(..., prefer_frameworks=("cert_in_aibom",))` + drilldown `RequirementFindingDetail` (Issue/Description) + AIBOM `bom_ref` on findings.

## Live after

Team CERT `aibom_ai_assets` T10-Model-Version → **fail** with field-gap evidence (not OOS).

OOS on a true no-model AI BOM scan remains valid product policy.
