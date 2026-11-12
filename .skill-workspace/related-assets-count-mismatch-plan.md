# Related assets count mismatch — plan + fix

## Symptom

CERT-In / RBI drilldown showed **Related assets: 50** while the scan had **49** AI asset findings and **View related findings** filtered to ~9 rows.

## Root cause (evidence)

1. Posture rollup caps compliance `refs` at `[:50]` (`certin_posture.py` / `rbi_posture.py`).
2. Those refs are inventory/graph bom-refs — a **superset** of persisted findings.
3. Drilldown UI used `refs.length` for the label.
4. The findings table uses `relatedFindingMatch` / `filterFindingsByRelatedRefs`, so the visible row count ≪ `refs.length`.

Live AIBOM #95: `data.length === 49`, posture requirements with `refs.length === 50` exist; matcher hits ≪ 50.

## Fix (shipped — option A)

- Display count = `countRelatedFindings(findings, refs, { aliases })` (same predicate as View related findings).
- Label: `N related finding(s)`.
- Hide the related row when match count is 0 (no false “50”).
- Wire `findings` + `refAliases` from AiBom/Cbom/Sbom Results → CertInLanePosture / RbiCsfRollup → drilldowns.
- Do **not** uncap backend refs; do **not** change attestation.

## Options considered

| Opt | Approach | Decision |
|-----|----------|----------|
| A | Honest UI count = matcher hits | **Chosen** |
| B | Trim refs at posture build to findings-only | Wrong layer; posture lacks findings list |
| C | “N related (M in findings)” | Noisier; A is enough |
| D | Improve matcher only | Still must not claim 50 when 9 match |

## Files

- `frontend/utils/relatedFindingMatch.ts` — `countRelatedFindings`
- `frontend/components/certin/CertInRequirementDrilldown.tsx`
- `frontend/components/rbi/RbiCsfRequirementDrilldown.tsx`
- `CertInLanePosture` / `CertInRollup` / `RbiCsfRollup` + Results pages
