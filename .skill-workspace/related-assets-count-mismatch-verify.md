# Related assets count mismatch — verify

## Unit

```bash
cd frontend && npx --yes tsx utils/relatedFindingMatch.test.ts
# → relatedFindingMatch.test.ts: all passed
```

Includes `countRelatedFindings` case: 50 refs → 2 matched findings.

## Live AIBOM #95 (2026-08-09)

- `GET /1/ai_bom/scan/95` → `findings_total=49`, `scan_status=success`
- 30 posture requirements with `refs.length===50` (CERT-In + RBI)
- `countRelatedFindings` === `filterFindingsByRelatedRefs.length` for all
- Examples (old UI would show 50):
  - `T10-Model-Name` → **7** related findings
  - `T10-Model-Type` → **10** related findings
  - `T10-ML-Models-and-Algorithms` → **10** related findings

## UI contract

Drilldown label: `{N} related finding(s)` where `N = countRelatedFindings(...)`.
Never `Related assets: {refs.length}`.
Row hidden when `N === 0`.

## Not changed

- Backend `[:50]` ref cap
- Attestation flow
- Matcher alias/location logic (count only)
