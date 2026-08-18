# CERT-In "View related findings" — plan

## Evidence (live API, team 1)

| Scan | Example ref | Finding `id` | Finding name/location |
|------|-------------|--------------|------------------------|
| CBOM #94 | `crypto-cert-tests-keys-testkey-rsa-cer-cert` | `6a785fdd…4aa4` (Mongo ObjectId) | `testkey_rsa.cer` @ `tests/keys/testkey_rsa.cer` |
| AIBOM #95 | `modelref-gpt-4o` | `6a7861d2…4adc` | `gpt-4o` |
| SBOM #91 | `sbom-dep-99` | `6a785a61…4a60` | findings\[99\] starlette DoS |

Current filter: `refSet.has(finding.id)` or `name/loc/id/desc.includes(fullRef)` → **0 hits** (proved for KM-4 / T9-Certificates-Signature-Algorithm-Reference).

BOM/graph still knows the asset: `cbom_graph.nodes[].id === bom-ref` and `.label === finding.algorithm_name`.

## Root cause

Compliance `refs` are CycloneDX **bom-refs**; persisted findings use Mongo **ObjectIds** as `id`. The filter never bridges bom-ref → name/location/index.

## Locked fix

1. Extract shared helper `frontend/utils/relatedFindingMatch.ts`:
   - exact `id` match (case-insensitive)
   - optional alias map (bom-ref → graph label) with name equality
   - strip prefixes (`pkg:`, `modelref-`, `modelfile-`, `lib-`, `crypto-algo|cert|protocol|material-`, …)
   - location: hyphenated path contained in ref
   - `sbom-dep-N` → finding index `N`
   - case-insensitive; do not weaken normal search
2. Wire into `CbomResults` / `AiBomResults` / `SbomResults` (pass graph aliases + index where available).
3. Empty state: when related-ref filter active and 0 rows, message clarifies assets may lack finding rows (AIBOM modelref-only inventory).
4. Hermetic `relatedFindingMatch.test.ts` (tsx) + live script check for CBOM #94 cert ref → ≥1 finding.

## Out of scope

- Backend id rewrite / re-persist
- Git push / PR
