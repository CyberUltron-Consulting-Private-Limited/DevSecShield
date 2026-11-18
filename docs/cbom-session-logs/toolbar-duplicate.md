# CBOM results header: one toolbar

Date: 2026-11-16

## Cause

On a Sources run the page is `/{team}/cbom/{id}/results?run=1` (PR #413). That route is `app/[team_id]/cbom/[scan_id]/results/page.tsx`, so `useParams().scan_id` is the run id. `RunResultsRoute` renders `CbomResults` with `source` and no `conversationId`.

`frontend/components/CbomResults.tsx` then sets `scan_id = conversationId ?? params?.scan_id`, which is set, and `run` from `source.kind === "run" && source.run`. The header mounted both groups as siblings:

- `run && run.run` → `RunHeaderActions` (CycloneDX JSON, CycloneDX XML, OSCAL, VEX, Signature, Evidence pack, PDF Report, Verify file, Compare, Open in CBOM Sources)
- `team_id && scan_id != null` → the code-scan row (the same downloads, plus Scan settings)

The header is `lg:flex-row`, and neither row is hidden at a breakpoint, so both groups sat side by side. The H1 stays "CBOM Scan Results". Source chips come from `RunHeaderMeta` when `run && run.run`.

## What shipped

PR: https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/423

Merge SHA: `13c36070cd4a18f884c4d6f403907a3cb88ab6c2` (into `dev`, not `main`)

Head: `9be2f04bf960418301a6be80925b6778113a8b06`

One toolbar. A Sources run keeps `RunHeaderActions`: the run downloads once, Verify file, Compare, and Open in CBOM Sources (`/{team}/cbom/sources?tab=review`). A code scan keeps its download row and Scan settings. The two rows are mutually exclusive (`run && run.run ? … : team_id && scan_id != null ? …`).

No deploy was started. Deploy staging for #422 had already completed. This merge is to `dev` only.

## Test

From `frontend/`: `npx --yes tsx components/cbom/results/runPageWiring.test.ts` → `run page wiring tests passed`.
