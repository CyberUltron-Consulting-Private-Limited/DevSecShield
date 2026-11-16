# One CBOM results page

Date: 2026-11-15

## What staging showed before this change

Live tag was still `71a95e3a8003`. Promotion #402 (which contains #401, `c01fbf81`) was still building, so staging did not have #401 yet.

As team 1 admin (`staging-admin@zeroshield.ai`):

- `https://devsec-staging.zeroshield.ai/1/cbom/2/results` is HTTP 200. H1 is "CBOM Scan Results". It is code scan 2, "Staging e2e code scan cbom-actions-proof" (repo `cbom-actions-proof`, branch main), status success, 3 findings. Not a blank page.
- `https://devsec-staging.zeroshield.ai/1/cbom/run-2/results` is HTTP 200 with no H1. Body: "Run not found. This CBOM Sources run does not exist or belongs to another team." Team 1 has no Sources run 2 (`GET /1/cbom/sources/runs/2` is 404). The newest runs are 6–40.

The team 2 QA user opening `/1/cbom/2/results` is refused with "You do not have access to this CBOM scan". That page is team 1's scan. The empty view was access control.

## What #401 already did

#401 is on `dev` (`c01fbf81`). It feeds a Sources run through the existing `CbomResults` component. It did not change the heading or the address. On current `dev` before this change the heading was still "Sources run #N" (`runTitle`) and `resultsHref` still returned `/{team}/cbom/run-{id}/results`.

## What shipped

PR: https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/413

Merge SHA: `7993f54166418e331908f4c302f0fda50b202cb0` (into `dev`, not `main`)

Head: `d7fa04227e8fd6a0ef2ad5cc54108325a3c84a75`

- One template: `CbomResults`. Heading is "CBOM Scan Results" for a code scan and a Sources run. The line under the heading still names the run.
- Scans table and Review & Run link to `/{team}/cbom/{id}/results?run=1`. The path is the code-scan results page. `?run=1` selects the Sources run, because scan ids and run ids are separate sequences (team 2 has both code scan 1 and Sources run 1; `/2/cbom/1/results` stays the code scan).
- `/cbom/run-{id}/results` and `/cbom/runs/{id}/results` only redirect to that URL.

No deploy was started. AI withhold / fix-generation files were not edited.

Local tests (`npx tsx` from `frontend/`): `resultsHref.test.ts` 5 pass, `runResultsRoute.test.ts` 4 pass, `pageWiring.test.ts` 6 pass, `runPageWiring.test.ts` pass, `resultRows.test.ts` 13 pass, `model.test.ts` pass.
