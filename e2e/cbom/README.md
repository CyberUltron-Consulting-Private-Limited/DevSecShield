# CBOM Tier-L gate (CB-01): customer user flow, evidence harness, strict ledger

Spec: DEVILS-ADVOCATE.md (round-7 CBOM plan) §3 oracle rules O-1..O-10, §4 gate G0-G17 and the known-fail ledger.
The lab and its oracles (CB-02) live in `lab/`; the interface between the two is fixed in the round's
`cbom/INTERFACES.md`. Nothing here is shipped or imported by product code, and nothing here imports product code
(`backend/tests/test_cbom_e2e_harness.py` enforces it).

```
run-gate.sh <ref>          one stack.lock hold: restack to <ref> if needed, then the gate (<= 45 min): lab up + self-check, oracle
                           frozen, G0 pre-flight, the customer flow in Chromium, DB + logs collected, redaction,
                           G17 seal, judge; lab and node torn down; stack back on dev; SHA256SUMS
collect-evidence.sh        <teams> <runs> <since> [run]: read-only DB rows + container logs (also the owner's OA-7 tool)
flow/gate.mjs              the customer: sign-up (G1), navigation (G2), scan node from the DOM command (G3), network
                           sources (G5), Review & Run with a double click (G9), watch (G10), results DOM + API pages
                           (G11), downloads (G12), customer B tenancy (G14), sign-out (G17)
flow/command.mjs           the G3 allowed-diff rule (UI command token for token + --network cbom-e2e-net + lab CA)
harness/                   the judge: per-row join keyed by asset id (UI DOM, API, DB, export), closed/open-world
                           oracle matching, derived numbers, canary grep, 5xx<->log ref, ledger, manifest, redaction
known-fail.yaml            the strict ledger: every failing check is fixed or listed with an issue and owner
harness/negative.py        negative controls: 27 deliberately wrong CBOMs made from a real run's evidence; each must FAIL
tools/mutants.py           one-line mutants of the judge; each must be killed by tests/
tests/                     the judge's own tests: a correct CBOM passes, deliberately wrong ones fail
```

## Judging a run directory by hand

```bash
cd e2e/cbom
python3 -m harness.gate judge <run>      # report.json + report.md + diff/; exit 0 pass, 1 fail, 2 error
python3 -m harness.gate verify <run>     # or: cd <run> && sha256sum -c SHA256SUMS
python3 -m pytest -q tests               # the judge's own suite
python3 -m harness.negative <run>        # the 27 wrong CBOMs on a copy of <run>: each FAILs, the run itself PASSes
python3 tools/mutants.py                 # mutation score of tests/ (every mutant must be killed)
node --test flow/command.test.mjs
```

## Verdicts and the ledger

A check is PASS, FAIL, NOT-JUDGED (the lab's independent self-check disagreed with its own oracle: a lab bug, never a
pass) or NOT-RUN. The ledger turns a listed FAIL into KNOWN-FAIL. The gate passes only when nothing unlisted fails,
nothing unlisted was skipped, and no ledger row is stale: a row whose checks all pass fails the gate until the PR that
fixed it deletes the row. Product correctness is judged against the oracle on the API value; a field the export does
not carry is FAIL(export-missing), never a skip.

Ledger rows (v2, INTERFACES v7 §B) match on allowlisted keys only (exact strings; a list is "any of"; never `verdict`,
`id` or a `*_prefix`) inside their `gate`, must name a narrowing key (`check`, `oracle_id`, `field`, `part`, `step`,
`probe`) and pin `expect_failing` (and `expect_not_run` with `not_run_ok`). A count that moves either way, up (a new
defect under an old row) or down (a fix), fails the gate until the row is edited.

## CI vs local

CI (ci-gate, backend job) runs `tests/` only: the judge's unit suite, the golden negative-control suite (a trimmed,
sanitised snapshot of a real Tier-L run under `tests/golden/`, re-judged with every wrong CBOM), the O-1 import lint and
the repository ledger's schema. CI never sees a live run: it cannot tell whether `known-fail.yaml`'s pinned counts are
still true on dev. Only `run-gate.sh` on the local stack (Tier L: the dss-staging stack, Docker, the CB-02 lab,
Chromium) can, so **a ledger edit needs a live run in the same PR**.

How a PR proves the gate (DA §4.6): run `run-gate.sh <head>` on the PR head rebased on dev, under `stack.lock`; no new
failure (nothing blocking, every ledger row `holds` or `not-run-ok`); post the bundle sha256
(`sha256sum <run>/SHA256SUMS`) and the `report.md` ledger table on the PR. A PR that fixes a ledgered defect sees its
row `moved` or `stale` and edits or deletes it in the same PR, backed by that run. The golden fixture is refreshed
with `python3 tools/golden.py <run> tests/golden` plus its own ledger snapshot when the lab or the judge changes shape.
