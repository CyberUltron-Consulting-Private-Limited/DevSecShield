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
harness/negative.py        negative controls: 47 deliberately wrong CBOMs made from a real run's evidence; each must FAIL
                           through the check it is aimed at (INTENDED), never an incidental one
harness/identity.py        stable identities of checks across runs (asset ids -> type@location, lab dates relative to
                           the oracle's generated_at, digests -> <hex:N>): what ledger rows pin
tools/mutants.py           one-line mutants of the judge; each must be killed by tests/
tests/                     the judge's own tests: a correct CBOM passes, deliberately wrong ones fail
```

## Judging a run directory by hand

```bash
cd e2e/cbom
python3 -m harness.gate judge <run>      # report.json + report.md + diff/; exit 0 pass, 1 fail, 2 error
python3 -m harness.gate verify <run>     # or: cd <run> && sha256sum -c SHA256SUMS
python3 -m pytest -q tests               # the judge's own suite
python3 -m harness.negative <run>        # the 47 wrong CBOMs on a copy of <run>: each FAILs, the run itself PASSes
python3 -m harness.ledger pin <run> --write   # re-pin every row's identities from <run> (after a live run only)
python3 tools/mutants.py                 # mutation score of tests/ (every mutant must be killed)
node --test flow/command.test.mjs
```

## Verdicts and the ledger

A check is PASS, FAIL, NOT-JUDGED or NOT-RUN. NOT-JUDGED means no independent oracle: the lab's self-check disagreed
with its own oracle (a lab bug), or the key is one the lab could not verify independently and the product AGREES with
the lab's value (the product's value is recorded; a product that disagrees is FAIL(disagrees-with-unverified-lab)).
NOT-JUDGED is never a pass: unless a ledger row pins it, it blocks. Finding codes and impact are judged where the lab
states them (`codes_include`, `codes_exclude`, `impact_min`, `impact_max`); elsewhere they are NOT-RUN(no-expectation)
carrying what the customer was shown, so a pinned row moves when that changes. The ledger turns a listed FAIL into KNOWN-FAIL. The gate passes only when nothing unlisted fails,
nothing unlisted was skipped, and no ledger row is stale: a row whose checks all pass fails the gate until the PR that
fixed it deletes the row. Product correctness is judged against the oracle on the API value; a field the export does
not carry is FAIL(export-missing), never a skip.

Ledger rows (v3, INTERFACES v7 §B + v7.3) match on allowlisted keys only (exact strings; a list is "any of"; never
`verdict`, `id` or a `*_prefix`) inside their `gate`, must name a narrowing key (`check`, `oracle_id`, `field`, `part`,
`step`, `probe`) and pin the IDENTITIES they tolerate in `expect`: each entry is a normalised check id with its verdict
(FAIL by default, NOT-JUDGED, NOT-RUN with `not_run_ok`) and its expected and observed values. Any difference in that
multiset fails the gate until the row is re-pinned: a fix, a new defect under an old row, a worse value under the same
check (a sample that lost another suite), or a fix plus a new defect that keep the count. `expect_failing` /
`expect_not_run` are optional and must agree with the pins.

## CI vs local

CI (ci-gate, backend job) runs `tests/` only: the judge's unit suite, the golden negative-control suite (a trimmed,
sanitised snapshot of a real Tier-L run under `tests/golden/`, re-judged with every wrong CBOM), the O-1 import lint and
the repository ledger's schema. CI never sees a live run: it cannot tell whether `known-fail.yaml`'s pinned identities
are still true on dev. Only `run-gate.sh` on the local stack (Tier L: the dss-staging stack, Docker, the CB-02 lab,
Chromium) can, so **a ledger edit needs a live run in the same PR**.

How a PR proves the gate (DA §4.6): run `run-gate.sh <head>` on the PR head rebased on dev, under `stack.lock`; no new
failure (nothing blocking, every ledger row `holds` or `not-run-ok`); post the bundle sha256
(`sha256sum <run>/SHA256SUMS`) and the `report.md` ledger table on the PR. A PR that fixes a ledgered defect sees its
row `moved` or `stale` (report.md lists the unexpected and missing identities) and re-pins it with
`python3 -m harness.ledger pin <run> --write` or deletes it in the same PR, backed by that run. The bundle proves which
ledger judged it (`report.json` / MANIFEST `ledger: {path, sha256}`), and G17 fails when the judge or the ledger is not
committed (`harness.dirty`, untracked files under `e2e/cbom`). The golden fixture is refreshed
with `python3 tools/golden.py <run> tests/golden` plus its own ledger snapshot when the lab or the judge changes shape.
