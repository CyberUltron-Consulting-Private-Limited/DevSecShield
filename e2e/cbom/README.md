# CBOM Tier-L gate (CB-01): customer user flow, evidence harness, strict ledger

Spec: DEVILS-ADVOCATE.md (round-7 CBOM plan) §3 oracle rules O-1..O-10, §4 gate G0-G17 and the known-fail ledger.
The lab and its oracles (CB-02) live in `lab/`; the interface between the two is fixed in the round's
`cbom/INTERFACES.md`. Nothing here is shipped or imported by product code, and nothing here imports product code
(`backend/tests/test_cbom_e2e_harness.py` enforces it).

```
run-gate.sh <ref>          restack to <ref>, then one stack.lock hold (<= 45 min): lab up + self-check, oracle
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
tests/                     the judge's own tests: a correct CBOM passes, deliberately wrong ones fail
```

## Judging a run directory by hand

```bash
cd e2e/cbom
python3 -m harness.gate judge <run>      # report.json + report.md + diff/; exit 0 pass, 1 fail, 2 error
python3 -m harness.gate verify <run>     # or: cd <run> && sha256sum -c SHA256SUMS
python3 -m pytest -q tests               # the judge's own suite
node --test flow/command.test.mjs
```

## Verdicts and the ledger

A check is PASS, FAIL, NOT-JUDGED (the lab's independent self-check disagreed with its own oracle: a lab bug, never a
pass) or NOT-RUN. The ledger turns a listed FAIL into KNOWN-FAIL. The gate passes only when nothing unlisted fails,
nothing unlisted was skipped, and no ledger row is stale: a row whose checks all pass fails the gate until the PR that
fixed it deletes the row. Product correctness is judged against the oracle on the API value; a field the export does
not carry is FAIL(export-missing), never a skip.
