# aibom/state/regression-lock = DONE

Every AI-BOM pipeline is now locked against regression by a CI-blocking gate in
`.github/workflows/aibom-gates.yml` (per push/PR) + a nightly live benchmark.

## CI gates (`.github/workflows/aibom-gates.yml`)
| gate | locks | runs |
|------|-------|------|
| **A — recall** | model/provider/framework recall vs the OSS oracles **and** vs the exact synthetic MANIFEST (recall stays 1.0) | `test_differential.py` + `test_model_recall.py` |
| **B — chart-data contract (P4)** | no results-page chart can go empty/flat; Trusera dimension-parity | `test_chart_data_contract{,_full}.py`, `test_chart_contract_severity.py`, `test_dimension_parity.py` |
| **C — golden lock** | emitted CycloneDX / SPDX / SARIF == committed goldens | `test_emit.py`, `test_spdx.py`, `test_sarif.py`, `test_parity.py` |
| **D — compliance tri-state (P5)** | `out_of_scope` never silently becomes `fail`; coverage = pass/(pass+fail) | `test_compliance{,_na,_tristate}.py` |
| **E — benchmark true-miss (P7, hermetic)** | ours vs FROZEN Trusera+Cisco oracle snapshots on the synthetic fixture = 0 true-misses; full model recall | `test_benchmark_gate.py` (→ `bench/ci_gate.py`, `bench/ci_baseline/`) + `test_model_recall.py` |
| **F — benchmark true-miss on real repos (P7, pinned)** | same gate on 2 representative repos (hf-model, tf-bedrock) cloned at a pinned SHA | `bench/ci_repos.sh` |

The per-PR P7 gate re-runs only OUR offline scanner against the FROZEN, committed
OSS oracle snapshots (`bench/ci_baseline/` + `bench/out/*.{trusera,cisco}.json`) —
no OSS tools / Bedrock / 71 MB clones in CI. A scanner change that starts dropping
an entity the oracles find (and that isn't a documented FP) fails the build.

## Nightly (`.github/workflows/aibom-nightly.yml`)
LIVE runs Trusera + Cisco(Bedrock) + ours on all 11 repos (`bench/run_all.sh`) and
gates true-miss=0 across the full set (`bench/diff.py`). Needs the OSS tools on PATH
+ `AWS_*` repo secrets for Bedrock.

## Goldens locked
- emit goldens: `aibom/examples/*/expected/*.{cdx,spdx}.json` (Gate C).
- frozen OSS oracle snapshots: `bench/ci_baseline/` + `bench/out/*.{trusera.cdx,cisco}.json`.
- FP-exclusions (84 justified rules): `bench/fp-exclusions.{json,md}`.

## Re-run the full 10-repo benchmark (locally)
```
uv tool install ai-bom                                      # Trusera
uv tool install --python 3.13 "cisco-aibom[agentic,llm-aws]"  # Cisco
set -a; source RabbitMQ/worker/.env; set +a                 # AWS creds for Bedrock
MAXJ=3 bash bench/run_all.sh                                 # all 3 tools × 11 repos
python3 bench/diff.py                                        # report.md + gate (exit 1 on true-miss)
```
Per-PR subset: `pytest aibom/tests/test_benchmark_gate.py` + `bash bench/ci_repos.sh`.

## Collision note
This gate set was built jointly with the parallel session (it authored the workflow
Gates A–F + `test_benchmark_gate.py` + `test_model_recall.py` + the nightly). I
completed the missing supporting harness its CI referenced but didn't ship:
`bench/ci_gate.py`, `bench/ci_baseline/`, `bench/ci_repos.sh`, `bench/run_all.sh`,
`bench/.gitignore` (so committing the harness never pulls in the large clones), and
this state file. See [[aibom-oss-benchmark]].
