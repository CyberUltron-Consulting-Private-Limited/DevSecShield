# bench/ — isolated AI-BOM benchmark harness (NOT product code)

Live-runs two OSS oracles + our tool on real repos and produces a true-positive
diff matrix. Nothing here is imported by `aibom/` product code.

- `repos.tsv`     — the repo set (id, slug, clone URL, scan subdir, pinned SHA)
- `run.sh`        — clone (shallow, record SHA) + run all 3 tools per repo
- `normalize.py`  — extract a comparable {(canon_name, type_class)} set per tool
- `diff.py`       — per-repo + aggregate Misses / OurUnique / Overlap + triage
- `out/`          — raw tool outputs (<repo>.{trusera.cdx,cisco,ours.cdx}.json)
- `report.md`     — the aggregate diff matrix (the deliverable)
- `fp-exclusions.md` — every OSS finding excluded as a false positive, justified
- `state/`        — per-repo miss/unique counts + SHAs (= aibom/state/benchmark)

Tools (installed via `uv tool`, in ~/.local/bin):
- Trusera: `ai-bom scan <repo> -f cyclonedx -o ...`        (L1 baseline, no llm-enrich)
- Cisco:   `cisco-aibom analyze <repo> --llm-provider bedrock --llm-model <haiku> -o json -O ...`
- Ours:    `aibom emit <repo> -f cyclonedx -o ...`

## CI regression-lock (P7)
- `ci_baseline/`  — FROZEN Trusera+Cisco oracle snapshots for the CI-gated repos.
- `ci_gate.py`    — `true_misses(repo_id, ours.cdx)` vs `ci_baseline/` + FP-triage; `[]`=pass.
- `ci_repos.sh`   — Gate F: clones 2 representative repos (hf-model, tf-bedrock) at a
                    pinned SHA, runs OURS, asserts 0 true-misses (no OSS tools/Bedrock).
- `run_all.sh`    — nightly: all 3 tools × every repo in `repos.tsv` (then `diff.py`).
- `.gitignore`    — excludes the large clones (`repos/`) + regenerated `out/*.ours.cdx.json`.

The per-PR gates (`.github/workflows/aibom-gates.yml`, Gates E+F) re-run only OUR
offline scanner against the committed frozen oracles — hermetic. See
`aibom/state/regression-lock.md`.

## Re-run the FULL 10-repo benchmark (live; needs Bedrock spend)
```bash
# 1. install the two OSS oracles
uv tool install ai-bom                                          # Trusera
uv tool install --python 3.13 "cisco-aibom[agentic,llm-aws]"    # Cisco
export PATH="$HOME/.local/bin:$PATH"
# 2. AWS creds for Cisco's mandatory Bedrock LLM pass
set -a; source RabbitMQ/worker/.env; set +a
export AWS_REGION=ap-south-1 BEDROCK_MODEL=global.anthropic.claude-haiku-4-5-20251001-v1:0
# 3. clone + run Trusera + Cisco + ours on the synthetic fixture + all 10 real repos
MAXJ=3 bash bench/run_all.sh
# 4. produce report.md + gate (exit 1 if any TRUE-positive miss survives FP-triage)
python3 bench/diff.py
```
Add/repin a repo in `repos.tsv`; record its HEAD SHA (printed by `run.sh` into
`state/shas.tsv`). Triage every new miss in `fp-exclusions.json` (OSS FP, with a
grep-verified reason) or fix the scanner (real miss).
