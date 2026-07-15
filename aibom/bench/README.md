# AI-BOM benchmark harness (`bench/`)

**ISOLATED — not product code.** Live-runs three AI-BOM tools on real repos and
diffs their findings. Nothing here is imported by `aibom/src`.

## Tools
| tool | install | invocation | notes |
|------|---------|-----------|-------|
| **Trusera** | `uv tool install ai-bom` | `ai-bom scan <p> -f cyclonedx -o …` | baseline L1 (no `--deep`, no LLM) for reproducibility |
| **Cisco** | `uv tool install --python 3.13 "cisco-aibom[agentic,llm-aws]"` | `cisco-aibom analyze <p> -o json -O … --llm-provider bedrock --llm-model global.anthropic.claude-haiku-4-5-20251001-v1:0` | **mandatory agentic LLM pass via Bedrock Haiku 4.5** (`AWS_REGION=us-east-1`); real spend |
| **Ours** | (this repo) | `aibom emit <p> -f cyclonedx -o …` | |

## Run
```
bash bench/run_all.sh          # clone + run 3 tools on every repo (MAXJ=3 concurrent)
cd bench && python diff.py     # build report.md + gate
```
- `repos.txt` — repo manifest (url | subdir-scope | flags). Big repos are scoped to
  a representative subdir to bound Cisco's Bedrock cost (the runner falls back to the
  whole repo if the subdir moved). `repo0-synthetic` (local fixture) and `chroma`
  (existing gitignored clone) are handled directly in `run_all.sh`.
- SHAs recorded per repo in `out/shas.json`.

## Compare
- `normalize.py` — canonical key `(normalized_name, type_class)`; matching rules
  documented in its header (name-first classification so the same entity lands in the
  same class regardless of each tool's vocabulary).
- `diff.py` — Misses = (Cisco ∪ Trusera) \ Ours; OurUnique = Ours \ (Cisco ∪ Trusera).
  Each raw Miss is triaged via `fp_exclusions.json` into TRUE miss vs OSS false-positive.
- **Gate:** total true-misses = 0 AND total our-unique > 0.
- `fp-exclusions.md` — human-readable justification for every excluded OSS finding.

## Resource notes (no silent caps)
- Disk ~21 GB free → shallow clones (`--depth 1`), HF weights skipped (`nolfs`),
  clones deleted after scanning.
- Repos run with bounded concurrency (`MAXJ`, default 3) rather than all-at-once.
- `langchain` Cisco can hang on its many HuggingFace model lookups; it is killed and
  diffed against Trusera + ours only (use `--skip-unchanged` for a Cisco baseline).

## Re-running the FULL 10-repo benchmark
```
# one-time: install the oracles
uv tool install ai-bom
uv tool install --python 3.13 "cisco-aibom[agentic,llm-aws]"
export AWS_REGION=us-east-1            # Cisco agentic pass -> Bedrock Haiku 4.5
export AIBOM_BEDROCK_MODEL=global.anthropic.claude-haiku-4-5-20251001-v1:0

MAXJ=3 bash bench/run_all.sh          # clone + Trusera + Cisco + ours on all repos
cd bench && python diff.py            # diff matrix + P7 gate -> report.md (exit 1 if true-misses)
```
`run_all.sh` clones chroma fresh when the local fixture is absent (so it works in CI too).

## CI regression gates (`.github/workflows/`)
**`aibom-gates.yml`** (per-PR, blocking — hermetic / pinned, no Bedrock):
- **A** differential recall vs committed oracles (`test_differential.py`)
- **B** chart-data contract — no chart can go empty (`test_chart_data_contract*`, `test_chart_contract_severity`, `test_dimension_parity`)
- **C** golden lock — CycloneDX / SPDX / SARIF / parity goldens (`test_emit/spdx/sarif/parity`)
- **D** compliance tri-state — out-of-scope ≠ fail (`test_compliance*`)
- **E** P7 true-miss gate (hermetic synthetic) + model recall vs the manifest (`test_benchmark_gate`, `test_model_recall`)
- **F** P7 true-miss gate on 2 representative real repos (hf-model, tf-bedrock) cloned at a **pinned SHA**, diffed vs the FROZEN oracles in `ci_baseline/` (`bench/ci_repos.sh`)

**`aibom-nightly.yml`** (scheduled / dispatch): the FULL live 10-repo benchmark
(installs Trusera + Cisco, runs `run_all.sh` + `diff.py`, uploads `report.md`).
Needs `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` repo secrets for Bedrock.

The 71 MB chroma clone is gitignored → absent in CI, so the differential + compliance
chroma cases self-skip; the gates run on the committed `synthetic` fixture + the
pinned representative repos. Frozen oracle snapshots + pinned SHAs live in
`ci_baseline/` (`{synthetic,hf-model,tf-bedrock}.{trusera.cdx,cisco}.json`, `repos.json`).
