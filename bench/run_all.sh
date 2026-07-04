#!/usr/bin/env bash
# bench/run_all.sh — nightly: LIVE-run all three tools (Trusera + Cisco/Bedrock +
# ours) on every repo in repos.tsv (the synthetic fixture + the 10 real repos),
# with bounded parallelism. Then run `python3 diff.py` to gate true-miss=0.
#
# Requires the OSS tools on PATH (~/.local/bin via `uv tool install ai-bom` +
# `uv tool install --python 3.13 "cisco-aibom[agentic,llm-aws]"`) and AWS_* creds
# for Cisco's Bedrock pass. Env: MAXJ (parallel repos, default 3); BEDROCK_MODEL.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.local/bin:$PATH"
MAXJ="${MAXJ:-3}"

# every non-comment repo id from the manifest
ids=$(grep -vE '^[[:space:]]*#' "$HERE/repos.tsv" | awk -F'\t' 'NF>=1 && $1!="" {print $1}')
echo "Nightly benchmark: $(echo "$ids" | wc -w | tr -d ' ') repos, ${MAXJ} parallel"
printf '%s\n' $ids | xargs -P "$MAXJ" -I {} bash "$HERE/run.sh" {}
echo "All scans complete — run 'python3 $HERE/diff.py' to produce report.md + gate."
