#!/usr/bin/env bash
# bench/cbom/run_all.sh — nightly: LIVE-run BOTH tools (cbomkit-theia oracle +
# ours) on every repo in repos.tsv, with bounded parallelism, then `diff.py` to
# gate true-miss=0 AND our-unique>0. Requires docker + the cbomkit-theia image.
# Env: MAXJ (parallel repos, default 2 — docker is the bottleneck).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MAXJ="${MAXJ:-2}"

ids=$(grep -vE '^[[:space:]]*#' "$HERE/repos.tsv" | awk -F'\t' 'NF>=1 && $1!="" {print $1}')
echo "Nightly CBOM benchmark: $(echo "$ids" | wc -w | tr -d ' ') repos, ${MAXJ} parallel"
printf '%s\n' $ids | xargs -P "$MAXJ" -I {} bash "$HERE/run.sh" {}
echo "All scans complete — run 'python3 $HERE/diff.py' to produce report.md + gate."
