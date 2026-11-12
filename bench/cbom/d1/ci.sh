#!/usr/bin/env bash
# CI entry of the D1 benchmark lane (job `cbom-d1` in .github/workflows/ci.yml, working directory aibom/, after
# `uv sync --frozen --all-extras --dev`). Unit tests first, then the lane; report.md goes to the job summary and the
# work files to test-reports/cbom-d1 (uploaded as the job's artifact). Exit: the lane's (0 pass, 1 floor, 2 not judged).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="$ROOT/aibom/.venv/bin/python"
OUT="${GITHUB_WORKSPACE:-$ROOT}/test-reports/cbom-d1"
WORK="${RUNNER_TEMP:-/tmp}/cbom-d1"
rm -rf "$WORK" && mkdir -p "$OUT" "$WORK"
start=$(date +%s)

python3 "$HERE/d1.py" prepare --work "$WORK"; rc=$?
if [ "$rc" -eq 0 ]; then
  python3 "$HERE/d1.py" product --work "$WORK" --python "$PY"; rc=$?
fi
if [ "$rc" -eq 0 ]; then
  python3 "$HERE/d1.py" score --work "$WORK" --out "$OUT"; rc=$?
fi
# unit tests, including the failing-first ones that need the fetched benchmarks (D1_WORK)
D1_WORK="$WORK" "$PY" -m pytest -q -p no:cacheprovider -o addopts= --rootdir "$HERE" "$HERE/tests" \
  --junitxml="$OUT/junit.xml" || { [ "$rc" -eq 0 ] && rc=1; }

cp -r "$WORK/cases" "$WORK/observed" "$WORK/osv.json" "$OUT/" 2>/dev/null || true
secs=$(( $(date +%s) - start ))
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  if [ -f "$OUT/report.md" ]; then cat "$OUT/report.md" >> "$GITHUB_STEP_SUMMARY"; fi
  echo "D1 lane: exit $rc in ${secs} s (0 pass, 1 floor failed, 2 not judged)." >> "$GITHUB_STEP_SUMMARY"
fi
echo "D1 lane: exit $rc in ${secs} s"
exit "$rc"
