#!/usr/bin/env bash
# CI entry of the D1 benchmark lane (job `cbom-d1` in .github/workflows/ci.yml, working directory aibom/, after
# `uv sync --frozen --all-extras --dev`). The floors check, the lane, then the unit tests; report.md goes to the job
# summary and the work files to test-reports/cbom-d1 (uploaded as the job's artifact).
# Exit: the lane's (0 pass, 1 floor failed or loosened, 2 not judged).
#
# Floors only rise: floors.json is compared with the base's copy (`d1.py check-floors`). D1_FLOORS_BASE wins; in
# GitHub Actions the base is HEAD^1 (the job checks out the PR's merge commit with fetch-depth 2, whose first parent
# is the base branch; on a push it is the previous tip); locally it is origin/dev.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="$ROOT/aibom/.venv/bin/python"
OUT="${GITHUB_WORKSPACE:-$ROOT}/test-reports/cbom-d1"
WORK="${RUNNER_TEMP:-/tmp}/cbom-d1"
rm -rf "$WORK" && mkdir -p "$OUT" "$WORK"
start=$(date +%s)
if [ -z "${D1_FLOORS_BASE:-}" ]; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then D1_FLOORS_BASE="HEAD^1"; else D1_FLOORS_BASE="origin/dev"; fi
fi
export D1_FLOORS_BASE

python3 "$HERE/d1.py" check-floors --base "$D1_FLOORS_BASE" > "$OUT/check-floors.txt" 2>&1; frc=$?
cat "$OUT/check-floors.txt"
python3 "$HERE/d1.py" prepare --work "$WORK"; rc=$?
if [ "$rc" -eq 0 ]; then
  python3 "$HERE/d1.py" product --work "$WORK" --python "$PY"; rc=$?
fi
if [ "$rc" -eq 0 ]; then
  python3 "$HERE/d1.py" score --work "$WORK" --out "$OUT"; rc=$?
fi
[ "$rc" -eq 0 ] && rc=$frc
# unit tests, including the failing-first ones that need the fetched benchmarks (D1_WORK) and test_floors_only_rise
# (D1_FLOORS_BASE)
D1_WORK="$WORK" "$PY" -m pytest -q -p no:cacheprovider -o addopts= --rootdir "$HERE" "$HERE/tests" \
  --junitxml="$OUT/junit.xml" || { [ "$rc" -eq 0 ] && rc=1; }

cp -r "$WORK/cases" "$WORK/observed" "$WORK/osv.json" "$OUT/" 2>/dev/null || true
secs=$(( $(date +%s) - start ))
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  if [ -f "$OUT/report.md" ]; then cat "$OUT/report.md" >> "$GITHUB_STEP_SUMMARY"; fi
  { echo; echo "Floors check against \`$D1_FLOORS_BASE\` (exit $frc):"; echo; sed 's/^/    /' "$OUT/check-floors.txt"; echo; } >> "$GITHUB_STEP_SUMMARY"
  echo "D1 lane: exit $rc in ${secs} s (0 pass, 1 floor failed or loosened, 2 not judged)." >> "$GITHUB_STEP_SUMMARY"
fi
echo "D1 lane: exit $rc in ${secs} s"
exit "$rc"
