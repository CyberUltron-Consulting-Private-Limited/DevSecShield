#!/usr/bin/env bash
# CBOM nightly waves (CB-35, DEVILS-ADVOCATE.md §4.5): every wave of e2e/cbom/waves.yaml on one SHA, the live steps in
# two stack.lock holds, then the nightly report and an issue draft per new failure.
#
#   e2e/cbom/run-waves.sh [options]
#     --ref REF           what to test (default dev; fetched first)
#     --waves LIST        comma-separated waves (default: all)
#     --hermetic          no Tier-L stack here (a GitHub-hosted runner): live steps are NOT-RUN, no lock is taken
#     --root DIR          nightly runs go under DIR (default $R6/cbom/nightly); the previous one there is compared
#     --file-issues       also open a GitHub issue per new failure (gh, the operator's login); default: drafts only
#   CBOM_WAVES_PYTHON (default python3) runs the harness; CBOM_WAVES_BACKEND_PYTEST / CBOM_WAVES_NODE_PYTEST the suites.
#
# Tier-L cron (the owner's host, after the gate's daytime use):  15 20 * * *  <repo>/e2e/cbom/run-waves.sh
# Locks: hold A then hold B on $R6/locks/stack.lock (each <= hold_budget_min, released in between so other sessions
# can run their gate), then the stack back on dev in its own hold. Exit: 0 nothing failed, 1 a step failed, 2 could
# not run. The last line printed is the sha256 of report.json.
set -euo pipefail
R6=${R6:-/home/claude/round6}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
REF=dev WAVES="" HERMETIC=0 ROOT=$R6/cbom/nightly FILE=0
while [ $# -gt 0 ]; do
  case $1 in
    --ref) REF=$2; shift 2 ;;
    --waves) WAVES=$2; shift 2 ;;
    --hermetic) HERMETIC=1; shift ;;
    --root) ROOT=$2; shift 2 ;;
    --file-issues) FILE=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
PY=${CBOM_WAVES_PYTHON:-python3}  # the harness needs PyYAML (the backend's venv has it)
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
git -C "$REPO" fetch -q origin "+refs/heads/dev:refs/remotes/origin/dev" || true
SHA=$(git -C "$REPO" rev-parse --verify "${REF}^{commit}" 2>/dev/null || git -C "$REPO" rev-parse --verify "origin/${REF}^{commit}") || exit 2
[ "$(git -C "$REPO" rev-parse HEAD)" = "$SHA" ] || log "note: this checkout is at $(git -C "$REPO" rev-parse --short HEAD); the hermetic steps test it, the gate steps restack to ${SHA:0:12}"
mkdir -p "$ROOT"
RUN="$ROOT/N-${SHA:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$RUN"
log "nightly waves on ${SHA:0:12} into $RUN"
args=(run "$RUN" --sha "$SHA" --mode nightly)
[ -n "$WAVES" ] && args+=(--waves "$WAVES")
if [ "$HERMETIC" = 1 ]; then args+=(--hermetic); else args+=(--lock "$R6/locks/stack.lock"); fi
rc=0
(cd "$HERE" && "$PY" -m harness.waves "${args[@]}") > "$RUN/waves.log" 2>&1 || rc=$?
[ "$rc" -le 1 ] || { log "the wave runner could not run (exit $rc); see $RUN/waves.log"; exit 2; }
iss=(issues "$RUN")
[ "$FILE" = 1 ] && iss+=(--file)
(cd "$HERE" && "$PY" -m harness.waves "${iss[@]}") || log "issue drafts not written"
if [ "$HERMETIC" = 0 ] && [ -x "$R6/local/restack.sh" ] && [ "$SHA" != "$(git -C "$REPO" rev-parse origin/dev)" ]; then
  log "restack dev"
  flock "$R6/locks/stack.lock" "$R6/local/restack.sh" dev || log "restack dev FAILED: tell the coordinator"
fi
log "nightly exit $rc; report $RUN/report.md"
sha256sum "$RUN/report.json" | awk '{print "report.json sha256 " $1}'
exit "$rc"
