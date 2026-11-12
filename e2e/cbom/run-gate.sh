#!/usr/bin/env bash
# CBOM Tier-L gate runner (DEVILS-ADVOCATE.md §4): replay the customer user flow in real Chromium against the local
# dss-staging stack built from <ref>, judge every row (UI / API / DB / export / logs / oracle) and bundle the evidence.
#
#   e2e/cbom/run-gate.sh <ref> [options]
#     --lab-dir DIR       a checkout whose e2e/cbom/lab/gen.py is the CB-02 lab (default: this checkout)
#     --node-image IMG    image to run when the UI's node image is not on this stack (pre-CB-03; recorded, G3 fails)
#     --skip-restack      the stack already runs <ref> (checked against STACK.md)
#     --no-return         leave the stack on <ref> (default: restack.sh dev afterwards)
#     --steps G1,G2,...   flow steps to run (default: all)
#     --runs-root DIR     default /home/claude/round6/cbom/runs
#
# Locks (TEAM-PROCESS): the restack and the gate each take $R6/locks/stack.lock for their own hold; the gate hold
# is budgeted at 45 minutes (G17 fails beyond it). Needs >= 1.5 GB available memory before it starts.
# Exit: 0 gate PASS, 1 gate FAIL, 2 could not run. The last line printed is the bundle's SHA256SUMS sha256.
set -euo pipefail

R6=${R6:-/home/claude/round6}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
LOCKS=$R6/locks
REF=${1:?usage: run-gate.sh <ref> [--lab-dir DIR] [--node-image IMG] [--skip-restack] [--no-return] [--steps LIST]}
shift
LAB_DIR=$REPO NODE_IMAGE="" SKIP_RESTACK=0 RETURN=1 STEPS="" RUNS_ROOT=$R6/cbom/runs
while [ $# -gt 0 ]; do
  case $1 in
    --lab-dir) LAB_DIR=$2; shift 2 ;;
    --node-image) NODE_IMAGE=$2; shift 2 ;;
    --skip-restack) SKIP_RESTACK=1; shift ;;
    --no-return) RETURN=0; shift ;;
    --steps) STEPS=$2; shift 2 ;;
    --runs-root) RUNS_ROOT=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
avail_mb() { free -m | awk '/^Mem:/ {print $7}'; }
git -C "$REPO" fetch -q origin "+refs/heads/dev:refs/remotes/origin/dev" || true
SHA=$(git -C "$REPO" rev-parse --verify "${REF}^{commit}" 2>/dev/null || git -C "$REPO" rev-parse --verify "origin/${REF}^{commit}")
[ "$(avail_mb)" -ge 1536 ] || { log "only $(avail_mb) MB available (< 1536): not starting"; exit 2; }

# 1. the stack at <ref> (its own lock hold)
if [ "$SKIP_RESTACK" = 1 ]; then
  grep -q "^READY ${SHA:0:7}" "$R6/local/STACK.md" || { log "--skip-restack but STACK.md is not READY at ${SHA:0:7}"; exit 2; }
else
  log "restack $SHA"
  flock "$LOCKS/stack.lock" "$R6/local/restack.sh" "$SHA"
fi

# 2. the gate (one hold, <= 45 min)
RUN=$(cd "$HERE" && python3 -c "import sys; from harness import rundir; print(rundir.create(sys.argv[1], sys.argv[2]))" "$RUNS_ROOT" "$SHA")
export CBOM_E2E_RUN_DIR=$RUN
SECRETS=$(mktemp /tmp/cbom-e2e-secrets.XXXXXX)
chmod 600 "$SECRETS"
log "run directory $RUN"

gate() {
  set -euo pipefail
  local started; started=$(date -u +%FT%TZ)
  cd "$HERE"
  local gen=$LAB_DIR/e2e/cbom/lab/gen.py
  # the lab is a singleton (cbom-e2e-net, cbom-e2e-*): hold its lock from up to down (INTERFACES.md v3)
  exec 9> "$LOCKS/cbom-lab.lock"
  flock 9
  if [ -f "$gen" ]; then
    log "lab up ($gen)"
    python3 "$gen" up --run-dir "$RUN" > "$RUN/lab/gen-up.log" 2>&1 || log "lab up failed (exit $?); see lab/gen-up.log"
    python3 "$gen" selfcheck --run-dir "$RUN" > "$RUN/lab/selfcheck.log" 2>&1 || log "lab self-check disagreed (exit $?)"
  else
    log "no lab at $gen: lab rows will be NOT-RUN"
  fi
  python3 -m harness.gate freeze-oracle "$RUN" > /dev/null
  python3 -m harness.bundle manifest "$RUN" --sha "$SHA" --ref "$REF" --started "$started" ${NODE_IMAGE:+--node-image "$NODE_IMAGE"}
  log "G0 pre-flight"
  python3 -m harness.preflight "$RUN" --sha "$SHA" --repo "$REPO" ${NODE_IMAGE:+--node-image "$NODE_IMAGE"}
  log "customer flow (Chromium)"
  ( cd "$R6/local/pw" && env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy \
      PLAYWRIGHT_BROWSERS_PATH="$R6/local/pw/browsers" node "$HERE/flow/gate.mjs" --run-dir "$RUN" --sha "$SHA" \
      --secrets-file "$SECRETS" ${NODE_IMAGE:+--node-image "$NODE_IMAGE"} ${STEPS:+--steps "$STEPS"} ) \
      2>&1 | tee "$RUN/steps/flow.log" || log "flow exited non-zero"
  local teams runs
  teams=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(','.join(str(v) for v in (d.get('teams') or {}).values()))" "$RUN/flow-state.json" 2>/dev/null || true)
  runs=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(','.join(str(v) for v in d.get('runs') or []))" "$RUN/flow-state.json" 2>/dev/null || true)
  local t_harness; t_harness=$(date +%s)
  if [ -n "$teams" ]; then
    log "collect evidence (teams $teams, runs ${runs:-none})"
    "$HERE/collect-evidence.sh" "$teams" "$runs" "$started" "$RUN" || log "collect-evidence incomplete"
  fi
  python3 -m harness.bundle manifest "$RUN" --sha "$SHA" --ref "$REF" --started "$started" ${NODE_IMAGE:+--node-image "$NODE_IMAGE"} > /dev/null
  # tear down what the gate started: the node container and volume, the lab
  local node vol
  node=$(python3 -c "import json,sys; print((json.load(open(sys.argv[1])).get('node') or {}).get('container') or '')" "$RUN/flow-state.json" 2>/dev/null || true)
  vol=$(python3 -c "import json,sys; print((json.load(open(sys.argv[1])).get('node') or {}).get('volume') or '')" "$RUN/flow-state.json" 2>/dev/null || true)
  [ -n "$node" ] && docker rm -f "$node" > /dev/null 2>&1 || true
  [ -n "$vol" ] && docker volume rm "$vol" > /dev/null 2>&1 || true
  [ -f "$gen" ] && { python3 "$gen" down --run-dir "$RUN" > "$RUN/lab/gen-down.log" 2>&1 || log "lab down failed"; }
  flock -u 9
  python3 -m harness.bundle seal "$RUN" --secrets-file "$SECRETS" --started "$started"
  log "judge"
  local rc=0
  python3 -m harness.gate judge "$RUN" || rc=$?
  echo "harness_seconds=$(( $(date +%s) - t_harness ))" >> "$RUN/steps/flow.log"
  return "$rc"
}
export -f gate log
export HERE RUN SHA REF REPO LAB_DIR NODE_IMAGE STEPS SECRETS R6 LOCKS
rc=0
flock "$LOCKS/stack.lock" bash -c gate || rc=$?
rm -f "$SECRETS"

# 3. the stack back on dev (its own hold), then the checksums
if [ "$RETURN" = 1 ] && [ "$SKIP_RESTACK" = 0 ]; then
  log "restack dev"
  flock "$LOCKS/stack.lock" "$R6/local/restack.sh" dev || log "restack dev FAILED: tell the coordinator"
fi
SUMS=$(cd "$HERE" && python3 -m harness.gate sums "$RUN")
(cd "$HERE" && python3 -m harness.gate verify "$RUN") >&2
log "gate exit $rc; report $RUN/report.md"
echo "SHA256SUMS sha256 $SUMS"
exit "$rc"
