#!/usr/bin/env bash
# One F1.1 bench scenario end to end: PostgreSQL up, seed, backend (and reaper) up, simulate, collect every artefact
# (V7), evaluate the gates, everything down.
#
#   bench/f1_node_api/run_bench.sh <src-root> <workdir> <name> <seed args...> -- <sim args...>
#
# e.g. (on the shared lab machine, always under the heavy-tests lock):
#   flock $L/heavy-tests.lock bench/f1_node_api/run_bench.sh . /scratch/f1 E1 \
#       --nodes 10000 --sources 0 --assign segment -- --duration 600 --warmup 60
# Result directory <workdir>/<name>/: sim.json (the simulator's report), trace.tsv (every attempt), server.log (the
# whole gunicorn log), reaper.log, pg.log (lock waits, deadlocks), db.json (run, money and job facts), gates.json
# (report.py: every gate and threshold of the scenario).  F1_PIN_SERVER / F1_PIN_SIM pin the server and the
# simulator to separate vCPUs (V1).  CBOM_NODE_STATS_S=10 so the server's stats lines cover the whole run.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "${1:?src root}" && pwd); work=${2:?workdir}; name=${3:?name}; shift 3
seed_args=(); while [[ $# -gt 0 && $1 != -- ]]; do seed_args+=("$1"); shift; done
[[ ${1:-} == -- ]] && shift
VENV=${F1_VENV:-/home/claude/devsecshield/backend/.venv}
WORKERS=${F1_WORKERS:-3}
PORT=${F1_API_PORT:-18080}
out=$work/$name
mkdir -p "$out"
export CBOM_NODE_STATS_S=${CBOM_NODE_STATS_S:-10}
collect() {
  cp "$work/gunicorn.log" "$out/server.log" 2>/dev/null || true
  cp "$work/reaper.log" "$out/reaper.log" 2>/dev/null || true
  docker logs "${F1_PG_NAME:-f1bench-pg}" > "$out/pg.log" 2>&1 || true
  if [[ -f $work/db_url ]]; then
    PYTHONPATH="$src" "$VENV/bin/python" "$here/facts.py" --db "$(cat "$work/db_url")" > "$out/db.json" 2>"$out/facts.err" || true
  fi
  "$VENV/bin/python" "$here/report.py" --name "$name" --dir "$out" > "$out/gates.json" 2>"$out/report.err" || true
}
trap 'collect; "$here/stack.sh" down "$work" >/dev/null 2>&1 || true' EXIT
"$here/stack.sh" down "$work" >/dev/null 2>&1 || true
rm -f "$work/env" "$work/gunicorn.log" "$work/reaper.log"
F1_SKIP_API=1 "$here/stack.sh" up "$src" "$work"
set -a; . "$work/env"; set +a
db=$(cat "$work/db_url")
PYTHONPATH="$src" "$VENV/bin/python" "$here/seed.py" --db "$db" --creds "$work/creds.json" --yes-drop-everything \
  "${seed_args[@]}" | tee "$out/seed.json"
"$here/stack.sh" up "$src" "$work" "$WORKERS"
master=$(cat "$work/gunicorn.pid")
pin=()
[[ -n ${F1_PIN_SIM:-} ]] && pin=(taskset -c "$F1_PIN_SIM")
lscpu -e > "$out/lscpu.txt" 2>/dev/null || true
free -m > "$out/free-before.txt" 2>/dev/null || true
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
cd "$src/backend"
PYTHONPATH="$src" "${pin[@]}" "$VENV/bin/python" "$here/sim.py" --api "http://127.0.0.1:$PORT" \
  --creds "$work/creds.json" --db "$db" --server-pid "$master" --port "$PORT" \
  --out "$out/sim.json" --trace "$out/trace.tsv" "$@" | tee "$out/sim-summary.json"
free -m > "$out/free-after.txt" 2>/dev/null || true
sleep $(( ${CBOM_NODE_STATS_S%.*} + 2 ))  # the server's last stats line
