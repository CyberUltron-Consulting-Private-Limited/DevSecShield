#!/usr/bin/env bash
# One F1.1 bench scenario end to end: PostgreSQL up, seed, backend up, simulate, collect, everything down.
#
#   bench/f1_node_api/run_bench.sh <src-root> <workdir> <name> <seed args...> -- <sim args...>
#
# e.g. (on the shared lab machine, always under the heavy-tests lock):
#   flock $L/heavy-tests.lock bench/f1_node_api/run_bench.sh . /scratch/f1 p2-steady \
#       --nodes 10000 --sources 0 --assign pinned -- --protocol 2 --duration 600 --warmup 60
# Result: <workdir>/<name>.json (the simulator's report) and <workdir>/<name>.gunicorn.log.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "${1:?src root}" && pwd); work=${2:?workdir}; name=${3:?name}; shift 3
seed_args=(); while [[ $# -gt 0 && $1 != -- ]]; do seed_args+=("$1"); shift; done
[[ ${1:-} == -- ]] && shift
VENV=${F1_VENV:-/home/claude/devsecshield/backend/.venv}
WORKERS=${F1_WORKERS:-2}
mkdir -p "$work"
trap '"$here/stack.sh" down "$work" >/dev/null 2>&1 || true' EXIT
"$here/stack.sh" down "$work" >/dev/null 2>&1 || true
rm -f "$work/env"
F1_SKIP_API=1 "$here/stack.sh" up "$src" "$work"
set -a; . "$work/env"; set +a
db=$(cat "$work/db_url")
PYTHONPATH="$src" "$VENV/bin/python" "$here/seed.py" --db "$db" --creds "$work/creds.json" --yes-drop-everything \
  "${seed_args[@]}"
"$here/stack.sh" up "$src" "$work" "$WORKERS"
master=$(cat "$work/gunicorn.pid")
pids="$master,$(pgrep -P "$master" | paste -sd,)"
cd "$src/backend"
PYTHONPATH="$src" "$VENV/bin/python" "$here/sim.py" --api "http://127.0.0.1:${F1_API_PORT:-18080}" \
  --creds "$work/creds.json" --db "$db" --pg-container "${F1_PG_NAME:-f1bench-pg}" --server-pids "$pids" \
  --out "$work/$name.json" "$@" > /dev/null
# the server log can reach hundreds of MB under overload: keep its error counts and its tail only
{ echo "tracebacks: $(grep -c Traceback "$work/gunicorn.log" || true)"
  echo "lines: $(wc -l < "$work/gunicorn.log")"
  grep -oE "(ref [A-Za-z0-9-]+|[A-Za-z]+(Error|Exception|Timeout)\b)" "$work/gunicorn.log" | sort | uniq -c | sort -rn | head -20
  echo "--- tail"; tail -n 60 "$work/gunicorn.log"; } > "$work/$name.server-log.txt" 2>&1 || true
python3 - "$work/$name.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(json.dumps({"rate": d["req_per_s"], "all": d["latency"]["all"], "errors": d["errors"],
                  "cpu": d["cpu_pct_of_one_cpu"], "db_tps": d["db"].get("tps_avg"),
                  "stmts_per_s": d["db"].get("statements_per_s"), "nonce_inserts": d["db"].get("nonce_inserts"),
                  "lag": d["sim_loop_lag_ms"], "run": {k: v for k, v in d["run"].items() if k != "timeline"}}))
PY
