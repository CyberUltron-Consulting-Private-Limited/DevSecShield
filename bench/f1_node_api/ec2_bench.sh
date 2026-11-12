#!/usr/bin/env bash
# F1.1 bench on a dedicated box (Amazon Linux 2023), "before" (dev) and "after" (branch) with the same parameters.
#
#   ec2_bench.sh setup                # docker, uv, Python 3.12, the backend venv, postgres:15-alpine
#   ec2_bench.sh run <scenario...>    # scenarios below; results in $ROOT/results/<scenario>.json
#   ec2_bench.sh summary              # one compact line per finished scenario
#
# $ROOT (default /opt/f1) holds before/{backend,scan_node}, after/{backend,scan_node} and after/bench/f1_node_api.
# No secret is shipped: the database password and JWT/encryption keys are generated on the box (stack.sh).
set -euo pipefail
ROOT=${F1_ROOT:-/opt/f1}
B=$ROOT/after/bench/f1_node_api
export F1_VENV=$ROOT/venv
export F1_WORKERS=${F1_WORKERS:-3}
cmd=${1:?setup|run|summary}; shift || true

if [[ $cmd == setup ]]; then
  dnf install -y -q docker tar gzip python3-pip >/dev/null
  systemctl start docker
  python3 -m pip install -q uv
  export PATH=/usr/local/bin:$PATH
  uv python install 3.12 >/dev/null
  (cd "$ROOT/after/backend" && UV_PROJECT_ENVIRONMENT=$F1_VENV uv sync --frozen --python 3.12 -q)
  docker pull -q postgres:15-alpine >/dev/null
  echo "setup done: $($F1_VENV/bin/python --version), $(docker --version), $(nproc) vCPU, $(free -g | awk '/Mem/{print $2}') GB"
  exit 0
fi

if [[ $cmd == summary ]]; then
  for f in "$ROOT"/results/*.json; do
    "$F1_VENV/bin/python" - "$f" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
lat = d["latency"]
out = {"scenario": os.path.basename(sys.argv[1])[:-5], "req_per_s": d["req_per_s"], "measured_s": d["measured_s"],
       "all": lat["all"], "by_call": {k: v for k, v in lat.items() if k != "all"}, "errors": d["errors"],
       "error_rate": d["error_rate"], "error_kinds": d["error_kinds"], "cpu": d["cpu_pct_of_one_cpu"],
       "lag": d["sim_loop_lag_ms"],
       "db": {k: d["db"].get(k) for k in ("tps_avg", "tps_peak", "statements_per_s", "calls", "nonce_inserts",
                                          "nonce_rows")},
       "run": {k: v for k, v in d["run"].items() if k not in ("timeline",)}}
print(json.dumps(out, separators=(",", ":")))
PY
  done
  exit 0
fi

mkdir -p "$ROOT/results" "$ROOT/work"
for scenario in "$@"; do
  echo "=== $(date -u +%T) $scenario"
  unset CBOM_JOB_LEASE_S
  export F1_REAPER=0
  case $scenario in
    before-steady)  src=before; seed=(--nodes 10000 --sources 0 --assign pinned)
                    sim=(--protocol 1 --hb-override 60 --no-claims --duration 600 --warmup 60 --spread 60) ;;
    after-steady)   src=after; seed=(--nodes 10000 --sources 0 --assign pinned)
                    sim=(--protocol 2 --duration 600 --warmup 60 --spread 60) ;;
    after-steady-p1) src=after; seed=(--nodes 10000 --sources 0 --assign pinned)
                    sim=(--protocol 1 --duration 180 --warmup 30) ;;
    # dev's own fleet behaviour (scan node 1.0 on dev: heartbeat every 30 s, a claim poll every 5 s per node)
    before-real)    src=before; seed=(--nodes 10000 --sources 0 --assign pinned)
                    sim=(--protocol 1 --duration 300 --warmup 60) ;;
    before-run)     src=before; seed=(--nodes 10000 --sources 10000 --assign pinned); export F1_REAPER=1
                    sim=(--protocol 1 --warmup 30 --duration 1 --run --run-timeout 600) ;;
    after-run)      src=after; seed=(--nodes 10000 --sources 10000 --assign segment); export F1_REAPER=1
                    sim=(--protocol 2 --warmup 75 --spread 60 --duration 1 --run --run-timeout 600) ;;
    after-run-kill) src=after; seed=(--nodes 10000 --sources 10000 --assign segment); export F1_REAPER=1
                    export CBOM_JOB_LEASE_S=120
                    sim=(--protocol 2 --warmup 75 --spread 60 --duration 1 --run --run-timeout 900 --kill-frac 0.05) ;;
    *) echo "unknown scenario $scenario" >&2; exit 2 ;;
  esac
  "$B/run_bench.sh" "$ROOT/$src" "$ROOT/work" "$scenario" "${seed[@]}" -- "${sim[@]}" || echo "scenario $scenario FAILED"
  cp "$ROOT/work/$scenario.json" "$ROOT/results/" 2>/dev/null || true
  cp "$ROOT/work/$scenario.server-log.txt" "$ROOT/results/" 2>/dev/null || true
  cp "$ROOT/work/reaper.log" "$ROOT/results/$scenario.reaper.log" 2>/dev/null || true
done
echo "=== $(date -u +%T) done"
