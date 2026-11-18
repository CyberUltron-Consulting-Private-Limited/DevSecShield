#!/usr/bin/env bash
# F1.1 re-bench on ONE dedicated box (c6i.xlarge class, Amazon Linux 2023): the devil's-advocate matrix
# (f1-1/DEVILS-ADVOCATE.md section 5.4), run in priority order.
#
#   ec2_bench.sh setup                 # docker, uv, Python 3.12, the backend venv, postgres:15-alpine
#   ec2_bench.sh run <scenario...>     # E0 E1 E2a E2b E5 E4a E4b E7 E6 E1b; artefacts in $ROOT/results/<scenario>/
#   ec2_bench.sh summary               # one line per scenario: valid, pass, the failing gates
#
# $ROOT (default /opt/f1) holds after/{backend,bench} (the branch).  No secret is shipped: the database password and
# JWT/encryption keys are generated on the box (stack.sh).  Pinning (V1): gunicorn, the reaper and PostgreSQL on
# vCPUs 0-2, the simulator on vCPU 3.  3 gunicorn workers; dispatch 25 claims/s per worker (75/s).
set -euo pipefail
ROOT=${F1_ROOT:-/opt/f1}
B=$ROOT/after/bench/f1_node_api
export F1_VENV=$ROOT/venv F1_WORKERS=3 F1_PIN_SERVER=0-2 F1_PIN_SIM=3 F1_API_PORT=18080 F1_PG_NAME=f1-1-bench-pg
export CBOM_DISPATCH_PER_WORKER_S=${CBOM_DISPATCH_PER_WORKER_S:-25}
cmd=${1:?setup|run|summary}; shift || true

if [[ $cmd == setup ]]; then
  dnf install -y -q docker tar gzip python3-pip util-linux iproute procps-ng >/dev/null
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
  for d in "$ROOT"/results/*/; do
    [[ -f $d/gates.json ]] || continue
    "$F1_VENV/bin/python" - "$d/gates.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
fails = [f"{x['gate']}={x['value']}" for x in g["gates"] if x["pass"] is False]
print(json.dumps({"scenario": g["scenario"], "valid": g["valid"], "pass": g["pass"], "invalid": g["invalid_because"],
                  "fails": fails}, default=str))
PY
  done
  exit 0
fi

mkdir -p "$ROOT/results" "$ROOT/work"
W=$ROOT/work
seg=(--assign segment)
for scenario in "$@"; do
  echo "=== $(date -u +%T) $scenario"
  unset CBOM_JOB_LEASE_S F1_BENCH_CAP_KIND
  export F1_REAPER=1
  ideal=()
  case $scenario in
    E0)   seed=(--nodes 1000 --sources 0 "${seg[@]}"); sim=(--duration 120 --warmup 30) ;;
    E1|E1b) seed=(--nodes 10000 --sources 0 "${seg[@]}")
          dur=600; [[ $scenario == E1b ]] && dur=300
          sim=(--duration "$dur" --warmup 60) ;;
    E2a|E2b) seed=(--nodes 10000 --sources 10000 "${seg[@]}")
          sim=(--warmup 60 --duration 1 --run --mix --run-timeout 600) ;;
    E5)   export F1_BENCH_CAP_KIND=linux_servers:bench_x
          seed=(--nodes 10000 --sources 10000 --team-b-nodes 201 --team-b-sources 1000 --closed-window-team 1 "${seg[@]}")
          sim=(--warmup 60 --duration 1 --run --mix --runs "0:1,0:2" --open-window "300:1" --cap-x bench_x
               --cap-x-ranges "0:10000,10200:10201" --run-timeout 900) ;;
    E4a)  seed=(--nodes 500 --sources 10000 "${seg[@]}"); sim=(--warmup 60 --duration 1 --run --mix --run-timeout 600) ;;
    E4b)  seed=(--nodes 500 --sources 10000 "${seg[@]}"); ideal=(--ideal-s 300)
          sim=(--warmup 60 --duration 1 --run --mix --work-s 30 --run-timeout 900) ;;
    E7)   export CBOM_JOB_LEASE_S=60  # raised to the 600 s floor (D4)
          seed=(--nodes 10000 --sources 10000 "${seg[@]}")
          sim=(--warmup 60 --duration 1 --run --mix --work-s 10 --kill-frac 0.05 --kill-at 30 --run-timeout 1000
               --at "90=kill -HUP \$(cat $W/gunicorn.pid)"
               --at "180=$B/stack.sh stop-api $W"
               --at "270=F1_KEEP_REAPER=1 $B/stack.sh up $ROOT/after $W 3") ;;
    E6)   seed=(--nodes 10000 --sources 10000 "${seg[@]}")
          sim=(--warmup 60 --duration 1 --run --mix --p1-frac 0.1 --run-timeout 600) ;;
    *) echo "unknown scenario $scenario" >&2; exit 2 ;;
  esac
  "$B/run_bench.sh" "$ROOT/after" "$W" "$scenario" "${seed[@]}" -- "${sim[@]}" > "$ROOT/results/$scenario.out" 2>&1 \
    || echo "scenario $scenario FAILED (see $scenario.out)"
  if [[ ${#ideal[@]} -gt 0 ]]; then
    "$F1_VENV/bin/python" "$B/report.py" --name "$scenario" --dir "$W/$scenario" "${ideal[@]}" > "$W/$scenario/gates.json" || true
  fi
  rm -rf "$ROOT/results/$scenario"; cp -r "$W/$scenario" "$ROOT/results/$scenario"
  tar -C "$ROOT/results" -czf "$ROOT/results/$scenario.tgz" "$scenario" "$scenario.out"
  echo "=== $(date -u +%T) $scenario done: $(sha256sum "$ROOT/results/$scenario.tgz" | cut -c1-16)"
done
