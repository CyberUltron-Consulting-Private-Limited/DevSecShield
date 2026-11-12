#!/usr/bin/env bash
# F1.1 local prechecks L1-L5 (f1-1/DEVILS-ADVOCATE.md section 5.3) on the shared lab box: 3 workers, dispatch 10/s per
# worker (below local capacity, so the bucket binds, not the CPU).  L6 undelivered_probe.py, L7 old_node_live.py and
# L8 ab_bind.sh run on their own.  Run under `flock heavy-tests.lock`.
#   bench/f1_node_api/local_prechecks.sh <src-root> <workdir> [L1 L2 L3 L4 L5]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "${1:?src root}" && pwd); work=${2:?workdir}; shift 2
export F1_WORKERS=3 F1_REAPER=1 CBOM_DISPATCH_PER_WORKER_S=10
VENV=${F1_VENV:-/home/claude/devsecshield/backend/.venv}
mkdir -p "$work"
for name in "${@:-L1 L2 L3 L4 L5}"; do
  unset F1_BENCH_CAP_KIND
  ideal=()
  case $name in
    L1) seed=(--nodes 2 --sources 200 --assign pinned --big-frac 0); ideal=(--ideal-s 100)
        sim=(--run --run-before-nodes --work-s 2 --warmup 0 --spread 1 --duration 1 --run-timeout 400) ;;
    L2) seed=(--nodes 10 --sources 1000 --assign segment); ideal=(--ideal-s 250)
        sim=(--run --run-before-nodes --work-s 5 --warmup 0 --spread 1 --duration 1 --run-timeout 600) ;;
    L3) seed=(--nodes "${F1_LOCAL_NODES:-3000}" --sources "${F1_LOCAL_NODES:-3000}" --team-b-nodes 5 --team-b-sources 50 --assign segment)
        sim=(--run --runs "0:1,10:2" --warmup 60 --duration 1 --run-timeout 900) ;;
    L4) export F1_BENCH_CAP_KIND=linux_servers:bench_x
        seed=(--nodes "${F1_LOCAL_NODES:-3000}" --sources "${F1_LOCAL_NODES:-3000}" --team-b-nodes 201 --team-b-sources 300 --closed-window-team 1 --assign segment)
        sim=(--run --runs "0:1,0:2" --cap-x bench_x --cap-x-ranges "0:${F1_LOCAL_NODES:-3000},$(( ${F1_LOCAL_NODES:-3000} + 200 )):$(( ${F1_LOCAL_NODES:-3000} + 201 ))" --warmup 60 --duration 180
             --run-timeout 170) ;;
    L5) seed=(--nodes "${F1_LOCAL_NODES:-3000}" --sources "${F1_LOCAL_NODES:-3000}" --assign segment)
        sim=(--run --mix --warmup 60 --duration 1 --run-timeout 900) ;;
    *) echo "unknown $name" >&2; exit 2 ;;
  esac
  echo "=== $(date -u +%T) $name"
  "$here/run_bench.sh" "$src" "$work" "$name" "${seed[@]}" -- "${sim[@]}" > "$work/$name.out" 2>&1 || echo "$name FAILED"
  "$VENV/bin/python" "$here/report.py" --name "$name" --dir "$work/$name" --rate 30 "${ideal[@]}" > "$work/$name/gates.json" \
    || true
  "$VENV/bin/python" - "$work/$name/gates.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
print(json.dumps({"scenario": g["scenario"], "valid": g["valid"], "pass": g["pass"], "invalid": g["invalid_because"],
                  "gates": [(x["gate"], x["value"], x["pass"]) for x in g["gates"]]}, default=str))
PY
done
