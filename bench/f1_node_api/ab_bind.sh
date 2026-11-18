#!/usr/bin/env bash
# L8 (DA E3 gate): CPU per heartbeat with CBOM_NODE_ONE_CONNECTION=1 (one pooled connection per request) and =0,
# alternating A B A B so drift on a shared box hits both.  1 gunicorn worker, 2,000 sequential heartbeats each.
#   bench/f1_node_api/ab_bind.sh <src-root> <workdir> [rounds]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "${1:?src root}" && pwd); work=${2:?workdir}; rounds=${3:-2}
VENV=${F1_VENV:-/home/claude/devsecshield/backend/.venv}
PORT=${F1_API_PORT:-18080}
mkdir -p "$work"
trap '"$here/stack.sh" down "$work" >/dev/null 2>&1 || true' EXIT
"$here/stack.sh" down "$work" >/dev/null 2>&1 || true
rm -f "$work/env" "$work/gunicorn.log"
F1_SKIP_API=1 "$here/stack.sh" up "$src" "$work"
set -a; . "$work/env"; set +a
PYTHONPATH="$src" "$VENV/bin/python" "$here/seed.py" --db "$(cat "$work/db_url")" --creds "$work/creds.json" \
  --yes-drop-everything --nodes 200 --sources 0 --assign segment >/dev/null
for r in $(seq 1 "$rounds"); do
  for mode in 1 0; do
    CBOM_NODE_ONE_CONNECTION=$mode "$here/stack.sh" up "$src" "$work" 1 >/dev/null
    worker=$(pgrep -P "$(cat "$work/gunicorn.pid")" | head -1)
    out=$(cd "$src/backend" && PYTHONPATH="$src" "$VENV/bin/python" "$here/ab_bind.py" --api "http://127.0.0.1:$PORT" \
      --creds "$work/creds.json" --worker-pid "$worker" --n "${F1_AB_N:-2000}")
    echo "{\"round\": $r, \"one_connection\": $mode, \"result\": $out}"
    kill "$(cat "$work/gunicorn.pid")"; rm -f "$work/gunicorn.pid"; sleep 3
  done
done
