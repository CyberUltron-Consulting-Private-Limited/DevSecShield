#!/usr/bin/env bash
# Throwaway PostgreSQL (docker) + the backend under gunicorn/uvicorn for the F1.1 node-API bench.
#
#   bench/f1_node_api/stack.sh up   <src-root> <workdir> [workers]   # src-root holds backend/ (dev baseline or branch)
#   bench/f1_node_api/stack.sh down <workdir>
#
# PostgreSQL 15 (the image the stack uses) with pg_stat_statements, on 127.0.0.1:${F1_PG_PORT:-55440}, container
# ${F1_PG_NAME:-f1bench-pg}; gunicorn on 127.0.0.1:${F1_API_PORT:-18080}; with F1_REAPER=1 also the job reaper loop
# (reaper.py, the cloud worker's reap_all) that re-queues a dead node's job when its lease expires. CBOM_* settings
# in the caller's environment (CBOM_JOB_LEASE_S, CBOM_NODE_HEARTBEAT_S ...) reach the server. Secrets are generated per run into
# <workdir>/env (mode 0600) and never printed. The venv is the shared backend venv (${F1_VENV}).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cmd=${1:?up|down}
PG_NAME=${F1_PG_NAME:-f1bench-pg}
PG_PORT=${F1_PG_PORT:-55440}
API_PORT=${F1_API_PORT:-18080}
VENV=${F1_VENV:-/home/claude/devsecshield/backend/.venv}

if [[ $cmd == down ]]; then
  work=${2:?workdir}
  if [[ -f $work/gunicorn.pid ]]; then kill "$(cat "$work/gunicorn.pid")" 2>/dev/null || true; fi
  if [[ -f $work/reaper.pid ]]; then kill "$(cat "$work/reaper.pid")" 2>/dev/null || true; rm -f "$work/reaper.pid"; fi
  sleep 2
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  echo "stack down"
  exit 0
fi

src=$(cd "${2:?src root}" && pwd)
work=${3:?workdir}
workers=${4:-2}
mkdir -p "$work"
umask 077
if [[ ! -f $work/env ]]; then
  pw=$(openssl rand -hex 16)
  {
    echo "PG_USER=postgres"; echo "PG_USER_PASS=$pw"; echo "PG_DB=f1bench"; echo "PG_HOST=127.0.0.1"
    echo "PG_PORT=$PG_PORT"
    echo "JWT_SECRET_KEY=$(openssl rand -hex 32)"; echo "JWT_REFRESH_SECRET_KEY=$(openssl rand -hex 32)"
    echo "ENCRYPTION_KEY=$("$VENV/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
    echo "AWS_ACCESS_KEY_ID=bench"; echo "AWS_SECRET_ACCESS_KEY=bench"; echo "AWS_DEFAULT_REGION=us-east-1"
    echo "CBOM_SCHEDULER=0"
  } > "$work/env"
fi
set -a; . "$work/env"; set +a

if ! docker inspect "$PG_NAME" >/dev/null 2>&1; then
  docker run -d --name "$PG_NAME" --label zs-owner=f1-1 -p "127.0.0.1:$PG_PORT:5432" \
    -e POSTGRES_PASSWORD="$PG_USER_PASS" -e POSTGRES_DB="$PG_DB" --shm-size=256m \
    postgres:15-alpine -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=top \
    -c max_connections=300 -c shared_buffers=256MB >/dev/null
  # the image's entrypoint runs a temporary server (unix socket only) for initdb, then restarts: wait for TCP
  ok=0
  for _ in $(seq 1 90); do
    if docker exec "$PG_NAME" psql -h 127.0.0.1 -U postgres -d "$PG_DB" -qc \
        "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [[ $ok == 1 ]] || { echo "postgres did not come up" >&2; docker logs --tail 30 "$PG_NAME" >&2; exit 1; }
fi
echo "postgresql://postgres:$PG_USER_PASS@127.0.0.1:$PG_PORT/$PG_DB" > "$work/db_url"

if [[ ${F1_SKIP_API:-0} != 1 ]]; then
  if [[ -f $work/gunicorn.pid ]]; then kill "$(cat "$work/gunicorn.pid")" 2>/dev/null || true; sleep 2; fi
  cd "$src/backend"
  PYTHONPATH="$src" nohup "$VENV/bin/gunicorn" main:app -k uvicorn.workers.UvicornWorker --workers "$workers" \
    --bind "127.0.0.1:$API_PORT" --timeout 120 --graceful-timeout 10 --keep-alive 5 \
    --pid "$work/gunicorn.pid" > "$work/gunicorn.log" 2>&1 &
  for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$API_PORT/health" >/dev/null || { tail -40 "$work/gunicorn.log"; exit 1; }
  echo "api up: http://127.0.0.1:$API_PORT (workers=$workers, src=$src)"
  if [[ ${F1_REAPER:-0} == 1 ]]; then
    if [[ -f $work/reaper.pid ]]; then kill "$(cat "$work/reaper.pid")" 2>/dev/null || true; fi
    PYTHONPATH="$src" nohup "$VENV/bin/python" "$here/reaper.py" --every "${F1_REAP_EVERY_S:-30}" \
      > "$work/reaper.log" 2>&1 &
    echo $! > "$work/reaper.pid"
    echo "reaper up (every ${F1_REAP_EVERY_S:-30} s)"
  fi
fi
