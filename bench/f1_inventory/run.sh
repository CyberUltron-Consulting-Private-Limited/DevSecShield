#!/usr/bin/env bash
# F1.2 inventory scale proof, end to end on PostgreSQL 15 (the product's database):
#   1. a throwaway PostgreSQL container (label zs-owner=f1-2) on 127.0.0.1:${F12_PG_PORT:-55450};
#   2. the schema from the real migrations (`alembic upgrade head`, which includes r6f12inv001 / r6f12pol001), then a
#      check that every fleet table and column the models declare exists;
#   3. bench.py: 1,000 and 10,000 targets imported through the real route (CSV), each re-imported (must be a no-op),
#      10% of the tags changed (must update exactly those), and 1,000 EC2 instances in 3 regions discovered through
#      the AWS inventory source against moto and saved, then synced again (must be a no-op);
#   4. everything torn down.
#
#   flock $L/heavy-tests.lock bench/f1_inventory/run.sh <src-root> <report.json>
#
# The venv is the shared backend venv (${F12_VENV}); it has moto 5.2.5, as backend CI does.
set -euo pipefail
src=$(cd "${1:?src root}" && pwd)
report=${2:?report path}
PG_NAME=${F12_PG_NAME:-f12bench-pg}
PG_PORT=${F12_PG_PORT:-55450}
VENV=${F12_VENV:-/home/claude/devsecshield/backend/.venv}
umask 077
pw=$(openssl rand -hex 16)
cleanup() { docker rm -f "$PG_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name "$PG_NAME" --label zs-owner=f1-2 -p "127.0.0.1:$PG_PORT:5432" -e POSTGRES_PASSWORD="$pw" \
  -e POSTGRES_DB=f12bench --shm-size=256m postgres:15-alpine >/dev/null
for _ in $(seq 1 90); do
  docker exec "$PG_NAME" psql -h 127.0.0.1 -U postgres -d f12bench -qc "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
export PG_USER=postgres PG_USER_PASS="$pw" PG_DB=f12bench PG_HOST=127.0.0.1 PG_PORT="$PG_PORT"
export JWT_SECRET_KEY=$(openssl rand -hex 32) JWT_REFRESH_SECRET_KEY=$(openssl rand -hex 32)
export AWS_ACCESS_KEY_ID=bench AWS_SECRET_ACCESS_KEY=bench AWS_DEFAULT_REGION=us-east-1 CBOM_SCHEDULER=0
export ENCRYPTION_KEY=$("$VENV/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
(cd "$src/prod_database_migrations" && PYTHONPATH="$src" "$VENV/bin/alembic" upgrade head 2>&1 | tail -3)
(cd "$src/prod_database_migrations" && PYTHONPATH="$src" "$VENV/bin/alembic" heads 2>/dev/null)
cd "$src/backend"
PYTHONPATH="$src" "$VENV/bin/python" "$src/bench/f1_inventory/bench.py" \
  --db "postgresql://postgres:$pw@127.0.0.1:$PG_PORT/f12bench" --out "$report"
