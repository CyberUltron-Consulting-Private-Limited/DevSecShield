#!/bin/sh
# PostgreSQL role hash-type matrix: postgres:16 in Docker (superuser, least-privilege reader with and without the
# zs_role_password_types() function, md5 / scram / no-password / plain-text roles). Needs a running Docker daemon
# and the scan-node test environment. Usage: scan_node/tests/pg_matrix.sh [python]
set -eu
PY=${1:-python}
NAME=wp5-pg16-matrix
PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name "$NAME" -e POSTGRES_PASSWORD="$PASS" -p 127.0.0.1::5432 postgres:16 >/dev/null
PORT=$(docker port "$NAME" 5432/tcp | head -1 | sed 's/.*://')
i=0
until docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "postgres did not start"; exit 1; }; sleep 1
done
docker exec "$NAME" psql -U postgres -tAc 'SELECT version()'
cd "$(dirname "$0")/.."
ZS_TEST_PG_HOST=127.0.0.1 ZS_TEST_PG_PORT="$PORT" ZS_TEST_PG_SUPERPASS="$PASS" \
  "$PY" -m pytest -q -p no:cacheprovider -rA tests/test_postgres_roles_live.py
