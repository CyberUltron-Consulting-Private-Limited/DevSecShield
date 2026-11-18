#!/usr/bin/env bash
# 10,000 certificates through the real issuing path on PostgreSQL 15 (a throw-away container named f1-4-bench-pg).
# Run from the repository root (a small container of its own: no stack lock; check `free -m` first, keep 1.5 GB):
#   flock "$L/heavy-tests.lock" bench/f1_sshca/run_issue_bench_pg.sh <out-dir>
set -euo pipefail
OUT=${1:?out dir}
N=${N:-10000}
NAME=f1-4-bench-pg
PORT=${PORT:-55432}
mkdir -p "$OUT"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --label zs-owner=f1-4 -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=bench \
  -p "127.0.0.1:${PORT}:5432" postgres:15-alpine >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 60); do
  docker exec "$NAME" pg_isready -U postgres -d bench >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
cd backend
PYTHONPATH=.. AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
  uv run --frozen python ../bench/f1_sshca/issue_bench.py --n "$N" --threads 4 --revoke 1000 \
  --pg-url "postgresql+psycopg2://postgres:bench@127.0.0.1:${PORT}/bench" --out "$OUT/issue-bench-pg.json" \
  > "$OUT/issue-bench-pg.log" 2>&1
tail -25 "$OUT/issue-bench-pg.log" | grep -v "certificate issued" || true
