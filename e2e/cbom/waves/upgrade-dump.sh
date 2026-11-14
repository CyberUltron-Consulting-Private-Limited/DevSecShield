#!/usr/bin/env bash
# W-UPGRADE (DEVILS-ADVOCATE.md §4.5): the previous release's database dump, upgraded to this SHA's migrations.
#
#   e2e/cbom/waves/upgrade-dump.sh <step-dir>
#     CBOM_WAVES_RELEASE_DUMP      a plain-SQL pg_dump of the previous release's database (the operator's copy)
#     CBOM_WAVES_UPGRADE_PG_URL    an EMPTY scratch PostgreSQL database for this step (never the stack's own database)
#
# Restores the dump, runs `alembic upgrade head` from prod_database_migrations, then checks there is one head and that
# the database is at it. Writes restore.log, upgrade.log and current.txt into <step-dir>. Exit 0 pass, 1 fail.
# The gate on the upgraded database is the W-STATE gate step run against a stack restacked onto this database.
set -euo pipefail
OUT=${1:?usage: upgrade-dump.sh <step-dir>}
: "${CBOM_WAVES_RELEASE_DUMP:?set CBOM_WAVES_RELEASE_DUMP}"
: "${CBOM_WAVES_UPGRADE_PG_URL:?set CBOM_WAVES_UPGRADE_PG_URL}"
REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
mkdir -p "$OUT"
if [ "$(psql "$CBOM_WAVES_UPGRADE_PG_URL" -Atc "select count(*) from pg_tables where schemaname = 'public'")" != 0 ]; then
  echo "the scratch database is not empty: refusing to restore into it" >&2
  exit 1
fi
psql "$CBOM_WAVES_UPGRADE_PG_URL" -v ON_ERROR_STOP=1 -q -f "$CBOM_WAVES_RELEASE_DUMP" > "$OUT/restore.log" 2>&1
cd "$REPO/prod_database_migrations"
DATABASE_URL=$CBOM_WAVES_UPGRADE_PG_URL alembic upgrade head > "$OUT/upgrade.log" 2>&1
heads=$(alembic heads 2>/dev/null | grep -c '(head)' || true)
current=$(DATABASE_URL=$CBOM_WAVES_UPGRADE_PG_URL alembic current 2>/dev/null | tee "$OUT/current.txt")
[ "$heads" = 1 ] || { echo "expected one alembic head, found $heads" >&2; exit 1; }
grep -q '(head)' <<< "$current" || { echo "the upgraded database is not at head: $current" >&2; exit 1; }
echo "upgraded to $(awk '{print $1}' <<< "$current")"
