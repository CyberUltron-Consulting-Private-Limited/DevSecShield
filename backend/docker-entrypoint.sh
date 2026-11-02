#!/bin/sh
# Backend image entrypoint (API, migrate one-shot, CBOM cloud worker, DAST scheduler all use it).
#   1. alembic upgrade head, unless SKIP_ALEMBIC=1. A missing alembic.ini means the image was built without the
#      Alembic bundle: stop here, loudly, instead of serving a database that was never migrated.
#      migrations/env.py holds a Postgres advisory lock, so containers that start together migrate one at a time.
#   2. idempotent Mongo data migration of DAST CI/CD logs (bounded; a failure is reported, not fatal).
#   3. exec the command (default: gunicorn).
set -eu
export PYTHONPATH="/backend/.."
ALEMBIC_INI=/prod_database_migrations/alembic.ini

if [ "${SKIP_ALEMBIC:-}" != "1" ]; then
  if [ ! -f "$ALEMBIC_INI" ]; then
    echo "FATAL: $ALEMBIC_INI is missing; this image was built without the Alembic bundle." >&2
    echo "FATAL: rebuild with --build-context migrations=prod_database_migrations (scripts/deploy/build_images.sh)," >&2
    echo "FATAL: or set SKIP_ALEMBIC=1 for a process that must never migrate." >&2
    exit 1
  fi
  echo "alembic upgrade head"
  # Bounded so a bad PG_HOST/DNS cannot block start-up forever; waiting for another migrator's lock counts too.
  timeout "${ALEMBIC_TIMEOUT_S:-300}" uv run alembic --config "$ALEMBIC_INI" upgrade head
fi

timeout 30 uv run python -c "from backend.utilities.cicd.migrate_dast_logs import migrate_all_dast_cicd_logs; migrate_all_dast_cicd_logs()" \
  || echo "dast cicd log migrate skipped"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi
exec uv run gunicorn main:app \
  -k uvicorn.workers.UvicornWorker \
  --workers 9 \
  --bind 0.0.0.0:8080 \
  --timeout 120 \
  --graceful-timeout 30 \
  --keep-alive 5
