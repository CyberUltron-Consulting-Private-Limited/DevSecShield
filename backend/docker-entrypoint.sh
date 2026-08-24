#!/bin/sh
set -e
export PYTHONPATH="/backend/.."
ALEMBIC_INI=/prod_database_migrations/alembic.ini

if [ "${SKIP_ALEMBIC:-}" != "1" ] && [ -f "$ALEMBIC_INI" ]; then
  echo "alembic upgrade head"
  # Bound so a bad DATABASE_URL/DNS cannot block gunicorn forever.
  timeout 60 uv run alembic --config "$ALEMBIC_INI" upgrade head
fi

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
