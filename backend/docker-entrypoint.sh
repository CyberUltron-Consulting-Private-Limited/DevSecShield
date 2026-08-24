#!/bin/sh
set -e
export PYTHONPATH="/backend/.."
ALEMBIC_INI=/prod_database_migrations/alembic.ini

run_alembic() {
  uv run alembic --config "$ALEMBIC_INI" "$@"
}

if [ "${SKIP_ALEMBIC:-}" != "1" ] && [ -f "$ALEMBIC_INI" ]; then
  echo "alembic: ensure schema"
  if ! run_alembic current >/tmp/alembic-current.out 2>/tmp/alembic-current.err; then
    echo "alembic current failed; stamping b7479fc393e1 for existing revamped schema"
    cat /tmp/alembic-current.err || true
    run_alembic stamp b7479fc393e1
  elif ! grep -q '[0-9a-fA-F]' /tmp/alembic-current.out; then
    echo "alembic_version empty; stamping b7479fc393e1"
    run_alembic stamp b7479fc393e1
  else
    echo "alembic current:"
    cat /tmp/alembic-current.out
  fi
  echo "alembic upgrade head"
  run_alembic upgrade head
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
