#!/usr/bin/env bash
# F3 Repositories pages in a real browser against the real API. Starts e2e/repos/serve_api.py (backend.main on a
# throw-away PostgreSQL database + the fake GitHub organisation) and `next dev`, runs the Playwright specs in
# e2e/repos, then stops both. Evidence (videos, screenshots, report.json, the two server logs) goes to $E2E_REPOS_OUT.
#
#   E2E_REPOS_DB=postgresql://user@127.0.0.1:5432/throwaway bash e2e/repos/run.sh [playwright args]
#
# Needs: backend/.venv (uv sync in backend/), frontend/node_modules, e2e/node_modules (PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
# npm ci in e2e/), a Chromium for Playwright 1.62.0 (PLAYWRIGHT_BROWSERS_PATH), and an empty database it may wipe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${E2E_REPOS_DB:?set E2E_REPOS_DB to a throw-away PostgreSQL database (its tables are dropped)}"
API_PORT="${E2E_REPOS_API_PORT:-18081}"
WEB_PORT="${E2E_REPOS_WEB_PORT:-13000}"
OUT="${E2E_REPOS_OUT:-$ROOT/e2e/.work/repos}"
PY="${E2E_REPOS_PYTHON:-$ROOT/backend/.venv/bin/python}"
WEB="http://127.0.0.1:$WEB_PORT"
mkdir -p "$OUT"
export E2E_REPOS_OUT="$OUT" E2E_REPOS_STATE="$OUT/state.json" E2E_REPOS_BASE_URL="$WEB"

pids=()
cleanup() {  # each server runs in its own session: stop the whole group (next dev forks workers)
  for pid in "${pids[@]}"; do kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for() {  # url, seconds, what
  local deadline=$((SECONDS + $2))
  until curl -fsS -o /dev/null "$1"; do
    if (( SECONDS > deadline )); then echo "run.sh: $3 did not answer $1 within $2 s" >&2; return 1; fi
    sleep 2
  done
}

rm -f "$E2E_REPOS_STATE"
PYTHONPATH="$ROOT" setsid "$PY" "$ROOT/e2e/repos/serve_api.py" --db "$E2E_REPOS_DB" --port "$API_PORT" --cors "$WEB" \
  --state "$E2E_REPOS_STATE" >"$OUT/api.log" 2>&1 &
pids+=($!)
wait_for "http://127.0.0.1:$API_PORT/health" 90 "the API"

# webpack, not turbopack: turbopack refuses a symlinked node_modules (the shared install)
NEXT_PUBLIC_BACKEND_URL="http://127.0.0.1:$API_PORT" NEXT_TELEMETRY_DISABLED=1 setsid bash -c \
  'cd "$1" && exec npx next dev --webpack -H 127.0.0.1 -p "$2"' _ "$ROOT/frontend" "$WEB_PORT" >"$OUT/web.log" 2>&1 &
pids+=($!)
wait_for "$WEB/login" 300 "next dev"
curl -fsS -o /dev/null --max-time 300 "$WEB/1/repositories" || true  # compile the page before the clock starts

cd "$ROOT/e2e"
set +e
npx playwright test --config repos/playwright.config.ts "$@"
status=$?
set -e
echo "run.sh: playwright exit $status; evidence in $OUT"
exit "$status"
