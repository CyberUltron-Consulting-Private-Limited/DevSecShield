#!/usr/bin/env bash
# up.sh - start the dss-e2e stack from the images build.sh produced (never builds, never pulls).
#
#   docker compose -p dss-e2e -f e2e/compose/docker-compose.e2e.yml up -d --no-build postgres mongo backend frontend
#
# then waits (condition-based, bounded) until every container reports healthy, until
# http://127.0.0.1:43080/docs and http://127.0.0.1:43000/login answer 200, and checks the published
# ports really are loopback-only. Seeding is a separate step (seed.sh).
#
# Logs: <evidence>/logs/02-up.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

check_loopback_only() {
  local bad
  # Every host-side binding of every dss-e2e container must be 127.0.0.1:43000 or 127.0.0.1:43080.
  bad="$(docker ps --filter "label=${E2E_LABEL}" --format '{{.Names}} {{.Ports}}' |
    tr ',' '\n' | grep -E -- '->' |
    grep -vE '127\.0\.0\.1:(43000->3000|43080->8080)/tcp' || true)"
  if [[ -n "${bad}" ]]; then
    log "unexpected host port exposure:"
    printf '%s\n' "${bad}"
    return 1
  fi
  log "published ports are loopback-only: $(docker ps --filter "label=${E2E_LABEL}" --format '{{.Names}} {{.Ports}}' | grep -- '->' | tr '\n' ';')"
}

main() {
  banner "up"
  need_cmd docker curl
  ensure_env_file

  local img
  for img in "${E2E_IMG_BACKEND}" "${E2E_IMG_FRONTEND}"; do
    image_exists "${img}" || die "image ${img} not found: run scripts/build.sh first"
  done
  for img in "${E2E_PG_IMAGE}" "${E2E_MONGO_IMAGE}"; do
    image_exists "${img}" || die "image ${img} not found locally: run scripts/build.sh (it pulls the stock images)"
  done

  log "starting postgres mongo backend frontend"
  compose up -d --no-build postgres mongo backend frontend

  local c
  for c in dss-e2e-postgres dss-e2e-mongo dss-e2e-backend dss-e2e-frontend; do
    # backend: 90s start_period + alembic + gunicorn; the others are quick.
    wait_until 240 3 "${c} healthy" container_healthy "${c}" || {
      log "last 40 log lines of ${c}:"
      docker logs --tail 40 "${c}" 2>&1 | sed 's/^/    | /' || true
      die "${c} did not become healthy"
    }
  done

  wait_until 60 2 "backend GET ${E2E_API_URL}/docs -> 200" http_ok "${E2E_API_URL}/docs" || die "backend /docs is not answering 200"
  wait_until 60 2 "frontend GET ${E2E_BASE_URL}/login -> 200" http_ok "${E2E_BASE_URL}/login" || die "frontend /login is not answering 200"
  log "status codes: backend /docs=$(http_code "${E2E_API_URL}/docs") frontend /login=$(http_code "${E2E_BASE_URL}/login")"

  check_loopback_only || die "published ports violate the loopback-only policy"
  compose ps
  log "images in use:"
  docker ps --filter "label=${E2E_LABEL}" --format '  {{.Names}}  {{.Image}}  {{.Status}}'
  log "UP OK"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 02-up.txt)"
run_logged "$(e2e_log_file 02-up.txt)" main
