#!/usr/bin/env bash
# staging.sh - build, ship and run the DevSecShield production images on the staging host (deploy/staging/README.md).
#
# On a connected build machine (Docker + this checkout):
#   staging.sh build                     build the images for DSS_TAG (scripts/deploy/build_images.sh)
#   staging.sh save                      docker save | gzip -> deploy/staging/images/dss-staging-<tag>.tar.gz + .sha256
#   staging.sh push <user@host> [dir]    scp the deploy bundle and the archive to <dir> (default
#                                        /opt/devsecshield-staging), then run `staging.sh deploy <tag>` there over ssh
#   staging.sh release <user@host> [dir] build + save + push
# On the staging host (inside <dir>, which holds deploy/staging/.env, backend.env and certs/):
#   staging.sh deploy [tag]              check + docker load the archive, switch DSS_TAG, compose up, health and
#                                        hydration checks; the previous images stay for rollback
#   staging.sh check                     health and hydration checks through nginx only
#   staging.sh rollback                  back to the previously deployed tag, compose up, checks
#
# Env: DSS_TAG (default: short git commit), DSS_IMAGE_PREFIX (default dss-staging), NEXT_PUBLIC_BACKEND_URL (default
#      https://<API_HOST>), STAGING_COMPONENTS (images, default backend,frontend,scan-worker,dast-worker),
#      STAGING_SERVICES (compose services to start, default all), STAGING_INCLUDE_INFRA=1 (also ship the postgres,
#      mongo, rabbitmq and nginx images, for a host without registry access), STAGING_CHECK_INSECURE=1 (accept a
#      self-signed certificate in the checks), SSH_OPTS (extra ssh/scp options).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIR="${REPO_ROOT}/deploy/staging"
COMPOSE_FILE="${STAGING_DIR}/docker-compose.yml"
ENV_FILE="${STAGING_DIR}/.env"
HISTORY_FILE="${STAGING_DIR}/deploy-history"
IMAGES_DIR="${STAGING_DIR}/images"
INFRA_IMAGES=(postgres:15-alpine mongo:8.0.6 rabbitmq:4.1-management-alpine nginx:1.27-alpine)
# `next dev` markers. A production `next build` (Turbopack or webpack) has none of them; note that Next.js 16
# production builds do reference a /_next/static/chunks/turbopack-<hash>.js runtime chunk, so "turbopack" alone is
# not a dev marker. "development" is the fixed build id of `next dev`.
DEV_MARKERS=('hmr-client' '_browser_dev_' 'webpack-hmr' 'react-refresh' '\"b\":\"development\"')

log() { printf '[staging %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[staging] ERROR: %s\n' "$*" >&2; exit 1; }

env_get() { # <KEY> [default]: value from deploy/staging/.env without sourcing it (values are never executed)
  local v=""
  [[ -f "${ENV_FILE}" ]] && v="$(sed -n -E "s/^$1=[\"']?([^\"']*)[\"']?[[:space:]]*$/\1/p" "${ENV_FILE}" | tail -n 1)"
  printf '%s\n' "${v:-${2:-}}"
}

default_tag() {
  local sha
  sha="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null)" || die "not a git checkout: set DSS_TAG"
  git -C "${REPO_ROOT}" diff --quiet HEAD -- 2>/dev/null || sha="${sha}-dirty"
  printf '%s\n' "${sha}"
}

prefix() { printf '%s\n' "${DSS_IMAGE_PREFIX:-$(env_get DSS_IMAGE_PREFIX dss-staging)}"; }
components() { local c="${STAGING_COMPONENTS:-backend,frontend,scan-worker,dast-worker}"; printf '%s\n' "${c//,/ }"; }
image_of() { # <component> <tag>
  case "$1" in
    backend) printf '%s/devsecshield-backend:%s\n' "$(prefix)" "$2" ;;
    frontend) printf '%s/devsecshield-frontend:%s\n' "$(prefix)" "$2" ;;
    scan-worker | dast-worker) printf '%s/%s:%s\n' "$(prefix)" "$1" "$2" ;;
    *) die "unknown component $1" ;;
  esac
}
archive_of() { printf '%s/%s-%s.tar.gz\n' "${IMAGES_DIR}" "$(prefix | tr '/' '-')" "$1"; }

compose() { docker compose --project-directory "${STAGING_DIR}" -f "${COMPOSE_FILE}" "$@"; }

# ------------------------------------------------------------------------------------------------ build machine
cmd_build() {
  local tag=${DSS_TAG:-$(default_tag)} api
  api="${NEXT_PUBLIC_BACKEND_URL:-https://$(env_get API_HOST devsec-staging-api.zeroshield.ai)}"
  log "building tag ${tag} (frontend API URL ${api})"
  DSS_TAG="${tag}" DSS_IMAGE_PREFIX="$(prefix)" NEXT_PUBLIC_BACKEND_URL="${api}" \
    "${REPO_ROOT}/scripts/deploy/build_images.sh" --only "$(components | tr ' ' ',')"
}

cmd_save() {
  local tag=${DSS_TAG:-$(default_tag)} c out
  local -a images=()
  for c in $(components); do images+=("$(image_of "${c}" "${tag}")"); done
  [[ "${STAGING_INCLUDE_INFRA:-0}" == 1 ]] && images+=("${INFRA_IMAGES[@]}")
  for c in "${images[@]}"; do docker image inspect "${c}" >/dev/null 2>&1 || die "image ${c} not found (run build)"; done
  mkdir -p "${IMAGES_DIR}"
  out="$(archive_of "${tag}")"
  log "saving ${#images[@]} images to ${out}"
  docker save "${images[@]}" | gzip -1 >"${out}.part"
  mv "${out}.part" "${out}"
  (cd "${IMAGES_DIR}" && sha256sum "$(basename "${out}")" >"$(basename "${out}").sha256")
  log "saved $(du -h "${out}" | cut -f1): $(cat "${out}.sha256")"
}

cmd_push() {
  local target=${1:?usage: staging.sh push <user@host> [dir]} dir=${2:-/opt/devsecshield-staging}
  local tag=${DSS_TAG:-$(default_tag)} archive bundle
  archive="$(archive_of "${tag}")"
  [[ -f "${archive}" && -f "${archive}.sha256" ]] || die "no archive for ${tag} (run save)"
  # The deploy bundle: compose file, nginx config, examples, the rollup overlay the backend mounts, and this script.
  # Never the host's .env, backend.env or certificates: they live only on the host.
  bundle="$(mktemp -d)/dss-staging-bundle-${tag}.tar.gz"
  tar -C "${REPO_ROOT}" -czf "${bundle}" \
    --exclude='deploy/staging/.env' --exclude='deploy/staging/*.env' --exclude='deploy/staging/certs' \
    --exclude='deploy/staging/images' --exclude='deploy/staging/deploy-history' \
    deploy/staging compose/aibom-config-overlay scripts/deploy/staging.sh scripts/deploy/staging_browser_check.py
  local -a ssh_opts=()
  # shellcheck disable=SC2206 # operator-supplied options, split on purpose
  [[ -n "${SSH_OPTS:-}" ]] && ssh_opts=(${SSH_OPTS})
  log "copying bundle and archive to ${target}:${dir}"
  # shellcheck disable=SC2029 # dir, tag and prefix are expanded here on purpose
  ssh "${ssh_opts[@]}" "${target}" "mkdir -p '${dir}/deploy/staging/images'"
  scp "${ssh_opts[@]}" "${bundle}" "${target}:${dir}/"
  scp "${ssh_opts[@]}" "${archive}" "${archive}.sha256" "${target}:${dir}/deploy/staging/images/"
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" "${target}" "cd '${dir}' && tar -xzf '$(basename "${bundle}")' && rm -f '$(basename "${bundle}")' \
    && DSS_IMAGE_PREFIX='$(prefix)' STAGING_SERVICES='${STAGING_SERVICES:-}' scripts/deploy/staging.sh deploy '${tag}'"
  rm -rf "$(dirname "${bundle}")"
}

# ------------------------------------------------------------------------------------------------ staging host
set_tag() { # <tag>: rewrite only the DSS_TAG line of .env
  if grep -q '^DSS_TAG=' "${ENV_FILE}"; then
    sed -i -E "s|^DSS_TAG=.*|DSS_TAG=$1|" "${ENV_FILE}"
  else
    printf 'DSS_TAG=%s\n' "$1" >>"${ENV_FILE}"
  fi
}

require_host_files() {
  [[ -f "${ENV_FILE}" ]] || die "missing ${ENV_FILE} (cp .env.example .env and set the values)"
  [[ -f "${STAGING_DIR}/backend.env" ]] || die "missing ${STAGING_DIR}/backend.env (cp backend.env.example backend.env)"
  if grep -Eq '^[[:space:]]*(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_(EMAIL|CODE))=' "${ENV_FILE}" "${STAGING_DIR}/backend.env"; then
    die "DSS_DEV_MODE / LOCAL_DEV_VERIFICATION_* must never be set on staging"
  fi
}

up() {
  local -a services=()
  # shellcheck disable=SC2206 # service names, split on purpose
  [[ -n "${STAGING_SERVICES:-}" ]] && services=(${STAGING_SERVICES//,/ })
  log "docker compose up (${services[*]:-all services})"
  compose up -d --remove-orphans --wait --wait-timeout "${STAGING_WAIT_S:-600}" "${services[@]}"
  compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
}

cmd_deploy() {
  require_host_files
  local tag=${1:-${DSS_TAG:-}} archive previous c
  [[ -n "${tag}" ]] || die "usage: staging.sh deploy <tag>"
  archive="$(archive_of "${tag}")"
  if [[ -f "${archive}" ]]; then
    log "verifying and loading ${archive}"
    (cd "${IMAGES_DIR}" && sha256sum -c "$(basename "${archive}").sha256")
    docker load -i "${archive}"
  fi
  for c in $(components); do
    docker image inspect "$(image_of "${c}" "${tag}")" >/dev/null 2>&1 ||
      [[ -n "${STAGING_SERVICES:-}" ]] || die "image $(image_of "${c}" "${tag}") is not loaded"
  done
  previous="$(env_get DSS_TAG)"
  set_tag "${tag}"
  if ! up; then
    [[ -n "${previous}" && "${previous}" != "${tag}" ]] && log "start failed; to go back: staging.sh rollback"
    printf '%s deploy %s FAILED (previous %s)\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" >>"${HISTORY_FILE}"
    die "compose up failed for ${tag}"
  fi
  printf '%s deploy %s previous %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" >>"${HISTORY_FILE}"
  cmd_check
  log "deployed ${tag}; previous tag ${previous:-none} is kept for rollback"
}

cmd_rollback() {
  require_host_files
  local current previous
  current="$(env_get DSS_TAG)"
  previous="$(grep -E " deploy ${current} previous " "${HISTORY_FILE}" 2>/dev/null | tail -n 1 | awk '{print $5}')"
  [[ -n "${previous}" && "${previous}" != none ]] || die "no previous tag recorded for ${current} in ${HISTORY_FILE}"
  cat >&2 <<EOF
[staging] WARNING: rolling back ${current} -> ${previous}.
[staging]   * Database migrations are not reversed: ${previous} runs on the schema ${current} left.
[staging]   * Users whose password was rehashed to Argon2id by ${current} cannot sign in on an image without Argon2
[staging]     support; they must reset their password after a later upgrade.
EOF
  set_tag "${previous}"
  up
  printf '%s rollback %s previous %s\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" >>"${HISTORY_FILE}"
  cmd_check
  log "rolled back to ${previous}"
}

# Health and hydration through nginx, the way a browser reaches the site. Host names resolve to this machine.
cmd_check() {
  local fe api scheme port cert_dir tmp code chunk found=0 m
  fe="$(env_get FRONTEND_HOST devsec-staging.zeroshield.ai)"
  api="$(env_get API_HOST devsec-staging-api.zeroshield.ai)"
  cert_dir="$(env_get TLS_CERT_DIR ./certs)"
  [[ "${cert_dir}" = /* ]] || cert_dir="${STAGING_DIR}/${cert_dir#./}"
  if [[ -s "${cert_dir}/fullchain.pem" && -s "${cert_dir}/privkey.pem" ]]; then
    scheme=https port="$(env_get HTTPS_PORT 443)"
  else
    scheme=http port="$(env_get HTTP_PORT 80)"
  fi
  local -a curl_opts=(-sS --noproxy '*' --max-time 30 --resolve "${fe}:${port}:127.0.0.1" --resolve "${api}:${port}:127.0.0.1")
  [[ "${STAGING_CHECK_INSECURE:-0}" == 1 ]] && curl_opts+=(-k)
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: the local variable is gone when the trap runs
  trap "rm -rf '${tmp}'" RETURN

  code="$(curl "${curl_opts[@]}" -o "${tmp}/health.json" -w '%{http_code}' "${scheme}://${api}:${port}/health")" || code=000
  if [[ "${code}" != 200 ]] || ! grep -q '"healthy"' "${tmp}/health.json"; then
    die "API health ${scheme}://${api}/health -> HTTP ${code}"
  fi
  log "API ${scheme}://${api}/health -> 200 healthy"

  code="$(curl "${curl_opts[@]}" -o "${tmp}/login.html" -w '%{http_code}' "${scheme}://${fe}:${port}/login")" || code=000
  [[ "${code}" == 200 ]] || die "frontend ${scheme}://${fe}/login -> HTTP ${code}"
  grep -o '/_next/static/chunks/[^"\\ ]*\.js' "${tmp}/login.html" | sort -u >"${tmp}/chunks.txt" || true
  [[ -s "${tmp}/chunks.txt" ]] || die "the login page references no /_next/static/chunks/*.js (not a Next.js production page)"
  for m in "${DEV_MARKERS[@]}"; do
    if grep -qF -- "${m}" "${tmp}/login.html"; then die "the login page is served by \`next dev\` (found '${m}')"; fi
  done
  # The chunks must load, and one of them must carry the API URL this frontend was built for.
  while read -r chunk; do
    code="$(curl "${curl_opts[@]}" -o "${tmp}/chunk.js" -w '%{http_code}' "${scheme}://${fe}:${port}${chunk}")" || code=000
    [[ "${code}" == 200 ]] || die "chunk ${chunk} -> HTTP ${code}"
    grep -qF -- "${api}" "${tmp}/chunk.js" && found=1
  done <"${tmp}/chunks.txt"
  [[ "${found}" == 1 ]] || die "no login-page chunk contains ${api}: the frontend image was built for another API URL"
  log "frontend ${scheme}://${fe}/login -> 200, $(wc -l <"${tmp}/chunks.txt") production chunks load, no dev markers, API URL ${api} baked in"
}

main() {
  local cmd=${1:-}
  shift || true
  case "${cmd}" in
    build) cmd_build ;;
    save) cmd_save ;;
    push) cmd_push "$@" ;;
    release) cmd_build && cmd_save && cmd_push "$@" ;;
    deploy) cmd_deploy "$@" ;;
    check) cmd_check ;;
    rollback) cmd_rollback ;;
    -h | --help | help | "") sed -n '2,24p' "${BASH_SOURCE[0]}" ;;
    *) die "unknown command ${cmd} (see --help)" ;;
  esac
}

main "$@"
