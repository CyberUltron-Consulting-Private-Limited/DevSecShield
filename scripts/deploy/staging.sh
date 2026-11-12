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
#   staging.sh deploy [tag]              check + docker load the archive, refuse a tag whose migrations do not contain
#                                        the database's revision, keep the tag's deploy files and Alembic head in
#                                        deploy/staging/releases/<tag>/, switch DSS_TAG, compose up, checks
#   staging.sh check                     every service runs DSS_TAG's images and is up; health and hydration via nginx
#   staging.sh rollback [--allow-downgrade]
#                                        back to the previously deployed tag and its own deploy files (compose file,
#                                        nginx, this script). When that tag's migrations do not contain the database's
#                                        revision, first `alembic downgrade` to its head with the current image; that
#                                        drops what the newer migrations added, so it asks (or --allow-downgrade)
#
# Env: DSS_TAG (default: short git commit), DSS_IMAGE_PREFIX (default dss-staging), NEXT_PUBLIC_BACKEND_URL (default
#      https://<API_HOST>), STAGING_COMPONENTS (images, default backend,frontend,scan-worker,dast-worker),
#      STAGING_SERVICES (compose services to start, default all), STAGING_INCLUDE_INFRA=1 (also ship the postgres,
#      mongo, rabbitmq, nginx and, with profile minio, MinIO images, for a host without registry access),
#      GRYPE_DB_ARCHIVE (save: also ship this Grype database archive as images/grype-db.tar.zst),
#      STAGING_CHECK_INSECURE=1 (accept a self-signed certificate in the checks), SSH_OPTS (extra ssh/scp options),
#      DSS_EXPOSE_BUILD (build: 1 = the frontend names its commit in <meta name="zs-build">; default: .env's value, else 0).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIR="${REPO_ROOT}/deploy/staging"
COMPOSE_FILE="${STAGING_DIR}/docker-compose.yml"
ENV_FILE="${STAGING_DIR}/.env"
HISTORY_FILE="${STAGING_DIR}/deploy-history"
IMAGES_DIR="${STAGING_DIR}/images"
# One directory per deployed tag: files.tar.gz (the deploy files it was started with) and alembic-head (the head of
# its migrations). files-tag names the tag whose recorded files are in place; it is absent when they came from a
# pushed bundle or a checkout.
RELEASES_DIR="${STAGING_DIR}/releases"
FILES_TAG_FILE="${RELEASES_DIR}/files-tag"
RELEASE_FILES=(deploy/staging/docker-compose.yml deploy/staging/nginx compose/aibom-config-overlay scripts/deploy/staging.sh)
ALEMBIC_INI=/prod_database_migrations/alembic.ini
INFRA_SERVICES=" postgres mongo rabbitmq minio "
ONESHOT_SERVICES=" migrate minio-init "
INFRA_IMAGES=(postgres:15-alpine mongo:8.0.6 rabbitmq:4.1-management-alpine nginx:1.27-alpine)
DEFAULT_MINIO_IMAGE=minio/minio:RELEASE.2025-04-22T22-12-26Z  # docker-compose.yml's MINIO_IMAGE default
GRYPE_DB_FILE=grype-db.tar.zst  # GRYPE_DB_ARCHIVE is copied under this name next to the images (save)
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
  # build_images.sh's rule: uncommitted or untracked changes (ignored files, such as deploy/staging/.env, do not count)
  [[ -z "$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=normal 2>/dev/null)" ]] || sha="${sha}-dirty"
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

# DSS_TAG comes from .env (the file this script switches), never from the caller's environment.
compose() { DSS_TAG="$(env_get DSS_TAG)" docker compose --project-directory "${STAGING_DIR}" -f "${COMPOSE_FILE}" "$@"; }

# ------------------------------------------------------------------------------------------------ build machine
cmd_build() {
  local tag=${DSS_TAG:-$(default_tag)} api
  api="${NEXT_PUBLIC_BACKEND_URL:-https://$(env_get API_HOST devsec-staging-api.zeroshield.ai)}"
  log "building tag ${tag} (frontend API URL ${api})"
  # The switch that makes the backend name its build publicly (.env) also puts the commit in the frontend's meta.
  # The caller's DSS_EXPOSE_BUILD comes first: deploy-staging.yml builds on a runner whose checkout has no .env.
  DSS_TAG="${tag}" DSS_IMAGE_PREFIX="$(prefix)" NEXT_PUBLIC_BACKEND_URL="${api}" \
    DSS_EXPOSE_BUILD="${DSS_EXPOSE_BUILD:-$(env_get DSS_EXPOSE_BUILD 0)}" \
    "${REPO_ROOT}/scripts/deploy/build_images.sh" --only "$(components | tr ' ' ',')"
}

cmd_save() {
  local tag=${DSS_TAG:-$(default_tag)} c out
  local -a images=()
  for c in $(components); do images+=("$(image_of "${c}" "${tag}")"); done
  if [[ "${STAGING_INCLUDE_INFRA:-0}" == 1 ]]; then
    images+=("${INFRA_IMAGES[@]}")
    # The optional local S3 (profile "minio") is infrastructure too: an air-gapped site that runs it needs its image.
    if [[ ",${COMPOSE_PROFILES:-$(env_get COMPOSE_PROFILES)}," == *,minio,* ]]; then
      images+=("$(env_get MINIO_IMAGE "${DEFAULT_MINIO_IMAGE}")")
    fi
  fi
  for c in "${images[@]}"; do docker image inspect "${c}" >/dev/null 2>&1 || die "image ${c} not found (run build)"; done
  mkdir -p "${IMAGES_DIR}"
  out="$(archive_of "${tag}")"
  log "saving ${#images[@]} images to ${out}"
  docker save "${images[@]}" | gzip -1 >"${out}.part"
  mv "${out}.part" "${out}"
  (cd "${IMAGES_DIR}" && sha256sum "$(basename "${out}")" >"$(basename "${out}").sha256")
  log "saved $(du -h "${out}" | cut -f1): $(cat "${out}.sha256")"
  # An air-gapped site cannot download Grype's vulnerability database: ship one (`grype db list` / the Anchore
  # listing, fetched on a connected machine) next to the images; the site imports it (README "Air gap").
  if [[ -n "${GRYPE_DB_ARCHIVE:-}" ]]; then
    [[ -f "${GRYPE_DB_ARCHIVE}" ]] || die "GRYPE_DB_ARCHIVE=${GRYPE_DB_ARCHIVE} is not a file"
    cp "${GRYPE_DB_ARCHIVE}" "${IMAGES_DIR}/${GRYPE_DB_FILE}.part"
    mv "${IMAGES_DIR}/${GRYPE_DB_FILE}.part" "${IMAGES_DIR}/${GRYPE_DB_FILE}"
    (cd "${IMAGES_DIR}" && sha256sum "${GRYPE_DB_FILE}" >"${GRYPE_DB_FILE}.sha256")
    log "added Grype database ${GRYPE_DB_ARCHIVE} as ${IMAGES_DIR}/${GRYPE_DB_FILE}"
  fi
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
    --exclude='deploy/staging/images' --exclude='deploy/staging/deploy-history' --exclude='deploy/staging/releases' \
    deploy/staging compose/aibom-config-overlay scripts/deploy/staging.sh scripts/deploy/staging_browser_check.py
  local -a ssh_opts=()
  # shellcheck disable=SC2206 # operator-supplied options, split on purpose
  [[ -n "${SSH_OPTS:-}" ]] && ssh_opts=(${SSH_OPTS})
  log "copying bundle and archive to ${target}:${dir}"
  # shellcheck disable=SC2029 # dir, tag and prefix are expanded here on purpose
  ssh "${ssh_opts[@]}" "${target}" "mkdir -p '${dir}/deploy/staging/images'"
  scp "${ssh_opts[@]}" "${bundle}" "${target}:${dir}/"
  scp "${ssh_opts[@]}" "${archive}" "${archive}.sha256" "${target}:${dir}/deploy/staging/images/"
  # The files in place are now the bundle's, no longer a recorded release's (files-tag).
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" "${target}" "cd '${dir}' && tar -xzf '$(basename "${bundle}")' && rm -f '$(basename "${bundle}")' \
    && rm -f deploy/staging/releases/files-tag \
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

record_services() { # <tag>: the STAGING_SERVICES <tag> is deployed with; no file means every service
  local f="${RELEASES_DIR}/$1/services"
  if [[ -n "${STAGING_SERVICES:-}" ]]; then
    # shellcheck disable=SC2086 # service names, one per line: split on purpose
    printf '%s\n' ${STAGING_SERVICES//,/ } >"${f}"
  else
    rm -f "${f}"
  fi
}

# `make check-staging` and `make rollback-staging` run this script over ssh without the STAGING_SERVICES the release
# was deployed with: without one from the operator, use the set recorded for <tag>, so a partial deploy is checked
# and rolled back as the partial deploy it is.
use_recorded_services() { # <tag>
  local f="${RELEASES_DIR}/$1/services"
  [[ -z "${STAGING_SERVICES:-}" && -s "${f}" ]] || return 0
  STAGING_SERVICES="$(paste -sd ' ' "${f}")"
  log "services: ${STAGING_SERVICES} (the STAGING_SERVICES $1 was deployed with)"
}

previous_of() { # <tag>: the tag that was running when <tag> was last deployed (deploy-history), empty if none
  [[ -f "${HISTORY_FILE}" ]] || return 0
  awk -v t="$1" '$2 == "deploy" && $3 == t && $4 == "previous" { p = $5 } END { print p }' "${HISTORY_FILE}"
}

# Alembic commands that need no database (heads, show, history read only the migration scripts) in a backend image.
alembic_offline() { # <image> <alembic args...>
  local image=$1
  shift
  docker run --rm --network none --entrypoint /backend/.venv/bin/python "${image}" -m alembic --config "${ALEMBIC_INI}" "$@"
}

image_head() { # <tag>: the head revision(s) of the tag's migrations, read from its backend image
  local out
  out="$(alembic_offline "$(image_of backend "$1")" heads)" || return 1
  awk 'NF { print $1 }' <<<"${out}" | sort | paste -sd' ' -
}

tag_head() { # <tag>: the head recorded when the tag was deployed, else read from its image
  if [[ -s "${RELEASES_DIR}/$1/alembic-head" ]]; then cat "${RELEASES_DIR}/$1/alembic-head"; else image_head "$1"; fi
}

knows_revisions() { # <tag> <revision>...: 0 when the tag's migrations contain every one of the revisions
  local image rev
  image="$(image_of backend "$1")"
  shift
  for rev in "$@"; do
    alembic_offline "${image}" show "${rev}" >/dev/null 2>&1 || return 1
  done
}

db_revision() { # the database's Alembic revision(s), space-separated; empty when Alembic never ran on it
  # Starts postgres when it is not running; never recreates it (the compose file in place may define it differently).
  compose up -d --no-recreate --wait postgres >&2 || return 1
  # shellcheck disable=SC2016 # expanded by the shell inside the postgres container
  compose exec -T postgres sh -c 'exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL' |
SELECT to_regclass('alembic_version') IS NOT NULL AS has_alembic \gset
\if :has_alembic
SELECT version_num FROM alembic_version ORDER BY version_num;
\endif
SQL
    paste -sd' ' -
}

app_services() { # every service but the stateful infrastructure
  local all s
  all="$(compose config --services)" || return 1
  for s in ${all}; do
    if [[ "${INFRA_SERVICES}" != *" ${s} "* ]]; then printf '%s\n' "${s}"; fi
  done
}

record_files() { # <tag>: keep the deploy files in place as the ones <tag> is started with
  local -a paths=()
  local p
  for p in "${RELEASE_FILES[@]}"; do
    if [[ -e "${REPO_ROOT}/${p}" ]]; then paths+=("${p}"); fi
  done
  mkdir -p "${RELEASES_DIR}/$1"
  tar -C "${REPO_ROOT}" -czf "${RELEASES_DIR}/$1/files.tar.gz.part" "${paths[@]}"
  mv "${RELEASES_DIR}/$1/files.tar.gz.part" "${RELEASES_DIR}/$1/files.tar.gz"
  printf '%s\n' "$1" >"${FILES_TAG_FILE}"
}

restore_files() { # <tag>: put <tag>'s recorded deploy files back in place. tar replaces each file with a new one, so
  # the copy of this script that is running is not touched.
  tar -C "${REPO_ROOT}" -xzf "${RELEASES_DIR}/$1/files.tar.gz"
  printf '%s\n' "$1" >"${FILES_TAG_FILE}"
}

up() { # compose up; returns compose's status (the listing after it is for the operator)
  local -a services=()
  local rc=0
  # shellcheck disable=SC2206 # service names, split on purpose
  [[ -n "${STAGING_SERVICES:-}" ]] && services=(${STAGING_SERVICES//,/ })
  log "docker compose up (${services[*]:-all services})"
  compose up -d --remove-orphans --wait --wait-timeout "${STAGING_WAIT_S:-600}" "${services[@]}" || rc=$?
  compose ps -a --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' || true
  return "${rc}"
}

# A tag can start only on a database at a revision its migrations contain: otherwise its migrate one-shot fails
# ("Can't locate revision identified by ...") and everything that waits for it never starts.
cmd_deploy() {
  require_host_files
  local tag=${1:-${DSS_TAG:-}} archive running previous head="" db in_place c
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
  running="$(env_get DSS_TAG)"
  previous="${running}"
  # A redeploy of the running tag keeps the tag it replaced as the rollback target.
  [[ "${previous}" == "${tag}" ]] && previous="$(previous_of "${tag}")"
  if docker image inspect "$(image_of backend "${tag}")" >/dev/null 2>&1; then
    head="$(image_head "${tag}")" || die "cannot read the Alembic head of $(image_of backend "${tag}")"
    [[ -n "${head}" ]] || die "$(image_of backend "${tag}") has no Alembic revisions"
    if [[ -n "${running}" ]]; then
      db="$(db_revision)" || die "cannot read the database's Alembic revision (postgres; output above)"
      # shellcheck disable=SC2086 # one argument per revision
      if [[ -n "${db}" ]] && ! knows_revisions "${tag}" ${db}; then
        die "the database is at ${db}, which ${tag}'s migrations do not contain (a newer release migrated it), so" \
          "${tag} cannot start on it. Nothing was changed. To go back to the release before ${running}: staging.sh rollback"
      fi
    fi
  fi
  in_place="$(cat "${FILES_TAG_FILE}" 2>/dev/null || true)"
  if [[ -n "${in_place}" && "${in_place}" != "${tag}" && -f "${RELEASES_DIR}/${tag}/files.tar.gz" ]]; then
    log "the deploy files in place are ${in_place}'s (rollback); putting back ${tag}'s"
    restore_files "${tag}"
  else
    if [[ -n "${in_place}" && "${in_place}" != "${tag}" ]]; then
      log "WARNING: the deploy files in place are ${in_place}'s and none are recorded for ${tag}; starting ${tag} with them"
    fi
    record_files "${tag}"
  fi
  [[ -z "${head}" ]] || printf '%s\n' "${head}" >"${RELEASES_DIR}/${tag}/alembic-head"
  record_services "${tag}"
  set_tag "${tag}"
  if ! up; then
    [[ -n "${previous}" && "${previous}" != "${tag}" ]] && log "start failed; to go back: staging.sh rollback"
    printf '%s deploy %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" \
      "${head:-unknown}" >>"${HISTORY_FILE}"
    die "compose up failed for ${tag}"
  fi
  printf '%s deploy %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" "${head:-unknown}" \
    >>"${HISTORY_FILE}"
  cmd_check
  log "deployed ${tag}; previous tag ${previous:-none} is kept for rollback"
}

# The database is at a revision the target's migrations do not contain (a later release migrated it). Step it down
# to the target's head with the current image, whose migrations contain both, before anything is switched.
downgrade_database() { # <current tag> <target tag> <database revision> <target head> <allowed: 0|1>
  local current=$1 target=$2 db=$3 head=$4 allowed=$5 answer services
  [[ "${head}" != *" "* ]] || die "${target} has several Alembic heads (${head}); downgrade the database by hand"
  [[ "${db}" != *" "* ]] || die "the database has several Alembic heads (${db}); downgrade it by hand"
  if ! knows_revisions "${current}" "${head}"; then
    die "no downgrade path: ${current}'s migrations do not contain ${head} (${target}'s head), so the database" \
      "(at ${db}) cannot be stepped down for ${target}. Nothing was changed. Restore a database backup taken before" \
      "${current} was deployed instead."
  fi
  cat >&2 <<EOF
[staging] The database is at ${db}; ${target}'s migrations end at ${head} and cannot start on it.
[staging] The rollback first runs \`alembic downgrade ${head}\` with ${current}'s image. It reverses the migrations below
[staging] that come after ${head} and DROPS the tables and columns they added, with their data (take a backup first):
EOF
  alembic_offline "$(image_of backend "${current}")" history -r "${head}:${db}" >&2 || true
  if [[ "${allowed}" != 1 ]]; then
    [[ -t 0 ]] || die "rolling back to ${target} needs that database downgrade; nothing was changed." \
      "Re-run with --allow-downgrade (staging.sh rollback --allow-downgrade; make rollback-... ALLOW_DOWNGRADE=1)"
    read -r -p "[staging] Type 'downgrade' to continue: " answer || answer=""
    [[ "${answer}" == downgrade ]] || die "aborted; nothing was changed"
  fi
  services="$(app_services)" || die "docker compose config failed; nothing was changed"
  [[ -n "${services}" ]] || die "docker compose config lists no application services; nothing was changed"
  log "stopping the application services, then alembic downgrade ${head} with ${current}'s image"
  # shellcheck disable=SC2086 # one argument per service
  if ! compose stop ${services} || ! compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python migrate \
    -m alembic --config "${ALEMBIC_INI}" downgrade "${head}"; then
    log "the downgrade failed; starting ${current} again (its migrate brings the database back to its head)"
    up || true
    die "rollback to ${target} refused: alembic downgrade ${head} failed (output above); ${current} was restarted"
  fi
}

cmd_rollback() {
  require_host_files
  local allowed=0 arg current previous head db c
  for arg in "$@"; do
    case "${arg}" in
      --allow-downgrade) allowed=1 ;;
      *) die "unknown rollback option ${arg} (see --help)" ;;
    esac
  done
  current="$(env_get DSS_TAG)"
  previous="$(previous_of "${current}")"
  [[ -n "${previous}" && "${previous}" != none ]] || die "no previous tag recorded for ${current} in ${HISTORY_FILE}"
  use_recorded_services "${previous}"
  for c in $(components); do
    docker image inspect "$(image_of "${c}" "${previous}")" >/dev/null 2>&1 || [[ -n "${STAGING_SERVICES:-}" ]] ||
      die "image $(image_of "${c}" "${previous}") is no longer on this host; cannot roll back to ${previous}"
  done
  head="$(tag_head "${previous}")" || die "cannot read the Alembic head of $(image_of backend "${previous}")"
  [[ -n "${head}" ]] || die "no Alembic head known for ${previous}"
  db="$(db_revision)" || die "cannot read the database's Alembic revision (postgres; output above)"
  log "rolling back ${current} -> ${previous}: database at ${db:-no revision}, ${previous}'s migrations end at ${head}"
  # shellcheck disable=SC2086 # one argument per revision
  if [[ -n "${db}" ]] && ! knows_revisions "${previous}" ${db}; then
    downgrade_database "${current}" "${previous}" "${db}" "${head}" "${allowed}"
  fi
  cat >&2 <<EOF
[staging] WARNING: users whose password was rehashed to Argon2id by ${current} cannot sign in on an image without
[staging]   Argon2 support; they must reset their password after a later upgrade.
EOF
  if [[ -f "${RELEASES_DIR}/${previous}/files.tar.gz" ]]; then
    log "putting back ${previous}'s deploy files (compose file, nginx, rollup overlay, staging.sh)"
    restore_files "${previous}"
  else
    log "WARNING: no deploy files are recorded for ${previous} (deployed before they were kept); using ${current}'s"
  fi
  set_tag "${previous}"
  if ! up; then
    printf '%s rollback %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" \
      >>"${HISTORY_FILE}"
    die "compose up failed for ${previous}; after fixing the cause: staging.sh deploy ${previous}" \
      "(or forward again: staging.sh deploy ${current})"
  fi
  printf '%s rollback %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" \
    >>"${HISTORY_FILE}"
  cmd_check
  log "rolled back to ${previous}"
}

# Every service of the stack (or of STAGING_SERVICES) has a container from <tag>'s images that is running, and
# healthy when it has a health check; one-shots exited 0.
check_services() { # <tag>
  local tag=$1 pfx want ps svc s image state health code found bad=0
  pfx="$(prefix)"
  if [[ -n "${STAGING_SERVICES:-}" ]]; then
    want="${STAGING_SERVICES//,/ }"
  else
    want="$(compose config --services)" || die "docker compose config failed"
  fi
  ps="$(compose ps -a --format '{{.Service}}|{{.Image}}|{{.State}}|{{.Health}}|{{.ExitCode}}')" ||
    die "docker compose ps failed"
  for svc in ${want}; do
    found=0
    while IFS='|' read -r s image state health code; do
      [[ "${s}" == "${svc}" ]] || continue
      found=1
      if [[ "${image}" == "${pfx}/"* && "${image}" != *":${tag}" ]]; then
        log "FAIL ${svc}: runs ${image}, not ${tag}"
        bad=1
      fi
      if [[ "${ONESHOT_SERVICES}" == *" ${svc} "* ]]; then
        if [[ "${state}" != exited || "${code}" != 0 ]]; then
          log "FAIL ${svc}: ${state} (exit ${code}); a one-shot must have exited 0"
          bad=1
        fi
      elif [[ "${state}" != running || (-n "${health}" && "${health}" != healthy) ]]; then
        log "FAIL ${svc}: ${state}${health:+ (${health})}"
        bad=1
      fi
    done <<<"${ps}"
    if [[ "${found}" == 0 ]]; then
      log "FAIL ${svc}: no container"
      bad=1
    fi
  done
  [[ "${bad}" == 0 ]] || die "not every service runs ${tag} and is up (above)"
  log "services on ${tag}, up: ${want//$'\n'/ }"
}

# Services, then health and hydration through nginx, the way a browser reaches the site. Host names resolve to this
# machine.
cmd_check() {
  local tag fe api scheme port cert_dir tmp code chunk found=0 m
  tag="$(env_get DSS_TAG)"
  [[ -n "${tag}" ]] || die "DSS_TAG is not set in ${ENV_FILE}"
  use_recorded_services "${tag}"
  check_services "${tag}"
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
    rollback) cmd_rollback "$@" ;;
    -h | --help | help | "") sed -n '2,27p' "${BASH_SOURCE[0]}" ;;
    *) die "unknown command ${cmd} (see --help)" ;;
  esac
}

main "$@"
