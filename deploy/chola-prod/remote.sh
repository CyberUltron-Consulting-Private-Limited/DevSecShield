#!/usr/bin/env bash
# remote.sh - the instance side of the Chola production kit (deploy/chola-prod/README.md). scripts/deploy/chola-prod.sh
# copies it to /opt/devsecshield-chola/deploy/chola-prod/ and runs it over the EC2 Instance Connect tunnel as ubuntu;
# nobody needs to run it by hand (it can be, for troubleshooting: same commands).
#
#   remote.sh preflight                     Docker, Compose, AWS CLI + instance role, the data volume, disk, IMDS view
#   remote.sh infra-missing                 the infrastructure images that are not loaded (one per line)
#   remote.sh infra-load <s3 uri> <sha256>  download the release archive to /var/lib/docker/releases, check, load, delete
#   remote.sh render [<tag>]                .env + backend.env from Secrets Manager with the instance role (kit.py)
#   remote.sh ecr-login                     docker login to the ECR registry with the instance role
#   remote.sh pull <tag>                    pull the four application images of <tag> from ECR (linux/amd64 checked)
#   remote.sh volume-exists                 exit 0 when the PostgreSQL volume exists (a database was initialised)
#   remote.sh dump                          logical dumps of PostgreSQL and MongoDB onto the data volume (before the
#                                           backup job), the last CHOLA_DUMPS_KEEP (default 3) of each kept
#   remote.sh deploy <tag>                  refuse a tag older than the database; record; switch DSS_TAG; migrate + up;
#                                           check; estate backfill + agility heal; keep images of this, previous, last-passed
#   remote.sh rollback [--allow-downgrade]  back to the previously deployed tag (alembic downgrade only when allowed)
#   remote.sh check                         every service on DSS_TAG and up; health + frontend through nginx on :80
#   remote.sh smtp-test                     SMTP login only, from the backend container with backend.env (sends nothing)
#   remote.sh admin <email>                 make an existing account the platform administrator (is_superuser)
#   remote.sh status | logs [service|all] [N]
#
# Settings come from the caller (chola-prod.sh passes them): CHOLA_REGION, CHOLA_REGISTRY, CHOLA_IMAGE_PREFIX,
# CHOLA_SECRET_PREFIX, CHOLA_FRONTEND_HOST, CHOLA_API_HOST, CHOLA_REAL_IP_FROM; defaults are the Chola values.
set -euo pipefail
export LC_ALL=C

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${KIT_DIR}/../.." && pwd)"
COMPOSE_FILE="${KIT_DIR}/docker-compose.yml"
ENV_FILE="${KIT_DIR}/.env"
BACKEND_ENV="${KIT_DIR}/backend.env"
STATE_DIR="${BASE_DIR}/state"
HISTORY_FILE="${STATE_DIR}/deploy-history"
RELEASES_DIR="${STATE_DIR}/releases"
PASSED_FILE="${STATE_DIR}/passed"
RELEASE_FILES=(deploy/chola-prod compose/aibom-config-overlay)
RELEASE_EXCLUDES=(--exclude=deploy/chola-prod/.env --exclude=deploy/chola-prod/backend.env)
ARCHIVE_DIR=/var/lib/docker/releases
DUMP_DIR=/var/lib/docker/dss-backups
ALEMBIC_INI=/prod_database_migrations/alembic.ini
PROJECT=dss-chola

REGION="${CHOLA_REGION:-ap-south-1}"
REGISTRY="${CHOLA_REGISTRY:-935951870001.dkr.ecr.ap-south-1.amazonaws.com}"
IMAGE_PREFIX="${CHOLA_IMAGE_PREFIX:-${REGISTRY}/devsec-chola}"
SECRET_PREFIX="${CHOLA_SECRET_PREFIX:-devsec-chola/prod}"
FRONTEND_HOST="${CHOLA_FRONTEND_HOST:-chola.zeroshield.ai}"
API_HOST="${CHOLA_API_HOST:-chola-api.zeroshield.ai}"
REAL_IP_FROM="${CHOLA_REAL_IP_FROM:-10.60.1.0/24,10.60.2.0/24}"
# Must match the images in docker-compose.yml (backend/tests/test_chola_prod_kit.py checks) and INFRA_IMAGES in
# scripts/deploy/chola-prod.sh, which puts them in the release archive.
INFRA_IMAGES=(postgres:15-alpine mongo:8.0.6 rabbitmq:4.1-management-alpine nginx:1.27-alpine qdrant/qdrant:v1.13.5)
APP_REPOS=(devsecshield-backend devsecshield-frontend scan-worker dast-worker)
INFRA_SERVICES=" postgres mongo rabbitmq qdrant "
ONESHOT_SERVICES=" migrate "
DEV_MARKERS=('hmr-client' '_browser_dev_' 'webpack-hmr' 'react-refresh' '\"b\":\"development\"')

log() { printf '[chola-remote %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[chola-remote] ERROR: %s\n' "$*" >&2; exit 1; }

DOCKER=(docker)
docker_setup() { # plain docker when ubuntu is in the docker group, else sudo -n docker
  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
  elif sudo -n docker info >/dev/null 2>&1; then
    DOCKER=(sudo -n docker)
  else
    die "cannot talk to Docker as $(id -un) (not in the docker group, no passwordless sudo)"
  fi
}
files_hash() { # sha256 over the bind-mounted files (nginx config, aibom overlay): docker-compose.yml's files-hash label
  (cd "${BASE_DIR}" && find deploy/chola-prod/nginx compose/aibom-config-overlay -type f 2>/dev/null | LC_ALL=C sort |
    xargs -r sha256sum | sha256sum | cut -c1-16)
}
compose() {
  DSS_FILES_HASH="${DSS_FILES_HASH:-$(files_hash)}" "${DOCKER[@]}" compose --project-name "${PROJECT}" --project-directory "${KIT_DIR}" -f "${COMPOSE_FILE}" \
    --env-file "${ENV_FILE}" "$@"
}

env_get() { # <KEY> [default] from .env without sourcing it
  local v=""
  [[ -f "${ENV_FILE}" ]] && v="$(sed -n -E "s/^$1=[\"']?([^\"']*)[\"']?[[:space:]]*$/\1/p" "${ENV_FILE}" | tail -n 1)"
  printf '%s\n' "${v:-${2:-}}"
}
set_tag() { # rewrite only the DSS_TAG line of .env
  [[ "$1" =~ ^[0-9a-f]{12}$ ]] || die "tag $1 is not a 12-character commit"
  if grep -q '^DSS_TAG=' "${ENV_FILE}"; then
    sed -i -E "s|^DSS_TAG=.*|DSS_TAG='$1'|" "${ENV_FILE}"
  else
    printf "DSS_TAG='%s'\n" "$1" >>"${ENV_FILE}"
  fi
}
image_of() { printf '%s/%s:%s\n' "${IMAGE_PREFIX}" "$1" "$2"; }

require_env_files() {
  [[ -f "${ENV_FILE}" && -f "${BACKEND_ENV}" ]] || die "missing ${ENV_FILE} or ${BACKEND_ENV} (chola-prod.sh renders them)"
  local f mode
  for f in "${ENV_FILE}" "${BACKEND_ENV}"; do
    mode="$(stat -c %a "${f}")"
    [[ "${mode}" == 600 ]] || die "${f} has mode ${mode}, expected 600"
  done
  if grep -Eq "^[[:space:]]*(export[[:space:]]+)?(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_(EMAIL|CODE))[[:space:]]*=" \
    "${ENV_FILE}" "${BACKEND_ENV}"; then
    die "DSS_DEV_MODE / LOCAL_DEV_VERIFICATION_* must never be set in production"
  fi
}

# ------------------------------------------------------------------------------------------------ preflight
cmd_preflight() {
  local bad=0 root croot dev_root dev_slash
  docker_setup
  log "docker: $("${DOCKER[@]}" version --format 'engine {{.Server.Version}}') ($(printf '%s' "${DOCKER[*]}")); compose: $("${DOCKER[@]}" compose version --short)"
  command -v python3 >/dev/null || { log "FAIL python3 is missing"; bad=1; }
  if command -v aws >/dev/null; then
    log "aws: $(aws --version 2>&1 | cut -d' ' -f1)"
    if arn="$(aws sts get-caller-identity --region "${REGION}" --query Arn --output text 2>/dev/null)"; then
      log "instance identity: ${arn}"
    else
      log "FAIL the instance role answers no STS call (aws sts get-caller-identity)"
      bad=1
    fi
  else
    log "FAIL the AWS CLI is not installed on the instance (chola-prod.sh host-setup installs it)"
    bad=1
  fi
  root="$("${DOCKER[@]}" info --format '{{.DockerRootDir}}')"
  dev_root="$(stat -c %d "${root}" 2>/dev/null || sudo -n stat -c %d "${root}")"
  dev_slash="$(stat -c %d /)"
  if [[ "${dev_root}" == "${dev_slash}" ]]; then
    log "FAIL ${root} is on the root filesystem, not on the separate data volume: databases would land on the root disk"
    bad=1
  else
    log "data volume: ${root} is $(findmnt -n -o SOURCE,FSTYPE,SIZE,AVAIL -T "${root}" | tr -s ' ')"
  fi
  if "${DOCKER[@]}" info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter && [[ -d /var/lib/containerd ]]; then
    croot=/var/lib/containerd
    log "image store: containerd snapshotter, images in ${croot}: $(findmnt -n -o SOURCE,AVAIL -T "${croot}" | tr -s ' ') free (volumes stay in ${root}/volumes)"
  fi
  log "free: / $(df -h --output=avail / | tail -1 | tr -d ' '), ${root} $(df -h --output=avail "${root}" | tail -1 | tr -d ' ')"
  if [[ -f "${ENV_FILE}" ]]; then log "deployed tag: $(env_get DSS_TAG none)"; else log "not deployed yet (no ${ENV_FILE})"; fi
  if "${DOCKER[@]}" volume inspect "${PROJECT}_pgdata" >/dev/null 2>&1; then log "database volume ${PROJECT}_pgdata exists"; fi
  local missing
  missing="$(infra_missing | paste -sd' ' -)"
  log "infrastructure images missing: ${missing:-none}"
  # IMDS from containers: Docker's bridge adds a hop; with HttpPutResponseHopLimit 1 and IMDSv2 required, containers
  # cannot get the instance role's credentials (which read every devsec-chola/prod secret). The app does not need it.
  local tok probe
  tok="$(curl -s -m 3 --noproxy '*' -o /dev/null -w '%{http_code}' -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    http://169.254.169.254/latest/api/token || true)"
  if [[ "${tok}" == 200 ]]; then log "IMDSv2 answers on the host (the AWS CLI here uses the instance role)"; else
    log "FAIL IMDSv2 does not answer on the host (HTTP ${tok:-none}): the instance role is unusable here"; bad=1; fi
  if "${DOCKER[@]}" image inspect qdrant/qdrant:v1.13.5 >/dev/null 2>&1; then
    # A raw IMDSv2 token PUT from a bridge-network container (the qdrant image has bash and timeout).
    probe="$("${DOCKER[@]}" run --rm --network bridge --entrypoint bash qdrant/qdrant:v1.13.5 -c \
      'exec 3<>/dev/tcp/169.254.169.254/80 || exit 2; printf "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nConnection: close\r\n\r\n" >&3; timeout 4 head -n 1 <&3 | grep -q " 200 " && echo reachable || echo blocked' 2>/dev/null || echo blocked)"
    if [[ "${probe}" == reachable ]]; then
      log "WARNING containers CAN get an IMDSv2 token (hop limit > 1): a compromised container could read the instance role's secrets; ask for HttpPutResponseHopLimit=1"
    else
      log "IMDS token from a container: blocked (good: containers cannot use the instance role)"
    fi
  fi
  [[ "${bad}" == 0 ]] || die "instance preflight failed (above)"
  log "instance preflight OK"
}

infra_missing() {
  local i
  for i in "${INFRA_IMAGES[@]}"; do
    "${DOCKER[@]}" image inspect "${i}" >/dev/null 2>&1 || printf '%s\n' "${i}"
  done
}

# ------------------------------------------------------------------------------------------------ infrastructure images
cmd_infra_load() {
  local uri=${1:?usage: remote.sh infra-load <s3 uri> <sha256>} want=${2:?sha256} file got missing arch i
  [[ "${uri}" =~ ^s3://[a-z0-9.-]+/[A-Za-z0-9._/-]+$ ]] || die "not an s3:// URI: ${uri}"
  [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "not a sha256: ${want}"
  sudo -n mkdir -p "${ARCHIVE_DIR}"
  sudo -n chown "$(id -u):$(id -g)" "${ARCHIVE_DIR}"
  chmod 700 "${ARCHIVE_DIR}"
  file="${ARCHIVE_DIR}/release.tar"
  rm -f "${file}"
  # shellcheck disable=SC2064 # expand now
  trap "rm -f '${file}'" EXIT
  log "downloading ${uri} to ${file} (data volume)"
  aws s3 cp --only-show-errors --region "${REGION}" "${uri}" "${file}"
  got="$(sha256sum "${file}" | cut -d' ' -f1)"
  [[ "${got}" == "${want}" ]] || die "release archive sha256 ${got} is not ${want} (damaged or replaced)"
  log "sha256 ok; docker load"
  "${DOCKER[@]}" load -i "${file}"
  rm -f "${file}"
  trap - EXIT
  missing="$(infra_missing | paste -sd' ' -)"
  [[ -z "${missing}" ]] || die "still missing after the load: ${missing}"
  for i in "${INFRA_IMAGES[@]}"; do
    arch="$("${DOCKER[@]}" image inspect -f '{{.Os}}/{{.Architecture}}' "${i}")"
    [[ "${arch}" == linux/amd64 ]] || die "${i} is ${arch}, not linux/amd64"
  done
  log "infrastructure images loaded (linux/amd64): ${INFRA_IMAGES[*]}; archive deleted"
}

# ------------------------------------------------------------------------------------------------ env, registry, images
cmd_render() { # [<tag>]: the tag is written only when .env has none yet (first deploy); deploy switches it later
  local tag
  tag="$(env_get DSS_TAG)"
  tag="${tag:-${1:-}}"
  command -v python3 >/dev/null || die "python3 is missing"
  command -v aws >/dev/null || die "the AWS CLI is missing (chola-prod.sh host-setup)"
  umask 077
  python3 -I "${KIT_DIR}/kit.py" render-env --dir "${KIT_DIR}" --tag "${tag}" --secret-prefix "${SECRET_PREFIX}" \
    --region "${REGION}" --image-prefix "${IMAGE_PREFIX}" --frontend-host "${FRONTEND_HOST}" --api-host "${API_HOST}" \
    --real-ip-from "${REAL_IP_FROM}"
  require_env_files
}

cmd_ecr_login() {
  docker_setup
  aws ecr get-login-password --region "${REGION}" | "${DOCKER[@]}" login --username AWS --password-stdin "${REGISTRY}" >/dev/null
  log "logged in to ${REGISTRY} (instance role)"
}

disk_check() { # refuse to pull with less than CHOLA_MIN_FREE_GB (default 15) free where images and volumes live
  local min=${CHOLA_MIN_FREE_GB:-15} p avail
  for p in "$("${DOCKER[@]}" info --format '{{.DockerRootDir}}')" /var/lib/containerd /; do
    [[ -e "${p}" ]] || continue
    avail="$(df -P -BG "${p}" | awk 'NR == 2 { sub("G", "", $4); print $4 }')"
    ((avail >= min)) || die "only ${avail} GB free on $(findmnt -n -o TARGET -T "${p}") (need ${min} GB): remove old images (remote.sh status lists them)"
  done
}

cmd_pull() {
  local tag=${1:?usage: remote.sh pull <tag>} r ref arch
  [[ "${tag}" =~ ^[0-9a-f]{12}$ ]] || die "tag ${tag} is not a 12-character commit"
  docker_setup
  disk_check
  for r in "${APP_REPOS[@]}"; do
    ref="$(image_of "${r}" "${tag}")"
    if "${DOCKER[@]}" image inspect "${ref}" >/dev/null 2>&1; then
      log "${ref} already here"
    else
      log "pulling ${ref}"
      "${DOCKER[@]}" pull -q --platform linux/amd64 "${ref}" >/dev/null || die "pull of ${ref} failed (ecr-login? pushed?)"
    fi
    arch="$("${DOCKER[@]}" image inspect -f '{{.Os}}/{{.Architecture}}' "${ref}")"
    [[ "${arch}" == linux/amd64 ]] || die "${ref} is ${arch}, not linux/amd64"
  done
  log "images of ${tag} present (linux/amd64)"
}

cmd_volume_exists() {
  docker_setup
  "${DOCKER[@]}" volume inspect "${PROJECT}_pgdata" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------------------------ logical dumps
cmd_dump() {
  docker_setup
  require_env_files
  local ts keep=${CHOLA_DUMPS_KEEP:-3} f
  if [[ -z "$(compose ps -q --status running postgres 2>/dev/null)" ]]; then
    log "postgres is not running: no logical dump (first deploy?)"
    return 0
  fi
  sudo -n mkdir -p "${DUMP_DIR}"
  sudo -n chown "$(id -u):$(id -g)" "${DUMP_DIR}"
  chmod 700 "${DUMP_DIR}"
  ts="$(date -u +%Y%m%dT%H%M%SZ)-$(env_get DSS_TAG none)"
  umask 077
  log "pg_dump -> ${DUMP_DIR}/pg-${ts}.dump"
  # shellcheck disable=SC2016 # expanded inside the container
  compose exec -T postgres sh -c 'exec pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >"${DUMP_DIR}/pg-${ts}.dump.part"
  mv "${DUMP_DIR}/pg-${ts}.dump.part" "${DUMP_DIR}/pg-${ts}.dump"
  if [[ -n "$(compose ps -q --status running mongo 2>/dev/null)" ]]; then
    log "mongodump -> ${DUMP_DIR}/mongo-${ts}.archive.gz"
    # shellcheck disable=SC2016
    compose exec -T mongo sh -c 'exec mongodump --quiet --archive --gzip -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin' \
      >"${DUMP_DIR}/mongo-${ts}.archive.gz.part"
    mv "${DUMP_DIR}/mongo-${ts}.archive.gz.part" "${DUMP_DIR}/mongo-${ts}.archive.gz"
  fi
  for f in pg mongo; do
    find "${DUMP_DIR}" -maxdepth 1 -name "${f}-*" ! -name '*.part' -printf '%T@ %p\n' | sort -rn | awk -v k="${keep}" 'NR > k { print $2 }' |
      while IFS= read -r old; do rm -f -- "${old}"; log "removed old dump ${old}"; done
  done
  log "dumps: $(find "${DUMP_DIR}" -maxdepth 1 -type f ! -name '*.part' -name "*${ts}*" -printf '%f (%s bytes) ' )"
}

# ------------------------------------------------------------------------------------------------ alembic helpers
alembic_offline() { # <image> <alembic args...>: commands that read only the migration scripts
  local image=$1
  shift
  "${DOCKER[@]}" run --rm --network none --entrypoint /backend/.venv/bin/python "${image}" -m alembic --config "${ALEMBIC_INI}" "$@"
}
image_head() { # <tag>
  local out
  out="$(alembic_offline "$(image_of devsecshield-backend "$1")" heads)" || return 1
  awk 'NF { print $1 }' <<<"${out}" | sort | paste -sd' ' -
}
tag_head() { if [[ -s "${RELEASES_DIR}/$1/alembic-head" ]]; then cat "${RELEASES_DIR}/$1/alembic-head"; else image_head "$1"; fi; }
knows_revisions() { # <tag> <revision>...
  local image rev
  image="$(image_of devsecshield-backend "$1")"
  shift
  for rev in "$@"; do alembic_offline "${image}" show "${rev}" >/dev/null 2>&1 || return 1; done
}
db_revision() { # the database's Alembic revision(s); empty when Alembic never ran on it
  compose up -d --no-recreate --wait postgres >&2 || return 1
  # shellcheck disable=SC2016 # expanded inside the container
  compose exec -T postgres sh -c 'exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL' |
SELECT to_regclass('alembic_version') IS NOT NULL AS has_alembic \gset
\if :has_alembic
SELECT version_num FROM alembic_version ORDER BY version_num;
\endif
SQL
    paste -sd' ' -
}
app_services() {
  local all s
  all="$(compose config --services)" || return 1
  for s in ${all}; do [[ "${INFRA_SERVICES}" == *" ${s} "* ]] || printf '%s\n' "${s}"; done
}
previous_of() { [[ -f "${HISTORY_FILE}" ]] || return 0; awk -v t="$1" '$2 == "deploy" && $3 == t && $4 == "previous" { p = $5 } END { print p }' "${HISTORY_FILE}"; }
last_passed() { [[ -s "${PASSED_FILE}" ]] || return 0; awk -v x="${1:-}" 'NF && $1 != x { t = $1 } END { print t }' "${PASSED_FILE}"; }
record_files() { # <tag>: the deploy files this tag is started with (for a rollback to it)
  mkdir -p "${RELEASES_DIR}/$1"
  tar -C "${BASE_DIR}" "${RELEASE_EXCLUDES[@]}" -czf "${RELEASES_DIR}/$1/files.tar.gz.part" "${RELEASE_FILES[@]}"
  mv "${RELEASES_DIR}/$1/files.tar.gz.part" "${RELEASES_DIR}/$1/files.tar.gz"
}
restore_files() { tar -C "${BASE_DIR}" -xzf "${RELEASES_DIR}/$1/files.tar.gz"; }

up() {
  local rc=0
  log "docker compose up (migrate runs first; everything else waits for it)"
  compose up -d --remove-orphans --wait --wait-timeout "${CHOLA_WAIT_S:-900}" || rc=$?
  compose ps -a --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' || true
  if [[ "${rc}" != 0 ]]; then
    log "last migrate / backend log lines:"
    compose logs --no-color --tail 40 migrate backend 2>&1 | sed 's/^/    /' || true
  fi
  return "${rc}"
}

retain() { # <tag> <previous> <last passed>: remove this deployment's other application images (never forced)
  local keep=" $1 $2 $3 " ref t
  while IFS= read -r ref; do
    t="${ref##*:}"
    [[ "${keep}" == *" ${t} "* ]] && continue
    if "${DOCKER[@]}" image rm "${ref}" >/dev/null 2>&1; then log "retention: removed ${ref}"; fi
  done < <("${DOCKER[@]}" image ls --format '{{.Repository}}:{{.Tag}}' | grep -E "^${IMAGE_PREFIX//./\\.}/(devsecshield-backend|devsecshield-frontend|scan-worker|dast-worker):[0-9a-f]{12}$" || true)
}

# ------------------------------------------------------------------------------------------------ deploy / rollback
cmd_deploy() {
  local tag=${1:?usage: remote.sh deploy <tag>} running previous head db last r
  [[ "${tag}" =~ ^[0-9a-f]{12}$ ]] || die "tag ${tag} is not a 12-character commit"
  docker_setup
  require_env_files
  mkdir -p "${STATE_DIR}"
  for r in "${APP_REPOS[@]}"; do
    "${DOCKER[@]}" image inspect "$(image_of "${r}" "${tag}")" >/dev/null 2>&1 || die "$(image_of "${r}" "${tag}") is not pulled"
  done
  local missing
  missing="$(infra_missing | paste -sd' ' -)"
  [[ -z "${missing}" ]] || die "infrastructure images missing: ${missing} (chola-prod.sh loads the release archive)"
  # What runs now: the tag of the backend container (none before the first deploy). Not .env's DSS_TAG: render may
  # have written the new tag there for a first deploy.
  running="$(compose ps -a --format '{{.Image}}' backend 2>/dev/null | sed -n -E 's/.*:([0-9a-f]{12})$/\1/p' | head -n 1)"
  previous="${running}"
  [[ "${previous}" != "${tag}" ]] || previous="$(previous_of "${tag}")"
  head="$(image_head "${tag}")" || die "cannot read the Alembic head of $(image_of devsecshield-backend "${tag}")"
  [[ -n "${head}" ]] || die "$(image_of devsecshield-backend "${tag}") has no Alembic revisions"
  db="$(db_revision)" || die "cannot read the database's Alembic revision (postgres; output above)"
  # shellcheck disable=SC2086 # one argument per revision
  if [[ -n "${db}" ]] && ! knows_revisions "${tag}" ${db}; then
    die "the database is at ${db}, which ${tag}'s migrations do not contain (a newer release migrated it): ${tag}" \
      "cannot start on it. Nothing was changed. To go back a release: chola-prod.sh rollback"
  fi
  log "deploying ${tag} (running: ${running:-nothing}; database at ${db:-no revision}; ${tag}'s head ${head})"
  record_files "${tag}"
  printf '%s\n' "${head}" >"${RELEASES_DIR}/${tag}/alembic-head"
  set_tag "${tag}"
  if ! up; then
    printf '%s deploy %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" "${head}" >>"${HISTORY_FILE}"
    die "compose up failed for ${tag}${previous:+; to go back: chola-prod.sh rollback}"
  fi
  printf '%s deploy %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" "${head}" >>"${HISTORY_FILE}"
  cmd_check
  log "estate backfill (idempotent)"
  compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python migrate -m backend.utilities.cbom_sources.estate backfill ||
    log "WARNING: estate backfill failed (above); the release is running"
  log "agility heal (idempotent)"
  compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python migrate -m backend.utilities.cbom_sources.agility_store heal ||
    log "WARNING: agility heal failed (above); the release is running"
  last="$(last_passed "${tag}")"
  printf '%s\n' "${tag}" >>"${PASSED_FILE}"
  retain "${tag}" "${previous}" "${last}"
  log "deployed ${tag}; rollback target: ${previous:-none}"
}

cmd_rollback() {
  local allowed=0 arg current previous head db services answer r
  for arg in "$@"; do
    case "${arg}" in
      --allow-downgrade) allowed=1 ;;
      *) die "unknown rollback option ${arg}" ;;
    esac
  done
  docker_setup
  require_env_files
  current="$(env_get DSS_TAG)"
  previous="$(previous_of "${current}")"
  [[ -n "${previous}" && "${previous}" != none ]] || die "no previous tag recorded for ${current} in ${HISTORY_FILE}"
  for r in "${APP_REPOS[@]}"; do
    "${DOCKER[@]}" image inspect "$(image_of "${r}" "${previous}")" >/dev/null 2>&1 || cmd_pull "${previous}"
  done
  head="$(tag_head "${previous}")" || die "cannot read the Alembic head of ${previous}"
  [[ -n "${head}" ]] || die "no Alembic head known for ${previous}"
  db="$(db_revision)" || die "cannot read the database's Alembic revision"
  log "rolling back ${current} -> ${previous}: database at ${db:-no revision}, ${previous}'s migrations end at ${head}"
  # shellcheck disable=SC2086
  if [[ -n "${db}" ]] && ! knows_revisions "${previous}" ${db}; then
    [[ "${head}" != *" "* && "${db}" != *" "* ]] || die "several Alembic heads (${head} / ${db}): downgrade by hand"
    knows_revisions "${current}" "${head}" || die "no downgrade path: ${current}'s migrations do not contain ${head}." \
      "Nothing was changed. Restore the pre-deployment backup instead (README 'Restore')."
    printf '[chola-remote] The database is at %s; %s ends at %s. The rollback first runs alembic downgrade %s with the image of %s;\n' \
      "${db}" "${previous}" "${head}" "${head}" "${current}" >&2
    printf '[chola-remote] that DROPS what these migrations added, with their data:\n' >&2
    alembic_offline "$(image_of devsecshield-backend "${current}")" history -r "${head}:${db}" >&2 || true
    if [[ "${allowed}" != 1 ]]; then
      [[ -t 0 ]] || die "the rollback needs that database downgrade; nothing was changed. Re-run with --allow-downgrade"
      read -r -p "[chola-remote] Type 'downgrade' to continue: " answer || answer=""
      [[ "${answer}" == downgrade ]] || die "aborted; nothing was changed"
    fi
    services="$(app_services)" || die "docker compose config failed; nothing was changed"
    log "stopping the application services, then alembic downgrade ${head} with ${current}'s image"
    # shellcheck disable=SC2086
    if ! compose stop ${services} || ! compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python migrate \
      -m alembic --config "${ALEMBIC_INI}" downgrade "${head}"; then
      log "the downgrade failed; starting ${current} again"
      up || true
      die "rollback to ${previous} refused: alembic downgrade failed (above); ${current} was restarted"
    fi
  fi
  if [[ -f "${RELEASES_DIR}/${previous}/files.tar.gz" ]]; then
    log "putting back ${previous}'s deploy files"
    restore_files "${previous}"
  fi
  set_tag "${previous}"
  if ! up; then
    printf '%s rollback %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
    die "compose up failed for ${previous}"
  fi
  printf '%s rollback %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
  cmd_check
  printf '%s\n' "${previous}" >>"${PASSED_FILE}"
  log "rolled back to ${previous} (users rehashed to Argon2id by ${current} may need a password reset on an older image)"
}

# ------------------------------------------------------------------------------------------------ checks
cmd_check() {
  docker_setup
  local tag want ps svc s image state health code found bad=0 tmp chunk m hit=0
  tag="$(env_get DSS_TAG)"
  [[ -n "${tag}" ]] || die "DSS_TAG is not set in ${ENV_FILE}"
  want="$(compose config --services)" || die "docker compose config failed"
  ps="$(compose ps -a --format '{{.Service}}|{{.Image}}|{{.State}}|{{.Health}}|{{.ExitCode}}')" || die "docker compose ps failed"
  for svc in ${want}; do
    found=0
    while IFS='|' read -r s image state health code; do
      [[ "${s}" == "${svc}" ]] || continue
      found=1
      if [[ "${image}" == "${IMAGE_PREFIX}/"* && "${image}" != *":${tag}" ]]; then log "FAIL ${svc}: runs ${image}, not ${tag}"; bad=1; fi
      if [[ "${ONESHOT_SERVICES}" == *" ${svc} "* ]]; then
        [[ "${state}" == exited && "${code}" == 0 ]] || { log "FAIL ${svc}: ${state} (exit ${code})"; bad=1; }
      elif [[ "${state}" != running || (-n "${health}" && "${health}" != healthy) ]]; then
        log "FAIL ${svc}: ${state}${health:+ (${health})}"
        bad=1
      fi
    done <<<"${ps}"
    [[ "${found}" == 1 ]] || { log "FAIL ${svc}: no container"; bad=1; }
  done
  [[ "${bad}" == 0 ]] || die "not every service runs ${tag} and is up (above)"
  log "services on ${tag}, up: ${want//$'\n'/ }"
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN
  local -a c=(curl -sS --noproxy '*' --max-time 30)
  local base
  base="http://127.0.0.1:$(env_get DSS_HTTP_PORT 80)"
  code="$("${c[@]}" -o "${tmp}/h" -w '%{http_code}' "${base}/nginx-health")" || code=000
  [[ "${code}" == 200 && "$(cat "${tmp}/h")" == ok ]] || die "http://localhost/nginx-health -> HTTP ${code}"
  log "nginx /nginx-health -> 200 ok (the ALB health check)"
  code="$("${c[@]}" -H "Host: ${API_HOST}" -H 'X-Forwarded-Proto: https' -o "${tmp}/health.json" -w '%{http_code}' "${base}/health")" || code=000
  if [[ "${code}" != 200 ]] || ! grep -q '"healthy"' "${tmp}/health.json"; then
    die "API ${API_HOST}/health through nginx -> HTTP ${code}"
  fi
  log "API ${API_HOST}/health through nginx -> 200 healthy"
  code="$("${c[@]}" -H "Host: ${FRONTEND_HOST}" -o "${tmp}/login.html" -w '%{http_code}' "${base}/login")" || code=000
  [[ "${code}" == 200 ]] || die "frontend ${FRONTEND_HOST}/login through nginx -> HTTP ${code}"
  grep -o '/_next/static/chunks/[^"\\ ]*\.js' "${tmp}/login.html" | sort -u >"${tmp}/chunks" || true
  [[ -s "${tmp}/chunks" ]] || die "the login page references no /_next/static/chunks/*.js (not a production build)"
  for m in "${DEV_MARKERS[@]}"; do
    if grep -qF -- "${m}" "${tmp}/login.html"; then die "the login page is served by \`next dev\` (found '${m}')"; fi
  done
  while read -r chunk; do
    code="$("${c[@]}" -H "Host: ${FRONTEND_HOST}" -o "${tmp}/chunk.js" -w '%{http_code}' "${base}${chunk}")" || code=000
    [[ "${code}" == 200 ]] || die "chunk ${chunk} -> HTTP ${code}"
    if grep -qF -- "https://${API_HOST}" "${tmp}/chunk.js"; then hit=1; fi
  done <"${tmp}/chunks"
  [[ "${hit}" == 1 ]] || die "no login-page chunk contains https://${API_HOST}: the frontend image was built for another API URL"
  log "frontend ${FRONTEND_HOST}/login -> 200, $(wc -l <"${tmp}/chunks") chunks, no dev markers, https://${API_HOST} baked in"
}

cmd_smtp_test() {
  docker_setup
  require_env_files
  local rc=0
  log "SMTP login test from a backend container (backend.env settings; authenticates only, sends nothing)"
  compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python backend - <"${KIT_DIR}/smtp_check.py" || rc=$?
  return "${rc}"
}

cmd_admin() {
  local email=${1:?usage: remote.sh admin <email>} out
  [[ "${email}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "not an e-mail address: ${email}"
  docker_setup
  require_env_files
  # psql's :'email' quotes the value as a literal; the address never becomes SQL.
  # shellcheck disable=SC2016 # expanded inside the container
  out="$(compose exec -T postgres sh -c 'exec psql -X -q -At -v ON_ERROR_STOP=1 -v email="$1" -U "$POSTGRES_USER" -d "$POSTGRES_DB"' sh "${email}" <<'SQL'
WITH u AS (UPDATE "user" SET is_superuser = true WHERE lower(email) = lower(:'email') RETURNING id) SELECT count(*) FROM u;
SQL
)" || die "the update failed (above)"
  case "${out}" in
    1) log "${email} is now the platform administrator: sign out and in again, then open https://${FRONTEND_HOST}/admin" ;;
    0) die "no account ${email} yet: sign up at https://${FRONTEND_HOST}/register first (the code arrives by e-mail)" ;;
    *) die "unexpected result '${out}' (more than one account matched?)" ;;
  esac
}

cmd_status() {
  docker_setup
  log "deployed tag: $(env_get DSS_TAG none); previous: $(previous_of "$(env_get DSS_TAG)")"
  compose ps -a --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' || true
  [[ -f "${HISTORY_FILE}" ]] && { log "deploy history (last 10):"; tail -n 10 "${HISTORY_FILE}" | sed 's/^/    /'; }
  log "application images here:"
  "${DOCKER[@]}" image ls --format '    {{.Repository}}:{{.Tag}} {{.Size}}' | grep -F "${IMAGE_PREFIX}/" || true
  log "disk: $(df -h --output=target,avail / /var/lib/docker 2>/dev/null | tail -n +2 | tr -s ' ' | paste -sd',' -)"
}

cmd_logs() {
  docker_setup
  local svc=${1:-all} n=${2:-200}
  [[ "${n}" =~ ^[0-9]{1,6}$ ]] || die "line count must be a number"
  if [[ "${svc}" != all ]]; then compose logs --no-color --tail "${n}" "${svc}"; else compose logs --no-color --tail "${n}"; fi
}

lock() { # one changing command at a time on this instance (two owners, or a retry while the first still runs)
  mkdir -p "${STATE_DIR}"
  exec 9>"${STATE_DIR}/.lock"
  flock -n 9 || die "another chola-prod command is running on this instance (${STATE_DIR}/.lock); wait for it"
}

main() {
  local cmd=${1:-}
  shift || true
  case "${cmd}" in
    infra-load | render | pull | dump | deploy | rollback | admin) lock ;;
  esac
  case "${cmd}" in
    preflight) cmd_preflight ;;
    infra-missing) docker_setup; infra_missing ;;
    infra-load) docker_setup; cmd_infra_load "$@" ;;
    render) cmd_render "$@" ;;
    ecr-login) cmd_ecr_login ;;
    pull) cmd_pull "$@" ;;
    volume-exists) cmd_volume_exists ;;
    dump) cmd_dump ;;
    deploy) cmd_deploy "$@" ;;
    rollback) cmd_rollback "$@" ;;
    check) cmd_check ;;
    smtp-test) cmd_smtp_test ;;
    admin) cmd_admin "$@" ;;
    status) cmd_status ;;
    logs) cmd_logs "$@" ;;
    -h | --help | help | "") sed -n '2,27p' "${BASH_SOURCE[0]}" ;;
    *) die "unknown command ${cmd}" ;;
  esac
}

main "$@"
