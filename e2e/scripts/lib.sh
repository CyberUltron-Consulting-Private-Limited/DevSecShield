#!/usr/bin/env bash
# lib.sh - shared helpers for the dss-e2e scripts. Source it; do not execute it.
#
# Everything the scripts must agree on lives here: paths, the compose project name, the label every
# Docker object we create carries, evidence-dir resolution, logging, condition-based waits, the
# per-run .env.e2e generator and the ONE path-guarded delete helper.
#
# Safety contract (the other scripts rely on it):
#   - the compose project is always exactly "dss-e2e", the buildx builder always "dss-fast";
#   - nothing here, or anywhere in e2e/, runs `docker system|image|volume|buildx prune`;
#   - `compose down -v` happens only in teardown.sh; files are deleted only via safe_rm_rf.
# shellcheck shell=bash
# Most constants below are consumed by the scripts that source this file, not by this file itself.
# shellcheck disable=SC2034

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "lib.sh is a library: source it from another script" >&2
  exit 2
fi

E2E_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
E2E_ROOT="$(cd "${E2E_SCRIPTS_DIR}/.." && pwd -P)"
REPO_ROOT="$(cd "${E2E_ROOT}/.." && pwd -P)"
readonly E2E_SCRIPTS_DIR E2E_ROOT REPO_ROOT

readonly E2E_PROJECT="dss-e2e"
readonly E2E_LABEL_KEY="com.dss-e2e"
readonly E2E_LABEL="${E2E_LABEL_KEY}=1"
readonly E2E_COMPOSE_FILE="${E2E_ROOT}/compose/docker-compose.e2e.yml"
readonly E2E_ENV_FILE="${E2E_ROOT}/compose/.env.e2e"
readonly E2E_WORK_DIR="${E2E_ROOT}/.work"
readonly E2E_TREES_DIR="${E2E_WORK_DIR}/trees"
readonly E2E_OUT_DIR="${E2E_WORK_DIR}/out"
readonly E2E_FRONTEND_PORT=43000
readonly E2E_BACKEND_PORT=43080
readonly E2E_BASE_URL="http://127.0.0.1:${E2E_FRONTEND_PORT}"
readonly E2E_API_URL="http://127.0.0.1:${E2E_BACKEND_PORT}"

# The builder the production image script uses. Images are only ever --load'ed, never pushed.
readonly E2E_BUILDER="dss-fast"
readonly E2E_IMG_BACKEND="dss-e2e/backend:local"
readonly E2E_IMG_FRONTEND="dss-e2e/frontend:local"
readonly E2E_IMG_AIBOM="dss-e2e/aibom-scan:local"
readonly E2E_PG_IMAGE="postgres:15-alpine"
readonly E2E_MONGO_IMAGE="mongo:8.0.6"

# @playwright/test 1.62.0 declares exactly these browser revisions (playwright-core/browsers.json).
readonly E2E_PLAYWRIGHT_VERSION="1.62.0"
readonly -a E2E_PLAYWRIGHT_REVISIONS=(chromium-1234 chromium_headless_shell-1234 ffmpeg-1011)

# Seed identities written into .env.e2e (the seed step creates these users; the specs log in as them).
readonly E2E_ADMIN_EMAIL_DEFAULT="e2e-admin@dss-e2e.test"
readonly E2E_OTHER_EMAIL_DEFAULT="e2e-other@dss-e2e.test"
readonly E2E_EMPTY_EMAIL_DEFAULT="e2e-empty@dss-e2e.test"

# ------------------------------------------------------------------------------------------------
# logging
# ------------------------------------------------------------------------------------------------
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
warn() { log "WARN: $*" >&2; }
die() {
  log "FATAL: $*" >&2
  exit 1
}

need_cmd() {
  local c
  for c in "$@"; do
    command -v "${c}" >/dev/null 2>&1 || die "required command not found: ${c}"
  done
}

git_sha() { git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown; }

git_dirty() {
  # Limit the scan to e2e/ and the inputs the images are built from: a full `git status` of this
  # worktree can be slow, and unrelated edits by other work packages are not our concern.
  if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain -- e2e backend/Dockerfile frontend/Dockerfile 2>/dev/null)" ]]; then
    echo true
  else
    echo false
  fi
}

banner() {
  log "=== $1 ==="
  log "host=$(hostname) user=$(id -un) uid=$(id -u) git=$(git_sha) dirty_e2e=$(git_dirty)"
  log "evidence_dir=$(e2e_evidence_dir)"
}

# Evidence directory (untracked, shared by every script of one E2E run).
# Default: <main checkout>/.agents/tasks/cbom-medium-renderers-evidence, derived from the git common
# dir so it resolves to the main checkout when run from a linked worktree.
e2e_evidence_dir() {
  if [[ -n "${E2E_EVIDENCE_DIR:-}" ]]; then
    printf '%s\n' "${E2E_EVIDENCE_DIR}"
    return 0
  fi
  local common
  if common="$(git -C "${REPO_ROOT}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" && [[ -n "${common}" ]]; then
    printf '%s\n' "$(dirname "${common}")/.agents/tasks/cbom-medium-renderers-evidence"
    return 0
  fi
  printf '%s\n' "${E2E_WORK_DIR}/evidence"
}

e2e_log_file() { printf '%s/logs/%s\n' "$(e2e_evidence_dir)" "$1"; }

e2e_prepare_evidence_dirs() {
  local ev
  ev="$(e2e_evidence_dir)"
  mkdir -p "${ev}/videos" "${ev}/screenshots" "${ev}/downloads" "${ev}/pdf-pages" "${ev}/logs" "${ev}/reports"
}

# run_logged <logfile> <command...>
# Runs the command, mirrors its output to stdout and appends it to <logfile>; returns its exit code.
run_logged() {
  local logfile=$1 rc=0
  shift
  mkdir -p "$(dirname "${logfile}")"
  set +e
  "$@" 2>&1 | tee -a "${logfile}"
  rc=${PIPESTATUS[0]}
  set -e
  return "${rc}"
}

# wait_until <timeout_s> <interval_s> <description> <command...>
# Condition-based wait: polls <command> until it succeeds, fails (return 1) once <timeout_s> elapsed.
wait_until() {
  local timeout=$1 interval=$2 what=$3
  shift 3
  local start=${SECONDS}
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS - start >= timeout)); then
      log "TIMEOUT after ${timeout}s waiting for: ${what}"
      return 1
    fi
    sleep "${interval}"
  done
  log "ready: ${what} ($((SECONDS - start))s)"
}

human_bytes() { numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "$1 B"; }

# Names (one per line, locale-independent order) of the direct children of a directory.
list_dir_names() { find "$1" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort; }

# ------------------------------------------------------------------------------------------------
# docker / compose
# ------------------------------------------------------------------------------------------------
# The only way scripts invoke compose: fixed project name and file, host uid/gid exported for the
# one-shot containers (see x-e2e-host-user in the compose file).
compose() {
  E2E_UID="$(id -u)" E2E_GID="$(id -g)" docker compose -p "${E2E_PROJECT}" -f "${E2E_COMPOSE_FILE}" "$@"
}

image_exists() { docker image inspect "$1" >/dev/null 2>&1; }

# healthy | unhealthy | starting | running (no healthcheck) | exited ... | missing
container_health() {
  local status
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null)" || status=missing
  printf '%s\n' "${status:-missing}"
}

container_healthy() { [[ "$(container_health "$1")" == "healthy" ]]; }

# Prints the HTTP status code, or 000 when nothing answered.
http_code() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null)" || true
  printf '%s\n' "${code:-000}"
}

http_ok() { [[ "$(http_code "$1")" == "200" ]]; }

# Snapshot the daemon's containers / volumes / networks (names only for the set comparison, plus
# image+status for containers) so teardown can prove it changed nothing that is not ours.
snapshot_docker() {
  local dir=$1 tag=$2
  mkdir -p "${dir}"
  docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | LC_ALL=C sort >"${dir}/docker-ps-${tag}.txt"
  docker volume ls --format '{{.Name}}' | LC_ALL=C sort >"${dir}/docker-volume-${tag}.txt"
  docker network ls --format '{{.Name}}' | LC_ALL=C sort >"${dir}/docker-network-${tag}.txt"
}

# ------------------------------------------------------------------------------------------------
# guarded delete (the only rm -rf in e2e/ besides teardown's label-guarded compose down)
# ------------------------------------------------------------------------------------------------
safe_rm_rf() {
  local target=${1:-} resolved
  [[ -n "${target}" ]] || die "safe_rm_rf: empty path"
  [[ "${target}" == /* ]] || die "safe_rm_rf: path must be absolute: ${target}"
  resolved="$(realpath -m -- "${target}")"
  case "${resolved}" in
    "${E2E_ROOT}/.work" | "${E2E_ROOT}/.work/"* | "${E2E_ROOT}/compose/.env.e2e" | "${E2E_ROOT}/test-results" | "${E2E_ROOT}/test-results/"*) ;;
    *) die "safe_rm_rf: refusing to delete outside the e2e scratch set: ${resolved}" ;;
  esac
  if [[ -e "${resolved}" || -L "${resolved}" ]]; then
    rm -rf -- "${resolved}"
  fi
}

# ------------------------------------------------------------------------------------------------
# per-run secrets
# ------------------------------------------------------------------------------------------------
# Generates compose/.env.e2e if absent. Every value is random and throw-away (openssl rand), the file
# is mode 600 and git-ignored, and NOTHING is copied from any repo .env. The AWS_* values are
# format-only dummies: backend/utilities/ai/chatbot.py raises at import when they are unset, and no
# code path exercised by the E2E calls AWS. Values are never printed.
ensure_env_file() {
  if [[ -f "${E2E_ENV_FILE}" ]]; then
    return 0
  fi
  need_cmd openssl od
  local old_umask pg_pass otp
  pg_pass="$(openssl rand -hex 16)"
  otp="$(printf '%06d' "$(($(od -An -N4 -tu4 /dev/urandom) % 1000000))")"
  old_umask="$(umask)"
  umask 077
  {
    printf '# Generated by e2e/scripts/lib.sh on %s. Throw-away values for the dss-e2e stack only.\n' "$(date -u +%FT%TZ)"
    printf '# Git-ignored. Never copied from, or reused as, any real .env. Do not commit, do not print.\n'
    printf 'POSTGRES_USER=dss_e2e\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${pg_pass}"
    printf 'POSTGRES_DB=dss_e2e\n'
    printf 'PG_USER=dss_e2e\n'
    printf 'PG_USER_PASS=%s\n' "${pg_pass}"
    printf 'PG_DB=dss_e2e\n'
    printf 'PG_HOST=dss-e2e-postgres\n'
    printf 'PG_PORT=5432\n'
    printf 'MONGO_HOST=dss-e2e-mongo\n'
    printf 'MONGO_PORT=27017\n'
    printf 'IS_DOCKER_CONTAINER=True\n'
    printf 'CORS_ORIGINS=http://127.0.0.1:%s,http://localhost:%s\n' "${E2E_FRONTEND_PORT}" "${E2E_FRONTEND_PORT}"
    printf 'JWT_SECRET_KEY=%s\n' "$(openssl rand -hex 32)"
    printf 'JWT_REFRESH_SECRET_KEY=%s\n' "$(openssl rand -hex 32)"
    printf 'CERTIN_HMAC_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'LOCAL_DEV_VERIFICATION_EMAIL=%s\n' "${E2E_ADMIN_EMAIL_DEFAULT}"
    printf 'LOCAL_DEV_VERIFICATION_CODE=%s\n' "${otp}"
    printf 'RABBIT_ADMIN_USERNAME=dss-e2e-unused\n'
    printf 'RABBIT_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 12)"
    printf 'AWS_ACCESS_KEY_ID=AKIA%s\n' "$(openssl rand -hex 8 | tr 'a-f' 'A-F')"
    printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$(openssl rand -hex 20)"
    printf 'AWS_DEFAULT_REGION=us-east-1\n'
    printf 'E2E_ADMIN_EMAIL=%s\n' "${E2E_ADMIN_EMAIL_DEFAULT}"
    # POST /login accepts passwords of 5 to 24 characters (UserLogin): 16 random hex + "Aa1!" = 20.
    printf 'E2E_ADMIN_PASSWORD=%sAa1!\n' "$(openssl rand -hex 8)"
    printf 'E2E_OTHER_EMAIL=%s\n' "${E2E_OTHER_EMAIL_DEFAULT}"
    printf 'E2E_OTHER_PASSWORD=%sAa1!\n' "$(openssl rand -hex 8)"
    printf 'E2E_EMPTY_EMAIL=%s\n' "${E2E_EMPTY_EMAIL_DEFAULT}"
    printf 'E2E_EMPTY_PASSWORD=%sAa1!\n' "$(openssl rand -hex 8)"
  } >"${E2E_ENV_FILE}"
  umask "${old_umask}"
  log "generated ${E2E_ENV_FILE#"${REPO_ROOT}"/} (mode 600; values not printed)"
}

# Name-only listing of the env keys (never values) for logs and docs.
env_file_keys() { sed -n -E 's/^([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p' "${E2E_ENV_FILE}"; }
