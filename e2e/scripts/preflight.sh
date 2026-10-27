#!/usr/bin/env bash
# preflight.sh - is this VM ready for a dss-e2e run, and is nothing of ours (or anyone's) in the way?
#
# Read-only apart from its own log files and the "before" snapshot of the Docker daemon. Starts,
# stops, builds and pulls nothing. Refuses (exit 1) on any clash:
#   - a required tool or the buildx builder "dss-fast" is missing
#   - host port 43000 or 43080 is already listening
#   - a leftover dss-e2e container / volume / network exists (run teardown.sh)
#   - the Playwright browser cache lacks the revisions @playwright/test 1.62.0 needs
#   - the compose file is invalid or violates the exposure / isolation policy
#   - the committed E2E inputs drifted (Dockerfile copies, dockerignore parts, package.json pin)
#
# Logs: <evidence>/logs/00-preflight.txt, docker-{ps,volume,network}-before.txt, playwright-cache-before.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

FAILS=0
PASSES=0
pass() {
  PASSES=$((PASSES + 1))
  log "PASS  $*"
}
fail() {
  FAILS=$((FAILS + 1))
  log "FAIL  $*"
}
note() { log "INFO  $*"; }

# version_ge <have> <want>: true when have >= want (sort -V)
version_ge() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]; }

check_tools() {
  local c
  for c in docker curl ss openssl node npm python3 git tar sha256sum realpath numfmt od \
    pdfinfo pdftotext pdffonts pdftoppm ffmpeg ffprobe; do
    if command -v "${c}" >/dev/null 2>&1; then
      pass "tool ${c} -> $(command -v "${c}")"
    else
      fail "required tool missing: ${c}"
    fi
  done
  note "docker:   $(docker --version 2>&1 | head -n1)"
  note "compose:  $(docker compose version 2>&1 | head -n1)"
  note "buildx:   $(docker buildx version 2>&1 | head -n1)"
  note "node/npm: $(node --version 2>&1) / $(npm --version 2>&1)"
  note "python3:  $(python3 --version 2>&1)"
  note "openssl:  $(openssl version 2>&1)"
  note "git:      $(git --version 2>&1)"
  note "poppler:  $(pdfinfo -v 2>&1 | head -n1)"
  note "ffmpeg:   $(ffmpeg -version 2>&1 | head -n1)"
}

check_docker() {
  if docker info >/dev/null 2>&1; then
    pass "docker daemon reachable"
  else
    fail "docker daemon not reachable"
    return 0
  fi

  local cv
  cv="$(docker compose version --short 2>/dev/null || true)"
  cv="${cv#v}"
  if [[ -n "${cv}" ]] && version_ge "${cv}" "2.24.0"; then
    pass "docker compose ${cv} >= 2.24.0 (env_file required:false)"
  else
    fail "docker compose >= 2.24.0 required (found '${cv:-none}')"
  fi

  if docker buildx inspect "${E2E_BUILDER}" 2>/dev/null | grep -Eq '^Status:[[:space:]]+running'; then
    pass "buildx builder ${E2E_BUILDER} exists and is running"
  else
    fail "buildx builder ${E2E_BUILDER} not found or not running (images are built with it, --load only)"
  fi

  local root free_kb
  root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /)"
  [[ -e "${root}" ]] || root=/
  free_kb="$(df -Pk "${root}" 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ -n "${free_kb}" ]] && ((free_kb >= 15 * 1024 * 1024)); then
    pass "free disk under ${root}: $(human_bytes $((free_kb * 1024))) (>= 15GiB)"
  else
    fail "less than 15GiB free under ${root} (${free_kb:-?} KiB): builds and images need ~5GiB plus cache growth"
  fi

  local mem_kb
  mem_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if ((mem_kb >= 6 * 1024 * 1024)); then
    pass "available memory: $(human_bytes $((mem_kb * 1024))) (>= 6GiB)"
  else
    fail "less than 6GiB of memory available (${mem_kb} KiB): next build + uv sync + stack need headroom"
  fi

  if grep -qw avx /proc/cpuinfo 2>/dev/null; then
    pass "CPU supports AVX (required by mongo:8)"
  else
    fail "CPU lacks AVX; mongo:8.0.6 would exit on start"
  fi
}

check_ports() {
  local p listeners
  for p in "${E2E_FRONTEND_PORT}" "${E2E_BACKEND_PORT}"; do
    listeners="$(ss -H -ltn "sport = :${p}" 2>/dev/null || true)"
    if [[ -z "${listeners}" ]]; then
      pass "host port ${p} is free"
    else
      fail "host port ${p} is already listening: ${listeners}"
    fi
  done
  note "ss -ltn filtered to the E2E ports: [$(ss -H -ltn '( sport = :43000 or sport = :43080 )' 2>/dev/null | tr '\n' ' ')] (empty = free)"
}

check_no_leftovers() {
  local what listing
  if [[ -n "$(compose ps -q 2>/dev/null || true)" ]]; then
    fail "docker compose -p ${E2E_PROJECT} ps -q is not empty: a stack is already up (run teardown.sh)"
  else
    pass "docker compose -p ${E2E_PROJECT} ps -q is empty"
  fi

  # Match by label, by compose project label, and by name prefix: any of them is a clash.
  listing="$(
    {
      docker ps -a --filter "label=${E2E_LABEL}" --format '{{.Names}}'
      docker ps -a --filter "label=com.docker.compose.project=${E2E_PROJECT}" --format '{{.Names}}'
      docker ps -a --format '{{.Names}}' | grep -E '^dss-e2e-' || true
    } 2>/dev/null | sort -u
  )"
  if [[ -z "${listing}" ]]; then
    pass "no dss-e2e containers exist"
  else
    fail "leftover containers: $(printf '%s' "${listing}" | tr '\n' ' ')"
  fi

  for what in volume network; do
    listing="$(
      {
        docker "${what}" ls --filter "label=${E2E_LABEL}" --format '{{.Name}}'
        docker "${what}" ls --format '{{.Name}}' | grep -E '^dss-e2e[_-]' || true
      } 2>/dev/null | sort -u
    )"
    if [[ -z "${listing}" ]]; then
      pass "no dss-e2e ${what}s exist"
    else
      fail "leftover ${what}s: $(printf '%s' "${listing}" | tr '\n' ' ')"
    fi
  done
}

check_playwright_cache() {
  local cache rev
  cache="${PLAYWRIGHT_BROWSERS_PATH:-${HOME}/.cache/ms-playwright}"
  if [[ -d "${cache}" ]]; then
    note "ls ${cache}: $(list_dir_names "${cache}" | tr '\n' ' ')"
  else
    fail "Playwright browser cache not found: ${cache}"
    return 0
  fi
  for rev in "${E2E_PLAYWRIGHT_REVISIONS[@]}"; do
    if [[ -d "${cache}/${rev}" ]]; then
      pass "Playwright cache has ${rev} (no browser download needed)"
    else
      fail "Playwright cache lacks ${rev}, which @playwright/test ${E2E_PLAYWRIGHT_VERSION} needs (do NOT run playwright install here)"
    fi
  done
  mkdir -p "$(e2e_evidence_dir)/logs"
  list_dir_names "${cache}" >"$(e2e_log_file playwright-cache-before.txt)"
}

check_openssl() {
  if openssl req -help 2>&1 | grep -q -- '-not_before' ||
    openssl ca -help 2>&1 | grep -q -- '-startdate'; then
    pass "openssl can set certificate notBefore/notAfter"
  else
    fail "openssl cannot set certificate notBefore/notAfter"
  fi
}

check_inputs() {
  local f
  for f in \
    compose/docker-compose.e2e.yml \
    docker/backend.e2e.Dockerfile docker/backend.e2e.Dockerfile.dockerignore \
    docker/frontend.e2e.Dockerfile docker/frontend.e2e.Dockerfile.dockerignore \
    docker/aibom-scan.Dockerfile docker/aibom-scan.Dockerfile.dockerignore \
    fixtures/build_trees.sh package.json package-lock.json playwright.config.ts .gitignore; do
    if [[ -f "${E2E_ROOT}/${f}" ]]; then pass "e2e/${f} present"; else fail "e2e/${f} missing"; fi
  done

  local s
  for s in preflight build up seed run-specs collect-evidence teardown all; do
    if [[ -x "${E2E_SCRIPTS_DIR}/${s}.sh" ]] && grep -q '^set -euo pipefail$' "${E2E_SCRIPTS_DIR}/${s}.sh"; then
      pass "scripts/${s}.sh is executable and sets -euo pipefail"
    else
      fail "scripts/${s}.sh missing, not executable, or lacks 'set -euo pipefail'"
    fi
  done

  # Verbatim-copy invariants: the E2E images must build the same thing production builds.
  local app
  for app in backend frontend; do
    if cmp -s "${REPO_ROOT}/${app}/Dockerfile" "${E2E_ROOT}/docker/${app}.e2e.Dockerfile"; then
      pass "${app}.e2e.Dockerfile is byte-identical to ${app}/Dockerfile"
    else
      fail "${app}.e2e.Dockerfile drifted from ${app}/Dockerfile (cp ${app}/Dockerfile e2e/docker/${app}.e2e.Dockerfile)"
    fi
  done

  # Every line of the production ignore files must still be in the E2E variants (they only ADD).
  local pair prod e2e missing
  for pair in "backend/.dockerignore:docker/backend.e2e.Dockerfile.dockerignore" "frontend/.dockerignore:docker/frontend.e2e.Dockerfile.dockerignore"; do
    prod="${REPO_ROOT}/${pair%%:*}"
    e2e="${E2E_ROOT}/${pair##*:}"
    if [[ -f "${prod}" && -f "${e2e}" ]]; then
      missing="$(grep -vxFf "${e2e}" "${prod}" || true)"
      if [[ -z "${missing}" ]]; then
        pass "${pair##*:} contains every line of ${pair%%:*}"
      else
        fail "${pair##*:} lacks lines of ${pair%%:*}: $(printf '%s' "${missing}" | tr '\n' '|')"
      fi
    fi
  done
  for f in .env '**/.env'; do
    if grep -qxF -- "${f}" "${E2E_ROOT}/docker/backend.e2e.Dockerfile.dockerignore" "${E2E_ROOT}/docker/frontend.e2e.Dockerfile.dockerignore" 2>/dev/null; then
      pass "E2E dockerignores exclude '${f}'"
    else
      fail "an E2E dockerignore does not exclude '${f}'"
    fi
  done

  # Toolchain pin.
  if python3 - "${E2E_ROOT}/package.json" "${E2E_PLAYWRIGHT_VERSION}" <<'PY'; then
import json, sys
pkg = json.load(open(sys.argv[1]))
sys.exit(0 if pkg.get("devDependencies", {}).get("@playwright/test") == sys.argv[2] and not pkg.get("dependencies") else 1)
PY
    pass "package.json pins @playwright/test exactly ${E2E_PLAYWRIGHT_VERSION}"
  else
    fail "package.json must pin @playwright/test to exactly ${E2E_PLAYWRIGHT_VERSION} (devDependencies only)"
  fi

  # Never-commit guard for secrets and scratch.
  for f in '.work/' 'compose/.env.e2e' 'node_modules/' 'test-results/'; do
    if grep -qxF -- "${f}" "${E2E_ROOT}/.gitignore"; then pass "e2e/.gitignore ignores ${f}"; else fail "e2e/.gitignore must ignore ${f}"; fi
  done

  # Repo prerequisites for the image builds.
  for f in prod_database_migrations/alembic.ini aibom/pyproject.toml backend/uv.lock backend/docker-entrypoint.sh \
    frontend/package-lock.json compose/aibom-config-overlay backend/tests/fixtures/cbom_export_scandata.json; do
    if [[ -e "${REPO_ROOT}/${f}" ]]; then pass "repo input ${f} present"; else fail "repo input ${f} missing"; fi
  done
}

check_compose() {
  if compose --profile seed config -q 2>/dev/null; then
    pass "docker compose -p ${E2E_PROJECT} config is valid"
  else
    fail "docker compose -p ${E2E_PROJECT} config is INVALID: $(compose --profile seed config -q 2>&1 | head -n3 | tr '\n' ' ')"
    return 0
  fi
  local line
  while IFS= read -r line; do
    case "${line}" in
      PASS*) pass "compose policy: ${line#PASS  }" ;;
      FAIL*) fail "compose policy: ${line#FAIL  }" ;;
      *) note "${line}" ;;
    esac
  done < <(compose --profile seed config --format json 2>/dev/null | python3 "${E2E_SCRIPTS_DIR}/compose_policy.py" || true)
}

main() {
  banner "preflight"
  check_tools
  check_docker
  check_ports
  check_no_leftovers
  check_playwright_cache
  check_openssl
  check_inputs
  check_compose

  if ((FAILS == 0)); then
    local ev
    ev="$(e2e_evidence_dir)"
    snapshot_docker "${ev}/logs" before
    note "snapshots written: ${ev}/logs/docker-{ps,volume,network}-before.txt"
  else
    note "snapshots NOT refreshed because preflight failed"
  fi
  log "preflight summary: ${PASSES} passed, ${FAILS} failed"
  if ((FAILS > 0)); then
    log "PREFLIGHT FAILED: refusing to continue"
    return 1
  fi
  log "PREFLIGHT PASSED"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 00-preflight.txt)"
run_logged "$(e2e_log_file 00-preflight.txt)" main
