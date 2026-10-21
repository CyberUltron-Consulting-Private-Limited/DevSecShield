#!/usr/bin/env bash
# build.sh - build the three E2E images from this worktree with the existing "dss-fast" builder.
#
#   dss-e2e/backend:local     e2e/docker/backend.e2e.Dockerfile      context backend/
#   dss-e2e/frontend:local    e2e/docker/frontend.e2e.Dockerfile     context frontend/  (NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:43080)
#   dss-e2e/aibom-scan:local  e2e/docker/aibom-scan.Dockerfile       context aibom/
#
# Docker safety: --builder dss-fast and --load only (never --push); the three images are built in
# parallel in the background, each with its own log, and waited on for their exit codes; nothing is
# pruned or removed except an image that FAILS its own "no secret inside" assertion (it is deleted
# so a leaky image can never be used by accident).
#
# Also here (plan 7.8): worktree prerequisites (populate the gitignored backend/_migrations from the
# tracked prod_database_migrations, F-09b), generation of the per-run compose/.env.e2e, pulls of the
# two stock images, and the post-build assertions:
#   backend    no .env anywhere in the image; alembic bundle + head revision present
#   frontend   no .env*; the E2E backend URL is baked into the bundle
#   aibom-scan scans a probe tree with --network none --read-only (no network, no LLM, no writes)
#
# Usage: build.sh [--only backend|frontend|aibom-scan]...      (default: all three)
# Env:   E2E_BUILD_CTX_MODE=copy   build backend/frontend from a sanitized rsync copy under .work/
#                                  instead of the repo dirs (fallback if BuildKit ever stops honouring
#                                  the per-Dockerfile .dockerignore; the assertions would flag that)
# Logs:  <evidence>/logs/01-build-{backend,frontend,aibom-scan}.txt, 01-build.txt, 01-build-summary.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ONLY=()
while (($#)); do
  case "$1" in
    --only)
      [[ $# -ge 2 ]] || die "--only needs a value"
      ONLY+=("$2")
      shift 2
      ;;
    -h | --help)
      sed -n '2,30p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

wanted() {
  local c=$1 o
  ((${#ONLY[@]} == 0)) && return 0
  for o in "${ONLY[@]}"; do [[ "${o}" == "${c}" ]] && return 0; done
  return 1
}

declare -A PIDS=()
declare -A LOGS=()
declare -A STARTED=()
declare -A IMAGES=([backend]="${E2E_IMG_BACKEND}" [frontend]="${E2E_IMG_FRONTEND}" [aibom-scan]="${E2E_IMG_AIBOM}")

# ------------------------------------------------------------------------------------------------
# prerequisites
# ------------------------------------------------------------------------------------------------
check_invariants() {
  local app
  for app in backend frontend; do
    cmp -s "${REPO_ROOT}/${app}/Dockerfile" "${E2E_ROOT}/docker/${app}.e2e.Dockerfile" ||
      die "${app}.e2e.Dockerfile is not a verbatim copy of ${app}/Dockerfile (cp ${app}/Dockerfile e2e/docker/${app}.e2e.Dockerfile)"
  done
  local f
  for f in backend.e2e frontend.e2e aibom-scan; do
    [[ -f "${E2E_ROOT}/docker/${f}.Dockerfile.dockerignore" ]] || die "missing e2e/docker/${f}.Dockerfile.dockerignore"
  done
  log "invariants OK: E2E Dockerfiles are verbatim copies, per-Dockerfile ignore files present"
}

# backend/_migrations is gitignored but the Dockerfile COPYs it to /prod_database_migrations; a clean
# worktree has it empty, which makes `COPY _migrations` fail or skips alembic (plan F-09b / R-12).
# The tracked, byte-identical source is prod_database_migrations/. Never copies a .env.
sync_migrations() {
  local src="${REPO_ROOT}/prod_database_migrations" dst="${REPO_ROOT}/backend/_migrations"
  [[ -f "${src}/alembic.ini" ]] || die "missing ${src}/alembic.ini"
  mkdir -p "${dst}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude='.env' --exclude='__pycache__' "${src}/" "${dst}/"
  else
    tar -C "${src}" --exclude='.env' --exclude='__pycache__' -cf - . | tar -C "${dst}" -xf -
  fi
  diff -rq -x .env -x __pycache__ -x .gitkeep "${src}" "${dst}" ||
    die "backend/_migrations differs from prod_database_migrations after sync"
  if ! git -C "${REPO_ROOT}" check-ignore -q backend/_migrations/alembic.ini; then
    warn "backend/_migrations/alembic.ini is not git-ignored: the sync would show up as untracked files"
  fi
  log "backend/_migrations populated from prod_database_migrations (identical, .env excluded)"
}

# Warn (never fail) when the dependency pins baked into aibom-scan.Dockerfile drift from aibom/uv.lock.
check_aibom_pins() {
  if ! command -v uv >/dev/null 2>&1; then
    log "uv not found: skipping the aibom pin drift check"
    return 0
  fi
  local want have
  want="$(cd "${REPO_ROOT}/aibom" && uv export --frozen --no-dev --no-emit-project --no-hashes --no-header 2>/dev/null |
    grep -E '^[A-Za-z0-9_.-]+==' | LC_ALL=C sort || true)"
  have="$(awk '/^COPY <<.PINS. /{f=1;next} /^PINS$/{f=0} f' "${E2E_ROOT}/docker/aibom-scan.Dockerfile" | grep -E '^[A-Za-z0-9_.-]+==' | LC_ALL=C sort || true)"
  if [[ -n "${want}" && "${want}" == "${have}" ]]; then
    log "aibom-scan.Dockerfile pins match aibom/uv.lock ($(printf '%s\n' "${want}" | wc -l) packages)"
  else
    warn "aibom-scan.Dockerfile dependency pins differ from 'uv export' of aibom/uv.lock; regenerate the PINS block"
  fi
}

# prepare_context <source dir> <name> -> prints the build context directory
prepare_context() {
  if [[ "${E2E_BUILD_CTX_MODE:-direct}" == "copy" ]]; then
    need_cmd rsync
    local dst="${E2E_WORK_DIR}/ctx-$2"
    safe_rm_rf "${dst}"
    mkdir -p "${dst}"
    rsync -a --exclude='.env' --exclude='.env.*' --exclude='__pycache__' --exclude='.venv' \
      --exclude='node_modules' --exclude='.next' "$1/" "${dst}/"
    printf '%s\n' "${dst}"
  else
    printf '%s\n' "$1"
  fi
}

# ------------------------------------------------------------------------------------------------
# builds (background, one log each)
# ------------------------------------------------------------------------------------------------
launch_build() { # <component> <context> <dockerfile> [extra docker build args...]
  local name=$1 ctx=$2 dockerfile=$3 sha
  shift 3
  sha="$(git_sha)"
  LOGS["${name}"]="$(e2e_log_file "01-build-${name}.txt")"
  : >"${LOGS[${name}]}"
  STARTED["${name}"]=${SECONDS}
  log "build ${name}: ${IMAGES[${name}]}  (context ${ctx#"${REPO_ROOT}"/}, log ${LOGS[${name}]})"
  docker buildx build --builder "${E2E_BUILDER}" --platform linux/amd64 \
    --provenance=false --sbom=false --load --progress=plain \
    --label "${E2E_LABEL}" --label "org.opencontainers.image.revision=${sha}" \
    "$@" -t "${IMAGES[${name}]}" -f "${dockerfile}" "${ctx}" >"${LOGS[${name}]}" 2>&1 &
  PIDS["${name}"]=$!
}

# ------------------------------------------------------------------------------------------------
# post-build assertions
# ------------------------------------------------------------------------------------------------
reject_image() { # <component> <reason>
  warn "$2"
  warn "removing ${IMAGES[$1]} so it cannot be used (only this tag; nothing else is touched)"
  docker rmi "${IMAGES[$1]}" >/dev/null 2>&1 || true
  die "$1 image failed its assertions"
}

assert_backend() {
  local out
  if ! out="$(docker run --rm --network none --entrypoint sh "${E2E_IMG_BACKEND}" -c '
set -u
fail=0
for f in /backend/.env /backend/utilities/ai/.env /prod_database_migrations/.env; do
  if [ -e "$f" ]; then echo "LEAK: $f exists"; fail=1; fi
done
found=$(find /backend /prod_database_migrations -path /backend/.venv -prune -o \( -name ".env" -o -name ".env.*" \) -print)
if [ -n "$found" ]; then echo "LEAK: env files inside the image:"; echo "$found"; fail=1; fi
[ -f /prod_database_migrations/alembic.ini ] || { echo "MISSING: /prod_database_migrations/alembic.ini"; fail=1; }
ls /prod_database_migrations/migrations/versions 2>/dev/null | grep -q d9e4b2c5st02 || { echo "MISSING: alembic head revision d9e4b2c5st02"; fail=1; }
[ -x /docker-entrypoint.sh ] || { echo "MISSING: /docker-entrypoint.sh"; fail=1; }
[ -f /backend/main.py ] || { echo "MISSING: /backend/main.py"; fail=1; }
[ -x /backend/.venv/bin/python ] || { echo "MISSING: /backend/.venv/bin/python"; fail=1; }
command -v uv >/dev/null 2>&1 || { echo "MISSING: uv"; fail=1; }
[ "$fail" = 0 ] && echo "backend image OK: no .env, alembic bundle + head d9e4b2c5st02, venv, uv, entrypoint"
exit "$fail"
' 2>&1)"; then
    printf '%s\n' "${out}"
    reject_image backend "backend image assertion failed (a secret-bearing file may be inside)"
  fi
  log "${out}"

  # The app must import with no network and only obviously-fake env (routers, models, the chatbot
  # module's AWS-presence check): this is what the container does at start-up, minus the databases.
  if ! out="$(docker run --rm --network none --entrypoint /backend/.venv/bin/python \
    -e JWT_SECRET_KEY=x -e JWT_REFRESH_SECRET_KEY=x -e AWS_ACCESS_KEY_ID=x -e AWS_SECRET_ACCESS_KEY=x \
    -e AWS_DEFAULT_REGION=us-east-1 -e RABBIT_ADMIN_USERNAME=x -e RABBIT_ADMIN_PASSWORD=x \
    -e PG_USER=x -e PG_USER_PASS=x -e PG_DB=x "${E2E_IMG_BACKEND}" \
    -c "import backend.main as m; print('backend.main imports offline:', len(m.app.routes), 'routes')" 2>&1 | tail -n 1)"; then
    printf '%s\n' "${out}"
    die "backend image cannot import backend.main with --network none and dummy env"
  fi
  log "${out}"
}

assert_frontend() {
  local out
  if ! out="$(docker run --rm --entrypoint sh "${E2E_IMG_FRONTEND}" -c '
set -u
fail=0
found=$(find /frontend -maxdepth 4 \( -name ".env" -o -name ".env.*" \) -print 2>/dev/null)
if [ -n "$found" ]; then echo "LEAK: env files inside the image:"; echo "$found"; fail=1; fi
[ -f /frontend/server.js ] || { echo "MISSING: /frontend/server.js (standalone output)"; fail=1; }
grep -rlq "127.0.0.1:43080" /frontend/.next/static 2>/dev/null || { echo "MISSING: E2E backend URL http://127.0.0.1:43080 is not baked into the bundle"; fail=1; }
if grep -rlq "devsecshieldapi.zeroshield.ai" /frontend/.next/static 2>/dev/null; then echo "NOTE: the production API host string is present in the bundle (the interceptors.js fallback literal); the browser egress guard in the specs is what proves it is never called"; fi
[ "$fail" = 0 ] && echo "frontend image OK: no .env*, standalone server, E2E backend URL baked in"
exit "$fail"
' 2>&1)"; then
    printf '%s\n' "${out}"
    reject_image frontend "frontend image assertion failed"
  fi
  log "${out}"
}

assert_aibom() {
  local out
  # Same restrictions the compose service applies: no network, read-only rootfs, no capabilities.
  if ! out="$(docker run -i --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" "${E2E_IMG_AIBOM}" python - 2>&1 <<'PY'
import pathlib
import tempfile

from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

root = pathlib.Path(tempfile.mkdtemp())
(root / "app.py").write_text(
    "import hashlib\nimport ssl\n"
    "digest = hashlib.md5(b'x').hexdigest()\n"
    "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n"
)
out = scan_crypto_to_devsecshield(str(root), level=4)
missing = {"results", "cbom_json", "duration_of_scan"} - set(out)
assert not missing, f"run-object lacks keys: {sorted(missing)}"
assert out["results"], "the scanner found nothing in a file that calls hashlib.md5"
print(f"aibom-scan image OK: offline scan returned {len(out['results'])} findings, keys={sorted(out)}")
PY
  )"; then
    printf '%s\n' "${out}"
    die "aibom-scan image smoke test failed"
  fi
  log "${out}"
}

# ------------------------------------------------------------------------------------------------
main() {
  banner "build"
  need_cmd docker git diff cmp tar awk sort
  docker buildx inspect "${E2E_BUILDER}" >/dev/null 2>&1 || die "buildx builder ${E2E_BUILDER} not found (create/restore it; this script never creates builders)"
  e2e_prepare_evidence_dirs

  check_invariants
  wanted backend && sync_migrations
  check_aibom_pins
  ensure_env_file

  local ctx
  if wanted backend; then
    ctx="$(prepare_context "${REPO_ROOT}/backend" backend)"
    launch_build backend "${ctx}" "${E2E_ROOT}/docker/backend.e2e.Dockerfile"
  fi
  if wanted frontend; then
    ctx="$(prepare_context "${REPO_ROOT}/frontend" frontend)"
    launch_build frontend "${ctx}" "${E2E_ROOT}/docker/frontend.e2e.Dockerfile" \
      --build-arg "NEXT_PUBLIC_BACKEND_URL=${E2E_API_URL}"
  fi
  if wanted aibom-scan; then
    launch_build aibom-scan "${REPO_ROOT}/aibom" "${E2E_ROOT}/docker/aibom-scan.Dockerfile"
  fi

  # Stock images the stack needs; pulled while the builds run (only when absent, never forced).
  local img
  for img in "${E2E_PG_IMAGE}" "${E2E_MONGO_IMAGE}"; do
    if image_exists "${img}"; then
      log "pull skipped: ${img} already present"
    else
      log "pulling ${img}"
      docker pull --quiet "${img}" >/dev/null
    fi
  done

  # Condition-based wait: block on each build's exit code (no sleeping, no polling of log text).
  local name rc failed=0
  for name in backend frontend aibom-scan; do
    [[ -n "${PIDS[${name}]:-}" ]] || continue
    if wait "${PIDS[${name}]}"; then
      log "build ${name}: OK in $((SECONDS - STARTED[${name}]))s"
    else
      rc=$?
      failed=1
      log "build ${name}: FAILED (exit ${rc}) after $((SECONDS - STARTED[${name}]))s; last lines of ${LOGS[${name}]}:"
      tail -n 40 "${LOGS[${name}]}" | sed 's/^/    | /'
    fi
  done
  ((failed == 0)) || die "one or more image builds failed"

  wanted backend && assert_backend
  wanted frontend && assert_frontend
  wanted aibom-scan && assert_aibom

  local summary
  summary="$(e2e_log_file 01-build-summary.txt)"
  {
    printf 'built_at=%s git=%s dirty_e2e=%s builder=%s ctx_mode=%s\n' "$(date -u +%FT%TZ)" "$(git_sha)" "$(git_dirty)" "${E2E_BUILDER}" "${E2E_BUILD_CTX_MODE:-direct}"
    for name in backend frontend aibom-scan; do
      wanted "${name}" || continue
      # disk_usage = what `docker images` shows (unpacked); content_size = `docker image inspect` .Size
      printf '%s image=%s id=%s disk_usage=%s content_size_bytes=%s content_size=%s\n' "${name}" "${IMAGES[${name}]}" \
        "$(docker image inspect -f '{{.Id}}' "${IMAGES[${name}]}")" \
        "$(docker image ls --format '{{.Size}}' "${IMAGES[${name}]}" | head -n1)" \
        "$(docker image inspect -f '{{.Size}}' "${IMAGES[${name}]}")" \
        "$(human_bytes "$(docker image inspect -f '{{.Size}}' "${IMAGES[${name}]}")")"
    done
    for img in "${E2E_PG_IMAGE}" "${E2E_MONGO_IMAGE}"; do
      printf 'stock image=%s id=%s\n' "${img}" "$(docker image inspect -f '{{.Id}}' "${img}")"
    done
  } >"${summary}"
  cat "${summary}"
  log "BUILD OK"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 01-build.txt)"
run_logged "$(e2e_log_file 01-build.txt)" main
