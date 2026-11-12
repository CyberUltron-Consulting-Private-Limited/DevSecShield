#!/usr/bin/env bash
# build_images.sh - build the DevSecShield production images from this checkout, one at a time, and check that no
# secret file (.env*, *.pem, the cu-devsecshield SSH key) is inside any of them.
#
#   <prefix>/devsecshield-backend:<tag>    backend/Dockerfile            context backend/ (+ named context migrations)
#   <prefix>/devsecshield-frontend:<tag>   frontend/Dockerfile           context frontend/ (NEXT_PUBLIC_BACKEND_URL)
#   <prefix>/scan-worker:<tag>             RabbitMQ/worker/Dockerfile    context . (repo root; scan + CI/CD queues)
#   <prefix>/dast-worker:<tag>             RabbitMQ/dast_worker/Dockerfile context RabbitMQ/dast_worker/
#
# The backend image also runs the migrate one-shot, the CBOM cloud worker and the DAST scheduler.
#
# Usage:  scripts/deploy/build_images.sh [--only backend,frontend,scan-worker,dast-worker]
# Env:    DSS_TAG                      image tag (default: short git commit, "-dirty" when the tree has changes)
#         DSS_IMAGE_PREFIX             repository prefix (default: dss-staging)
#         NEXT_PUBLIC_BACKEND_URL      API URL baked into the browser bundle (required for the frontend)
#         NEXT_PUBLIC_CBOM_NODE_IMAGE  scan-node image the UI tells operators to run (optional)
#         UV_BASE_IMAGE / NODE_BASE_IMAGE / GO_BASE_IMAGE  base images that trust a TLS-intercepting proxy's CA
#                                      (optional; UV: backend and both workers, NODE: frontend, GO: the scan
#                                      worker's cbomkit-theia stage)
#         DSS_BUILD_ARGS               extra arguments for every `docker buildx build` (optional, word-split)
#         DSS_BUILD_SHA                the commit baked into the images (default: git HEAD of a clean tree; a full
#                                      40-character sha; a tree with uncommitted or untracked changes gets none)
#         DSS_BUILD_VERSION            the version string baked into the backend (default: DSS_TAG; "-dirty" is added
#                                      when the tree has changes and DSS_BUILD_SHA is unset)
#         DSS_EXPOSE_BUILD             1 = the frontend also names the commit in <meta name="zs-build"> on every page
#                                      (the local stack, the lab, staging); default off (production)
#
# Build identity (CB-03): the backend carries DSS_BUILD_SHA / DSS_BUILD_VERSION (GET /version for signed-in users,
# runs and CBOM exports; GET /health and X-ZS-Build only where DSS_EXPOSE_BUILD=1 at run time); every image's
# org.opencontainers.image.revision label names the same commit ("unknown" without one). The frontend's meta is
# compiled in by `next build`, so with DSS_EXPOSE_BUILD=1 every new commit rebuilds the frontend (~4-8 min on 2 CPUs).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '[build_images %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[build_images] ERROR: %s\n' "$*" >&2; exit 1; }

default_tag() {
  local sha
  sha="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  # the same rule as the commit check below (and staging.sh): uncommitted or untracked changes; ignored files do not
  if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then sha="${sha}-dirty"; fi
  printf '%s\n' "${sha}"
}

DSS_TAG="${DSS_TAG:-$(default_tag)}"
DSS_IMAGE_PREFIX="${DSS_IMAGE_PREFIX:-dss-staging}"

if [[ -n "${DSS_BUILD_SHA:-}" ]]; then
  [[ "${DSS_BUILD_SHA}" =~ ^[0-9a-f]{40}$ ]] || die "DSS_BUILD_SHA must be a full 40-character commit (lowercase hex)"
  BUILD_SHA="${DSS_BUILD_SHA}"
else
  BUILD_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
  [[ "${BUILD_SHA}" =~ ^[0-9a-f]{40}$ ]] || BUILD_SHA=""
  # Code that is not the commit must not claim it: uncommitted or untracked changes -> no build identity.
  if [[ -n "${BUILD_SHA}" && -n "$(git -C "${REPO_ROOT}" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
    DIRTY_SHA="${BUILD_SHA}"
    BUILD_SHA=""
  fi
fi
case "${DSS_EXPOSE_BUILD:-0}" in 1 | true | yes | on) EXPOSE_SHA="${BUILD_SHA}" ;; *) EXPOSE_SHA="" ;; esac
BUILD_VERSION="${DSS_BUILD_VERSION:-${DSS_TAG}}"
# Without a commit, runs record the version (engine_version): a dirty tree's must not look like the clean build's,
# whoever chose the tag (deploy-staging.yml passes DSS_TAG=<short commit>).
if [[ -n "${DIRTY_SHA:-}" && "${BUILD_VERSION}" != *-dirty ]]; then BUILD_VERSION="${BUILD_VERSION}-dirty"; fi
[[ "${BUILD_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$ ]] ||
  die "DSS_BUILD_VERSION (default DSS_TAG${DIRTY_SHA:+, plus -dirty for the uncommitted changes}) must be 1-64 letters, digits, dots, plus, dash or underscore: ${BUILD_VERSION}"
ALL=(backend frontend scan-worker dast-worker)
ONLY=("${ALL[@]}")

while (($#)); do
  case "$1" in
    --only)
      [[ $# -ge 2 ]] || die "--only needs a comma-separated list"
      IFS=, read -r -a ONLY <<<"$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,20p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

image_name() { # <component>
  case "$1" in
    backend) printf '%s/devsecshield-backend:%s\n' "${DSS_IMAGE_PREFIX}" "${DSS_TAG}" ;;
    frontend) printf '%s/devsecshield-frontend:%s\n' "${DSS_IMAGE_PREFIX}" "${DSS_TAG}" ;;
    scan-worker) printf '%s/scan-worker:%s\n' "${DSS_IMAGE_PREFIX}" "${DSS_TAG}" ;;
    dast-worker) printf '%s/dast-worker:%s\n' "${DSS_IMAGE_PREFIX}" "${DSS_TAG}" ;;
    *) die "unknown component: $1 (one of: ${ALL[*]})" ;;
  esac
}

build() { # <component> <dockerfile> <context> [extra args...]
  local name=$1 dockerfile=$2 ctx=$3 image
  shift 3
  image="$(image_name "${name}")"
  local -a extra=()
  # shellcheck disable=SC2206 # deliberate word splitting of operator-supplied extra arguments
  [[ -n "${DSS_BUILD_ARGS:-}" ]] && extra=(${DSS_BUILD_ARGS})
  log "building ${image} (${dockerfile}, context ${ctx})"
  local started=${SECONDS}
  docker buildx build --load --provenance=false \
    --label "org.opencontainers.image.revision=${BUILD_SHA:-unknown}" \
    --label "org.opencontainers.image.version=${DSS_TAG}" \
    "${extra[@]}" "$@" -t "${image}" -f "${dockerfile}" "${ctx}"
  log "built ${image} in $((SECONDS - started))s"
}

# No secret file may be inside an image. Base images legitimately carry CA bundles (*.pem) in system and venv paths,
# so *.pem is checked in the application directories; .env files and the SSH key are checked everywhere.
# find runs as root: the image's own USER (nextjs in the frontend) cannot read every directory, and a directory find
# cannot read is one it did not check. A find that fails is "could not check", never "nothing found"; either way the
# image is removed so it cannot be saved and shipped.
image_find() { # <image> <find arguments...>
  local image=$1
  shift
  docker run --rm --network none --user 0 --entrypoint find "${image}" "$@"
}

reject_image() { # <image> <reason>
  docker rmi "$1" >/dev/null 2>&1 || true
  die "$2; the image was removed"
}

assert_no_secrets() { # <component> <app dir>...
  local name=$1 image out more d
  shift
  image="$(image_name "${name}")"
  out="$(image_find "${image}" / -xdev \( -path /proc -o -path /sys \) -prune -o \
    \( -name '.env' -o -name '.env.*' -o -name 'cu-devsecshield-key*' \) ! -name '.env.example' -print)" ||
    reject_image "${image}" "could not check ${image} for secret files (find failed in the image, output above)"
  for d in "$@"; do
    more="$(image_find "${image}" "${d}" \( -name .venv -o -name node_modules \) -prune -o -name '*.pem' -print)" ||
      reject_image "${image}" "could not check ${d} in ${image} for *.pem files (find failed in the image, output above)"
    out+="${out:+${more:+$'\n'}}${more}"
  done
  if [[ -n "${out}" ]]; then
    printf '%s\n' "${out}" >&2
    reject_image "${image}" "${image} contains secret-bearing files (listed above)"
  fi
  log "${image}: no .env, *.pem or SSH key inside"
}

wanted() { local c; for c in "${ONLY[@]}"; do [[ "${c}" == "$1" ]] && return 0; done; return 1; }
for c in "${ONLY[@]}"; do image_name "${c}" >/dev/null; done

base_args=()
[[ -n "${UV_BASE_IMAGE:-}" ]] && base_args+=(--build-arg "UV_BASE_IMAGE=${UV_BASE_IMAGE}")
go_args=()
[[ -n "${GO_BASE_IMAGE:-}" ]] && go_args+=(--build-arg "GO_BASE_IMAGE=${GO_BASE_IMAGE}")

log "tag=${DSS_TAG} prefix=${DSS_IMAGE_PREFIX} components=${ONLY[*]}"
if [[ -n "${BUILD_SHA}" ]]; then
  log "build ${BUILD_SHA} version ${BUILD_VERSION}${EXPOSE_SHA:+ (exposed: the frontend meta names it)}"
elif [[ -n "${DIRTY_SHA:-}" ]]; then
  log "WARNING: the tree at ${DIRTY_SHA:0:12} has uncommitted changes: the images report build \"unknown\", version ${BUILD_VERSION}"
else
  log "WARNING: no git commit (not a git checkout and DSS_BUILD_SHA unset): the images report build \"unknown\""
fi
[[ -f prod_database_migrations/alembic.ini ]] || die "prod_database_migrations/alembic.ini is missing"

if wanted backend; then
  build backend backend/Dockerfile backend \
    --build-context migrations=prod_database_migrations "${base_args[@]}" \
    --build-arg "DSS_BUILD_SHA=${BUILD_SHA}" --build-arg "DSS_BUILD_VERSION=${BUILD_VERSION}"
  assert_no_secrets backend /backend /prod_database_migrations
  docker run --rm --network none --entrypoint test "$(image_name backend)" -f /prod_database_migrations/alembic.ini ||
    die "backend image has no Alembic bundle"
fi

if wanted frontend; then
  [[ "${NEXT_PUBLIC_BACKEND_URL:-}" =~ ^https?://. ]] ||
    die "set NEXT_PUBLIC_BACKEND_URL (e.g. https://devsec-staging-api.zeroshield.ai) to build the frontend"
  fe_args=(--build-arg "NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL}" --build-arg "NEXT_PUBLIC_BUILD_SHA=${EXPOSE_SHA}")
  [[ -n "${NEXT_PUBLIC_CBOM_NODE_IMAGE:-}" ]] && fe_args+=(--build-arg "NEXT_PUBLIC_CBOM_NODE_IMAGE=${NEXT_PUBLIC_CBOM_NODE_IMAGE}")
  [[ -n "${NODE_BASE_IMAGE:-}" ]] && fe_args+=(--build-arg "NODE_BASE_IMAGE=${NODE_BASE_IMAGE}")
  build frontend frontend/Dockerfile frontend "${fe_args[@]}"
  assert_no_secrets frontend /frontend
fi

if wanted scan-worker; then
  build scan-worker RabbitMQ/worker/Dockerfile . "${base_args[@]}" "${go_args[@]}"
  assert_no_secrets scan-worker /build
fi

if wanted dast-worker; then
  build dast-worker RabbitMQ/dast_worker/Dockerfile RabbitMQ/dast_worker "${base_args[@]}"
  assert_no_secrets dast-worker /app
fi

log "done: $(for c in "${ONLY[@]}"; do printf '%s ' "$(image_name "${c}")"; done)"
