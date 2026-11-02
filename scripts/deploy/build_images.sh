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
#         UV_BASE_IMAGE / NODE_BASE_IMAGE  base images that trust a TLS-intercepting proxy's CA (optional)
#         DSS_BUILD_ARGS               extra arguments for every `docker buildx build` (optional, word-split)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '[build_images %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[build_images] ERROR: %s\n' "$*" >&2; exit 1; }

default_tag() {
  local sha
  sha="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  if ! git -C "${REPO_ROOT}" diff --quiet HEAD -- 2>/dev/null; then sha="${sha}-dirty"; fi
  printf '%s\n' "${sha}"
}

DSS_TAG="${DSS_TAG:-$(default_tag)}"
DSS_IMAGE_PREFIX="${DSS_IMAGE_PREFIX:-dss-staging}"
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
      sed -n '2,22p' "${BASH_SOURCE[0]}"
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
    --label "org.opencontainers.image.revision=$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --label "org.opencontainers.image.version=${DSS_TAG}" \
    "${extra[@]}" "$@" -t "${image}" -f "${dockerfile}" "${ctx}"
  log "built ${image} in $((SECONDS - started))s"
}

# No secret file may be inside an image. Base images legitimately carry CA bundles (*.pem) in system and venv paths,
# so *.pem is checked in the application directories; .env files and the SSH key are checked everywhere.
assert_no_secrets() { # <component> <app dir>...
  local name=$1 image out
  shift
  image="$(image_name "${name}")"
  out="$(docker run --rm --network none --entrypoint find "${image}" / -xdev \
    \( -path /proc -o -path /sys \) -prune -o \
    \( -name '.env' -o -name '.env.*' -o -name 'cu-devsecshield-key*' \) ! -name '.env.example' -print 2>/dev/null || true)"
  local d
  for d in "$@"; do
    out+="$(docker run --rm --network none --entrypoint find "${image}" "${d}" \
      \( -name .venv -o -name node_modules \) -prune -o -name '*.pem' -print 2>/dev/null || true)"
  done
  if [[ -n "${out}" ]]; then
    printf '%s\n' "${out}" >&2
    docker rmi "${image}" >/dev/null 2>&1 || true
    die "${image} contains secret-bearing files (listed above); the image was removed"
  fi
  log "${image}: no .env, *.pem or SSH key inside"
}

wanted() { local c; for c in "${ONLY[@]}"; do [[ "${c}" == "$1" ]] && return 0; done; return 1; }
for c in "${ONLY[@]}"; do image_name "${c}" >/dev/null; done

base_args=()
[[ -n "${UV_BASE_IMAGE:-}" ]] && base_args+=(--build-arg "UV_BASE_IMAGE=${UV_BASE_IMAGE}")

log "tag=${DSS_TAG} prefix=${DSS_IMAGE_PREFIX} components=${ONLY[*]}"
[[ -f prod_database_migrations/alembic.ini ]] || die "prod_database_migrations/alembic.ini is missing"

if wanted backend; then
  build backend backend/Dockerfile backend \
    --build-context migrations=prod_database_migrations "${base_args[@]}"
  assert_no_secrets backend /backend /prod_database_migrations
  docker run --rm --network none --entrypoint test "$(image_name backend)" -f /prod_database_migrations/alembic.ini ||
    die "backend image has no Alembic bundle"
fi

if wanted frontend; then
  [[ "${NEXT_PUBLIC_BACKEND_URL:-}" =~ ^https?://. ]] ||
    die "set NEXT_PUBLIC_BACKEND_URL (e.g. https://devsec-staging-api.zeroshield.ai) to build the frontend"
  fe_args=(--build-arg "NEXT_PUBLIC_BACKEND_URL=${NEXT_PUBLIC_BACKEND_URL}")
  [[ -n "${NEXT_PUBLIC_CBOM_NODE_IMAGE:-}" ]] && fe_args+=(--build-arg "NEXT_PUBLIC_CBOM_NODE_IMAGE=${NEXT_PUBLIC_CBOM_NODE_IMAGE}")
  [[ -n "${NODE_BASE_IMAGE:-}" ]] && fe_args+=(--build-arg "NODE_BASE_IMAGE=${NODE_BASE_IMAGE}")
  build frontend frontend/Dockerfile frontend "${fe_args[@]}"
  assert_no_secrets frontend /frontend
fi

if wanted scan-worker; then
  build scan-worker RabbitMQ/worker/Dockerfile . "${base_args[@]}"
  assert_no_secrets scan-worker /build
fi

if wanted dast-worker; then
  build dast-worker RabbitMQ/dast_worker/Dockerfile RabbitMQ/dast_worker "${base_args[@]}"
  assert_no_secrets dast-worker /app
fi

log "done: $(for c in "${ONLY[@]}"; do printf '%s ' "$(image_name "${c}")"; done)"
