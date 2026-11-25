#!/usr/bin/env bash
# ci_images.sh - the steps of .github/workflows/chola-prod-images.yml (deploy/chola-prod/README.md, "Images from a CI
# run"), kept in a file so they are shellchecked and tested (backend/tests/test_chola_prod_kit.py). Runs on the
# runner from the checkout of the commit being packaged; writes only under $OUT.
#
#   ci_images.sh ghcr-tag                   the GHCR tag that has the commit's images (dev-, staging-, manual-<sha12>)
#   ci_images.sh ghcr <component> <tag>     $OUT/image-<component>: its linux/amd64 manifest, byte for byte (crane)
#   ci_images.sh frontend                   $OUT/image-frontend: built for $API_URL as the kit builds it
#   ci_images.sh infra                      $OUT/infra/release.tar.gz: docker save of $INFRA_IMAGES (pinned)
#   ci_images.sh free <dir>                 delete $OUT/<dir> after its upload (one image on disk at a time)
#
# Environment: OUT, SHA (40 hex), API_URL, REGISTRY (ghcr.io/<owner>), INFRA_IMAGES, BUILDER, RUN_URL, MAX_BYTES,
# DOCKER_CONFIG for crane (the run's own config; docker itself keeps the runner's).
set -Eeuo pipefail
export LC_ALL=C
die() { echo "::error::$*" >&2; exit 1; }
: "${OUT:?}" "${SHA:?}"
[[ "${SHA}" =~ ^[0-9a-f]{40}$ ]] || die "SHA is not a 40-character commit"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ART=(python3 -I "${HERE}/artifacts.py")
MANIFEST="${OUT}/manifest/manifest.json"
MAX_BYTES=${MAX_BYTES:-4294967296}

size_guard() { # <dir>: each artifact stays well under GitHub's limits
  local n
  n=$(du -sb "$1" | cut -f1)
  echo "$(basename "$1"): $((n / 1048576)) MB"
  [[ "${n}" -le "${MAX_BYTES}" ]] || die "$(basename "$1") is ${n} bytes, over ${MAX_BYTES}"
}

cmd_ghcr_tag() {
  local t sha12=${SHA:0:12}
  for t in "dev-${sha12}" "staging-${sha12}" "manual-${sha12}"; do
    if crane digest "${REGISTRY:?}/devsecshield-backend:${t}" >/dev/null 2>&1; then
      echo "${t}"
      return 0
    fi
  done
  die "no GHCR images for ${sha12} (dev-, staging- or manual-${sha12}): is its 'Publish images (GHCR)' run green?"
}

cmd_ghcr() { # <component> <tag>
  local c=$1 tag=$2 ref index
  [[ "${c}" =~ ^(backend|scan-worker|dast-worker)$ ]] || die "not a GHCR component: ${c}"
  ref="${REGISTRY:?}/devsecshield-${c}:${tag}"
  index=$(crane digest "${ref}")
  rm -rf "${OUT:?}/image-${c}"
  crane pull --format=oci --platform linux/amd64 "${ref}" "${OUT}/image-${c}"
  # checks the layout (one linux/amd64 image, every blob) and that its revision label is this commit
  "${ART[@]}" manifest-add-image --manifest "${MANIFEST}" --component "${c}" --artifact "chola-image-${c}" \
    --source "${ref}" --layout "${OUT}/image-${c}" --index-digest "${index}"
  size_guard "${OUT}/image-${c}"
}

cmd_frontend() {
  local blob n hits=0
  rm -rf "${OUT:?}/image-frontend" "${OUT:?}/frontend-oci.tar"
  docker buildx build --builder "${BUILDER:?}" --platform linux/amd64 \
    --build-arg "NEXT_PUBLIC_BACKEND_URL=${API_URL:?}" \
    --label "org.opencontainers.image.revision=${SHA}" --label "com.zeroshield.devsecshield.api-url=${API_URL}" \
    --provenance=false --sbom=false --output "type=oci,dest=${OUT}/frontend-oci.tar" frontend
  mkdir -p "${OUT}/image-frontend"
  tar -xf "${OUT}/frontend-oci.tar" -C "${OUT}/image-frontend"
  rm -f "${OUT:?}/frontend-oci.tar"
  "${ART[@]}" oci-check --normalize --layout "${OUT}/image-frontend" --revision "${SHA}" \
    --label "com.zeroshield.devsecshield.api-url=${API_URL}" >/dev/null
  # the API URL is inlined into the browser chunks: refuse a bundle without it (the instance checks again)
  for blob in "${OUT}"/image-frontend/blobs/sha256/*; do
    if tar -tzf "${blob}" >/dev/null 2>&1; then
      n=$(tar -xzOf "${blob}" --wildcards 'frontend/.next/static/*' 2>/dev/null | grep -acF "${API_URL}" || true)
      hits=$((hits + ${n:-0}))
    fi
  done
  [[ "${hits}" -ge 1 ]] || die "the frontend bundle does not contain ${API_URL}"
  echo "frontend: ${API_URL} is in the browser bundle (${hits} chunks)"
  "${ART[@]}" manifest-add-image --manifest "${MANIFEST}" --component frontend --artifact chola-image-frontend \
    --source "built in ${RUN_URL:-this run}" --layout "${OUT}/image-frontend"
  size_guard "${OUT}/image-frontend"
}

# As the kit's own infra step: pulled by digest, tagged with the name the compose file runs, saved for linux/amd64
# (docker save --platform exists only with the containerd image store), compressed (docker load reads it so). The
# runner's Docker is shared: a tag that existed before is put back on its image, one that did not is removed, and so
# is every pinned image this step pulled.
cmd_infra() {
  local i t id
  local -a images tags=() plat=() iplat=() args=()
  PULLED=() RESTORE=() # global: the EXIT trap reads them after this function returned
  read -r -a images <<<"${INFRA_IMAGES:?}"
  for i in "${images[@]}"; do
    t=${i%%@*}
    docker image inspect "${i}" >/dev/null 2>&1 || PULLED+=("${i}")
    id=$(docker image inspect -f '{{.Id}}' "${t}" 2>/dev/null || true)
    RESTORE+=("${t}=${id}")
  done
  # shellcheck disable=SC2317 # run by the trap
  put_back() {
    local r
    for r in "${RESTORE[@]}"; do
      if [[ -n "${r#*=}" ]]; then docker tag "${r#*=}" "${r%%=*}" >/dev/null 2>&1 || true
      else docker image rm "${r%%=*}" >/dev/null 2>&1 || true; fi
    done
    if ((${#PULLED[@]})); then docker image rm "${PULLED[@]}" >/dev/null 2>&1 || true; fi
  }
  trap put_back EXIT # also when a step dies
  for i in "${images[@]}"; do
    docker pull -q --platform linux/amd64 "${i}" >/dev/null
    docker tag "${i}" "${i%%@*}"
    tags+=("${i%%@*}")
  done
  if docker info --format '{{json .DriverStatus}}' 2>/dev/null | grep -q io.containerd.snapshotter &&
    docker save --help 2>/dev/null | grep -q -- '--platform'; then
    plat=(--platform linux/amd64)
    if docker image inspect --help 2>/dev/null | grep -q -- '--platform'; then iplat=(--platform linux/amd64); fi
  fi
  for t in "${tags[@]}"; do
    i=$(docker image inspect ${iplat[@]+"${iplat[@]}"} -f '{{.Os}}/{{.Architecture}}' "${t}")
    [[ "${i}" == linux/amd64 ]] || die "${t} is ${i}, not linux/amd64"
  done
  mkdir -p "${OUT}/infra"
  docker save ${plat[@]+"${plat[@]}"} "${tags[@]}" | gzip -6 >"${OUT}/infra/release.tar.gz"
  for i in "${images[@]}"; do args+=(--image "${i}"); done
  "${ART[@]}" manifest-set-infra --manifest "${MANIFEST}" --artifact chola-infra --file "${OUT}/infra/release.tar.gz" \
    "${args[@]}"
  size_guard "${OUT}/infra"
}

cmd_free() {
  [[ "$1" =~ ^(image-(backend|frontend|scan-worker|dast-worker)|infra)$ ]] || die "not an artifact directory: $1"
  rm -rf "${OUT:?}/$1"
}

case "${1:-}" in
  ghcr-tag) cmd_ghcr_tag ;;
  ghcr) cmd_ghcr "${2:?component}" "${3:?tag}" ;;
  frontend) cmd_frontend ;;
  infra) cmd_infra ;;
  free) cmd_free "${2:?directory}" ;;
  *) die "usage: ci_images.sh ghcr-tag | ghcr <component> <tag> | frontend | infra | free <dir>" ;;
esac
