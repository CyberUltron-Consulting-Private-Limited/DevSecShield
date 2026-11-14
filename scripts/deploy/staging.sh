#!/usr/bin/env bash
# staging.sh - build, ship and run the DevSecShield production images on the staging host (deploy/staging/README.md).
#
# On a connected build machine (Docker + this checkout):
#   staging.sh build                     build the images for DSS_TAG (scripts/deploy/build_images.sh)
#   staging.sh save                      docker save | gzip -> deploy/staging/images/dss-staging-<tag>.tar.gz + .sha256
#                                        + .need (bytes loading it needs where the host stores images)
#   staging.sh node-artifacts            the scan-node downloads the API serves on Add scan node, in
#                                        deploy/staging/images/node-artifacts/: the node image file
#                                        (scripts/release/scan_node_image.sh), the Helm chart, the OVA and AMI build
#                                        kits and manifest.json (scripts/release/node_artifacts.py); push ships them
#   staging.sh push <user@host> [dir]    scp the deploy bundle to <dir> (default /opt/devsecshield-staging), check the
#                                        host's disk there (disk-check, the node downloads included), scp the archive
#                                        and the node downloads, then run `staging.sh deploy <tag>` there over ssh
#   staging.sh release <user@host> [dir] build + save + push
# On the staging host (inside <dir>, which holds deploy/staging/.env, backend.env and certs/):
#   staging.sh deploy [tag]              check + docker load the archive (after the disk check), check and put the
#                                        tag's node downloads in deploy/staging/node-artifacts/<tag>/ (the backend's
#                                        CBOM_NODE_ARTIFACT_DIR), refuse a tag whose
#                                        migrations do not contain the database's revision, keep the tag's deploy files
#                                        and Alembic head in deploy/staging/releases/<tag>/, switch DSS_TAG, compose up,
#                                        checks; then keep the images of this tag, the previous one and the last that
#                                        passed its checks, and this tag's archive only
#   staging.sh disk-check <tag> [--archive-bytes N] [--need-bytes N] [--node-artifacts-bytes N]
#                                        enough free disk to copy and load <tag>'s archive? If not, remove this
#                                        deployment's other images and archives (never the running tag, its rollback
#                                        target, the last that passed or <tag>; never another site's) and check again;
#                                        fail when still short
#   staging.sh disk-plan <tag> [--archive-bytes N] [--need-bytes N] [--node-artifacts-bytes N]
#                                        what disk-check and the deploy's retention would remove; removes nothing
#   staging.sh check                     every service runs DSS_TAG's images and is up; health and hydration via nginx
#   staging.sh backend-env               read KEY=VALUE lines on stdin and set exactly those keys in backend.env (only
#                                        the BACKEND_ENV_KEYS below; empty values are skipped; never prints a value).
#                                        `push` runs it just before `deploy` when STAGING_SET_<KEY> is set (CI: the
#                                        staging environment's CBOM_AWS_* secrets; deploy/staging/README.md "AWS")
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
#      DSS_EXPOSE_BUILD (build: 1 = the frontend names its commit in <meta name="zs-build">; default: .env's value, else 0),
#      STAGING_DISK_FACTOR (free space loading needs in the image store, times the archive size, when no .need was
#      measured; default 3.3),
#      STAGING_DISK_RESERVE_MB (left free on every filesystem after that; default 1024), STAGING_CONTAINERD_ROOT
#      (containerd's root when Docker uses the containerd image store; default: found from the containerd config),
#      CBOM_NODE_VERSION (node-artifacts: the scan-node version; default scan_node/zs_scan_node/__init__.py VERSION),
#      SCAN_NODE_IMAGE (node-artifacts: the name the node image file loads as; default localhost/zeroshield/cbom-scan-node),
#      STAGING_SET_<KEY> for each of BACKEND_ENV_KEYS (push: set <KEY> in the host's backend.env; unset or empty:
#      the host's value is left as it is).
set -euo pipefail
export LC_ALL=C # df, awk and sort read the same everywhere (an ssh session may forward the caller's LC_*)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DIR="${REPO_ROOT}/deploy/staging"
COMPOSE_FILE="${STAGING_DIR}/docker-compose.yml"
ENV_FILE="${STAGING_DIR}/.env"
HISTORY_FILE="${STAGING_DIR}/deploy-history"
IMAGES_DIR="${STAGING_DIR}/images"
# Scan-node downloads: built into images/node-artifacts/ on the build machine; on the host one directory per tag,
# node-artifacts/<tag>/, which docker-compose.yml mounts read-only into the backend (CBOM_NODE_ARTIFACT_DIR).
NODE_BUILD_DIR="${IMAGES_DIR}/node-artifacts"
NODE_ARTIFACTS_DIR="${STAGING_DIR}/node-artifacts"
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
# This deployment's images are <prefix>/<repository>:<tag> for these repositories, its archives
# deploy/staging/images/<prefix>-<tag>.tar.gz. Nothing else is ever removed: the host is shared with other sites.
DSS_REPOS=(devsecshield-backend devsecshield-frontend scan-worker dast-worker)
# Free space `docker load` needs where the images are stored, as a multiple of the archive's size, for an archive
# without the .need that `save` measures. Measured on the archive of Deploy staging run 43572299641 (5.48 GB, saved by
# a containerd-store builder): its layers are stored gzip-compressed (1.00x the archive) and unpack to 2.04x; the
# containerd image store keeps both (content store + snapshots), 3.04x, and the classic store's temporary extraction
# plus its layers come to the same. 3.3 adds about 10% for filesystem overhead (blocks, inodes). An archive saved by a
# classic-store builder holds uncompressed layer tars and needs about 4x: set STAGING_DISK_FACTOR=4 for one.
DEFAULT_DISK_FACTOR=3.3
DEFAULT_DISK_RESERVE_MB=1024  # left free on every filesystem after the copy and the load (the host is shared)
# The only backend.env keys a deploy may set (push -> backend-env): the AWS collector identity and the lab switch.
BACKEND_ENV_KEYS=(CBOM_AWS_ACCESS_KEY_ID CBOM_AWS_SECRET_ACCESS_KEY CBOM_AWS_PRINCIPAL_ARN CBOM_AWS_LAB_SAME_ACCOUNT)

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
  # What loading it needs where the host stores images (every layer as stored plus unpacked; archive_need.py): the
  # host's disk check uses it instead of STAGING_DISK_FACTOR, whatever store the builder had.
  rm -f "${out}.need"
  if command -v python3 >/dev/null 2>&1 &&
    gzip -dc "${out}" | python3 -I "${REPO_ROOT}/scripts/deploy/archive_need.py" >"${out}.need.part"; then
    mv "${out}.need.part" "${out}.need"
    log "loading it needs $(kib_h "$(need_kib "$(cat "${out}.need")")") where the host stores images (${out}.need)"
  else
    rm -f "${out}.need.part"
    log "WARNING: could not measure what loading ${out} needs; the host falls back to STAGING_DISK_FACTOR"
  fi
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

# The scan-node downloads of this checkout: the image file (built and checked by scan_node_image.sh), then the chart,
# the kits and manifest.json (node_artifacts.py). The node image is removed from the builder's Docker afterwards.
cmd_node_artifacts() {
  local version image
  version="${CBOM_NODE_VERSION:-$(sed -n -E 's/^VERSION = "([^"]+)"$/\1/p' "${REPO_ROOT}/scan_node/zs_scan_node/__init__.py")}"
  [[ -n "${version}" ]] || die "cannot read the scan-node VERSION from scan_node/zs_scan_node/__init__.py"
  image="${SCAN_NODE_IMAGE:-localhost/zeroshield/cbom-scan-node}"
  rm -rf "${NODE_BUILD_DIR}"
  mkdir -p "${NODE_BUILD_DIR}"
  log "scan-node downloads ${version} (${image}:${version}) in ${NODE_BUILD_DIR}"
  SCAN_NODE_IMAGE="${image}" OUT_DIR="${NODE_BUILD_DIR}" "${REPO_ROOT}/scripts/release/scan_node_image.sh" build "${version}"
  python3 -I "${REPO_ROOT}/scripts/release/node_artifacts.py" --version "${version}" --image-ref "${image}:${version}" \
    --out "${NODE_BUILD_DIR}"
  docker image rm "${image}:${version}" >/dev/null 2>&1 || true
  log "scan-node downloads: $(du -sh "${NODE_BUILD_DIR}" | cut -f1)"
}

node_files() { # the files of the scan-node downloads on the build machine (none when node-artifacts was not run)
  [[ -f "${NODE_BUILD_DIR}/manifest.json" ]] || return 0
  find "${NODE_BUILD_DIR}" -maxdepth 1 -type f ! -name '*.part' | sort
}

cmd_push() {
  local target=${1:?usage: staging.sh push <user@host> [dir]} dir=${2:-/opt/devsecshield-staging}
  local tag=${DSS_TAG:-$(default_tag)} archive bundle bytes remote_env need_bytes
  archive="$(archive_of "${tag}")"
  [[ -f "${archive}" && -f "${archive}.sha256" ]] || die "no archive for ${tag} (run save)"
  bytes="$(wc -c <"${archive}" | tr -d '[:space:]')"
  local -a files=("${archive}" "${archive}.sha256")
  local need_arg=""
  need_bytes="$(sidecar_need "${archive}")"
  if [[ -n "${need_bytes}" ]]; then
    need_arg=" --need-bytes ${need_bytes}"
    files+=("${archive}.need")
  fi
  # The scan-node downloads (node-artifacts) ride along: their size counts in the host's disk check.
  local -a node=()
  local f node_bytes=0
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    node+=("${f}")
    node_bytes=$((node_bytes + $(wc -c <"${f}" | tr -d '[:space:]')))
  done < <(node_files)
  if ((${#node[@]})); then
    need_arg+=" --node-artifacts-bytes ${node_bytes}"
  else
    log "WARNING: no scan-node downloads in ${NODE_BUILD_DIR} (staging.sh node-artifacts): Add scan node will say they are not available"
  fi
  # The deploy bundle: compose file, nginx config, examples, the rollup overlay the backend mounts, and this script.
  # Never the host's .env, backend.env or certificates: they live only on the host.
  bundle="$(mktemp -d)/dss-staging-bundle-${tag}.tar.gz"
  tar -C "${REPO_ROOT}" -czf "${bundle}" \
    --exclude='deploy/staging/.env' --exclude='deploy/staging/*.env' --exclude='deploy/staging/certs' \
    --exclude='deploy/staging/images' --exclude='deploy/staging/deploy-history' --exclude='deploy/staging/releases' \
    --exclude='deploy/staging/node-artifacts' \
    deploy/staging compose/aibom-config-overlay scripts/deploy/staging.sh scripts/deploy/staging_browser_check.py
  local -a ssh_opts=()
  # shellcheck disable=SC2206 # operator-supplied options, split on purpose
  [[ -n "${SSH_OPTS:-}" ]] && ssh_opts=(${SSH_OPTS})
  remote_env="DSS_IMAGE_PREFIX='$(prefix)' STAGING_DISK_FACTOR='${STAGING_DISK_FACTOR:-}'"
  remote_env+=" STAGING_DISK_RESERVE_MB='${STAGING_DISK_RESERVE_MB:-}'"
  log "copying the deploy bundle to ${target}:${dir}"
  # shellcheck disable=SC2029 # dir, tag and prefix are expanded here on purpose
  ssh "${ssh_opts[@]}" "${target}" "mkdir -p '${dir}/deploy/staging/images'"
  scp "${ssh_opts[@]}" "${bundle}" "${target}:${dir}/"
  rm -rf "$(dirname "${bundle}")"
  # The files in place are now the bundle's, no longer a recorded release's (files-tag). Then, before the archive
  # is copied, the host checks it has room to copy and load it (and frees this deployment's stale images if not).
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" "${target}" "cd '${dir}' && tar -xzf '$(basename "${bundle}")' && rm -f '$(basename "${bundle}")' \
    && rm -f deploy/staging/releases/files-tag \
    && ${remote_env} scripts/deploy/staging.sh disk-check '${tag}' --archive-bytes ${bytes}${need_arg}"
  log "copying the archive ($(kib_h $(((bytes + 1023) / 1024)))) to ${target}:${dir}"
  scp "${ssh_opts[@]}" "${files[@]}" "${target}:${dir}/deploy/staging/images/"
  if ((${#node[@]})); then
    log "copying the scan-node downloads ($(kib_h $(((node_bytes + 1023) / 1024)))) to ${target}:${dir}"
    # into <tag>.part: `deploy` checks every file against its .sha256 before it becomes node-artifacts/<tag>
    # shellcheck disable=SC2029
    ssh "${ssh_opts[@]}" "${target}" "rm -rf '${dir}/deploy/staging/node-artifacts/${tag}.part' \
      && mkdir -p '${dir}/deploy/staging/node-artifacts/${tag}.part'"
    scp "${ssh_opts[@]}" "${node[@]}" "${target}:${dir}/deploy/staging/node-artifacts/${tag}.part/"
  fi
  # backend.env keys from STAGING_SET_<KEY> (CI: the staging environment's secrets) go over ssh's stdin, never on a
  # command line or in the log; the host sets exactly those keys just before the deploy, which then reads them.
  local key name set_env="" payload=""
  for key in "${BACKEND_ENV_KEYS[@]}"; do
    name="STAGING_SET_${key}"
    if [[ -n "${!name:-}" ]]; then
      payload+="${key}=${!name}"$'\n'
    fi
  done
  [[ -z "${payload}" ]] || set_env="scripts/deploy/staging.sh backend-env && "
  # shellcheck disable=SC2029
  printf '%s' "${payload}" | ssh "${ssh_opts[@]}" "${target}" "cd '${dir}' && ${set_env}\
    ${remote_env} STAGING_SERVICES='${STAGING_SERVICES:-}' scripts/deploy/staging.sh deploy '${tag}' </dev/null"
}

# ------------------------------------------------------------------------------------------------ backend.env keys
cmd_backend_env() { # stdin: KEY=VALUE lines; sets exactly those keys in backend.env, prints key names only
  local file="${STAGING_DIR}/backend.env" line key value k known tmp changed=0
  [[ -f "${file}" ]] || die "missing ${file} (cp backend.env.example backend.env)"
  local -A want=()
  local -a order=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -n "${line}" ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${line}" == *=* ]] || die "backend-env: a line without KEY=VALUE"
    known=0
    for k in "${BACKEND_ENV_KEYS[@]}"; do [[ "${k}" == "${key}" ]] && known=1; done
    ((known)) || die "backend-env: ${key:0:64} is not one of: ${BACKEND_ENV_KEYS[*]}"
    [[ -n "${value}" ]] || continue # not provided: leave the host's value
    # AWS key ids, secret keys and ARNs, or 0/1: nothing that could break the env file or a shell
    [[ "${value}" =~ ^[A-Za-z0-9/+=:@._,-]{1,512}$ ]] || die "backend-env: the value of ${key} has characters an env file cannot hold"
    [[ -n "${want[${key}]+x}" ]] || order+=("${key}")
    want[${key}]="${value}"
  done
  ((${#order[@]})) || { log "backend-env: no keys given; backend.env unchanged"; return 0; }
  tmp="$(mktemp "${STAGING_DIR}/.backend.env.XXXXXX")" # 0600, same filesystem: replaced atomically below
  chmod --reference="${file}" "${tmp}" 2>/dev/null || chmod 600 "${tmp}"
  local -A done_=()
  {
    while IFS= read -r line || [[ -n "${line}" ]]; do
      key="${line%%=*}"
      if [[ "${line}" == *=* && -n "${want[${key}]+x}" ]]; then
        [[ -n "${done_[${key}]+x}" ]] && continue # a later duplicate of a key set here: dropped
        done_[${key}]=1
        printf '%s=%s\n' "${key}" "${want[${key}]}"
      else
        printf '%s\n' "${line}"
      fi
    done <"${file}"
    for key in "${order[@]}"; do
      [[ -n "${done_[${key}]+x}" ]] || printf '%s=%s\n' "${key}" "${want[${key}]}"
    done
  } >"${tmp}"
  if cmp -s "${tmp}" "${file}"; then
    rm -f "${tmp}"
  else
    mv -f "${tmp}" "${file}"
    changed=1
  fi
  log "backend-env: ${order[*]} $( ((changed)) && echo "set in backend.env" || echo "already set; backend.env unchanged")"
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

# ------------------------------------------------------------------------------------------------ disk
# Deploy staging run 43572299641 ran the host out of disk while `docker load` unpacked the 5.5 GB archive. Before the
# archive is copied (push runs disk-check on the host) and before it is loaded (deploy), the filesystems that receive
# it must have room for it; when they do not, this deployment's images and archives that no release needs are
# removed first. After a successful deploy only the new release, its rollback target and the last release that passed
# its checks keep their images, and only the new release keeps its archive (rollback needs images, not archives).
PASSED_FILE="${RELEASES_DIR}/passed" # tags whose deploy or rollback passed its checks, oldest first
SEEN_FILE="${RELEASES_DIR}/seen"     # tags whose archive this script checked or loaded on this host

kib_h() { # <KiB>: human readable
  awk -v k="$1" 'BEGIN {
    if (k >= 1048576) printf "%.1f GiB\n", k / 1048576; else if (k >= 1024) printf "%.1f MiB\n", k / 1024
    else printf "%d KiB\n", k }'
}

file_kib() { # <file>: the space it takes, KiB
  du -k "$1" | awk 'NR == 1 { print $1 }'
}

fs_of() { # <path>: "<device> <mount point> <available KiB>" of the filesystem that holds <path> (or its nearest
  # parent). The device identifies the filesystem: a bind mount (/var/lib/containerd bound from /) is the same one.
  local p=$1 dev line
  while [[ ! -e "${p}" && "${p}" == /?* ]]; do p="$(dirname "${p}")"; done
  dev="$(stat -c %d "${p}")" || return 1
  line="$(df -P -k "${p}" | awk 'NR == 2 { print $NF, $4 }')" || return 1
  [[ "${dev}" =~ ^[0-9]+$ && "${line}" =~ ^[^[:space:]]+\ [0-9]+$ ]] || return 1
  printf '%s %s\n' "${dev}" "${line}"
}

toml_root() { # <containerd config>: its top-level root, if readable and set
  [[ -r "$1" ]] || return 0
  awk -F'"' '/^root[[:space:]]*=/ { print $2; exit }' "$1"
}

containerd_root() { # <Docker root>: where containerd keeps its content store and snapshots
  local r="${STAGING_CONTAINERD_ROOT:-$(env_get STAGING_CONTAINERD_ROOT)}" own=/var/run/docker/containerd/containerd.toml
  [[ -n "${r}" ]] || r="$(toml_root "${own}")"
  # dockerd started its own containerd (no system containerd): its root is under Docker's
  if [[ -z "${r}" && -e "${own}" ]]; then r="$1/containerd/daemon"; fi
  [[ -n "${r}" ]] || r="$(toml_root /etc/containerd/config.toml)"
  printf '%s\n' "${r:-/var/lib/containerd}"
}

image_store() { # the directory `docker load` fills: containerd's root with the containerd image store (Docker 29's
  # default; run 43572299641 failed in /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs), else Docker's root
  local info root
  info="$(docker info --format '{{.DockerRootDir}}|{{.Driver}}|{{json .DriverStatus}}')" || return 1
  root="${info%%|*}"
  [[ -n "${root}" ]] || return 1
  if [[ "${info}" == *io.containerd.snapshotter* ]]; then containerd_root "${root}"; else printf '%s\n' "${root}"; fi
}

# STAGING_DISK_FACTOR and STAGING_DISK_RESERVE_MB (environment, else .env, else the defaults), validated before any
# check and never inside a condition (where set -e is off): a typo such as "3,3" or "1G" refuses the deploy instead
# of turning the check off.
DISK_FACTOR=""
DISK_RESERVE_KIB=""
disk_settings() {
  local f r
  f="${STAGING_DISK_FACTOR:-$(env_get STAGING_DISK_FACTOR "${DEFAULT_DISK_FACTOR}")}"
  r="${STAGING_DISK_RESERVE_MB:-$(env_get STAGING_DISK_RESERVE_MB "${DEFAULT_DISK_RESERVE_MB}")}"
  [[ "${f}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "STAGING_DISK_FACTOR=${f} is not a number (e.g. 3.3); nothing was changed"
  [[ "${r}" =~ ^[0-9]+$ ]] || die "STAGING_DISK_RESERVE_MB=${r} is not a whole number of MiB (e.g. 1024); nothing was changed"
  DISK_FACTOR=${f}
  DISK_RESERVE_KIB=$((r * 1024))
}

need_kib() { # <bytes>: KiB, rounded up; empty for an empty argument
  [[ -n "$1" ]] || return 0
  printf '%s\n' "$((($1 + 1023) / 1024))"
}

sidecar_need() { # <archive>: the bytes `save` measured that loading it needs (<archive>.need), empty if none or invalid
  local b
  [[ -f "$1.need" ]] || return 0
  b="$(tr -d '[:space:]' <"$1.need")"
  if [[ "${b}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${b}"
  else
    printf '[staging] WARNING: %s.need is not a byte count; using STAGING_DISK_FACTOR\n' "$1" >&2
  fi
}

# Room to copy an archive of <KiB> (the part not on disk yet) next to the images and to load it into the image store
# (the measured need + 10%, else factor x its size), plus the reserve, on every filesystem (by device)? Sets
# DISK_REPORT (one line per filesystem) and DISK_SHORT (1 when one is short); call it plainly, never as a condition.
DISK_REPORT=""
DISK_SHORT=0
NODE_KIB=0 # the scan-node downloads still to copy (push's --node-artifacts-bytes), on node-artifacts/'s filesystem
disk_room() { # <archive KiB> <KiB of it already on disk> [<measured need KiB>]
  local akib=$1 have=$2 measured=${3:-} store out dev m a copy load how line
  local -A need=() free=() what=() mounts=()
  [[ -n "${DISK_FACTOR}" ]] || die "disk_room before disk_settings"
  store="$(image_store)" || die "docker info failed: cannot tell where Docker stores images; nothing was changed"
  copy=$((akib > have ? akib - have : 0))
  out="$(fs_of "${IMAGES_DIR}")" || die "stat/df failed for ${IMAGES_DIR}; nothing was changed"
  read -r dev m a <<<"${out}"
  need[${dev}]=${copy}
  free[${dev}]=${a}
  mounts[${dev}]=${m}
  if ((copy == 0)); then
    what[${dev}]="archive ${IMAGES_DIR} (in place)"
  else
    what[${dev}]="archive ${IMAGES_DIR} ($(kib_h "${copy}") to copy)"
  fi
  if [[ -n "${measured}" ]]; then
    load=$((measured + measured / 10))
    how="measured $(kib_h "${measured}") + 10%"
  else
    load="$(awk -v k="${akib}" -v f="${DISK_FACTOR}" 'BEGIN { n = k * f; if (n > int(n)) n = int(n) + 1; printf "%d\n", n }')"
    how="x${DISK_FACTOR} the archive"
  fi
  if ((NODE_KIB > 0)); then
    out="$(fs_of "${NODE_ARTIFACTS_DIR}")" || die "stat/df failed for ${NODE_ARTIFACTS_DIR}; nothing was changed"
    read -r dev m a <<<"${out}"
    need[${dev}]=$((${need[${dev}]:-0} + NODE_KIB))
    free[${dev}]=${a}
    if [[ -n "${mounts[${dev}]:-}" && "${mounts[${dev}]}" != "${m}" ]]; then m="${mounts[${dev}]}, ${m}"; fi
    mounts[${dev}]=${m}
    what[${dev}]="${what[${dev}]:+${what[${dev}]} + }scan-node downloads ${NODE_ARTIFACTS_DIR} ($(kib_h "${NODE_KIB}") to copy)"
  fi
  out="$(fs_of "${store}")" || die "stat/df failed for ${store}; nothing was changed"
  read -r dev m a <<<"${out}"
  need[${dev}]=$((${need[${dev}]:-0} + load))
  free[${dev}]=${a}
  if [[ -n "${mounts[${dev}]:-}" && "${mounts[${dev}]}" != "${m}" ]]; then m="${mounts[${dev}]}, ${m}"; fi
  mounts[${dev}]=${m}
  what[${dev}]="${what[${dev}]:+${what[${dev}]} + }images ${store} (${how}: $(kib_h "${load}"))"
  DISK_REPORT=""
  DISK_SHORT=0
  for dev in "${!need[@]}"; do
    line="  ${mounts[${dev}]}: ${what[${dev}]}; need $(kib_h "${need[${dev}]}") + $(kib_h "${DISK_RESERVE_KIB}") reserve,"
    line+=" free $(kib_h "${free[${dev}]}")"
    if ((free[${dev}] >= need[${dev}] + DISK_RESERVE_KIB)); then
      line+=": ok"
    else
      line+=": short by $(kib_h $((need[${dev}] + DISK_RESERVE_KIB - free[${dev}])))"
      DISK_SHORT=1
    fi
    DISK_REPORT+="${line}"$'\n'
  done
  DISK_REPORT="${DISK_REPORT%$'\n'}"
}

rollback_target() { # the tag `rollback` would go back to now (deploy-history), empty if none
  local running p
  running="$(env_get DSS_TAG)"
  [[ -n "${running}" ]] || return 0
  p="$(previous_of "${running}")"
  if [[ "${p}" != none ]]; then printf '%s\n' "${p}"; fi
}

last_passed() { # [<tag>]: the last release (other than <tag>) whose deploy or rollback passed its checks
  local t=""
  if [[ -s "${PASSED_FILE}" ]]; then
    t="$(awk -v x="${1:-}" 'NF && $1 != x { t = $1 } END { print t }' "${PASSED_FILE}")"
  elif [[ -f "${HISTORY_FILE}" ]]; then
    # a host deployed before releases/passed existed: the last deploy or rollback not marked FAILED
    t="$(awk -v x="${1:-}" '($2 == "deploy" || $2 == "rollback") && $NF != "FAILED" && $3 != x { t = $3 }
      END { print t }' "${HISTORY_FILE}")"
  fi
  printf '%s\n' "${t}"
}

record_passed() { # <tag>
  mkdir -p "${RELEASES_DIR}"
  printf '%s\n' "$1" >>"${PASSED_FILE}"
}

record_seen() { # <tag>: its archive was checked or loaded here (so a stale copy of it is known to be ours)
  mkdir -p "${RELEASES_DIR}"
  if ! grep -qxF -- "$1" "${SEEN_FILE}" 2>/dev/null; then printf '%s\n' "$1" >>"${SEEN_FILE}"; fi
}

words() { # <words...>: each non-empty word once, in order
  printf '%s\n' "$@" | awk 'NF && !seen[$0]++' | paste -sd' ' -
}

kept() { # <tag> <kept tags...>: 0 when <tag> is one of them
  local t=$1 k
  shift
  for k in "$@"; do
    if [[ -n "${k}" && "${t}" == "${k}" ]]; then return 0; fi
  done
  return 1
}

dss_images() { # this deployment's tagged images on the host, "<repository>:<tag>\t<size>" (never another site's).
  # Every image is listed and matched here, exactly, rather than trusting docker's reference filter.
  local pfx list repo tag size r
  pfx="$(prefix)"
  list="$(docker image ls --format '{{.Repository}}	{{.Tag}}	{{.Size}}')" || return 1
  while IFS=$'\t' read -r repo tag size; do
    [[ -n "${tag}" && "${tag}" != "<none>" ]] || continue
    for r in "${DSS_REPOS[@]}"; do
      if [[ "${repo}" == "${pfx}/${r}" ]]; then printf '%s:%s\t%s\n' "${repo}" "${tag}" "${size}"; fi
    done
  done <<<"${list}" | sort -u
}

known_tags() { # every release tag of this deployment this host knows: its images' tags, deploy-history, releases/,
  # the passed and seen lists. An archive is this deployment's only as <prefix>-<one of these>.tar.gz exactly (so
  # dss-staging-eu-<tag>.tar.gz, another deployment's, never matches dss-staging's tag "eu-<tag>").
  local images line
  images="$(dss_images)" || return 1
  {
    while IFS= read -r line; do
      line="${line%%$'\t'*}"
      if [[ -n "${line}" ]]; then printf '%s\n' "${line##*:}"; fi
    done <<<"${images}"
    if [[ -f "${HISTORY_FILE}" ]]; then awk '{ print $3 }' "${HISTORY_FILE}"; fi
    if [[ -d "${RELEASES_DIR}" ]]; then find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'; fi
    cat "${PASSED_FILE}" "${SEEN_FILE}" 2>/dev/null || true
  } | awk 'NF' | sort -u
}

stale_images() { # <kept tags...>: this deployment's images of any other tag
  local images line ref
  images="$(dss_images)" || return 1
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    ref="${line%%$'\t'*}"
    kept "${ref##*:}" "$@" || printf '%s\n' "${line}"
  done <<<"${images}"
}

stale_archives() { # <kept tag>: this deployment's archives (.tar.gz, .sha256, .part, .need) of its other known tags
  local keep=$1 base tags t f s
  base="${IMAGES_DIR}/$(prefix | tr '/' '-')-"
  tags="$(known_tags)" || return 1
  while IFS= read -r t; do
    if [[ -z "${t}" || "${t}" == "${keep}" ]]; then continue; fi
    for s in "" .sha256 .part .need; do
      f="${base}${t}.tar.gz${s}"
      if [[ -f "${f}" ]]; then printf '%s\n' "${f}"; fi
    done
  done <<<"${tags}"
}

stale_node_artifacts() { # <kept tags...>: node-artifacts/<tag> (and <tag>.part) directories of every other tag
  local d t
  [[ -d "${NODE_ARTIFACTS_DIR}" ]] || return 0
  for d in "${NODE_ARTIFACTS_DIR}"/*; do
    [[ -d "${d}" && ! -L "${d}" ]] || continue
    t="$(basename "${d}")"
    t="${t%.part}"
    kept "${t}" "$@" || printf '%s\n' "${d}"
  done
}

remove_stale() { # <label> <archive kept> <image tags kept...>: remove this deployment's other images and archives
  local label=$1 akeep=$2 images archives ref size f kib err
  shift 2
  # archives first: their tags are known from the images that are about to go
  archives="$(stale_archives "${akeep}")" || return 1
  images="$(stale_images "$@")" || return 1
  while IFS=$'\t' read -r ref size; do
    [[ -n "${ref}" ]] || continue
    # never forced: docker refuses an image that a container (running or stopped) was created from
    if err="$(docker image rm "${ref}" 2>&1 >/dev/null)"; then
      log "${label}: removed ${ref} (${size})"
    else
      log "${label}: kept ${ref}: ${err##*$'\n'}"
    fi
  done <<<"${images}"
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    kib="$(file_kib "${f}")"
    rm -f -- "${f}"
    log "${label}: removed ${f} ($(kib_h "${kib}"))"
  done <<<"${archives}"
  # the scan-node downloads go with their tag's images (the backend of a kept tag mounts them)
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    rm -rf -- "${f}"
    log "${label}: removed ${f}/ (scan-node downloads)"
  done < <(stale_node_artifacts "$@")
}

plan_stale() { # <label> <archive kept> <image tags kept...>: what remove_stale would remove
  local label=$1 akeep=$2 images archives ref size f n=0
  shift 2
  archives="$(stale_archives "${akeep}")" || die "docker image ls failed"
  images="$(stale_images "$@")" || die "docker image ls failed"
  while IFS=$'\t' read -r ref size; do
    [[ -n "${ref}" ]] || continue
    log "${label}: would remove ${ref} (${size})"
    n=$((n + 1))
  done <<<"${images}"
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    log "${label}: would remove ${f} ($(kib_h "$(file_kib "${f}")"))"
    n=$((n + 1))
  done <<<"${archives}"
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    log "${label}: would remove ${f}/ (scan-node downloads)"
    n=$((n + 1))
  done < <(stale_node_artifacts "$@")
  if ((n == 0)); then log "${label}: nothing to remove"; fi
}

previous_for() { # <tag>: the rollback target once <tag> is deployed: the tag running now, or for a redeploy of the
  # running tag the one it replaced
  local running p
  running="$(env_get DSS_TAG)"
  p="${running}"
  [[ "${p}" != "$1" ]] || p="$(previous_of "$1")"
  if [[ "${p}" != none ]]; then printf '%s\n' "${p}"; fi
}

# Before the copy (`push` runs disk-check on the host) and before the load (deploy): room for <tag>'s archive? If
# not, remove this deployment's images of every tag but <tag>, the running one, its rollback target and the last
# release that passed its checks, and its archives but <tag>'s, and check again; still short: stop before anything
# is switched. plan: say what would be removed (now and by the retention after the deploy), remove nothing.
make_room() { # <check|plan> <tag> <archive KiB> <KiB of it already on disk> [<measured need KiB>]
  local mode=$1 tag=$2 akib=$3 have=$4 measured=${5:-} running keep after
  disk_settings
  running="$(env_get DSS_TAG)"
  keep="$(words "${tag}" "${running}" "$(rollback_target)" "$(last_passed)")"
  after="$(words "${tag}" "$(previous_for "${tag}")" "$(last_passed "${tag}")")"
  [[ "${mode}" == plan ]] || record_seen "${tag}"
  disk_room "${akib}" "${have}" "${measured}"
  if ((DISK_SHORT == 0)); then
    log "disk: enough space to load ${tag} ($(kib_h "${akib}") archive):"$'\n'"${DISK_REPORT}"
    [[ "${mode}" == plan ]] || return 0
    log "preflight: nothing to remove"
  else
    log "disk: short for ${tag} ($(kib_h "${akib}") archive):"$'\n'"${DISK_REPORT}"
    if [[ "${mode}" == plan ]]; then
      log "preflight (keeps the images of ${keep}, the archive of ${tag}):"
      # shellcheck disable=SC2086 # tags, one word each
      plan_stale preflight "${tag}" ${keep}
    else
      log "disk: removing this deployment's images of tags other than ${keep} and archives other than ${tag}'s"
      # shellcheck disable=SC2086
      remove_stale preflight "${tag}" ${keep} || die "docker image ls failed; nothing was switched"
      disk_room "${akib}" "${have}" "${measured}"
      if ((DISK_SHORT == 0)); then
        log "disk: enough space to load ${tag} now:"$'\n'"${DISK_REPORT}"
        return 0
      fi
      die "not enough disk space to load ${tag}, even after removing this deployment's other images and archives:" \
        $'\n'"${DISK_REPORT}"$'\n'"[staging] nothing was switched: the containers still run ${running:-nothing}." \
        "Free space on those filesystems (other sites share the host; \`staging.sh disk-plan ${tag}\` shows what" \
        "this deployment holds) or set STAGING_DISK_FACTOR, then deploy again."
    fi
  fi
  log "after the deploy (keeps the images of ${after}, the archive of ${tag}):"
  # shellcheck disable=SC2086
  plan_stale "after the deploy" "${tag}" ${after}
}

cmd_disk() { # <check|plan> <tag> [--archive-bytes N] [--need-bytes N] [--node-artifacts-bytes N]
  local mode=$1 tag="" bytes="" need_bytes="" archive akib have=0
  shift
  while (($#)); do
    case "$1" in
      --archive-bytes | --need-bytes | --node-artifacts-bytes)
        (($# >= 2)) || die "$1 needs a value"
        [[ "$2" =~ ^[0-9]+$ ]] || die "$1 $2 is not a number of bytes"
        case "$1" in
          --archive-bytes) bytes=$2 ;;
          --need-bytes) need_bytes=$2 ;;
          *) NODE_KIB="$(need_kib "$2")" ;;
        esac
        shift 2
        ;;
      -*) die "unknown disk-${mode} option $1 (see --help)" ;;
      *)
        [[ -z "${tag}" ]] || die "usage: staging.sh disk-${mode} <tag> [--archive-bytes N] [--need-bytes N] [--node-artifacts-bytes N]"
        tag=$1
        shift
        ;;
    esac
  done
  [[ -n "${tag}" ]] || die "usage: staging.sh disk-${mode} <tag> [--archive-bytes N] [--need-bytes N]"
  archive="$(archive_of "${tag}")"
  if [[ -f "${archive}" ]]; then have="$(file_kib "${archive}")"; fi
  if [[ -n "${bytes}" ]]; then
    akib="$(need_kib "${bytes}")"
  elif [[ -f "${archive}" ]]; then
    akib=${have}
  else
    die "no archive ${archive}: give its size with --archive-bytes"
  fi
  [[ -n "${need_bytes}" ]] || need_bytes="$(sidecar_need "${archive}")"
  make_room "${mode}" "${tag}" "${akib}" "${have}" "$(need_kib "${need_bytes}")"
}

# `docker load` of <tag>'s archive. Out of disk, the containerd image store still tags every image, prints "Error
# unpacking image ...: no space left on device" and exits 0 (run 43572299641: `docker image inspect` then found every
# image and the deploy died at its first `docker run`); the classic store exits non-zero part way. Either way: remove
# the images of <tag> this load left behind (never when <tag> is the running tag, its rollback target or the last
# release that passed its checks, whose images were there before) and stop before anything is switched.
load_archive() { # <tag> <archive>
  local tag=$1 archive=$2 out rc=0 running r ref
  out="$(mktemp)"
  docker load -i "${archive}" 2>&1 | tee "${out}" || rc=$?
  if [[ "${rc}" == 0 ]] && ! grep -qiE 'error unpacking image|no space left on device' "${out}"; then
    rm -f "${out}"
    return 0
  fi
  rm -f "${out}"
  running="$(env_get DSS_TAG)"
  if kept "${tag}" "${running}" "$(rollback_target)" "$(last_passed)"; then
    die "docker load of ${archive} failed (output above); ${tag} is running, the rollback target or the last" \
      "release that passed its checks, so its images were not removed. Free disk space (staging.sh disk-plan ${tag})" \
      "and deploy again."
  fi
  for r in "${DSS_REPOS[@]}"; do
    ref="$(prefix)/${r}:${tag}"
    docker image inspect "${ref}" >/dev/null 2>&1 || continue
    if docker image rm "${ref}" >/dev/null; then log "removed ${ref} (partly loaded)"; else log "WARNING: could not remove ${ref}"; fi
  done
  die "docker load of ${archive} failed (output above): removed the images of ${tag} it loaded. Nothing was" \
    "switched: the containers still run ${running:-nothing}. Free disk space (staging.sh disk-plan ${tag}) and" \
    "deploy again."
}

# After a deploy whose checks passed: images of <tag>, of <previous> (the rollback target) and of <last passed> (the
# last other release that passed its checks; it differs from <previous> after a failed deploy) are kept, and the
# archive of <tag> only.
retain() { # <tag> <previous> <last passed>
  local msg=$1
  [[ -z "$2" ]] || msg+=", $2 (rollback target)"
  if [[ -n "$3" && "$3" != "$1" && "$3" != "$2" ]]; then msg+=", $3 (last release that passed its checks)"; fi
  log "retention: kept ${msg}; removing this deployment's other images, and its archives but ${1}'s"
  # shellcheck disable=SC2046 # tags, one word each
  remove_stale retention "$1" $(words "$1" "$2" "$3") || log "WARNING: retention skipped: docker image ls failed"
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

# node-artifacts/<tag>.part (copied by push) becomes node-artifacts/<tag> once it has its manifest.json and every file
# has a .sha256 beside it that matches; the backend of <tag> mounts it read-only (docker-compose.yml). A tag
# deployed without downloads gets an empty directory (the API then says they are not available), never one that
# Docker would create as root.
install_node_artifacts() { # <tag>
  local tag=$1 part="${NODE_ARTIFACTS_DIR}/$1.part" dest="${NODE_ARTIFACTS_DIR}/$1" sums f
  mkdir -p "${NODE_ARTIFACTS_DIR}"
  if [[ -d "${part}" ]]; then
    [[ -f "${part}/manifest.json" ]] || die "${part} has no manifest.json; nothing was switched"
    sums="$(cd "${part}" && find . -maxdepth 1 -name '*.sha256' -printf '%f\n' | sort)"
    [[ -n "${sums}" ]] || die "${part} has no .sha256 files; nothing was switched"
    # shellcheck disable=SC2086 # file names without spaces (node_artifacts.py names them)
    (cd "${part}" && sha256sum --quiet -c ${sums}) ||
      die "the scan-node downloads in ${part} do not match their .sha256 (copy damaged?); nothing was switched"
    for f in "${part}"/*; do
      case "${f}" in *.sha256 | */manifest.json) continue ;; esac
      [[ -f "${f}.sha256" ]] || die "${f} has no .sha256 beside it; nothing was switched"
    done
    rm -rf "${dest}"
    mv "${part}" "${dest}"
    log "scan-node downloads of ${tag} in place: $(paste -sd' ' <(cd "${dest}" && ls))"
  elif [[ -f "${dest}/manifest.json" ]]; then
    log "scan-node downloads of ${tag} already in place (${dest})"
  else
    mkdir -p "${dest}"
    log "WARNING: no scan-node downloads for ${tag} (push them with staging.sh node-artifacts): Add scan node will say they are not available"
  fi
}

# A tag can start only on a database at a revision its migrations contain: otherwise its migrate one-shot fails
# ("Can't locate revision identified by ...") and everything that waits for it never starts.
cmd_deploy() {
  require_host_files
  local tag=${1:-${DSS_TAG:-}} archive running previous head="" db in_place c kib last
  [[ -n "${tag}" ]] || die "usage: staging.sh deploy <tag>"
  archive="$(archive_of "${tag}")"
  running="$(env_get DSS_TAG)"
  # The rollback target once this deploy succeeds: the running tag; a redeploy of it keeps the tag it replaced.
  previous="$(previous_for "${tag}")"
  if [[ -f "${archive}" ]]; then
    log "verifying ${archive}"
    (cd "${IMAGES_DIR}" && sha256sum -c "$(basename "${archive}").sha256")
    kib="$(file_kib "${archive}")"
    make_room check "${tag}" "${kib}" "${kib}" "$(need_kib "$(sidecar_need "${archive}")")"
    log "loading ${archive}"
    load_archive "${tag}" "${archive}"
  fi
  for c in $(components); do
    docker image inspect "$(image_of "${c}" "${tag}")" >/dev/null 2>&1 ||
      [[ -n "${STAGING_SERVICES:-}" ]] || die "image $(image_of "${c}" "${tag}") is not loaded"
  done
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
  install_node_artifacts "${tag}"
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
  last="$(last_passed "${tag}")"
  record_passed "${tag}"
  retain "${tag}" "${previous}" "${last}"
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
  mkdir -p "${NODE_ARTIFACTS_DIR}/${previous}" # kept with its images; never one Docker creates as root
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
  record_passed "${previous}"
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
    disk-check) cmd_disk check "$@" ;;
    disk-plan) cmd_disk plan "$@" ;;
    node-artifacts) cmd_node_artifacts ;;
    backend-env) cmd_backend_env ;;
    -h | --help | help | "") sed -n '2,56p' "${BASH_SOURCE[0]}" ;;
    *) die "unknown command ${cmd} (see --help)" ;;
  esac
}

main "$@"
