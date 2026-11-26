#!/usr/bin/env bash
# remote.sh - the instance side of the Chola production kit (deploy/chola-prod/README.md). scripts/deploy/chola-prod.sh
# copies the kit to /opt/devsecshield-chola/.kit-next/ and runs this script from there over the EC2 Instance Connect
# tunnel as ubuntu, with CHOLA_BASE_DIR=/opt/devsecshield-chola: the LIVE files (compose file, nginx, env files) are
# in $CHOLA_BASE_DIR/deploy/chola-prod and only `install` (deploy) replaces them. Read-only commands never do.
#
#   remote.sh preflight                     Docker, Compose >= 2.24, AWS CLI + instance role (STS, S3 read of the
#                                           release prefix), the data volume, free disk where images AND volumes live,
#                                           IMDS: the host answers; containers do not (a token probe from a
#                                           container; with a hop limit > 1 also the IMDS block's rule and unit;
#                                           fails otherwise unless CHOLA_ALLOW_IMDS=1)
#   remote.sh imds-block                    install (idempotent) the rule that drops container traffic to the metadata
#                                           service (DOCKER-USER), its systemd unit and Docker's ExecStartPre drop-in
#   remote.sh imds-check                    the IMDS checks of preflight, with the container probe REQUIRED (deploy:
#                                           after the infrastructure images are loaded, before anything starts)
#   remote.sh install                       copy this kit (.kit-next) over the live kit files (deploy only)
#   remote.sh infra-missing                 the infrastructure images that are not loaded (one per line)
#   remote.sh infra-load <s3 key> <sha256>  download the release archive to /var/lib/docker/releases, check, load, delete
#   remote.sh render [<tag>]                the env files from Secrets Manager with the instance role (kit.py)
#   remote.sh ecr-login                     docker login to the ECR registry with the instance role
#   remote.sh pull <tag> [--local]          pull the four application images (linux/amd64; frontend API URL checked);
#                                           --local: only check them (the S3 relay loaded them; nothing is pulled)
#   remote.sh relay-load <sha40> <spec>...  the S3 relay of a CI run's artifacts: download from S3, sha256, extract,
#                                           check (digest, blobs, linux/amd64, revision), load, delete (detached job)
#   remote.sh volume-exists                 "yes" or "no" (exit 0) whether any database / queue volume exists; any
#                                           other outcome is an error (exit != 0)
#   remote.sh dump                          pg_dump + mongodump onto the data volume (last CHOLA_DUMPS_KEEP=3 kept)
#   remote.sh deploy <tag>                  refuse a tag older than the database; record STARTED; switch DSS_TAG;
#                                           migrate + up; check; estate backfill + agility heal; image retention
#   remote.sh rollback [--allow-downgrade]  back to the previous tag (from the last deploy or STARTED record); records
#                                           ROLLBACK-STARTED first, and a retry of a failed or interrupted rollback
#                                           retries it (never one release further back)
#   remote.sh rollback ... --to <tag>       to that release instead (it must have been deployed and passed its checks)
#   remote.sh rollback --plan [--to <tag>]  what a rollback would do; exit 3 when it needs a database downgrade
#   remote.sh check                         every service on DSS_TAG and up; health + frontend through nginx on :80
#   remote.sh smtp-test                     SMTP login only, from a backend container with backend.env (sends nothing)
#   remote.sh admin <email>                 make an existing account the platform administrator (is_superuser)
#   remote.sh status | logs [service|all] [N]
#   remote.sh job-start <deploy|rollback|dump|infra-load|relay-load> [args]
#                                           run that command DETACHED (setsid nohup; survives a dropped tunnel or
#                                           Ctrl-C), output in state/jobs/<id>/log, exit status in .../rc; prints <id>
#   remote.sh job-follow <id> <offset> [wait-s]
#                                           print the job's output from byte <offset>; last stderr line:
#                                           "chola-job: running <offset>", "chola-job: done <rc> <offset>" or
#                                           "chola-job: lost <offset>" (its wrapper and its worker are gone and no
#                                           exit status was written)
#
# Settings come from the caller (chola-prod.sh passes them): CHOLA_BASE_DIR, CHOLA_REGION, CHOLA_ACCOUNT,
# CHOLA_REGISTRY, CHOLA_IMAGE_PREFIX, CHOLA_SECRET_PREFIX, CHOLA_BUCKET, CHOLA_FRONTEND_HOST, CHOLA_API_HOST,
# CHOLA_REAL_IP_FROM, CHOLA_ALLOW_IMDS, CHOLA_MIN_FREE_GB (15), CHOLA_WAIT_S (900), CHOLA_DUMPS_KEEP (3),
# CHOLA_S3_PROBE_KEY (preflight: a small object the owner just wrote, read here to prove s3:GetObject),
# CHOLA_IMDS_HOP and CHOLA_IMDS_IPV6 (the instance's HttpPutResponseHopLimit and HttpProtocolIpv6, read by the owner
# with describe-instances; an unknown hop limit is treated as > 1).
set -Eeuo pipefail
export LC_ALL=C
# No silent exit: a failing command that no check handles names itself. Only an assignment from a failing $(...) is
# skipped: its inner command (or die) has already said why. Any other command (an ssh or docker line with a $(...)
# argument included) is reported.
ASSIGN_FROM_SUBST='^((local|export|readonly|declare|typeset)([[:space:]]+-[A-Za-z]+)*[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=.*\$\('
# EXIT_EXPECTED: 1 once this shell is ending on purpose (main returned, die, an explicit exit, an errexit failure: the
# ERR trap fires right before errexit ends the shell, and in exactly the same places). A detached job's worker writes
# its exit status only then (on_exit): when a signal kills it, bash runs the EXIT trap with $? = the LAST COMMAND's
# status (often 0), so the worker writes nothing and the wrapper records the real 128+n (or the job reads as lost).
EXIT_EXPECTED=0
err_report() {
  EXIT_EXPECTED=1
  [[ "${BASH_COMMAND}" =~ ${ASSIGN_FROM_SUBST} ]] || printf '[chola-remote] ERROR: line %s: %s (exit %s)\n' "$2" "${BASH_COMMAND}" "$1" >&2
}
trap 'err_report "$?" "${LINENO}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
BASE_DIR="${CHOLA_BASE_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
KIT_DIR="${BASE_DIR}/deploy/chola-prod" # the live kit: compose file, nginx, env files
COMPOSE_FILE="${KIT_DIR}/docker-compose.yml"
ENV_FILE="${KIT_DIR}/.env"
ENV_FILES=(.env backend.env scan-worker.env dast-worker.env)
NODE_ARTIFACTS_DIR="${BASE_DIR}/node-artifacts"
STATE_DIR="${BASE_DIR}/state"
HISTORY_FILE="${STATE_DIR}/deploy-history"
RELEASES_DIR="${STATE_DIR}/releases"
PASSED_FILE="${STATE_DIR}/passed"
JOBS_DIR="${STATE_DIR}/jobs"
RELEASE_FILES=(deploy/chola-prod compose/aibom-config-overlay)
RELEASE_EXCLUDES=(--exclude=deploy/chola-prod/.env --exclude='deploy/chola-prod/*.env')
ARCHIVE_DIR=${CHOLA_ARCHIVE_DIR:-/var/lib/docker/releases} # the variable: tests only
DUMP_DIR=/var/lib/docker/dss-backups
ALEMBIC_INI=/prod_database_migrations/alembic.ini
PROJECT=dss-chola
DATA_VOLUMES=("${PROJECT}_pgdata" "${PROJECT}_mongodata" "${PROJECT}_rabbitmq")
MIN_COMPOSE=2.24.0 # env_file entries with path:, --wait with one-shot dependencies

REGION="${CHOLA_REGION:-ap-south-1}"
ACCOUNT="${CHOLA_ACCOUNT:-935951870001}"
REGISTRY="${CHOLA_REGISTRY:-${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com}"
IMAGE_PREFIX="${CHOLA_IMAGE_PREFIX:-${REGISTRY}/devsec-chola}"
SECRET_PREFIX="${CHOLA_SECRET_PREFIX:-devsec-chola/prod}"
BUCKET="${CHOLA_BUCKET:-devsecshield-storage}"
FRONTEND_HOST="${CHOLA_FRONTEND_HOST:-chola.zeroshield.ai}"
API_HOST="${CHOLA_API_HOST:-chola-api.zeroshield.ai}"
REAL_IP_FROM="${CHOLA_REAL_IP_FROM:-10.60.1.0/24,10.60.2.0/24}"
# The tags docker-compose.yml runs (backend/tests/test_chola_prod_kit.py checks). chola-prod.sh pulls them by digest
# (its INFRA_IMAGES) and ships them under these tags in the release archive.
INFRA_IMAGES=(postgres:15-alpine mongo:8.0.6 rabbitmq:4.1-management-alpine nginx:1.27-alpine qdrant/qdrant:v1.13.5)
APP_REPOS=(devsecshield-backend devsecshield-frontend scan-worker dast-worker)
INFRA_SERVICES=" postgres mongo rabbitmq qdrant "
ONESHOT_SERVICES=" migrate "
# The container IMDS block (deploy/chola-prod/host/; README "Instance metadata (IMDS)").
IMDS_SCRIPT=/usr/local/sbin/devsec-chola-imds-block
IMDS_UNIT=devsec-chola-imds-block.service
IMDS_DROPIN=/etc/systemd/system/docker.service.d/devsec-chola-imds-block.conf
IMDS_CONF=/etc/default/devsec-chola-imds-block
IMDS_COMMENT=devsec-chola-imds
PROBE_IMAGE=qdrant/qdrant:v1.13.5 # has bash and timeout; loaded with the infrastructure images
DEV_MARKERS=('hmr-client' '_browser_dev_' 'webpack-hmr' 'react-refresh' '\"b\":\"development\"')

log() { printf '[chola-remote %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { EXIT_EXPECTED=1; printf '[chola-remote] ERROR: %s\n' "$*" >&2; exit 1; }

SUDO=()
docker_setup() { # plain docker when ubuntu is in the docker group, else sudo -n docker
  if docker info >/dev/null 2>&1; then
    SUDO=()
  elif sudo -n docker info >/dev/null 2>&1; then
    SUDO=(sudo -n)
  else
    die "cannot talk to Docker as $(id -un) (not in the docker group, no passwordless sudo)"
  fi
}
d() { "${SUDO[@]}" docker "$@"; }
# sha256 over the bind-mounted files (nginx config, aibom overlay) AND the overlay directory's inode: docker-compose.yml's
# files-hash label. The backend mounts the overlay DIRECTORY: a container keeps the generation it was created on, and
# prune_old_dirs empties that generation. The inode changes with every swap (put_live), so every reader of a replaced
# overlay is recreated even when the new one has the same content; an overlay left in place keeps its inode and label.
# (nginx mounts single files: those keep their inode in the container when the old kit generation is removed.)
files_hash() {
  (cd "${BASE_DIR}" && {
    find deploy/chola-prod/nginx compose/aibom-config-overlay -type f 2>/dev/null | LC_ALL=C sort | xargs -r sha256sum
    stat -c 'overlay-dir inode %i' compose/aibom-config-overlay 2>/dev/null || true
  } | sha256sum | cut -c1-16)
}
# `env` after sudo: sudo resets the environment, so a plain VAR=... prefix would never reach Compose.
compose() {
  "${SUDO[@]}" env "DSS_FILES_HASH=${DSS_FILES_HASH:-$(files_hash)}" docker compose --project-name "${PROJECT}" \
    --project-directory "${KIT_DIR}" -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
}

env_get() { # <KEY> [default] from .env without sourcing it
  local v=""
  [[ -f "${ENV_FILE}" ]] && v="$(sed -n -E "s/^$1=[\"']?([^\"']*)[\"']?[[:space:]]*$/\1/p" "${ENV_FILE}" | tail -n 1)"
  printf '%s\n' "${v:-${2:-}}"
}
set_tag() { # rewrite only the DSS_TAG line of .env (GNU sed -i keeps the file's mode)
  [[ "$1" =~ ^[0-9a-f]{12}$ ]] || die "tag $1 is not a 12-character commit"
  if grep -q '^DSS_TAG=' "${ENV_FILE}"; then
    sed -i -E "s|^DSS_TAG=.*|DSS_TAG='$1'|" "${ENV_FILE}"
  else
    printf "DSS_TAG='%s'\n" "$1" >>"${ENV_FILE}"
  fi
}
image_of() { printf '%s/%s:%s\n' "${IMAGE_PREFIX}" "$1" "$2"; }

require_env_files() {
  local f mode
  for f in "${ENV_FILES[@]}"; do
    [[ -f "${KIT_DIR}/${f}" ]] || die "missing ${KIT_DIR}/${f} (chola-prod.sh renders it)"
    mode="$(stat -c %a "${KIT_DIR}/${f}")"
    [[ "${mode}" == 600 ]] || die "${KIT_DIR}/${f} has mode ${mode}, expected 600"
    if grep -Eq "^[[:space:]]*(export[[:space:]]+)?(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_(EMAIL|CODE))[[:space:]]*=" \
      "${KIT_DIR}/${f}"; then
      die "DSS_DEV_MODE / LOCAL_DEV_VERIFICATION_* must never be set in production (${f})"
    fi
  done
}

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }

# ------------------------------------------------------------------------------------------------ disk
toml_root() { if [[ -r "$1" ]]; then awk -F'"' '/^root[[:space:]]*=/ { print $2; exit }' "$1"; fi; }
image_store() { # the directory `docker pull` / `docker load` fill: containerd's root with the containerd image store
  # (Docker 29's default for new installs), else Docker's root dir (deploy/staging's staging.sh does the same)
  local root r own=/var/run/docker/containerd/containerd.toml
  root="$(d info --format '{{.DockerRootDir}}')"
  if d info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter; then
    r="$(toml_root "${own}")"
    if [[ -z "${r}" && -e "${own}" ]]; then r="${root}/containerd/daemon"; fi
    [[ -n "${r}" ]] || r="$(toml_root /etc/containerd/config.toml)"
    printf '%s\n' "${r:-/var/lib/containerd}"
  else
    printf '%s\n' "${root}"
  fi
}
store_kind() { # containerd (Docker's containerd image store) or graphdriver (overlay2 and the like)
  if d info --format '{{json .DriverStatus}}' 2>/dev/null | grep -q io.containerd.snapshotter; then echo containerd
  else echo "graphdriver $(d info --format '{{.Driver}}' 2>/dev/null || echo '?')"; fi
}
disk_check() { # CHOLA_MIN_FREE_GB (default 15) free where images are stored AND where volumes are
  local min=${CHOLA_MIN_FREE_GB:-15} p avail bad=0
  for p in "$(image_store)" "$(d info --format '{{.DockerRootDir}}')"; do
    while [[ ! -e "${p}" && "${p}" == /?* ]]; do p="$(dirname "${p}")"; done
    avail="$(df -P -BG "${p}" | awk 'NR == 2 { sub("G", "", $4); print $4 }')"
    if ((avail >= min)); then
      log "disk: ${avail} GB free on $(findmnt -n -o TARGET -T "${p}") (for ${p}; need ${min})"
    else
      log "FAIL disk: only ${avail} GB free on $(findmnt -n -o TARGET -T "${p}") (for ${p}; need ${min} GB)"
      bad=1
    fi
  done
  return "${bad}"
}

# ------------------------------------------------------------------------------------------------ preflight
cmd_preflight() {
  local bad=0 root dev_root dev_slash cv arn
  docker_setup
  cv="$(d compose version --short 2>/dev/null || echo 0)"
  log "docker: $(d version --format 'engine {{.Server.Version}}')${SUDO[*]:+ (through sudo)}; compose: ${cv}"
  version_ge "${cv#v}" "${MIN_COMPOSE}" || { log "FAIL Docker Compose ${cv} is older than ${MIN_COMPOSE}"; bad=1; }
  command -v python3 >/dev/null || { log "FAIL python3 is missing"; bad=1; }
  command -v flock >/dev/null || { log "FAIL flock is missing (util-linux)"; bad=1; }
  command -v setsid >/dev/null || { log "FAIL setsid is missing (util-linux)"; bad=1; }
  if command -v aws >/dev/null; then
    log "aws: $(aws --version 2>&1 | cut -d' ' -f1)"
    if arn="$(aws sts get-caller-identity --region "${REGION}" --query Arn --output text 2>/dev/null)"; then
      log "instance identity: ${arn}"
    else
      log "FAIL the instance role answers no STS call (aws sts get-caller-identity)"
      bad=1
    fi
    # The release archive path: the instance role must read s3://BUCKET/releases/ in the expected account.
    local err
    err="$(mktemp)"
    if aws s3api list-objects-v2 --region "${REGION}" --bucket "${BUCKET}" --prefix releases/ --max-keys 1 \
      --expected-bucket-owner "${ACCOUNT}" --query KeyCount --output text >/dev/null 2>"${err}"; then
      log "instance role: S3 list of s3://${BUCKET}/releases/ (bucket owner ${ACCOUNT}) OK"
    else
      log "FAIL instance role cannot list s3://${BUCKET}/releases/ as owner ${ACCOUNT}: $(tail -n 1 "${err}")"
      bad=1
    fi
    # Listing is not reading: get the probe object the owner wrote for this preflight (infra-load needs GetObject).
    if [[ -n "${CHOLA_S3_PROBE_KEY:-}" ]]; then
      [[ "${CHOLA_S3_PROBE_KEY}" =~ ^releases/[A-Za-z0-9._-]+$ ]] || die "CHOLA_S3_PROBE_KEY is not a releases/ key"
      if aws s3api get-object --region "${REGION}" --bucket "${BUCKET}" --key "${CHOLA_S3_PROBE_KEY}" \
        --expected-bucket-owner "${ACCOUNT}" "${err}.obj" >/dev/null 2>"${err}"; then
        log "instance role: S3 read (GetObject) of s3://${BUCKET}/${CHOLA_S3_PROBE_KEY} OK"
      else
        log "FAIL instance role cannot read s3://${BUCKET}/${CHOLA_S3_PROBE_KEY} as owner ${ACCOUNT}: $(tail -n 1 "${err}")"
        bad=1
      fi
      rm -f "${err}.obj"
    else
      log "WARNING S3 read not proved (no probe object given); infra-load will tell"
    fi
    rm -f "${err}"
  else
    log "FAIL the AWS CLI is not installed on the instance (chola-prod.sh host-setup installs it)"
    bad=1
  fi
  root="$(d info --format '{{.DockerRootDir}}')"
  dev_root="$(stat -c %d "${root}" 2>/dev/null || sudo -n stat -c %d "${root}")"
  dev_slash="$(stat -c %d /)"
  if [[ "${dev_root}" == "${dev_slash}" ]]; then
    log "FAIL ${root} is on the root filesystem, not on the separate data volume: databases would land on the root disk"
    bad=1
  else
    log "data volume: ${root} is $(findmnt -n -o SOURCE,FSTYPE,SIZE,AVAIL -T "${root}" | tr -s ' ')"
  fi
  log "image store: $(image_store) ($(store_kind)); the S3 relay loads OCI layouts with a docker-save manifest.json on either"
  disk_check || bad=1
  if [[ -f "${ENV_FILE}" ]]; then log "deployed tag: $(env_get DSS_TAG none)"; else log "not deployed yet (no ${ENV_FILE})"; fi
  log "data volumes present: $(volume_state)"
  log "infrastructure images missing: $(infra_missing | paste -sd' ' -)"
  imds_checks || bad=1
  [[ "${bad}" == 0 ]] || die "instance preflight failed (above)"
  log "instance preflight OK"
}

# ------------------------------------------------------------------------------------------------ instance metadata
# Containers must not get the instance role's credentials (they read every devsec-chola/prod secret; the app uses the
# app-user keys). With HttpPutResponseHopLimit 1 AWS stops a container's token at the bridge hop. Infra keeps 2, so the
# host drops container traffic to the metadata service itself (imds-block) and preflight proves both the rule and a
# failed token request from a container.
imds_rule() { # <4|6>: 0 when the DROP rule is in DOCKER-USER
  local t=iptables dst=169.254.169.254/32
  if [[ "$1" == 6 ]]; then t=ip6tables dst=fd00:ec2::254/128; fi
  sudo -n "${t}" -w -C DOCKER-USER -d "${dst}" -m comment --comment "${IMDS_COMMENT}" -j DROP >/dev/null 2>&1
}

# The probe's script, run inside a container: one word for what the token request met. A connect that never completes
# (a DROP rule) is "timeout", a refused one "refused", no route "noroute"; a 200 answer "reachable"; anything else
# (accepted but never answered, another answer, no timeout or /dev/tcp in the image) "error".
# shellcheck disable=SC2016 # expanded inside the container
PROBE_SCRIPT='command -v timeout >/dev/null 2>&1 || { echo error; exit 0; }
r=$(timeout "${T:-8}" bash -c '"'"'exec 3<>"/dev/tcp/$A/${P:-80}" || exit 7; echo connected; printf "PUT /latest/api/token HTTP/1.1\r\nHost: %s\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nConnection: close\r\n\r\n" "$H" >&3; head -n 1 <&3'"'"' 2>&1); rc=$?
if [ "$rc" = 124 ]; then case "$r" in *connected*) echo error ;; *) echo timeout ;; esac
elif printf "%s" "$r" | grep -q " 200 "; then echo reachable
else case "$r" in *connected*) echo error ;; *"Connection refused"*) echo refused ;; *nreachable*|*"No route"*|*"Cannot assign"*) echo noroute ;; *) echo error ;; esac
fi'

imds_probe() { # <4|6>: reachable | blocked | error | unprobed, over the default bridge AND the stack's egress network
  # (once it exists): every network a container of this stack can route out of. No output (Docker failed, the image
  # is missing) is "error", never "blocked". IPv4: only timeout or refused is blocked. IPv6: no route counts as
  # blocked too (a container without IPv6 cannot reach fd00:ec2::254 at all).
  local addr=169.254.169.254 host=169.254.169.254 out net verdict=blocked w
  local -a nets=(bridge)
  if [[ "$1" == 6 ]]; then addr=fd00:ec2::254 host='[fd00:ec2::254]'; fi
  d image inspect "${PROBE_IMAGE}" >/dev/null 2>&1 || { printf 'unprobed\n'; return 0; }
  if d network inspect "${PROJECT}_egress" >/dev/null 2>&1; then nets+=("${PROJECT}_egress"); fi
  for net in "${nets[@]}"; do
    out="$(d run --rm --network "${net}" --entrypoint bash -e "A=${addr}" -e "H=${host}" "${PROBE_IMAGE}" \
      -c "${PROBE_SCRIPT}" 2>/dev/null || true)"
    case "${out}" in
      reachable) w=reachable ;;
      timeout | refused) w=blocked ;;
      noroute) if [[ "$1" == 6 ]]; then w=blocked; else w=error; fi ;;
      *) w=error ;;
    esac
    log "IMDS probe (IPv$1) on network ${net}: ${out:-no answer} -> ${w}" >&2
    if [[ "${w}" == reachable ]]; then verdict=reachable
    elif [[ "${w}" == error && "${verdict}" != reachable ]]; then verdict=error; fi
  done
  printf '%s\n' "${verdict}"
}

# imds_verdict <hop> <ipv6 enabled|disabled> <rule4> <rule6> <unit> <probe4> <probe6> <require-probe 0|1> <allow 0|1>
# One line per finding; exit 1 on a failure. rule*/unit: yes | no; probe*: reachable | blocked | error | unprobed.
imds_verdict() {
  local hop=$1 v6=$2 rule4=$3 rule6=$4 unit=$5 p4=$6 p6=$7 need=$8 allow=$9 bad=0 probe=$6 need_block=1
  [[ "${hop}" =~ ^[0-9]+$ && "${hop}" -le 1 ]] && need_block=0
  if [[ "${v6}" == enabled ]]; then
    case "${p4} ${p6}" in *reachable*) probe=reachable ;; *error*) probe=error ;; *unprobed*) probe=unprobed ;; esac
  fi
  fail() { # a finding that fails the check unless --allow-imds
    if [[ "${allow}" == 1 ]]; then log "WARNING $* (accepted: --allow-imds)"; else log "FAIL $*"; bad=1; fi
  }
  local block="rule ${rule4}"
  if [[ "${v6}" == enabled ]]; then block+=", IPv6 rule ${rule6}"; fi
  block+=", unit ${unit}"
  if ((need_block)); then
    log "IMDS hop limit ${hop:-unknown}: containers are kept off the metadata service by the host (${block})"
    if [[ "${rule4}" != yes || "${unit}" != yes || ("${v6}" == enabled && "${rule6}" != yes) ]]; then
      fail "the container IMDS block is not installed (${block}): with hop limit ${hop:-unknown} a container could get the instance role's credentials. Run chola-prod.sh host-setup (or a deploy installs it), or ask infra for HttpPutResponseHopLimit=1"
    fi
  else
    log "IMDS hop limit ${hop}: AWS stops a container's token at the bridge hop (container IMDS block: ${block})"
  fi
  case "${probe}" in
    blocked) log "IMDS token from a container: blocked (good: containers cannot use the instance role)" ;;
    reachable) fail "containers can get an IMDSv2 token: a compromised container could read the instance role's secrets" ;;
    error)
      if ((need_block || need)); then fail "the IMDS probe from a container gave no clear answer (the probe lines say what it met: it did not run, was accepted but never answered, got another answer, or had no route)"
      else log "WARNING the IMDS probe from a container gave no clear answer (hop limit ${hop} still stops it)"; fi ;;
    unprobed)
      if ((need)); then fail "the IMDS probe from a container needs ${PROBE_IMAGE} (the infrastructure images), which is not loaded"
      else log "IMDS from a container: not probed yet (needs ${PROBE_IMAGE}); a deploy probes it after loading the infrastructure images, before anything starts"; fi ;;
  esac
  return "${bad}"
}

imds_checks() { # [require-probe]: the host answers IMDSv2; then imds_verdict on this instance's state
  local tok bad=0 hop=${CHOLA_IMDS_HOP:-} v6=${CHOLA_IMDS_IPV6:-disabled} r4=no r6=no unit=no p4 p6=blocked
  docker_setup
  tok="$(curl -s -m 3 --noproxy '*' -o /dev/null -w '%{http_code}' -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    http://169.254.169.254/latest/api/token || true)"
  if [[ "${tok}" == 200 ]]; then log "IMDSv2 answers on the host (the AWS CLI here uses the instance role)"; else
    log "FAIL IMDSv2 does not answer on the host (HTTP ${tok:-none}): the instance role is unusable here"; bad=1; fi
  imds_rule 4 && r4=yes
  if [[ "${v6}" == enabled ]]; then imds_rule 6 && r6=yes; fi
  if sudo -n systemctl is-enabled --quiet "${IMDS_UNIT}" 2>/dev/null && sudo -n test -x "${IMDS_SCRIPT}" &&
    sudo -n test -f "${IMDS_DROPIN}"; then unit=yes; fi
  p4="$(imds_probe 4)"
  if [[ "${v6}" == enabled ]]; then p6="$(imds_probe 6)"; fi
  imds_verdict "${hop}" "${v6}" "${r4}" "${r6}" "${unit}" "${p4}" "${p6}" "${1:-0}" "${CHOLA_ALLOW_IMDS:-0}" || bad=1
  return "${bad}"
}

cmd_imds_check() {
  imds_checks 1 || die "the IMDS checks failed (above); nothing was started"
  log "IMDS checks OK"
}

cmd_imds_block() { # install the block from this run's kit copy (host/): script, unit, Docker drop-in, the IPv6 setting
  local src="${SCRIPT_DIR}/host" v6=${CHOLA_IMDS_IPV6:-disabled} f
  [[ "${v6}" =~ ^(enabled|disabled)$ ]] || die "CHOLA_IMDS_IPV6 must be enabled or disabled, not '${v6}'"
  for f in devsec-chola-imds-block devsec-chola-imds-block.service docker-imds-block.conf; do
    [[ -f "${src}/${f}" ]] || die "the kit copy lacks host/${f}"
  done
  sudo -n true 2>/dev/null || die "the IMDS block needs passwordless sudo for $(id -un)"
  sudo -n install -D -m 0755 -o root -g root "${src}/devsec-chola-imds-block" "${IMDS_SCRIPT}"
  sudo -n install -D -m 0644 -o root -g root "${src}/devsec-chola-imds-block.service" "/etc/systemd/system/${IMDS_UNIT}"
  sudo -n install -D -m 0644 -o root -g root "${src}/docker-imds-block.conf" "${IMDS_DROPIN}"
  printf 'IPV6=%s\n' "${v6}" | sudo -n tee "${IMDS_CONF}.new" >/dev/null
  sudo -n chmod 0644 "${IMDS_CONF}.new"
  sudo -n mv "${IMDS_CONF}.new" "${IMDS_CONF}"
  # daemon-reload only reads the files: Docker itself is NOT restarted (its drop-in applies from its next start)
  sudo -n systemctl daemon-reload
  sudo -n systemctl enable --quiet "${IMDS_UNIT}"
  sudo -n systemctl restart "${IMDS_UNIT}" # runs the script now (oneshot): the rule is in place from here on
  imds_rule 4 || die "the IMDS block ran but the IPv4 rule is not in DOCKER-USER (journalctl -u ${IMDS_UNIT})"
  if [[ "${v6}" == enabled ]]; then
    imds_rule 6 || die "the IMDS block ran but the IPv6 rule is not in DOCKER-USER (journalctl -u ${IMDS_UNIT})"
  fi
  local dst=169.254.169.254
  if [[ "${v6}" == enabled ]]; then dst+=" and fd00:ec2::254"; fi
  log "container IMDS block installed: ${IMDS_UNIT} enabled (after and with docker.service), Docker ExecStartPre" \
    "drop-in, DROP to ${dst} in DOCKER-USER"
}

infra_missing() {
  local i
  for i in "${INFRA_IMAGES[@]}"; do d image inspect "${i}" >/dev/null 2>&1 || printf '%s\n' "${i}"; done
}

volume_state() { # the data volumes that exist (none: none); dies when Docker cannot be asked
  local names v out=""
  names="$(d volume ls --format '{{.Name}}')" || die "docker volume ls failed"
  for v in "${DATA_VOLUMES[@]}"; do
    if grep -qxF -- "${v}" <<<"${names}"; then out+="${out:+ }${v}"; fi
  done
  printf '%s\n' "${out:-none}"
}

cmd_volume_exists() { # yes / no, exit 0; anything else is an error
  docker_setup
  local s
  s="$(volume_state)"
  if [[ "${s}" == none ]]; then echo no; else echo yes; fi
}

# ------------------------------------------------------------------------------------------------ install / infra
# Old generations are renamed to <target>.old.<time>, never deleted here: a running container bind-mounts the overlay
# directory, and deleting its files would empty /aibom/config under it (a rename keeps its view intact). They are
# pruned once `compose up` has recreated every container whose files changed (prune_old_dirs): they stay until the
# next successful deploy or rollback, however long that takes. The env files are removed from a replaced kit
# generation at once (scrub_old_kits): Compose reads env files when it creates a container, no container mounts them,
# so the only copies of the secrets on disk are the live ones.
swap_dir() { # <new dir> <target>: put <new dir> in place of <target> by rename (no mix of old and new files)
  local new=$1 target=$2
  if [[ -e "${target}" ]]; then mv "${target}" "${target}.old.$(date -u +%Y%m%dT%H%M%S%N)"; fi
  mv "${new}" "${target}"
}
prune_old_dirs() { # after a successful up: no container uses an old generation any more
  find "${BASE_DIR}/deploy" "${BASE_DIR}/compose" -mindepth 1 -maxdepth 1 -type d -name '*.old.*' -exec rm -rf {} + 2>/dev/null || true
}
scrub_old_kits() { # the env files (secrets) of replaced kit generations; the generations themselves stay (above)
  [[ -d "${BASE_DIR}/deploy" ]] || return 0
  find "${BASE_DIR}/deploy" -mindepth 2 -maxdepth 2 -path "${BASE_DIR}/deploy/chola-prod.old.*/*" -type f \
    \( -name '*.env' -o -name .env \) -delete 2>/dev/null || true
}
# Under the lock: a .stage.* or .restore.* directory belongs to a run that was killed (a finished run removes its own);
# a .stage.* one holds copies of the env files. Every changing command sweeps them (and scrubs old kits) first.
sweep_stale() {
  find "${BASE_DIR}" -mindepth 1 -maxdepth 1 -type d \( -name '.stage.*' -o -name '.restore.*' \) -exec rm -rf {} + 2>/dev/null || true
  scrub_old_kits
}

# <kit dir> <overlay dir or empty>: the live kit becomes these files (the live env files are kept, mode 600), the
# live aibom overlay that directory; each by a rename, so an old file never lingers next to new ones.
put_live() {
  local src=$1 overlay=${2:-} stage f
  stage="$(mktemp -d "${BASE_DIR}/.stage.XXXXXX")"
  mkdir -p "${stage}/kit"
  tar -C "${src}" --exclude='*.env' --exclude=.env --exclude=__pycache__ -cf - . | tar -C "${stage}/kit" -xf -
  for f in "${ENV_FILES[@]}"; do
    if [[ -f "${KIT_DIR}/${f}" ]]; then cp -p "${KIT_DIR}/${f}" "${stage}/kit/${f}"; fi
  done
  chmod 700 "${stage}/kit"
  mkdir -p "$(dirname "${KIT_DIR}")" "${BASE_DIR}/compose" "${NODE_ARTIFACTS_DIR}"
  swap_dir "${stage}/kit" "${KIT_DIR}"
  scrub_old_kits
  # an identical overlay is left in place: its readers are not recreated (same files-hash), so it must stay theirs
  if [[ -n "${overlay}" ]] && ! diff -rq "${overlay}" "${BASE_DIR}/compose/aibom-config-overlay" >/dev/null 2>&1; then
    cp -R "${overlay}" "${stage}/overlay"
    swap_dir "${stage}/overlay" "${BASE_DIR}/compose/aibom-config-overlay"
  fi
  rm -rf "${stage}"
}

cmd_install() { # this run's kit (and the commit's aibom overlay uploaded with it) becomes the live kit; env files,
  # volumes and state stay. A deploy does it once its checks have passed (deploy files are recorded per tag).
  [[ "${SCRIPT_DIR}" != "${KIT_DIR}" ]] || { log "already running from the live kit"; return 0; }
  local overlay="${SCRIPT_DIR}/../../compose/aibom-config-overlay"
  if [[ ! -d "${overlay}" ]]; then
    [[ -d "${BASE_DIR}/compose/aibom-config-overlay" ]] ||
      die "no compose/aibom-config-overlay in this kit copy nor live (chola-prod.sh deploy uploads it)"
    overlay=""
  fi
  put_live "${SCRIPT_DIR}" "${overlay}"
  log "kit installed in ${KIT_DIR}"
}

cmd_infra_load() {
  local key=${1:?usage: remote.sh infra-load <s3 key> <sha256>} want=${2:?sha256} file got
  [[ "${key}" =~ ^[A-Za-z0-9._/-]+$ ]] || die "not an S3 key: ${key}"
  [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "not a sha256: ${want}"
  sudo -n mkdir -p "${ARCHIVE_DIR}"
  sudo -n chown "$(id -u):$(id -g)" "${ARCHIVE_DIR}"
  chmod 700 "${ARCHIVE_DIR}"
  file="${ARCHIVE_DIR}/release.tar"
  rm -f "${file}"
  EXIT_RM=("${file}") # removed by on_exit however this ends
  log "downloading s3://${BUCKET}/${key} (bucket owner ${ACCOUNT}) to ${file} (data volume)"
  aws s3api get-object --region "${REGION}" --bucket "${BUCKET}" --key "${key}" --expected-bucket-owner "${ACCOUNT}" \
    "${file}" >/dev/null
  got="$(sha256sum "${file}" | cut -d' ' -f1)"
  [[ "${got}" == "${want}" ]] || die "release archive sha256 ${got} is not ${want} (damaged or replaced)"
  log "sha256 ok; docker load"
  load_release_file "${file}"
}

load_release_file() { # <docker save archive, plain or compressed>: load, delete, check every pinned image is there
  local missing arch i
  d load -i "$1"
  rm -f "$1"
  EXIT_RM=()
  missing="$(infra_missing | paste -sd' ' -)"
  [[ -z "${missing}" ]] || die "still missing after the load: ${missing}"
  for i in "${INFRA_IMAGES[@]}"; do
    arch="$(d image inspect -f '{{.Os}}/{{.Architecture}}' "${i}")"
    [[ "${arch}" == linux/amd64 ]] || die "${i} is ${arch}, not linux/amd64"
  done
  log "infrastructure images loaded (linux/amd64): ${INFRA_IMAGES[*]}; archive deleted"
}

node_artifacts_missing() { # <version>: "missing" when manifest.json or any of the 4 files for <version> is absent
  local ver=${1:?usage: remote.sh node-artifacts-missing <version>} f
  [[ "${ver}" =~ ^[0-9][0-9A-Za-z.-]{0,18}$ ]] || die "invalid scan-node version: ${ver}"
  if [[ ! -f "${NODE_ARTIFACTS_DIR}/manifest.json" ]] ||
    ! grep -q "\"version\": \"${ver}\"" "${NODE_ARTIFACTS_DIR}/manifest.json" 2>/dev/null; then
    printf 'missing\n'
    return 0
  fi
  for f in "scan-node-${ver}.tar.gz" "cbom-scan-node-${ver}.tgz" \
    "cbom-scan-node-ova-kit-${ver}.zip" "cbom-scan-node-ami-kit-${ver}.zip"; do
    if [[ ! -s "${NODE_ARTIFACTS_DIR}/${f}" ]]; then
      printf 'missing\n'
      return 0
    fi
  done
}

cmd_node_artifacts_load() { # <s3 key> <sha256> <version>
  local key=${1:?usage: remote.sh node-artifacts-load <s3 key> <sha256> <version>} want=${2:?sha256} ver=${3:?version}
  local file got stage
  [[ "${key}" =~ ^releases/[A-Za-z0-9._-]+$ ]] || die "not a releases/ S3 key: ${key}"
  [[ "${want}" =~ ^[0-9a-f]{64}$ ]] || die "not a sha256: ${want}"
  [[ "${ver}" =~ ^[0-9][0-9A-Za-z.-]{0,18}$ ]] || die "invalid scan-node version: ${ver}"
  sudo -n mkdir -p "${ARCHIVE_DIR}"
  sudo -n chown "$(id -u):$(id -g)" "${ARCHIVE_DIR}"
  chmod 700 "${ARCHIVE_DIR}"
  file="${ARCHIVE_DIR}/node-artifacts.tar.gz"
  rm -f "${file}"
  EXIT_RM=("${file}")
  log "downloading s3://${BUCKET}/${key} (bucket owner ${ACCOUNT}) to ${file}"
  aws s3api get-object --region "${REGION}" --bucket "${BUCKET}" --key "${key}" --expected-bucket-owner "${ACCOUNT}" \
    "${file}" >/dev/null
  got="$(sha256sum "${file}" | cut -d' ' -f1)"
  [[ "${got}" == "${want}" ]] || die "node-artifacts archive sha256 ${got} is not ${want}"
  mkdir -p "${BASE_DIR}"
  stage="$(mktemp -d "${BASE_DIR}/.stage.XXXXXX")"
  tar -C "${stage}" -xzf "${file}"
  rm -f "${file}"
  EXIT_RM=()
  (cd "${stage}" && sha256sum -c ./*.sha256 >/dev/null) || { rm -rf "${stage}"; die "scan-node download checksum mismatch"; }
  chmod 755 "${stage}"
  chmod 644 "${stage}"/*
  swap_dir "${stage}" "${NODE_ARTIFACTS_DIR}"
  find "${BASE_DIR}" -mindepth 1 -maxdepth 1 -type d -name 'node-artifacts.old.*' -exec rm -rf {} + 2>/dev/null || true
  log "scan-node downloads ${ver} installed in ${NODE_ARTIFACTS_DIR}"
}

# ------------------------------------------------------------------------------------------------ S3 relay (--from-run)
# chola-prod.sh streamed each artifact zip of a chola-prod-images.yml run into s3://BUCKET/releases/<sha12>/ (sha256
# computed in the same stream). Here, one at a time on the data volume: download, sha256, extract (artifacts.py
# unzip-stream: only OCI layout names), check (artifacts.py oci-check: the manifest's digest, every blob, linux/amd64,
# the revision label = the commit), name it ${IMAGE_PREFIX}/<repo>:<sha12>, load it into Docker, check what Docker has
# (linux/amd64, the label, its id = the config or manifest digest), delete the zip and the files. The release archive
# likewise. Nothing is pulled from ECR.
relay_repo() { case "$1" in backend | frontend) printf 'devsecshield-%s\n' "$1" ;; scan-worker | dast-worker) printf '%s\n' "$1" ;; *) return 1 ;; esac; }

relay_fetch() { # <s3 key> <sha256> <file>
  rm -f "$3"
  log "downloading s3://${BUCKET}/$1 (bucket owner ${ACCOUNT})"
  aws s3api get-object --region "${REGION}" --bucket "${BUCKET}" --key "$1" --expected-bucket-owner "${ACCOUNT}" \
    "$3" >/dev/null || die "cannot download s3://${BUCKET}/$1"
  local got
  got="$(sha256sum "$3" | cut -d' ' -f1)"
  [[ "${got}" == "$2" ]] || die "s3://${BUCKET}/$1 has sha256 ${got}, not $2 (damaged or replaced)"
}

oci_load() { # <layout dir> <ref>: Docker 25+ loads an OCI layout archive (its index.json names the image); otherwise
  # skopeo, when the instance has it
  local major
  major="$(d version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)"
  if [[ "${major}" =~ ^[0-9]+$ ]] && ((major >= 25)); then
    # index.json (containerd image store) and manifest.json (graphdriver store) both name it
    tar -C "$1" -cf - oci-layout index.json manifest.json blobs | d load >/dev/null || die "docker load of $2 failed"
  elif command -v skopeo >/dev/null 2>&1; then
    "${SUDO[@]}" skopeo copy --quiet "oci:$1" "docker-daemon:$2" || die "skopeo copy of $2 failed"
  else
    die "Docker ${major:-?} cannot load an OCI layout (25+ can) and skopeo is not installed"
  fi
}

cmd_relay_load() { # <sha40> image:<component>:<key>:<zip sha256>:sha256:<hex> ... infra:<key>:<zip sha256>:<file sha256>
  local sha=${1:?usage: remote.sh relay-load <sha40> <spec>...} tag spec kind c key zsum alg hex repo ref dir out
  local config want got labels
  shift
  [[ "${sha}" =~ ^[0-9a-f]{40}$ ]] || die "not a 40-character commit: ${sha}"
  (($#)) || die "nothing to load"
  tag=${sha:0:12}
  for spec in "$@"; do # every spec checked before anything is downloaded
    case "${spec}" in
      image:*) [[ "${spec}" =~ ^image:(backend|frontend|scan-worker|dast-worker):releases/${tag}/[A-Za-z0-9._-]+\.zip:[0-9a-f]{64}:sha256:[0-9a-f]{64}$ ]] || die "bad spec: ${spec}" ;;
      infra:*) [[ "${spec}" =~ ^infra:releases/${tag}/[A-Za-z0-9._-]+\.zip:[0-9a-f]{64}:[0-9a-f]{64}$ ]] || die "bad spec: ${spec}" ;;
      *) die "bad spec: ${spec}" ;;
    esac
  done
  docker_setup
  disk_check || die "not enough disk for the relay (above)"
  sudo -n mkdir -p "${ARCHIVE_DIR}"
  sudo -n chown "$(id -u):$(id -g)" "${ARCHIVE_DIR}"
  chmod 700 "${ARCHIVE_DIR}"
  for spec in "$@"; do
    kind=${spec%%:*}
    if [[ "${kind}" == image ]]; then
      IFS=: read -r _ c key zsum alg hex <<<"${spec}"
      repo="$(relay_repo "${c}")"
      ref="$(image_of "${repo}" "${tag}")"
      dir="${ARCHIVE_DIR}/oci-${c}"
      EXIT_RM=("${ARCHIVE_DIR}/relay.zip")
      relay_fetch "${key}" "${zsum}" "${ARCHIVE_DIR}/relay.zip"
      rm -rf "${dir:?}"
      EXIT_RMDIR=${dir} # a layout that failed its check goes too
      python3 -I "${SCRIPT_DIR}/artifacts.py" unzip-stream --dest "${dir}" --oci <"${ARCHIVE_DIR}/relay.zip" >/dev/null ||
        die "the ${c} artifact is not an OCI image layout (above)"
      rm -f "${ARCHIVE_DIR}/relay.zip"
      labels=()
      [[ "${c}" != frontend ]] || labels=(--label "com.zeroshield.devsecshield.api-url=https://${API_HOST}")
      out="$(python3 -I "${SCRIPT_DIR}/artifacts.py" oci-check --layout "${dir}" --digest "${alg}:${hex}" \
        --revision "${sha}" ${labels[@]+"${labels[@]}"})" || die "the ${c} image failed its check (above); not loaded"
      config=${out##* }
      python3 -I "${SCRIPT_DIR}/artifacts.py" oci-name --layout "${dir}" --ref "${ref}"
      oci_load "${dir}" "${ref}"
      rm -rf "${dir:?}"
      EXIT_RMDIR=""
      got="$(d image inspect -f '{{.Os}}/{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}} {{.Id}}' "${ref}" 2>/dev/null)" ||
        die "Docker has no ${ref} after the load"
      want="linux/amd64 ${sha}"
      if [[ "${got% *}" != "${want}" ]]; then
        d image rm -f "${ref}" >/dev/null 2>&1 || true
        die "${ref} in Docker is '${got% *}', not '${want}'; removed again"
      fi
      if [[ "${got##* }" != "${config}" && "${got##* }" != "${alg}:${hex}" ]]; then
        d image rm -f "${ref}" >/dev/null 2>&1 || true
        die "${ref} in Docker is ${got##* }, neither the checked config ${config} nor the manifest ${alg}:${hex}; removed again"
      fi
      # what pull --local accepts later: exactly this id and this revision under this name
      mkdir -p "${STATE_DIR}/relay"
      { grep -v "^${ref} " "${STATE_DIR}/relay/${tag}" 2>/dev/null || true; printf '%s %s %s\n' "${ref}" "${got##* }" "${sha}"; } \
        >"${STATE_DIR}/relay/${tag}.new"
      mv "${STATE_DIR}/relay/${tag}.new" "${STATE_DIR}/relay/${tag}"
      log "${ref} loaded: ${alg}:${hex} (linux/amd64, revision ${tag}); zip and layout deleted"
    else
      IFS=: read -r _ key zsum hex <<<"${spec}"
      EXIT_RM=("${ARCHIVE_DIR}/relay.zip" "${ARCHIVE_DIR}/release.tar.gz")
      relay_fetch "${key}" "${zsum}" "${ARCHIVE_DIR}/relay.zip"
      rm -f "${ARCHIVE_DIR}/release.tar.gz"
      python3 -I "${SCRIPT_DIR}/artifacts.py" unzip-stream --dest "${ARCHIVE_DIR}" --file release.tar.gz \
        <"${ARCHIVE_DIR}/relay.zip" >/dev/null || die "the infrastructure artifact has no release.tar.gz (above)"
      rm -f "${ARCHIVE_DIR}/relay.zip"
      got="$(sha256sum "${ARCHIVE_DIR}/release.tar.gz" | cut -d' ' -f1)"
      [[ "${got}" == "${hex}" ]] || die "release.tar.gz has sha256 ${got}, the run's manifest says ${hex}"
      load_release_file "${ARCHIVE_DIR}/release.tar.gz"
    fi
  done
  EXIT_RM=()
  log "relay of ${tag} loaded ($# artifacts); nothing was pulled from ECR"
}

# ------------------------------------------------------------------------------------------------ env, registry, images
cmd_render() { # [<tag>]: the tag is written only when .env has none yet (first deploy); deploy switches it later
  local tag
  tag="$(env_get DSS_TAG)"
  tag="${tag:-${1:-}}"
  command -v python3 >/dev/null || die "python3 is missing"
  command -v aws >/dev/null || die "the AWS CLI is missing (chola-prod.sh host-setup)"
  mkdir -p "${KIT_DIR}"
  chmod 700 "${KIT_DIR}"
  umask 077
  python3 -I "${SCRIPT_DIR}/kit.py" render-env --dir "${KIT_DIR}" --tag "${tag}" --secret-prefix "${SECRET_PREFIX}" \
    --region "${REGION}" --image-prefix "${IMAGE_PREFIX}" --frontend-host "${FRONTEND_HOST}" --api-host "${API_HOST}" \
    --real-ip-from "${REAL_IP_FROM}"
  require_env_files
}

cmd_ecr_login() {
  docker_setup
  aws ecr get-login-password --region "${REGION}" | d login --username AWS --password-stdin "${REGISTRY}" >/dev/null
  log "logged in to ${REGISTRY} (instance role)"
}

frontend_url_ok() { # <image>: the browser bundle carries https://API_HOST (read out of the image; nothing runs)
  local cid hit
  cid="$(d create "$1")" || die "docker create $1 failed"
  # grep -c reads the whole stream (grep -q would stop early and docker cp die of SIGPIPE under pipefail)
  hit="$(d cp "${cid}:/frontend/.next/static" - 2>/dev/null | grep -acF "https://${API_HOST}" || true)"
  d rm -f "${cid}" >/dev/null 2>&1 || true
  [[ "${hit:-0}" =~ ^[1-9] ]] || die "$1 was built for another API URL (no https://${API_HOST} in its bundle); not starting it"
}

relayed_ok() { # <ref> <tag>: the image under ref is the one relay-load checked (same id, revision label = the commit)
  local rec got
  rec="$({ awk -v r="$1" '$1 == r { print $2, $3 }' "${STATE_DIR}/relay/$2" 2>/dev/null || true; } | tail -n 1)"
  [[ -n "${rec}" ]] || die "$1 was not loaded by the S3 relay on this instance (nothing is pulled from ECR in that mode)"
  got="$(d image inspect -f '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null)" ||
    die "$1 is not on the instance (the relay loads it; nothing is pulled from ECR in that mode)"
  [[ "${got}" == "${rec}" ]] || die "$1 is '${got}' in Docker, the relay checked '${rec}': not accepted"
  log "$1: the relayed image (${rec%% *})"
}

cmd_pull() { # <tag> [--local]: --local (the S3 relay loaded them) never pulls, it only checks
  local tag=${1:?usage: remote.sh pull <tag> [--local]} local_only=0 r ref arch
  [[ "${2:-}" != --local ]] || local_only=1
  [[ "${tag}" =~ ^[0-9a-f]{12}$ ]] || die "tag ${tag} is not a 12-character commit"
  docker_setup
  disk_check || die "not enough disk to pull (above)"
  for r in "${APP_REPOS[@]}"; do
    ref="$(image_of "${r}" "${tag}")"
    if ((local_only)); then
      relayed_ok "${ref}" "${tag}"
    elif d image inspect "${ref}" >/dev/null 2>&1; then
      log "${ref} already here"
    else
      ((!local_only)) || die "${ref} is not on the instance (the relay loads it; nothing is pulled from ECR in that mode)"
      log "pulling ${ref}"
      d pull -q --platform linux/amd64 "${ref}" >/dev/null || die "pull of ${ref} failed (ecr-login? pushed?)"
    fi
    arch="$(d image inspect -f '{{.Os}}/{{.Architecture}}' "${ref}")"
    [[ "${arch}" == linux/amd64 ]] || die "${ref} is ${arch}, not linux/amd64"
  done
  frontend_url_ok "$(image_of devsecshield-frontend "${tag}")"
  log "images of ${tag} present (linux/amd64); the frontend carries https://${API_HOST}"
}

# ------------------------------------------------------------------------------------------------ logical dumps
# No password on any command line (ps shows them): pg_dump uses the container's local socket (trust for local
# connections in the official image); mongodump reads its password from a 0600 --config file written by the shell's
# printf builtin inside the container and removed right after.
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
    compose exec -T mongo sh -c 'umask 077; f=$(mktemp); printf "password: \"%s\"\n" "$MONGO_INITDB_ROOT_PASSWORD" >"$f"; mongodump --quiet --archive --gzip --config "$f" -u "$MONGO_INITDB_ROOT_USERNAME" --authenticationDatabase admin; rc=$?; rm -f "$f"; exit $rc' \
      >"${DUMP_DIR}/mongo-${ts}.archive.gz.part"
    mv "${DUMP_DIR}/mongo-${ts}.archive.gz.part" "${DUMP_DIR}/mongo-${ts}.archive.gz"
  fi
  for f in pg mongo; do
    find "${DUMP_DIR}" -maxdepth 1 -name "${f}-*" ! -name '*.part' -printf '%T@ %p\n' | sort -rn | awk -v k="${keep}" 'NR > k { print $2 }' |
      while IFS= read -r old; do rm -f -- "${old}"; log "removed old dump ${old}"; done
  done
  log "dumps: $(find "${DUMP_DIR}" -maxdepth 1 -type f ! -name '*.part' -name "*${ts}*" -printf '%f (%s bytes) ')"
}

# ------------------------------------------------------------------------------------------------ alembic helpers
alembic_offline() { # <image> <alembic args...>: commands that read only the migration scripts
  local image=$1
  shift
  d run --rm --network none --entrypoint /backend/.venv/bin/python "${image}" -m alembic --config "${ALEMBIC_INI}" "$@"
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
# The tag that was running when <tag> was deployed: from its deploy line, or from its STARTED line when the deploy was
# interrupted (tunnel dropped, Ctrl-C, instance reboot) before it recorded an outcome.
previous_of() { # the last real (not "none") previous tag recorded for <tag>
  [[ -f "${HISTORY_FILE}" ]] || return 0
  awk -v t="$1" '($2 == "deploy" || $2 == "started" || $2 == "switched") && $3 == t && $4 == "previous" && $5 != "none" && $5 != t { p = $5 }
    END { print p }' "${HISTORY_FILE}"
}
# The rollback target to record when <tag> is deployed while <running> runs (empty: nothing runs, e.g. after a failed
# recovery removed the application containers): the running tag; else, when an unfinished rollback (ROLLBACK-STARTED
# or a FAILED rollback line last) was heading to DSS_TAG, that release (the operator was moving TO it, away from the
# one before); else what <tag> replaced before; else the last release that passed its checks.
target_for() { # <tag> <running>
  local tag=$1 p=${2:-} t
  if [[ -z "${p}" ]]; then
    t="$(unfinished_rollback_target)"
    if [[ -n "${t}" && "${t}" == "$(env_get DSS_TAG)" && "${t}" != "${tag}" ]]; then p=${t}; fi
  fi
  if [[ -z "${p}" || "${p}" == "${tag}" ]]; then p="$(previous_of "${tag}")"; fi
  if [[ -z "${p}" ]]; then p="$(last_passed "${tag}")"; fi
  printf '%s\n' "${p}"
}
last_passed() { [[ -s "${PASSED_FILE}" ]] || return 0; awk -v x="${1:-}" 'NF && $1 != x { t = $1 } END { print t }' "${PASSED_FILE}"; }
record_files() { # <tag>: the deploy files this tag is started with (for a rollback to it)
  mkdir -p "${RELEASES_DIR}/$1"
  tar -C "${BASE_DIR}" "${RELEASE_EXCLUDES[@]}" -czf "${RELEASES_DIR}/$1/files.tar.gz.part" "${RELEASE_FILES[@]}"
  mv "${RELEASES_DIR}/$1/files.tar.gz.part" "${RELEASES_DIR}/$1/files.tar.gz"
}
restore_files() { # <tag>: its recorded deploy files become the live ones (env files kept), each directory by a rename
  local tmp
  tmp="$(mktemp -d "${BASE_DIR}/.restore.XXXXXX")"
  tar -C "${tmp}" -xzf "${RELEASES_DIR}/$1/files.tar.gz"
  put_live "${tmp}/deploy/chola-prod" "$([[ -d "${tmp}/compose/aibom-config-overlay" ]] && echo "${tmp}/compose/aibom-config-overlay")"
  rm -rf "${tmp}"
}
running_tag() { # the tag of the backend container (none before the first deploy, or without a live compose file)
  [[ -f "${COMPOSE_FILE}" ]] || return 0
  { compose ps -a --format '{{.Image}}' backend 2>/dev/null || true; } | sed -n -E 's/.*:([0-9a-f]{12})$/\1/p' | head -n 1
}

interrupted() { # 0 when the last recorded step is a deploy or rollback without an outcome (tunnel loss, kill,
  # reboot): STARTED (it never switched DSS_TAG) or SWITCHED (it did), or ROLLBACK-STARTED (either)
  local kind
  read -r _ kind _ <<<"$(last_step)"
  case "${kind}" in started | switched | rollback-started) return 0 ;; esac
  return 1
}
# The last non-blank history line, trailing whitespace (a hand edit, CRLF) removed.
last_step() {
  [[ -f "${HISTORY_FILE}" ]] || return 0
  awk 'NF { l = $0 } END { sub(/[[:space:]]+$/, "", l); print l }' "${HISTORY_FILE}"
}

clear_app_containers() { # remove the application containers (stateless; datastores and named volumes stay) and the
  # <id>_dss-chola-* containers a killed `compose up` leaves renamed half way through a recreate
  local services c
  services="$(app_services)" || die "docker compose config failed"
  # shellcheck disable=SC2086 # one argument per service
  compose rm -s -f ${services} >/dev/null 2>&1 || true
  while IFS= read -r c; do
    [[ -n "${c}" ]] || continue
    d rm -f "${c}" >/dev/null 2>&1 && log "removed the leftover container ${c}"
  done < <(d ps -a --filter "label=com.docker.compose.project=${PROJECT}" --format '{{.Names}}' | grep -E "^[0-9a-f]{12}_${PROJECT}-" || true)
}

up() { # [recover]: after an interrupted run (or for a rollback), start the application containers from scratch and try
  # once more on failure: a killed `compose up` leaves containers stopped, renamed or only created, and the daemon may
  # still be finishing that run's stops when the next one starts
  local rc=0 recover=${1:-} tries=1
  local -a extra=()
  if [[ "${recover}" == recover ]]; then
    tries=2
    log "recovering: removing the application containers (data stays) before starting them"
    clear_app_containers
  fi
  mkdir -p "${NODE_ARTIFACTS_DIR}"
  log "docker compose up${extra[*]:+ ${extra[*]}} (migrate runs first; everything else waits for it)"
  while :; do
    rc=0
    compose up -d --remove-orphans "${extra[@]}" --wait --wait-timeout "${CHOLA_WAIT_S:-900}" || rc=$?
    tries=$((tries - 1))
    if [[ "${rc}" == 0 || "${tries}" == 0 ]]; then break; fi
    log "compose up failed after an interrupted run; waiting 20 s and trying once more"
    sleep 20
    clear_app_containers
  done
  compose ps -a --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' || true
  if [[ "${rc}" != 0 ]]; then
    log "last migrate / backend log lines (more: chola-prod.sh logs --service backend, or on the instance from any"
    log "directory: ${SUDO[*]:+sudo }docker compose -p ${PROJECT} logs backend):"
    compose logs --no-color --tail 40 migrate backend 2>&1 | sed 's/^/    /' || true
  fi
  return "${rc}"
}

retain() { # <tag> <previous> <last passed>: remove this deployment's other application images (never forced)
  local keep=" $1 $2 $3 " ref t
  while IFS= read -r ref; do
    t="${ref##*:}"
    [[ "${keep}" == *" ${t} "* ]] && continue
    if d image rm "${ref}" >/dev/null 2>&1; then log "retention: removed ${ref}"; fi
  done < <(d image ls --format '{{.Repository}}:{{.Tag}}' | grep -E "^${IMAGE_PREFIX//./\\.}/(devsecshield-backend|devsecshield-frontend|scan-worker|dast-worker):[0-9a-f]{12}$" || true)
}

# ------------------------------------------------------------------------------------------------ deploy / rollback
cmd_deploy() {
  local tag=${1:?usage: remote.sh deploy <tag>} running previous head db last r
  [[ "${tag}" =~ ^[0-9a-f]{12}$ ]] || die "tag ${tag} is not a 12-character commit"
  docker_setup
  require_env_files
  mkdir -p "${STATE_DIR}"
  # first deploy: there is no live kit yet, and the checks below need its compose file
  [[ -f "${COMPOSE_FILE}" ]] || cmd_install
  for r in "${APP_REPOS[@]}"; do
    d image inspect "$(image_of "${r}" "${tag}")" >/dev/null 2>&1 || die "$(image_of "${r}" "${tag}") is not pulled"
  done
  frontend_url_ok "$(image_of devsecshield-frontend "${tag}")"
  local missing
  missing="$(infra_missing | paste -sd' ' -)"
  [[ -z "${missing}" ]] || die "infrastructure images missing: ${missing} (chola-prod.sh loads the release archive)"
  running="$(running_tag)"
  previous="$(target_for "${tag}" "${running}")"
  head="$(image_head "${tag}")" || die "cannot read the Alembic head of $(image_of devsecshield-backend "${tag}")"
  [[ -n "${head}" ]] || die "$(image_of devsecshield-backend "${tag}") has no Alembic revisions"
  db="$(db_revision)" || die "cannot read the database's Alembic revision (postgres; output above)"
  # shellcheck disable=SC2086 # one argument per revision
  if [[ -n "${db}" ]] && ! knows_revisions "${tag}" ${db}; then
    die "the database is at ${db}, which ${tag}'s migrations do not contain (a newer release migrated it): ${tag}" \
      "cannot start on it. Nothing was changed. To go back a release: chola-prod.sh rollback"
  fi
  log "deploying ${tag} (running: ${running:-nothing}; database at ${db:-no revision}; ${tag}'s head ${head})"
  cmd_install # this run's kit (compose file, nginx, the commit's aibom overlay) becomes the live kit
  record_files "${tag}"
  printf '%s\n' "${head}" >"${RELEASES_DIR}/${tag}/alembic-head"
  local recover=""
  if interrupted; then recover=recover; log "the last deploy was interrupted: recreating every container"; fi
  # Recorded BEFORE anything switches: an interrupted deploy still names its rollback target and the database revision
  # it started from (rollback reads it).
  printf '%s started %s previous %s alembic-before %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" \
    "${db:-none}" >>"${HISTORY_FILE}"
  set_tag "${tag}"
  printf '%s switched %s previous %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" >>"${HISTORY_FILE}"
  if ! up "${recover}"; then
    printf '%s deploy %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" "${head}" >>"${HISTORY_FILE}"
    die "compose up failed for ${tag}${previous:+; to go back: chola-prod.sh rollback}"
  fi
  printf '%s deploy %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${tag}" "${previous:-none}" "${head}" >>"${HISTORY_FILE}"
  prune_old_dirs
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

ROLLBACK_CURRENT="" ROLLBACK_PREVIOUS="" ROLLBACK_HEAD="" ROLLBACK_DB="" ROLLBACK_DOWNGRADE=0
# <current tag> -> "<target> <restart> <why>" for a rollback, from the history only. Never one release further back
# than the operation being retried:
# * deploy-unswitched: a deploy interrupted between its STARTED record and the tag switch changed nothing (DSS_TAG
#   still names the release that ran before it): that release itself, started again (restart=1);
# * rollback-switched / rollback-failed: a rollback to <current> was interrupted after it switched (ROLLBACK-STARTED
#   is the last line) or its `up` failed (a FAILED rollback line): <current> IS the rollback's target, started again;
# * rollback-retry: a rollback <current> -> T stopped before it switched (ROLLBACK-STARTED, or FAILED in the
#   downgrade): the same rollback to T again;
# * normal: the tag that was running before <current> was deployed (previous_of).
# History lines (field 2 on): started X previous P alembic-before D | switched X previous P |
# deploy X previous P alembic H [FAILED] | rollback-started T from F alembic-before D | rollback T previous F alembic H [FAILED]
# The last record, parsed in ONE place (the grammar above): LAST_KIND (field 2), LAST_A (field 3: the tag), LAST_B
# (field 5: its previous / from tag), LAST_FAILED (1 when the line ends with FAILED; an Alembic head may be several words).
LAST_KIND="" LAST_A="" LAST_B="" LAST_FAILED=0
read_last_step() {
  local line
  line="$(last_step)"
  LAST_KIND="" LAST_A="" LAST_B="" LAST_FAILED=0
  read -r _ LAST_KIND LAST_A _ LAST_B _ <<<"${line}" || true
  if [[ "${line##* }" == FAILED ]]; then LAST_FAILED=1; fi
}
unfinished_rollback_target() { # the target of the last record when that is an unfinished rollback (ROLLBACK-STARTED, or
  # a FAILED rollback line); else nothing
  read_last_step
  if [[ "${LAST_KIND}" == rollback-started || ("${LAST_KIND}" == rollback && "${LAST_FAILED}" == 1) ]]; then
    printf '%s\n' "${LAST_A}"
  fi
}
rollback_pair() {
  local current=$1 p
  read_last_step
  case "${LAST_KIND}" in
    started)
      if [[ "${LAST_B}" == "${current}" ]]; then printf '%s 1 deploy-unswitched\n' "${current}"; return 0; fi ;;
    rollback-started)
      if [[ "${LAST_A}" == "${current}" ]]; then printf '%s 1 rollback-switched\n' "${current}"; return 0; fi
      if [[ "${LAST_B}" == "${current}" ]]; then printf '%s 0 rollback-retry\n' "${LAST_A}"; return 0; fi ;;
    rollback)
      if ((LAST_FAILED)) && [[ "${LAST_A}" == "${current}" ]]; then printf '%s 1 rollback-failed\n' "${current}"; return 0; fi
      if ((LAST_FAILED)) && [[ "${LAST_B}" == "${current}" ]]; then printf '%s 0 rollback-retry\n' "${LAST_A}"; return 0; fi ;;
  esac
  p="$(previous_of "${current}")"
  printf '%s 0 normal\n' "${p:-none}" # never an empty first word: read would shift "0" into it
}

ROLLBACK_WHY=normal ROLLBACK_TO=""
passed_release() { # <tag>: 0 when <tag> was deployed (history) and passed its checks at least once (state/passed)
  [[ -s "${PASSED_FILE}" && -f "${HISTORY_FILE}" ]] || return 1
  grep -qxF -- "$1" "${PASSED_FILE}" && awk -v t="$1" '$2 == "deploy" && $3 == t { f = 1 } END { exit !f }' "${HISTORY_FILE}"
}
# <tag>: the line number of its first STARTED or deploy record in the history (0: never deployed). STARTED counts:
# every deploy writes it first, and a deploy interrupted after its switch has no deploy line (yet D is the newest).
first_deployed() {
  if [[ ! -f "${HISTORY_FILE}" ]]; then echo 0; return 0; fi
  awk -v t="$1" '($2 == "started" || $2 == "deploy") && $3 == t { print NR; f = 1; exit } END { if (!f) print 0 }' \
    "${HISTORY_FILE}"
}
# <a> <b>: 0 when release <a> was first deployed after <b> (newer), or <b> was never deployed (unknown: not "older").
# The order of first deploys is the order the releases came in; a later redeploy of an old commit does not make it new.
newer_release() {
  local a b
  a="$(first_deployed "$1")"
  b="$(first_deployed "$2")"
  ((a > b || (b == 0 && a > 0)))
}
to_candidates() { # <current>: the releases `rollback --to` accepts (deployed, passed, not newer than <current>), newest
  # pass first
  local t out=""
  [[ -s "${PASSED_FILE}" ]] || { echo none; return 0; }
  while IFS= read -r t; do
    [[ "${t}" =~ ^[0-9a-f]{12}$ ]] || continue
    if passed_release "${t}" && ! newer_release "${t}" "$1"; then out+="${out:+ }${t}"; fi
  done < <(awk 'NF { seen[$1] = NR } END { for (t in seen) print seen[t], t }' "${PASSED_FILE}" | sort -rn | awk '{ print $2 }')
  printf '%s\n' "${out:-none}"
}
rollback_plan() {
  local r
  ROLLBACK_CURRENT="$(env_get DSS_TAG)"
  if [[ -n "${ROLLBACK_TO}" ]]; then
    # The escape from a rollback target that cannot start (every retry restarts it): an explicit release, only one
    # that was deployed and passed its checks before. The same downgrade plan and confirmation apply.
    [[ "${ROLLBACK_TO}" =~ ^[0-9a-f]{12}$ ]] || die "--to ${ROLLBACK_TO} is not a 12-character commit"
    passed_release "${ROLLBACK_TO}" || die "--to ${ROLLBACK_TO}: not a release that was deployed and passed its" \
      "checks here (${HISTORY_FILE}, ${PASSED_FILE}; 'chola-prod.sh status' lists the accepted ones); nothing was changed"
    # Only back: forward is `deploy`, which also runs the estate backfill, agility heal and image retention.
    if newer_release "${ROLLBACK_TO}" "${ROLLBACK_CURRENT}"; then
      die "--to ${ROLLBACK_TO} is newer than ${ROLLBACK_CURRENT} (first deployed after it): rollback only goes back." \
        "Go forward with: chola-prod.sh deploy --sha ${ROLLBACK_TO}. Nothing was changed"
    fi
    ROLLBACK_PREVIOUS=${ROLLBACK_TO} ROLLBACK_WHY=explicit
    log "rollback to ${ROLLBACK_TO} as asked (--to), not to the target the history names"
  else
    read -r ROLLBACK_PREVIOUS _ ROLLBACK_WHY <<<"$(rollback_pair "${ROLLBACK_CURRENT}")"
  fi
  case "${ROLLBACK_WHY}" in
    deploy-unswitched)
      log "the last deploy was interrupted before it switched: ${ROLLBACK_CURRENT} is still the deployed release; starting it again" ;;
    rollback-switched | rollback-failed)
      log "the last rollback (to ${ROLLBACK_CURRENT}) switched the tag and then failed or was interrupted: retrying it," \
        "i.e. starting ${ROLLBACK_CURRENT} again (NOT going back to the release before it; for that, run rollback again" \
        "once ${ROLLBACK_CURRENT} runs, or, if it can never start, rollback --to <an older release that passed>)" ;;
    rollback-retry)
      log "the last rollback ${ROLLBACK_CURRENT} -> ${ROLLBACK_PREVIOUS} stopped before it switched: running the same rollback again" ;;
  esac
  [[ -n "${ROLLBACK_PREVIOUS}" && "${ROLLBACK_PREVIOUS}" != none ]] ||
    die "no previous tag recorded for ${ROLLBACK_CURRENT} in ${HISTORY_FILE}"
  local -a absent=()
  local pulled=0
  for r in "${APP_REPOS[@]}"; do
    d image inspect "$(image_of "${r}" "${ROLLBACK_PREVIOUS}")" >/dev/null 2>&1 && continue
    # not here (retention removed it, or it was relayed): only ECR can still have it
    pulled=1
    d pull -q --platform linux/amd64 "$(image_of "${r}" "${ROLLBACK_PREVIOUS}")" >/dev/null 2>&1 || absent+=("${r}")
  done
  if ((${#absent[@]})); then
    die "the images of ${ROLLBACK_PREVIOUS} (${absent[*]}) are neither on the instance nor in ECR: relay that commit" \
      "again first (chola-prod.sh images --sha ${ROLLBACK_PREVIOUS} --from-run <run>), or rollback --to another" \
      "release; nothing was changed"
  fi
  if ((pulled)); then cmd_pull "${ROLLBACK_PREVIOUS}"; fi # what came from ECR: linux/amd64 and the frontend URL checked
  ROLLBACK_HEAD="$(tag_head "${ROLLBACK_PREVIOUS}")" || die "cannot read the Alembic head of ${ROLLBACK_PREVIOUS}"
  [[ -n "${ROLLBACK_HEAD}" ]] || die "no Alembic head known for ${ROLLBACK_PREVIOUS}"
  ROLLBACK_DB="$(db_revision)" || die "cannot read the database's Alembic revision"
  ROLLBACK_DOWNGRADE=0
  # shellcheck disable=SC2086
  if [[ -n "${ROLLBACK_DB}" ]] && ! knows_revisions "${ROLLBACK_PREVIOUS}" ${ROLLBACK_DB}; then ROLLBACK_DOWNGRADE=1; fi
  log "rollback ${ROLLBACK_CURRENT} -> ${ROLLBACK_PREVIOUS}: database at ${ROLLBACK_DB:-no revision}, ${ROLLBACK_PREVIOUS}'s migrations end at ${ROLLBACK_HEAD}"
  if ((ROLLBACK_DOWNGRADE)); then
    [[ "${ROLLBACK_HEAD}" != *" "* && "${ROLLBACK_DB}" != *" "* ]] ||
      die "several Alembic heads (${ROLLBACK_HEAD} / ${ROLLBACK_DB}): downgrade by hand"
    knows_revisions "${ROLLBACK_CURRENT}" "${ROLLBACK_HEAD}" || die "no downgrade path: ${ROLLBACK_CURRENT}'s migrations" \
      "do not contain ${ROLLBACK_HEAD}. Nothing was changed. Restore the pre-deployment backup instead (README 'Restore')."
    printf '[chola-remote] It needs alembic downgrade %s with the image of %s, which DROPS what these migrations added, with their data:\n' \
      "${ROLLBACK_HEAD}" "${ROLLBACK_CURRENT}" >&2
    alembic_offline "$(image_of devsecshield-backend "${ROLLBACK_CURRENT}")" history -r "${ROLLBACK_HEAD}:${ROLLBACK_DB}" >&2 || true
  fi
}

cmd_rollback() {
  local allowed=0 plan=0 services
  while (($#)); do
    case "$1" in
      --allow-downgrade) allowed=1; shift ;;
      --plan) plan=1; shift ;;
      --to) [[ $# -ge 2 ]] || die "--to needs a tag"; ROLLBACK_TO=$2; shift 2 ;;
      *) die "unknown rollback option $1" ;;
    esac
  done
  docker_setup
  require_env_files
  rollback_plan
  if ((plan)); then
    if ((ROLLBACK_DOWNGRADE)); then EXIT_EXPECTED=1; exit 3; fi
    return 0
  fi
  local current=${ROLLBACK_CURRENT} previous=${ROLLBACK_PREVIOUS} head=${ROLLBACK_HEAD}
  if ((ROLLBACK_DOWNGRADE)) && [[ "${allowed}" != 1 ]]; then
    # Detached jobs have no terminal: the confirmation is asked on the owner's machine (rollback --plan exit 3).
    die "the rollback needs that database downgrade; nothing was changed. Re-run with --allow-downgrade"
  fi
  # Recorded BEFORE anything changes (downgrade, deploy files, tag): a retry of a rollback that fails or is killed
  # from here on retries THIS rollback (rollback_pair), never goes one release further back.
  printf '%s rollback-started %s from %s alembic-before %s\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" \
    "${ROLLBACK_DB:-none}" >>"${HISTORY_FILE}"
  if ((ROLLBACK_DOWNGRADE)); then
    services="$(app_services)" || die "docker compose config failed; nothing was changed"
    log "stopping the application services, then alembic downgrade ${head} with ${current}'s image"
    # shellcheck disable=SC2086
    if ! compose stop ${services} || ! compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python migrate \
      -m alembic --config "${ALEMBIC_INI}" downgrade "${head}"; then
      log "the downgrade failed; starting ${current} again"
      printf '%s rollback %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
      up || true
      die "rollback to ${previous} refused: alembic downgrade failed (above); ${current} was restarted"
    fi
  fi
  if [[ -f "${RELEASES_DIR}/${previous}/files.tar.gz" ]]; then
    log "putting back ${previous}'s deploy files"
    restore_files "${previous}"
  fi
  set_tag "${previous}"
  # a rollback recreates every container: it often follows a failed or interrupted run
  if ! up recover; then
    printf '%s rollback %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
    die "compose up failed for ${previous}"
  fi
  prune_old_dirs # up recreated every container: none uses an old generation
  # The outcome is recorded only after the checks: a check that fails (or a job killed during it) leaves the rollback
  # unfinished (FAILED / ROLLBACK-STARTED last), so its retry starts ${previous} again instead of going one release
  # further back. The checks run as their own process: errexit stays on inside them (an `if !` would turn it off).
  if ! bash "${SCRIPT}" check; then
    printf '%s rollback %s previous %s alembic %s FAILED\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
    die "${previous} started but its checks failed (above); a retry ('chola-prod.sh rollback') starts ${previous} again"
  fi
  printf '%s\n' "${previous}" >>"${PASSED_FILE}"
  printf '%s rollback %s previous %s alembic %s\n' "$(date -u +%FT%TZ)" "${previous}" "${current}" "${head}" >>"${HISTORY_FILE}"
  case "${ROLLBACK_WHY}" in
    deploy-unswitched) log "${previous} is running again (the interrupted deploy had not switched to its release)" ;;
    rollback-switched | rollback-failed) log "rolled back to ${previous}: the retried rollback finished" ;;
    *) log "rolled back to ${previous} (users rehashed to Argon2id by ${current} may need a password reset on an older image)" ;;
  esac
}

# ------------------------------------------------------------------------------------------------ detached jobs
DETACHABLE=" deploy rollback dump infra-load relay-load node-artifacts-load "
cmd_job_start() {
  local cmd=${1:?usage: remote.sh job-start <command> [args]} id dir
  [[ "${DETACHABLE}" == *" ${cmd} "* ]] || die "${cmd} cannot run detached"
  mkdir -p "${JOBS_DIR}"
  # refuse now, not inside the job, when another changing command holds the lock
  exec 8>"${STATE_DIR}/.lock"
  flock -n 8 || die "another chola-prod command is running on this instance (${STATE_DIR}/.lock); wait for it"
  exec 8>&-
  id="$(date -u +%Y%m%dT%H%M%SZ)-${cmd}-$$"
  dir="${JOBS_DIR}/${id}"
  mkdir -p "${dir}"
  printf '%s\n' "$*" >"${dir}/cmd"
  : >"${dir}/log"
  # setsid: a new session without a controlling terminal, so neither a dropped tunnel nor Ctrl-C on the owner's
  # machine (SIGHUP / SIGINT) reaches it. The wrapper records itself in pid; the worker (remote.sh <cmd>) records itself
  # in worker and writes rc when it ends (on_exit), so a killed wrapper loses nothing; the wrapper writes rc only when
  # the worker could not (killed with SIGKILL: 137).
  # shellcheck disable=SC2016 # expanded by the detached bash, not here
  CHOLA_JOB_DIR="${dir}" nohup setsid bash -c 'trap "" HUP INT; read -r -a s </proc/$$/stat; echo "$$ ${s[21]}" >"$CHOLA_JOB_DIR/pid"; bash "$0" "$@"; rc=$?; [ -f "$CHOLA_JOB_DIR/rc" ] || { echo $rc >"$CHOLA_JOB_DIR/rc.part" && mv "$CHOLA_JOB_DIR/rc.part" "$CHOLA_JOB_DIR/rc"; }' \
    "${SCRIPT}" "$@" </dev/null >>"${dir}/log" 2>&1 &
  disown || true
  # Return only once the job runs in its own session, ignoring hang-ups: before that, the end of the SSH session could
  # still take it down.
  local i
  for i in $(seq 1 100); do
    [[ -s "${dir}/pid" ]] && break
    sleep 0.1
  done
  [[ -s "${dir}/pid" ]] || die "job ${id} did not start (see ${dir}/log)"
  printf '%s\n' "${id}"
  find "${JOBS_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
}

# <file with "pid start-time">: 0 while that process lives. Its pid AND its start time (field 22 of /proc/<pid>/stat)
# must match: after a reboot the pid may belong to another process. A zombie (state Z, field 3: it has exited and only
# waits to be reaped) is dead. (comm, field 2, is "(bash)": no spaces, so the fields split as numbered.)
proc_alive() {
  local pid start s=()
  read -r pid start <"$1" 2>/dev/null || return 1
  [[ "${pid}" =~ ^[0-9]+$ && -r "/proc/${pid}/stat" ]] || return 1
  read -r -a s <"/proc/${pid}/stat" 2>/dev/null || return 1
  [[ "${s[21]:-}" == "${start}" && "${s[2]:-}" != Z ]]
}
# <job dir>: 0 while the job's wrapper OR its worker lives (the worker keeps going when only the wrapper is killed; it
# then writes rc itself, which every reader checks before liveness).
job_alive() { proc_alive "$1/pid" || proc_alive "$1/worker"; }

EXIT_RM=() EXIT_RMDIR="" JOB_RC_DIR=""
on_exit() { # the one EXIT trap: temporary files; in a detached job, the worker's own exit status (only when this shell
  # ends on purpose: EXIT_EXPECTED, above; never a status read after a signal)
  local rc=$?
  if ((${#EXIT_RM[@]})); then rm -f -- "${EXIT_RM[@]}"; fi
  if [[ -n "${EXIT_RMDIR}" && "${EXIT_RMDIR}" == "${ARCHIVE_DIR}/"* ]]; then rm -rf -- "${EXIT_RMDIR}"; fi
  if [[ -n "${JOB_RC_DIR}" && "${EXIT_EXPECTED}" == 1 && ! -f "${JOB_RC_DIR}/rc" ]]; then
    printf '%s\n' "${rc}" >"${JOB_RC_DIR}/rc.worker" && mv "${JOB_RC_DIR}/rc.worker" "${JOB_RC_DIR}/rc"
  fi
  return 0 # the script's exit status stays ${rc}
}
job_worker() { # run by a job's worker (job-start's wrapper set CHOLA_JOB_DIR): record it, and its exit status at the end
  local s=()
  # SIGTERM (a graceful reboot or stop: systemd TERMs the whole session; `kill <pid>`) is recorded as 143. Bash runs a
  # trap only once the current foreground command ends (`compose up --wait` can take CHOLA_WAIT_S). Every other fatal
  # signal leaves rc to the wrapper (EXIT_EXPECTED stays 0). No trap for HUP, INT or QUIT: they are ignored on entry
  # (the wrapper's `trap ""`, and bash ignores INT and QUIT for a `&` job without job control), so they cannot kill
  # the worker, and bash does not let a script trap a signal that was ignored on entry.
  trap 'EXIT_EXPECTED=1; exit 143' TERM
  [[ "${CHOLA_JOB_DIR}" == "${JOBS_DIR}/"* && -d "${CHOLA_JOB_DIR}" ]] || die "CHOLA_JOB_DIR ${CHOLA_JOB_DIR} is not a job of ${JOBS_DIR}"
  JOB_RC_DIR=${CHOLA_JOB_DIR}
  unset CHOLA_JOB_DIR
  read -r -a s </proc/$$/stat
  printf '%s %s\n' "$$" "${s[21]}" >"${JOB_RC_DIR}/worker"
}

cmd_job_follow() {
  local id=${1:?usage: remote.sh job-follow <id> <offset> [wait-s]} off=${2:-0} wait=${3:-20} dir size waited=0
  [[ "${id}" =~ ^[0-9TZ]+-[a-z-]+-[0-9]+$ ]] || die "not a job id: ${id}"
  [[ "${off}" =~ ^[0-9]+$ && "${wait}" =~ ^[0-9]{1,4}$ ]] || die "offset and wait must be numbers"
  dir="${JOBS_DIR}/${id}"
  [[ -d "${dir}" ]] || die "no job ${id} on this instance"
  while :; do
    size="$(stat -c %s "${dir}/log")"
    if ((size > off)) || [[ -f "${dir}/rc" ]] || ((waited >= wait)) || ! job_alive "${dir}"; then break; fi
    sleep 1
    waited=$((waited + 1))
  done
  size="$(stat -c %s "${dir}/log")"
  if ((size > off)); then tail -c +"$((off + 1))" "${dir}/log" | head -c "$((size - off))"; fi
  if [[ -f "${dir}/rc" && "$(stat -c %s "${dir}/log")" == "${size}" ]]; then
    printf 'chola-job: done %s %s\n' "$(cat "${dir}/rc")" "${size}" >&2
  elif [[ ! -f "${dir}/rc" ]] && ! job_alive "${dir}" && [[ "$(stat -c %s "${dir}/log")" == "${size}" ]]; then
    sleep 1 # the job may have written rc just now
    if [[ -f "${dir}/rc" ]]; then printf 'chola-job: running %s\n' "${size}" >&2; else printf 'chola-job: lost %s\n' "${size}" >&2; fi
  else
    printf 'chola-job: running %s\n' "${size}" >&2
  fi
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
  compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python backend - <"${SCRIPT_DIR}/smtp_check.py" || rc=$?
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
  local target restart why
  read -r target restart why <<<"$(rollback_pair "$(env_get DSS_TAG)")"
  log "deployed tag: $(env_get DSS_TAG none); rollback target: ${target}$( ((restart)) && echo " (started again: ${why})")"
  log "rollback --to accepts (deployed, passed, not newer; newest first): $(to_candidates "$(env_get DSS_TAG)")"
  if [[ -f "${COMPOSE_FILE}" && -f "${ENV_FILE}" ]]; then
    compose ps -a --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}' || true
  fi
  if [[ -f "${HISTORY_FILE}" ]]; then log "deploy history (last 10):"; tail -n 10 "${HISTORY_FILE}" | sed 's/^/    /'; fi
  if [[ -d "${JOBS_DIR}" ]]; then
    log "last jobs (chola-prod.sh attach --job <id>):"
    find "${JOBS_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort | tail -n 5 | while IFS= read -r j; do
      if [[ -f "${JOBS_DIR}/${j}/rc" ]]; then printf '    %s exit %s\n' "${j}" "$(cat "${JOBS_DIR}/${j}/rc")"
      elif job_alive "${JOBS_DIR}/${j}"; then printf '    %s running\n' "${j}"
      else printf '    %s LOST (ended without an exit status: reboot or kill; see its log, then deploy again or roll back)\n' "${j}"; fi
    done
  fi
  log "application images here:"
  d image ls --format '    {{.Repository}}:{{.Tag}} {{.Size}}' | grep -F "${IMAGE_PREFIX}/" || true
  # Free space on / and on Docker's root (the data volume), each only if it exists here. df exits 1 when it cannot read
  # one of its paths (a host without /var/lib/docker, an unreadable Docker root): under pipefail that failed the
  # pipeline inside $(...), and the ERR trap (inherited there by set -E) printed an ERROR line from a working status.
  local root disk p
  local -a paths=()
  root="$(d info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
  for p in / "${root}"; do if [[ -n "${p}" && -e "${p}" ]]; then paths+=("${p}"); fi; done
  disk="$({ df -h --output=target,avail "${paths[@]}" 2>/dev/null || true; } | tail -n +2 | tr -s ' ' | paste -sd',' -)"
  log "disk: ${disk:-unknown}"
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
  sweep_stale
}

usage() { awk 'NR > 1 && /^set -/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${SCRIPT}"; }

main() {
  local cmd=${1:-}
  shift || true
  trap on_exit EXIT
  if [[ -n "${CHOLA_JOB_DIR:-}" ]]; then job_worker; fi
  case "${cmd}" in
    install | infra-load | node-artifacts-load | relay-load | render | pull | dump | deploy | admin | imds-block) lock ;;
    rollback) [[ " $* " == *" --plan "* ]] || lock ;;
  esac
  case "${cmd}" in
    preflight) cmd_preflight ;;
    imds-block) cmd_imds_block ;;
    imds-check) cmd_imds_check ;;
    install) cmd_install ;;
    infra-missing) docker_setup; infra_missing ;;
    infra-load) docker_setup; cmd_infra_load "$@" ;;
    node-artifacts-missing) node_artifacts_missing "$@" ;;
    node-artifacts-load) cmd_node_artifacts_load "$@" ;;
    relay-load) cmd_relay_load "$@" ;;
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
    job-start) cmd_job_start "$@" ;;
    job-follow) cmd_job_follow "$@" ;;
    -h | --help | help | "") usage ;;
    *) die "unknown command ${cmd}" ;;
  esac
  EXIT_EXPECTED=1
}

# Sourced by backend/tests/test_chola_prod_kit.py to test single functions; run as a script otherwise.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
