#!/usr/bin/env bash
# chola-prod.sh - deploy DevSecShield to the Chola production instance from the owner's machine
# (deploy/chola-prod/README.md). Uses the caller's own AWS credentials (AWS CLI v2; AWS_PROFILE is honoured); never
# prints, stores or commits a secret value. `chola-prod.sh --help` lists commands, flags and environment variables.
set -Eeuo pipefail
export LC_ALL=C
# No silent exit: a failing command that no check handles names itself.
trap 'rc=$?; printf "[chola] ERROR: line %s: %s (exit %s)\n" "${LINENO}" "${BASH_COMMAND}" "${rc}" >&2' ERR

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIT_DIR="${REPO_ROOT}/deploy/chola-prod"
KIT_PY="${KIT_DIR}/kit.py"

ACCOUNT="${CHOLA_ACCOUNT:-935951870001}"
REGION="${CHOLA_REGION:-ap-south-1}"
INSTANCE_ID="${CHOLA_INSTANCE_ID:-i-0b7fe756ebfd4d1e6}"
SSH_USER=ubuntu
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
ECR_NS=devsec-chola
IMAGE_PREFIX="${REGISTRY}/${ECR_NS}"
SECRET_PREFIX=devsec-chola/prod
BUCKET=devsecshield-storage
RELEASE_KEY=releases/release.tar
TG_ARN="${CHOLA_TG_ARN:-arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:targetgroup/devsec-chola-prod-tg/3c35d6b360c5c80a}"
BACKUP_VAULT=devsec-chola-prod-backup-vault
BACKUP_ROLE="arn:aws:iam::${ACCOUNT}:role/devsec-chola-prod-backup-role"
VOLUME_ID=vol-02a57fae6510bb790
BACKUP_TAGS="Application=DevSecShield,CostCenter=DevSecShield-Production,Deployment=Chola,Environment=Production,ManagedBy=DevOps,Name=devsec-chola-prod-pre-deployment,Owner=CyberUltron,Project=DevSecShield"
FRONTEND_HOST=chola.zeroshield.ai
API_HOST=chola-api.zeroshield.ai
REAL_IP_FROM=10.60.1.0/24,10.60.2.0/24
REMOTE_DIR=/opt/devsecshield-chola
GHCR="${CHOLA_GHCR:-ghcr.io/cyberultron-consulting-private-limited}"
KNOWN_HOSTS="${CHOLA_KNOWN_HOSTS:-${HOME}/.ssh/known_hosts_devsec_chola}"
ANSH_REFSPEC=+refs/heads/ansh:refs/remotes/origin/ansh
# Pulled by digest, shipped under the tag docker-compose.yml and deploy/chola-prod/remote.sh name (tested). To move
# one: `docker buildx imagetools inspect <name:tag>` for the new index digest, update it here, run `infra --force-infra`.
INFRA_IMAGES=(
  postgres:15-alpine@sha256:e18480a22d6e48f4d816a6696769b1ec09ac73a824c5649e49c7d8b684913f3d
  mongo:8.0.6@sha256:ab6556e6d71d9773dd74002db924dc637abb49d079d6ef945982af3078fdf22c
  rabbitmq:4.1-management-alpine@sha256:71dc98bb14d16c7240efc1d9b6356e5ac1470a51c63e8cce16f246e09748a995
  nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
  qdrant/qdrant:v1.13.5@sha256:7c648cc0883113b2046d6def26da345b61a8e4caa16b0df206eacc01d516bdda
)
COMPONENTS=(backend frontend scan-worker dast-worker)

DRY=0 YES=0 HELP=0 SHA="" SHA12="" GHCR_TAG="" FRONTEND_IMAGE="" FORCE_INFRA=0 ALLOW_DOWNGRADE=0 REFRESH_MAIL=0
MAIL_PROMPT=0 ALLOW_IMDS=0 EMAIL="" SERVICE="" TAIL=200 JOB=""
WORK=""
SSH_READY=0
KIT_RUN="" # this run's kit copy on the instance: $REMOTE_DIR/.kit/<run>
CURRENT_JOB=""
declare -a SSH_OPTS=()
declare -a SUMMARY=()

usage() {
  cat <<'EOF'
chola-prod.sh <command> [flags]      (flags may come before or after the command; deploy/chola-prod/README.md)

Commands
  preflight [--sha S]        prove the prerequisites: local tools, AWS identity and account, instance and IMDS options,
                             target group, secrets, ECR repositories, S3 bucket owner, iam:PassRole for the backup,
                             the EC2 Instance Connect tunnel, and on the instance Docker/Compose, the instance role
                             (STS, S3), the data volume, free disk where images and volumes live; read-only
  host-setup                 install AWS CLI v2 on the instance from an installer downloaded here (only if preflight
                             says it is missing)
  secrets                    fill devsec-chola/prod/app-secrets: generate what is missing, keep every existing value;
                             the mail login only on first setup (from origin/ansh) or with --refresh-mail/--mail-prompt
  images --sha S             backend + workers from GHCR (linux/amd64), the frontend built here for the API URL, all
                             pushed to ECR as :<sha12>
  infra [--force-infra]      the infrastructure images as the S3 release archive, loaded on the instance if missing
  backup                     logical dumps on the instance, then the AWS Backup job of the data volume (waits)
  deploy --sha S [--yes]     all of the above in order, then migrate + start (detached on the instance), smtp-test,
                             verify
  verify                     ALB target health (instance or ip targets), nginx-health on the instance, public URLs
  rollback [--allow-downgrade] [--yes]
                             backup, then back to the previous tag (also after an interrupted deploy), then verify
  attach --job ID            follow a detached deploy/rollback/dump/infra-load job again (after Ctrl-C or a dropped
                             tunnel; `status` lists recent jobs)
  smtp-test                  SMTP login from the instance with the deployed settings (sends nothing)
  admin --email E            make the signed-up account E the platform administrator
  status                     containers, deployed tag, history, jobs, images, disk, ALB target health
  logs [--service S] [--tail N]

Flags
  --dry-run                  print every step; run no AWS, SSH, Docker, registry or git-fetch command, read no secret
  --yes                      no confirmation prompt (deploy, rollback)
  --sha S                    the commit to deploy (7-40 hex characters; must exist in this checkout)
  --ghcr-tag T               GHCR tag of the backend/worker images (default: dev-, staging- or manual-<sha12>)
  --frontend-image REF       use this frontend image instead of building one (its API URL is checked)
  --force-infra              build and load the release archive even when the instance has every image
  --allow-downgrade          let rollback run alembic downgrade (drops what newer migrations added)
  --refresh-mail             re-read the mail login from origin/ansh:backend/.env into app-secrets
  --mail-prompt              type the mailbox address and password at a hidden prompt instead of reading origin/ansh
  --allow-imds               accept IMDSv1 or a hop limit > 1 (containers could use the instance role); not advised
  --email E, --service S, --tail N, --job ID
  -h, --help                 this text (also `<command> --help`)

Environment (defaults are the Chola values)
  AWS_PROFILE                the owner's AWS profile (AnshSinghal-Cyberultron)
  CHOLA_ACCOUNT, CHOLA_REGION, CHOLA_INSTANCE_ID, CHOLA_TG_ARN, CHOLA_GHCR
  CHOLA_KNOWN_HOSTS          SSH host keys of the instance (default ~/.ssh/known_hosts_devsec_chola)
  CHOLA_WORK_PARENT          scratch directory parent (default $TMPDIR); the scratch dir is removed on exit
  CHOLA_BACKUP_TIMEOUT_S     wait for the backup job (default 7200)
  CHOLA_POLL_RETRIES         consecutive failed AWS polls tolerated (default 10)
  CHOLA_POLL_S               seconds between polls (default: 30 backup job, 10 target health and reconnects)
  CHOLA_SSH_RETRIES          consecutive lost connections while following a job (default 30)
  CHOLA_AWSCLI_PGP_KEY       host-setup: file with the AWS CLI PGP key to verify the installer
EOF
}

log() { printf '[chola %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
warn() { printf '[chola %s] WARNING: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { printf '[chola] ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n[chola] ==== %s\n' "$*"; }
note() { # <step> <result>: the summary; a dry run reports the step as skipped, never as a result
  if ((DRY)); then SUMMARY+=("$1: skipped (dry-run)"); else SUMMARY+=("$1: $2"); fi
}

quote() { local a out=""; for a in "$@"; do out+="$(printf '%q' "${a}") "; done; printf '%s' "${out% }"; }
# x <command...>: run it, or print it with --dry-run. Every command that touches AWS, SSH, Docker or a registry goes
# through x (or checks DRY itself).
x() {
  if ((DRY)); then printf '[dry-run] %s\n' "$(quote "$@")"; return 0; fi
  "$@"
}
ecr_repo() { case "$1" in backend | frontend) printf 'devsecshield-%s\n' "$1" ;; *) printf '%s\n' "$1" ;; esac; }
ecr_ref() { printf '%s/%s:%s\n' "${IMAGE_PREFIX}" "$(ecr_repo "$1")" "$2"; }
infra_tag() { printf '%s\n' "${1%%@*}"; } # postgres:15-alpine@sha256:... -> postgres:15-alpine

cleanup() {
  local rc=$?
  if [[ -n "${WORK}" && -d "${WORK}" ]]; then
    if ((SSH_READY && !DRY)); then ssh "${SSH_OPTS[@]}" -O exit "${SSH_USER}@${INSTANCE_ID}" >/dev/null 2>&1 || true; fi
    # the SSH key, the mail source copy, the merged secret JSON, the release archive, the isolated Docker config
    rm -rf -- "${WORK}"
  fi
  return "${rc}"
}
trap cleanup EXIT
on_interrupt() {
  if [[ -n "${CURRENT_JOB}" ]]; then
    printf '\n[chola] Ctrl-C: job %s KEEPS RUNNING on the instance. Follow it again: %s attach --job %s\n' \
      "${CURRENT_JOB}" "$0" "${CURRENT_JOB}" >&2
  fi
  exit 130
}
trap on_interrupt INT
trap 'exit 143' TERM

work() {
  # Never first in a subshell ($(...)): the EXIT trap of the main shell would not know the directory (it holds the key).
  if [[ -z "${WORK}" && "${BASH_SUBSHELL}" -gt 0 ]]; then die "internal: scratch directory first created in a subshell"; fi
  if [[ -z "${WORK}" ]]; then
    umask 077
    WORK="$(mktemp -d "${CHOLA_WORK_PARENT:-${TMPDIR:-/tmp}}/chola-prod.XXXXXX")"
    chmod 700 "${WORK}"
  fi
}

# ------------------------------------------------------------------------------------------------ arguments
parse_args() { # flags may come before or after the command
  CMD=""
  while (($#)); do
    case "$1" in
      --sha) [[ $# -ge 2 ]] || die "--sha needs a commit"; SHA=$2; shift 2 ;;
      --dry-run) DRY=1; shift ;;
      --yes) YES=1; shift ;;
      -h | --help) HELP=1; shift ;;
      --ghcr-tag) [[ $# -ge 2 ]] || die "--ghcr-tag needs a tag"; GHCR_TAG=$2; shift 2 ;;
      --frontend-image) [[ $# -ge 2 ]] || die "--frontend-image needs an image"; FRONTEND_IMAGE=$2; shift 2 ;;
      --force-infra) FORCE_INFRA=1; shift ;;
      --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
      --refresh-mail) REFRESH_MAIL=1; shift ;;
      --mail-prompt) MAIL_PROMPT=1; shift ;;
      --allow-imds) ALLOW_IMDS=1; shift ;;
      --email) [[ $# -ge 2 ]] || die "--email needs an address"; EMAIL=$2; shift 2 ;;
      --service) [[ $# -ge 2 ]] || die "--service needs a name"; SERVICE=$2; shift 2 ;;
      --tail) [[ $# -ge 2 && "$2" =~ ^[0-9]{1,6}$ ]] || die "--tail needs a number"; TAIL=$2; shift 2 ;;
      --job) [[ $# -ge 2 ]] || die "--job needs an id"; JOB=$2; shift 2 ;;
      -*) die "unknown option $1 (see --help)" ;;
      *) [[ -z "${CMD}" ]] || die "unexpected argument $1 (see --help)"; CMD=$1; shift ;;
    esac
  done
  [[ -z "${GHCR_TAG}" || "${GHCR_TAG}" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || die "--ghcr-tag ${GHCR_TAG} is not a tag"
  [[ -z "${SERVICE}" || "${SERVICE}" =~ ^[a-z0-9-]{1,40}$ ]] || die "--service ${SERVICE} is not a service name"
  [[ -z "${JOB}" || "${JOB}" =~ ^[0-9TZ]+-[a-z-]+-[0-9]+$ ]] || die "--job ${JOB} is not a job id"
  ((!(REFRESH_MAIL && MAIL_PROMPT))) || die "--refresh-mail and --mail-prompt exclude each other"
}

resolve_sha() {
  [[ -n "${SHA}" ]] || die "give --sha <commit>"
  [[ "${SHA}" =~ ^[0-9a-fA-F]{7,40}$ ]] || die "--sha must be a commit id"
  if ! git -C "${REPO_ROOT}" cat-file -e "${SHA}^{commit}" 2>/dev/null; then
    ((!DRY)) || die "commit ${SHA} is not in this checkout (a dry run fetches nothing: git fetch origin first)"
    log "fetching origin to find ${SHA}"
    git -C "${REPO_ROOT}" fetch -q origin
  fi
  local full
  full="$(git -C "${REPO_ROOT}" rev-parse --verify -q "${SHA}^{commit}")" || die "commit ${SHA} not found (git fetch origin?)"
  SHA="${full}"
  SHA12="${SHA:0:12}"
}

# ------------------------------------------------------------------------------------------------ AWS / SSH plumbing
aws_() { x aws --region "${REGION}" "$@"; }

ssh_setup() {
  ((SSH_READY)) && return 0
  [[ "${BASH_SUBSHELL}" -eq 0 ]] || die "internal: SSH first set up in a subshell"
  work
  local key="${WORK}/ssh-admin.pem"
  SSH_OPTS=(-i "${key}" -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR
    -o "ProxyCommand=aws ec2-instance-connect open-tunnel --region ${REGION} --instance-id %h"
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=${KNOWN_HOSTS}"
    -o ControlMaster=auto -o "ControlPath=${WORK}/cm-%C" -o ControlPersist=15m
    -o ServerAliveInterval=30 -o ServerAliveCountMax=4 -o ConnectTimeout=90)
  if ((DRY)); then
    printf '[dry-run] aws secretsmanager get-secret-value --secret-id %s/ssh-admin (field private_key_pem) > %s (mode 600)\n' \
      "${SECRET_PREFIX}" "${key}"
    SSH_READY=1
    return 0
  fi
  mkdir -p "$(dirname "${KNOWN_HOSTS}")"
  # The key goes from the AWS CLI through kit.py straight into a 0600 file in the 0700 scratch directory; removed on exit.
  (umask 077 && aws --region "${REGION}" secretsmanager get-secret-value --secret-id "${SECRET_PREFIX}/ssh-admin" \
    --query SecretString --output text | python3 -I "${KIT_PY}" json-field private_key_pem >"${key}") ||
    die "cannot read ${SECRET_PREFIX}/ssh-admin (field private_key_pem)"
  chmod 600 "${key}"
  head -n 1 "${key}" | grep -q -- '-----BEGIN' || die "${SECRET_PREFIX}/ssh-admin private_key_pem is not a PEM key"
  # The EC2 Instance Connect tunnel (ec2-instance-connect:OpenTunnel) is proved here: its errors are shown as they come.
  if ! ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" true 2>"${WORK}/ssh.err"; then
    sed 's/^/    /' "${WORK}/ssh.err" >&2
    die "SSH to ${INSTANCE_ID} through EC2 Instance Connect failed (above). AccessDenied: the user lacks" \
      "ec2-instance-connect:OpenTunnel; a timeout: no endpoint in the VPC or its security group cannot reach port 22;" \
      "README 'Troubleshooting: EICE tunnel'"
  fi
  log "EC2 Instance Connect tunnel OK: ${SSH_USER}@${INSTANCE_ID} (key from ${SECRET_PREFIX}/ssh-admin, removed on exit)"
  SSH_READY=1
}
ssh_refresh() { # a fresh control connection before a long step (EICE connections are time-limited)
  ((SSH_READY && !DRY)) || return 0
  ssh "${SSH_OPTS[@]}" -O exit "${SSH_USER}@${INSTANCE_ID}" >/dev/null 2>&1 || true
}

# This run's copy of the kit on the instance ($REMOTE_DIR/.kit/<run>): remote.sh runs from it with
# CHOLA_BASE_DIR=$REMOTE_DIR, so read-only commands never replace the live kit files; only remote.sh deploy installs
# them (with the commit's aibom-config-overlay, uploaded here for a deploy).
kit_upload() { # [with-overlay]
  ssh_setup
  [[ -z "${KIT_RUN}" || "${1:-}" == with-overlay ]] || return 0
  local stage="${WORK}/bundle" with=${1:-} run
  run="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  rm -rf "${stage}"
  mkdir -p "${stage}/deploy"
  tar -C "${REPO_ROOT}" --exclude='deploy/chola-prod/*.env' --exclude='deploy/chola-prod/.env' --exclude='__pycache__' \
    -cf - deploy/chola-prod | tar -C "${stage}" -xf -
  local -a dirs=(deploy)
  if [[ "${with}" == with-overlay ]]; then
    if git -C "${REPO_ROOT}" cat-file -e "${SHA}:compose/aibom-config-overlay" 2>/dev/null; then
      git -C "${REPO_ROOT}" archive --format=tar "${SHA}" compose/aibom-config-overlay | tar -C "${stage}" -xf -
    else
      warn "${SHA12} has no compose/aibom-config-overlay: using this checkout's"
      tar -C "${REPO_ROOT}" -cf - compose/aibom-config-overlay | tar -C "${stage}" -xf -
    fi
    dirs+=(compose)
  fi
  if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain -- deploy/chola-prod scripts/deploy/chola-prod.sh 2>/dev/null)" ]]; then
    warn "the kit files in this checkout have uncommitted changes; they are what gets copied"
  fi
  KIT_RUN="${REMOTE_DIR}/.kit/${run}"
  if ((DRY)); then
    printf '[dry-run] tar -czf - %s | ssh ... %s@%s "tar -xzf - -C %s" (not the live kit)\n' "${dirs[*]}" "${SSH_USER}" \
      "${INSTANCE_ID}" "${KIT_RUN}"
    return 0
  fi
  # shellcheck disable=SC2029 # expanded here on purpose (quoted with %q)
  tar -C "${stage}" -czf - "${dirs[@]}" | ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" \
    "sudo -n mkdir -p $(quote "${REMOTE_DIR}") && sudo -n chown $(quote "${SSH_USER}:${SSH_USER}") $(quote "${REMOTE_DIR}") && chmod 750 $(quote "${REMOTE_DIR}") && mkdir -p $(quote "${KIT_RUN}") && chmod 700 $(quote "${REMOTE_DIR}/.kit") && tar -xzf - -C $(quote "${KIT_RUN}") && find $(quote "${REMOTE_DIR}/.kit") -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +" ||
    die "copying the kit to the instance failed"
}

remote_cmdline() { # the shell command that runs remote.sh <args> on the instance
  printf 'cd %s && CHOLA_BASE_DIR=%s CHOLA_REGION=%s CHOLA_ACCOUNT=%s CHOLA_REGISTRY=%s CHOLA_IMAGE_PREFIX=%s CHOLA_SECRET_PREFIX=%s CHOLA_BUCKET=%s CHOLA_FRONTEND_HOST=%s CHOLA_API_HOST=%s CHOLA_REAL_IP_FROM=%s CHOLA_ALLOW_IMDS=%s bash %s %s' \
    "$(quote "${REMOTE_DIR}")" "$(quote "${REMOTE_DIR}")" "$(quote "${REGION}")" "$(quote "${ACCOUNT}")" \
    "$(quote "${REGISTRY}")" "$(quote "${IMAGE_PREFIX}")" "$(quote "${SECRET_PREFIX}")" "$(quote "${BUCKET}")" \
    "$(quote "${FRONTEND_HOST}")" "$(quote "${API_HOST}")" "$(quote "${REAL_IP_FROM}")" "${ALLOW_IMDS}" \
    "$(quote "${KIT_RUN}/deploy/chola-prod/remote.sh")" "$(quote "$@")"
}

# remote <remote.sh args...>: run deploy/chola-prod/remote.sh on the instance (this run's kit copy).
remote() {
  kit_upload
  if ((DRY)); then
    printf '[dry-run] ssh (EICE tunnel, key from %s/ssh-admin) %s@%s: remote.sh %s\n' \
      "${SECRET_PREFIX}" "${SSH_USER}" "${INSTANCE_ID}" "$(quote "$@")"
    return 0
  fi
  # shellcheck disable=SC2029 # the remote command line is built here on purpose (every word quoted with %q)
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" "$(remote_cmdline "$@")"
}

# remote_job <deploy|rollback|dump|infra-load> [args]: started DETACHED on the instance (setsid nohup), so a dropped
# tunnel or Ctrl-C here cannot kill it half way; its output is followed here until it ends; its exit status is ours.
remote_job() {
  kit_upload
  if ((DRY)); then
    printf '[dry-run] ssh ... remote.sh job-start %s   (detached on the instance; output followed here)\n' "$(quote "$@")"
    return 0
  fi
  ssh_refresh
  local id
  # shellcheck disable=SC2029
  id="$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" "$(remote_cmdline job-start "$@")")" ||
    die "could not start '$1' on the instance (above)"
  [[ "${id}" =~ ^[0-9TZ]+-[a-z-]+-[0-9]+$ ]] || die "unexpected job id from the instance: ${id:0:80}"
  log "job ${id} runs detached on the instance (Ctrl-C here does not stop it; ${0##*/} attach --job ${id})"
  follow_job "${id}"
}

follow_job() { # <id>: print the job's output until it ends; returns its exit status
  local id=$1 off=0 fails=0 status rc max=${CHOLA_SSH_RETRIES:-30}
  CURRENT_JOB="${id}"
  while :; do
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" "$(remote_cmdline job-follow "${id}" "${off}" 20)" \
      >"${WORK}/job.out" 2>"${WORK}/job.err" || true
    cat "${WORK}/job.out"
    status="$(grep '^chola-job: ' "${WORK}/job.err" | tail -n 1 || true)"
    if [[ -z "${status}" ]]; then
      grep -v '^chola-job: ' "${WORK}/job.err" | sed 's/^/    /' >&2 || true
      fails=$((fails + 1))
      ((fails < max)) || die "lost the connection to the instance ${max} times; job ${id} continues there:" \
        "${0##*/} attach --job ${id}"
      warn "no answer from the instance while following ${id} (${fails}/${max}); reconnecting"
      ssh_refresh
      sleep "${CHOLA_POLL_S:-10}"
      continue
    fi
    fails=0
    read -r _ state a b <<<"${status}"
    if [[ "${state}" == "done" ]]; then
      rc=${a}
      CURRENT_JOB=""
      [[ "${rc}" =~ ^[0-9]+$ ]] || rc=1
      return "${rc}"
    fi
    off=${a}
    : "${b:=}"
  done
}

# ------------------------------------------------------------------------------------------------ Docker config
# GHCR and ECR logins go into a throwaway Docker config in the scratch directory, never into the owner's credential
# store (the gh token would stay there otherwise). The current Docker endpoint and CLI plugins are kept.
DOCKER_ISOLATED=0
docker_isolate() {
  ((DOCKER_ISOLATED || DRY)) && return 0
  work
  local host cfg="${WORK}/docker-config"
  if [[ -z "${DOCKER_HOST:-}" ]]; then
    host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
    [[ -z "${host}" ]] || export DOCKER_HOST="${host}"
  fi
  mkdir -p "${cfg}"
  printf '{}\n' >"${cfg}/config.json"
  if [[ -d "${HOME}/.docker/cli-plugins" ]]; then ln -s "${HOME}/.docker/cli-plugins" "${cfg}/cli-plugins"; fi
  export DOCKER_CONFIG="${cfg}"
  DOCKER_ISOLATED=1
}

# ------------------------------------------------------------------------------------------------ preflight
need() { command -v "$1" >/dev/null 2>&1 || { if ((DRY)); then warn "$1 not found (needed for a real run)"; else die "$1 is not installed"; fi; }; }

local_preflight() {
  local v major minor
  for v in aws docker git python3 curl ssh tar; do need "${v}"; done
  if ((DRY)); then
    printf '[dry-run] aws --version (2.12+ for ec2-instance-connect open-tunnel); docker info; docker buildx version\n'
  else
    v="$(aws --version 2>&1 | sed -n -E 's|^aws-cli/([0-9]+)\.([0-9]+)\..*|\1 \2|p')"
    read -r major minor <<<"${v:-0 0}"
    ((major >= 2 && (major > 2 || minor >= 12))) || die "AWS CLI v2.12+ is needed (ec2-instance-connect open-tunnel); found $(aws --version 2>&1 | cut -d' ' -f1)"
    docker info >/dev/null 2>&1 || die "Docker is not running"
    docker buildx version >/dev/null 2>&1 || die "docker buildx is missing (needed to build the linux/amd64 frontend)"
  fi
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || die "python3 3.8+ is needed"
  git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1 || die "${REPO_ROOT} is not a git checkout"
}

aws_identity() {
  if ((DRY)); then printf '[dry-run] aws sts get-caller-identity (account must be %s)\n' "${ACCOUNT}"; return 0; fi
  local id
  id="$(aws sts get-caller-identity --query '[Account,Arn]' --output text)" || die "no AWS credentials (aws configure / AWS_PROFILE)"
  [[ "${id%%[[:space:]]*}" == "${ACCOUNT}" ]] || die "AWS account is ${id%%[[:space:]]*}, not ${ACCOUNT} (wrong AWS_PROFILE?)"
  CALLER_ARN="${id##*[[:space:]]}"
  log "AWS identity: ${CALLER_ARN}"
}
CALLER_ARN=""

simulate() { # <action> <resource>: allowed / implicitDeny / explicitDeny, or "unknown" when the simulation is refused
  local src=${CALLER_ARN} out
  # an assumed role is simulated as its role
  if [[ "${src}" == arn:aws:sts::*:assumed-role/* ]]; then
    src="${src/:sts::/:iam::}"
    src="${src/:assumed-role\//:role/}"
    src="${src%/*}"
  fi
  out="$(aws iam simulate-principal-policy --policy-source-arn "${src}" --action-names "$1" --resource-arns "$2" \
    --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)" || out=unknown
  printf '%s\n' "${out}"
}

aws_resources() {
  if ((DRY)); then
    printf '[dry-run] aws ec2 describe-instances %s (state, MetadataOptions); aws elbv2 describe-target-groups/-health;\n' "${INSTANCE_ID}"
    printf '[dry-run] aws secretsmanager describe-secret (4 secrets); aws ecr describe-repositories (4); aws backup describe-backup-vault;\n'
    printf '[dry-run] aws s3api head-bucket --bucket %s --expected-bucket-owner %s; aws iam simulate-principal-policy (iam:PassRole %s, backup:StartBackupJob)\n' \
      "${BUCKET}" "${ACCOUNT}" "${BACKUP_ROLE}"
    return 0
  fi
  local out s r c state itype ip tokens hop endpoint dec
  out="$(aws --region "${REGION}" ec2 describe-instances --instance-ids "${INSTANCE_ID}" --query \
    'Reservations[0].Instances[0].[State.Name,InstanceType,PrivateIpAddress,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit,MetadataOptions.HttpEndpoint]' --output text)" ||
    die "cannot describe ${INSTANCE_ID}"
  read -r state itype ip tokens hop endpoint <<<"${out}"
  log "instance ${INSTANCE_ID}: ${state}, ${itype}, ${ip}; IMDS ${endpoint} tokens=${tokens} hop-limit=${hop}"
  [[ "${state}" == running ]] || die "the instance is ${state}"
  if [[ "${tokens}" != required || ! "${hop}" =~ ^[0-9]+$ || "${hop}" -gt 1 ]]; then
    local why="HttpTokens=${tokens}, HttpPutResponseHopLimit=${hop}: containers can obtain the instance role's credentials, which read every ${SECRET_PREFIX} secret (the app does not need them: S3/Bedrock use the app-user keys). Ask the infra team for HttpTokens=required and hop limit 1"
    if ((ALLOW_IMDS)); then warn "${why} (accepted: --allow-imds)"; else die "${why}, or pass --allow-imds"; fi
  fi
  out="$(aws --region "${REGION}" elbv2 describe-target-groups --target-group-arns "${TG_ARN}" --query \
    'TargetGroups[0].[TargetType,Protocol,Port,HealthCheckPath]' --output text)" || die "cannot read the target group"
  log "target group: ${out//$'\t'/ } (expect HTTP 80 /nginx-health)"
  [[ "${out}" == *"/nginx-health"* ]] || warn "the target group health check path is not /nginx-health"
  log "target health: $(target_health_line || echo 'not readable now')"
  for s in ssh-admin app-user cbom-collector app-secrets; do
    aws --region "${REGION}" secretsmanager describe-secret --secret-id "${SECRET_PREFIX}/${s}" --query Name --output text >/dev/null ||
      die "cannot see secret ${SECRET_PREFIX}/${s}"
  done
  log "secrets: ${SECRET_PREFIX}/{ssh-admin,app-user,cbom-collector,app-secrets} visible"
  for c in "${COMPONENTS[@]}"; do
    r="$(ecr_repo "${c}")"
    out="$(aws --region "${REGION}" ecr describe-repositories --repository-names "${ECR_NS}/${r}" \
      --query 'repositories[0].imageTagMutability' --output text)" || die "cannot see ECR repository ${ECR_NS}/${r}"
    log "ECR ${ECR_NS}/${r}: tags ${out}"
  done
  aws --region "${REGION}" s3api head-bucket --bucket "${BUCKET}" --expected-bucket-owner "${ACCOUNT}" >/dev/null ||
    die "s3://${BUCKET} is not reachable or not owned by ${ACCOUNT} (head-bucket --expected-bucket-owner)"
  log "S3: s3://${BUCKET} owned by ${ACCOUNT}"
  aws --region "${REGION}" backup describe-backup-vault --backup-vault-name "${BACKUP_VAULT}" --query BackupVaultName --output text >/dev/null ||
    die "cannot see backup vault ${BACKUP_VAULT}"
  [[ -n "${CALLER_ARN}" ]] || aws_identity
  dec="$(simulate iam:PassRole "${BACKUP_ROLE}")"
  case "${dec}" in
    allowed) log "backup: iam:PassRole on ${BACKUP_ROLE##*/} allowed" ;;
    unknown) warn "cannot simulate iam:PassRole (no iam:SimulatePrincipalPolicy): the backup step fails with AccessDenied if ${CALLER_ARN##*/} may not pass ${BACKUP_ROLE##*/}" ;;
    *) die "iam:PassRole on ${BACKUP_ROLE} is ${dec} for ${CALLER_ARN}: the pre-deployment backup cannot start. Ask the infra team to allow it" ;;
  esac
  dec="$(simulate backup:StartBackupJob "arn:aws:backup:${REGION}:${ACCOUNT}:backup-vault:${BACKUP_VAULT}")"
  case "${dec}" in
    allowed) log "backup: backup:StartBackupJob on ${BACKUP_VAULT} allowed" ;;
    unknown) warn "cannot simulate backup:StartBackupJob; the backup step will tell" ;;
    *) die "backup:StartBackupJob on ${BACKUP_VAULT} is ${dec} for ${CALLER_ARN}" ;;
  esac
}

target_health_line() { # one line; fails (non-zero) when the call fails
  local out
  out="$(aws --region "${REGION}" elbv2 describe-target-health --target-group-arn "${TG_ARN}" --query \
    'TargetHealthDescriptions[].[Target.Id,Target.Port,TargetHealth.State,TargetHealth.Reason]' --output text)" || return 1
  printf '%s\n' "$(tr '\t\n' ' ;' <<<"${out}")"
}

cmd_preflight() {
  step "preflight"
  local_preflight
  aws_identity
  aws_resources
  if [[ -n "${SHA}" ]]; then
    resolve_sha
    docker_isolate
    ghcr_login
    ghcr_tag >/dev/null
  fi
  remote preflight
  mail_source_check
  note "preflight" "OK"
}

# ------------------------------------------------------------------------------------------------ host setup
cmd_host_setup() {
  step "host-setup: AWS CLI v2 on the instance"
  ssh_setup
  work
  local d="${WORK}/awscli"
  mkdir -p "${d}"
  x curl -fsSL --retry 3 -o "${d}/awscliv2.zip" https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
  x curl -fsSL --retry 3 -o "${d}/awscliv2.sig" https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip.sig
  if [[ -n "${CHOLA_AWSCLI_PGP_KEY:-}" ]]; then
    # The AWS CLI team's public key, saved from the AWS CLI install guide (Linux, "Verify the integrity").
    x gpg --batch --no-default-keyring --keyring "${d}/k.gpg" --import "${CHOLA_AWSCLI_PGP_KEY}"
    x gpg --batch --no-default-keyring --keyring "${d}/k.gpg" --verify "${d}/awscliv2.sig" "${d}/awscliv2.zip" || die "signature check failed"
  else
    warn "installer not signature-checked: set CHOLA_AWSCLI_PGP_KEY=<file with the AWS CLI PGP key> to check it"
  fi
  x unzip -q "${d}/awscliv2.zip" -d "${d}"
  if ((DRY)); then printf '[dry-run] tar -C %s -czf - aws | ssh ... "sudo ./aws/install --update"\n' "${d}"; note "host-setup" ""; return 0; fi
  tar -C "${d}" -czf - aws | ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" \
    't=$(mktemp -d) && tar -xzf - -C "$t" && sudo -n "$t/aws/install" --update && rm -rf "$t" && aws --version'
  note "host-setup" "AWS CLI installed on the instance"
}

# ------------------------------------------------------------------------------------------------ secrets
# The mail login: origin/ansh:backend/.env (OUTLOOK_EMAIL / OUTLOOK_PASSWORD) is read ONLY when app-secrets has no mail
# keys yet (first setup) or with --refresh-mail; --mail-prompt asks for them instead. Fetched with an explicit refspec,
# so a single-branch clone works and a stale origin/ansh is never used silently.
fetch_ansh() { # -> ${WORK}/mail.env (mode 600)
  local err="${WORK}/git.err" keys rc=0
  if ! git -C "${REPO_ROOT}" fetch -q origin "${ANSH_REFSPEC}" 2>"${err}"; then
    git -C "${REPO_ROOT}" ls-remote --exit-code origin refs/heads/ansh >/dev/null 2>&1 || rc=$?
    if [[ "${rc}" == 2 ]]; then
      die "origin has no branch 'ansh' (the mail login was read from it): use --mail-prompt"
    fi
    die "git fetch origin ansh failed: $(tail -n 1 "${err}") (network or access; nothing was changed)"
  fi
  git -C "${REPO_ROOT}" cat-file -e refs/remotes/origin/ansh:backend/.env 2>/dev/null ||
    die "origin/ansh has no backend/.env any more (moved out of git?): use --mail-prompt"
  (umask 077 && git -C "${REPO_ROOT}" show refs/remotes/origin/ansh:backend/.env >"${WORK}/mail.env") ||
    die "cannot read origin/ansh:backend/.env"
  keys="$(python3 -I "${KIT_PY}" dotenv-keys "${WORK}/mail.env" | { grep -xE 'OUTLOOK_EMAIL|OUTLOOK_PASSWORD' || true; } |
    sort | paste -sd' ' -)"
  [[ "${keys}" == "OUTLOOK_EMAIL OUTLOOK_PASSWORD" ]] ||
    die "origin/ansh:backend/.env is there but lacks OUTLOOK_EMAIL / OUTLOOK_PASSWORD (found: ${keys:-neither}): use --mail-prompt"
  log "mail login read from origin/ansh:backend/.env ($(git -C "${REPO_ROOT}" rev-parse --short=12 refs/remotes/origin/ansh); values not shown)"
}

prompt_mail() { # -> ${WORK}/mail.lines (address, password; mode 600)
  [[ -t 0 ]] || die "--mail-prompt needs a terminal"
  local addr pw
  read -r -p "[chola] Mailbox address (SMTP login and From): " addr
  read -r -s -p "[chola] Mailbox password (not shown): " pw
  printf '\n'
  [[ -n "${addr}" && -n "${pw}" ]] || die "address and password are both required"
  (umask 077 && printf '%s\n%s\n' "${addr}" "${pw}" >"${WORK}/mail.lines")
  pw=""
}

read_app_secrets() { # -> ${WORK}/app-secrets.json ("{}" when the secret has no value yet)
  local cur="${WORK}/app-secrets.json" err
  if ! (umask 077 && aws --region "${REGION}" secretsmanager get-secret-value --secret-id "${SECRET_PREFIX}/app-secrets" \
    --query SecretString --output text >"${cur}" 2>"${WORK}/err"); then
    err="$(tail -n 1 "${WORK}/err")"
    # A secret created without a value has no AWSCURRENT version yet: start from {}.
    [[ "${err}" == *ResourceNotFoundException* && "${err}" == *AWSCURRENT* ]] || die "cannot read ${SECRET_PREFIX}/app-secrets: ${err}"
    printf '{}' >"${cur}"
  fi
}

data_on_instance() { # yes / no; any other outcome (ssh, Docker) stops everything: never guess "no data"
  local out
  out="$(remote volume-exists)" || die "cannot tell whether the instance already has database volumes (SSH or Docker" \
    "failed, above); nothing was changed"
  case "${out}" in
    yes | no) printf '%s\n' "${out}" ;;
    *) die "unexpected answer from remote.sh volume-exists: '${out:0:40}'; nothing was changed" ;;
  esac
}

mail_source_check() { # preflight: will the first `secrets` find a mail login?
  ((!DRY)) || { printf '[dry-run] app-secrets mail keys present? (else origin/ansh or --mail-prompt is needed)\n'; return 0; }
  work
  read_app_secrets
  if [[ "$(python3 -I "${KIT_PY}" mail-state <"${WORK}/app-secrets.json")" == present ]]; then
    log "mail: app-secrets already holds the mail login (origin/ansh is not needed)"
  elif ((MAIL_PROMPT)); then
    log "mail: app-secrets has no mail login yet; it will be asked for (--mail-prompt)"
  else
    fetch_ansh
    rm -f "${WORK}/mail.env"
    log "mail: app-secrets has no mail login yet; origin/ansh:backend/.env has it (first setup)"
  fi
  rm -f "${WORK}/app-secrets.json"
}

cmd_secrets() {
  step "secrets: ${SECRET_PREFIX}/app-secrets (generated values kept across runs)"
  work
  local cur="${WORK}/app-secrets.json" out="${WORK}/app-secrets.new.json" rc=0 data state
  if ((DRY)); then
    printf '[dry-run] aws secretsmanager get-secret-value --secret-id %s/app-secrets > %s\n' "${SECRET_PREFIX}" "${cur}"
    remote volume-exists
    printf '[dry-run] mail login: kept when app-secrets has it; else (or --refresh-mail) git fetch origin %s and read OUTLOOK_EMAIL / OUTLOOK_PASSWORD; --mail-prompt asks instead\n' "${ANSH_REFSPEC}"
    printf '[dry-run] python3 kit.py merge-app-secrets [--data-exists] (generate missing; keep existing; never generate data keys when data exists)\n'
    printf '[dry-run] aws secretsmanager put-secret-value --secret-id %s/app-secrets --secret-string file://%s (only when changed)\n' "${SECRET_PREFIX}" "${out}"
    note "secrets" ""
    return 0
  fi
  kit_upload # before $(remote ...) below: SSH and the kit copy are set up in this shell
  read_app_secrets
  data="$(data_on_instance)"
  state="$(python3 -I "${KIT_PY}" mail-state <"${cur}")"
  local -a args=()
  [[ "${data}" == yes ]] && args+=(--data-exists)
  if ((MAIL_PROMPT)); then
    prompt_mail
    args+=(--mail-lines "${WORK}/mail.lines" --refresh-mail)
  elif ((REFRESH_MAIL)) || [[ "${state}" == missing ]]; then
    fetch_ansh
    args+=(--mail-env "${WORK}/mail.env")
    ((REFRESH_MAIL)) && args+=(--refresh-mail)
  else
    log "mail login: kept from app-secrets (origin/ansh not read)"
  fi
  log "instance data volumes: ${data}"
  python3 -I "${KIT_PY}" merge-app-secrets --existing "${cur}" --out "${out}" ${args[@]+"${args[@]}"} || rc=$?
  rm -f "${WORK}/mail.env" "${WORK}/mail.lines"
  case "${rc}" in
    0)
      aws --region "${REGION}" secretsmanager put-secret-value --secret-id "${SECRET_PREFIX}/app-secrets" \
        --secret-string "file://${out}" --query VersionId --output text >/dev/null || die "put-secret-value failed"
      log "app-secrets updated (new version; the previous one stays as AWSPREVIOUS)"
      note "secrets" "app-secrets updated"
      ;;
    3) log "app-secrets unchanged"; note "secrets" "app-secrets unchanged" ;;
    *) die "app-secrets merge refused (above); nothing was written" ;;
  esac
  rm -f "${out}" "${cur}"
}

# ------------------------------------------------------------------------------------------------ images
ghcr_login() {
  if ((DRY)); then printf '[dry-run] gh auth token | docker login ghcr.io --password-stdin (throwaway DOCKER_CONFIG)\n'; return 0; fi
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh auth token | docker login ghcr.io -u "$(gh api user --jq .login 2>/dev/null || echo oauth)" --password-stdin >/dev/null ||
      die "docker login ghcr.io with the gh token failed (scope read:packages: gh auth refresh -s read:packages)"
  else
    die "gh is not signed in (gh auth login; scope read:packages): the backend and worker images come from GHCR"
  fi
}

ghcr_tag() { # the GHCR tag that has this commit's images: --ghcr-tag, else dev-/staging-/manual-<sha12>
  if [[ -n "${GHCR_TAG}" ]]; then printf '%s\n' "${GHCR_TAG}"; return 0; fi
  if ((DRY)); then printf 'dev-%s\n' "${SHA12}"; return 0; fi
  local t
  for t in "dev-${SHA12}" "staging-${SHA12}" "manual-${SHA12}"; do
    if docker buildx imagetools inspect "${GHCR}/devsecshield-backend:${t}" >/dev/null 2>&1; then
      log "GHCR images of ${SHA12}: ${GHCR}/devsecshield-*:${t}" >&2
      printf '%s\n' "${t}"
      return 0
    fi
  done
  die "no GHCR images for ${SHA12} (dev-, staging- or manual-${SHA12}): is the commit on dev/staging and its 'Publish images (GHCR)' run green? Or pass --ghcr-tag"
}

ecr_login_local() {
  if ((DRY)); then printf '[dry-run] aws ecr get-login-password | docker login %s --password-stdin (throwaway DOCKER_CONFIG)\n' "${REGISTRY}"; return 0; fi
  aws --region "${REGION}" ecr get-login-password | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null ||
    die "docker login to ECR failed"
}

ecr_has() { # <component> <tag>
  ((DRY)) && return 1
  aws --region "${REGION}" ecr describe-images --repository-name "${ECR_NS}/$(ecr_repo "$1")" --image-ids "imageTag=$2" \
    --query 'imageDetails[0].imageDigest' --output text >/dev/null 2>&1
}

# --platform on push / save / image inspect selects one platform of an image index; it exists only with the containerd
# image store (Docker Desktop's default for new installs), where a pull keeps the index. The classic store keeps the
# single pulled platform, and those commands take no --platform there.
CSTORE=""
containerd_store() {
  if [[ -z "${CSTORE}" ]]; then
    CSTORE=no
    if docker info --format '{{json .DriverStatus}}' 2>/dev/null | grep -q io.containerd.snapshotter; then CSTORE=yes; fi
  fi
  [[ "${CSTORE}" == yes ]]
}
push_supports_platform() { containerd_store && docker push --help 2>/dev/null | grep -q -- '--platform'; }

inspect_amd64() { # <format> <image>: docker image inspect of the linux/amd64 variant (containerd image store: an index)
  if containerd_store && docker image inspect --help 2>/dev/null | grep -q -- '--platform'; then
    docker image inspect --platform linux/amd64 -f "$1" "$2"
  else
    docker image inspect -f "$1" "$2"
  fi
}

check_amd64() { # <local image> <expected revision or empty>
  local arch rev
  arch="$(inspect_amd64 '{{.Os}}/{{.Architecture}}' "$1")"
  [[ "${arch}" == linux/amd64 ]] || die "$1 is ${arch}, not linux/amd64"
  rev="$(inspect_amd64 '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null || true)"
  if [[ -n "$2" && -n "${rev}" && "${rev}" != "<no value>" && "${rev}" != "$2" ]]; then
    die "$1 was built from ${rev}, not $2"
  fi
}

# The API URL is compiled into the browser chunks: read them out of the image (docker create + cp: no container runs,
# so no amd64 emulation is needed) and refuse an image built for another API before it can reach production. The
# instance checks the same again after its pull (remote.sh pull/deploy), also for a frontend already in ECR.
check_frontend_url() { # <local image>
  local cid hit
  cid="$(docker create --platform linux/amd64 "$1" 2>/dev/null || docker create "$1")" || die "docker create $1 failed"
  # grep -c reads the whole stream: grep -q would stop early, docker cp would die of SIGPIPE and pipefail say "no"
  hit="$(docker cp "${cid}:/frontend/.next/static" - 2>/dev/null | grep -acF "https://${API_HOST}" || true)"
  docker rm -f "${cid}" >/dev/null 2>&1 || true
  [[ "${hit:-0}" =~ ^[1-9] ]] || die "$1 does not contain https://${API_HOST} in /frontend/.next/static: built for another API URL; not pushed"
  log "$1: https://${API_HOST} is baked into the browser bundle"
}

push_ecr() { # <local image> <ecr ref>
  local -a plat=()
  if ((!DRY)) && push_supports_platform; then plat=(--platform linux/amd64); fi
  x docker tag "$1" "$2"
  x docker push -q ${plat[@]+"${plat[@]}"} "$2"
}

cmd_images() {
  step "images: ${SHA12:-<sha>} -> ${IMAGE_PREFIX}/*:<sha12> (linux/amd64)"
  resolve_sha
  docker_isolate
  ghcr_login
  ecr_login_local
  local tag c ref src
  tag="$(ghcr_tag)"
  for c in backend scan-worker dast-worker; do
    ref="$(ecr_ref "${c}" "${SHA12}")"
    if ecr_has "${c}" "${SHA12}"; then log "${ref} already in ECR (tags are written once)"; continue; fi
    src="${GHCR}/devsecshield-${c}:${tag}"
    log "${src} -> ${ref}"
    x docker pull -q --platform linux/amd64 "${src}"
    ((DRY)) || check_amd64 "${src}" "${SHA}"
    push_ecr "${src}" "${ref}"
  done
  ref="$(ecr_ref frontend "${SHA12}")"
  if ecr_has frontend "${SHA12}"; then
    log "${ref} already in ECR (the instance checks its API URL before starting it)"
  elif [[ -n "${FRONTEND_IMAGE}" ]]; then
    log "frontend from ${FRONTEND_IMAGE}"
    x docker pull -q --platform linux/amd64 "${FRONTEND_IMAGE}"
    if ((!DRY)); then check_amd64 "${FRONTEND_IMAGE}" ""; check_frontend_url "${FRONTEND_IMAGE}"; fi
    push_ecr "${FRONTEND_IMAGE}" "${ref}"
  else
    # NEXT_PUBLIC_BACKEND_URL is inlined into the browser bundle by `next build` (frontend/Dockerfile); the GHCR
    # dev/staging frontends carry http://localhost:8000 (.github/ci/ghcr_meta.py DEFAULT_API_URL). So the production
    # frontend is built here from the commit's own tree (git archive: no checkout, no uncommitted file).
    log "building the frontend of ${SHA12} for https://${API_HOST} (linux/amd64; a few minutes, longer under emulation)"
    if ((DRY)); then
      printf '[dry-run] git archive %s:frontend | docker buildx build --platform linux/amd64 --build-arg NEXT_PUBLIC_BACKEND_URL=https://%s --provenance=false --load -t %s -\n' \
        "${SHA}" "${API_HOST}" "${ref}"
    else
      git -C "${REPO_ROOT}" archive --format=tar "${SHA}:frontend" |
        docker buildx build --platform linux/amd64 --build-arg "NEXT_PUBLIC_BACKEND_URL=https://${API_HOST}" \
          --label "org.opencontainers.image.revision=${SHA}" --label "com.zeroshield.devsecshield.api-url=https://${API_HOST}" \
          --provenance=false --load -t "${ref}" - || die "frontend build failed"
      check_amd64 "${ref}" "${SHA}"
      check_frontend_url "${ref}"
    fi
    local -a plat=()
    if ((!DRY)) && push_supports_platform; then plat=(--platform linux/amd64); fi
    x docker push -q ${plat[@]+"${plat[@]}"} "${ref}"
  fi
  note "images" "${IMAGE_PREFIX}/{devsecshield-backend,devsecshield-frontend,scan-worker,dast-worker}:${SHA12}"
}

# ------------------------------------------------------------------------------------------------ infrastructure images
cmd_infra() {
  step "infra: release archive of the infrastructure images"
  ssh_setup # here, not inside $(remote ...) below
  local missing="" i
  if ((DRY)); then
    remote infra-missing
    missing="(dry-run)"
  else
    kit_upload
    missing="$(remote infra-missing | paste -sd' ' -)" || die "cannot list the instance's images (above)"
  fi
  if [[ -z "${missing}" && "${FORCE_INFRA}" != 1 ]]; then
    log "the instance has every infrastructure image: no archive needed"
    note "infra" "already loaded"
    return 0
  fi
  log "instance lacks: ${missing:-nothing (--force-infra)}"
  work
  local tar="${WORK}/release.tar" sum
  local -a plat=() tags=()
  # pulled by digest, shipped under the tag the compose file runs
  for i in "${INFRA_IMAGES[@]}"; do
    x docker pull -q --platform linux/amd64 "${i}"
    x docker tag "${i}" "$(infra_tag "${i}")"
    tags+=("$(infra_tag "${i}")")
  done
  if ((!DRY)) && containerd_store && docker save --help 2>/dev/null | grep -q -- '--platform'; then plat=(--platform linux/amd64); fi
  if ((!DRY)); then for i in "${tags[@]}"; do check_amd64 "${i}" ""; done; fi
  x docker save ${plat[@]+"${plat[@]}"} -o "${tar}" "${tags[@]}"
  if ((DRY)); then sum="<sha256>"; else sum="$(sha256sum "${tar}" 2>/dev/null || shasum -a 256 "${tar}")"; sum="${sum%% *}"; fi
  log "release archive sha256 ${sum}"
  # s3api put-object: one PUT (the archive is ~2.5 GB, under the 5 GB limit) with the bucket owner pinned
  aws_ s3api put-object --bucket "${BUCKET}" --key "${RELEASE_KEY}" --body "${tar}" --expected-bucket-owner "${ACCOUNT}" \
    --query ETag --output text
  remote_job infra-load "${RELEASE_KEY}" "${sum}" || die "loading the release archive on the instance failed (above)"
  x rm -f "${tar}"
  note "infra" "release archive uploaded (s3://${BUCKET}/${RELEASE_KEY}) and loaded"
}

# ------------------------------------------------------------------------------------------------ backup
cmd_backup() {
  step "backup: logical dumps, then AWS Backup of ${VOLUME_ID} (wait for COMPLETED)"
  remote_job dump || die "the logical dumps failed (above); not continuing"
  local job state pct waited=0 timeout=${CHOLA_BACKUP_TIMEOUT_S:-7200} fails=0 max=${CHOLA_POLL_RETRIES:-10} out
  if ((DRY)); then
    aws_ backup start-backup-job --backup-vault-name "${BACKUP_VAULT}" \
      --resource-arn "arn:aws:ec2:${REGION}:${ACCOUNT}:volume/${VOLUME_ID}" --iam-role-arn "${BACKUP_ROLE}" \
      --lifecycle DeleteAfterDays=14 --recovery-point-tags "${BACKUP_TAGS}" --query BackupJobId --output text
    printf '[dry-run] every 30 s: aws backup describe-backup-job --backup-job-id <id> --query "[State,PercentDone]" until COMPLETED\n'
    note "backup" ""
    return 0
  fi
  job="$(aws --region "${REGION}" backup start-backup-job --backup-vault-name "${BACKUP_VAULT}" \
    --resource-arn "arn:aws:ec2:${REGION}:${ACCOUNT}:volume/${VOLUME_ID}" --iam-role-arn "${BACKUP_ROLE}" \
    --lifecycle DeleteAfterDays=14 --recovery-point-tags "${BACKUP_TAGS}" --query BackupJobId --output text)" ||
    die "start-backup-job failed (AccessDenied: iam:PassRole on ${BACKUP_ROLE##*/} or backup:StartBackupJob is missing)"
  log "backup job ${job} started"
  while :; do
    if out="$(aws --region "${REGION}" backup describe-backup-job --backup-job-id "${job}" --query '[State,PercentDone]' \
      --output text 2>"${WORK}/err")"; then
      fails=0
      read -r state pct <<<"${out}"
      log "backup ${job}: ${state} ${pct:-}%"
      case "${state}" in
        COMPLETED) break ;;
        FAILED | ABORTED | EXPIRED | PARTIAL)
          die "backup job ${job} ended ${state}: not deploying ($(aws --region "${REGION}" backup describe-backup-job --backup-job-id "${job}" --query StatusMessage --output text 2>/dev/null || echo 'no status message'))" ;;
      esac
    else
      fails=$((fails + 1))
      ((fails < max)) || die "describe-backup-job failed ${max} times in a row ($(tail -n 1 "${WORK}/err")); the job ${job} may still finish: aws backup describe-backup-job --backup-job-id ${job}"
      warn "describe-backup-job failed (${fails}/${max}: $(tail -n 1 "${WORK}/err")); retrying"
    fi
    ((waited < timeout)) || die "backup job ${job} not COMPLETED after ${timeout} s; not deploying"
    sleep "${CHOLA_POLL_S:-30}"
    waited=$((waited + ${CHOLA_POLL_S:-30} + 1))
  done
  note "backup" "job ${job} COMPLETED (recovery point kept 14 days)"
}

# ------------------------------------------------------------------------------------------------ verify
cmd_verify() {
  step "verify"
  local i out code body hdr ip fails=0 max=${CHOLA_POLL_RETRIES:-10}
  if ((DRY)); then
    printf '[dry-run] aws elbv2 describe-target-health --target-group-arn %s (instance or ip target; wait for healthy)\n' "${TG_ARN}"
    remote check
    printf '[dry-run] curl -sS -I https://%s ; curl -sS https://%s/health\n' "${FRONTEND_HOST}" "${API_HOST}"
    note "verify" ""
    return 0
  fi
  # A target group of type instance lists the instance id, one of type ip its private address.
  ip="$(aws --region "${REGION}" ec2 describe-instances --instance-ids "${INSTANCE_ID}" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text 2>/dev/null || true)"
  i=0
  while :; do
    if out="$(target_health_line 2>"${WORK}/err")"; then
      fails=0
      if [[ "${out}" == *"${INSTANCE_ID} 80 healthy"* || (-n "${ip}" && "${out}" == *"${ip} 80 healthy"*) ]]; then break; fi
      i=$((i + 1))
      ((i < 30)) || die "ALB target not healthy after 5 minutes: ${out} (README 'Troubleshooting: target unhealthy')"
      log "ALB target: ${out} (waiting)"
    else
      fails=$((fails + 1))
      ((fails < max)) || die "describe-target-health failed ${max} times in a row: $(tail -n 1 "${WORK}/err")"
      warn "describe-target-health failed (${fails}/${max}: $(tail -n 1 "${WORK}/err")); retrying"
    fi
    sleep "${CHOLA_POLL_S:-10}"
  done
  log "ALB target: ${out}"
  remote check
  out="$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" 'curl -sS --noproxy "*" --max-time 10 http://localhost/nginx-health')" ||
    die "curl http://localhost/nginx-health on the instance failed"
  [[ "${out}" == ok ]] || die "curl http://localhost/nginx-health on the instance -> '${out}'"
  log "instance: curl http://localhost/nginx-health -> ok"
  hdr="$(curl -sS -I --max-time 30 "https://${FRONTEND_HOST}/login" | tr -d '\r')" || die "https://${FRONTEND_HOST}/login unreachable"
  code="$(printf '%s' "${hdr}" | awk 'NR == 1 { print $2 }')"
  [[ "${code}" == 200 ]] || die "https://${FRONTEND_HOST}/login -> HTTP ${code}"
  printf '%s' "${hdr}" | grep -qi '^strict-transport-security:' || warn "no HSTS header on https://${FRONTEND_HOST}"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -I "https://${FRONTEND_HOST}")" || code=000
  log "https://${FRONTEND_HOST} -> ${code}; /login -> 200"
  body="$(curl -sS --max-time 30 -w '\n%{http_code}' "https://${API_HOST}/health")" || die "https://${API_HOST}/health unreachable"
  code="${body##*$'\n'}"
  [[ "${code}" == 200 && "${body}" == *'"healthy"'* ]] || die "https://${API_HOST}/health -> HTTP ${code}"
  log "https://${API_HOST}/health -> 200 healthy"
  note "verify" "ALB target healthy, nginx-health ok, https://${FRONTEND_HOST}/login 200, https://${API_HOST}/health 200"
}

# ------------------------------------------------------------------------------------------------ deploy / rollback
confirm() { # <what>
  ((YES || DRY)) && return 0
  [[ -t 0 ]] || die "$1 needs confirmation: run it in a terminal or pass --yes"
  local a
  read -r -p "[chola] $1 on PRODUCTION (${INSTANCE_ID}). Type 'chola' to continue: " a || a=""
  [[ "${a}" == chola ]] || die "aborted"
}

cmd_deploy() {
  resolve_sha
  confirm "Deploy ${SHA12}"
  step "deploy ${SHA12} to ${FRONTEND_HOST} / ${API_HOST}"
  local_preflight
  aws_identity
  aws_resources
  kit_upload with-overlay
  remote preflight
  cmd_secrets
  cmd_images
  step "environment and images on the instance"
  remote render "${SHA12}"
  remote ecr-login
  remote pull "${SHA12}"
  note "instance" "env rendered from Secrets Manager (instance role), images of ${SHA12} pulled, frontend URL checked"
  cmd_infra
  cmd_backup
  step "migrate and start ${SHA12} (detached on the instance)"
  remote_job deploy "${SHA12}" || die "the deploy of ${SHA12} failed on the instance (above); to go back: ${0##*/} rollback"
  note "deploy" "${SHA12} running, migrations applied, services healthy"
  step "SMTP login test"
  if ((DRY)); then remote smtp-test; note "smtp" ""; elif remote smtp-test; then note "smtp" "Office 365 login OK"; else
    warn "SMTP login FAILED (above): sign-in codes cannot be mailed until it works (README 'Troubleshooting: SMTP AUTH')"
    note "smtp" "FAILED - see above"
  fi
  cmd_verify
}

cmd_rollback() {
  confirm "Roll back"
  step "rollback"
  aws_identity
  cmd_backup
  remote ecr-login
  local rc=0
  if ((DRY)); then
    remote rollback --plan
  elif remote rollback --plan; then
    rc=0
  else
    rc=$?
  fi
  if [[ "${rc}" == 3 && "${ALLOW_DOWNGRADE}" != 1 ]]; then
    [[ -t 0 ]] || die "the rollback needs the database downgrade listed above; re-run with --allow-downgrade"
    local a
    read -r -p "[chola] Type 'downgrade' to run it (it drops the data those migrations added): " a || a=""
    [[ "${a}" == downgrade ]] || die "aborted; nothing was changed"
    ALLOW_DOWNGRADE=1
  elif [[ "${rc}" != 0 && "${rc}" != 3 ]]; then
    die "cannot plan the rollback (above); nothing was changed"
  fi
  local -a args=()
  ((ALLOW_DOWNGRADE)) && args=(--allow-downgrade)
  remote_job rollback ${args[@]+"${args[@]}"} || die "the rollback failed on the instance (above)"
  note "rollback" "done"
  cmd_verify
}

cmd_attach() {
  [[ -n "${JOB}" ]] || die "attach needs --job <id> (status lists recent jobs)"
  kit_upload
  if ((DRY)); then printf '[dry-run] follow job %s\n' "${JOB}"; return 0; fi
  local rc=0
  follow_job "${JOB}" || rc=$?
  log "job ${JOB} ended with exit ${rc}"
  return "${rc}"
}

summary() {
  ((${#SUMMARY[@]})) || return 0
  printf '\n[chola] ==== summary%s\n' "$( ((DRY)) && echo ' (dry-run: nothing was run or changed)')"
  local s
  for s in "${SUMMARY[@]}"; do printf '  - %s\n' "${s}"; done
}

main() {
  parse_args "$@"
  if ((HELP)) || [[ -z "${CMD}" || "${CMD}" == help ]]; then usage; return 0; fi
  ((DRY)) && log "dry-run: printing the steps; no AWS, SSH, Docker, registry or git-fetch command is run, no secret read"
  case "${CMD}" in
    preflight) cmd_preflight ;;
    host-setup) cmd_host_setup ;;
    secrets) aws_identity; cmd_secrets ;;
    images) aws_identity; cmd_images ;;
    infra) aws_identity; cmd_infra ;;
    backup) aws_identity; cmd_backup ;;
    deploy) cmd_deploy ;;
    verify) cmd_verify ;;
    rollback) cmd_rollback ;;
    attach) cmd_attach ;;
    smtp-test) remote smtp-test ;;
    admin) [[ -n "${EMAIL}" ]] || die "admin needs --email"; remote admin "${EMAIL}"; note "admin" "${EMAIL} is platform administrator" ;;
    status)
      remote status
      if ((!DRY)); then log "ALB target: $(target_health_line || echo 'describe-target-health failed')"; fi
      ;;
    logs) remote logs "${SERVICE:-all}" "${TAIL}" ;;
    *) die "unknown command ${CMD} (see --help)" ;;
  esac
  summary
}

main "$@"
