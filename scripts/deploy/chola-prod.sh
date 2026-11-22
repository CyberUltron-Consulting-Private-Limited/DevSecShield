#!/usr/bin/env bash
# chola-prod.sh - deploy DevSecShield to the Chola production instance from the owner's machine
# (deploy/chola-prod/README.md). Uses the caller's own AWS credentials (AWS CLI v2; AWS_PROFILE is honoured); never
# prints, stores or commits a secret value.
#
#   chola-prod.sh preflight [--sha S]       local tools, AWS identity and resources (read-only), the mail source in
#                                           origin/ansh, GHCR images of S, SSH over EC2 Instance Connect, the instance
#   chola-prod.sh host-setup                once, only if preflight says the instance has no AWS CLI: installs AWS CLI v2
#                                           from an installer downloaded HERE (the instance cannot reach the download)
#   chola-prod.sh secrets [--refresh-mail]  fill devsec-chola/prod/app-secrets: generate what is missing (CSPRNG), keep
#                                           every existing value, mail login from origin/ansh:backend/.env
#   chola-prod.sh images --sha S            backend, scan-worker, dast-worker from GHCR (<prefix>-<sha12>, linux/amd64),
#                                           the frontend BUILT here for https://chola-api.zeroshield.ai (its API URL is
#                                           baked in at build time); all four pushed to ECR as :<sha12>
#   chola-prod.sh infra [--force-infra]     the infrastructure images (postgres, mongo, rabbitmq, nginx, qdrant) as
#                                           s3://devsecshield-storage/releases/release.tar, loaded on the instance;
#                                           only when the instance lacks one of them (or --force-infra)
#   chola-prod.sh backup                    logical dumps on the instance, then the on-demand AWS Backup job of the data
#                                           volume; waits for COMPLETED
#   chola-prod.sh deploy --sha S [--yes]    everything above in order (preflight, secrets, images, files, env, ECR login,
#                                           pull, infra, backup, migrate + up, health), then smtp-test and verify
#   chola-prod.sh verify                    ALB target health, nginx-health on the instance, both public URLs
#   chola-prod.sh rollback [--allow-downgrade] [--yes]
#                                           backup, then back to the previously deployed tag (a database downgrade only
#                                           with --allow-downgrade or typed confirmation), then verify
#   chola-prod.sh smtp-test                 SMTP login from the instance with the deployed settings (sends nothing)
#   chola-prod.sh admin --email E           make the signed-up account E the platform administrator
#   chola-prod.sh status | logs [--service S] [--tail N]
#
# Global: --dry-run prints every step (AWS, SSH, Docker, GHCR commands) without running any of them.
# Env (defaults are the Chola values): CHOLA_ACCOUNT, CHOLA_REGION, CHOLA_INSTANCE_ID, CHOLA_TG_ARN,
# CHOLA_KNOWN_HOSTS (default ~/.ssh/known_hosts_devsec_chola), CHOLA_WORK_PARENT (scratch, default $TMPDIR),
# CHOLA_BACKUP_TIMEOUT_S (default 7200), CHOLA_GHCR (default ghcr.io/cyberultron-consulting-private-limited).
set -euo pipefail
export LC_ALL=C

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
# Same list as deploy/chola-prod/remote.sh and the images of deploy/chola-prod/docker-compose.yml (tested).
INFRA_IMAGES=(postgres:15-alpine mongo:8.0.6 rabbitmq:4.1-management-alpine nginx:1.27-alpine qdrant/qdrant:v1.13.5)
COMPONENTS=(backend frontend scan-worker dast-worker)

DRY=0 YES=0 SHA="" SHA12="" GHCR_TAG="" FRONTEND_IMAGE="" FORCE_INFRA=0 ALLOW_DOWNGRADE=0 REFRESH_MAIL=0
EMAIL="" SERVICE="" TAIL=200
WORK=""
SSH_READY=0
declare -a SSH_OPTS=()
declare -a SUMMARY=()

log() { printf '[chola %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
warn() { printf '[chola %s] WARNING: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { printf '[chola] ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n[chola] ==== %s\n' "$*"; }
note() { if ((DRY)); then SUMMARY+=("[dry-run] $*"); else SUMMARY+=("$*"); fi; }

quote() { local a out=""; for a in "$@"; do out+="$(printf '%q' "${a}") "; done; printf '%s' "${out% }"; }
# x <command...>: run it, or print it with --dry-run. Every command that touches AWS, SSH, Docker or a registry goes
# through x (or checks DRY itself).
x() {
  if ((DRY)); then printf '[dry-run] %s\n' "$(quote "$@")"; return 0; fi
  "$@"
}
ecr_repo() { case "$1" in backend | frontend) printf 'devsecshield-%s\n' "$1" ;; *) printf '%s\n' "$1" ;; esac; }
ecr_ref() { printf '%s/%s:%s\n' "${IMAGE_PREFIX}" "$(ecr_repo "$1")" "$2"; }

cleanup() {
  local rc=$?
  if [[ -n "${WORK}" && -d "${WORK}" ]]; then
    if ((SSH_READY && !DRY)); then ssh "${SSH_OPTS[@]}" -O exit "${SSH_USER}@${INSTANCE_ID}" >/dev/null 2>&1 || true; fi
    rm -rf -- "${WORK}" # the SSH key, the mail source copy, the merged secret JSON, the release archive
  fi
  return "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
parse_args() {
  while (($#)); do
    case "$1" in
      --sha) [[ $# -ge 2 ]] || die "--sha needs a commit"; SHA=$2; shift 2 ;;
      --dry-run) DRY=1; shift ;;
      --yes) YES=1; shift ;;
      --ghcr-tag) [[ $# -ge 2 ]] || die "--ghcr-tag needs a tag"; GHCR_TAG=$2; shift 2 ;;
      --frontend-image) [[ $# -ge 2 ]] || die "--frontend-image needs an image"; FRONTEND_IMAGE=$2; shift 2 ;;
      --force-infra) FORCE_INFRA=1; shift ;;
      --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
      --refresh-mail) REFRESH_MAIL=1; shift ;;
      --email) [[ $# -ge 2 ]] || die "--email needs an address"; EMAIL=$2; shift 2 ;;
      --service) [[ $# -ge 2 ]] || die "--service needs a name"; SERVICE=$2; shift 2 ;;
      --tail) [[ $# -ge 2 && "$2" =~ ^[0-9]{1,6}$ ]] || die "--tail needs a number"; TAIL=$2; shift 2 ;;
      *) die "unknown option $1 (see --help)" ;;
    esac
  done
  [[ -z "${GHCR_TAG}" || "${GHCR_TAG}" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || die "--ghcr-tag ${GHCR_TAG} is not a tag"
  [[ -z "${SERVICE}" || "${SERVICE}" =~ ^[a-z0-9-]{1,40}$ ]] || die "--service ${SERVICE} is not a service name"
}

resolve_sha() {
  [[ -n "${SHA}" ]] || die "give --sha <commit>"
  [[ "${SHA}" =~ ^[0-9a-fA-F]{7,40}$ ]] || die "--sha must be a commit id"
  if ! git -C "${REPO_ROOT}" cat-file -e "${SHA}^{commit}" 2>/dev/null; then
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
    -o ServerAliveInterval=30 -o ConnectTimeout=90)
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
  log "SSH: ${SSH_USER}@${INSTANCE_ID} through EC2 Instance Connect Endpoint (key from ${SECRET_PREFIX}/ssh-admin, removed on exit)"
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" true ||
    die "SSH to ${INSTANCE_ID} failed (README 'Troubleshooting: EICE tunnel')"
  SSH_READY=1
}

# remote <remote.sh args...>: run deploy/chola-prod/remote.sh on the instance with the kit settings.
remote() {
  ssh_setup
  local cmd tty=()
  cmd="cd $(quote "${REMOTE_DIR}") && CHOLA_REGION=$(quote "${REGION}") CHOLA_REGISTRY=$(quote "${REGISTRY}")"
  cmd+=" CHOLA_IMAGE_PREFIX=$(quote "${IMAGE_PREFIX}") CHOLA_SECRET_PREFIX=$(quote "${SECRET_PREFIX}")"
  cmd+=" CHOLA_FRONTEND_HOST=$(quote "${FRONTEND_HOST}") CHOLA_API_HOST=$(quote "${API_HOST}")"
  cmd+=" CHOLA_REAL_IP_FROM=$(quote "${REAL_IP_FROM}") bash deploy/chola-prod/remote.sh $(quote "$@")"
  [[ "${1:-}" == rollback && -t 0 ]] && tty=(-t)
  if ((DRY)); then
    printf '[dry-run] ssh (EICE tunnel, key from %s/ssh-admin) %s@%s: cd %s && CHOLA_*=... bash deploy/chola-prod/remote.sh %s\n' \
      "${SECRET_PREFIX}" "${SSH_USER}" "${INSTANCE_ID}" "${REMOTE_DIR}" "$(quote "$@")"
    return 0
  fi
  # shellcheck disable=SC2029 # the remote command line is built here on purpose (every word quoted with %q)
  ssh ${tty[@]+"${tty[@]}"} "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" "${cmd}"
}

# The kit files (this checkout) and, with a commit, compose/aibom-config-overlay of that commit (the backend reads it,
# so it must match the image). Never an env file.
upload_files() { # [with-overlay]
  ssh_setup
  local stage="${WORK}/bundle" with=${1:-}
  rm -rf "${stage}"
  mkdir -p "${stage}/deploy"
  tar -C "${REPO_ROOT}" --exclude='deploy/chola-prod/*.env' --exclude='deploy/chola-prod/.env' --exclude='__pycache__' \
    -cf - deploy/chola-prod | tar -C "${stage}" -xf -
  if [[ "${with}" == with-overlay ]]; then
    if git -C "${REPO_ROOT}" cat-file -e "${SHA}:compose/aibom-config-overlay" 2>/dev/null; then
      git -C "${REPO_ROOT}" archive --format=tar "${SHA}" compose/aibom-config-overlay | tar -C "${stage}" -xf -
    else
      warn "${SHA12} has no compose/aibom-config-overlay: using this checkout's"
      tar -C "${REPO_ROOT}" -cf - compose/aibom-config-overlay | tar -C "${stage}" -xf -
    fi
  fi
  if [[ -n "$(git -C "${REPO_ROOT}" status --porcelain -- deploy/chola-prod scripts/deploy/chola-prod.sh)" ]]; then
    warn "the kit files in this checkout have uncommitted changes; they are what gets copied"
  fi
  local dirs=(deploy)
  [[ "${with}" == with-overlay ]] && dirs+=(compose)
  local what="the kit files"
  [[ "${with}" == with-overlay ]] && what+=" and the aibom-config-overlay of ${SHA12}"
  log "copying ${what} to ${INSTANCE_ID}:${REMOTE_DIR}"
  if ((DRY)); then
    printf '[dry-run] tar -C %s -czf - %s | ssh ... %s@%s "sudo mkdir -p %s && sudo chown ubuntu: %s && tar -xzf - -C %s"\n' \
      "${stage}" "${dirs[*]}" "${SSH_USER}" "${INSTANCE_ID}" "${REMOTE_DIR}" "${REMOTE_DIR}" "${REMOTE_DIR}"
    return 0
  fi
  # shellcheck disable=SC2029 # expanded here on purpose (quoted with %q)
  tar -C "${stage}" -czf - "${dirs[@]}" | ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" \
    "sudo -n mkdir -p $(quote "${REMOTE_DIR}") && sudo -n chown $(quote "${SSH_USER}:${SSH_USER}") $(quote "${REMOTE_DIR}") && chmod 750 $(quote "${REMOTE_DIR}") && tar -xzf - -C $(quote "${REMOTE_DIR}") && chmod 700 $(quote "${REMOTE_DIR}/deploy/chola-prod")"
}

# ------------------------------------------------------------------------------------------------ preflight
need() { command -v "$1" >/dev/null 2>&1 || { if ((DRY)); then warn "$1 not found (needed for a real run)"; else die "$1 is not installed"; fi; }; }

local_preflight() {
  local v
  for v in aws docker git python3 curl ssh tar; do need "${v}"; done
  if ((DRY)); then
    printf '[dry-run] aws --version (2.12+ for ec2-instance-connect open-tunnel)\n'
  elif command -v aws >/dev/null 2>&1; then
    v="$(aws --version 2>&1 | sed -n -E 's|^aws-cli/([0-9]+)\.([0-9]+)\..*|\1 \2|p')"
    read -r major minor <<<"${v:-0 0}"
    ((major >= 2 && (major > 2 || minor >= 12))) || die "AWS CLI v2.12+ is needed (ec2-instance-connect open-tunnel); found $(aws --version 2>&1 | cut -d' ' -f1)"
  fi
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || die "python3 3.8+ is needed"
  git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1 || die "${REPO_ROOT} is not a git checkout"
  git -C "${REPO_ROOT}" fetch -q origin ansh || die "git fetch origin ansh failed (the mail login is read from origin/ansh)"
  local keys
  keys="$(git -C "${REPO_ROOT}" show origin/ansh:backend/.env 2>/dev/null | python3 -I -c '
import sys, importlib.util
spec = importlib.util.spec_from_file_location("kit", sys.argv[1]); kit = importlib.util.module_from_spec(spec); spec.loader.exec_module(kit)
env = kit.parse_dotenv(sys.stdin.read())
print(" ".join(k for k in ("OUTLOOK_EMAIL", "OUTLOOK_PASSWORD") if env.get(k)))' "${KIT_PY}")" || keys=""
  [[ "${keys}" == "OUTLOOK_EMAIL OUTLOOK_PASSWORD" ]] || die "origin/ansh:backend/.env lacks OUTLOOK_EMAIL / OUTLOOK_PASSWORD (found: ${keys:-none})"
  log "mail source origin/ansh:backend/.env has OUTLOOK_EMAIL and OUTLOOK_PASSWORD (values not shown)"
  if ((DRY)); then
    printf '[dry-run] docker info; docker buildx version; gh auth status\n'
  else
    docker info >/dev/null 2>&1 || die "Docker is not running"
    docker buildx version >/dev/null 2>&1 || die "docker buildx is missing (needed to build the linux/amd64 frontend)"
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
      log "gh: signed in (GHCR login uses its token; it needs the read:packages scope: gh auth refresh -s read:packages)"
    else
      warn "gh is not signed in: GHCR pulls need 'docker login ghcr.io' done by hand (a token with read:packages)"
    fi
  fi
}

aws_identity() {
  if ((DRY)); then printf '[dry-run] aws sts get-caller-identity (account must be %s)\n' "${ACCOUNT}"; return 0; fi
  local id
  id="$(aws sts get-caller-identity --query '[Account,Arn]' --output text)" || die "no AWS credentials (aws configure / AWS_PROFILE)"
  [[ "${id%%[[:space:]]*}" == "${ACCOUNT}" ]] || die "AWS account is ${id%%[[:space:]]*}, not ${ACCOUNT} (wrong AWS_PROFILE?)"
  log "AWS identity: ${id##*[[:space:]]}"
}

aws_resources() {
  if ((DRY)); then
    printf '[dry-run] aws ec2 describe-instances %s (state, MetadataOptions); aws elbv2 describe-target-groups/-health;\n' "${INSTANCE_ID}"
    printf '[dry-run] aws secretsmanager describe-secret (4 secrets); aws ecr describe-repositories (4); aws backup describe-backup-vault\n'
    return 0
  fi
  local out s r
  out="$(aws --region "${REGION}" ec2 describe-instances --instance-ids "${INSTANCE_ID}" --query \
    'Reservations[0].Instances[0].[State.Name,InstanceType,PrivateIpAddress,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit,MetadataOptions.HttpEndpoint]' --output text)" ||
    die "cannot describe ${INSTANCE_ID}"
  read -r state itype ip tokens hop endpoint <<<"${out}"
  log "instance ${INSTANCE_ID}: ${state}, ${itype}, ${ip}; IMDS ${endpoint} tokens=${tokens} hop-limit=${hop}"
  [[ "${state}" == running ]] || die "the instance is ${state}"
  [[ "${tokens}" == required ]] || warn "IMDSv1 is allowed (HttpTokens=${tokens}): any container can read the instance role's credentials; ask for HttpTokens=required"
  ((hop <= 1)) || warn "HttpPutResponseHopLimit=${hop}: containers can obtain instance-role credentials (which read every ${SECRET_PREFIX} secret). The app does not need it (S3/Bedrock use the app-user keys): ask the infra team for hop limit 1"
  out="$(aws --region "${REGION}" elbv2 describe-target-groups --target-group-arns "${TG_ARN}" --query \
    'TargetGroups[0].[Protocol,Port,HealthCheckPath,HealthCheckPort,Matcher.HttpCode]' --output text)" || die "cannot read the target group"
  log "target group: ${out//$'\t'/ } (expect HTTP 80 /nginx-health)"
  [[ "${out}" == *"/nginx-health"* ]] || warn "the target group health check path is not /nginx-health"
  log "target health: $(target_health_line)"
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
  aws --region "${REGION}" backup describe-backup-vault --backup-vault-name "${BACKUP_VAULT}" --query BackupVaultName --output text >/dev/null ||
    die "cannot see backup vault ${BACKUP_VAULT}"
  log "backup vault ${BACKUP_VAULT} visible"
}

target_health_line() {
  aws --region "${REGION}" elbv2 describe-target-health --target-group-arn "${TG_ARN}" --query \
    'TargetHealthDescriptions[].[Target.Id,Target.Port,TargetHealth.State,TargetHealth.Reason]' --output text | tr '\t\n' ' ;'
}

cmd_preflight() {
  step "preflight"
  local_preflight
  aws_identity
  aws_resources
  if [[ -n "${SHA}" ]]; then resolve_sha; ghcr_login; ghcr_tag >/dev/null; fi
  upload_files
  remote preflight
  note "preflight: OK"
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
  if ((DRY)); then printf '[dry-run] tar -C %s -czf - aws | ssh ... "sudo ./aws/install --update"\n' "${d}"; return 0; fi
  tar -C "${d}" -czf - aws | ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" \
    't=$(mktemp -d) && tar -xzf - -C "$t" && sudo -n "$t/aws/install" --update && rm -rf "$t" && aws --version'
  note "host-setup: AWS CLI installed on the instance"
}

# ------------------------------------------------------------------------------------------------ secrets
cmd_secrets() {
  step "secrets: ${SECRET_PREFIX}/app-secrets (generated values kept across runs)"
  work
  local cur="${WORK}/app-secrets.json" mail="${WORK}/mail.env" out="${WORK}/app-secrets.new.json" rc=0 err
  if ((DRY)); then
    printf '[dry-run] git show origin/ansh:backend/.env > %s (mode 600, scratch; OUTLOOK_EMAIL / OUTLOOK_PASSWORD)\n' "${mail}"
    printf '[dry-run] aws secretsmanager get-secret-value --secret-id %s/app-secrets > %s\n' "${SECRET_PREFIX}" "${cur}"
    printf '[dry-run] python3 kit.py merge-app-secrets (generate missing: JWT x2, ENCRYPTION_KEY, CERTIN_HMAC_SECRET, PG/Mongo/RabbitMQ passwords, QDRANT_API_KEY; keep existing; mail from origin/ansh)\n'
    printf '[dry-run] aws secretsmanager put-secret-value --secret-id %s/app-secrets --secret-string file://%s (only when changed)\n' "${SECRET_PREFIX}" "${out}"
    note "secrets: dry-run"
    return 0
  fi
  git -C "${REPO_ROOT}" fetch -q origin ansh || die "git fetch origin ansh failed"
  # The mailbox login is read at run time from this checkout's origin/ansh into the scratch directory, never into the repo.
  (umask 077 && git -C "${REPO_ROOT}" show origin/ansh:backend/.env >"${mail}") || die "cannot read origin/ansh:backend/.env"
  if ! (umask 077 && aws --region "${REGION}" secretsmanager get-secret-value --secret-id "${SECRET_PREFIX}/app-secrets" \
    --query SecretString --output text >"${cur}" 2>"${WORK}/err"); then
    err="$(tail -n 1 "${WORK}/err")"
    # A secret created without a value has no AWSCURRENT version yet: start from {}.
    [[ "${err}" == *ResourceNotFoundException* && "${err}" == *AWSCURRENT* ]] || die "cannot read ${SECRET_PREFIX}/app-secrets: ${err}"
    printf '{}' >"${cur}"
    log "app-secrets has no value yet"
  fi
  # A database volume on the instance with no stored password would be locked out by newly generated ones.
  if ! grep -q '"PG_USER_PASS"' "${cur}"; then
    if remote volume-exists 2>/dev/null; then
      die "app-secrets holds no PG_USER_PASS but the instance already has a database volume: generating new database" \
        "passwords would lock the application out. Restore the earlier app-secrets version (Secrets Manager keeps it as" \
        "AWSPREVIOUS) instead."
    fi
  fi
  local -a refresh=()
  ((REFRESH_MAIL)) && refresh=(--refresh-mail)
  python3 -I "${KIT_PY}" merge-app-secrets --existing "${cur}" --mail-env "${mail}" --out "${out}" ${refresh[@]+"${refresh[@]}"} || rc=$?
  rm -f "${mail}"
  case "${rc}" in
    0)
      aws --region "${REGION}" secretsmanager put-secret-value --secret-id "${SECRET_PREFIX}/app-secrets" \
        --secret-string "file://${out}" --query VersionId --output text >/dev/null || die "put-secret-value failed"
      log "app-secrets updated (new version; the previous one stays as AWSPREVIOUS)"
      note "secrets: app-secrets updated"
      ;;
    3) log "app-secrets unchanged"; note "secrets: app-secrets unchanged" ;;
    *) die "app-secrets merge refused (above); nothing was written" ;;
  esac
  rm -f "${out}" "${cur}"
}

# ------------------------------------------------------------------------------------------------ images
ghcr_login() {
  if ((DRY)); then printf '[dry-run] gh auth token | docker login ghcr.io --password-stdin\n'; return 0; fi
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh auth token | docker login ghcr.io -u "$(gh api user --jq .login 2>/dev/null || echo oauth)" --password-stdin >/dev/null ||
      die "docker login ghcr.io with the gh token failed"
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
  if ((DRY)); then printf '[dry-run] aws ecr get-login-password | docker login %s --password-stdin\n' "${REGISTRY}"; return 0; fi
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
# so no amd64 emulation is needed) and refuse an image built for another API before it can reach production.
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
  step "images: ${SHA12} -> ${IMAGE_PREFIX}/*:${SHA12} (linux/amd64)"
  resolve_sha
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
    log "${ref} already in ECR"
  elif [[ -n "${FRONTEND_IMAGE}" ]]; then
    log "frontend from ${FRONTEND_IMAGE} (it must have been built with NEXT_PUBLIC_BACKEND_URL=https://${API_HOST}; the deploy checks)"
    x docker pull -q --platform linux/amd64 "${FRONTEND_IMAGE}"
    if ((!DRY)); then check_amd64 "${FRONTEND_IMAGE}" ""; check_frontend_url "${FRONTEND_IMAGE}"; fi
    push_ecr "${FRONTEND_IMAGE}" "${ref}"
  else
    # NEXT_PUBLIC_BACKEND_URL is inlined into the browser bundle by `next build` (frontend/Dockerfile); the GHCR
    # dev/staging frontends carry http://localhost:8000 (.github/ci/ghcr_meta.py DEFAULT_API_URL). So the production
    # frontend is built here from the commit's own tree (git archive: no checkout, no uncommitted file).
    log "building the frontend of ${SHA12} for https://${API_HOST} (linux/amd64; a few minutes, longer under emulation)"
    if ((DRY)); then
      printf '[dry-run] git archive %s:frontend | docker buildx build --platform linux/amd64 --build-arg NEXT_PUBLIC_BACKEND_URL=https://%s --label org.opencontainers.image.revision=%s --provenance=false --load -t %s -\n' \
        "${SHA}" "${API_HOST}" "${SHA}" "${ref}"
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
  note "images: ${IMAGE_PREFIX}/{devsecshield-backend,devsecshield-frontend,scan-worker,dast-worker}:${SHA12}"
}

# ------------------------------------------------------------------------------------------------ infrastructure images
cmd_infra() {
  step "infra: release archive of the infrastructure images"
  ssh_setup # here, not inside $(remote ...) below
  local missing=""
  if ((DRY)); then
    remote infra-missing
    missing="(dry-run)"
  else
    missing="$(remote infra-missing | paste -sd' ' -)"
  fi
  if [[ -z "${missing}" && "${FORCE_INFRA}" != 1 ]]; then
    log "the instance has every infrastructure image: no archive needed"
    note "infra: already loaded"
    return 0
  fi
  log "instance lacks: ${missing:-nothing (--force-infra)}"
  work
  local tar="${WORK}/release.tar" sum i
  local -a plat=()
  for i in "${INFRA_IMAGES[@]}"; do x docker pull -q --platform linux/amd64 "${i}"; done
  if ((!DRY)) && containerd_store && docker save --help 2>/dev/null | grep -q -- '--platform'; then plat=(--platform linux/amd64); fi
  if ((!DRY)); then for i in "${INFRA_IMAGES[@]}"; do check_amd64 "${i}" ""; done; fi
  x docker save ${plat[@]+"${plat[@]}"} -o "${tar}" "${INFRA_IMAGES[@]}"
  if ((DRY)); then sum="<sha256>"; else sum="$(sha256sum "${tar}" 2>/dev/null || shasum -a 256 "${tar}")"; sum="${sum%% *}"; fi
  log "release archive: $( ((DRY)) || du -h "${tar}" | cut -f1) sha256 ${sum}"
  aws_ s3 cp --only-show-errors "${tar}" "s3://${BUCKET}/${RELEASE_KEY}"
  remote infra-load "s3://${BUCKET}/${RELEASE_KEY}" "${sum}"
  x rm -f "${tar}"
  note "infra: release archive uploaded (s3://${BUCKET}/${RELEASE_KEY}) and loaded"
}

# ------------------------------------------------------------------------------------------------ backup
cmd_backup() {
  step "backup: logical dumps, then AWS Backup of ${VOLUME_ID} (wait for COMPLETED)"
  remote dump
  local job state pct waited=0 timeout=${CHOLA_BACKUP_TIMEOUT_S:-7200}
  if ((DRY)); then
    aws_ backup start-backup-job --backup-vault-name "${BACKUP_VAULT}" \
      --resource-arn "arn:aws:ec2:${REGION}:${ACCOUNT}:volume/${VOLUME_ID}" --iam-role-arn "${BACKUP_ROLE}" \
      --lifecycle DeleteAfterDays=14 --recovery-point-tags "${BACKUP_TAGS}" --query BackupJobId --output text
    printf '[dry-run] every 30 s: aws backup describe-backup-job --backup-job-id <id> --query "[State,PercentDone]" until COMPLETED\n'
    note "backup: dry-run"
    return 0
  fi
  job="$(aws --region "${REGION}" backup start-backup-job --backup-vault-name "${BACKUP_VAULT}" \
    --resource-arn "arn:aws:ec2:${REGION}:${ACCOUNT}:volume/${VOLUME_ID}" --iam-role-arn "${BACKUP_ROLE}" \
    --lifecycle DeleteAfterDays=14 --recovery-point-tags "${BACKUP_TAGS}" --query BackupJobId --output text)" ||
    die "start-backup-job failed"
  log "backup job ${job} started"
  while :; do
    read -r state pct < <(aws --region "${REGION}" backup describe-backup-job --backup-job-id "${job}" \
      --query '[State,PercentDone]' --output text)
    log "backup ${job}: ${state:-unknown (describe-backup-job failed; retrying)} ${pct:-}%"
    case "${state}" in
      COMPLETED) break ;;
      FAILED | ABORTED | EXPIRED | PARTIAL)
        die "backup job ${job} ended ${state}: not deploying ($(aws --region "${REGION}" backup describe-backup-job --backup-job-id "${job}" --query StatusMessage --output text))" ;;
    esac
    ((waited < timeout)) || die "backup job ${job} not COMPLETED after ${timeout} s; not deploying"
    sleep 30
    waited=$((waited + 30))
  done
  note "backup: job ${job} COMPLETED (recovery point kept 14 days)"
}

# ------------------------------------------------------------------------------------------------ verify
cmd_verify() {
  step "verify"
  local i out code body hdr
  if ((DRY)); then
    printf '[dry-run] aws elbv2 describe-target-health --target-group-arn %s (wait for healthy)\n' "${TG_ARN}"
    remote check
    printf '[dry-run] curl -sS -I https://%s ; curl -sS https://%s/health\n' "${FRONTEND_HOST}" "${API_HOST}"
    note "verify: dry-run"
    return 0
  fi
  for i in $(seq 1 30); do
    out="$(target_health_line)"
    [[ "${out}" == *"${INSTANCE_ID} 80 healthy"* ]] && break
    ((i < 30)) || die "ALB target not healthy after 5 minutes: ${out} (README 'Troubleshooting: target unhealthy')"
    log "ALB target: ${out} (waiting)"
    sleep 10
  done
  log "ALB target: ${out}"
  remote check
  out="$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${INSTANCE_ID}" 'curl -sS --noproxy "*" --max-time 10 http://localhost/nginx-health')"
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
  note "verify: ALB target healthy, nginx-health ok, https://${FRONTEND_HOST}/login 200, https://${API_HOST}/health 200"
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
  upload_files
  remote preflight
  cmd_secrets
  cmd_images
  step "files and environment on the instance"
  upload_files with-overlay
  remote render "${SHA12}"
  remote ecr-login
  remote pull "${SHA12}"
  note "instance: env rendered from Secrets Manager (instance role), images of ${SHA12} pulled"
  cmd_infra
  cmd_backup
  step "migrate and start ${SHA12}"
  remote deploy "${SHA12}"
  note "deploy: ${SHA12} running, migrations applied, services healthy"
  step "SMTP login test"
  if remote smtp-test; then note "smtp: Office 365 login OK"; else
    warn "SMTP login FAILED (above): sign-in codes cannot be mailed until it works (README 'Troubleshooting: SMTP AUTH')"
    note "smtp: FAILED - see above"
  fi
  cmd_verify
}

cmd_rollback() {
  confirm "Roll back"
  step "rollback"
  aws_identity
  upload_files
  cmd_backup
  local -a args=()
  ((ALLOW_DOWNGRADE)) && args=(--allow-downgrade)
  remote ecr-login
  remote rollback ${args[@]+"${args[@]}"}
  note "rollback: done"
  cmd_verify
}

summary() {
  ((${#SUMMARY[@]})) || return 0
  printf '\n[chola] ==== summary%s\n' "$( ((DRY)) && echo ' (dry-run: nothing was changed)')"
  local s
  for s in "${SUMMARY[@]}"; do printf '  - %s\n' "${s}"; done
}

main() {
  local cmd=${1:-}
  shift || true
  parse_args "$@"
  ((DRY)) && log "dry-run: printing the steps; no AWS, SSH, Docker or registry command is run"
  case "${cmd}" in
    preflight) cmd_preflight ;;
    host-setup) cmd_host_setup ;;
    secrets) aws_identity; cmd_secrets ;;
    images) aws_identity; cmd_images ;;
    infra) aws_identity; cmd_infra ;;
    backup) aws_identity; cmd_backup ;;
    deploy) cmd_deploy ;;
    verify) cmd_verify ;;
    rollback) cmd_rollback ;;
    smtp-test) remote smtp-test ;;
    admin) [[ -n "${EMAIL}" ]] || die "admin needs --email"; remote admin "${EMAIL}"; note "admin: ${EMAIL} is platform administrator" ;;
    status) remote status; ((DRY)) || log "ALB target: $(target_health_line)" ;;
    logs) remote logs "${SERVICE:-all}" "${TAIL}" ;;
    -h | --help | help | "") sed -n '2,36p' "${BASH_SOURCE[0]}" ;;
    *) die "unknown command ${cmd} (see --help)" ;;
  esac
  summary
}

main "$@"
