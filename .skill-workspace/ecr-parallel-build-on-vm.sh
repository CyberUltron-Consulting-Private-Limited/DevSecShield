#!/usr/bin/env bash
# Parallel ECR build+push on the build VM — max concurrency for CPU/RAM/disk/network.
# Critical: scan-worker context MUST be repo root (includes aibom for CBOM/AIBOM).
# Run ON the VM from ~/DevSecShield
set -euo pipefail
cd /home/contact_cyberultron_com/DevSecShield

export AWS_REGION="${AWS_REGION:-ap-south-1}"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-935951870001}"
export ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
export TAG="${TAG:-RBI_CERT_SEBI}"
export NEXT_PUBLIC_BACKEND_URL="${NEXT_PUBLIC_BACKEND_URL:-https://devsecshieldapi.zeroshield.ai}"

# BuildKit / parallelism — saturate 16 cores + high IOPS disk
export DOCKER_BUILDKIT=1
export BUILDKIT_PROGRESS=plain
NPROC="$(nproc)"
export GOMAXPROCS="$NPROC"
export BUILDKIT_STEP_LOG_MAX_SIZE=10485760
# Concurrent build steps inside BuildKit (jobs across stages/layers)
export BUILDKIT_MAX_PARALLELISM="$NPROC"

LOG=/tmp/ecr-parallel-build-${TAG}.log
exec > >(tee -a "$LOG") 2>&1

echo "=== parallel ECR build start $(date -u) ==="
echo "nproc=$NPROC TAG=$TAG ECR=$ECR_REGISTRY"
echo "NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL"
echo "BUILDKIT_MAX_PARALLELISM=$BUILDKIT_MAX_PARALLELISM"
df -h / | tail -1
free -h | head -2

# High-parallelism container builder (better than docker driver for concurrent builds)
BUILDER="dss-fast"
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "env.BUILDKIT_STEP_LOG_MAX_SIZE=10485760" \
    --driver-opt "network=host" \
    --buildkitd-flags "--allow-insecure-entitlement network.host" \
    --use
else
  docker buildx use "$BUILDER"
fi
# Tune BuildKit worker concurrency via config if supported
docker buildx inspect --bootstrap >/dev/null 2>&1 || true

echo "=== ECR login ==="
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "=== ensure ECR repos ==="
for r in devsecshield-backend devsecshield-frontend scan-worker guardrail-worker dast-worker; do
  aws ecr describe-repositories --repository-names "$r" --region "$AWS_REGION" >/dev/null 2>&1 \
    || aws ecr create-repository --repository-name "$r" --region "$AWS_REGION" >/dev/null
done

# Forced rebuild (--no-cache), amd64, push directly (no local store pressure)
COMMON=(
  docker buildx build
  --builder "$BUILDER"
  --platform linux/amd64
  --no-cache
  --push
  --provenance=false
  --sbom=false
)

echo "=== launching 5 builds in PARALLEL (forced rebuild) ==="
pids=()
names=()

(
  echo "[backend] START $(date -u)"
  "${COMMON[@]}" \
    -t "$ECR_REGISTRY/devsecshield-backend:$TAG" \
    -f backend/Dockerfile backend
  echo "[backend] DONE $(date -u)"
) >"/tmp/build-backend-${TAG}.log" 2>&1 &
pids+=($!)
names+=("backend")

(
  echo "[frontend] START $(date -u)"
  "${COMMON[@]}" \
    --build-arg "NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL" \
    -t "$ECR_REGISTRY/devsecshield-frontend:$TAG" \
    -f frontend/Dockerfile frontend
  echo "[frontend] DONE $(date -u)"
) >"/tmp/build-frontend-${TAG}.log" 2>&1 &
pids+=($!)
names+=("frontend")

# CRITICAL: context = repo root so COPY aibom works (CBOM + AIBOM in image)
(
  echo "[scan-worker] START $(date -u) context=repo-root (aibom+cbom)"
  "${COMMON[@]}" \
    -t "$ECR_REGISTRY/scan-worker:$TAG" \
    -f RabbitMQ/worker/Dockerfile .
  echo "[scan-worker] DONE $(date -u)"
) >"/tmp/build-scan-worker-${TAG}.log" 2>&1 &
pids+=($!)
names+=("scan-worker")

(
  echo "[guardrail-worker] START $(date -u)"
  "${COMMON[@]}" \
    -t "$ECR_REGISTRY/guardrail-worker:$TAG" \
    -f RabbitMQ/guardrail_worker/Dockerfile RabbitMQ/guardrail_worker
  echo "[guardrail-worker] DONE $(date -u)"
) >"/tmp/build-guardrail-worker-${TAG}.log" 2>&1 &
pids+=($!)
names+=("guardrail-worker")

(
  echo "[dast-worker] START $(date -u)"
  "${COMMON[@]}" \
    -t "$ECR_REGISTRY/dast-worker:$TAG" \
    -f RabbitMQ/dast_worker/Dockerfile RabbitMQ/dast_worker
  echo "[dast-worker] DONE $(date -u)"
) >"/tmp/build-dast-worker-${TAG}.log" 2>&1 &
pids+=($!)
names+=("dast-worker")

echo "PIDs: ${pids[*]} names: ${names[*]}"
echo "Per-image logs: /tmp/build-*-${TAG}.log"

# Progress ticker while waiting
fail=0
remaining=("${pids[@]}")
declare -A pid_name
for i in "${!pids[@]}"; do
  pid_name[${pids[$i]}]=${names[$i]}
done

while ((${#remaining[@]})); do
  still=()
  for pid in "${remaining[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      still+=("$pid")
    else
      name="${pid_name[$pid]}"
      if wait "$pid"; then
        echo "BUILD OK  $name (pid=$pid) $(date -u)"
      else
        echo "BUILD FAIL $name (pid=$pid) $(date -u) — see /tmp/build-${name}-${TAG}.log"
        fail=1
      fi
    fi
  done
  remaining=("${still[@]}")
  if ((${#remaining[@]})); then
    echo "… still running: $(for p in "${remaining[@]}"; do echo -n "${pid_name[$p]} "; done) $(date -u)"
    # light I/O/CPU snapshot
    free -h | awk '/Mem:/{print "  mem avail="$NF}'
    sleep 30
  fi
done

echo "=== ECR image verify ==="
for repo in devsecshield-backend devsecshield-frontend scan-worker guardrail-worker dast-worker; do
  aws ecr describe-images --repository-name "$repo" --region "$AWS_REGION" \
    --image-ids "imageTag=$TAG" \
    --query 'imageDetails[0].{tag:imageTags[0],pushed:imagePushedAt,mb:imageSizeInBytes}' \
    --output table 2>/dev/null || echo "MISSING $repo:$TAG"
done

if [[ $fail -ne 0 ]]; then
  echo "ONE OR MORE BUILDS FAILED — see $LOG and /tmp/build-*-${TAG}.log"
  exit 1
fi
echo "=== ALL PARALLEL BUILDS PUSHED $(date -u) ==="
echo "Log: $LOG"
echo "Images tagged $TAG @ $ECR_REGISTRY"
echo "Frontend baked NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL"
echo "scan-worker includes aibom (CBOM+AIBOM) via repo-root build context"
