#!/usr/bin/env bash
# Build + push all DevSecShield images for TAG=RBI_CERT_SEBI
# Critical: scan-worker context MUST be repo root (includes aibom for CBOM/AIBOM).
set -euo pipefail

cd /Users/anshsinghal/Desktop/DevSecShield

export AWS_REGION="ap-south-1"
export AWS_ACCOUNT_ID="935951870001"
export ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
export TAG="RBI_CERT_SEBI"
export NEXT_PUBLIC_BACKEND_URL="https://devsecshieldapi.zeroshield.ai"

LOG=/tmp/ecr-build-push-rbi-cert-sebi.log
exec > >(tee -a "$LOG") 2>&1

echo "=== ECR build/push start $(date -u) ==="
echo "ECR_REGISTRY=$ECR_REGISTRY TAG=$TAG"
echo "NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "=== 1/5 backend ==="
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  -t "$ECR_REGISTRY/devsecshield-backend:$TAG" \
  -f backend/Dockerfile backend \
  --push

echo "=== 2/5 frontend (prod API URL baked in) ==="
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  --build-arg "NEXT_PUBLIC_BACKEND_URL=$NEXT_PUBLIC_BACKEND_URL" \
  -t "$ECR_REGISTRY/devsecshield-frontend:$TAG" \
  -f frontend/Dockerfile frontend \
  --push

echo "=== 3/5 scan-worker (context=. includes aibom + CBOM) ==="
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  -t "$ECR_REGISTRY/scan-worker:$TAG" \
  -f RabbitMQ/worker/Dockerfile . \
  --push

echo "=== 4/5 guardrail-worker ==="
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  -t "$ECR_REGISTRY/guardrail-worker:$TAG" \
  -f RabbitMQ/guardrail_worker/Dockerfile RabbitMQ/guardrail_worker \
  --push

echo "=== 5/5 dast-worker ==="
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  -t "$ECR_REGISTRY/dast-worker:$TAG" \
  -f RabbitMQ/dast_worker/Dockerfile RabbitMQ/dast_worker \
  --push

echo "=== verifying images in ECR ==="
for repo in devsecshield-backend devsecshield-frontend scan-worker guardrail-worker dast-worker; do
  aws ecr describe-images \
    --repository-name "$repo" \
    --region "$AWS_REGION" \
    --image-ids "imageTag=$TAG" \
    --query 'imageDetails[0].{tag:imageTags[0],pushed:imagePushedAt,size:imageSizeInBytes}' \
    --output table || echo "MISSING: $repo:$TAG"
done

echo "=== ECR build/push done $(date -u) ==="
echo "Log: $LOG"
