#!/usr/bin/env bash
# Rsync DevSecShield + Cursor settings to AIMeshFirewallDev (16c/58G VM)
set -euo pipefail

REMOTE_HOST="AIMeshFirewallDev"
REMOTE_REPO="~/DevSecShield"
REMOTE_CURSOR="~/cursor-settings-backup"
LOCAL_REPO="/Users/anshsinghal/Desktop/DevSecShield"
LOCAL_CURSOR="/Users/anshsinghal/.cursor"
LOG="/tmp/rsync-to-aimmesh.log"

RSYNC=(rsync -az --progress --partial -e "ssh -o IdentitiesOnly=yes -o ServerAliveInterval=30")

# Regenerable / huge noise — source + .git + .env + configs DO transfer
EXCLUDES=(
  --exclude 'frontend/node_modules/'
  --exclude '**/node_modules/'
  --exclude 'frontend/.next/'
  --exclude '**/.next/'
  --exclude 'backend/.venv/'
  --exclude 'aibom/.venv/'
  --exclude 'RabbitMQ/**/.venv/'
  --exclude '**/.venv/'
  --exclude '**/__pycache__/'
  --exclude '**/*.pyc'
  --exclude '.playwright-mcp/'
  --exclude '**/.pytest_cache/'
  --exclude '**/uv.cache/'
  --exclude '.claude-flow/daemon.pid'
  --exclude '**/ruvector.db'
  --exclude 'bench/cbom/repos/'
  --exclude 'bench/repos/'
  --exclude 'aibom/tests/fixtures/chroma/'
)

CURSOR_EXCLUDES=(
  --exclude 'ai-tracking/'
  --exclude '**/CachedData/'
  --exclude '**/Cache/'
  --exclude '**/GPUCache/'
  --exclude '**/Code Cache/'
  --exclude 'browser-logs/'
  --exclude '**/*.db-wal'
  --exclude '**/*.db-shm'
)

exec > >(tee -a "$LOG") 2>&1
echo "=== rsync start $(date -u) ==="

echo "=== 1) DevSecShield → ${REMOTE_HOST}:${REMOTE_REPO} ==="
"${RSYNC[@]}" "${EXCLUDES[@]}" \
  "${LOCAL_REPO}/" \
  "${REMOTE_HOST}:${REMOTE_REPO}/"

echo "=== 2) ~/.cursor → ${REMOTE_HOST}:${REMOTE_CURSOR} ==="
"${RSYNC[@]}" "${CURSOR_EXCLUDES[@]}" \
  "${LOCAL_CURSOR}/" \
  "${REMOTE_HOST}:${REMOTE_CURSOR}/"

echo "=== remote verify ==="
ssh "$REMOTE_HOST" "du -sh ${REMOTE_REPO} ${REMOTE_CURSOR}; ls ${REMOTE_REPO}/aibom/src/aibom/cbom >/dev/null && echo aibom_cbom_ok; ls ${REMOTE_REPO}/RabbitMQ/worker/Dockerfile >/dev/null && echo worker_ok; test -f ${REMOTE_REPO}/backend/.env && echo backend_env_ok || echo backend_env_missing; df -h ~ | tail -1"

echo "=== rsync done $(date -u) ==="
echo "Log: $LOG"
