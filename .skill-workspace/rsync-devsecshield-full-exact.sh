#!/usr/bin/env bash
# Exact full copy of DevSecShield → AIMeshFirewallDev. NOTHING excluded.
# Parallel top-level rsyncs (high concurrent writers / IOPS on VM).
set -euo pipefail
set -m

REMOTE_HOST="AIMeshFirewallDev"
REMOTE_REPO="DevSecShield"
LOCAL_REPO="/Users/anshsinghal/Desktop/DevSecShield"
LOG="/tmp/rsync-devsecshield-full-exact.log"
PARALLEL="${PARALLEL:-12}"
RSH="ssh -o IdentitiesOnly=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=120"

exec > >(tee "$LOG") 2>&1
echo "=== FULL exact rsync start $(date -u) PARALLEL=$PARALLEL ==="

ssh "$REMOTE_HOST" "mkdir -p ~/${REMOTE_REPO} && df -h / | tail -1"
cd "$LOCAL_REPO"

running() { jobs -pr | wc -l | tr -d ' '; }

for entry in $(ls -A); do
  while [ "$(running)" -ge "$PARALLEL" ]; do sleep 0.5; done
  echo "START: $entry"
  (
    if [ -d "$LOCAL_REPO/$entry" ]; then
      rsync -a --partial --inplace --whole-file -e "$RSH" \
        "$LOCAL_REPO/$entry/" "${REMOTE_HOST}:~/${REMOTE_REPO}/$entry/"
    else
      rsync -a --partial --inplace --whole-file -e "$RSH" \
        "$LOCAL_REPO/$entry" "${REMOTE_HOST}:~/${REMOTE_REPO}/"
    fi
    echo "OK: $entry"
  ) &
done
wait

echo "=== final pass with --delete (exact mirror) ==="
rsync -a --partial --inplace --whole-file --delete -e "$RSH" \
  "$LOCAL_REPO/" "${REMOTE_HOST}:~/${REMOTE_REPO}/"

echo "=== verify ==="
ssh "$REMOTE_HOST" "bash -s" <<'EOF'
set -e
cd ~/DevSecShield
du -sh . .git .claude-flow .cursor frontend/node_modules backend/.venv aibom 2>/dev/null || true
test -d aibom/src/aibom/cbom && echo aibom_cbom_ok
test -f RabbitMQ/worker/Dockerfile && echo worker_ok
test -f backend/.env && echo backend_env_ok
test -d .claude-flow && echo claude_flow_ok
test -d .cursor && echo cursor_project_ok
test -d frontend/node_modules && echo node_modules_ok || echo node_modules_absent
df -h / | tail -1
EOF

echo "=== FULL exact rsync done $(date -u) ==="
echo "Log: $LOG"
