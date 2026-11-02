#!/usr/bin/env bash
# WP11 integration proof: mock receivers on a private, internal Docker network; the backend's real dispatcher and
# SSRF guard deliver to them; evidence lands in OUT. Air-gap safe (python:3.12-slim already on disk, no pulls).
#
#   bash scripts/integrations_lab/run_lab.sh <out dir> <python with the backend deps> [--own-dockerd]
#
# --own-dockerd starts a Docker daemon for the duration of the run and stops it afterwards (shared CI machines).
set -euo pipefail
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
PY="$2"
OWN="${3:-}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LAB_IP=10.211.0.10
SUBNET=10.211.0.0/24
IMAGE=python:3.12-slim
rm -rf "$OUT/pki" "$OUT/received" "$OUT/evidence"
mkdir -p "$OUT/pki" "$OUT/received" "$OUT/evidence"
chmod 777 "$OUT/received"

DOCKERD_PID=""
cleanup() {
  docker logs wp11-receivers >"$OUT/evidence/receivers.log" 2>&1 || true
  docker rm -f wp11-receivers >/dev/null 2>&1 || true
  docker network rm wp11-net >/dev/null 2>&1 || true
  if [ -n "$DOCKERD_PID" ]; then kill "$DOCKERD_PID" 2>/dev/null || true; wait "$DOCKERD_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

if [ "$OWN" = "--own-dockerd" ]; then
  dockerd >"$OUT/evidence/wp11-dockerd.log" 2>&1 &
  DOCKERD_PID=$!
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker info >/dev/null
docker image inspect "$IMAGE" >/dev/null  # never pulled here: the lab must work offline

# lab PKI (CA + server certificate for the lab IP) and per-run secrets
"$PY" -c "
import sys; sys.path.insert(0, '$REPO/backend/tests')
from pathlib import Path
from integrations_helpers import make_pki
make_pki(Path('$OUT/pki'), ['$LAB_IP', 'receivers.wp11.lab'])
"
chmod 644 "$OUT/pki/"*
export LAB_HOOK_SECRET="$("$PY" -c 'import secrets; print(secrets.token_hex(24))')"
export LAB_HEC_TOKEN="$("$PY" -c 'import uuid; print(uuid.uuid4())')"
export LAB_SN_USER=zs-integration
export LAB_SN_PASS="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(18))')"

docker network create --internal --subnet "$SUBNET" wp11-net >/dev/null
docker run -d --name wp11-receivers --network wp11-net --ip "$LAB_IP" \
  -v "$REPO/scripts/integrations_lab:/lab:ro" -v "$OUT/pki:/pki:ro" -v "$OUT/received:/out" \
  -e LAB_OUT=/out -e LAB_CERT=/pki/server.pem -e LAB_KEY=/pki/server.key -e LAB_HEC_FAIL_FIRST=1 \
  -e LAB_HOOK_SECRET -e LAB_HEC_TOKEN -e LAB_SN_USER -e LAB_SN_PASS \
  "$IMAGE" python -u /lab/mock_receivers.py >/dev/null
for _ in $(seq 1 30); do
  "$PY" -c "import socket; socket.create_connection(('$LAB_IP', 9443), 1).close()" 2>/dev/null && break
  sleep 1
done
docker exec wp11-receivers python -c "import urllib.request; urllib.request.urlopen('https://pypi.org', timeout=3)" \
  >"$OUT/evidence/egress-check.txt" 2>&1 && echo "EGRESS POSSIBLE" >>"$OUT/evidence/egress-check.txt" \
  || echo "no egress from the lab network (internal)" >>"$OUT/evidence/egress-check.txt"

export INTEGRATION_LAB_IP="$LAB_IP" INTEGRATION_LAB_CA="$OUT/pki/ca.pem" INTEGRATION_LAB_OUT="$OUT/received"
export INTEGRATION_LAB_EVIDENCE="$OUT/evidence" INTEGRATION_ALLOWED_PRIVATE="$SUBNET"
cd "$REPO"
"$PY" -m pytest backend/tests/test_integrations_lab.py -q -p no:cacheprovider -W ignore::DeprecationWarning -s \
  2>&1 | tee "$OUT/evidence/pytest.log"
cp "$OUT/received/"* "$OUT/evidence/" 2>/dev/null || true
