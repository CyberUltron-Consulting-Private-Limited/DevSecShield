#!/usr/bin/env bash
# Jenkins-contract gate: the exact fire-and-forget curl from Jenkinsfile.dast
# against the local backend. Does not require a Jenkins master.
set -euo pipefail

BASE="${DAST_API_BASE:-http://127.0.0.1:8082}"
KEY="${CICD_API_KEY:-}"
PROFILE_ID="${DAST_PROFILE_ID:-}"
OUT_DIR="${DAST_PROOF_DIR:-.skill-workspace/dast-auto-proofs}"

if [[ -z "$KEY" || -z "$PROFILE_ID" ]]; then
  echo "usage: CICD_API_KEY=... DAST_PROFILE_ID=... $0" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
PAYLOAD="{\"profile_id\": ${PROFILE_ID}}"
echo "POST ${BASE}/cicd/dast/scan payload=${PAYLOAD}"
RESPONSE=$(curl -sS -w "\nHTTP_CODE:%{http_code}\n" -X POST \
  -H "cicd-api-key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "${BASE}/cicd/dast/scan")
echo "$RESPONSE" | tee "${OUT_DIR}/jenkins_contract_post.txt"
HTTP_CODE=$(echo "$RESPONSE" | awk -F: '/HTTP_CODE/{print $2}')
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')
SCAN_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan_id') or '')" 2>/dev/null || true)

if [[ "$HTTP_CODE" != "200" && "$HTTP_CODE" != "202" && "$HTTP_CODE" != "409" ]]; then
  echo "unexpected HTTP ${HTTP_CODE}" >&2
  exit 1
fi

if [[ -n "$SCAN_ID" ]]; then
  echo "GET ${BASE}/cicd/dast/scan/${SCAN_ID}"
  curl -sS -H "cicd-api-key: ${KEY}" "${BASE}/cicd/dast/scan/${SCAN_ID}" | tee "${OUT_DIR}/jenkins_contract_get.txt"
  if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); auth=(d.get('scan_metadata') or {}).get('auth') or d.get('auth') or {}; assert 'password' not in auth; assert 'demo123' not in json.dumps(d)" "${OUT_DIR}/jenkins_contract_get.txt"; then
    :
  else
    echo "password leaked in GET body" >&2
    exit 1
  fi
fi

echo "jenkins contract ok scan_id=${SCAN_ID:-none} http=${HTTP_CODE}"
