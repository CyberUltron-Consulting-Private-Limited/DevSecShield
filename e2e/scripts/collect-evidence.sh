#!/usr/bin/env bash
# collect-evidence.sh - harvest, index and verify the evidence directory after the specs ran.
#
# Does the work of collect_evidence.py (read its docstring): copies Playwright's per-test videos and
# screenshots to their documented names, writes sha256 / ffprobe sidecars, proves the backend made no
# outbound connection beyond postgres / mongo / loopback (decoding /proc/net/tcp{,6} of
# dss-e2e-backend), checks every deliverable has its complete artefact set and generates
# reports/index.json plus SUMMARY.md.
#
# Usage: collect-evidence.sh [--strict] [--skip-egress]
#   --strict       exit 1 unless every deliverable is complete, no test failed and the egress proof is OK
#   --skip-egress  do not touch the running containers (offline indexing of an evidence dir)
# Logs:  <evidence>/logs/05-collect.txt, 05-stack-state.txt, 80-no-egress-proc-net-tcp.txt
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

main() {
  banner "collect-evidence"
  need_cmd python3 ffprobe pdfinfo
  local ev
  ev="$(e2e_evidence_dir)"
  e2e_prepare_evidence_dirs

  # What was running while the specs ran (names, images, status, published ports; no env, no secrets).
  {
    printf 'captured_at=%s git=%s\n' "$(date -u +%FT%TZ)" "$(git_sha)"
    docker ps -a --filter "label=${E2E_LABEL}" --format 'container={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}}' 2>&1 || true
    local img
    for img in "${E2E_IMG_BACKEND}" "${E2E_IMG_FRONTEND}" "${E2E_IMG_AIBOM}" "${E2E_PG_IMAGE}" "${E2E_MONGO_IMAGE}"; do
      if image_exists "${img}"; then
        printf 'image=%s id=%s size_bytes=%s\n' "${img}" "$(docker image inspect -f '{{.Id}}' "${img}")" "$(docker image inspect -f '{{.Size}}' "${img}")"
      fi
    done
  } >"$(e2e_log_file 05-stack-state.txt)"

  python3 "${E2E_SCRIPTS_DIR}/collect_evidence.py" \
    --evidence-dir "${ev}" --git-sha "$(git_sha)" --git-dirty "$(git_dirty)" "$@"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 05-collect.txt)"
run_logged "$(e2e_log_file 05-collect.txt)" main "$@"
