#!/usr/bin/env bash
# seed.sh - put the Appendix-B team data into the running stack (plan 7.4).
#
#   1. fixtures/build_trees.sh                          ephemeral trees under e2e/.work/trees
#   2. compose --profile seed run --rm aibom-scan       real CBOM scan per tree -> e2e/.work/out/<tree>.scan_data.json
#                                                       (network_mode: none: the scan needs no network and no LLM)
#   3. compose --profile seed run --rm seed             users / teams / scans via the real backend models and the
#                                                       real create_findings_in_mongo_db -> e2e/.work/seed.json
#   4. optional e2e/seed/check_determinism.sh           container scan vs host aibom/.venv scan, if the file exists
#
# Usage: seed.sh [--perf]     --perf also seeds the "Perf Team" (E2E_SEED_PERF=1 reaches seed_team.py)
#
# The seed code itself (e2e/seed/scan_trees.py, seed_team.py) belongs to WP6b; this script only runs
# it with the contract documented in e2e/README.md.
# Logs: <evidence>/logs/03-seed.txt, 03-seed.json (redacted copy of .work/seed.json)
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PERF=0
while (($#)); do
  case "$1" in
    --perf)
      PERF=1
      shift
      ;;
    -h | --help)
      sed -n '2,19p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

redact_seed_json() { # <in> <out>: blank every value whose key looks credential-like
  python3 - "$1" "$2" <<'PY'
import json
import re
import sys

SENSITIVE = re.compile(r"pass|secret|token|otp|verification|credential|authorization|api[_-]?key", re.I)


def redact(node):
    if isinstance(node, dict):
        return {k: ("***" if SENSITIVE.search(k) and not isinstance(v, (dict, list)) else redact(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [redact(item) for item in node]
    return node


with open(sys.argv[1], encoding="utf-8") as src:
    data = json.load(src)
with open(sys.argv[2], "w", encoding="utf-8") as dst:
    json.dump(redact(data), dst, indent=2, sort_keys=True)
    dst.write("\n")
PY
}

main() {
  banner "seed"
  need_cmd docker python3

  container_healthy dss-e2e-backend || die "the backend is not healthy: run scripts/up.sh first"
  # The stack was started with this exact file; regenerating it here would hand the seed container
  # different passwords than the running databases have, so a missing file is an error, not a fix-up.
  [[ -f "${E2E_ENV_FILE}" ]] || die "${E2E_ENV_FILE#"${REPO_ROOT}"/} is missing while a stack is running: run scripts/teardown.sh and start again"
  [[ -d "${E2E_ROOT}/seed" ]] || die "e2e/seed/ is missing: the seed code (scan_trees.py, seed_team.py) is delivered by WP6b"
  for f in scan_trees.py seed_team.py; do
    [[ -f "${E2E_ROOT}/seed/${f}" ]] || die "e2e/seed/${f} is missing (WP6b)"
  done

  log "step 1/3: build scan trees"
  bash "${E2E_ROOT}/fixtures/build_trees.sh"

  log "step 2/3: real CBOM scan of every tree (aibom-scan container, no network)"
  compose --profile seed run --rm -T aibom-scan
  local scans
  scans="$(find "${E2E_OUT_DIR}" -maxdepth 1 -name '*.scan_data.json' | wc -l)"
  ((scans > 0)) || die "aibom-scan produced no ${E2E_OUT_DIR#"${REPO_ROOT}"/}/*.scan_data.json"
  log "scan outputs: ${scans} file(s)"
  python3 - "${E2E_OUT_DIR}" <<'PY'
import glob
import json
import sys

for path in sorted(glob.glob(sys.argv[1] + "/*.scan_data.json")):
    with open(path, encoding="utf-8") as fh:
        json.load(fh)  # must be valid JSON
PY

  log "step 3/3: seed the team data (real backend models + real create_findings_in_mongo_db)"
  if ((PERF)); then
    compose --profile seed run --rm -T -e E2E_SEED_PERF=1 seed
  else
    compose --profile seed run --rm -T seed
  fi
  [[ -s "${E2E_WORK_DIR}/seed.json" ]] || die "the seed step did not write ${E2E_WORK_DIR#"${REPO_ROOT}"/}/seed.json"
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${E2E_WORK_DIR}/seed.json" || die "seed.json is not valid JSON"
  redact_seed_json "${E2E_WORK_DIR}/seed.json" "$(e2e_log_file 03-seed.json)"
  log "redacted copy of seed.json -> $(e2e_log_file 03-seed.json)"

  if [[ -x "${E2E_ROOT}/seed/check_determinism.sh" ]]; then
    log "optional: container-vs-host determinism check"
    bash "${E2E_ROOT}/seed/check_determinism.sh"
  fi
  log "SEED OK"
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 03-seed.txt)"
run_logged "$(e2e_log_file 03-seed.txt)" main
