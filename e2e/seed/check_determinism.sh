#!/usr/bin/env bash
# check_determinism.sh - the scan the container produced equals the scan a DIFFERENT interpreter produces.
#
# seed.sh runs this after the seed when the file is executable (plan 7.4 step 2). It scans every tree under
# e2e/.work/trees again with the host's aibom virtualenv (a different Python than the aibom-scan image,
# source pinned to THIS worktree through PYTHONPATH) and compares the SHA-256 of each canonical run-object
# (`duration_of_scan` zeroed) with e2e/.work/out/scan_summary.json written by the container. Any difference
# fails: the CBOM engine must be a pure function of the tree.
#
# Skipped, loudly, when the host virtualenv does not exist (it is not part of the stack).
set -euo pipefail
# shellcheck source=../scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../scripts/lib.sh"

main() {
  need_cmd git python3
  local common main_checkout host_py tmp
  common="$(git -C "${REPO_ROOT}" rev-parse --path-format=absolute --git-common-dir)"
  main_checkout="$(dirname "${common}")"
  host_py="${main_checkout}/aibom/.venv/bin/python"
  if [[ ! -x "${host_py}" ]]; then
    warn "determinism check skipped: no host aibom virtualenv at ${host_py}"
    return 0
  fi
  [[ -s "${E2E_OUT_DIR}/scan_summary.json" ]] || die "${E2E_OUT_DIR#"${REPO_ROOT}"/}/scan_summary.json is missing: run the aibom-scan step first"

  tmp="$(mktemp -d "${E2E_WORK_DIR}/determinism.XXXXXX")"
  log "re-scanning every tree with the host interpreter ($("${host_py}" --version 2>&1)) into ${tmp#"${REPO_ROOT}"/}"
  # lib.sh declares E2E_TREES_DIR / E2E_OUT_DIR readonly, so hand the child its own values through env(1).
  env "E2E_TREES_DIR=${E2E_TREES_DIR}" "E2E_OUT_DIR=${tmp}" PYTHONDONTWRITEBYTECODE=1 "PYTHONPATH=${REPO_ROOT}/aibom/src" \
    "${host_py}" "${E2E_ROOT}/seed/scan_trees.py" >/dev/null

  python3 - "${E2E_OUT_DIR}/scan_summary.json" "${tmp}/scan_summary.json" <<'PY'
import json
import sys

container = json.load(open(sys.argv[1], encoding="utf-8"))
host = json.load(open(sys.argv[2], encoding="utf-8"))
print(f"container: python {container['python']}   host: python {host['python']}")
bad = []
for tree, info in sorted(container["trees"].items()):
    other = host["trees"].get(tree)
    same = other is not None and other["sha256"] == info["sha256"]
    print(f"  {tree:<22} {info['sha256'][:16]}  {'identical' if same else 'DIFFERENT'}")
    if not same:
        bad.append(tree)
if set(host["trees"]) != set(container["trees"]):
    bad.append("tree sets differ")
if bad:
    sys.exit("determinism check FAILED for: " + ", ".join(bad))
print("determinism check OK: container and host scans are identical apart from duration_of_scan")
PY
  safe_rm_rf "${tmp}"
}

main "$@"
