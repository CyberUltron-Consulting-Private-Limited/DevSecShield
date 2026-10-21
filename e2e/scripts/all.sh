#!/usr/bin/env bash
# all.sh - the whole local proof run: preflight -> build -> up -> seed -> specs -> collect -> (teardown).
#
# Exit code = the worst exit code of any step. The run stops early only where continuing would be
# unsafe or pointless (a failed preflight or build, a stack that never came up or could not be
# seeded); evidence collection still runs after a failed stack/seed/spec step so the logs are indexed,
# and teardown (when requested) always runs last.
#
# Usage: all.sh [--skip-build] [--perf] [--teardown] [--purge-images] [-- <playwright test args>]
#   --skip-build    reuse the dss-e2e/*:local images already built
#   --perf          seed the optional "Perf Team" as well (seed.sh --perf)
#   --teardown      run teardown.sh at the end (default: leave the stack up for inspection)
#   --purge-images  with --teardown: also remove the three dss-e2e/*:local images
# Expected wall clock on this VM: ~25-35 min on a cold build cache.
# Logs: <evidence>/logs/06-all.txt plus each step's own log.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SKIP_BUILD=0
PERF=0
TEARDOWN=0
PURGE=0
SPEC_ARGS=()
while (($#)); do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --perf)
      PERF=1
      shift
      ;;
    --teardown)
      TEARDOWN=1
      shift
      ;;
    --purge-images)
      PURGE=1
      shift
      ;;
    --)
      shift
      SPEC_ARGS=("$@")
      break
      ;;
    -h | --help)
      sed -n '2,18p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

WORST=0
declare -a SUMMARY=()

# step <name> <command...>: run, record the exit code, keep going. Returns the step's exit code.
step() {
  local name=$1 rc=0 started=${SECONDS}
  shift
  log "--- step: ${name} ---"
  "$@" || rc=$?
  SUMMARY+=("$(printf '%-10s exit=%s  %ss' "${name}" "${rc}" "$((SECONDS - started))")")
  ((rc <= WORST)) || WORST=${rc}
  return "${rc}"
}

main() {
  banner "all"
  local s="${E2E_SCRIPTS_DIR}"

  step preflight bash "${s}/preflight.sh" || {
    log "preflight failed: stopping before touching anything"
    print_summary
    return "${WORST}"
  }

  if ((SKIP_BUILD)); then
    log "build skipped (--skip-build)"
  else
    step build bash "${s}/build.sh" || {
      log "build failed: stopping"
      print_summary
      return "${WORST}"
    }
  fi

  local stack_ok=1
  step up bash "${s}/up.sh" || stack_ok=0
  if ((stack_ok)); then
    if ((PERF)); then
      step seed bash "${s}/seed.sh" --perf || stack_ok=0
    else
      step seed bash "${s}/seed.sh" || stack_ok=0
    fi
  fi
  if ((stack_ok)); then
    step specs bash "${s}/run-specs.sh" "${SPEC_ARGS[@]}" || true
  else
    log "stack is not usable: skipping the specs"
  fi

  step collect bash "${s}/collect-evidence.sh" --strict || true

  if ((TEARDOWN)); then
    if ((PURGE)); then
      step teardown bash "${s}/teardown.sh" --purge-images || true
    else
      step teardown bash "${s}/teardown.sh" || true
    fi
  else
    log "stack left running (pass --teardown, or run scripts/teardown.sh)"
  fi

  print_summary
  return "${WORST}"
}

print_summary() {
  local line
  log "=== summary (exit code = worst step = ${WORST}) ==="
  for line in "${SUMMARY[@]}"; do log "  ${line}"; done
}

e2e_prepare_evidence_dirs
: >"$(e2e_log_file 06-all.txt)"
run_logged "$(e2e_log_file 06-all.txt)" main
