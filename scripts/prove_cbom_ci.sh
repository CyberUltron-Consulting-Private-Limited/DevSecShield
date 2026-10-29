#!/usr/bin/env bash
# Run the CBOM GitHub Action step the way Actions runs it.
# Exit 0 only when the clean tree is allowed and the vulnerable tree is blocked.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export GITHUB_WORKSPACE="$ROOT"
LOG="/tmp/cbom-ci-proof.log"
: > "$LOG"

run_action() {
  local scan_path="$1"
  local no_fail="${2:-false}"
  local label="$3"
  local out err code
  out="$(mktemp)"
  err="$(mktemp)"
  set +e
  (
    cd "$ROOT/aibom"
    export SCAN_PATH="$scan_path"
    export NO_FAIL="$no_fail"
    set -euo pipefail
    args=(cbom "$GITHUB_WORKSPACE/$SCAN_PATH")
    if [ "$NO_FAIL" = "true" ]; then
      args+=(--no-fail)
    fi
    uv run aibom "${args[@]}"
  ) >"$out" 2>"$err"
  code=$?
  set -e
  {
    echo "===== $label ====="
    echo "command: uv run aibom cbom $GITHUB_WORKSPACE/$scan_path"
    echo "exit: $code"
    echo "----- stderr -----"
    cat "$err"
    echo "----- stdout head -----"
    python3 - "$out" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
try:
    doc = json.loads(raw)
except json.JSONDecodeError as exc:
    print("stdout is not JSON:", exc)
    print(raw[:400])
else:
    print(f"bomFormat={doc.get('bomFormat')} specVersion={doc.get('specVersion')} components={len(doc.get('components') or [])}")
PY
    echo
  } | tee -a "$LOG"
  rm -f "$out" "$err"
  echo "$code"
}

clean_code="$(run_action "aibom/tests/fixtures/code-supply/clean" false clean | tail -n 1)"
vuln_code="$(run_action "aibom/tests/fixtures/code-supply/vulnerable" false vulnerable | tail -n 1)"

{
  echo "===== verdict ====="
  echo "clean_exit=$clean_code (must be 0)"
  echo "vulnerable_exit=$vuln_code (must be non-zero)"
} | tee -a "$LOG"

if [ "$clean_code" != "0" ]; then
  echo "FAIL: clean tree was blocked" | tee -a "$LOG"
  exit 1
fi
if [ "$vuln_code" = "0" ]; then
  echo "FAIL: vulnerable tree was not blocked" | tee -a "$LOG"
  exit 1
fi
echo "PASS: CI step allows the clean tree and blocks the vulnerable tree" | tee -a "$LOG"
exit 0
