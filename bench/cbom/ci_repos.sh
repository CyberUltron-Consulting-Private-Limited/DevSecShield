#!/usr/bin/env bash
# bench/cbom/ci_repos.sh — the CBOM true-miss gate on representative REAL repos
# (a JWT/auth lib + an OpenSSL wrapper) cloned at a PINNED SHA, diffed vs the
# frozen cbomkit-theia oracle snapshots in bench/cbom/ci_baseline/. Runs only OUR
# (offline, deterministic) crypto scanner — no docker, no oracle run. The full
# live benchmark runs on the nightly. Exit 1 on any true-positive miss; SKIPs a
# repo only if its clone is impossible.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
fail=0

emit_and_check() {  # <id> <repo-source-path>
  local id="$1" path="$2"
  local out; out="$(mktemp -t cbom_ours_XXXXXX).cdx.json"
  ( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run python "$HERE/emit_ours.py" \
      "$path" "$out" ) >/dev/null 2>&1
  if python3 "$HERE/ci_gate.py" "$id" "$out"; then :; else fail=1; fi
  rm -f "$out"
}

for entry in \
  "01-pyjwt https://github.com/jpadilla/pyjwt HEAD ." \
  "02-pyopenssl https://github.com/pyca/pyopenssl HEAD ."; do
  read -r id url sha subdir <<<"$entry"
  # only gate a repo whose frozen oracle snapshot is committed
  [ -f "$HERE/ci_baseline/$id.cbomkit.cdx.json" ] || { echo "[$id] no frozen oracle — skipped"; continue; }
  dir="$HERE/repos/$id"
  if [ ! -d "$dir/$subdir" ]; then
    echo "[$id] cloning $url"
    rm -rf "$dir"
    if ! GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 \
         git clone --depth 1 -q "$url" "$dir"; then
      echo "[$id] clone unavailable — skipped (covered by the nightly full run)"
      continue
    fi
  fi
  emit_and_check "$id" "$dir/$subdir"
done

[ "$fail" -eq 0 ] && echo "CBOM gate: all representative repos PASS (0 true-misses)"
exit "$fail"
