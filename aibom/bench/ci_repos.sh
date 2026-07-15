#!/usr/bin/env bash
# bench/ci_repos.sh — P7 true-miss gate on the "representative repos" in CI.
# Clones each non-hermetic repo in ci_baseline/repos.json at its PINNED SHA,
# emits OURS at level 4, and diffs vs the frozen Trusera+Cisco oracles via
# ci_gate.py. Exit 1 on any true-positive miss. (synthetic is covered hermetically
# by tests/test_benchmark_gate.py; the full 10 run on the nightly workflow.)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; AIBOM="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"; rc=0

repos() { python3 -c "
import json,sys
d=json.load(open('$HERE/ci_baseline/repos.json'))
for k,v in d.items():
    if not v.get('hermetic'):
        print(k, v['url'], v['sha'], v.get('subdir','.'), '1' if v.get('nolfs') else '0')
"; }

while read -r key url sha subdir nolfs; do
  [ -z "$key" ] && continue
  echo "::group::P7 gate — $key @ $sha"
  CE=""; [ "$nolfs" = "1" ] && CE="GIT_LFS_SKIP_SMUDGE=1"
  if env $CE git clone --quiet "$url" "$TMP/$key" && \
     git -C "$TMP/$key" checkout --quiet "$sha"; then
    SCAN="$TMP/$key"; [ "$subdir" != "." ] && [ -d "$TMP/$key/$subdir" ] && SCAN="$TMP/$key/$subdir"
    ( cd "$AIBOM" && uv run python "$HERE/emit_ours.py" "$SCAN" "$TMP/$key.ours.cdx.json" )
    ( cd "$HERE" && uv run python ci_gate.py "$key" "$TMP/$key.ours.cdx.json" ) || rc=1
  else
    echo "CLONE FAILED $key — cannot run gate"; rc=1
  fi
  rm -rf "$TMP/$key"
  echo "::endgroup::"
done < <(repos)

rm -rf "$TMP"
exit $rc
