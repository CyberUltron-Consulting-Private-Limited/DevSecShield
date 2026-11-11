#!/usr/bin/env bash
# bench/cbom/ci_repos.sh — the CBOM true-miss gate on representative REAL repos
# (a JWT/auth lib + an OpenSSL wrapper) cloned at a PINNED SHA, diffed vs the
# frozen cbomkit-theia oracle snapshots in bench/cbom/ci_baseline/. Runs only OUR
# (offline, deterministic) crypto scanner — no docker, no oracle run. The full
# live benchmark runs weekly (cbom-nightly.yml). Exit 1 on any true-positive miss,
# on a repo that cannot be fetched at its pinned commit, or when nothing was scanned.
# The SHAs are the commits the oracle snapshots were made from (the former gitlinks).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
fail=0; scanned=0

emit_and_check() {  # <id> <repo-source-path>
  local id="$1" path="$2"
  local out; out="$(mktemp -t cbom_ours_XXXXXX).cdx.json"
  ( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run python "$HERE/emit_ours.py" \
      "$path" "$out" ) >/dev/null 2>&1
  if python3 "$HERE/ci_gate.py" "$id" "$out"; then :; else fail=1; fi
  rm -f "$out"
  scanned=$((scanned + 1))
}

for entry in \
  "01-pyjwt https://github.com/jpadilla/pyjwt 7144e4534c34810f4525dc4578a32addd8212cff ." \
  "02-pyopenssl https://github.com/pyca/pyopenssl c6b4a5f19d681b84e9da364740ae0a416ee966f4 ."; do
  read -r id url sha subdir <<<"$entry"
  # only gate a repo whose frozen oracle snapshot is committed
  [ -f "$HERE/ci_baseline/$id.cbomkit.cdx.json" ] || { echo "[$id] no frozen oracle — skipped"; continue; }
  dir="$HERE/repos/$id"
  # "Exists" is not "cloned". repos/01-pyjwt and repos/02-pyopenssl used to be committed as bare gitlinks, so a
  # checkout had them as EMPTY directories. Scanning an empty directory gave 0 crypto assets, i.e. a false "true
  # miss" on every run. The gitlinks are gone, but an empty leftover directory must still trigger a clone.
  # A local clone is reused only when it is at the pinned commit.
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$sha" ]; then
    echo "[$id] fetching $url @ ${sha:0:12}"
    rm -rf "$dir"; mkdir -p "$dir"
    if ! { git -C "$dir" init -q && git -C "$dir" remote add origin "$url" \
           && GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 git -C "$dir" fetch -q --depth 1 origin "$sha" \
           && git -C "$dir" checkout -q FETCH_HEAD; }; then
      echo "[$id] FAIL: could not fetch $url at $sha, so the gate did not run"
      fail=1
      continue
    fi
  fi
  emit_and_check "$id" "$dir/$subdir"
done

if [ "$scanned" -eq 0 ]; then
  echo "CBOM gate: FAIL, no representative repo was scanned"; exit 1
fi
[ "$fail" -eq 0 ] && echo "CBOM gate: all $scanned representative repos PASS (0 true-misses)"
exit "$fail"
