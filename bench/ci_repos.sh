#!/usr/bin/env bash
# bench/ci_repos.sh — Gate F: the P7 true-miss gate on 2 representative REAL repos
# (hf-model, tf-bedrock) cloned at a PINNED SHA, diffed vs the frozen OSS oracle
# snapshots in bench/ci_baseline/. Runs only OUR (offline, deterministic) scanner —
# no OSS tools, no Bedrock. The full 10-repo LIVE benchmark runs weekly (aibom-nightly.yml).
# Exit 1 on any true-positive miss, on a repo that cannot be fetched at its pinned
# commit, or when nothing was scanned. (CI runs aibom/bench/ci_repos.sh; this copy
# is the root benchmark's.)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
fail=0; scanned=0

emit_and_check() {  # <id> <repo-source-path>
  local id="$1" path="$2"
  local out; out="$(mktemp -t ours_XXXXXX).cdx.json"
  ( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run aibom emit "$path" \
      -f cyclonedx -o "$out" ) >/dev/null 2>&1
  if python3 "$HERE/ci_gate.py" "$id" "$out"; then :; else fail=1; fi
  rm -f "$out"
  scanned=$((scanned + 1))
}

for entry in \
  "07-hf-minilm https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 1110a243fdf4706b3f48f1d95db1a4f5529b4d41 ." \
  "09-tf-bedrock https://github.com/aws-ia/terraform-aws-bedrock 4b74b7dd5110292cb34ca911448581153484f13f ."; do
  read -r id url sha subdir <<<"$entry"
  dir="$HERE/repos/$id"
  # reuse a local clone only when it is at the pinned commit, else fetch it (`git fetch` needs the full SHA)
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$sha" ]; then
    echo "[$id] fetching $url @ $sha"
    rm -rf "$dir"; mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" remote add origin "$url"
    if ! GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 \
         git -C "$dir" fetch -q --depth 1 origin "$sha" \
         || ! git -C "$dir" checkout -q FETCH_HEAD; then
      echo "[$id] FAIL: could not fetch $url at $sha, so the gate did not run"
      fail=1
      continue
    fi
  fi
  emit_and_check "$id" "$dir/$subdir"
done

if [ "$scanned" -eq 0 ]; then
  echo "Gate F: FAIL, no representative repo was scanned"; exit 1
fi
[ "$fail" -eq 0 ] && echo "Gate F: all $scanned representative repos PASS (0 true-misses)"
exit "$fail"
