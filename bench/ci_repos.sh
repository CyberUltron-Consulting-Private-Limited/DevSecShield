#!/usr/bin/env bash
# bench/ci_repos.sh — Gate F: the P7 true-miss gate on 2 representative REAL repos
# (hf-model, tf-bedrock) cloned at a PINNED SHA, diffed vs the frozen OSS oracle
# snapshots in bench/ci_baseline/. Runs only OUR (offline, deterministic) scanner —
# no OSS tools, no Bedrock. The full 10-repo LIVE benchmark runs on the nightly.
# Exit 1 on any true-positive miss; SKIPs a repo only if its clone is impossible.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
fail=0

emit_and_check() {  # <id> <repo-source-path>
  local id="$1" path="$2"
  local out; out="$(mktemp -t ours_XXXXXX).cdx.json"
  ( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run aibom emit "$path" \
      -f cyclonedx -o "$out" ) >/dev/null 2>&1
  if python3 "$HERE/ci_gate.py" "$id" "$out"; then :; else fail=1; fi
  rm -f "$out"
}

for entry in \
  "07-hf-minilm https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2 1110a24 ." \
  "09-tf-bedrock https://github.com/aws-ia/terraform-aws-bedrock 4b74b7d ."; do
  read -r id url sha subdir <<<"$entry"
  dir="$HERE/repos/$id"
  if [ ! -d "$dir/$subdir" ]; then              # reuse a local clone, else fetch the pinned SHA
    echo "[$id] fetching $url @ $sha"
    rm -rf "$dir"; mkdir -p "$dir"
    git -C "$dir" init -q
    git -C "$dir" remote add origin "$url"
    if ! GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 \
         git -C "$dir" fetch -q --depth 1 origin "$sha" \
         || ! git -C "$dir" checkout -q FETCH_HEAD; then
      echo "[$id] clone unavailable — skipped (covered by the nightly full run)"
      continue
    fi
  fi
  emit_and_check "$id" "$dir/$subdir"
done

[ "$fail" -eq 0 ] && echo "Gate F: all representative repos PASS (0 true-misses)"
exit "$fail"
