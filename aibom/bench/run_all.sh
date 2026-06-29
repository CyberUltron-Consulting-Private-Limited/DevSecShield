#!/usr/bin/env bash
# bench/run_all.sh — clone + run all three tools on every benchmark repo.
# Concurrency-bounded (MAXJ) — "parallel runners where resources allow" (disk +
# Bedrock $); within a repo Trusera+ours are parallel, Cisco follows. No sleeps.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/out"; AIBOM="$(cd "$HERE/.." && pwd)"
MAXJ="${MAXJ:-3}"
export AWS_REGION=us-east-1
HAIKU="global.anthropic.claude-haiku-4-5-20251001-v1:0"
mkdir -p "$OUT"

# ── chroma: scan the gitignored local clone in place (scoped to the python pkg),
#    or clone it fresh when absent (CI nightly) ──
chroma() {
  local ROOT="$AIBOM/tests/fixtures/chroma"
  if [[ ! -d "$ROOT" ]]; then
    ROOT="$OUT/../repos/chroma-src"
    git clone --depth 1 --quiet https://github.com/chroma-core/chroma "$ROOT" 2>/dev/null || return
  fi
  local SCAN="$ROOT/chromadb"; [[ -d "$SCAN" ]] || SCAN="$ROOT"
  local SHA; SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "[chroma] scan $SCAN sha=$SHA"
  ( ai-bom scan "$SCAN" -f cyclonedx -o "$OUT/chroma.trusera.cdx.json" -q >"$OUT/chroma.trusera.log" 2>&1 ) &
  ( cd "$AIBOM" && uv run aibom emit "$SCAN" -f cyclonedx -o "$OUT/chroma.ours.cdx.json" >"$OUT/chroma.ours.log" 2>&1 ) &
  wait
  cisco-aibom analyze "$SCAN" -o json -O "$OUT/chroma.cisco.json" --llm-provider bedrock --llm-model "$HAIKU" >"$OUT/chroma.cisco.log" 2>&1
  python3 - "$OUT/shas.json" chroma "$SHA" <<'PY'
import json,sys
p,k,s=sys.argv[1:4]
try:d=json.load(open(p))
except Exception:d={}
d[k]=s;json.dump(d,open(p,"w"),indent=2)
PY
  echo "[chroma] DONE"
}

chroma &   # chroma runs alongside the cloned repos

# ── manifest repos, bounded concurrency (portable batches; bash 3.2 has no wait -n) ──
n=0
while IFS='|' read -r key url subdir flags; do
  key="$(echo "$key"|xargs)"; [[ -z "$key" || "$key" == \#* ]] && continue
  url="$(echo "$url"|xargs)"; subdir="$(echo "$subdir"|xargs)"; flags="$(echo "$flags"|xargs)"
  bash "$HERE/run_repo.sh" "$key" "$url" "$subdir" "$flags" >"$OUT/$key.run.log" 2>&1 &
  n=$((n+1))
  if (( n % MAXJ == 0 )); then wait; fi   # drain the batch before starting the next
done < "$HERE/repos.txt"
wait
echo "ALL REPOS COMPLETE"
ls -1 "$OUT"/*.cisco.json 2>/dev/null | wc -l | xargs echo "cisco outputs:"
