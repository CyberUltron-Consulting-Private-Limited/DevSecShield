#!/usr/bin/env bash
# bench/run_repo.sh KEY GIT_URL SUBDIR FLAGS
# Clone shallow, record SHA, run all three tools on the (scoped) path, clean up.
# Trusera + ours run in PARALLEL (fast, free); Cisco runs after (slow, Bedrock $).
# Condition-based: every scan is `wait`ed on — no sleeps.
set -uo pipefail
KEY="$1"; URL="$2"; SUBDIR="${3:-.}"; FLAGS="${4:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"; REPOS="$HERE/repos"; AIBOM="$(cd "$HERE/.." && pwd)"
mkdir -p "$OUT" "$REPOS"
export AWS_REGION=us-east-1
HAIKU="global.anthropic.claude-haiku-4-5-20251001-v1:0"
DEST="$REPOS/$KEY"
log(){ echo "[$KEY] $*"; }

# ── clone (shallow) ──
rm -rf "$DEST"
CLONE_ENV=""
[[ "$FLAGS" == *nolfs* ]] && CLONE_ENV="GIT_LFS_SKIP_SMUDGE=1"
log "cloning $URL (shallow)…"
if ! env $CLONE_ENV git clone --depth 1 --quiet "$URL" "$DEST" 2>"$OUT/$KEY.clone.log"; then
  log "CLONE FAILED — see $OUT/$KEY.clone.log"; tail -3 "$OUT/$KEY.clone.log"; exit 2
fi
SHA="$(git -C "$DEST" rev-parse HEAD 2>/dev/null || echo unknown)"
log "SHA=$SHA"

# ── resolve scan path (subdir with fallback) ──
SCAN="$DEST"
if [[ "$SUBDIR" != "." && -d "$DEST/$SUBDIR" ]]; then SCAN="$DEST/$SUBDIR";
elif [[ "$SUBDIR" != "." ]]; then log "WARN subdir '$SUBDIR' missing -> scanning whole repo"; fi
log "scan path: ${SCAN#$DEST/}"

# ── Trusera + ours in parallel ──
( ai-bom scan "$SCAN" -f cyclonedx -o "$OUT/$KEY.trusera.cdx.json" -q \
    >"$OUT/$KEY.trusera.log" 2>&1; echo "trusera_exit=$?" >>"$OUT/$KEY.trusera.log" ) &
T=$!
( cd "$AIBOM" && uv run aibom emit "$SCAN" -f cyclonedx -o "$OUT/$KEY.ours.cdx.json" \
    >"$OUT/$KEY.ours.log" 2>&1; echo "ours_exit=$?" >>"$OUT/$KEY.ours.log" ) &
O=$!
wait $T; log "trusera done ($(tail -1 "$OUT/$KEY.trusera.log"))"
wait $O; log "ours done ($(tail -1 "$OUT/$KEY.ours.log"))"

# ── Cisco (agentic, Bedrock Haiku) ──
log "cisco analyze (agentic/bedrock)…"
cisco-aibom analyze "$SCAN" -o json -O "$OUT/$KEY.cisco.json" \
  --llm-provider bedrock --llm-model "$HAIKU" >"$OUT/$KEY.cisco.log" 2>&1
log "cisco done (exit=$?)"

# ── record SHA, free disk ──
python3 - "$OUT/shas.json" "$KEY" "$SHA" <<'PY'
import json,sys
p,k,sha=sys.argv[1:4]
try: d=json.load(open(p))
except Exception: d={}
d[k]=sha; json.dump(d,open(p,"w"),indent=2)
PY
rm -rf "$DEST"
log "DONE (clone removed)"
