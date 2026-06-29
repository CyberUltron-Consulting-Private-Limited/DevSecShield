#!/usr/bin/env bash
# bench/run.sh — clone (shallow, record SHA) + LIVE-run all 3 tools on one repo.
# Isolated harness (NOT product code). Usage: run.sh <id>   (reads repos.tsv row)
# Env: PATH must include ~/.local/bin (ai-bom, cisco-aibom); AWS creds for Cisco.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/out"; REPOS="$HERE/repos"; mkdir -p "$OUT" "$REPOS"
ID="$1"
BEDROCK_MODEL="${BEDROCK_MODEL:-global.anthropic.claude-haiku-4-5-20251001-v1:0}"

row=$(grep -E "^${ID}\b" "$HERE/repos.tsv") || { echo "no repos.tsv row for $ID"; exit 2; }
IFS=$'\t' read -r _id slug url subdir note <<<"$row"

# --- clone (shallow) + record SHA --------------------------------------------
dir="$REPOS/$ID"
if [ "$url" = "-" ]; then
  echo "[$ID] local fixture at $dir"
else
  if [ ! -d "$dir/.git" ]; then
    echo "[$ID] cloning $url (shallow) ..."
    git clone --depth 1 --quiet "$url" "$dir" || { echo "[$ID] CLONE FAILED"; exit 3; }
  fi
fi
sha=$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo "local")
echo "$ID	$slug	$sha	$subdir" >> "$HERE/state/shas.tsv"
target="$dir/$subdir"
echo "[$ID] target=$target sha=$sha"

# --- Trusera (L1 baseline, no --llm-enrich) ----------------------------------
echo "[$ID] trusera ..."
ai-bom scan "$target" -f cyclonedx -o "$OUT/$ID.trusera.cdx.json" >"$OUT/$ID.trusera.log" 2>&1
echo "[$ID] trusera exit=$?"

# --- Ours --------------------------------------------------------------------
echo "[$ID] ours ..."
( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run aibom emit "$target" -f cyclonedx \
    -o "$OUT/$ID.ours.cdx.json" ) >"$OUT/$ID.ours.log" 2>&1
echo "[$ID] ours exit=$?"

# --- Cisco (mandatory agentic pass -> Bedrock Haiku) -------------------------
echo "[$ID] cisco (bedrock) ..."
( set -a; source "$ROOT/RabbitMQ/worker/.env" 2>/dev/null; set +a
  export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-south-1}"
  cisco-aibom analyze "$target" --llm-provider bedrock --llm-model "$BEDROCK_MODEL" \
    -o json -O "$OUT/$ID.cisco.json" ) >"$OUT/$ID.cisco.log" 2>&1
echo "[$ID] cisco exit=$?"
echo "[$ID] DONE"
