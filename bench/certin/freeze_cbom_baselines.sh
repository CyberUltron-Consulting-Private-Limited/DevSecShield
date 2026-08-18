#!/usr/bin/env bash
# Freeze CBOM oracle snapshots for Phase 6 repos into ci_baseline/.
# Clones at pinned SHAs from state/shas.tsv; runs cbomkit + cdxgen + ours.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CBOM="$ROOT/bench/cbom"
OUT="$CBOM/out"
BASE="$CBOM/ci_baseline"
ORACLE_IMG="${ORACLE_IMG:-ghcr.io/cbomkit/cbomkit-theia:latest}"
mkdir -p "$OUT" "$CBOM/repos" "$BASE"

trim_cdx() {
  # Drop volatile fields for stable freeze
  python3 - "$1" "$2" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src))
data.pop("serialNumber", None)
meta = data.get("metadata") or {}
meta.pop("timestamp", None)
data["metadata"] = meta
comps = data.get("components") or []
def key(c):
    return (c.get("type"), c.get("name"), c.get("bom-ref") or c.get("purl") or "")
comps = sorted(comps, key=key)
data["components"] = comps
json.dump(data, open(dst, "w"), indent=2, sort_keys=True)
open(dst, "a").write("\n")
PY
}

freeze_one() {
  local ID="$1"
  local row pin slug url subdir dir target sha
  row=$(grep -E "^${ID}\b" "$CBOM/repos.tsv") || { echo "missing $ID"; return 1; }
  IFS=$'\t' read -r _id slug url subdir note <<<"$row"
  pin=$(awk -F'\t' -v id="$ID" '$1==id{print $3; exit}' "$CBOM/state/shas.tsv")
  dir="$CBOM/repos/$ID"
  if [ "$url" = "-" ]; then
    src="$ROOT/aibom/tests/fixtures/synthetic-crypto-app"
    mkdir -p "$dir"; cp -R "$src/." "$dir/"
  else
    if [ ! -d "$dir/.git" ]; then
      echo "[$ID] clone $url"
      GIT_LFS_SKIP_SMUDGE=1 git clone --filter=blob:none --quiet "$url" "$dir" || return 3
    fi
    if [ -n "$pin" ]; then
      git -C "$dir" fetch --depth 1 origin "$pin" >/dev/null 2>&1 || \
        git -C "$dir" fetch --depth 1 origin "+refs/heads/*:refs/remotes/origin/*" >/dev/null 2>&1 || true
      git -C "$dir" checkout --quiet "$pin" 2>/dev/null || \
        git -C "$dir" checkout --quiet "$(git -C "$dir" rev-parse HEAD)" 
    fi
  fi
  sha=$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo local)
  target="$dir/$subdir"
  echo "[$ID] target=$target sha=$sha"

  echo "[$ID] cbomkit..."
  docker run --rm -v "$target:/scan:ro" "$ORACLE_IMG" dir /scan --log-level error \
    > "$OUT/$ID.cbomkit.cdx.json" 2>"$OUT/$ID.cbomkit.log" || echo "[$ID] cbomkit failed"
  if [ -s "$OUT/$ID.cbomkit.cdx.json" ]; then
    trim_cdx "$OUT/$ID.cbomkit.cdx.json" "$BASE/$ID.cbomkit.cdx.json"
    echo "[$ID] froze cbomkit baseline"
  fi

  if command -v npx >/dev/null 2>&1; then
    echo "[$ID] cdxgen..."
    FETCH_LICENSE=false npx --yes @cyclonedx/cdxgen@11 -t python --include-crypto --spec-version 1.6 \
      -o "$OUT/$ID.cdxgen.cdx.json" "$target" >"$OUT/$ID.cdxgen.log" 2>&1 || true
    if [ -s "$OUT/$ID.cdxgen.cdx.json" ]; then
      trim_cdx "$OUT/$ID.cdxgen.cdx.json" "$BASE/$ID.cdxgen.cdx.json"
      echo "[$ID] froze cdxgen baseline"
    fi
  fi

  echo "[$ID] ours..."
  ( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run python "$CBOM/emit_ours.py" \
      "$target" "$OUT/$ID.ours.cdx.json" ) >"$OUT/$ID.ours.log" 2>&1 || true
  echo "[$ID] DONE"
}

# Prefer Phase 6 new freezes; refresh pyjwt/pyopenssl optional via ALL=1
IDS=(03-cryptography 04-mitmproxy 05-paramiko)
if [ "${ALL:-0}" = 1 ]; then
  IDS=(01-pyjwt 02-pyopenssl 03-cryptography 04-mitmproxy 05-paramiko)
fi
for id in "${IDS[@]}"; do
  freeze_one "$id" || echo "freeze $id failed"
done
echo "Baselines now:"; ls -la "$BASE" | sed -n '1,30p'
