#!/usr/bin/env bash
# bench/sbom/run.sh — clone pin + cdxgen inventory oracle + ours package projection.
# Usage: run.sh <id>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"; REPOS="$HERE/repos"; mkdir -p "$OUT" "$REPOS" "$HERE/state"
ID="$1"

row=$(grep -E "^${ID}\b" "$HERE/repos.tsv") || { echo "no repos.tsv row for $ID"; exit 2; }
IFS=$'\t' read -r _id slug url subdir note <<<"$row"

dir="$REPOS/$ID"
pin=$(awk -F'\t' -v id="$ID" '$1==id{print $3; exit}' "$HERE/state/shas.tsv")
if [ ! -d "$dir/.git" ]; then
  echo "[$ID] cloning $url ..."
  GIT_LFS_SKIP_SMUDGE=1 git clone --filter=blob:none --quiet "$url" "$dir" \
    || { echo "[$ID] CLONE FAILED"; exit 3; }
fi
if [ -n "${pin:-}" ]; then
  git -C "$dir" fetch --depth 1 origin "$pin" >/dev/null 2>&1 || true
  git -C "$dir" checkout --quiet "$pin" 2>/dev/null \
    || git -C "$dir" checkout --quiet "origin/$pin" 2>/dev/null \
    || echo "[$ID] pin checkout best-effort failed; using $(git -C "$dir" rev-parse --short HEAD)"
fi
sha=$(git -C "$dir" rev-parse --short HEAD)
target="$dir/$subdir"
echo "[$ID] target=$target sha=$sha"

if command -v npx >/dev/null 2>&1; then
  echo "[$ID] cdxgen ..."
  FETCH_LICENSE=false npx --yes @cyclonedx/cdxgen@11 -t python --spec-version 1.6 \
    -o "$OUT/$ID.cdxgen.cdx.json" "$target" \
    >"$OUT/$ID.cdxgen.log" 2>&1 && echo "[$ID] cdxgen ok" || echo "[$ID] cdxgen failed"
else
  echo "[$ID] npx missing — cdxgen skipped"
fi

echo "[$ID] ours (pip freeze / requirements projection) ..."
( cd "$ROOT" && python3 "$HERE/emit_ours.py" "$target" "$OUT/$ID.ours.json" ) \
  >"$OUT/$ID.ours.log" 2>&1
echo "[$ID] ours exit=$? DONE"
