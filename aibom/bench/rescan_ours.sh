#!/usr/bin/env bash
# Re-run OURS only, at level 4 (production depth), on every repo. Re-clones the
# manifest repos (no Bedrock, fast); chroma in-place; repo0 from the local copy.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/out"; REPOS="$HERE/repos"; AIBOM="$(cd "$HERE/.." && pwd)"
MAXJ="${MAXJ:-3}"; mkdir -p "$OUT" "$REPOS"

emit() { cd "$AIBOM" && uv run python "$HERE/emit_ours.py" "$1" "$2"; }

# repo0 (local) + chroma (in-place, scoped to the python pkg)
emit "$REPOS/synthetic-app" "$OUT/repo0-synthetic.ours.cdx.json" >"$OUT/repo0-synthetic.ours.log" 2>&1 &
CHR="$AIBOM/tests/fixtures/chroma/chromadb"; [ -d "$CHR" ] || CHR="$AIBOM/tests/fixtures/chroma"
emit "$CHR" "$OUT/chroma.ours.cdx.json" >"$OUT/chroma.ours.log" 2>&1 &

n=0
while IFS='|' read -r key url subdir flags; do
  key="$(echo "$key"|xargs)"; [[ -z "$key" || "$key" == \#* ]] && continue
  url="$(echo "$url"|xargs)"; subdir="$(echo "$subdir"|xargs)"; flags="$(echo "$flags"|xargs)"
  (
    DEST="$REPOS/$key"; rm -rf "$DEST"
    CE=""; [[ "$flags" == *nolfs* ]] && CE="GIT_LFS_SKIP_SMUDGE=1"
    if env $CE git clone --depth 1 --quiet "$url" "$DEST" 2>/dev/null; then
      SCAN="$DEST"; [[ "$subdir" != "." && -d "$DEST/$subdir" ]] && SCAN="$DEST/$subdir"
      emit "$SCAN" "$OUT/$key.ours.cdx.json" >"$OUT/$key.ours.log" 2>&1
      rm -rf "$DEST"
    else echo "CLONE FAILED $key" >"$OUT/$key.ours.log"; fi
  ) &
  n=$((n+1)); if (( n % MAXJ == 0 )); then wait; fi
done < "$HERE/repos.txt"
wait
echo "OURS RESCAN COMPLETE (level 4)"
