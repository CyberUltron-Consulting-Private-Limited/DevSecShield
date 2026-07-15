#!/usr/bin/env bash
# bench/cbom/run.sh — clone (shallow, record SHA) + LIVE-run BOTH tools on one repo:
# the IBM cbomkit-theia oracle (docker) and OURS (offline, deterministic).
# Isolated harness (NOT product code). Usage: run.sh <id>   (reads repos.tsv row)
# Env: docker available + ghcr.io/cbomkit/cbomkit-theia pulled. No AWS/Bedrock.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"; REPOS="$HERE/repos"; mkdir -p "$OUT" "$REPOS" "$HERE/state"
ID="$1"
ORACLE_IMG="${ORACLE_IMG:-ghcr.io/cbomkit/cbomkit-theia:latest}"

row=$(grep -E "^${ID}\b" "$HERE/repos.tsv") || { echo "no repos.tsv row for $ID"; exit 2; }
IFS=$'\t' read -r _id slug url subdir note <<<"$row"

# --- clone (shallow) + record SHA --------------------------------------------
dir="$REPOS/$ID"
if [ "$url" = "-" ]; then
  # local fixture: mirror it under repos/ so the oracle + ours scan the same tree
  src="$ROOT/aibom/tests/fixtures/synthetic-crypto-app"
  mkdir -p "$dir"; cp -R "$src/." "$dir/"
  echo "[$ID] local fixture copied to $dir"
else
  if [ ! -d "$dir/.git" ]; then
    echo "[$ID] cloning $url (shallow) ..."
    GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --quiet "$url" "$dir" \
      || { echo "[$ID] CLONE FAILED"; exit 3; }
  fi
fi
sha=$(git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo "local")
echo "$ID	$slug	$sha	$subdir" >> "$HERE/state/shas.tsv"
target="$dir/$subdir"
echo "[$ID] target=$target sha=$sha"

# --- Oracle 1: IBM cbomkit-theia (filesystem: certs/keys/secrets/openssl) -----
echo "[$ID] cbomkit-theia (oracle) ..."
docker run --rm -v "$target:/scan:ro" "$ORACLE_IMG" dir /scan --log-level error \
  > "$OUT/$ID.cbomkit.cdx.json" 2>"$OUT/$ID.cbomkit.log"
echo "[$ID] cbomkit exit=$?"

# --- Oracle 2: @cyclonedx/cdxgen (dependency graph: crypto libraries) ----------
# cdxgen is the reference CycloneDX BOM generator; with --include-crypto it
# resolves the project's library graph. Compared in the crypto-LIBRARY lane
# (diff.py filters to known crypto libs). No docker; runs via npx. Best-effort:
# a cdxgen failure/absence just skips this oracle for the repo (diff.py handles a
# missing snapshot). CDXGEN_TYPE overrides the auto -t (python|javascript|java).
if command -v npx >/dev/null 2>&1; then
  echo "[$ID] cdxgen (oracle) ..."
  FETCH_LICENSE=false npx --yes @cyclonedx/cdxgen@11 -t "${CDXGEN_TYPE:-python}" \
    --include-crypto --spec-version 1.6 -o "$OUT/$ID.cdxgen.cdx.json" "$target" \
    > "$OUT/$ID.cdxgen.log" 2>&1 && echo "[$ID] cdxgen ok" \
    || echo "[$ID] cdxgen unavailable — oracle skipped for this repo"
else
  echo "[$ID] npx not found — cdxgen oracle skipped"
fi

# --- Ours (source-code crypto scanner, level 4 production depth) --------------
echo "[$ID] ours ..."
( cd "$ROOT/aibom" && AIBOM_LLM_OFFLINE=1 uv run python "$HERE/emit_ours.py" \
    "$target" "$OUT/$ID.ours.cdx.json" ) >"$OUT/$ID.ours.log" 2>&1
echo "[$ID] ours exit=$?"
echo "[$ID] DONE"
