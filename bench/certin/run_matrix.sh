#!/usr/bin/env bash
# bench/certin/run_matrix.sh — clone pins + optional oracle lanes + print scan enqueue hints.
# Live product scans are driven by backend/tests/test_certin_phase6_e2e.py.
# Usage: bash bench/certin/run_matrix.sh [--oracles] [--sbom-oracles]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DO_ORACLES=0
DO_SBOM=0
for a in "$@"; do
  case "$a" in
    --oracles) DO_ORACLES=1 ;;
    --sbom-oracles) DO_SBOM=1 ;;
  esac
done

echo "== CERT-In Phase 6 matrix manifest =="
awk -F'\t' 'NR>1 && $1!=""{printf "%s %s %s@%s subdir=%s\n",$1,$2,$3,$5,$6}' "$HERE/repos.tsv"

if [ "$DO_ORACLES" = 1 ]; then
  echo "== CBOM oracle freeze (03/04/05 + refresh 01/02) =="
  bash "$HERE/freeze_cbom_baselines.sh" || echo "CBOM freeze had failures — see logs"
fi

if [ "$DO_SBOM" = 1 ]; then
  echo "== SBOM cdxgen inventory =="
  for id in 01-requests 02-flask 03-urllib3 04-sqlalchemy 05-click; do
    bash "$ROOT/bench/sbom/run.sh" "$id" || echo "SBOM $id failed"
  done
  ( cd "$ROOT/bench/sbom" && python3 diff.py ) || true
  bash "$HERE/freeze_sbom_baselines.sh" || true
fi

echo "== Next: live product matrix =="
echo "  cd backend && uv run pytest tests/test_certin_phase6_e2e.py -q --tb=short"
