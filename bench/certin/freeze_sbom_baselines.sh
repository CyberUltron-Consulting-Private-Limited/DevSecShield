#!/usr/bin/env bash
# Freeze SBOM declared-package baselines from ours∩cdxgen into ci_baseline/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SBOM="$(cd "$HERE/../sbom" && pwd)"
OUT="$SBOM/out"
BASE="$SBOM/ci_baseline"
mkdir -p "$BASE"
python3 - <<PY
import json, re
from pathlib import Path
out = Path("$OUT")
base = Path("$BASE")
def norm(n):
    return re.sub(r"[-_.]+", "-", (n or "").strip().lower())
def cdx_pkgs(p):
    if not p.exists(): return set()
    data = json.loads(p.read_text())
    s=set()
    for c in data.get("components") or []:
        name=c.get("name") or ""
        purl=c.get("purl") or ""
        if purl.startswith("pkg:"):
            try: name=purl.split("/")[1].split("@")[0]
            except IndexError: pass
        if name: s.add(norm(name))
    return s
def ours(p):
    if not p.exists(): return set()
    return {norm(x) for x in json.loads(p.read_text()).get("packages") or []}
for ours_path in sorted(out.glob("*.ours.json")):
    rid = ours_path.name.split(".")[0]
    inter = sorted(ours(ours_path) & cdx_pkgs(out / f"{rid}.cdxgen.cdx.json"))
    if not inter:
        inter = sorted(ours(ours_path))[:20]
    (base / f"{rid}.cdxgen.pkgs.json").write_text(json.dumps({"packages": inter}, indent=2)+"\n")
    print(rid, "froze", len(inter))
PY
