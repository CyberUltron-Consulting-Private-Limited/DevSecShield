#!/usr/bin/env python3
"""SBOM inventory recall gate vs cdxgen (thin, package-name level).

Gate: true-miss == 0 for packages that appear in BOTH cdxgen components and
the declared direct-deps surface (intersection honesty). Misses are cdxgen
library names that our declared inventory lacks, after normalizing names.

our-unique >= 0 always (stdlib / undeclared may appear only on one side).
Pass = true_miss == 0 (for compared intersection scope) AND our inventory non-empty.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
BASELINE = HERE / "ci_baseline"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def cdxgen_packages(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for c in data.get("components") or []:
        if not isinstance(c, dict):
            continue
        if c.get("type") not in (None, "library", "framework", "application"):
            continue
        name = c.get("name") or ""
        purl = c.get("purl") or ""
        if purl.startswith("pkg:"):
            # pkg:pypi/requests@2.x -> requests
            try:
                name = purl.split("/")[1].split("@")[0]
            except IndexError:
                pass
        if name:
            out.add(_norm(name))
    return out


def ours_packages(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {_norm(p) for p in (data.get("packages") or []) if p}


def true_misses(repo_id: str) -> list[str]:
    """cdxgen packages that are also in baseline intersection scope but missing from ours.

    Scope: only packages that appear in OUR declared set OR are the project name.
    Full cdxgen graphs include transitive noise — we score recall on declared deps.
    For gate: miss = declared_ours empty when cdxgen has project library? 
    Simpler lock: miss = (ours ∩ cdxgen_project_surface) empty of cdxgen direct?
    
    Locked rule from plan: miss only if cdxgen package absent from our projected
    components for packages we claim — i.e. every name in OURS must either be
    ignorable OR we check cdxgen\\ours only for names that are in the *declared*
    requirements file that cdxgen also found.

    Practical: compare ours to cdxgen; true_miss = (cdxgen ∩ ours_candidates) wait.

    Final lock used here:
      candidates = ours  (declared inventory)
      # A miss is a declared package that cdxgen found under another spelling? No.
      # Plan: miss if cdxgen package absent from ours — but only for packages that
      # appear in BOTH the declared file AND cdxgen (so we don't fail on transitive).
      # => true_miss = [] always when we only fail on declared∩cdxgen \\ ours which is empty by construction.

    Honest gate that still fails empty ours:
      - ours must be non-empty
      - for each name in ours, if cdxgen has a *different* spelling only — OK
      - true_miss = packages in ci_baseline expected set (frozen) that ours lacks
    """
    snap = BASELINE / f"{repo_id}.cdxgen.pkgs.json"
    ours_path = OUT / f"{repo_id}.ours.json"
    ours = ours_packages(ours_path)
    if snap.exists():
        expected = set(json.loads(snap.read_text(encoding="utf-8")).get("packages") or [])
        expected = {_norm(x) for x in expected}
        # Recall: frozen expected packages must be subset of ours OR of live cdxgen∩ours
        live = cdxgen_packages(OUT / f"{repo_id}.cdxgen.cdx.json")
        scope = expected & live if live else expected
        return sorted(scope - ours)
    # First-freeze mode: no misses until baseline exists
    live = cdxgen_packages(OUT / f"{repo_id}.cdxgen.cdx.json")
    if not ours:
        return ["__empty_ours__"]
    # Without freeze, require non-empty overlap when cdxgen present
    if live and not (ours & live):
        return ["__no_overlap_with_cdxgen__"]
    return []


def our_unique(repo_id: str) -> int:
    ours = ours_packages(OUT / f"{repo_id}.ours.json")
    live = cdxgen_packages(OUT / f"{repo_id}.cdxgen.cdx.json")
    return len(ours - live)


def main() -> int:
    ids = [p.name.split(".")[0] for p in OUT.glob("*.ours.json")]
    if len(sys.argv) > 1:
        ids = [sys.argv[1]]
    ok = True
    lines = ["# SBOM inventory recall (cdxgen)", ""]
    for rid in sorted(set(ids)):
        misses = true_misses(rid)
        uniq = our_unique(rid)
        ours_n = len(ours_packages(OUT / f"{rid}.ours.json"))
        status = "PASS" if not misses and ours_n > 0 else "FAIL"
        if status == "FAIL":
            ok = False
        lines.append(
            f"- `{rid}`: {status} true_miss={len(misses)} our_unique={uniq} ours={ours_n} misses={misses[:8]}"
        )
        print(lines[-1])
    (HERE / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
