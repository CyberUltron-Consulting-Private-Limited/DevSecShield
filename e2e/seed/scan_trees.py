#!/usr/bin/env python3
"""Scan every ephemeral tree with the REAL CBOM engine (plan 7.4 step 2).

Runs inside the ``aibom-scan`` container (profile ``seed``): no network, read-only root filesystem,
no capabilities.  For each directory under ``$E2E_TREES_DIR`` (default ``/work/trees``) it calls the
exact function the production worker calls (``scan_worker.cbom``)::

    aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield(path, level=4)

and writes ``$E2E_OUT_DIR/<tree>.scan_data.json`` (default ``/work/out``): the persisted
``Scan.scan_data`` run-object, as compact JSON with sorted keys.  ``seed_team.py`` stores these files
verbatim in the database, so what the specs see in the PDFs is what this scanner produced.

Evidence written next to the scan outputs:

* ``scan_summary.json``  per tree: rows, components, certificate / library counts, the SHA-256 of the
  canonical run-object (``duration_of_scan`` zeroed, so two scans of one tree compare equal), the
  real scan duration, and the interpreter / ``aibom`` location.  ``check_determinism.sh`` compares a
  second scan of the same tree (host ``aibom/.venv``, another interpreter) against these hashes.

Self-checks (any failure exits non-zero, so ``seed.sh`` stops before anything is stored):

* every tree is scanned twice in this process and the two run-objects must be identical apart from
  ``duration_of_scan``;
* the run-object must be a Tier-A one (``results``, ``cbom_json``, ``cbom_compliance``,
  ``cbom_distributions``) - a partial output would silently degrade the roll-up to "reduced fidelity";
* the tree's absolute path must not leak into the output (it would make the fixture machine specific).

Standard library only.  No LLM, no network: the CBOM lane is deterministic pure Python.

Environment (all optional):

``E2E_TREES_DIR``  trees to scan                 (default ``/work/trees``)
``E2E_OUT_DIR``    where the JSON files go      (default ``/work/out``)
``E2E_SCAN_ONLY``  comma separated tree names to scan (default: all)
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

LEVEL = 4  # the product runs the CBOM engine at level 4 (scan_worker.cbom)
REQUIRED_KEYS = ("results", "cbom_json", "cbom_compliance", "cbom_distributions", "duration_of_scan")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_hash(run: dict[str, Any]) -> str:
    """SHA-256 of the run-object with the wall-clock duration zeroed."""
    stable = dict(run)
    stable["duration_of_scan"] = 0
    return hashlib.sha256(_dumps(stable).encode("utf-8")).hexdigest()


def _components(run: dict[str, Any]) -> list[dict[str, Any]]:
    bom = run.get("cbom_json")
    comps = bom.get("components") if isinstance(bom, dict) else None
    return [c for c in comps or [] if isinstance(c, dict)]


def summarize(name: str, run: dict[str, Any], seconds: float) -> dict[str, Any]:
    rows = [r for r in run.get("results") or [] if isinstance(r, dict)]
    components = _components(run)
    certificates = sum(
        1 for c in components if (c.get("cryptoProperties") or {}).get("assetType") == "certificate"
    )
    libraries = sum(1 for c in components if c.get("type") == "library")
    return {
        "tree": name,
        "rows": len(rows),
        "components": len(components),
        "certificates": certificates,
        "libraries": libraries,
        "keys": sorted(run),
        "sha256": canonical_hash(run),
        "duration_of_scan": run.get("duration_of_scan"),
        "wall_seconds": round(seconds, 3),
    }


def scan_one(tree: Path, scan: Any) -> dict[str, Any]:
    """Scan ``tree`` twice; the two run-objects must agree except for the duration."""
    first = scan(str(tree), level=LEVEL)
    second = scan(str(tree), level=LEVEL)
    if canonical_hash(first) != canonical_hash(second):
        raise SystemExit(f"FATAL: scanning {tree.name} twice in one process gave different results")
    return first


def main() -> int:
    import time

    trees_dir = Path(os.environ.get("E2E_TREES_DIR", "/work/trees"))
    out_dir = Path(os.environ.get("E2E_OUT_DIR", "/work/out"))
    only = {n.strip() for n in os.environ.get("E2E_SCAN_ONLY", "").split(",") if n.strip()}
    if not trees_dir.is_dir():
        print(f"FATAL: trees directory not found: {trees_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    import aibom

    trees = sorted(p for p in trees_dir.iterdir() if p.is_dir() and not p.name.startswith("."))
    if only:
        trees = [p for p in trees if p.name in only]
    if not trees:
        print(f"FATAL: no trees to scan under {trees_dir}", file=sys.stderr)
        return 2

    print(f"aibom: {Path(aibom.__file__).resolve()}  python {platform.python_version()}  level {LEVEL}")
    print(f"scanning {len(trees)} tree(s) from {trees_dir} into {out_dir}")
    summaries: list[dict[str, Any]] = []
    for tree in trees:
        started = time.monotonic()
        run = scan_one(tree, scan_crypto_to_devsecshield)
        seconds = time.monotonic() - started
        missing = [k for k in REQUIRED_KEYS if k not in run]
        if missing:
            print(f"FATAL: {tree.name}: run-object lacks {missing} (not a Tier-A run-object)", file=sys.stderr)
            return 3
        text = _dumps(run)
        if str(trees_dir) in text:
            print(f"FATAL: {tree.name}: the tree's absolute path leaked into the run-object", file=sys.stderr)
            return 3
        target = out_dir / f"{tree.name}.scan_data.json"
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(text + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, target)
        info = summarize(tree.name, run, seconds)
        summaries.append(info)
        print(
            f"  {tree.name:<22} rows={info['rows']:<3} components={info['components']:<3} "
            f"certs={info['certificates']:<2} libs={info['libraries']:<2} "
            f"sha256={info['sha256'][:16]}  {info['wall_seconds']}s  -> {target.name}"
        )

    summary_path = out_dir / "scan_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "level": LEVEL,
                "python": platform.python_version(),
                "aibom": str(Path(aibom.__file__).resolve()),
                "trees": {s["tree"]: s for s in summaries},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(summaries)} scan_data file(s) and {summary_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
