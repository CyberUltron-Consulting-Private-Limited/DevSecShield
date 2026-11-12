"""MANIFEST.json + SHA256SUMS for a run directory (G17), and their verification.

SHA256SUMS uses the coreutils format (``<hex>  <relative path>``) so ``cd <run> && sha256sum -c SHA256SUMS`` works
without the harness. It covers every file except itself; MANIFEST.json is covered, and MANIFEST.json records the
oracle hash taken before "Start scan" (O-5) and, at the end, the sha256 of SHA256SUMS is printed for the PR.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import SCHEMA_MANIFEST
from .rundir import iso, read_json, sha256_file, sha256_tree, utc_now, write_json

SUMS = "SHA256SUMS"
MANIFEST = "MANIFEST.json"


def oracle_hash(run: Path) -> str | None:
    files = sorted(p for p in (Path(run) / "oracle").rglob("*") if p.is_file())
    return sha256_tree(files, Path(run)) if files else None


def freeze_oracle(run: Path) -> dict[str, Any]:
    """O-5: record sha256(oracle/*) in MANIFEST.json before Start. A later different hash means the oracle changed
    after the run started; the judge then refuses to judge that run (a new run is needed)."""
    manifest = read_json(Path(run) / MANIFEST, {}) or {}
    manifest.setdefault("schema", SCHEMA_MANIFEST)
    oracle_dir = Path(run) / "oracle"
    manifest["oracle"] = {"sha256": oracle_hash(run), "frozen_at": iso(utc_now()),
                          "files": sorted(p.relative_to(run).as_posix() for p in oracle_dir.rglob("*") if p.is_file())
                          if oracle_dir.is_dir() else []}
    write_json(Path(run) / MANIFEST, manifest)
    return manifest["oracle"]


def update(run: Path, **sections: Any) -> dict[str, Any]:
    manifest = read_json(Path(run) / MANIFEST, {}) or {}
    manifest.setdefault("schema", SCHEMA_MANIFEST)
    for key, value in sections.items():
        if isinstance(value, dict) and isinstance(manifest.get(key), dict):
            manifest[key].update(value)
        else:
            manifest[key] = value
    write_json(Path(run) / MANIFEST, manifest)
    return manifest


def write_sums(run: Path) -> str:
    """Write SHA256SUMS over every file but itself and return its own sha256 (the value posted on the PR)."""
    run = Path(run)
    lines = []
    for path in sorted(p for p in run.rglob("*") if p.is_file() and p.name != SUMS and not p.name.endswith(".tmp")):
        lines.append(f"{sha256_file(path)}  {path.relative_to(run).as_posix()}")
    (run / SUMS).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return hashlib.sha256((run / SUMS).read_bytes()).hexdigest()


def verify(run: Path) -> list[str]:
    """Problems found by re-hashing: changed, missing and unlisted files. Empty list = the bundle is intact."""
    run = Path(run)
    sums = run / SUMS
    if not sums.is_file():
        return [f"{SUMS} missing"]
    problems, listed = [], set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        listed.add(rel)
        path = run / rel
        if not path.is_file():
            problems.append(f"missing {rel}")
        elif sha256_file(path) != digest:
            problems.append(f"changed {rel}")
    for path in run.rglob("*"):
        if path.is_file() and path.name != SUMS and path.relative_to(run).as_posix() not in listed:
            problems.append(f"unlisted {path.relative_to(run).as_posix()}")
    return problems


def oracle_unchanged(run: Path) -> tuple[bool, str]:
    manifest = read_json(Path(run) / MANIFEST, {}) or {}
    frozen = (manifest.get("oracle") or {}).get("sha256")
    now = oracle_hash(run)
    if frozen is None:
        return (now is None), ("no oracle frozen before Start" if now else "no oracle")
    return frozen == now, ("oracle unchanged since Start" if frozen == now else "oracle changed after Start (O-5)")
