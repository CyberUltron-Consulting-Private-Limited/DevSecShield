"""Bom-ref prefix, uniqueness, and stability for the committed Terraform tree."""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

TREE = Path(__file__).resolve().parent / "fixtures" / "synthetic-config-aws-tf"
PREFIX = "crypto-cfg_"


def _posture_refs(result: ScanResult) -> list[str]:
    refs: list[str] = []
    for comp in result.components:
        props = comp.properties or {}
        marked = "crypto:factId" in props or "crypto:factSchema" in props
        if marked:
            refs.append(comp.bom_ref)
    return refs


def test_posture_fact_refs_are_prefixed_unique_and_stable() -> None:
    assert TREE.is_dir()
    first = scan_crypto(TREE)
    second = scan_crypto(TREE)
    refs = _posture_refs(first)
    assert refs
    assert all(ref.startswith(PREFIX) for ref in refs)
    assert len(refs) == len(set(refs))
    every = [comp.bom_ref for comp in first.components]
    assert len(every) == len(set(every))
    assert _posture_refs(second) == refs
