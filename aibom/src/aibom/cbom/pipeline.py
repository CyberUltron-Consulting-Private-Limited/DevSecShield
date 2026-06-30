"""CBOM scan pipeline: a repo on disk -> a :class:`~aibom.model.result.ScanResult`
of ``crypto_asset`` components.

A peer of :func:`aibom.scan.pipeline.scan_repo`, kept deliberately thin: it
imports :mod:`aibom.cbom.scanners` (which self-registers every CBOM scanner),
runs each matching scanner over a shared
:class:`~aibom.scan.registry.ScanContext`, and assembles a ``ScanResult``.

It does NOT call the AIBOM scorer or the OWASP-LLM mapper — those are AIBOM
concerns. The CBOM ``scores`` seam is filled here (C8) by the CBOM scorer, which
weights the crypto flags (weak crypto -> high, quantum-vulnerable -> medium,
expired certificate -> high; per-asset flags stack) with the same machinery as
the AIBOM scorer but a separate weights file. The ``compliance`` seam is filled
here too (C7): after inventory, the crypto-regulatory frameworks (NIST SP
1800-38B / SP 800-57, OMB M-23-02, EU CRA / DORA) are mapped onto the graph with
the same tri-state verdict model as the AIBOM lane.
"""

from __future__ import annotations

from pathlib import Path

# Importing the CBOM scanners package self-registers every CBOM scanner.
import aibom.cbom.scanners  # noqa: F401
from aibom.cbom.compliance import run_cbom_compliance
from aibom.cbom.registry import ordered_cbom_scanners
from aibom.cbom.scorer import score_crypto
from aibom.model.component import AIComponent, MetadataComponent
from aibom.model.result import ScanResult
from aibom.scan.registry import ScanContext


def _dedup_by_ref(components: list[AIComponent]) -> list[AIComponent]:
    """Collapse components that share a ``bom_ref`` to the richest one.

    Two CBOM scanners can legitimately detect the same logical asset — the AST
    scanner (C1) and the line-regex scanner emit identical
    ``crypto-algo-{name}-{file}`` refs for the same usage. Keeping the component
    with the most ``properties`` preserves the argument-bound (richer) detection
    while guaranteeing the emitted BOM has no duplicate refs (a determinism +
    schema-validity invariant). Ties keep the first occurrence (stable)."""
    best: dict[str, AIComponent] = {}
    order: list[str] = []
    for comp in components:
        ref = comp.bom_ref
        if ref not in best:
            best[ref] = comp
            order.append(ref)
        elif len(comp.properties or {}) > len(best[ref].properties or {}):
            best[ref] = comp
    return [best[ref] for ref in order]


def scan_crypto(path: str | Path, level: int = 1) -> ScanResult:
    """Scan a repo at ``path`` into a CBOM :class:`ScanResult`.

    Only CBOM scanners with ``scanner.level <= level`` run. Raises
    ``NotADirectoryError`` if ``path`` is not a directory.
    """
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")

    ctx = ScanContext(root)
    for scanner in ordered_cbom_scanners():
        if scanner.level <= level and scanner.matches(root):
            scanner.scan(ctx)

    components = _dedup_by_ref(ctx.components)
    result = ScanResult(
        subject=ctx.subject or MetadataComponent(name=root.name),
        components=sorted(components, key=lambda c: (c.kind, c.bom_ref)),
        edges=ctx.edges,
        flags=ctx.flags,
        properties=ctx.properties,
    )
    result.sort()
    score_crypto(result)  # C8: weight crypto flags -> result.scores (stacked severity)
    run_cbom_compliance(result)  # C7: fill the compliance seam (tri-state, graph-only)
    return result


__all__ = ["scan_crypto"]
