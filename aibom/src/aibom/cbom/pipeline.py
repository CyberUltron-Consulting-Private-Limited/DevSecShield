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
from typing import Any

# Importing the CBOM scanners package self-registers every CBOM scanner.
import aibom.cbom.scanners  # noqa: F401
from aibom.cbom.compliance import run_cbom_compliance
from aibom.cbom.posture.assemble import discard_posture, finalize_posture
from aibom.cbom.posture.context import CbomScanContext, CbomScanResult
from aibom.cbom.registry import ordered_cbom_scanners
from aibom.cbom.scorer import score_crypto
from aibom.model.component import AIComponent, MetadataComponent
from aibom.model.result import ScanResult

_TIME_LIMITS = frozenset({"SoftTimeLimitExceeded", "TimeLimitExceeded"})


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


def scan_crypto(
    path: str | Path,
    level: int = 1,
    *,
    seed: list[AIComponent] | None = None,
    subject: MetadataComponent | None = None,
) -> ScanResult:
    """Scan a repo at ``path`` into a CBOM :class:`ScanResult`.

    Only CBOM scanners with ``scanner.level <= level`` run. Raises
    ``NotADirectoryError`` if ``path`` is not a directory. ``seed`` components
    (an imported CBOM) are placed on the context before the scanners run, so
    the flagging / PQC / scoring scanners judge them exactly like inventoried
    assets.
    """
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")

    ctx = CbomScanContext(root)
    for component in seed or []:
        ctx.add_component(component)
    if subject is not None:
        ctx.subject = subject
    for scanner in ordered_cbom_scanners():
        if scanner.level <= level and scanner.matches(root):
            scanner.scan(ctx)

    components = _dedup_by_ref(ctx.components)
    edges = ctx.edges
    flags = ctx.flags
    properties = ctx.properties
    assembly_failed = False
    try:
        components, edges, flags, properties = finalize_posture(
            components, edges, flags, properties, ctx.posture
        )
    except Exception as exc:
        if type(exc).__name__ in _TIME_LIMITS:
            raise
        ctx.posture.diagnostics.add("internal_error", "", 0)
        components, edges, flags, properties = discard_posture(
            components, edges, flags, properties
        )
        assembly_failed = True
    result = CbomScanResult(
        subject=ctx.subject or MetadataComponent(name=root.name),
        components=sorted(components, key=lambda c: (c.kind, c.bom_ref)),
        edges=edges,
        flags=flags,
        properties=properties,
        posture=ctx.posture.freeze(assembly_failed=assembly_failed),
    )
    result.sort()
    score_crypto(result)  # C8: weight crypto flags -> result.scores (stacked severity)
    run_cbom_compliance(result)  # C7: fill the compliance seam (tri-state, graph-only)
    return result


def analyze_cbom_document(doc: Any, level: int = 4) -> tuple[ScanResult, dict[str, Any]]:
    """Judge an uploaded CycloneDX CBOM with the same rules as a repository scan.

    Returns the scored result and the import statistics (what was read, skipped
    or truncated). Runs over an empty scratch directory so no repository
    scanner finds anything of its own.
    """
    import tempfile

    from aibom.cbom.ingest import components_from_cyclonedx

    seed, stats = components_from_cyclonedx(doc)
    metadata = doc.get("metadata") if isinstance(doc, dict) else None
    meta = metadata.get("component") if isinstance(metadata, dict) else None
    name = str((meta if isinstance(meta, dict) else {}).get("name") or "uploaded-cbom")[:200]
    with tempfile.TemporaryDirectory(prefix="cbom-upload-") as scratch:
        result = scan_crypto(scratch, level=level, seed=seed, subject=MetadataComponent(name=name))
    return result, stats.as_dict()


__all__ = ["analyze_cbom_document", "scan_crypto"]
