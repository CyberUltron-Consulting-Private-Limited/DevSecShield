"""CBOM scan pipeline: a repo on disk -> a :class:`~aibom.model.result.ScanResult`
of ``crypto_asset`` components.

A peer of :func:`aibom.scan.pipeline.scan_repo`, kept deliberately thin: it
imports :mod:`aibom.cbom.scanners` (which self-registers every CBOM scanner),
runs each matching scanner over a shared
:class:`~aibom.scan.registry.ScanContext`, and assembles a ``ScanResult``.

It does NOT call the AIBOM scorer or the OWASP-LLM mapper — those are AIBOM
concerns. The CBOM scorer/severity layer lands in C8; until then ``scores`` and
``compliance`` are empty seams.
"""

from __future__ import annotations

from pathlib import Path

# Importing the CBOM scanners package self-registers every CBOM scanner.
import aibom.cbom.scanners  # noqa: F401
from aibom.cbom.registry import ordered_cbom_scanners
from aibom.model.component import MetadataComponent
from aibom.model.result import ScanResult
from aibom.scan.registry import ScanContext


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

    result = ScanResult(
        subject=ctx.subject or MetadataComponent(name=root.name),
        components=sorted(ctx.components, key=lambda c: (c.kind, c.bom_ref)),
        edges=ctx.edges,
        flags=ctx.flags,
        properties=ctx.properties,
    )
    result.sort()
    return result


__all__ = ["scan_crypto"]
