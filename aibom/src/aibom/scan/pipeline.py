"""Scan pipeline: a model repo on disk -> a scored :class:`ScanResult`.

The pipeline is thin by design. It imports :mod:`aibom.scan.scanners` (which
self-registers every scanner), runs each matching scanner over a shared
:class:`ScanContext`, assembles a :class:`ScanResult`, and hands it to the
scorer. All real work lives in the scanners (components/edges/flags) and the
scorer (scores) — adding a scanner or changing the score model never touches
this file.
"""

from __future__ import annotations

from pathlib import Path

# Importing the scanners package self-registers every scanner into SCANNERS.
import aibom.scan.scanners  # noqa: F401
from aibom.model.component import MetadataComponent
from aibom.model.result import ScanResult
from aibom.scan.registry import ScanContext, ordered_scanners
from aibom.score.scorer import score_result

# Canonical component presentation order (subject-relevant first), then bom_ref.
_KIND_ORDER = {
    "model": 0,
    "dataset": 1,
    "framework": 2,
    "service": 3,
    "infra": 4,
    "prompt": 5,
    "secret": 6,
}


def scan_repo(path: str | Path, weights_path: str | None = None) -> ScanResult:
    """Scan a model repo at ``path`` into a scored :class:`ScanResult`.

    Raises ``NotADirectoryError`` if ``path`` is not an existing directory.
    """
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")

    ctx = ScanContext(root)
    for scanner in ordered_scanners():
        if scanner.matches(root):
            scanner.scan(ctx)

    components = sorted(
        ctx.components, key=lambda c: (_KIND_ORDER.get(c.kind, 9), c.bom_ref)
    )
    result = ScanResult(
        subject=ctx.subject or MetadataComponent(name=root.name),
        components=components,
        edges=ctx.edges,
        flags=ctx.flags,
        properties=ctx.properties,
    )
    result.sort()  # deterministic, golden-stable edge/flag ordering
    score_result(result, weights_path)  # writes result.scores
    return result


__all__ = ["scan_repo"]
