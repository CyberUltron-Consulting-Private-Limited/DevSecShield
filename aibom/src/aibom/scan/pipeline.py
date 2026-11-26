"""Scan pipeline: a model repo on disk -> a scored :class:`ScanResult`.

The pipeline is thin by design. It imports :mod:`aibom.scan.scanners` (which
self-registers every scanner), runs each matching scanner over a shared
:class:`ScanContext`, assembles a :class:`ScanResult`, and hands it to the
scorer. All real work lives in the scanners (components/edges/flags) and the
scorer (scores) — adding a scanner or changing the score model never touches
this file.
"""

from __future__ import annotations

import logging
import re
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


_LOG = logging.getLogger("aibom.scan")
# errors a scanner raises on input it cannot parse (an expected, logged warning)
_PARSE_ERRORS = (ValueError, UnicodeError, OSError, RecursionError, re.error,
                 SyntaxError)


def scan_repo(
    path: str | Path,
    level: int = 1,
    allowlist: str | Path | None = None,
    weights_path: str | None = None,
) -> ScanResult:
    """Scan a repo at ``path`` into a scored :class:`ScanResult`.

    ``level`` selects scan depth: only scanners with ``scanner.level <= level``
    run (1=filesystem … 5=live cloud). ``allowlist`` (a YAML path) enables shadow
    diffing: discovered components not on the allowlist get an ``UNSANCTIONED_*``
    flag before scoring. Raises ``NotADirectoryError`` if ``path`` is not a dir.
    """
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")

    ctx = ScanContext(root)
    errors: list[str] = []
    for scanner in ordered_scanners():
        if scanner.level <= level and scanner.matches(root):
            try:
                scanner.scan(ctx)
            except _PARSE_ERRORS as exc:
                # input the scanner could not parse: the BOM is still produced and
                # says which scanner did not finish (review 6062066749 of #498, M3)
                _LOG.warning("AI BOM scanner %s did not finish: %s: %s", scanner.name,
                             type(exc).__name__, exc)
                errors.append(f"{scanner.name}: {type(exc).__name__}")
            except Exception as exc:  # noqa: BLE001 - one scanner never aborts a scan
                # an engine bug, not bad input: logged with its traceback at error
                # level and counted, never silent (review 6063080163 of #498, R4-M2)
                _LOG.exception("AI BOM scanner %s failed unexpectedly", scanner.name)
                errors.append(f"{scanner.name}: {type(exc).__name__} (unexpected)")
    if errors:
        ctx.properties["aibom:scanner_errors"] = "; ".join(errors)
        ctx.properties["aibom:scan_completeness"] = "partial"
    if ctx.unreadable_notebooks:
        # read as raw text (JSON escapes undone), and said so in the BOM
        ctx.properties["aibom:notebooks_unreadable"] = ", ".join(
            sorted(ctx.unreadable_notebooks)
        )

    if allowlist is not None:
        # Shadow-AI diff is a finalize step: it EMITS flags (lane-clean), the
        # scorer weights them. Imported here to keep the core pipeline thin.
        from aibom.shadow.diff import flag_unsanctioned

        flag_unsanctioned(ctx, allowlist)

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
    # OWASP-LLM mapping is a pure, cheap projection of components+flags; populate
    # it on every scan so result.owasp is always available (imported here to keep
    # the module graph acyclic and the core pipeline thin).
    from aibom.owasp import annotate as annotate_owasp

    annotate_owasp(result)  # writes result.owasp
    return result


__all__ = ["scan_repo"]
