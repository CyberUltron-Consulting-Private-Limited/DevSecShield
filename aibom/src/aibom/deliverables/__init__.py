"""Client deliverables generated FROM ``ScanResult.compliance`` (advisory).

A deliverable is a pure consumer of the compliance report: it reads the
``{framework: {pass,fail,na,coverage,requirements}}`` dict and writes an office
document (xlsx traceability matrix / pdf readiness report / docx SaMD-PCCP memo).

This is a separate lane from BOM emit: emitters are no-I/O/no-network pure
serializers; deliverables intentionally WRITE files (that is their product).
They never run checks or read the graph directly — only the already-computed
``compliance`` report — so they cannot leak check logic.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

# Display titles + the canonical framework order used by every deliverable.
FRAMEWORK_TITLES: dict[str, str] = {
    "fda_524b": "FDA §524B",
    "eu_ai_act_annexIV": "EU AI Act Annex IV",
    "gmlp": "IMDRF GMLP",
    "hipaa": "HIPAA",
    "nist_rmf": "NIST AI RMF",
}

#: format -> writer(compliance, path, subject) -> None
Writer = Callable[[dict[str, Any], Path, str], None]
_WRITERS: dict[str, Writer] = {}


def register_writer(fmt: str) -> Callable[[Writer], Writer]:
    def _decorate(fn: Writer) -> Writer:
        _WRITERS[fmt] = fn
        return fn

    return _decorate


def get_writer(fmt: str) -> Writer:
    # Importing the modules registers their writers (lazy to keep deps optional).
    from aibom.deliverables import docx, pdf, xlsx  # noqa: F401

    if fmt not in _WRITERS:
        raise KeyError(f"unknown deliverable format {fmt!r}; choose: xlsx|pdf|docx")
    return _WRITERS[fmt]


def available_formats() -> list[str]:
    from aibom.deliverables import docx, pdf, xlsx  # noqa: F401

    return sorted(_WRITERS)


def coverage_label(coverage: float | None) -> str:
    """Coverage as a display string; 'N/A' when there are 0 applicable checks."""
    return "N/A" if coverage is None else f"{coverage * 100:.0f}%"


__all__ = [
    "FRAMEWORK_TITLES",
    "Writer",
    "register_writer",
    "get_writer",
    "available_formats",
    "coverage_label",
]
