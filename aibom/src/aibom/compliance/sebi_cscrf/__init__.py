"""SEBI CSCRF compliance package — lane modules register on import.

Import isolation:
- ``ai`` may be imported from ``aibom.compliance`` (AIBOM runner).
- ``crypto`` must only be imported from ``aibom.cbom.compliance``.
- ``sbom`` must only be imported from ``aibom.sbom.compliance``.
"""

from __future__ import annotations

from aibom.compliance.sebi_cscrf.common import (
    FRAMEWORK_LABELS,
    SEBI_DISCLAIMER,
    load_ledger,
    requirement_ids,
    requirements_for,
)

__all__ = [
    "FRAMEWORK_LABELS",
    "SEBI_DISCLAIMER",
    "load_ledger",
    "requirement_ids",
    "requirements_for",
]
