"""CBOM scanner registry — a peer of :mod:`aibom.scan.registry`.

CBOM scanners use the SAME contract and the SAME
:class:`~aibom.scan.registry.ScanContext` accumulator as AIBOM scanners (emit
components/edges/flags, never score), but
register into a SEPARATE list so they never run inside the AIBOM ``scan_repo``
pipeline (which would pollute the AIBOM emit goldens, differential, and
dashboard). The CBOM pipeline (:mod:`aibom.cbom.pipeline`) runs only these.

Adding a CBOM scanner is one file: subclass :class:`~aibom.scan.registry.Scanner`,
decorate with :func:`cbom_register`, and import it in
:mod:`aibom.cbom.scanners`.
"""

from __future__ import annotations

from aibom.scan.registry import Scanner

# The live CBOM registry, populated by @cbom_register at import time. Deliberately
# distinct from aibom.scan.registry.SCANNERS.
CBOM_SCANNERS: list[Scanner] = []


def cbom_register(cls: type[Scanner]) -> type[Scanner]:
    """Class decorator: instantiate ``cls`` and add it to :data:`CBOM_SCANNERS`.

    Idempotent (re-import / reload does not double-register), keeping the emitted
    CBOM deterministic — mirrors :func:`aibom.scan.registry.register`.
    """
    if any(type(s) is cls or s.name == cls.name for s in CBOM_SCANNERS):
        return cls
    CBOM_SCANNERS.append(cls())
    return cls


def ordered_cbom_scanners() -> list[Scanner]:
    """Registered CBOM scanners sorted by explicit ``order`` (then ``name``)."""
    return sorted(CBOM_SCANNERS, key=lambda s: (s.order, s.name))


__all__ = ["CBOM_SCANNERS", "cbom_register", "ordered_cbom_scanners"]
