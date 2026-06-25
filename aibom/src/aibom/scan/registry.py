"""Self-registering scanner registry.

A scanner is one file. It subclasses :class:`Scanner`, decorates itself with
``@register``, and on ``scan`` appends components, typed **edges**, and semantic
**flags** to the shared :class:`ScanContext`. Scanners NEVER compute scores
(that is the scorer's job) and never serialize (that is the reporters' job).

Registration order is import order; the pipeline imports
:mod:`aibom.scan.scanners` which imports each scanner module. Earlier scanners'
components are visible to later ones (e.g. the model scanner links
``depends_on`` edges to frameworks the requirements scanner already added).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from aibom.model.component import AIComponent, MetadataComponent
from aibom.model.result import Edge, Flag


class ScanContext:
    """Mutable accumulator threaded through every scanner in a run."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.components: list[AIComponent] = []
        self.edges: list[Edge] = []
        self.flags: list[Flag] = []
        self.subject: MetadataComponent | None = None
        self.properties: dict[str, str] = {}

    # --- mutation helpers (the scanner-facing API) ---------------------- #

    def add_component(self, component: AIComponent) -> None:
        self.components.append(component)

    def add_edge(self, src: str, rel: str, dst: str) -> None:
        self.edges.append(Edge(src=src, rel=rel, dst=dst))

    def add_flag(
        self,
        code: str,
        target: str,
        *,
        severity: str = "warning",
        message: str = "",
        advisory: bool = True,
    ) -> None:
        self.flags.append(
            Flag(
                code=code,
                target=target,
                severity=severity,
                message=message,
                advisory=advisory,
            )
        )

    # --- read helpers --------------------------------------------------- #

    def components_of_kind(self, kind: str) -> list[AIComponent]:
        return [c for c in self.components if c.kind == kind]

    def has_ref(self, ref: str) -> bool:
        return any(c.bom_ref == ref for c in self.components)


class Scanner(ABC):
    """Base class for a self-registering scanner."""

    #: short, stable identifier (for logging / debugging).
    name: str = "scanner"

    #: explicit run order (low first). Scanners that produce components other
    #: scanners link to (e.g. frameworks) run before the linkers. This keeps
    #: correctness independent of import/registration order.
    order: int = 100

    #: scan LEVEL (depth). 1=filesystem (default), 2=docker, 3=network/env,
    #: 4=cloud IaC, 5=live cloud. ``scan_repo(path, level=N)`` runs scanners with
    #: ``level <= N`` — each level is a registry entry, no special-casing (D4).
    level: int = 1

    def matches(self, root: Path) -> bool:
        """Whether this scanner has anything to do for ``root`` (default: yes)."""
        return True

    @abstractmethod
    def scan(self, ctx: ScanContext) -> None:
        """Inspect ``ctx.root`` and append components/edges/flags to ``ctx``."""


# The live registry, populated by @register at import time.
SCANNERS: list[Scanner] = []


def register(cls: type[Scanner]) -> type[Scanner]:
    """Class decorator: instantiate ``cls`` and add it to :data:`SCANNERS`.

    Idempotent: re-importing or reloading a scanner module (which re-runs this
    decorator) does not register the scanner twice — keeping ``ordered_scanners``
    and therefore the emitted BOM deterministic.
    """
    if any(type(s) is cls or s.name == cls.name for s in SCANNERS):
        return cls
    SCANNERS.append(cls())
    return cls


def ordered_scanners() -> list[Scanner]:
    """Registered scanners sorted by explicit ``order`` (then ``name``)."""
    return sorted(SCANNERS, key=lambda s: (s.order, s.name))


__all__ = ["ScanContext", "Scanner", "SCANNERS", "register", "ordered_scanners"]
