"""The canonical scan output: :class:`ScanResult` plus :class:`Edge` /
:class:`Flag`.

A scan produces a typed inventory graph, not a flat list:

* ``components`` — the normalized :mod:`aibom.model.component` objects.
* ``edges`` — typed relationships between components (``trained_on``,
  ``depends_on``) that the emitters turn into CycloneDX ``dependencies`` /
  SPDX ``Relationship`` objects.
* ``flags`` — semantic findings raised by scanners (e.g. ``MODEL_NO_LICENSE``).
  Scanners raise flags; they NEVER compute scores.
* ``scores`` — written by :mod:`aibom.score` from the flags (config-driven).
* ``compliance`` — reserved seam for the Phase-3 compliance-mapping layer.

``subject`` and ``properties`` carry the BOM subject (the deployed SaMD
application) and BOM-level namespaced properties for the emitters. Everything is
serializer-agnostic; reporters map it onto exact spec field names.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from aibom.model.component import AIComponent, MetadataComponent

# Edge relationship vocabulary (small, explicit; extend as scanners grow).
REL_TRAINED_ON = "trained_on"
REL_DEPENDS_ON = "depends_on"
REL_SERVED_BY = "served_by"  # model -> inference service (carries service:baa)
REL_DEPLOYED_AT = "deployed_at"  # model -> site (carries version/validation/drift)

# Flag severities == SARIF result levels (so flags map 1:1 to SARIF `level`).
SEVERITIES = ("none", "note", "warning", "error")


@dataclass(frozen=True)
class Edge:
    """A typed, directed relationship between two components (by ``bom_ref``)."""

    src: str
    rel: str
    dst: str

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.rel, self.dst)


@dataclass(frozen=True)
class Flag:
    """A semantic finding about a component (or the BOM, when ``target`` is '').

    Scanners raise flags; the scorer weights them; the SARIF reporter renders
    them. ``advisory`` records that the finding supports — but does not assert —
    a compliance conclusion.
    """

    code: str
    target: str  # bom_ref the flag is about ('' = BOM-level)
    severity: str = "warning"
    message: str = ""
    advisory: bool = True

    def __post_init__(self) -> None:
        # Enforce the SARIF-level invariant at construction, so a bad severity
        # fails at the scanner that set it — not later, at SARIF emit time.
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Flag severity {self.severity!r} is not one of {SEVERITIES} "
                f"(SARIF result levels); flag code={self.code!r}"
            )

    def key(self) -> tuple[str, str]:
        return (self.target, self.code)


@dataclass
class ScanResult:
    """The complete output of a scan: components + graph + findings + scores."""

    subject: MetadataComponent
    components: list[AIComponent] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    scores: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    #: OWASP Top 10 for LLM Applications (2025) distribution {code: count},
    #: written by :mod:`aibom.owasp` from the components + flags.
    owasp: dict[str, Any] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)

    # --- graph helpers -------------------------------------------------- #

    def by_ref(self, ref: str) -> AIComponent | None:
        """Return the component with ``bom_ref == ref`` (or None)."""
        for comp in self.components:
            if comp.bom_ref == ref:
                return comp
        return None

    def out_edges(self, ref: str, rel: str | None = None) -> list[Edge]:
        """Edges leaving ``ref`` (optionally filtered to a relationship type)."""
        return [e for e in self.edges if e.src == ref and (rel is None or e.rel == rel)]

    def neighbors(self, ref: str, rel: str | None = None) -> list[AIComponent]:
        """Components reachable from ``ref`` via its out-edges (resolved, dedup)."""
        seen: list[AIComponent] = []
        for e in self.out_edges(ref, rel):
            comp = self.by_ref(e.dst)
            if comp is not None and comp not in seen:
                seen.append(comp)
        return seen

    def flags_for(self, ref: str) -> list[Flag]:
        """Flags whose target is ``ref``."""
        return [f for f in self.flags if f.target == ref]

    def component_bom_refs(self) -> list[str]:
        """Sorted bom-refs of all components (deterministic serial derivation)."""
        return sorted(c.bom_ref for c in self.components)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable view of the whole scan result (for `aibom scan`)."""
        return {
            "subject": self.subject.model_dump(mode="json", exclude_none=True),
            "components": [
                c.model_dump(mode="json", exclude_none=True) for c in self.components
            ],
            "edges": [asdict(e) for e in self.edges],
            "flags": [asdict(f) for f in self.flags],
            "scores": self.scores,
            "compliance": self.compliance,
            "owasp": self.owasp,
            "properties": self.properties,
        }

    def sort(self) -> None:
        """Sort edges/flags in place for deterministic, golden-stable output."""
        self.edges.sort(key=lambda e: e.key())
        self.flags.sort(key=lambda f: f.key())


__all__ = [
    "REL_TRAINED_ON",
    "REL_DEPENDS_ON",
    "REL_SERVED_BY",
    "REL_DEPLOYED_AT",
    "SEVERITIES",
    "Edge",
    "Flag",
    "ScanResult",
]
