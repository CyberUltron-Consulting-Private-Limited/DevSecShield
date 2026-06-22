"""Compliance-check foundation: the ``Requirement`` / ``CheckResult`` contract,
the ``_CHECK_REGISTRY``, and the shared **graph** helpers every check uses.

HARD RULE (``aibom/contract/lanes`` + ``/phi``): a check reads the GRAPH —
component fields, ``.properties[...]``, and edges via ``ScanResult`` helpers —
and decides ``pass`` / ``fail`` / ``na`` from that. A check NEVER reads
``result.flags`` (flags are the scoring echo only). Checks are PURE: no I/O, no
network, deterministic; identical graph in → identical verdict out.

A framework checker is one file that defines ``Requirement`` constants and
``@register_check(req)``-decorated pure functions; importing
:mod:`aibom.compliance` self-registers all five (mirrors the scanner / reporter
registries). Coverage math + ``ScanResult.compliance`` assembly live in
:mod:`aibom.compliance.engine`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from aibom.emit._disclaimer import ADVISORY_DISCLAIMER
from aibom.model.component import (
    DatasetComponent,
    FrameworkComponent,
    InfraComponent,
    ModelComponent,
    ServiceComponent,
    is_deidentified,
)
from aibom.model.result import (
    REL_DEPENDS_ON,
    REL_DEPLOYED_AT,
    REL_SERVED_BY,
    REL_TRAINED_ON,
    ScanResult,
)

__all__ = [
    "ADVISORY_DISCLAIMER",
    "Verdict",
    "Requirement",
    "CheckResult",
    "Check",
    "register_check",
    "checks_for",
    "PASS",
    "FAIL",
    "NA",
    "models",
    "datasets",
    "frameworks",
    "services",
    "sites",
    "phi_models",
    "trained_datasets",
    "serving_services",
    "deployed_sites",
    "depends_on_frameworks",
    "is_deidentified",
    "has_license",
    "human_in_the_loop",
]

Verdict = Literal["pass", "fail", "na"]


@dataclass(frozen=True)
class Requirement:
    """One regulatory requirement, anchored to a framework + primary source."""

    id: str
    framework: str  # canonical key, e.g. "hipaa", "eu_ai_act_annexIV"
    title: str
    source: str  # citation, e.g. "Annex IV §2 / Art 10"


@dataclass(frozen=True)
class CheckResult:
    """A check verdict + the graph evidence that justifies it."""

    verdict: Verdict
    evidence: str
    refs: tuple[str, ...] = field(default_factory=tuple)


#: A check: pure function of (graph, requirement) -> verdict. NEVER reads flags.
Check = Callable[[ScanResult, Requirement], CheckResult]

_CHECK_REGISTRY: dict[str, list[tuple[Requirement, Check]]] = {}


def register_check(requirement: Requirement) -> Callable[[Check], Check]:
    """Decorator: register a pure check under ``requirement.framework``."""

    def _decorate(fn: Check) -> Check:
        _CHECK_REGISTRY.setdefault(requirement.framework, []).append((requirement, fn))
        return fn

    return _decorate


def checks_for(framework: str) -> list[tuple[Requirement, Check]]:
    """The registered (requirement, check) pairs for a framework (in order)."""
    return list(_CHECK_REGISTRY.get(framework, []))


# --------------------------------------------------------------------------- #
# Verdict constructors (concise, readable check bodies)
# --------------------------------------------------------------------------- #


def PASS(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("pass", evidence, tuple(refs or ()))


def FAIL(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("fail", evidence, tuple(refs or ()))


def NA(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("na", evidence, tuple(refs or ()))


# --------------------------------------------------------------------------- #
# Shared GRAPH helpers (read-only; NO flags). Checks compose these.
# --------------------------------------------------------------------------- #


def models(r: ScanResult) -> list[ModelComponent]:
    return [c for c in r.components if isinstance(c, ModelComponent)]


def datasets(r: ScanResult) -> list[DatasetComponent]:
    return [c for c in r.components if isinstance(c, DatasetComponent)]


def frameworks(r: ScanResult) -> list[FrameworkComponent]:
    return [c for c in r.components if isinstance(c, FrameworkComponent)]


def services(r: ScanResult) -> list[ServiceComponent]:
    return [c for c in r.components if isinstance(c, ServiceComponent)]


def sites(r: ScanResult) -> list[InfraComponent]:
    return [c for c in r.components if isinstance(c, InfraComponent)]


def phi_models(r: ScanResult) -> list[ModelComponent]:
    """Models in HIPAA scope — the applicability gate (``aibom/contract/phi``).

    Fails CLOSED: a model is in scope when it carries the authoritative
    ``clinical:processes_phi`` graph fact OR any ``trained_on`` dataset is
    explicitly PHI-labeled and not de-identified. So a card that omits / sets
    ``noAssertion`` on the PHI field cannot silently void the whole framework
    when the dataset graph plainly indicates PHI. When this is empty, no PHI is
    in scope and every HIPAA check returns ``na``.
    """
    out: list[ModelComponent] = []
    for m in models(r):
        if (m.properties or {}).get("clinical:processes_phi") == "true":
            out.append(m)
            continue
        ds = [
            c
            for c in r.neighbors(m.bom_ref, REL_TRAINED_ON)
            if isinstance(c, DatasetComponent)
        ]
        if any(
            d.has_sensitive_personal_information == "yes" and not is_deidentified(d)
            for d in ds
        ):
            out.append(m)
    return out


def trained_datasets(r: ScanResult, m: ModelComponent) -> list[DatasetComponent]:
    return [
        c
        for c in r.neighbors(m.bom_ref, REL_TRAINED_ON)
        if isinstance(c, DatasetComponent)
    ]


def serving_services(r: ScanResult, m: ModelComponent) -> list[ServiceComponent]:
    return [
        c
        for c in r.neighbors(m.bom_ref, REL_SERVED_BY)
        if isinstance(c, ServiceComponent)
    ]


def deployed_sites(r: ScanResult, m: ModelComponent) -> list[InfraComponent]:
    return [
        c
        for c in r.neighbors(m.bom_ref, REL_DEPLOYED_AT)
        if isinstance(c, InfraComponent)
    ]


def depends_on_frameworks(r: ScanResult, m: ModelComponent) -> list[FrameworkComponent]:
    return [
        c
        for c in r.neighbors(m.bom_ref, REL_DEPENDS_ON)
        if isinstance(c, FrameworkComponent)
    ]


def has_license(c: object) -> bool:
    return bool(getattr(c, "licenses", None))


def human_in_the_loop(m: ModelComponent) -> bool:
    """Whether the model declares human oversight (Art 14 / GMLP-7).

    Reads the STRUCTURED ``model_card.human_oversight`` graph fact — NEVER
    inferred by substring-scanning the free-text ``considerations.users`` list
    (which false-passes on negation like "no human review required" and
    false-fails on unlisted reviewer roles), matching the rule in
    :func:`is_deidentified`. Fails closed when oversight is unasserted.
    """
    return m.model_card.human_oversight == "yes"
