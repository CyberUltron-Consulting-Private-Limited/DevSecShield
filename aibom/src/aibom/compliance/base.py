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
    "register_manual",
    "register_applicability",
    "applicability_for",
    "checks_for",
    "PASS",
    "FAIL",
    "NA",
    "OUT_OF_SCOPE",
    "NOT_EVIDENCEABLE",
    "models",
    "clinical_models",
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
]

Verdict = Literal[
    "pass",  # graph-evidenced satisfied
    "pass_with_evidence",  # satisfied by an uploaded attestation (counts as pass)
    "fail",  # the graph shows the requirement unmet
    "out_of_scope",  # the framework does NOT apply to this artifact
    "not_bom_evidenceable",  # process evidence a BOM scan cannot see (attestable)
    "na",  # truly neither of the above (rare)
]


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


def register_manual(requirement: Requirement, note: str) -> None:
    """Register a requirement whose evidence is PROCESS, not in the BOM.

    Returns ``not_bom_evidenceable`` (excluded from coverage, reported as its own
    count) — honest: never a false pass/fail, and DISTINCT from a generic ``na``.
    An uploaded attestation for this requirement flips it to ``pass_with_evidence``
    (see :func:`aibom.compliance.engine.run_framework`).
    """

    @register_check(requirement)
    def _manual(r: ScanResult, req: Requirement) -> CheckResult:
        return NOT_EVIDENCEABLE(note)


# --------------------------------------------------------------------------- #
# Framework APPLICABILITY (out-of-scope gate). A framework whose predicate is
# False does not apply to the artifact -> ALL its requirements are out_of_scope
# (NOT fail, NOT generic na). e.g. GMLP/§524B on a vector DB with no clinical model.
# --------------------------------------------------------------------------- #

_APPLICABILITY: dict[str, tuple[Callable[[ScanResult], bool], str]] = {}


def register_applicability(
    framework: str, predicate: Callable[[ScanResult], bool], out_of_scope_reason: str
) -> None:
    """Register a framework's applicability predicate + its out-of-scope reason."""
    _APPLICABILITY[framework] = (predicate, out_of_scope_reason)


def applicability_for(
    framework: str,
) -> tuple[Callable[[ScanResult], bool], str] | None:
    """The (predicate, reason) for a framework, or None if it always applies."""
    return _APPLICABILITY.get(framework)


# --------------------------------------------------------------------------- #
# Verdict constructors (concise, readable check bodies)
# --------------------------------------------------------------------------- #


def PASS(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("pass", evidence, tuple(refs or ()))


def FAIL(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("fail", evidence, tuple(refs or ()))


def NA(evidence: str, refs: list[str] | None = None) -> CheckResult:
    return CheckResult("na", evidence, tuple(refs or ()))


def OUT_OF_SCOPE(evidence: str, refs: list[str] | None = None) -> CheckResult:
    """The framework does not apply to this artifact (NOT a fail, NOT a generic NA)."""
    return CheckResult("out_of_scope", evidence, tuple(refs or ()))


def NOT_EVIDENCEABLE(evidence: str, refs: list[str] | None = None) -> CheckResult:
    """Process evidence a BOM scan cannot see (attestable -> pass_with_evidence)."""
    return CheckResult("not_bom_evidenceable", evidence, tuple(refs or ()))


# --------------------------------------------------------------------------- #
# Shared GRAPH helpers (read-only; NO flags). Checks compose these.
# --------------------------------------------------------------------------- #


def models(r: ScanResult) -> list[ModelComponent]:
    return [c for c in r.components if isinstance(c, ModelComponent)]


def clinical_models(r: ScanResult) -> list[ModelComponent]:
    """Models that are CLINICAL / medical-AI (SaMD) — the applicability anchor for
    GMLP / FDA §524B. A model qualifies if it carries any ``clinical:`` /
    ``regulatory:`` graph property OR a clinical model-card field (intended use,
    modality, device class, FDA product code). Generic embedding / LLM model
    references (e.g. chroma's) carry none -> those frameworks are out_of_scope.
    """
    out: list[ModelComponent] = []
    for m in models(r):
        props = m.properties or {}
        mc = m.model_card
        if (
            any(k.startswith(("clinical:", "regulatory:")) for k in props)
            or mc.intended_use
            or mc.modality
            or mc.device_class
            or mc.fda_product_code
        ):
            out.append(m)
    return out


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
