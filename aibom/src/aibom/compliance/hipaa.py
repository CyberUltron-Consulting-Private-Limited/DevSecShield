"""HIPAA — BAA, PHI de-identification, retention, and the many privacy/security
obligations that live in the BAA + risk analysis rather than the AI-BOM.

APPLICABILITY GATE (``aibom/contract/phi``): the graph-evidenceable checks apply
only when a PHI-processing model is in scope (``phi_models``). With none, they
return ``na`` — so a non-PHI BOM is out of scope, never a HIPAA failure.
Decisions come from the GRAPH (``clinical:processes_phi``, the ``served_by`` edge's
``service:baa``, the ``trained_on`` datasets' de-identification fields), never the
``MODEL_PHI_AT_INFERENCE`` flag.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    is_deidentified,
    phi_models,
    register_applicability,
    register_check,
    register_manual,
    serving_services,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "hipaa"

# HIPAA applies only when a model processes PHI (the contract-locked gate). With
# no PHI in scope the whole framework is out_of_scope, NOT a generic na/fail.
register_applicability(
    _FW,
    lambda r: bool(phi_models(r)),
    "HIPAA applies when a model processes PHI; this artifact has no PHI model",
)


def _r(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


R_BAA = _r(
    "HIPAA-1",
    "Business Associate Agreement with serving vendor",
    "45 CFR 164.502(e) / 164.504(e)",
)
R_DEIDENT = _r(
    "HIPAA-2",
    "PHI training data de-identified",
    "45 CFR 164.514(b) Safe Harbor / Expert Determination",
)
R_RETENTION = _r(
    "HIPAA-3",
    "No PHI retained in training data (retention proxy)",
    "45 CFR 164.502(b) / minimum necessary",
)

_NO_PHI = "no PHI-processing model in scope (clinical:processes_phi); HIPAA N/A"


@register_check(R_BAA)
def _baa(r: ScanResult, req: Requirement) -> CheckResult:
    """★ graph-aware flagship: each PHI model served_by a BAA'd vendor."""
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures = [
        m.bom_ref
        for m in phi
        if not any(
            (s.properties or {}).get("service:baa") == "true"
            for s in serving_services(r, m)
        )
    ]
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) not served by a BAA'd vendor", failures
        )
    return PASS("every PHI model is served by a BAA'd vendor", [m.bom_ref for m in phi])


@register_check(R_DEIDENT)
def _deident(r: ScanResult, req: Requirement) -> CheckResult:
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures: list[str] = []
    for m in phi:
        ds = trained_datasets(r, m)
        if not ds or any(not is_deidentified(d) for d in ds):  # fail closed
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) trained on non-de-identified or "
            "undeclared data",
            failures,
        )
    return PASS(
        "PHI models trained only on de-identified data", [m.bom_ref for m in phi]
    )


@register_check(R_RETENTION)
def _retention(r: ScanResult, req: Requirement) -> CheckResult:
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures: list[str] = []
    for m in phi:
        ds = trained_datasets(r, m)
        if not ds or any(
            d.has_sensitive_personal_information != "no" for d in ds
        ):  # fail closed: PHI must be explicitly removed/retained-as-none
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) retain or do not clear PHI in training data",
            failures,
        )
    return PASS("no PHI retained in training data", [m.bom_ref for m in phi])


# Privacy/security obligations carried by the BAA + security risk analysis, not
# the AI-BOM graph -> NA (advisory).
register_manual(
    _r("HIPAA-4", "Permitted uses + disclosures limited", "164.504(e)"),
    "permitted-use limits live in the BAA, not the AI-BOM graph",
)
register_manual(
    _r("HIPAA-5", "Audio / source data retention limits", "164.530(j)"),
    "audio/source retention limits are operational, not BOM-modelled",
)
register_manual(
    _r("HIPAA-6", "Subcontractor flow-down (BAA chain)", "164.502(e)(2)"),
    "subcontractor BAA flow-down is contractual, not BOM-modelled",
)
register_manual(
    _r("HIPAA-7", "Breach notification", "164.410"),
    "breach-notification terms are contractual, not BOM-modelled",
)
register_manual(
    _r("HIPAA-8", "Administrative/physical/technical safeguards", "164.308-312"),
    "Security Rule safeguards are operational, not BOM-modelled",
)
register_manual(
    _r("HIPAA-9", "Minimum-necessary access controls", "164.502(b)"),
    "role-based minimum-necessary controls are operational evidence",
)
register_manual(
    _r("HIPAA-10", "Patient consent / authorization", "164.508"),
    "consent/authorization is operational, not BOM-modelled",
)
register_manual(
    _r("HIPAA-11", "Notice of Privacy Practices updated", "164.520"),
    "NPP updates are operational, not BOM-modelled",
)
register_manual(
    _r("HIPAA-12", "No secondary use / model training on PHI", "BAA terms"),
    "no-secondary-use/no-training is a BAA term, not BOM-modelled",
)
register_manual(
    _r("HIPAA-13", "Consent/wiretap + malpractice exposure reviewed", "state law"),
    "consent/wiretap + malpractice review is legal, not BOM-modelled",
)
