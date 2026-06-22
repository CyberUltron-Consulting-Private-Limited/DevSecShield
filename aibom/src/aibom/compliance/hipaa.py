"""HIPAA — BAA presence, PHI de-identification, data-flow, minimum-necessary.

APPLICABILITY GATE (``aibom/contract/phi``): HIPAA applies only when the graph
contains a PHI-processing model (``clinical:processes_phi == "true"``). With no
such model, every HIPAA check returns ``na`` — so a non-PHI BOM is never a HIPAA
failure, it is simply out of scope (coverage = None).

Decisions are made from the GRAPH — the model's ``clinical:processes_phi``
property, its ``served_by`` edge to a service carrying ``service:baa``, and the
``trained_on`` datasets' de-identification fields — NEVER from the
``MODEL_PHI_AT_INFERENCE`` flag (that is the scoring echo only).
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
    register_check,
    serving_services,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "hipaa"

R_BAA = Requirement(
    "HIPAA-1", _FW, "Business Associate Agreement with serving vendor",
    "45 CFR 164.502(e) / 164.504(e)",
)
R_DEIDENT = Requirement(
    "HIPAA-2", _FW, "PHI training data de-identified",
    "45 CFR 164.514(b) Safe Harbor / Expert Determination",
)
R_DATAFLOW = Requirement(
    "HIPAA-3", _FW, "PHI data flow documented (serving service)", "Security Rule",
)
R_RETENTION = Requirement(
    "HIPAA-4", _FW, "Retention / secondary-use terms", "BAA terms",
)
R_SENSITIVITY = Requirement(
    "HIPAA-5", _FW, "Sensitivity labeled (minimum necessary)",
    "45 CFR 164.502(b) minimum necessary",
)

_NO_PHI = "no PHI-processing model in scope (clinical:processes_phi); HIPAA N/A"


@register_check(R_BAA)
def _baa(r: ScanResult, req: Requirement) -> CheckResult:
    """★ graph-aware: each PHI model is served_by a BAA'd vendor."""
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures: list[str] = []
    for m in phi:
        svcs = serving_services(r, m)
        if not any((s.properties or {}).get("service:baa") == "true" for s in svcs):
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) not served by a BAA'd vendor "
            "(service:baa != true)",
            failures,
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
        # Fail CLOSED: a PHI model with no declared training data cannot be
        # asserted to train only on de-identified data.
        if not ds or any(not is_deidentified(d) for d in ds):
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) trained on non-de-identified or "
            "undeclared data",
            failures,
        )
    return PASS("PHI models trained only on de-identified data",
                [m.bom_ref for m in phi])


@register_check(R_DATAFLOW)
def _dataflow(r: ScanResult, req: Requirement) -> CheckResult:
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures = [m.bom_ref for m in phi if not serving_services(r, m)]
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) document no serving data flow", failures
        )
    return PASS("every PHI model documents its serving data flow",
                [m.bom_ref for m in phi])


@register_check(R_RETENTION)
def _retention(r: ScanResult, req: Requirement) -> CheckResult:
    if not phi_models(r):
        return NA(_NO_PHI)
    return NA(
        "retention / secondary-use terms live in the BAA, not the AI-BOM graph "
        "(advisory: confirm no-training + retention clauses with the vendor)"
    )


@register_check(R_SENSITIVITY)
def _sensitivity(r: ScanResult, req: Requirement) -> CheckResult:
    phi = phi_models(r)
    if not phi:
        return NA(_NO_PHI)
    failures: list[str] = []
    for m in phi:
        ds = trained_datasets(r, m)
        # Fail CLOSED: no datasets -> sensitivity labeling cannot be asserted.
        if not ds or any(d.has_sensitive_personal_information is None for d in ds):
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} PHI model(s) have unlabeled or undeclared dataset "
            "sensitivity",
            failures,
        )
    return PASS("PHI models' datasets carry a sensitivity label",
                [m.bom_ref for m in phi])
