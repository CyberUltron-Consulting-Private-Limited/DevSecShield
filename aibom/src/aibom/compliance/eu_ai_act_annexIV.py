"""EU AI Act — Article 11 / Annex IV technical documentation (+ Art 10/12/14).

Annex IV's nine sections, reduced to the graph-evidenceable obligations a
high-risk medical-AI provider must show: intended purpose, data governance,
accuracy/robustness, human oversight, traceability, risk-tier classification.
Pure graph checks; never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    human_in_the_loop,
    is_deidentified,
    models,
    register_check,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "eu_ai_act_annexIV"

R_PURPOSE = Requirement("AIV-1", _FW, "Intended purpose documented", "Annex IV §1")
R_DATAGOV = Requirement(
    "AIV-2", _FW, "Data governance: de-identified, provenanced training data",
    "Annex IV §2 / Art 10",
)
R_ACCURACY = Requirement(
    "AIV-3", _FW, "Accuracy / robustness metrics", "Annex IV §3-4"
)
R_OVERSIGHT = Requirement("AIV-4", _FW, "Human oversight", "Art 14")
R_TRACE = Requirement("AIV-5", _FW, "Traceability / logging (lineage)", "Art 12")
R_RISK = Requirement("AIV-6", _FW, "Risk-tier classification", "Art 6 / Annex I")


@register_check(R_PURPOSE)
def _purpose(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not m.model_card.intended_use]
    if missing:
        return FAIL(f"{len(missing)} model(s) document no intended purpose", missing)
    return PASS("every model documents an intended purpose", [m.bom_ref for m in ms])


@register_check(R_DATAGOV)
def _data_governance(r: ScanResult, req: Requirement) -> CheckResult:
    """★ graph-aware: every model trained on de-identified, provenanced data."""
    ms = models(r)
    if not ms:
        return NA("no model component")
    failures: list[str] = []
    for m in ms:
        ds = trained_datasets(r, m)
        if not ds:
            failures.append(m.bom_ref)
            continue
        if any(not is_deidentified(d) or not d.provenance for d in ds):
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} model(s) lack de-identified+provenanced training data",
            failures,
        )
    return PASS("all training datasets are de-identified with provenance",
                [m.bom_ref for m in ms])


@register_check(R_ACCURACY)
def _accuracy(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not m.model_card.performance_metrics]
    if missing:
        return FAIL(f"{len(missing)} model(s) report no performance metrics", missing)
    return PASS("every model reports accuracy/robustness metrics",
                [m.bom_ref for m in ms])


@register_check(R_OVERSIGHT)
def _oversight(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not human_in_the_loop(m)]
    if missing:
        return FAIL(f"{len(missing)} model(s) name no human-in-the-loop", missing)
    return PASS("every model names a human reviewer in the loop",
                [m.bom_ref for m in ms])


@register_check(R_TRACE)
def _traceability(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    failures = [
        m.bom_ref
        for m in ms
        if not trained_datasets(r, m)
        or not (m.model_card.pedigree_ancestors or m.external_references)
    ]
    if failures:
        return FAIL(
            f"{len(failures)} model(s) lack lineage (trained_on + pedigree/refs)",
            failures,
        )
    return PASS("every model has training lineage + pedigree/external references",
                [m.bom_ref for m in ms])


@register_check(R_RISK)
def _risk_tier(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not m.model_card.eu_ai_act_risk_tier]
    if missing:
        return FAIL(f"{len(missing)} model(s) declare no EU AI Act risk tier", missing)
    return PASS("every model declares an EU AI Act risk tier",
                [m.bom_ref for m in ms])
