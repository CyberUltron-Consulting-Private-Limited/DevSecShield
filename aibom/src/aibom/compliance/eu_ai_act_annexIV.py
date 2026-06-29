"""EU AI Act — Article 11 / Annex IV technical documentation, enumerated.

The Annex IV / Art 9-14-72 obligations, split into the graph-evidenceable ones
(intended purpose, data governance, accuracy, fairness, de-identification,
integrity, model card, lineage, risk tier) and the narrative/process ones
(foreseeable misuse, data-flow diagram, human oversight, logging, risk-management
system, post-market monitoring) which return NA. Never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    is_deidentified,
    models,
    register_applicability,
    register_check,
    register_manual,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "eu_ai_act_annexIV"

# Annex IV technical documentation applies to any AI SYSTEM (a model is present).
# An artifact with no AI model at all is out_of_scope; with models, its data-
# governance / lineage requirements resolve to pass/fail on the graph.
register_applicability(
    _FW,
    lambda r: bool(models(r)),
    "EU AI Act Annex IV applies to AI systems; this artifact has no AI model",
)


def _r(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


R1 = _r("EUAIACT-1", "Intended purpose documented", "Annex IV §1")
R2 = _r(
    "EUAIACT-2",
    "Training data declared (>=1 trained_on dataset)",
    "Annex IV §2 / Art 10",
)
R3 = _r("EUAIACT-3", "Known dataset bias documented", "Art 10(2)(f-g)")
R4 = _r("EUAIACT-4", "Data preparation / preprocessing documented", "Art 10(2)(b-c)")
R5 = _r("EUAIACT-5", "Accuracy / robustness metrics", "Annex IV §3 / Art 15")
R6 = _r("EUAIACT-6", "Fairness / groups-at-risk assessed", "Art 10(2)(f)")
R7 = _r("EUAIACT-7", "Data governance: training data de-identified", "Annex IV §2")
R8 = _r("EUAIACT-8", "Model integrity (hash)", "Annex IV §2(e)")
R9 = _r("EUAIACT-9", "Model card / technical description present", "Annex IV §2(b)")
R10 = _r("EUAIACT-10", "Versioning + lineage (pedigree)", "Annex IV §1 / Art 12")
R11 = _r("EUAIACT-11", "High-risk classification asserted", "Art 6 / Annex I")


@register_check(R1)
def _purpose(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.model_card.intended_use]
    if bad:
        return FAIL(f"{len(bad)} model(s) document no intended purpose", bad)
    return PASS("every model documents an intended purpose", [m.bom_ref for m in ms])


@register_check(R2)
def _training_declared(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not trained_datasets(r, m)]
    if bad:
        return FAIL(f"{len(bad)} model(s) declare no training data", bad)
    return PASS("every model declares its training data", [m.bom_ref for m in ms])


@register_check(R3)
def _known_bias(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not trained_datasets(r, m)
        or any(not d.known_bias for d in trained_datasets(r, m))
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack documented dataset bias", bad)
    return PASS("training datasets document known bias", [m.bom_ref for m in ms])


@register_check(R4)
def _preprocessing(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not trained_datasets(r, m)
        or any(not d.data_preprocessing for d in trained_datasets(r, m))
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack documented data preprocessing", bad)
    return PASS("data preparation / preprocessing documented", [m.bom_ref for m in ms])


@register_check(R5)
def _accuracy(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.model_card.performance_metrics]
    if bad:
        return FAIL(f"{len(bad)} model(s) report no accuracy metrics", bad)
    return PASS(
        "every model reports accuracy/robustness metrics", [m.bom_ref for m in ms]
    )


@register_check(R6)
def _fairness(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.model_card.considerations
            and any(
                f.group_at_risk
                for f in m.model_card.considerations.fairness_assessments
            )
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) assess no groups at risk", bad)
    return PASS(
        "every model assesses fairness / groups at risk", [m.bom_ref for m in ms]
    )


@register_check(R7)
def _data_governance(r: ScanResult, req: Requirement) -> CheckResult:
    """★ graph-aware flagship: training data is de-identified."""
    ms = models(r)
    if not ms:
        return NA("no model component")
    failures: list[str] = []
    for m in ms:
        ds = trained_datasets(r, m)
        if not ds or any(not is_deidentified(d) for d in ds):  # fail closed
            failures.append(m.bom_ref)
    if failures:
        return FAIL(
            f"{len(failures)} model(s) lack de-identified training data", failures
        )
    return PASS("all training data is de-identified", [m.bom_ref for m in ms])


@register_check(R8)
def _integrity(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.hashes]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack an integrity hash", bad)
    return PASS("every model carries an integrity hash", [m.bom_ref for m in ms])


@register_check(R9)
def _model_card(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (m.model_card.model_architecture or m.model_card.task)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack a technical description", bad)
    return PASS(
        "every model has a technical model-card description", [m.bom_ref for m in ms]
    )


@register_check(R10)
def _lineage(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.version and m.model_card.pedigree_ancestors)]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack version + pedigree lineage", bad)
    return PASS("every model has version + pedigree lineage", [m.bom_ref for m in ms])


@register_check(R11)
def _high_risk(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if "high-risk" not in (m.model_card.eu_ai_act_risk_tier or "").lower()
    ]
    if bad:
        return FAIL(
            f"{len(bad)} model(s) not classified high-risk (Annex I / MDR)", bad
        )
    return PASS(
        "every model asserts its high-risk classification", [m.bom_ref for m in ms]
    )


# Narrative / process Annex-IV obligations -> NA (advisory).
register_manual(
    _r("EUAIACT-12", "Foreseeable misuse described", "Annex IV §2(a)"),
    "foreseeable-misuse analysis is narrative, not BOM-modelled",
)
register_manual(
    _r("EUAIACT-13", "Data-flow / architecture diagram", "Annex IV §2(b)"),
    "data-flow diagrams are documentation, not BOM-modelled",
)
register_manual(
    _r("EUAIACT-14", "Human oversight measures (Art 14)", "Art 14"),
    "human-oversight measures are narrative; the model_card carries "
    "a human_oversight signal but Annex IV requires a described measure",
)
register_manual(
    _r("EUAIACT-15", "Logging / record-keeping (Art 12)", "Art 12"),
    "automatic event logging is a runtime capability, not BOM-modelled",
)
register_manual(
    _r("EUAIACT-16", "Risk-management system (Art 9)", "Art 9"),
    "the risk-management system is process evidence, not BOM-modelled",
)
register_manual(
    _r("EUAIACT-17", "Post-market monitoring plan (Art 72)", "Art 72"),
    "the post-market monitoring plan is documentation, not BOM-modelled",
)
