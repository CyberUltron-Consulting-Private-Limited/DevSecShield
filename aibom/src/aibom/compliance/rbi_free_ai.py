"""RBI FREE-AI — Framework for Responsible and Ethical Enablement of AI.

Maps graph-evidenceable FREE-AI recommendations (Rec 6–7, 15–16, 19 partial,
21, 23–25) to the AI-BOM inventory. Organizational/process obligations
(sandboxes, board policy, red teaming, incident reporting) are
``not_bom_evidenceable``. Never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    deployed_sites,
    has_license,
    is_deidentified,
    models,
    register_applicability,
    register_check,
    register_manual,
    serving_services,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "rbi_free_ai"
_SRC = "RBI FREE-AI Committee Report (2025)"


def _r(rid: str, title: str, pillar: str) -> Requirement:
    return Requirement(rid, _FW, title, f"{_SRC} — {pillar}")


register_applicability(
    _FW,
    lambda r: bool(models(r)),
    "RBI FREE-AI applies to AI systems; this artifact has no AI model",
)

# --- Graph-evidenceable (Governance / Assurance) --------------------------- #
R_23_1 = _r(
    "FREEAI-23-1",
    "AI model inventory: every model has name and version",
    "Assurance — AI Inventory (Rec 23)",
)
R_16_1 = _r(
    "FREEAI-16-1",
    "Model technical documentation (model card) present",
    "Governance — AI System Governance (Rec 16)",
)
R_16_2 = _r(
    "FREEAI-16-2",
    "Model version and training-data lineage declared",
    "Governance — AI System Governance (Rec 16)",
)
R_16_3 = _r(
    "FREEAI-16-3",
    "Training data provenance characterized",
    "Governance — AI System Governance (Rec 16)",
)
R_16_4 = _r(
    "FREEAI-16-4",
    "Performance metrics quantified per model",
    "Governance — AI System Governance (Rec 16)",
)
R_16_5 = _r(
    "FREEAI-16-5",
    "Model integrity verified (hash + license)",
    "Governance — AI System Governance (Rec 16)",
)
R_7_1 = _r(
    "FREEAI-7-1",
    "Fairness / bias assessment documented",
    "Policy — Affirmative Action (Rec 7)",
)
R_6_1 = _r(
    "FREEAI-6-1",
    "Intended purpose documented (understandable by design)",
    "Policy — Adaptive Policies (Rec 6)",
)
R_15_1 = _r(
    "FREEAI-15-1",
    "Training data de-identified (DPDP / data lifecycle)",
    "Governance — Data Lifecycle (Rec 15)",
)
R_19_1 = _r(
    "FREEAI-19-1",
    "Third-party serving vendor accountability (outsourcing)",
    "Protection — Cybersecurity (Rec 19)",
)
R_21_1 = _r(
    "FREEAI-21-1",
    "Deployed models report drift / performance status",
    "Protection — BCP for AI (Rec 21)",
)
R_24_1 = _r(
    "FREEAI-24-1",
    "Audit-ready model integrity (hash present)",
    "Assurance — AI Audit (Rec 24)",
)
R_25_1 = _r(
    "FREEAI-25-1",
    "Risk tier / intended-use disclosure documented",
    "Assurance — Disclosures (Rec 25)",
)

# --- Manual / process (not BOM-evidenceable) -------------------------------- #
R_1 = _r("FREEAI-1", "Financial sector data infrastructure", "Infrastructure (Rec 1)")
R_2 = _r("FREEAI-2", "AI innovation sandbox", "Infrastructure (Rec 2)")
R_3 = _r("FREEAI-3", "Incentives and funding support", "Infrastructure (Rec 3)")
R_5 = _r("FREEAI-5", "Integrating AI with DPI", "Infrastructure (Rec 5)")
R_8 = _r("FREEAI-8", "Graded AI liability framework", "Policy (Rec 8)")
R_10 = _r("FREEAI-10", "Capacity building within REs", "Capacity (Rec 10)")
R_14 = _r("FREEAI-14", "Board-approved AI policy", "Governance (Rec 14)")
R_17 = _r("FREEAI-17", "AI-specific product approval process", "Governance (Rec 17)")
R_18 = _r("FREEAI-18", "Consumer protection framework", "Protection (Rec 18)")
R_20 = _r("FREEAI-20", "Structured red teaming program", "Protection (Rec 20)")
R_22 = _r("FREEAI-22", "AI incident reporting framework", "Protection (Rec 22)")


@register_check(R_23_1)
def _inventory(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.name and m.version)]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack name or version in inventory", bad)
    return PASS(f"AI inventory lists {len(ms)} model(s) with name + version", [m.bom_ref for m in ms])


@register_check(R_16_1)
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
        return FAIL(f"{len(bad)} model(s) lack technical model-card documentation", bad)
    return PASS("every model has model-card technical documentation", [m.bom_ref for m in ms])


@register_check(R_16_2)
def _lineage(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.version and trained_datasets(r, m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack version or training-data lineage", bad)
    return PASS("version + training-data lineage mapped", [m.bom_ref for m in ms])


@register_check(R_16_3)
def _provenance(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if any(not d.provenance for d in trained_datasets(r, m))
        or not trained_datasets(r, m)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack characterized data provenance", bad)
    return PASS("training data provenance characterized", [m.bom_ref for m in ms])


@register_check(R_16_4)
def _metrics(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.model_card.performance_metrics]
    if bad:
        return FAIL(f"{len(bad)} model(s) quantify no performance metrics", bad)
    return PASS("performance metrics quantified", [m.bom_ref for m in ms])


@register_check(R_16_5)
def _integrity(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.hashes and has_license(m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack integrity hash or license", bad)
    return PASS("model integrity verified (hash + license)", [m.bom_ref for m in ms])


@register_check(R_7_1)
def _fairness(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.model_card.considerations
            and m.model_card.considerations.fairness_assessments
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) include no fairness assessment", bad)
    return PASS("fairness / bias assessed", [m.bom_ref for m in ms])


@register_check(R_6_1)
def _purpose(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.model_card.intended_use]
    if bad:
        return FAIL(f"{len(bad)} model(s) document no intended purpose", bad)
    return PASS("every model documents intended purpose", [m.bom_ref for m in ms])


@register_check(R_15_1)
def _deid(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if any(not is_deidentified(d) for d in trained_datasets(r, m))
        or not trained_datasets(r, m)
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) use non-de-identified training data", bad)
    return PASS("training data de-identified per DPDP-aligned governance", [m.bom_ref for m in ms])


@register_check(R_19_1)
def _vendor(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    served = [m for m in ms if serving_services(r, m)]
    if not served:
        return NA("no externally-served models to assess vendor accountability")
    bad = [
        m.bom_ref
        for m in served
        if not any(
            (s.properties or {}).get("service:baa") == "true"
            for s in serving_services(r, m)
        )
    ]
    if bad:
        return FAIL(
            f"{len(bad)} served model(s) lack accountable third-party vendor (BAA)",
            bad,
        )
    return PASS(
        "every externally-served model has an accountable vendor",
        [m.bom_ref for m in served],
    )


@register_check(R_21_1)
def _drift(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    deployed = [m for m in ms if deployed_sites(r, m)]
    if not deployed:
        return NA("no deployed models (deployed_at) to monitor for drift")
    bad = [
        m.bom_ref
        for m in deployed
        if any(
            not (s.properties or {}).get("site:drift_status")
            for s in deployed_sites(r, m)
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} deployed model(s) lack drift / performance status", bad)
    return PASS("deployment sites report drift status for BCP monitoring", [m.bom_ref for m in deployed])


@register_check(R_24_1)
def _audit_hash(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.hashes]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack integrity hash for audit trail", bad)
    return PASS("every model carries an audit-ready integrity hash", [m.bom_ref for m in ms])


@register_check(R_25_1)
def _disclosure(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.model_card.intended_use
            or (m.model_card.eu_ai_act_risk_tier or "").strip()
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack risk-tier or intended-use disclosure", bad)
    return PASS("risk tier / intended-use disclosed", [m.bom_ref for m in ms])


for _req, _note in (
    (R_1, "shared financial-sector data infrastructure is institutional / DPI evidence"),
    (R_2, "AI innovation sandbox participation is process evidence"),
    (R_3, "funding and incentive structures are organizational evidence"),
    (R_5, "AI+DPI integration strategy is policy evidence"),
    (R_8, "graded liability framework is regulatory / legal evidence"),
    (R_10, "workforce AI capacity building is organizational evidence"),
    (R_14, "board-approved AI policy is governance documentation"),
    (R_17, "institutional product-approval process is not BOM-modelled"),
    (R_18, "consumer protection framework and grievance redressal are process evidence"),
    (R_20, "red teaming program and cadence are process evidence"),
    (R_22, "AI incident reporting framework is process evidence"),
):
    register_manual(_req, _note)
