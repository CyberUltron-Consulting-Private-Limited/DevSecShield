"""NIST AI Risk Management Framework 1.0 — Govern / Map / Measure / Manage,
enumerated at the SUBCATEGORY level (16). Graph-evidenceable subcategories
(GV-2, MP-1, MP-3, ME-1, ME-2, ME-3) get pass/fail; the rest are organizational/
process obligations the AI-BOM cannot evidence -> NA. Never reads flags.
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    has_license,
    models,
    register_check,
    register_manual,
    serving_services,
    trained_datasets,
)
from aibom.model.result import ScanResult

_FW = "nist_rmf"


def _r(rid: str, title: str, func: str) -> Requirement:
    return Requirement(rid, _FW, title, f"NIST AI RMF 1.0 {func}")


# --- GOVERN ---------------------------------------------------------------- #
R_GV1 = _r("GV-1", "Govern: AI risk-management policies + accountability", "GOVERN")
R_GV2 = _r("GV-2", "Govern: serving vendor accountability (BAA-bound)", "GOVERN")
R_GV3 = _r("GV-3", "Govern: workforce diversity + competency", "GOVERN")
R_GV4 = _r("GV-4", "Govern: risk-aware organizational culture", "GOVERN")
# --- MAP ------------------------------------------------------------------- #
R_MP1 = _r("MP-1", "Map: system context, components + data lineage established", "MAP")
R_MP2 = _r("MP-2", "Map: intended purpose + categorization", "MAP")
R_MP3 = _r("MP-3", "Map: data provenance characterized", "MAP")
R_MP4 = _r("MP-4", "Map: risks + benefits to impacted groups characterized", "MAP")
# --- MEASURE --------------------------------------------------------------- #
R_ME1 = _r("ME-1", "Measure: performance metrics quantified", "MEASURE")
R_ME2 = _r("ME-2", "Measure: fairness / bias assessed", "MEASURE")
R_ME3 = _r("ME-3", "Measure: model integrity verified", "MEASURE")
R_ME4 = _r("ME-4", "Measure: feedback + ongoing measurement mechanisms", "MEASURE")
# --- MANAGE ---------------------------------------------------------------- #
R_MG1 = _r("MG-1", "Manage: risks prioritized + resourced", "MANAGE")
R_MG2 = _r("MG-2", "Manage: strategies to maximize benefit / minimize harm", "MANAGE")
R_MG3 = _r("MG-3", "Manage: third-party risks managed", "MANAGE")
R_MG4 = _r("MG-4", "Manage: incident response + recovery", "MANAGE")


@register_check(R_GV2)
def _gv2(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not any(
            (s.properties or {}).get("service:baa") == "true"
            for s in serving_services(r, m)
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack a BAA-bound serving vendor", bad)
    return PASS(
        "every model is served by an accountable BAA-bound vendor",
        [m.bom_ref for m in ms],
    )


@register_check(R_MP1)
def _mp1(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.version and trained_datasets(r, m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack version or data lineage", bad)
    return PASS(
        "system context: components versioned + data lineage mapped",
        [m.bom_ref for m in ms],
    )


@register_check(R_MP3)
def _mp3(r: ScanResult, req: Requirement) -> CheckResult:
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


@register_check(R_ME1)
def _me1(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not m.model_card.performance_metrics]
    if bad:
        return FAIL(f"{len(bad)} model(s) quantify no performance metrics", bad)
    return PASS("performance metrics quantified", [m.bom_ref for m in ms])


@register_check(R_ME2)
def _me2(r: ScanResult, req: Requirement) -> CheckResult:
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


@register_check(R_ME3)
def _me3(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (m.hashes and has_license(m))]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack integrity hash or license", bad)
    return PASS("model integrity verified (hash + license)", [m.bom_ref for m in ms])


# Organizational / process subcategories the AI-BOM cannot evidence -> NA.
register_manual(
    R_GV1,
    "AI risk-management policies + accountability are "
    "organizational evidence, not BOM-modelled",
)
register_manual(R_GV3, "workforce diversity/competency is organizational evidence")
register_manual(R_GV4, "risk-aware culture is organizational evidence")
register_manual(R_MP2, "intended-purpose categorization is documentation evidence")
register_manual(R_MP4, "risk/benefit-to-impacted-groups analysis is doc evidence")
register_manual(R_ME4, "feedback + ongoing-measurement processes are not BOM-modelled")
register_manual(R_MG1, "risk prioritization + resourcing is organizational evidence")
register_manual(R_MG2, "benefit/harm management strategies are documentation evidence")
register_manual(R_MG3, "third-party risk management is process evidence")
register_manual(R_MG4, "incident response + recovery is process evidence")
