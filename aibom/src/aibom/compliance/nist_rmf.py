"""NIST AI Risk Management Framework 1.0 — Govern / Map / Measure / Manage.

One graph-aware check per function, evaluated over the model nodes. Never reads
flags.
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
    models,
    register_check,
)
from aibom.model.result import ScanResult

_FW = "nist_rmf"

R_GOVERN = Requirement("NIST-GOVERN", _FW, "Govern: ownership + license governance",
                       "NIST AI RMF 1.0 GOVERN")
R_MAP = Requirement("NIST-MAP", _FW, "Map: context + intended use mapped",
                    "NIST AI RMF 1.0 MAP")
R_MEASURE = Requirement("NIST-MEASURE", _FW, "Measure: performance + fairness measured",
                        "NIST AI RMF 1.0 MEASURE")
R_MANAGE = Requirement("NIST-MANAGE", _FW, "Manage: drift / risk managed",
                       "NIST AI RMF 1.0 MANAGE")


@register_check(R_GOVERN)
def _govern(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not (has_license(m) and m.publisher)]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack license or owner/publisher", bad)
    return PASS("every model has a license + accountable owner",
                [m.bom_ref for m in ms])


@register_check(R_MAP)
def _map(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.model_card.intended_use
            and (m.model_card.device_class or m.model_card.eu_ai_act_risk_tier)
        )
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack mapped context (use + risk class)", bad)
    return PASS("every model's context + risk class is mapped",
                [m.bom_ref for m in ms])


@register_check(R_MEASURE)
def _measure(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (
            m.model_card.performance_metrics
            and m.model_card.considerations
            and m.model_card.considerations.fairness_assessments
        )
    ]
    if bad:
        return FAIL(
            f"{len(bad)} model(s) lack performance or fairness measurement", bad
        )
    return PASS("every model measures performance + fairness",
                [m.bom_ref for m in ms])


@register_check(R_MANAGE)
def _manage(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad: list[str] = []
    for m in ms:
        drift = any(
            (s.properties or {}).get("site:drift_status") for s in deployed_sites(r, m)
        )
        cons = m.model_card.considerations
        mitigations = bool(
            cons and any(e.mitigation_strategy for e in cons.ethical_considerations)
        )
        if not (drift or mitigations):
            bad.append(m.bom_ref)
    if bad:
        return FAIL(f"{len(bad)} model(s) show no drift monitoring or risk mitigation",
                    bad)
    return PASS("every model has drift monitoring or documented risk mitigation",
                [m.bom_ref for m in ms])
