"""
NIST AI Risk Management Framework (AI RMF 1.0, Jan 2023) mapping — the four
functions Govern / Map / Measure / Manage. The AI-BOM is the inventory backbone
that the Map function depends on and a source of evidence for Measure/Manage.
ADVISORY ONLY.
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance import base as B
from helpers.tools.ai_bom_agent.compliance.base import (
    FrameworkReport,
    RequirementResult,
    register,
)

KEY = "nist_rmf"
NAME = "NIST AI Risk Management Framework (AI RMF 1.0)"
VERSION = "NIST AI 100-1 (Jan 2023)"


@register(KEY)
def evaluate(bom: dict, findings: list[dict]) -> FrameworkReport:
    ml = B.models(bom)
    ds = B.datasets(bom)
    reqs: list[RequirementResult] = []

    # MAP 1 — context & inventory of AI components established
    reqs.append(RequirementResult(
        id="NIST-MAP-1",
        title="MAP: AI components, datasets and dependencies inventoried with context",
        status="met" if ml or ds else "gap",
        mapped_fields=["components", "metadata.component", "dependencies"],
        evidence=(f"{len(ml)} model(s) + {len(ds)} dataset(s) inventoried with system context"
                  if (ml or ds) else None),
        gap=None if (ml or ds) else "No AI models or datasets inventoried to map.",
        recommendation="Maintain the AI-BOM as the authoritative AI component inventory.",
    ))

    # MAP 2 — intended purpose, capabilities and limitations characterized
    reqs.append(RequirementResult(
        id="NIST-MAP-2",
        title="MAP: intended purpose, capabilities and limitations characterized",
        status="met" if B.any_model_has_considerations(bom) else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.considerations.useCases",
                       "modelCard.considerations.technicalLimitations"],
        evidence="considerations (use cases/limitations) present" if B.any_model_has_considerations(bom) else None,
        gap=None if B.any_model_has_considerations(bom) else ("Intended purpose/limitations not characterized." if ml else None),
        recommendation="Populate modelCard.considerations.useCases and technicalLimitations.",
    ))

    # MEASURE 1 — performance metrics tracked
    reqs.append(RequirementResult(
        id="NIST-MEASURE-1",
        title="MEASURE: quantitative performance metrics tracked",
        status="met" if B.any_model_has_metrics(bom) else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.quantitativeAnalysis.performanceMetrics"],
        evidence="performanceMetrics present" if B.any_model_has_metrics(bom) else None,
        gap=None if B.any_model_has_metrics(bom) else ("No performance metrics recorded." if ml else None),
        recommendation="Record performanceMetrics and re-measure on each model version.",
    ))

    # MEASURE 2 — trustworthiness: fairness / bias evaluated
    has_fairness = any(
        ((m.get("modelCard") or {}).get("considerations") or {}).get("fairnessAssessments")
        or ((m.get("modelCard") or {}).get("considerations") or {}).get("ethicalConsiderations")
        for m in ml
    )
    reqs.append(RequirementResult(
        id="NIST-MEASURE-2",
        title="MEASURE: trustworthiness characteristics (bias/fairness) evaluated",
        status="met" if has_fairness else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.considerations.fairnessAssessments",
                       "modelCard.considerations.ethicalConsiderations",
                       "properties[dataset:known_bias]"],
        evidence="Fairness/ethical assessment present" if has_fairness else None,
        gap=None if has_fairness else ("Bias/fairness not evaluated." if ml else None),
        recommendation="Add fairnessAssessments + dataset:known_bias and evaluate subgroup performance.",
    ))

    # MEASURE 3 — security / vulnerability posture measured
    reqs.append(RequirementResult(
        id="NIST-MEASURE-3",
        title="MEASURE: AI security risks identified (untrusted weights, CVEs, risk categories)",
        status="met" if B.has_vulnerability_data(bom, findings) else "gap",
        mapped_fields=["properties[aibom:untrusted-deserialization]",
                       "properties[aibom:risk-category]", "findings[].risk_category"],
        evidence=((f"{len(findings)} AI-risk finding(s) + per-component risk categories present"
                   if findings else "Per-component aibom:risk-category present")
                  if B.has_vulnerability_data(bom, findings) else None),
        gap=None if B.has_vulnerability_data(bom, findings) else "No security-risk signals captured.",
        recommendation="Keep aibom:risk-category + untrusted-deserialization flags; add CVE/OSV references.",
    ))

    # MANAGE 1 — risks prioritized and provenance/lineage tracked for response
    reqs.append(RequirementResult(
        id="NIST-MANAGE-1",
        title="MANAGE: provenance/lineage & versioning support risk response and change control",
        status="met" if (B.any_component_has_version(bom) or B.any_external_references(bom)) else ("partial" if (ml or ds) else "gap"),
        mapped_fields=["components[].version", "pedigree", "externalReferences", "dependencies"],
        evidence="Versions / external references / lineage present" if (B.any_component_has_version(bom) or B.any_external_references(bom)) else None,
        gap=None if (B.any_component_has_version(bom) or B.any_external_references(bom)) else "Limited lineage/version data for change management.",
        recommendation="Track pedigree.ancestors and externalReferences; version every component.",
    ))

    # GOVERN 1 — licensing & ownership documented (accountability)
    reqs.append(RequirementResult(
        id="NIST-GOVERN-1",
        title="GOVERN: licensing, ownership and accountability documented",
        status="met" if B.any_component_has_license(bom) else ("partial" if (ml or ds) else "gap"),
        mapped_fields=["components[].licenses", "components[].supplier", "data[].governance.owners"],
        evidence="License/ownership metadata present" if B.any_component_has_license(bom) else None,
        gap=None if B.any_component_has_license(bom) else "License/ownership not documented for governance.",
        recommendation="Populate licenses, supplier, and data[].governance.owners for accountability.",
    ))

    return FrameworkReport(framework=NAME, framework_key=KEY, version=VERSION, requirements=reqs)
