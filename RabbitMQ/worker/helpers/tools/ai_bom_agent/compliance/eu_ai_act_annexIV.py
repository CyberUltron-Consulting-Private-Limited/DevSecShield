"""
EU AI Act Annex IV (technical documentation for high-risk AI systems) mapping.

AI-enabled medical devices are automatically high-risk under Article 6(1)/Annex I
(MDR/IVDR). Annex IV enumerates the technical documentation a provider must maintain;
an AI-BOM is the machine-readable backbone of the data-governance/traceability
content (Morgan Lewis notes overlap with Articles 11/13 and Annex IV). The Annex IV
points are paraphrased to the AI-BOM-relevant subset. ADVISORY ONLY — confirm current
deadlines (Digital Omnibus pushed Annex I embedded high-risk to 2028-08-02; Art. 4/5
apply now).
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance import base as B
from helpers.tools.ai_bom_agent.compliance.base import (
    FrameworkReport,
    RequirementResult,
    register,
)

KEY = "eu_ai_act_annexIV"
NAME = "EU AI Act Annex IV (high-risk technical documentation)"
VERSION = "Regulation (EU) 2024/1689, Annex IV"


@register(KEY)
def evaluate(bom: dict, findings: list[dict]) -> FrameworkReport:
    ml = B.models(bom)
    ds = B.datasets(bom)
    reqs: list[RequirementResult] = []

    # 1(a) general description of the AI system / intended purpose
    has_system = bool((bom.get("metadata") or {}).get("component"))
    has_intended = B.bom_has_property(bom, "clinical:intended_use", "regulatory:eu_ai_act_risk") \
        or B.any_model_has_considerations(bom)
    reqs.append(RequirementResult(
        id="AnnexIV-1(a)",
        title="General description of the AI system, its intended purpose and risk classification",
        status="met" if has_system and has_intended else ("partial" if has_system else "gap"),
        mapped_fields=["metadata.component", "metadata.properties[regulatory:eu_ai_act_risk]",
                       "metadata.properties[clinical:intended_use]", "modelCard.considerations.useCases"],
        evidence=("System component named in metadata"
                  + ("; intended purpose/risk declared" if has_intended else "")),
        gap=None if has_intended else "Intended purpose and EU-AI-Act risk class not declared.",
        recommendation="Add metadata.properties regulatory:eu_ai_act_risk and clinical:intended_use; "
                       "populate modelCard.considerations.useCases.",
    ))

    # 2(b) design specifications, model architecture, key design choices
    has_params = B.any_model_has_parameters(bom)
    reqs.append(RequirementResult(
        id="AnnexIV-2(b)",
        title="Design specifications: model architecture, algorithmic logic, key design choices",
        status="met" if has_params else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.modelParameters.modelArchitecture",
                       "modelCard.modelParameters.architectureFamily",
                       "modelCard.modelParameters.approach", "modelCard.modelParameters.task"],
        evidence="modelCard.modelParameters present" if has_params else None,
        gap=(None if has_params else
             ("Model architecture/approach/task not captured in modelCard.modelParameters." if ml else None)),
        recommendation="Populate modelCard.modelParameters (modelArchitecture, architectureFamily, approach, task).",
    ))

    # 2(c)/2(d) data: training/validation/testing datasets, provenance, governance
    has_dataset_props = B.bom_has_property(bom, "dataset:provenance", "dataset:type", "dataset:size")
    reqs.append(RequirementResult(
        id="AnnexIV-2(d)",
        title="Data requirements: datasets, provenance, characteristics, governance measures",
        status="met" if ds and has_dataset_props else ("partial" if ds else "gap"),
        mapped_fields=["components[type=data]", "data[].governance",
                       "properties[dataset:provenance]", "properties[dataset:type]",
                       "properties[dataset:known_bias]"],
        evidence=(f"{len(ds)} dataset component(s) inventoried" if ds else None),
        gap=(None if ds and has_dataset_props else
             ("Datasets present but lack dataset:provenance/type/known_bias properties." if ds
              else "No training/validation/test datasets captured.")),
        recommendation="Emit data components with dataset:type, dataset:size, dataset:provenance, "
                       "dataset:sensitivity, dataset:known_bias properties + data[].governance owners.",
    ))

    # 3 monitoring, functioning and control — performance metrics & limitations
    has_metrics = B.any_model_has_metrics(bom)
    reqs.append(RequirementResult(
        id="AnnexIV-3",
        title="Capabilities/limitations, expected accuracy, metrics for monitoring & control",
        status="met" if has_metrics else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.quantitativeAnalysis.performanceMetrics",
                       "modelCard.considerations.technicalLimitations"],
        evidence="quantitativeAnalysis.performanceMetrics present" if has_metrics else None,
        gap=(None if has_metrics else
             ("No performance metrics / accuracy levels captured for monitoring." if ml else None)),
        recommendation="Populate modelCard.quantitativeAnalysis.performanceMetrics (with subgroup slices) "
                       "and considerations.technicalLimitations.",
    ))

    # 4 risk management & known/foreseeable risks (incl. fairness)
    has_fairness = False
    for m in ml:
        cons = (m.get("modelCard") or {}).get("considerations") or {}
        if cons.get("ethicalConsiderations") or cons.get("fairnessAssessments"):
            has_fairness = True
            break
    reqs.append(RequirementResult(
        id="AnnexIV-4",
        title="Risk management: foreseeable risks, discriminatory/fairness impacts and mitigations",
        status="met" if has_fairness else ("partial" if findings else ("gap" if ml else "not_applicable")),
        mapped_fields=["modelCard.considerations.ethicalConsiderations",
                       "modelCard.considerations.fairnessAssessments", "findings[].risk_category"],
        evidence=("Fairness/ethical considerations captured on a model" if has_fairness
                  else (f"{len(findings)} AI-risk findings provide partial risk coverage" if findings else None)),
        gap=(None if has_fairness else "No fairness/ethical-consideration assessment on models."),
        recommendation="Populate modelCard.considerations.ethicalConsiderations and fairnessAssessments "
                       "(groupAtRisk + mitigationStrategy).",
    ))

    # 5 changes through lifecycle / versioning
    reqs.append(RequirementResult(
        id="AnnexIV-6",
        title="Lifecycle changes & version control of the system and its components",
        status="met" if B.any_component_has_version(bom) else "partial",
        mapped_fields=["components[].version", "version", "metadata.timestamp"],
        evidence="Components carry versions" if B.any_component_has_version(bom) else "BOM carries a document version/timestamp",
        gap=None if B.any_component_has_version(bom) else "Component-level versions largely absent.",
        recommendation="Pin versions on models and libraries; treat each BOM as a versioned lifecycle snapshot.",
    ))

    return FrameworkReport(framework=NAME, framework_key=KEY, version=VERSION, requirements=reqs)
