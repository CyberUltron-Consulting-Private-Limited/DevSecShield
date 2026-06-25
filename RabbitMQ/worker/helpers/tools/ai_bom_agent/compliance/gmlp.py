"""
Good Machine Learning Practice (GMLP) mapping — IMDRF 10 guiding principles
(finalized Jan 2025; FDA/Health Canada/MHRA). The AI-BOM supports the
traceability/transparency-oriented principles; clinical-process principles
(e.g. clinical study design, human-factors) are out of BOM scope and reported
as not_applicable so they are visibly excluded rather than silently dropped.
ADVISORY ONLY.
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance import base as B
from helpers.tools.ai_bom_agent.compliance.base import (
    FrameworkReport,
    RequirementResult,
    register,
)

KEY = "gmlp"
NAME = "Good Machine Learning Practice (IMDRF/FDA 10 principles)"
VERSION = "IMDRF GMLP 2025-01"


@register(KEY)
def evaluate(bom: dict, findings: list[dict]) -> FrameworkReport:
    ml = B.models(bom)
    ds = B.datasets(bom)
    reqs: list[RequirementResult] = []

    # P3 — clinical study participants & datasets represent the intended population
    has_dataset_bias = B.bom_has_property(bom, "dataset:known_bias", "dataset:provenance",
                                          "clinical:cohort_demographics")
    reqs.append(RequirementResult(
        id="GMLP-3",
        title="Datasets represent the intended population (provenance & representativeness)",
        status="met" if ds and has_dataset_bias else ("partial" if ds else ("gap" if ml else "not_applicable")),
        mapped_fields=["components[type=data]", "properties[dataset:provenance]",
                       "properties[dataset:known_bias]", "properties[clinical:cohort_demographics]"],
        evidence=(f"{len(ds)} dataset(s) inventoried" + ("; representativeness/bias documented" if has_dataset_bias else "")
                  if ds else None),
        gap=(None if ds and has_dataset_bias else
             ("Datasets lack representativeness/bias provenance." if ds else "Training datasets not captured.")),
        recommendation="Document dataset:provenance, dataset:known_bias, and clinical:cohort_demographics.",
    ))

    # P4 — training data independent of test data (datasets distinguished)
    reqs.append(RequirementResult(
        id="GMLP-4",
        title="Training data sets are independent of test sets (datasets enumerated & linked)",
        status="partial" if ds else ("gap" if ml else "not_applicable"),
        mapped_fields=["components[type=data]", "modelCard.modelParameters.datasets", "dependencies"],
        evidence=(f"{len(ds)} dataset component(s) present" if ds else None),
        gap="Train/validation/test split roles are not distinguished in the BOM.",
        recommendation="Tag each dataset with dataset:role (train/validation/test) and link via "
                       "modelCard.modelParameters.datasets + dependencies.",
    ))

    # P5 — selected reference datasets based on best available methods
    reqs.append(RequirementResult(
        id="GMLP-5",
        title="Reference/ground-truth datasets documented",
        status="partial" if ds else ("gap" if ml else "not_applicable"),
        mapped_fields=["components[type=data]", "properties[dataset:type]"],
        evidence=(f"{len(ds)} dataset(s) inventoried" if ds else None),
        gap="Ground-truth / reference standard not explicitly labelled.",
        recommendation="Capture dataset:type and a dataset:reference_standard property where applicable.",
    ))

    # P6 — model design suited to available data & intended use
    reqs.append(RequirementResult(
        id="GMLP-6",
        title="Model design tailored to data and intended use (architecture + intended use captured)",
        status="met" if B.any_model_has_parameters(bom) and B.any_model_has_considerations(bom)
               else ("partial" if B.any_model_has_parameters(bom) or B.any_model_has_considerations(bom)
                     else ("gap" if ml else "not_applicable")),
        mapped_fields=["modelCard.modelParameters", "modelCard.considerations.useCases"],
        evidence="modelParameters and/or considerations captured" if (B.any_model_has_parameters(bom) or B.any_model_has_considerations(bom)) else None,
        gap=None if (B.any_model_has_parameters(bom) and B.any_model_has_considerations(bom)) else
            ("Architecture or intended-use context missing from modelCard." if ml else None),
        recommendation="Populate modelCard.modelParameters and considerations.useCases together.",
    ))

    # P7 — focus on performance of the human-AI team (intended users / HITL)
    has_users = any((m.get("modelCard") or {}).get("considerations", {}).get("users") for m in ml)
    reqs.append(RequirementResult(
        id="GMLP-7",
        title="Human-AI team performance: intended users / human-in-the-loop documented",
        status="met" if has_users else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.considerations.users"],
        evidence="Intended users documented" if has_users else None,
        gap=None if has_users else ("Intended users / HITL role not documented." if ml else None),
        recommendation="List modelCard.considerations.users (e.g. board-certified radiologist, human-in-the-loop).",
    ))

    # P8 — testing demonstrates device performance under clinically relevant conditions
    reqs.append(RequirementResult(
        id="GMLP-8",
        title="Performance validated under clinically relevant conditions (metrics with slices)",
        status="met" if B.any_model_has_metrics(bom) else ("gap" if ml else "not_applicable"),
        mapped_fields=["modelCard.quantitativeAnalysis.performanceMetrics"],
        evidence="Performance metrics present" if B.any_model_has_metrics(bom) else None,
        gap=None if B.any_model_has_metrics(bom) else ("No validation metrics captured." if ml else None),
        recommendation="Record performanceMetrics with clinically relevant subgroup slices (age, scanner, site).",
    ))

    # P9 — users provided clear, essential information (model card transparency)
    reqs.append(RequirementResult(
        id="GMLP-9",
        title="Users provided clear essential information (model card present & complete)",
        status="met" if B.any_model_has_considerations(bom) else ("partial" if B.any_model_has_modelcard(bom) else ("gap" if ml else "not_applicable")),
        mapped_fields=["modelCard", "modelCard.considerations", "externalReferences[type=model-card]"],
        evidence="modelCard considerations present" if B.any_model_has_considerations(bom) else
                 ("modelCard present" if B.any_model_has_modelcard(bom) else None),
        gap=None if B.any_model_has_considerations(bom) else "Model card lacks user-facing considerations.",
        recommendation="Provide a complete modelCard + externalReference of type model-card.",
    ))

    # P10 — deployed models monitored for performance & re-training risks
    reqs.append(RequirementResult(
        id="GMLP-10",
        title="Deployed-model monitoring & re-training controls (versioning + drift signals)",
        status="partial" if B.any_component_has_version(bom) else ("gap" if ml else "not_applicable"),
        mapped_fields=["components[].version", "properties[aibom:model-pinned]", "metadata.timestamp"],
        evidence="Model versions/pinning tracked for change detection" if B.any_component_has_version(bom) else None,
        gap="No drift/monitoring telemetry is captured in the BOM itself.",
        recommendation="Pin model versions; pair each BOM snapshot with drift-monitoring metrics over time.",
    ))

    return FrameworkReport(framework=NAME, framework_key=KEY, version=VERSION, requirements=reqs)
