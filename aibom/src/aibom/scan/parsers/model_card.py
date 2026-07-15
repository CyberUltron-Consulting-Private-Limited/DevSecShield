"""Parse a ``MODEL_CARD.md`` front-matter block into model metadata.

The card owns model identity, lineage (pedigree), quantitative metrics, the
``considerations`` block, and the clinical/regulatory extension fields.
``modelParameters`` (architecture/task/io) come from ``config.json`` and are
merged by the pipeline. Returns a plain :class:`ParsedModelCard` so the pipeline
stays the single place that assembles Pydantic components.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aibom.model.component import (
    Considerations,
    EthicalConsideration,
    ExternalReference,
    FairnessAssessment,
    MetadataComponent,
    PedigreeAncestor,
    PerformanceMetric,
)
from aibom.scan.parsers.frontmatter import split_frontmatter
from aibom.scan.parsers.licenses import license_choice


@dataclass
class ParsedModelCard:
    """Normalized model-card data (front-matter), pre-merge with config.json."""

    bom_ref: str
    name: str
    version: str | None = None
    publisher: str | None = None
    licenses: list[dict] | None = None
    datasets: list[str] = field(default_factory=list)
    external_references: list[ExternalReference] = field(default_factory=list)
    application: MetadataComponent | None = None
    performance_metrics: list[PerformanceMetric] = field(default_factory=list)
    considerations: Considerations | None = None
    pedigree_ancestors: list[PedigreeAncestor] = field(default_factory=list)
    # clinical / regulatory extensions
    intended_use: str | None = None
    modality: str | None = None
    body_part: str | None = None
    pacs_ae_title: str | None = None
    fda_product_code: str | None = None
    device_class: str | None = None
    eu_ai_act_risk_tier: str | None = None
    uses_sensitive_personal_information: str | None = None
    human_oversight: str | None = None
    # Deployment graph: the inference service that serves the model (with BAA
    # status) and the sites where it is deployed (with validation/drift state).
    served_by: dict[str, Any] | None = None
    deployed_at: list[dict[str, Any]] = field(default_factory=list)


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _metrics(raw: Any) -> list[PerformanceMetric]:
    out: list[PerformanceMetric] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("type") and "value" in item:
                out.append(
                    PerformanceMetric(
                        type=str(item["type"]),
                        value=str(item["value"]),
                        slice=_opt_str(item.get("slice")),
                    )
                )
    return out


def _considerations(raw: Any) -> Considerations | None:
    if not isinstance(raw, dict):
        return None
    ethical = [
        EthicalConsideration(
            name=str(e["name"]),
            mitigation_strategy=_opt_str(e.get("mitigation_strategy")),
        )
        for e in raw.get("ethical_considerations", []) or []
        if isinstance(e, dict) and e.get("name")
    ]
    fairness = [
        FairnessAssessment(
            group_at_risk=_opt_str(f.get("group_at_risk")),
            benefits=_opt_str(f.get("benefits")),
            harms=_opt_str(f.get("harms")),
            mitigation_strategy=_opt_str(f.get("mitigation_strategy")),
        )
        for f in raw.get("fairness_assessments", []) or []
        if isinstance(f, dict)
    ]
    return Considerations(
        users=[str(u) for u in raw.get("users", []) or []],
        use_cases=[str(u) for u in raw.get("use_cases", []) or []],
        technical_limitations=[
            str(t) for t in raw.get("technical_limitations", []) or []
        ],
        ethical_considerations=ethical,
        fairness_assessments=fairness,
    )


def _pedigree(raw: Any) -> list[PedigreeAncestor]:
    out: list[PedigreeAncestor] = []
    if isinstance(raw, list):
        for a in raw:
            if isinstance(a, dict) and a.get("name"):
                out.append(
                    PedigreeAncestor(
                        name=str(a["name"]),
                        version=_opt_str(a.get("version")),
                        type=str(a.get("type", "machine-learning-model")),
                    )
                )
    return out


def _external_refs(raw: Any) -> list[ExternalReference]:
    out: list[ExternalReference] = []
    if isinstance(raw, list):
        for r in raw:
            if isinstance(r, dict) and r.get("url"):
                out.append(
                    ExternalReference(
                        url=str(r["url"]),
                        type=str(r.get("type", "other")),
                        comment=_opt_str(r.get("comment")),
                    )
                )
    return out


def _application(raw: Any) -> MetadataComponent | None:
    if not isinstance(raw, dict) or not raw.get("name"):
        return None
    return MetadataComponent(
        type=str(raw.get("type", "application")),
        name=str(raw["name"]),
        version=_opt_str(raw.get("version")),
    )


def parse_model_card(path: Path) -> ParsedModelCard | None:
    """Parse a model card. Returns None if absent or missing a model name."""
    if not path.is_file():
        return None
    fm, _body = split_frontmatter(path.read_text())
    name = _opt_str(fm.get("name"))
    if not name:
        return None

    licenses = None
    lic = _opt_str(fm.get("license"))
    if lic:
        licenses = [license_choice(lic)]

    clinical = fm.get("clinical") or {}
    regulatory = fm.get("regulatory") or {}
    clinical = clinical if isinstance(clinical, dict) else {}
    regulatory = regulatory if isinstance(regulatory, dict) else {}

    return ParsedModelCard(
        bom_ref=_opt_str(fm.get("bom_ref")) or f"model-{name.lower()}",
        name=name,
        version=_opt_str(fm.get("version")),
        publisher=_opt_str(fm.get("publisher")),
        licenses=licenses,
        datasets=[str(d) for d in fm.get("datasets", []) or []],
        external_references=_external_refs(fm.get("external_references")),
        application=_application(fm.get("application")),
        performance_metrics=_metrics(fm.get("performance_metrics")),
        considerations=_considerations(fm.get("considerations")),
        pedigree_ancestors=_pedigree(fm.get("pedigree_ancestors")),
        intended_use=_opt_str(clinical.get("intended_use")),
        modality=_opt_str(clinical.get("modality")),
        body_part=_opt_str(clinical.get("body_part")),
        pacs_ae_title=_opt_str(clinical.get("pacs_ae_title")),
        fda_product_code=_opt_str(regulatory.get("fda_product_code")),
        device_class=_opt_str(regulatory.get("device_class")),
        eu_ai_act_risk_tier=_opt_str(regulatory.get("eu_ai_act_risk_tier")),
        uses_sensitive_personal_information=_opt_str(
            clinical.get("uses_sensitive_personal_information")
        ),
        human_oversight=_opt_str(clinical.get("human_oversight")),
        served_by=(
            fm.get("served_by") if isinstance(fm.get("served_by"), dict) else None
        ),
        deployed_at=[s for s in (fm.get("deployed_at") or []) if isinstance(s, dict)],
    )


__all__ = ["ParsedModelCard", "parse_model_card"]
