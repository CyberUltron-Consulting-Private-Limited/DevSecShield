"""SPDX 3.0.1 serializer (AI Profile + Dataset Profile), JSON-LD.

PURE function: ``emit_spdx(aibom) -> dict`` maps the same normalized
:class:`AIBom` the CycloneDX serializer uses onto an SPDX 3.0.1 JSON-LD
document. No network, deterministic output.

The model becomes an ``ai_AIPackage`` (architecture, limitations, safety risk,
``ai_useSensitivePersonalInformation``, metrics, application info) with exactly
one ``hasConcludedLicense`` relationship; the dataset becomes a
``dataset_DatasetPackage`` (mandatory ``dataset_datasetType``, size, collection/
preprocessing, sensitivity, bias, intended use); libraries become
``software_Package`` elements. Field names are the exact SPDX 3.0.1 names.

HARD RULE (build-failure): the emitted document MUST validate against the
bundled SPDX 3.0.1 schema. ``emit_and_validate_spdx`` enforces it.
"""

from __future__ import annotations

import uuid
from typing import Any

from aibom.emit._disclaimer import ADVISORY_DISCLAIMER
from aibom.emit.registry import BaseReporter, register_reporter
from aibom.emit.validate import validate_spdx
from aibom.model.component import (
    DatasetComponent,
    FrameworkComponent,
    ModelComponent,
)
from aibom.model.result import (
    REL_DEPENDS_ON,
    REL_DEPLOYED_AT,
    REL_SERVED_BY,
    REL_TRAINED_ON,
    ScanResult,
)

SPDX_VERSION = "3.0.1"
SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
TOOL_NAME = "clinithread-aibom"
_CREATED = "2026-06-21T00:00:00Z"  # pinned for deterministic, golden-stable output
_NS_SEED = uuid.UUID("6f3c8b1e-2a4d-4f6a-9c0b-7e1d2f3a4b5c")
_CREATION_INFO = "_:creationinfo"

# free-text dataset_type -> SPDX DatasetType enum.
_DATASET_TYPE = {
    "image": "image",
    "text": "text",
    "audio": "audio",
    "video": "image",
    "timeseries": "timeseries",
    "time series": "timeseries",
    "sensor": "sensor",
    "graph": "graph",
    "structured": "structured",
    "categorical": "categorical",
    "numeric": "numeric",
}
_CONFIDENTIALITY = {"amber", "clear", "green", "red"}
_AVAILABILITY = {
    "clickthrough",
    "directDownload",
    "query",
    "registration",
    "scrapingScript",
}
_PRESENCE = {"yes", "no", "noAssertion"}


class SpdxValidationError(Exception):
    """Raised when an emitted SPDX document fails schema validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        joined = "\n  - ".join(errors)
        super().__init__(
            f"Emitted SPDX 3.0.1 document failed schema validation "
            f"({len(errors)} error(s)):\n  - {joined}"
        )


def _base_ns(result: ScanResult) -> str:
    seed = "|".join(result.component_bom_refs())
    return f"https://devsecshield.example/aibom/{uuid.uuid5(_NS_SEED, seed)}"


def _dataset_type_enum(value: str | None) -> str:
    if not value:
        return "noAssertion"
    low = value.lower()
    for key, enum in _DATASET_TYPE.items():
        if key in low:
            return enum
    return "other"


def _size_int(value: str | None) -> int | None:
    if not value:
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    return int(digits) if digits else None


def _safety_risk(card: Any) -> str | None:
    """Map EU AI Act risk tier / device class to ai_safetyRiskAssessment enum."""
    tier = (card.eu_ai_act_risk_tier or "").lower()
    if "high" in tier or "serious" in tier:
        return "serious"
    if "limited" in tier:
        return "medium"
    if "minimal" in tier:
        return "low"
    return None


def _new(spdx_type: str, spdx_id: str, **props: Any) -> dict[str, Any]:
    element: dict[str, Any] = {
        "type": spdx_type,
        "spdxId": spdx_id,
        "creationInfo": _CREATION_INFO,
    }
    for key, value in props.items():
        if value is None:
            continue
        if isinstance(value, (list, dict, str)) and len(value) == 0:
            continue
        element[key] = value
    return element


# --------------------------------------------------------------------------- #
# Element builders
# --------------------------------------------------------------------------- #


def _ai_package(comp: ModelComponent, sid: str) -> dict[str, Any]:
    card = comp.model_card
    type_of_model = []
    if card.architecture_family:
        family = card.architecture_family
        if card.model_architecture:
            family = f"{family} ({card.model_architecture})"
        type_of_model.append(family)
    elif card.model_architecture:
        type_of_model.append(card.model_architecture)

    limitations = (
        "; ".join(card.considerations.technical_limitations)
        if card.considerations and card.considerations.technical_limitations
        else None
    )
    metrics = []
    for m in card.performance_metrics:
        key = f"{m.type} ({m.slice})" if m.slice else m.type
        metrics.append({"type": "DictionaryEntry", "key": key, "value": m.value})

    use_phi = card.uses_sensitive_personal_information
    if use_phi not in _PRESENCE:
        use_phi = None

    return _new(
        "ai_AIPackage",
        sid,
        name=comp.name,
        software_packageVersion=comp.version,
        ai_typeOfModel=type_of_model or None,
        ai_limitation=limitations,
        ai_safetyRiskAssessment=_safety_risk(card),
        ai_useSensitivePersonalInformation=use_phi,
        ai_informationAboutApplication=card.intended_use,
        ai_metric=metrics or None,
    )


def _dataset_package(comp: DatasetComponent, sid: str) -> dict[str, Any]:
    conf = (comp.confidentiality_level or "").lower() or None
    if conf not in _CONFIDENTIALITY:
        conf = None
    avail = comp.availability if comp.availability in _AVAILABILITY else None
    phi = (
        comp.has_sensitive_personal_information
        if comp.has_sensitive_personal_information in _PRESENCE
        else None
    )
    known_bias = comp.known_bias if comp.known_bias else None
    return _new(
        "dataset_DatasetPackage",
        sid,
        name=comp.name,
        software_packageVersion=comp.version,
        dataset_datasetType=[_dataset_type_enum(comp.dataset_type)],  # mandatory
        dataset_datasetSize=_size_int(comp.dataset_size),
        dataset_datasetAvailability=avail,
        dataset_dataCollectionProcess=comp.data_collection_process or comp.provenance,
        dataset_dataPreprocessing=list(comp.data_preprocessing) or None,
        dataset_anonymizationMethodUsed=list(comp.anonymization_method) or None,
        dataset_confidentialityLevel=conf,
        dataset_intendedUse=comp.intended_use,
        dataset_knownBias=[known_bias] if known_bias else None,
        dataset_hasSensitivePersonalInformation=phi,
    )


def _software_package(comp: Any, sid: str) -> dict[str, Any]:
    """Emit a framework / service / infra component as a generic SPDX package."""
    return _new(
        "software_Package",
        sid,
        name=comp.name,
        software_packageVersion=comp.version,
        software_packageUrl=comp.purl,
    )


def _license_expression(expr: str, sid: str) -> dict[str, Any]:
    return _new(
        "simplelicensing_LicenseExpression",
        sid,
        simplelicensing_licenseExpression=expr,
    )


def _relationship(
    sid: str, frm: str, rel_type: str, to: list[str], comment: str | None = None
) -> dict[str, Any]:
    return _new(
        "Relationship",
        sid,
        comment=comment,
        **{"from": frm, "relationshipType": rel_type, "to": to},
    )


def _license_expr_str(licenses: list[dict] | None) -> str:
    """Best-effort single SPDX license expression from a CycloneDX licenseChoice."""
    if licenses:
        lic = licenses[0].get("license", {})
        if lic.get("id"):
            return str(lic["id"])
        if lic.get("name"):
            return f"LicenseRef-{str(lic['name']).replace(' ', '-')}"
    return "NOASSERTION"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


# scan edge relationship -> (SPDX 3.0.1 relationshipType, comment).
# served_by / deployed_at have no exact SPDX type, so map to "other" and carry
# the precise scan relation in the relationship comment (schema-valid, lossless).
_REL_TO_SPDX: dict[str, tuple[str, str | None]] = {
    REL_TRAINED_ON: ("trainedOn", None),
    REL_DEPENDS_ON: ("dependsOn", None),
    REL_SERVED_BY: ("other", REL_SERVED_BY),
    REL_DEPLOYED_AT: ("other", REL_DEPLOYED_AT),
}


def emit_spdx(result: ScanResult) -> dict[str, Any]:
    """Serialize a :class:`ScanResult` to an SPDX 3.0.1 JSON-LD dict (PURE)."""
    ns = _base_ns(result)

    def sid(suffix: str) -> str:
        return f"{ns}/{suffix}"

    tool_id = sid("tool/clinithread-aibom")
    graph: list[dict[str, Any]] = [
        {
            "type": "CreationInfo",
            "@id": _CREATION_INFO,
            "specVersion": SPDX_VERSION,
            "created": _CREATED,
            "createdBy": [tool_id],
        },
        _new("Tool", tool_id, name=TOOL_NAME),
    ]

    models = [c for c in result.components if isinstance(c, ModelComponent)]
    datasets = [c for c in result.components if isinstance(c, DatasetComponent)]
    libs = [c for c in result.components if isinstance(c, FrameworkComponent)]
    # Every other kind (services, infra/sites, and the full shadow-AI taxonomy:
    # agents, tools, MCP servers, vector stores, …) is emitted as a generic
    # software_Package so its edges resolve — no per-kind special-casing.
    _core = (ModelComponent, DatasetComponent, FrameworkComponent)
    others = [c for c in result.components if not isinstance(c, _core)]
    present = {c.bom_ref for c in result.components}

    root_ids: list[str] = []
    relationships: list[dict[str, Any]] = []
    rel_n = 0

    def rel_id() -> str:
        nonlocal rel_n
        rel_n += 1
        return sid(f"relationship/{rel_n}")

    for model in models:
        mid = sid(f"package/{model.bom_ref}")
        graph.append(_ai_package(model, mid))
        root_ids.append(mid)

        # Exactly one concluded-license relationship per AIPackage (hard rule).
        lic_id = sid(f"license/{model.bom_ref}")
        graph.append(_license_expression(_license_expr_str(model.licenses), lic_id))
        relationships.append(
            _relationship(rel_id(), mid, "hasConcludedLicense", [lic_id])
        )

        # Structural relationships come straight from the scan edge graph,
        # grouped by relationship type (trainedOn, dependsOn, served_by,
        # deployed_at). Unmapped rels use "other" + a comment (see _REL_TO_SPDX).
        for rel, (spdx_rel, comment) in _REL_TO_SPDX.items():
            targets = [
                sid(f"package/{e.dst}")
                for e in result.out_edges(model.bom_ref, rel)
                if e.dst in present
            ]
            if targets:
                relationships.append(
                    _relationship(
                        rel_id(), mid, spdx_rel, sorted(targets), comment=comment
                    )
                )

    for ds in datasets:
        graph.append(_dataset_package(ds, sid(f"package/{ds.bom_ref}")))
    for lib in libs:
        graph.append(_software_package(lib, sid(f"package/{lib.bom_ref}")))
    for other in others:
        graph.append(_software_package(other, sid(f"package/{other.bom_ref}")))

    graph.append(
        _new(
            "SpdxDocument",
            sid("document"),
            name=result.subject.name,
            comment=ADVISORY_DISCLAIMER,  # advisory-only hard rule: every report
            rootElement=root_ids or None,
        )
    )
    graph.extend(relationships)

    return {"@context": SPDX_CONTEXT, "@graph": graph}


def emit_and_validate_spdx(result: ScanResult) -> dict[str, Any]:
    """Emit SPDX then schema-validate. Raises ``SpdxValidationError`` on error."""
    doc = emit_spdx(result)
    errors = validate_spdx(doc)
    if errors:
        raise SpdxValidationError(errors)
    return doc


@register_reporter
class SpdxReporter(BaseReporter):
    """SPDX 3.0.1 (AI + Dataset profiles) JSON-LD reporter."""

    format = "spdx"

    def render(self, result: ScanResult) -> str:
        import json

        return json.dumps(emit_and_validate_spdx(result), indent=2) + "\n"


__all__ = [
    "SpdxValidationError",
    "SpdxReporter",
    "emit_spdx",
    "emit_and_validate_spdx",
    "SPDX_VERSION",
    "SPDX_CONTEXT",
]
