"""CycloneDX 1.6 ML-BOM serializer.

PURE function: ``emit_cyclonedx(aibom) -> dict`` takes a normalized
``model.component.AIBom`` and produces a CycloneDX 1.6 ML-BOM dict using the
EXACT spec field names. No network calls, no I/O, deterministic output.

HARD RULE (build-failure): the emitted BOM MUST schema-validate. The public
entry point ``emit_and_validate`` runs the offline validator and raises
``BomValidationError`` if the document is not valid. A BOM that fails
validation is a build failure, not a warning.

Healthcare data is NEVER emitted as invented top-level keys. Clinical/
regulatory/dataset metadata is emitted as CycloneDX ``properties[]`` under the
``clinical:`` / ``regulatory:`` / ``dataset:`` namespaces only.

Compliance note (advisory): any regulatory mapping these properties support is
ADVISORY ONLY -- an AI BOM creates visibility, not assurance, and does not by
itself satisfy FDA / EU AI Act / HIPAA obligations.
"""

from __future__ import annotations

import uuid
from typing import Any

from aibom.emit._disclaimer import ADVISORY_DISCLAIMER as _ADVISORY_DISCLAIMER
from aibom.emit.registry import BaseReporter, register_reporter
from aibom.emit.validate import validate_cyclonedx
from aibom.model.component import (
    KIND_TO_CDX,
    DatasetComponent,
    ModelCard,
    ModelComponent,
)
from aibom.model.result import ScanResult

# Tool identity stamped into metadata.tools[].
TOOL_NAME = "clinithread-aibom"
TOOL_VERSION = "0.1.0"

# Deterministic namespace for serial-number derivation. Stable across runs so
# identical inventories yield identical serialNumbers (golden-file friendly).
_SERIAL_NS = uuid.UUID("6f3c8b1e-2a4d-4f6a-9c0b-7e1d2f3a4b5c")

# Pinned, deterministic timestamp when none is supplied. Keeps emit() pure and
# golden-file stable; callers can override via aibom.properties or by post-edit.
_DEFAULT_TIMESTAMP = "2026-06-21T00:00:00Z"

# Re-exported from the shared module so all reporters use one disclaimer string;
# kept importable here for backward compat (cli.py imports it from cyclonedx).
ADVISORY_DISCLAIMER = _ADVISORY_DISCLAIMER


class BomValidationError(Exception):
    """Raised when an emitted BOM fails CycloneDX 1.6 schema validation.

    Per the HARD RULE, a BOM that fails validation is a build failure.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        joined = "\n  - ".join(errors)
        super().__init__(
            f"Emitted BOM failed CycloneDX 1.6 schema validation "
            f"({len(errors)} error(s)):\n  - {joined}"
        )


# --------------------------------------------------------------------------- #
# Helpers (pure)
# --------------------------------------------------------------------------- #


def _serial_number(result: ScanResult) -> str:
    """Deterministic ``urn:uuid:`` from sorted component bom-refs (uuid5)."""
    seed = "|".join(result.component_bom_refs())
    return f"urn:uuid:{uuid.uuid5(_SERIAL_NS, seed)}"


def _properties_list(props: dict[str, str]) -> list[dict[str, str]]:
    """Map a {name: value} dict to CycloneDX properties[] (sorted, deterministic)."""
    return [{"name": k, "value": v} for k, v in sorted(props.items())]


def _add(d: dict[str, Any], key: str, value: Any) -> None:
    """Set ``d[key] = value`` only when value is meaningful (non-empty)."""
    if value is None:
        return
    if isinstance(value, (list, dict, str)) and len(value) == 0:
        return
    d[key] = value


def _base_component(comp: Any, cdx_type: str) -> dict[str, Any]:
    """Build the shared CycloneDX component skeleton (exact spec keys)."""
    out: dict[str, Any] = {"type": cdx_type, "bom-ref": comp.bom_ref, "name": comp.name}
    _add(out, "version", comp.version)
    _add(out, "publisher", comp.publisher)
    _add(out, "purl", comp.purl)
    _add(out, "licenses", comp.licenses)
    if comp.hashes:
        out["hashes"] = [{"alg": h.alg, "content": h.content} for h in comp.hashes]
    if comp.external_references:
        out["externalReferences"] = [
            _external_reference(r) for r in comp.external_references
        ]
    return out


def _external_reference(ref: Any) -> dict[str, str]:
    out = {"url": ref.url, "type": ref.type}
    _add(out, "comment", ref.comment)
    return out


def _model_card_clinical_props(card: ModelCard) -> dict[str, str]:
    """Collect clinical:/regulatory: properties from a model card."""
    props: dict[str, str] = {}
    if card.intended_use:
        props["clinical:intended_use"] = card.intended_use
    if card.modality:
        props["clinical:modality"] = card.modality
    if card.body_part:
        props["clinical:body_part"] = card.body_part
    if card.pacs_ae_title:
        props["clinical:pacs_ae_title"] = card.pacs_ae_title
    if card.fda_product_code:
        props["regulatory:fda_product_code"] = card.fda_product_code
    if card.device_class:
        props["regulatory:device_class"] = card.device_class
    if card.eu_ai_act_risk_tier:
        # Canonical key matches the BOM-level promotion + the dossier skeleton
        # (regulatory:eu_ai_act_risk) so one regulatory fact has one key name.
        props["regulatory:eu_ai_act_risk"] = card.eu_ai_act_risk_tier
    if card.uses_sensitive_personal_information:
        props["clinical:uses_sensitive_personal_information"] = (
            card.uses_sensitive_personal_information
        )
    return props


def _model_card_dict(card: ModelCard) -> dict[str, Any]:
    """Serialize the non-clinical model-card fields to CycloneDX modelCard."""
    model_params: dict[str, Any] = {}
    if card.approach_type:
        model_params["approach"] = {"type": card.approach_type}
    _add(model_params, "task", card.task)
    _add(model_params, "architectureFamily", card.architecture_family)
    _add(model_params, "modelArchitecture", card.model_architecture)
    if card.datasets:
        model_params["datasets"] = [{"ref": ref} for ref in card.datasets]
    if card.inputs:
        model_params["inputs"] = [{"format": fmt} for fmt in card.inputs]
    if card.outputs:
        model_params["outputs"] = [{"format": fmt} for fmt in card.outputs]

    quantitative: dict[str, Any] = {}
    if card.performance_metrics:
        metrics = []
        for m in card.performance_metrics:
            entry = {"type": m.type, "value": m.value}
            _add(entry, "slice", m.slice)
            metrics.append(entry)
        quantitative["performanceMetrics"] = metrics

    considerations: dict[str, Any] = {}
    c = card.considerations
    if c is not None:
        _add(considerations, "users", list(c.users))
        _add(considerations, "useCases", list(c.use_cases))
        _add(considerations, "technicalLimitations", list(c.technical_limitations))
        if c.ethical_considerations:
            ethical = []
            for e in c.ethical_considerations:
                entry = {"name": e.name}
                _add(entry, "mitigationStrategy", e.mitigation_strategy)
                ethical.append(entry)
            considerations["ethicalConsiderations"] = ethical
        if c.fairness_assessments:
            fairness = []
            for f in c.fairness_assessments:
                fairness_entry: dict[str, str] = {}
                _add(fairness_entry, "groupAtRisk", f.group_at_risk)
                _add(fairness_entry, "benefits", f.benefits)
                _add(fairness_entry, "harms", f.harms)
                _add(fairness_entry, "mitigationStrategy", f.mitigation_strategy)
                fairness.append(fairness_entry)
            considerations["fairnessAssessments"] = fairness

    card_dict: dict[str, Any] = {}
    _add(card_dict, "modelParameters", model_params)
    _add(card_dict, "quantitativeAnalysis", quantitative)
    _add(card_dict, "considerations", considerations)
    return card_dict


def _pedigree_dict(card: ModelCard) -> dict[str, Any]:
    if not card.pedigree_ancestors:
        return {}
    ancestors = []
    for a in card.pedigree_ancestors:
        entry = {"type": a.type, "name": a.name}
        _add(entry, "version", a.version)
        ancestors.append(entry)
    return {"ancestors": ancestors}


# --------------------------------------------------------------------------- #
# Per-kind component serializers
# --------------------------------------------------------------------------- #


def _emit_model(comp: ModelComponent) -> dict[str, Any]:
    out = _base_component(comp, "machine-learning-model")
    card_dict = _model_card_dict(comp.model_card)
    if card_dict:
        out["modelCard"] = card_dict
    pedigree = _pedigree_dict(comp.model_card)
    if pedigree:
        out["pedigree"] = pedigree

    # Merge explicit properties with derived clinical/regulatory properties.
    merged: dict[str, str] = {}
    merged.update(_model_card_clinical_props(comp.model_card))
    if comp.properties:
        merged.update(comp.properties)
    if merged:
        out["properties"] = _properties_list(merged)
    return out


def _emit_dataset(comp: DatasetComponent) -> dict[str, Any]:
    out = _base_component(comp, "data")
    merged: dict[str, str] = {}
    if comp.dataset_type:
        merged["dataset:type"] = comp.dataset_type
    if comp.dataset_size:
        merged["dataset:size"] = comp.dataset_size
    if comp.provenance:
        merged["dataset:provenance"] = comp.provenance
    if comp.sensitivity:
        merged["dataset:sensitivity"] = comp.sensitivity
    if comp.known_bias:
        merged["dataset:known_bias"] = comp.known_bias
    if comp.availability:
        merged["dataset:availability"] = comp.availability
    if comp.data_collection_process:
        merged["dataset:data_collection_process"] = comp.data_collection_process
    if comp.data_preprocessing:
        merged["dataset:data_preprocessing"] = "; ".join(comp.data_preprocessing)
    if comp.anonymization_method:
        merged["dataset:anonymization_method"] = "; ".join(comp.anonymization_method)
    if comp.confidentiality_level:
        merged["dataset:confidentiality_level"] = comp.confidentiality_level
    if comp.intended_use:
        merged["dataset:intended_use"] = comp.intended_use
    if comp.has_sensitive_personal_information:
        merged["dataset:has_sensitive_personal_information"] = (
            comp.has_sensitive_personal_information
        )
    if comp.properties:
        merged.update(comp.properties)
    if merged:
        out["properties"] = _properties_list(merged)
    return out


def _emit_plain(comp: Any, cdx_type: str) -> dict[str, Any]:
    out = _base_component(comp, cdx_type)
    if comp.properties:
        out["properties"] = _properties_list(comp.properties)
    return out


# --------------------------------------------------------------------------- #
# CBOM crypto-asset serializer (C4) — hand-built CycloneDX 1.6 cryptoProperties
# --------------------------------------------------------------------------- #

# CycloneDX 1.6 algorithm mode-of-operation enum (lower-case). The scanner emits
# the upper-case token off the source line; anything outside the spec enum
# (e.g. XTS) maps to "other" so the BOM still validates.
_CDX_MODE = {
    "GCM": "gcm",
    "CBC": "cbc",
    "ECB": "ecb",
    "CTR": "ctr",
    "CFB": "cfb",
    "OFB": "ofb",
    "CCM": "ccm",
}

# CycloneDX 1.6 algorithmProperties.primitive enum.
_CDX_PRIMITIVE = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
    "unknown",
}

# CycloneDX 1.6 relatedCryptoMaterialProperties.type enum.
_CDX_MATERIAL = {
    "private-key", "public-key", "secret-key", "key", "ciphertext",
    "signature", "digest", "initialization-vector", "nonce", "seed", "salt",
    "shared-secret", "tag", "additional-data", "password", "credential",
    "token", "other", "unknown",
}

# CycloneDX 1.6 protocolProperties.type enum.
_CDX_PROTOCOL = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}


def _nist_quantum_level(props: dict[str, str]) -> int | None:
    """Resolve ``nistQuantumSecurityLevel`` (0-6) from the scanner properties.

    Honours an explicit ``crypto:nistQuantumSecurityLevel`` when a later story
    (C6 PQC grading) sets one; otherwise a quantum-vulnerable public-key
    algorithm has no quantum security (level 0). Strong symmetric/hash
    primitives are left ungraded here — their detailed level is C6's job.
    """
    raw = props.get("crypto:nistQuantumSecurityLevel")
    if raw is not None:
        try:
            return int(raw)
        except ValueError:
            return None
    if props.get("crypto:quantumVulnerable") == "true":
        return 0
    return None


def _algorithm_properties(props: dict[str, str]) -> dict[str, Any]:
    algo: dict[str, Any] = {}
    primitive = props.get("crypto:primitive")
    if primitive in _CDX_PRIMITIVE:
        algo["primitive"] = primitive
    # RSA/AES carry a bit-length key size; PQC assets a parameter-set identifier
    # (ML-KEM-768 -> "768") — both render into ``parameterSetIdentifier``.
    if props.get("crypto:keySize"):
        algo["parameterSetIdentifier"] = props["crypto:keySize"]
    elif props.get("crypto:parameterSet"):
        algo["parameterSetIdentifier"] = props["crypto:parameterSet"]
    if props.get("crypto:curve"):
        algo["curve"] = props["crypto:curve"]
    mode = props.get("crypto:mode")
    if mode:
        algo["mode"] = _CDX_MODE.get(mode.upper(), "other")
    level = _nist_quantum_level(props)
    if level is not None:
        algo["nistQuantumSecurityLevel"] = level
    return algo


def _certificate_properties(props: dict[str, str]) -> dict[str, Any]:
    certp: dict[str, Any] = {}
    for src, dst in (
        ("crypto:subjectName", "subjectName"),
        ("crypto:issuerName", "issuerName"),
        ("crypto:notValidBefore", "notValidBefore"),
        ("crypto:notValidAfter", "notValidAfter"),
    ):
        if props.get(src):
            certp[dst] = props[src]
    return certp


def _related_material_properties(props: dict[str, str]) -> dict[str, Any]:
    relp: dict[str, Any] = {}
    kind = props.get("crypto:materialKind")
    if kind in _CDX_MATERIAL:
        relp["type"] = kind
    return relp


def _protocol_properties(props: dict[str, str]) -> dict[str, Any]:
    protp: dict[str, Any] = {}
    ptype = props.get("crypto:protocolType")
    if ptype in _CDX_PROTOCOL:
        protp["type"] = ptype
    if props.get("crypto:protocolVersion"):
        protp["version"] = props["crypto:protocolVersion"]
    if props.get("crypto:cipherSuite"):
        protp["cipherSuites"] = [{"name": props["crypto:cipherSuite"]}]
    return protp


def _crypto_properties(props: dict[str, str]) -> dict[str, Any] | None:
    """Build the CycloneDX 1.6 ``cryptoProperties`` block from ``crypto:`` props.

    Returns ``None`` when the asset carries no recognized ``crypto:assetType``
    (so the component falls back to a plain serialization rather than emitting an
    invalid crypto-asset).
    """
    asset_type = props.get("crypto:assetType")
    if asset_type not in {
        "algorithm",
        "certificate",
        "protocol",
        "related-crypto-material",
    }:
        return None
    cp: dict[str, Any] = {"assetType": asset_type}
    if asset_type == "algorithm":
        _add(cp, "algorithmProperties", _algorithm_properties(props))
    elif asset_type == "certificate":
        _add(cp, "certificateProperties", _certificate_properties(props))
    elif asset_type == "related-crypto-material":
        _add(
            cp,
            "relatedCryptoMaterialProperties",
            _related_material_properties(props),
        )
    elif asset_type == "protocol":
        _add(cp, "protocolProperties", _protocol_properties(props))
    return cp


def _emit_crypto_asset(comp: Any) -> dict[str, Any]:
    """Serialize a ``crypto_asset`` to a CycloneDX 1.6 ``cryptographic-asset``.

    The crypto detail is rendered into the spec ``cryptoProperties`` block; the
    raw ``crypto:`` (and ``discovery:``) properties are also carried through as
    ``properties[]`` so the dashboard reads one consistent place.
    """
    out = _base_component(comp, "cryptographic-asset")
    props = dict(comp.properties or {})
    crypto = _crypto_properties(props)
    if crypto is not None:
        out["cryptoProperties"] = crypto
    if props:
        out["properties"] = _properties_list(props)
    return out


def _emit_component(comp: Any) -> dict[str, Any]:
    # model + dataset have rich, bespoke serializers; crypto assets render the
    # hand-built cryptoProperties block (C4); every other kind (the full
    # shadow-AI taxonomy) maps to a CycloneDX type via KIND_TO_CDX — one place,
    # no per-kind special-casing (decision D4).
    if isinstance(comp, ModelComponent):
        return _emit_model(comp)
    if isinstance(comp, DatasetComponent):
        return _emit_dataset(comp)
    if comp.kind == "crypto_asset":
        return _emit_crypto_asset(comp)
    cdx_type = KIND_TO_CDX.get(comp.kind)
    if cdx_type is None:
        raise TypeError(f"Unknown component kind: {comp.kind!r}")
    return _emit_plain(comp, cdx_type)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _dependencies(result: ScanResult) -> list[dict[str, Any]]:
    """Collapse typed edges into CycloneDX ``dependencies[]`` (ref -> dependsOn).

    CycloneDX has a single ``dependsOn`` relation, so every out-edge of a
    component (``trained_on``, ``depends_on``, ...) becomes a dependsOn target.
    """
    grouped: dict[str, list[str]] = {}
    for edge in result.edges:
        grouped.setdefault(edge.src, [])
        if edge.dst not in grouped[edge.src]:
            grouped[edge.src].append(edge.dst)
    deps = []
    for ref in sorted(grouped):
        entry: dict[str, Any] = {"ref": ref}
        if grouped[ref]:
            entry["dependsOn"] = sorted(grouped[ref])
        deps.append(entry)
    return deps


def emit_cyclonedx(result: ScanResult) -> dict[str, Any]:
    """Serialize a :class:`ScanResult` to a CycloneDX 1.6 ML-BOM dict.

    PURE: no network, no I/O, deterministic. Does NOT validate -- use
    ``emit_and_validate`` (or call ``validate_cyclonedx`` yourself) to enforce
    the build-failure rule.
    """
    metadata: dict[str, Any] = {
        "timestamp": _DEFAULT_TIMESTAMP,
        "tools": [{"name": TOOL_NAME, "version": TOOL_VERSION}],
        "component": {
            "type": result.subject.type,
            "name": result.subject.name,
        },
    }
    _add(metadata["component"], "version", result.subject.version)

    bom_props = dict(result.properties)
    bom_props.setdefault("regulatory:disclaimer", ADVISORY_DISCLAIMER)
    metadata["properties"] = _properties_list(bom_props)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": _serial_number(result),
        "version": 1,
        "metadata": metadata,
        "components": [_emit_component(c) for c in result.components],
    }

    deps = _dependencies(result)
    if deps:
        bom["dependencies"] = deps

    return bom


def emit_and_validate(result: ScanResult) -> dict[str, Any]:
    """Emit then schema-validate. Raises ``BomValidationError`` on any error.

    This is the enforcement point for the build-failure rule.
    """
    bom = emit_cyclonedx(result)
    errors = validate_cyclonedx(bom)
    if errors:
        raise BomValidationError(errors)
    return bom


@register_reporter
class CyclonedxReporter(BaseReporter):
    """Hand-built CycloneDX 1.6 ML-BOM reporter (no cyclonedx-python-lib)."""

    format = "cyclonedx"

    def render(self, result: ScanResult) -> str:
        import json

        return json.dumps(emit_and_validate(result), indent=2) + "\n"


__all__ = [
    "BomValidationError",
    "CyclonedxReporter",
    "emit_cyclonedx",
    "emit_and_validate",
    "TOOL_NAME",
    "TOOL_VERSION",
    "ADVISORY_DISCLAIMER",
]
