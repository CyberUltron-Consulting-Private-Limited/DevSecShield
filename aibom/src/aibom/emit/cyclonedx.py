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

import contextlib
import re
import uuid
from typing import Any, NamedTuple

from aibom.emit._disclaimer import ADVISORY_DISCLAIMER as _ADVISORY_DISCLAIMER
from aibom.emit.crypto_oid import algorithm_oid
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
    props = comp.properties or {}
    # A crypto library row (declared or imported) and a configuration-posture fact (Terraform resource, TLS
    # setting, ...) say where they were found in the standard place too, like a crypto asset does.
    occurrences: list[dict[str, Any]] = []
    if props.get("crypto:role") == "library":
        occurrences = _occurrences(props)
    elif "crypto:factId" in props:
        occurrences = _fact_occurrences(props)
    if occurrences:
        out["evidence"] = {"occurrences": occurrences}
    if props:
        out["properties"] = _properties_list(props)
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


# --------------------------------------------------------------------------- #
# C9 crypto dependency graph — algorithm-reference resolution (pure)
# --------------------------------------------------------------------------- #

# Algorithm-family tokens used to link certificate / protocol / material assets
# to the algorithm assets they name (``*Ref`` / ``cryptoRefArray``). Ordered so a
# composite/PQC token wins over a substring (ML-DSA before DSA, 3DES before DES,
# SHA-2 before SHA-1). Mirrors the strength scanner's taxonomy but is kept LOCAL
# so the shared emit layer never imports the cbom package (no layering cycle).
_FAMILY_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ml-kem", ("ML-KEM", "MLKEM", "KYBER")),
    ("ml-dsa", ("ML-DSA", "MLDSA", "DILITHIUM")),
    ("slh-dsa", ("SLH-DSA", "SPHINCS")),
    ("falcon", ("FALCON",)),
    ("3des", ("3DES", "TRIPLEDES", "DESEDE", "DES-EDE")),
    ("chacha20", ("CHACHA",)),
    ("aes", ("AES",)),
    ("rc4", ("RC4", "ARCFOUR", "ARC4")),
    ("des", ("DES",)),
    # A keyed construction that names its inner hash (HMAC-SHA256,
    # PBKDF2-HMAC-SHA512) is that construction, never the bare hash.
    ("pbkdf2", ("PBKDF2",)),
    ("hkdf", ("HKDF",)),
    ("hmac", ("HMAC",)),
    ("md5", ("MD5",)),
    ("sha3", ("SHA3", "SHA-3")),
    ("sha2", ("SHA-224", "SHA224", "SHA-256", "SHA256",
              "SHA-384", "SHA384", "SHA-512", "SHA512")),
    ("sha1", ("SHA-1", "SHA1")),
    ("ecdsa", ("ECDSA",)),
    ("ecdh", ("ECDH",)),
    ("eddsa", ("ED25519", "ED448", "EDDSA")),
    ("xdh", ("X25519", "X448")),
    ("rsa", ("RSA",)),
    ("dsa", ("DSA",)),
    ("dh", ("DIFFIE",)),
    ("poly1305", ("POLY1305",)),
)

# Specific digest tokens (longest-first) for pulling the hash out of a composite
# certificate signature-algorithm name (``sha256WithRSAEncryption`` -> SHA-256).
_HASH_TOKENS: tuple[tuple[str, str], ...] = (
    ("SHA-512", "SHA-512"), ("SHA512", "SHA-512"),
    ("SHA-384", "SHA-384"), ("SHA384", "SHA-384"),
    ("SHA-256", "SHA-256"), ("SHA256", "SHA-256"),
    ("SHA-224", "SHA-224"), ("SHA224", "SHA-224"),
    ("SHA-1", "SHA-1"), ("SHA1", "SHA-1"),
    ("MD5", "MD5"), ("MD4", "MD4"), ("MD2", "MD2"),
)

# Source-file extension -> CycloneDX material format token.
_MATERIAL_FORMAT = {
    "pem": "PEM", "der": "DER", "key": "PEM",
    "p12": "P12", "pfx": "PFX", "p8": "P8",
}


class _AlgoRef(NamedTuple):
    """One inventoried algorithm asset, indexed for reference resolution."""

    bom_ref: str
    family: str | None
    key_size: int | None
    curve: str | None
    name_upper: str


def _family_of(name: str | None) -> str | None:
    """Map an algorithm display / OID name to a canonical family token."""
    if not name:
        return None
    up = name.upper()
    for family, tokens in _FAMILY_TOKENS:
        if any(tok in up for tok in tokens):
            return family
    return None


def _pubkey_family(pk_alg: str | None, curve: str | None) -> str | None:
    """Family of a certificate subject public key (from its algorithm name)."""
    if pk_alg:
        low = pk_alg.lower()
        if "rsa" in low:
            return "rsa"
        if "ed25519" in low or "ed448" in low:
            return "eddsa"
        if "ecpublickey" in low or "ecdsa" in low:
            return "ecdsa"
        if "dsa" in low:
            return "dsa"
    return "ecdsa" if curve else _family_of(pk_alg)


def _algorithm_index(components: list[Any]) -> list[_AlgoRef]:
    """Index the algorithm crypto-assets so refs can resolve to real bom-refs."""
    out: list[_AlgoRef] = []
    for c in components:
        if getattr(c, "kind", None) != "crypto_asset":
            continue
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        raw = props.get("crypto:keySize")
        key_size: int | None = None
        if raw is not None:
            with contextlib.suppress(ValueError):
                key_size = int(raw)
        out.append(
            _AlgoRef(
                bom_ref=c.bom_ref,
                family=_family_of(c.name),
                key_size=key_size,
                curve=props.get("crypto:curve"),
                name_upper=(c.name or "").upper(),
            )
        )
    return out


def _find_key_ref(
    index: list[_AlgoRef], family: str | None, key_size: int | None, curve: str | None
) -> str | None:
    """Resolve a keyed algorithm (RSA/EC/…) to an inventoried asset's bom-ref."""
    if curve is not None:
        cu = curve.upper()
        for e in index:
            if e.curve == curve or cu in e.name_upper:
                return e.bom_ref
        return None
    if family is None:
        return None
    for e in index:
        if e.family != family:
            continue
        if key_size is not None and e.key_size != key_size:
            continue
        return e.bom_ref
    return None


def _find_hash_ref(index: list[_AlgoRef], display: str) -> str | None:
    """Resolve a digest display name (``SHA-256``) to an inventoried hash asset."""
    fam = _family_of(display)
    compact = display.upper().replace("-", "")
    for e in index:
        if e.family == fam and compact in e.name_upper.replace("-", ""):
            return e.bom_ref
    return None


def _key_display(family: str | None, key_size: int | None, curve: str | None) -> str:
    """Human name for a synthesized public-key algorithm asset."""
    base = {
        "rsa": "RSA", "dsa": "DSA", "eddsa": "EdDSA", "ecdsa": "EC",
    }.get(family or "", (family or "key").upper())
    if curve:
        return f"{base}-{curve}" if base != "EC" else curve
    if key_size:
        return f"{base}-{key_size}"
    return base


def _synth_algorithm(
    synth: dict[str, dict[str, Any]],
    bom_ref: str,
    name: str,
    primitive: str,
    key_size: int | None = None,
    curve: str | None = None,
    *,
    derived_from: str,
) -> str:
    """Add a minimal algorithm crypto-asset to the synthesis sink; return its ref.

    Used only when a certificate names a signature / public-key algorithm that is
    NOT already in the source inventory, so the certificate remains self-describing
    (the cbomkit-theia ``certificates``-plugin behavior, clean-room). Deterministic:
    keyed by ``bom_ref`` so repeated resolutions collapse to one component.

    The component is DERIVED (``crypto:derived=true``, ``crypto:derivedFrom=<certificate ref>``): it was not
    found in source on its own, has no location and carries no finding of its own, so a reader (or a scorer)
    never counts it as a separate detection.
    """
    if bom_ref not in synth:
        props: dict[str, str] = {
            "crypto:assetType": "algorithm",
            "crypto:primitive": primitive,
            "crypto:derived": "true",
            "crypto:derivedFrom": derived_from,
        }
        algo: dict[str, Any] = {"primitive": primitive}
        if key_size is not None:
            props["crypto:keySize"] = str(key_size)
            algo["parameterSetIdentifier"] = str(key_size)
        if curve:
            props["crypto:curve"] = curve
            algo["curve"] = curve
        cp: dict[str, Any] = {
            "assetType": "algorithm",
            "algorithmProperties": algo,
        }
        # C10: a synthesized (cert-only) algorithm asset self-describes its OID.
        _add(cp, "oid", algorithm_oid(name, primitive, key_size, None, curve))
        synth[bom_ref] = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": name,
            "cryptoProperties": cp,
            "properties": _properties_list(props),
        }
    return bom_ref


def _source_extension(props: dict[str, str]) -> str:
    """Lower-case file extension of the asset's discovery source (``""`` if none)."""
    src = props.get("discovery:source") or ""
    return src.rsplit(".", 1)[-1].lower() if "." in src else ""


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
    # C15: the classical (non-quantum) comparable security strength in bits
    # (SP 800-57 Table 2), stamped on the asset by the strength scanner.
    strength = props.get("crypto:securityStrengthBits")
    if strength is not None:
        with contextlib.suppress(ValueError):
            algo["classicalSecurityLevel"] = int(strength)
    return algo


def _certificate_properties(
    props: dict[str, str],
    comp_ref: str,
    index: list[_AlgoRef],
    synth: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    certp: dict[str, Any] = {}
    for src, dst in (
        ("crypto:subjectName", "subjectName"),
        ("crypto:issuerName", "issuerName"),
        ("crypto:notValidBefore", "notValidBefore"),
        ("crypto:notValidAfter", "notValidAfter"),
    ):
        if props.get(src):
            certp[dst] = props[src]
    # A parsed X.509 certificate always has the X.509 format; the file suffix
    # (pem/crt/cer/der/…) is the certificateExtension where the source has one.
    certp["certificateFormat"] = "X.509"
    ext = _source_extension(props)
    if ext in {"crt", "pem", "cer", "der", "p12", "pfx"}:
        certp["certificateExtension"] = ext

    # subjectPublicKeyRef -> the algorithm asset for the subject public key,
    # resolved to source inventory (RSA-2048/EC curve) or synthesized when absent.
    key_size: int | None = None
    raw = props.get("crypto:keySize")
    if raw is not None:
        with contextlib.suppress(ValueError):
            key_size = int(raw)
    curve = props.get("crypto:curve")
    pk_alg = props.get("crypto:publicKeyAlgorithm")
    key_ref: str | None = None
    pk_family = _pubkey_family(pk_alg, curve)
    if pk_family or curve:
        key_ref = _find_key_ref(index, pk_family, key_size, curve)
        if key_ref is None:
            key_ref = _synth_algorithm(
                synth,
                f"{comp_ref}-pubkey",
                _key_display(pk_family, key_size, curve),
                "pke",
                key_size,
                curve,
                derived_from=comp_ref,
            )
        certp["subjectPublicKeyRef"] = key_ref

    # signatureAlgorithmRef -> the digest asset named by a composite signature
    # (sha256WithRSA -> SHA-256); a pure scheme (Ed25519) falls back to the key.
    sig = props.get("crypto:signatureAlgorithm")
    if sig:
        sig_ref = _signature_ref(sig, comp_ref, index, synth, key_ref)
        if sig_ref:
            certp["signatureAlgorithmRef"] = sig_ref
    return certp


def _signature_ref(
    sig: str,
    comp_ref: str,
    index: list[_AlgoRef],
    synth: dict[str, dict[str, Any]],
    key_ref: str | None,
) -> str | None:
    up = sig.upper()
    for tok, display in _HASH_TOKENS:
        if tok in up:
            ref = _find_hash_ref(index, display)
            if ref is None:
                ref = _synth_algorithm(
                    synth, f"{comp_ref}-sigalg", display, "hash", derived_from=comp_ref
                )
            return ref
    # No standalone digest (Ed25519 / RSASSA-PSS) -> the key algorithm signs.
    return key_ref


def _related_material_properties(
    props: dict[str, str], index: list[_AlgoRef]
) -> dict[str, Any]:
    relp: dict[str, Any] = {}
    kind = props.get("crypto:materialKind")
    if kind in _CDX_MATERIAL:
        relp["type"] = kind
    fmt = _MATERIAL_FORMAT.get(_source_extension(props))
    if fmt:
        relp["format"] = fmt
    # algorithmRef -> the algorithm that generated the material, when the family
    # resolves to exactly one inventoried asset (never a false-precision guess).
    alg = props.get("crypto:algorithm")
    if alg:
        fam = _family_of(alg)
        cands = [e.bom_ref for e in index if fam is not None and e.family == fam]
        if len(cands) == 1:
            relp["algorithmRef"] = cands[0]
    raw = props.get("crypto:keySize")
    if raw is not None and raw.isdigit():
        relp["size"] = int(raw)
    return relp


def _suite_algorithm_refs(token: str, index: list[_AlgoRef]) -> list[str]:
    """Refs to the algorithm assets a cipher-suite token names (unambiguous only).

    A suite names families (ECDHE-RSA-AES128-SHA -> ecdh/rsa/aes/sha); each family
    is linked ONLY when the inventory holds exactly one asset of that family, so an
    ambiguous family (two AES usages) never yields a false-precision reference.
    """
    refs: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[-_]", token):
        fam = _family_of(part)
        if fam is None:
            continue
        cands = [e.bom_ref for e in index if e.family == fam]
        if len(cands) == 1 and cands[0] not in seen:
            seen.add(cands[0])
            refs.append(cands[0])
    return refs


def _protocol_properties(
    props: dict[str, str], index: list[_AlgoRef]
) -> dict[str, Any]:
    protp: dict[str, Any] = {}
    ptype = props.get("crypto:protocolType")
    if ptype in _CDX_PROTOCOL:
        protp["type"] = ptype
    if props.get("crypto:protocolVersion"):
        protp["version"] = props["crypto:protocolVersion"]
    raw = props.get("crypto:cipherSuite")
    if raw:
        suites: list[dict[str, Any]] = []
        all_refs: list[str] = []
        for token in (t.strip() for t in raw.split(",")):
            if not token:
                continue
            suite: dict[str, Any] = {"name": token}
            refs = _suite_algorithm_refs(token, index)
            if refs:
                suite["algorithms"] = refs
                all_refs.extend(refs)
            suites.append(suite)
        if suites:
            protp["cipherSuites"] = suites
        uniq = sorted(set(all_refs))
        if uniq:
            protp["cryptoRefArray"] = uniq
    return protp


def _crypto_properties(
    props: dict[str, str],
    comp_ref: str,
    index: list[_AlgoRef],
    synth: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Build the CycloneDX 1.6 ``cryptoProperties`` block from ``crypto:`` props.

    Returns ``None`` when the asset carries no recognized ``crypto:assetType``
    (so the component falls back to a plain serialization rather than emitting an
    invalid crypto-asset). ``index``/``synth`` wire the C9 dependency graph:
    certificate/protocol/material assets reference the algorithm assets they name.
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
        _add(
            cp,
            "certificateProperties",
            _certificate_properties(props, comp_ref, index, synth),
        )
    elif asset_type == "related-crypto-material":
        _add(
            cp,
            "relatedCryptoMaterialProperties",
            _related_material_properties(props, index),
        )
    elif asset_type == "protocol":
        _add(cp, "protocolProperties", _protocol_properties(props, index))
    return cp


def _emit_crypto_asset(
    comp: Any, index: list[_AlgoRef], synth: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Serialize a ``crypto_asset`` to a CycloneDX 1.6 ``cryptographic-asset``.

    The crypto detail is rendered into the spec ``cryptoProperties`` block; the
    raw ``crypto:`` (and ``discovery:``) properties are also carried through as
    ``properties[]`` so the dashboard reads one consistent place.
    """
    out = _base_component(comp, "cryptographic-asset")
    props = dict(comp.properties or {})
    crypto = _crypto_properties(props, comp.bom_ref, index, synth)
    if crypto is not None:
        # C10 OID enrichment: stamp the canonical object identifier onto an
        # algorithm asset when its parameters pin it unambiguously.
        if crypto.get("assetType") == "algorithm":
            key_size: int | None = None
            raw = props.get("crypto:keySize")
            if raw is not None:
                with contextlib.suppress(ValueError):
                    key_size = int(raw)
            _add(
                crypto,
                "oid",
                algorithm_oid(
                    comp.name,
                    props.get("crypto:primitive"),
                    key_size,
                    props.get("crypto:mode"),
                    props.get("crypto:curve"),
                    props.get("crypto:parameterSet"),
                ),
            )
        out["cryptoProperties"] = crypto
    occurrences = _occurrences(props)
    if occurrences:
        out["evidence"] = {"occurrences": occurrences}
    if props:
        out["properties"] = _properties_list(props)
    return out


_MAX_EVIDENCE_OCCURRENCES = 50


def _repo_relative(src: str) -> bool:
    """A repository-relative source path (never a host path, a URL or a ``..`` escape)."""
    return bool(src) and not src.startswith(("/", "\\")) and "://" not in src and \
        ".." not in src.replace("\\", "/").split("/")


_SOURCE_WITH_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)$")


def _occurrences(props: dict[str, str]) -> list[dict[str, Any]]:
    """CycloneDX 1.6 ``evidence.occurrences`` (file + line) from the occurrence pass, so other CBOM tools and
    reviewers read the locations in the standard place.  Only repository-relative source paths (never a host path
    or URL).  A source recorded as ``path:line`` (Kubernetes, key specs) gives the path as the location and the
    line as the line; a source whose line is not known (an archive member, a package database) is a location
    alone."""
    src = props.get("discovery:source") or ""
    own = _SOURCE_WITH_LINE.match(src)
    if own:
        src = own.group("path")
    if not _repo_relative(src):
        return []
    lines = [int(x) for x in (props.get("crypto:occurrences") or props.get("crypto:line") or "").split(",")
             if x.strip().isdigit() and int(x) > 0]
    if not lines and own and int(own.group("line")) > 0:
        lines = [int(own.group("line"))]
    out: list[dict[str, Any]] = [{"location": src, "line": n} for n in lines[:_MAX_EVIDENCE_OCCURRENCES]]
    if not out:
        return [{"location": src}]
    # Where else the same usage shows: the constant of another file that spells the algorithm
    # (``crypto:definedAt``) and the other modules that call the helper using it (``crypto:calledFrom``).
    for prop, context in (("crypto:definedAt", "value defined here"),
                          ("crypto:calledFrom", "called from here")):
        for item in (props.get(prop) or "").split(","):
            path, _, line = item.strip().rpartition(":")
            if path and line.isdigit() and int(line) > 0 and _repo_relative(path) and \
                    len(out) < _MAX_EVIDENCE_OCCURRENCES:
                out.append({"location": path, "line": int(line), "additionalContext": context})
    return out


def _fact_occurrences(props: dict[str, str]) -> list[dict[str, Any]]:
    """The file and line a configuration-posture fact was read from (``crypto:factPath`` / ``crypto:factLine``)."""
    src = props.get("crypto:factPath") or ""
    line = str(props.get("crypto:factLine") or "")
    if not _repo_relative(src):
        return []
    if not line.isdigit() or int(line) < 1:
        return [{"location": src}]
    return [{"location": src, "line": int(line)}]


def _emit_component(
    comp: Any, index: list[_AlgoRef], synth: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    # model + dataset have rich, bespoke serializers; crypto assets render the
    # hand-built cryptoProperties block (C4); every other kind (the full
    # shadow-AI taxonomy) maps to a CycloneDX type via KIND_TO_CDX — one place,
    # no per-kind special-casing (decision D4).
    if isinstance(comp, ModelComponent):
        return _emit_model(comp)
    if isinstance(comp, DatasetComponent):
        return _emit_dataset(comp)
    if comp.kind == "crypto_asset":
        return _emit_crypto_asset(comp, index, synth)
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

    # C9 crypto dependency graph: index the algorithm assets once so certificate/
    # protocol/material assets resolve their *Ref / cryptoRefArray links. Only a
    # certificate naming an algorithm ABSENT from the inventory adds a synthesized
    # asset (kept in ``synth``, appended after the scanned components).
    index = _algorithm_index(result.components)
    synth: dict[str, dict[str, Any]] = {}
    components = [_emit_component(c, index, synth) for c in result.components]
    components.extend(synth[ref] for ref in sorted(synth))

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": _serial_number(result),
        "version": 1,
        "metadata": metadata,
        "components": components,
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
