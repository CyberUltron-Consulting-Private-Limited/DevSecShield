"""CBOM normalizer (C8): a scored crypto ``ScanResult`` -> the API run-object.

The peer of :func:`aibom.integrations.devsecshield.normalize` for the crypto
lane. It shapes a scanned + scored + compliance-mapped CBOM ``ScanResult`` into
the dict the DevSecShield frontend renders on the CBOM results page, carrying
**through** — never flattening — the per-asset severity, the five chart
distributions (algorithm / weak-crypto / PQC readiness / certificate-expiry /
protocol-TLS), the tri-state compliance breakdown, and the scores.

Pure + deterministic for a given ``ScanResult`` (``duration_of_scan`` aside): it
reads the EXPIRED_CERTIFICATE flag the scanner already computed rather than
re-evaluating "now", so identical input -> identical output. Lane discipline: it
computes no scores and raises no flags; it only reads + reshapes.
"""

from __future__ import annotations

import json
from typing import Any

from aibom.cbom.pqc import QUANTUM_VULNERABLE
from aibom.cbom.weakness import (
    CERT_NEAR_EXPIRY,
    EXPIRED_CERTIFICATE,
    WEAK_CERT_KEY_SIZE,
    WEAK_CERT_SIGNATURE,
    WEAK_CRYPTO_CODES,
)
from aibom.emit import get_reporter
from aibom.model.component import AIComponent
from aibom.model.result import ScanResult

# A crypto-asset weakness flag is any C5 weak-crypto code OR an expired cert.
_WEAKNESS_CODES = WEAK_CRYPTO_CODES | {EXPIRED_CERTIFICATE}

_SEVERITY_IMPACT = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _crypto_assets(result: ScanResult) -> list[AIComponent]:
    """The ``crypto_asset`` components — the CBOM inventory / risk-asset rows."""
    return [c for c in result.components if c.kind == "crypto_asset"]


def _impact_for(comp: AIComponent, result: ScanResult) -> str:
    """Stacked per-component severity (scorer) -> Impact, else top-flag, else Low."""
    stacked = (result.scores or {}).get("component_severity", {}).get(comp.bom_ref)
    if stacked:
        return str(stacked).capitalize()
    flags = result.flags_for(comp.bom_ref)
    if flags:
        return min(
            (_SEVERITY_IMPACT.get(f.severity, "Medium") for f in flags),
            key=lambda imp: _IMPACT_RANK[imp],
        )
    return "Low"


def _finding(comp: AIComponent, result: ScanResult) -> dict[str, Any]:
    """One crypto asset -> a CBOM finding row (carries every chart field)."""
    props = comp.properties or {}
    flags = result.flags_for(comp.bom_ref)
    codes = sorted(f.code for f in flags)
    description = "; ".join(f.message for f in flags if f.message) or (
        f"Inventoried crypto asset ({props.get('crypto:assetType') or comp.kind})."
    )
    nqsl = props.get("crypto:nistQuantumSecurityLevel")
    return {
        "title": comp.name,
        "impact": _impact_for(comp, result),
        "asset_type": props.get("crypto:assetType"),
        "primitive": props.get("crypto:primitive"),
        "key_size": props.get("crypto:keySize"),
        "mode": props.get("crypto:mode"),
        "curve": props.get("crypto:curve"),
        "protocol_version": props.get("crypto:protocolVersion"),
        "not_valid_after": props.get("crypto:notValidAfter"),
        "quantum_vulnerable": props.get("crypto:quantumVulnerable") == "true",
        "nist_quantum_security_level": int(nqsl) if nqsl is not None else None,
        "pqc_migration_target": props.get("crypto:pqcMigrationTarget"),
        "weak": any(c in _WEAKNESS_CODES for c in codes),
        "finding_codes": codes,
        "description": description,
        "location": props.get("crypto:source") or props.get("discovery:source") or "",
    }


def _algorithm_distribution(assets: list[AIComponent]) -> dict[str, int]:
    """Algorithm assets bucketed by primitive (block-cipher / hash / pke / ...)."""
    dist: dict[str, int] = {}
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        primitive = props.get("crypto:primitive") or "unknown"
        dist[primitive] = dist.get(primitive, 0) + 1
    return dict(sorted(dist.items()))


def _weakness_distribution(result: ScanResult) -> dict[str, int]:
    """Weak-crypto findings bucketed by flag code (WEAK_* + EXPIRED_CERTIFICATE)."""
    dist: dict[str, int] = {}
    for f in result.flags:
        if f.code in _WEAKNESS_CODES:
            dist[f.code] = dist.get(f.code, 0) + 1
    return dict(sorted(dist.items()))


def _pqc_readiness(assets: list[AIComponent]) -> dict[str, Any]:
    """PQC readiness over algorithm assets: quantum-vulnerable vs quantum-safe."""
    vulnerable = safe = 0
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        if props.get("crypto:quantumVulnerable") == "true":
            vulnerable += 1
        else:
            safe += 1
    graded = vulnerable + safe
    readiness = round(safe / graded * 100, 1) if graded else None
    return {
        "quantum_vulnerable": vulnerable,
        "quantum_safe": safe,
        "readiness_pct": readiness,
    }


def _certificate_expiry(
    assets: list[AIComponent], result: ScanResult
) -> list[dict[str, Any]]:
    """Per-certificate rows: expiry + the C4 weakness catalog verdicts.

    Carries the depth the C4 certificate-weakness lane raises (weak signature
    hash, undersized key, near-expiry) as booleans alongside the base
    expiry/self-signed fields, so the CBOM results page can surface every cert
    verdict without re-deriving it. Reads the flags the scanner already computed.
    """
    rows = []
    for c in assets:
        if (c.properties or {}).get("crypto:assetType") != "certificate":
            continue
        codes = {f.code for f in result.flags_for(c.bom_ref)}
        rows.append(
            {
                "name": c.name,
                "not_valid_after": (c.properties or {}).get("crypto:notValidAfter"),
                "self_signed": (c.properties or {}).get("crypto:selfSigned") == "true",
                "expired": EXPIRED_CERTIFICATE in codes,
                "near_expiry": CERT_NEAR_EXPIRY in codes,
                "weak_signature": WEAK_CERT_SIGNATURE in codes,
                "weak_key_size": WEAK_CERT_KEY_SIZE in codes,
                "signature_algorithm": (c.properties or {}).get(
                    "crypto:signatureAlgorithm"
                ),
                "key_size": (c.properties or {}).get("crypto:keySize"),
            }
        )
    rows.sort(key=lambda r: str(r["name"]))
    return rows


def _protocol_distribution(assets: list[AIComponent]) -> dict[str, int]:
    """Protocol assets bucketed by display label (e.g. ``TLS 1.0``)."""
    dist: dict[str, int] = {}
    for c in assets:
        if (c.properties or {}).get("crypto:assetType") != "protocol":
            continue
        dist[c.name] = dist.get(c.name, 0) + 1
    return dict(sorted(dist.items()))


def _bom(result: ScanResult) -> dict[str, Any]:
    """Render the hand-built CycloneDX 1.6 CBOM to a dict (downloadable)."""
    return json.loads(get_reporter("cyclonedx").render(result))


def normalize_crypto(result: ScanResult, *, duration_of_scan: float) -> dict[str, Any]:
    """Normalize a scored CBOM ScanResult into the DevSecShield run-object.

    Carries the five CBOM chart distributions + the tri-state compliance + the
    scores through verbatim, so no chart can be starved by a flattened payload.
    """
    assets = _crypto_assets(result)
    findings = [_finding(c, result) for c in assets]
    findings.sort(
        key=lambda f: (_IMPACT_RANK.get(f["impact"], 9), str(f["title"]))
    )
    return {
        # --- inventory rows (every crypto asset, carrying its chart fields) ---
        "results": findings,
        # --- carried-through, never flattened ---
        "cbom_json": _bom(result),
        "cbom_compliance": result.compliance or {},
        "cbom_scores": result.scores or {},
        "cbom_distributions": {
            "algorithms": _algorithm_distribution(assets),
            "weakness": _weakness_distribution(result),
            "pqc": _pqc_readiness(assets),
            "certificates": _certificate_expiry(assets, result),
            "protocols": _protocol_distribution(assets),
        },
        "quantum_vulnerable_count": sum(
            1 for f in result.flags if f.code == QUANTUM_VULNERABLE
        ),
        "duration_of_scan": duration_of_scan,
    }


__all__ = ["normalize_crypto"]
