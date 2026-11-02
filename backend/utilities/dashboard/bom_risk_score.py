"""Differentiated per-finding risk scores for BOM scanners (0–10).

Impact alone collapses every High finding to the same number (e.g. 7.0), so the
\"Risk scores per finding\" chart is a flat line. These helpers fold in
BOM-specific signals already present on finding rows / finding_data:

* CBOM — finding_codes / weak / quantum / security_strength_bits
* AI-BOM — risk_category / component_type / license gaps
* SBOM — CVE count / reachability / inventory-only

Pure functions; safe to call from findings serializers and dashboards.
"""

from __future__ import annotations

from typing import Any

# Shared 0–10 impact floors (aligned with CBOM/AI-BOM dashboard maps).
_IMPACT_BASE = {
    "critical": 7.5,
    "high": 5.5,
    "medium": 3.5,
    "low": 1.2,
}

# CBOM flag → additive risk (mirrors crypto-risk-weights.yaml relative severity).
_CBOM_FLAG_DELTA: dict[str, float] = {
    "WEAK_ALGORITHM": 1.4,
    "WEAK_CIPHER_MODE": 1.4,
    "WEAK_KEY_SIZE": 1.5,
    "WEAK_PROTOCOL": 1.3,
    "WEAK_CIPHER_SUITE": 1.3,
    "WEAK_PADDING": 1.4,
    "EXPIRED_CERTIFICATE": 1.6,
    "WEAK_CERTIFICATE_SIGNATURE": 1.5,
    "WEAK_CERTIFICATE_KEY": 1.5,
    "WEAK_RNG": 1.4,
    "STATIC_IV": 1.3,
    "REUSED_NONCE": 1.5,
    "HARDCODED_KEY": 1.7,
    "QUANTUM_VULNERABLE": 0.9,
    "SELF_SIGNED_LEAF": 0.7,
    "CERT_NEAR_EXPIRY": 0.6,
    # weight 8 in crypto-risk-weights.yaml, like WEAK_ALGORITHM: same delta (these fell back to 0.4 before)
    "VULNERABLE_CRYPTO_LIBRARY": 1.4,
    "UNENCRYPTED_AT_REST": 1.4,
    "TLS_VERIFICATION_DISABLED": 1.4,
    "CUSTOM_CRYPTO": 0.8,
    # images, binaries and firmware (WP8): weight 4 like CUSTOM_CRYPTO; LIBRARY_CVE_RANGE (weight 1) keeps the default
    "EOL_CRYPTO_LIBRARY": 0.8,
}

_AIBOM_CATEGORY_DELTA: dict[str, float] = {
    "model_theft_exposure": 2.0,
    "hardcoded_secret": 2.0,
    "prompt_injection": 1.6,
    "insecure_output": 1.4,
    "supply_chain": 1.3,
    "license_compliance_gap": 0.9,
    "missing_model_card": 0.7,
    "unpinned_dependency": 0.8,
    "shadow_ai": 1.1,
}

_AIBOM_TYPE_DELTA: dict[str, float] = {
    "external_provider": 0.8,
    "local_model_file": 0.6,
    "huggingface_model": 0.7,
    "embedding_model": 0.5,
    "ml_framework": 0.3,
    "vector_db": 0.4,
    "agent_framework": 0.5,
}

_REACHABILITY_DELTA: dict[str, float] = {
    "reachable": 1.6,
    "potentially_reachable": 0.9,
    "not_reachable": 0.0,
    "not_assessed": 0.3,
}


def _clamp(score: float) -> float:
    return round(min(10.0, max(0.0, score)), 1)


def _impact_base(impact: Any) -> float:
    return _IMPACT_BASE.get(str(impact or "low").lower(), 1.2)


def _cve_count(cves: Any) -> int:
    if not cves:
        return 0
    if isinstance(cves, dict):
        return len(cves)
    if isinstance(cves, list):
        return len(cves)
    return 0


def cbom_finding_risk_score(fd: dict[str, Any] | None) -> float:
    """0–10 risk for a CBOM finding / result row; 0.0 for clean inventory (``cbom_rows.is_finding``)."""
    from backend.utilities.cbom_sources.cbom_rows import is_finding

    fd = fd or {}
    if not is_finding(fd):
        return 0.0  # an AES-GCM a CBOM must list is not a Low finding (the engine scores it 0.0 too)
    score = _impact_base(fd.get("impact"))
    codes = fd.get("finding_codes") or []
    if isinstance(codes, (list, tuple, set)):
        score += sum(_CBOM_FLAG_DELTA.get(str(c), 0.4) for c in codes)
    if fd.get("weak") and not codes:
        score += 1.0
    qv = fd.get("quantum_vulnerable")
    qs = fd.get("quantum_safe")
    if qv is True or qs is False:
        if "QUANTUM_VULNERABLE" not in set(map(str, codes)):
            score += 0.9
    ssb = fd.get("security_strength_bits")
    if ssb is not None:
        try:
            bits = int(ssb)
        except (TypeError, ValueError):
            bits = None
        if bits is not None:
            if bits < 112:
                score += 0.8
            elif bits < 128:
                score += 0.3
    strength = str(fd.get("crypto_strength") or "").lower()
    if strength == "weak" and not codes and not fd.get("weak"):
        score += 1.0
    return _clamp(score)


def aibom_finding_risk_score(fd: dict[str, Any] | None) -> float:
    """0–10 risk for an AI-BOM finding / result row."""
    fd = fd or {}
    score = _impact_base(fd.get("impact"))
    cat = str(fd.get("risk_category") or "").lower()
    score += _AIBOM_CATEGORY_DELTA.get(cat, 0.2 if cat else 0.0)
    ctype = str(
        fd.get("component_type") or fd.get("asset_type") or ""
    ).lower()
    score += _AIBOM_TYPE_DELTA.get(ctype, 0.0)
    lic = str(fd.get("license") or fd.get("license_type") or "").lower()
    if not lic or lic in {"unknown", "n/a", "none", "unlicensed", "not_declared", "licenseref-not-declared"}:
        score += 0.4
    return _clamp(score)


def sbom_finding_risk_score(fd: dict[str, Any] | None) -> float:
    """0–10 risk for an SBOM/SCA finding (was previously a flat 0–4 impact map)."""
    fd = fd or {}
    score = _impact_base(fd.get("impact"))
    n_cves = _cve_count(fd.get("cves"))
    if n_cves:
        score += min(3.0, n_cves * 0.7)
    reach = str(fd.get("reachability") or "not_assessed").lower().replace(" ", "_")
    if reach == "unknown":
        reach = "not_assessed"
    score += _REACHABILITY_DELTA.get(reach, 0.3)
    if fd.get("inventory_only") and n_cves == 0:
        # Pure inventory rows stay near the low floor.
        score = min(score, 2.0)
    lic = str(fd.get("license_type") or "").lower()
    if lic in {
        "strong_copyleft",
        "network_copyleft",
        "source_available",
    }:
        score += 0.5
    return _clamp(score)


__all__ = [
    "cbom_finding_risk_score",
    "aibom_finding_risk_score",
    "sbom_finding_risk_score",
]
