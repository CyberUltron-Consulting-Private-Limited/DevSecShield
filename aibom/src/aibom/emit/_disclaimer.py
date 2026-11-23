"""The advisory disclaimer each emitted BOM carries, by what the BOM is (A-13).

CLAUDE.md hard rule: compliance mapping is advisory only; every report carries a
disclaimer. Every reporter (CycloneDX / SPDX / SARIF) takes it from here, so the
caveat is never present in one format and missing in another.

The wording names the regimes the BOM can actually be mapped to: a CBOM (crypto
inventory) names the cryptography instruments, an AI BOM the AI regimes, and only
an AI BOM that carries clinical / regulatory healthcare metadata (``clinical:`` or
``regulatory:`` properties: FDA product code, device class, modality ...) names
FDA and HIPAA. A bank's CBOM never says FDA or HIPAA.
"""

from typing import Any

HEALTHCARE_AIBOM_DISCLAIMER = (
    "Regulatory mappings are advisory only; an AI BOM creates visibility, not "
    "assurance, and does not by itself satisfy FDA, EU AI Act, or HIPAA "
    "obligations. A qualified regulatory reviewer must sign off."
)

AIBOM_DISCLAIMER = (
    "Regulatory mappings are advisory only; an AI BOM creates visibility, not "
    "assurance, and does not by itself satisfy EU AI Act, NIST AI RMF or other "
    "AI governance obligations. A qualified regulatory reviewer must sign off."
)

CBOM_DISCLAIMER = (
    "Regulatory mappings are advisory only; a CBOM creates visibility of "
    "cryptographic assets, not assurance, and does not by itself satisfy CERT-In, "
    "RBI, SEBI CSCRF, NIST or CNSA 2.0 obligations. A qualified reviewer must "
    "sign off."
)

#: The default (an AI BOM without healthcare metadata). Kept under its old name
#: for the reporters and compliance engines that import it.
ADVISORY_DISCLAIMER = AIBOM_DISCLAIMER


def disclaimer_of(result: Any) -> str:
    """The disclaimer of one ``ScanResult``, the same in every format.

    A crypto inventory (a CBOM scan result, or any crypto asset / ``crypto:``
    property) gets the CBOM wording; an AI BOM with clinical / regulatory
    healthcare metadata the FDA / HIPAA wording; any other AI BOM the neutral one.
    """
    components = list(getattr(result, "components", None) or [])
    props = getattr(result, "properties", None) or {}
    crypto = (
        type(result).__name__ == "CbomScanResult"
        or any(getattr(c, "kind", None) == "crypto_asset" for c in components)
        or any(str(k).startswith("crypto:") for k in props)
    )
    healthcare = any(
        str(k).startswith(("clinical:", "regulatory:"))
        for c in components
        for k in (getattr(c, "properties", None) or {})
    ) or any(
        getattr(getattr(c, "model_card", None), f, None)
        for c in components
        for f in ("modality", "body_part", "fda_product_code", "device_class")
    )
    return disclaimer_for(crypto=crypto, healthcare=healthcare)


def disclaimer_for(*, crypto: bool, healthcare: bool = False) -> str:
    """The disclaimer of one BOM: CBOM wording for a crypto inventory, healthcare
    wording for an AI BOM with clinical metadata, else the neutral AI BOM wording."""
    if crypto:
        return CBOM_DISCLAIMER
    return HEALTHCARE_AIBOM_DISCLAIMER if healthcare else AIBOM_DISCLAIMER


__all__ = [
    "ADVISORY_DISCLAIMER",
    "AIBOM_DISCLAIMER",
    "CBOM_DISCLAIMER",
    "HEALTHCARE_AIBOM_DISCLAIMER",
    "disclaimer_for",
    "disclaimer_of",
]
