"""The advisory disclaimer carried by EVERY emitted report.

CLAUDE.md hard rule: compliance mapping is advisory only; every report carries a
disclaimer. All three reporters (CycloneDX / SPDX / SARIF) and the compliance
reports take it from here, so the caveat can never be present in one format and
missing in another.

The default text is neutral (no sector regulator is named): most scans are of
banking, fintech or general software, where an FDA / HIPAA caveat is wrong and
misleading. The healthcare text is used only when the scan itself carries
clinical facts (:func:`is_healthcare`), i.e. the healthcare profile applies.
"""

from __future__ import annotations

from typing import Any

ADVISORY_DISCLAIMER = (
    "Regulatory and standards mappings are advisory only; a bill of materials "
    "creates visibility, not assurance, and does not by itself satisfy any "
    "regulatory obligation. A qualified reviewer must confirm conformance."
)

HEALTHCARE_DISCLAIMER = (
    "Regulatory mappings are advisory only; an AI BOM creates visibility, not "
    "assurance, and does not by itself satisfy FDA, EU AI Act, or HIPAA "
    "obligations. A qualified regulatory reviewer must sign off."
)

# Model-card fields that only a clinical / medical-device model fills in.
_CLINICAL_CARD_FIELDS = (
    "modality",
    "body_part",
    "pacs_ae_title",
    "fda_product_code",
    "device_class",
)


def is_healthcare(result: Any) -> bool:
    """Whether the healthcare profile applies: the scan found clinical facts.

    True when a component carries a ``clinical:`` property, or a model card names
    a clinical modality / body part / PACS AE title / FDA product code / device
    class. Duck-typed on purpose so the emit layer never imports the scanners.
    """
    for comp in getattr(result, "components", None) or []:
        props = getattr(comp, "properties", None) or {}
        if any(str(k).startswith("clinical:") for k in props):
            return True
        card = getattr(comp, "model_card", None)
        if card is not None and any(
            getattr(card, name, None) for name in _CLINICAL_CARD_FIELDS
        ):
            return True
    return any(
        str(k).startswith("clinical:")
        for k in (getattr(result, "properties", None) or {})
    )


def disclaimer_for(result: Any) -> str:
    """The disclaimer for this scan: healthcare text only for a clinical scan."""
    return HEALTHCARE_DISCLAIMER if is_healthcare(result) else ADVISORY_DISCLAIMER


__all__ = [
    "ADVISORY_DISCLAIMER",
    "HEALTHCARE_DISCLAIMER",
    "disclaimer_for",
    "is_healthcare",
]
