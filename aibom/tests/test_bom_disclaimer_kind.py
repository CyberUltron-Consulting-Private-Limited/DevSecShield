"""Audit A-13 (D11): a bank's CBOM carried the AI BOM disclaimer.

The code-scan CBOM said "... does not by itself satisfy FDA, EU AI Act, or HIPAA
obligations" (``emit/_disclaimer.py``, used for every BOM by ``emit/cyclonedx.py``).

Failing first on dev 214d3ca1e: the CBOM's ``regulatory:disclaimer`` and the CBOM
compliance report's ``disclaimer`` both name FDA and HIPAA. Each BOM now gets its
own wording: a CBOM the crypto regimes, an AI BOM the neutral AI wording, and only
an AI BOM with clinical metadata the FDA / HIPAA one.
"""
from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.emit._disclaimer import (
    AIBOM_DISCLAIMER,
    CBOM_DISCLAIMER,
    HEALTHCARE_AIBOM_DISCLAIMER,
    disclaimer_for,
)
from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.model.component import FrameworkComponent, MetadataComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _disclaimer(bom: dict) -> str:
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    return props["regulatory:disclaimer"]


def test_cbom_code_scan_names_crypto_regimes_never_fda_or_hipaa() -> None:
    result = scan_crypto(_FX)
    text = _disclaimer(emit_cyclonedx(result))
    assert text == CBOM_DISCLAIMER
    assert "FDA" not in text and "HIPAA" not in text and "AI BOM" not in text
    # the CBOM compliance report too
    assert (result.compliance or {}).get("disclaimer") == CBOM_DISCLAIMER


def test_plain_ai_bom_is_neutral_healthcare_only_with_clinical_metadata() -> None:
    lib = FrameworkComponent(bom_ref="lib-torch", name="torch", version="2.3.0")
    plain = ScanResult(subject=MetadataComponent(name="svc"), components=[lib])
    text = _disclaimer(emit_cyclonedx(plain))
    assert text == AIBOM_DISCLAIMER and "FDA" not in text and "HIPAA" not in text
    assert disclaimer_for(crypto=False, healthcare=True) == HEALTHCARE_AIBOM_DISCLAIMER
    healthcare = HEALTHCARE_AIBOM_DISCLAIMER
    assert "FDA" in healthcare and "HIPAA" in healthcare


def test_an_empty_cbom_scan_is_still_a_cbom() -> None:
    assert disclaimer_for(crypto=True, healthcare=True) == CBOM_DISCLAIMER
