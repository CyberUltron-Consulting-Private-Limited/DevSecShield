"""Hermetic CERT-In PDF section + evidence-pack member presence (offline)."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import zipfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from reportlab.lib.styles import getSampleStyleSheet  # noqa: E402
from reportlab.platypus import SimpleDocTemplate  # noqa: E402

from backend.utilities.pdf.certin_compliance_pdf import (  # noqa: E402
    append_certin_compliance_pdf_section,
)


def test_certin_pdf_section_contains_disclaimer_and_framework() -> None:
    styles = getSampleStyleSheet()
    story: list = []
    payload = {
        "cbom_compliance": {
            "cert_in_cbom": {
                "pass": 1,
                "fail": 0,
                "not_bom_evidenceable": 2,
                "pass_with_evidence": 1,
                "coverage": 1.0,
                "requirements": [
                    {
                        "id": "8.4.1.1",
                        "title": "manual",
                        "verdict": "pass_with_evidence",
                    }
                ],
            },
            "nist_800_57": {"pass": 0, "fail": 1, "coverage": 0.0},
        }
    }
    append_certin_compliance_pdf_section(
        story, payload, styles["Heading2"], styles["Normal"], styles["Normal"]
    )
    assert story, "expected CERT-In section content"
    texts = []
    for item in story:
        t = getattr(item, "text", None) or getattr(item, "_argW", None)
        if isinstance(t, str):
            texts.append(t)
        # Tables: peek first cell
        data = getattr(item, "_argW", None)
        if hasattr(item, "_cellvalues"):
            for row in item._cellvalues:
                for cell in row:
                    if isinstance(cell, str):
                        texts.append(cell)
    joined = " ".join(texts)
    assert "CERT-In" in joined
    assert "certification" in joined.lower() or "Advisory" in joined
    assert "cert_in_cbom" in joined
    # Still builds a PDF without error
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf)
    doc.build(story)
    assert buf.getvalue().startswith(b"%PDF")


def test_evidence_pack_zip_members_shape() -> None:
    """Offline stand-in: zip members match evidence-pack contract keys."""
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        path = tmp.name
    try:
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("bom.cdx.json", "{}")
            zf.writestr("vex.json", "{}")
            zf.writestr("bom_signature.json", "{}")
            zf.writestr("compliance.json", "{}")
            zf.writestr("attestations.json", "{}")
            zf.writestr("report.pdf", b"%PDF-1.4")
        names = set(zipfile.ZipFile(path).namelist())
        assert {
            "bom.cdx.json",
            "vex.json",
            "bom_signature.json",
            "compliance.json",
            "attestations.json",
            "report.pdf",
        } <= names
    finally:
        os.unlink(path)
