"""Review of #491 (D3 code-scan CBOM PDF): evidence printed once-escaped, inventory columns that never split words.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_cbom_d3_review_pdf.py -q
"""
from __future__ import annotations

import io
import json
import pathlib

import pytest
from reportlab.platypus import SimpleDocTemplate

from backend.utilities.pdf.cbom_inventory_pdf import _algorithm_rows, _library_rows
from backend.utilities.pdf.cbom_pdf import generate_pdf
from backend.utilities.pdf.report_branding import build_finding_section, get_report_styles

_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "cbom_d3_bank_scandata.json"


def _text(pdf: bytes) -> str:
    pypdf = pytest.importorskip("pypdf")
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_evidence_is_printed_as_written_once(tmp_path):
    """``salt=b"<redacted:21>"`` printed as ``&lt;redacted:21&gt;`` (m1): Preformatted draws text verbatim, so the
    evidence is not escaped first; markup in it is printed, never interpreted."""
    styles = get_report_styles()
    out = io.BytesIO()
    evidence = 'kdf = PBKDF2HMAC(salt=b"<redacted:21>")\n<font size=40>x</font> & <b>y</b>'
    SimpleDocTemplate(out).build([build_finding_section(index=1, title="salt", severity="Medium", detail_rows=[],
                                                        description="", evidence=evidence, recommended_fix="",
                                                        styles=styles)])
    text = _text(out.getvalue())
    assert 'salt=b"<redacted:21>"' in text
    assert "&lt;" not in text and "&amp;" not in text
    assert "<font size=40>x</font> & <b>y</b>" in text


@pytest.mark.parametrize(
    ("value", "separators", "width", "lines"),
    [("router/encryption.py:71", "/:", 65, ["router/", "encryption.py:71"]),
     ("pyca/cryptography", "/ ", 40, ["pyca/", "cryptography"]),
     ("block-cipher", "-", 30, ["block-", "cipher"])],
)
def test_narrow_cells_break_only_after_a_separator(value, separators, width, lines):
    """"block-ciph er", "router/encryption.p y:71" (m5): a cell breaks after a separator, never inside a word."""
    from backend.utilities.pdf.report_branding import wrap_at_separators

    style = get_report_styles()["table_cell"]
    assert wrap_at_separators(value, style, width, separators).split("<br/>") == lines


def test_unknown_key_size_does_not_start_with_a_dash():
    comp = {"type": "cryptographic-asset", "name": "PBKDF2",
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kdf"}},
            "properties": [{"name": "crypto:iterations", "value": "600000"},
                           {"name": "discovery:source", "value": "a.py"}]}
    (row,) = _algorithm_rows([comp], {})
    assert row[3] == "iterations 600000"


def test_one_cryptography_library_row_with_its_advisories():
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    names = [r[0] for r in _library_rows(payload["cbom_json"]["components"])]
    assert names.count("pyca/cryptography") == 1
    assert not [n for n in names if n.startswith("cryptography@")]


def test_inventory_headers_are_whole_words(tmp_path):
    out = tmp_path / "cbom.pdf"
    generate_pdf(json.loads(_FIXTURE.read_text(encoding="utf-8")), str(out))
    text = _text(out.read_bytes())
    for broken in ("MO DE", "NIS T", "block-ciph er", "pyca/cryptogr aphy", "—;"):
        assert broken not in text, broken
