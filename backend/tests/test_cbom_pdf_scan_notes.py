"""The CBOM PDF carries the import notes (uploaded CBOM file) and the coverage notes (code scan) that the results
page shows above the table; it used to leave both out (round 5, G3 item 3)."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.pdf.cbom_pdf import scan_notes  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload  # noqa: E402
from backend.tests.support.pdf_text import pdf_text  # noqa: E402

ROW = {"algorithm_name": "MD5", "quantum_safe": True, "crypto_strength": "weak", "impact": "High", "location": "a.py"}


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_uploaded_cbom_import_notes_are_in_the_pdf(tmp_path):
    scan_data = {
        "results": [ROW],
        "cbom_input": {"components_total": 9, "crypto_assets": 3, "imported": 1, "skipped_not_crypto": 6,
                       "duplicates": 2, "truncated": False, "spec_version": "1.6",
                       "notes": ["2 duplicate cryptographic assets were merged."]},
    }
    title, summary, lines = scan_notes(scan_data)
    assert title == "About the uploaded CBOM file"
    assert summary == "1 of 3 cryptographic assets imported · CycloneDX 1.6 · 6 non-crypto components skipped · 2 duplicates"
    assert lines[0] == "2 duplicate cryptographic assets were merged."
    assert lines[1].startswith("6 component(s) of the file are not cryptographic assets")
    out = tmp_path / "upload.pdf"
    generate_pdf_for_type("cbom", prepare_pdf_export_payload("cbom", scan_data), str(out))
    text = _flat(pdf_text(out.read_bytes()))
    assert "About the uploaded CBOM file" in text
    assert "2 duplicate cryptographic assets were merged." in text
    assert "6 component(s) of the file are not cryptographic assets" in text


def test_code_scan_coverage_notes_are_in_the_pdf(tmp_path):
    scan_data = {
        "results": [ROW],
        "cbom_json": {"metadata": {"properties": [
            {"name": "crypto:coverage:skippedBinary", "value": "4"},
            {"name": "crypto:coverage:archiveEncrypted", "value": "1"},
        ]}},
    }
    title, summary, lines = scan_notes(scan_data)
    assert title == "What this scan covered"
    assert summary.startswith("2 kind(s) of input were skipped")
    assert any(line.startswith("4 binary file(s) were skipped") for line in lines)
    out = tmp_path / "code.pdf"
    generate_pdf_for_type("cbom", prepare_pdf_export_payload("cbom", scan_data), str(out))
    text = _flat(pdf_text(out.read_bytes()))
    assert "What this scan covered" in text
    assert "4 binary file(s) were skipped" in text
    assert "1 encrypted archive member(s) could not be read" in text


def test_no_notes_no_section(tmp_path):
    assert scan_notes({"results": [ROW]}) is None
    clean_import = {"results": [ROW], "cbom_input": {"crypto_assets": 1, "imported": 1, "notes": []}}
    assert scan_notes(clean_import) is None
    out = tmp_path / "plain.pdf"
    generate_pdf_for_type("cbom", {"results": [ROW]}, str(out))
    text = _flat(pdf_text(out.read_bytes()))
    assert "What this scan covered" not in text and "About the uploaded CBOM file" not in text
