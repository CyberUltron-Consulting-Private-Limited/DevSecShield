"""Deliverables (xlsx/pdf/docx) are valid documents generated FROM
``ScanResult.compliance`` — real fixture graph, no mocking.
"""

from __future__ import annotations

import pathlib

from aibom.compliance.engine import run_all
from aibom.deliverables import available_formats, get_writer
from aibom.scan.pipeline import scan_repo

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _compliance() -> dict:
    r = scan_repo(_EX / "clinical-imaging")
    run_all(r)
    return r.compliance


def test_all_three_formats_registered() -> None:
    assert set(available_formats()) == {"xlsx", "pdf", "docx"}


def test_xlsx_has_summary_and_framework_sheets(tmp_path: pathlib.Path) -> None:
    from openpyxl import load_workbook

    out = tmp_path / "matrix.xlsx"
    get_writer("xlsx")(_compliance(), out, "ChestXR-Triage-SaMD")
    assert out.stat().st_size > 0
    wb = load_workbook(out)
    assert "Summary" in wb.sheetnames
    assert "HIPAA" in wb.sheetnames and "FDA §524B" in wb.sheetnames
    hipaa = wb["HIPAA"]
    assert hipaa.max_row == 14  # header + 13 requirements
    verdicts = {hipaa.cell(row=i, column=4).value for i in range(2, 15)}
    assert verdicts <= {"PASS", "FAIL", "NA"}


def test_pdf_is_a_pdf(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "report.pdf"
    get_writer("pdf")(_compliance(), out, "ChestXR-Triage-SaMD")
    assert out.read_bytes().startswith(b"%PDF")


def test_docx_opens_and_has_headings(tmp_path: pathlib.Path) -> None:
    from docx import Document

    out = tmp_path / "memo.docx"
    get_writer("docx")(_compliance(), out, "ChestXR-Triage-SaMD")
    doc = Document(str(out))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "SaMD / PCCP Readiness Memo" in text
    assert "Disclaimer" in text


def test_docx_tolerates_missing_disclaimer(tmp_path: pathlib.Path) -> None:
    """docx must degrade gracefully (no IndexError) on a partial compliance dict."""
    from docx import Document

    compliance = _compliance()
    compliance.pop("disclaimer", None)  # partial report
    out = tmp_path / "memo.docx"
    get_writer("docx")(compliance, out, "Subject")  # must not raise
    text = "\n".join(p.text for p in Document(str(out)).paragraphs)
    assert "Disclaimer" in text and "advisory only" in text


def test_pdf_includes_source_citation(tmp_path: pathlib.Path) -> None:
    """The PDF readiness report carries each requirement's regulatory citation."""
    from pypdf import PdfReader

    out = tmp_path / "report.pdf"
    get_writer("pdf")(_compliance(), out, "Subject")
    text = "".join(page.extract_text() for page in PdfReader(str(out)).pages)
    assert "Annex IV" in text  # a Requirement.source citation rendered in the PDF


def test_deliverables_reflect_na_coverage(tmp_path: pathlib.Path) -> None:
    """A no-PHI scan -> HIPAA coverage 'N/A' surfaces in the xlsx summary."""
    from openpyxl import load_workbook

    r = scan_repo(_EX / "no-phi-model")
    run_all(r)
    out = tmp_path / "matrix.xlsx"
    get_writer("xlsx")(r.compliance, out, r.subject.name)
    summary = load_workbook(out)["Summary"]
    rows = {row[0]: row[4] for row in summary.iter_rows(min_row=4, values_only=True)
            if row[0]}
    assert rows["HIPAA"] == "N/A"
