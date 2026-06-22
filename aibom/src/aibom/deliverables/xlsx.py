"""XLSX traceability matrix — one sheet per framework (requirement → mapped
field/edge → evidence → pass/fail/na) + a summary sheet. Generated from
``ScanResult.compliance``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from aibom.deliverables import FRAMEWORK_TITLES, coverage_label, register_writer

_VERDICT_FILL = {
    "pass": PatternFill("solid", fgColor="C6EFCE"),
    "fail": PatternFill("solid", fgColor="FFC7CE"),
    "na": PatternFill("solid", fgColor="FFEB9C"),
}
_HEADER = Font(bold=True)
_WRAP = Alignment(wrap_text=True, vertical="top")


@register_writer("xlsx")
def write_xlsx(compliance: dict[str, Any], path: Path, subject: str) -> None:
    wb = Workbook()
    wb.remove(wb.active)  # drop the default sheet

    summary = wb.create_sheet("Summary")
    summary.append([f"AI BOM Compliance Readiness — {subject}"])
    summary["A1"].font = Font(bold=True, size=14)
    summary.append([])
    summary.append(["Framework", "Pass", "Fail", "N/A", "Coverage"])
    for c in summary[3]:
        c.font = _HEADER
    for fw, title in FRAMEWORK_TITLES.items():
        b = compliance[fw]
        summary.append(
            [title, b["pass"], b["fail"], b["na"], coverage_label(b["coverage"])]
        )
    summary.append([])
    summary.append([compliance.get("disclaimer", "")])

    for fw, title in FRAMEWORK_TITLES.items():
        ws = wb.create_sheet(title[:31])
        headers = [
            "ID", "Requirement", "Mapped to (source)", "Verdict", "Evidence", "Refs"
        ]
        ws.append(headers)
        for c in ws[1]:
            c.font = _HEADER
        for q in compliance[fw]["requirements"]:
            ws.append(
                [
                    q["id"],
                    q["title"],
                    q["source"],
                    q["verdict"].upper(),
                    q["evidence"],
                    ", ".join(q["refs"]),
                ]
            )
            verdict_cell = ws.cell(row=ws.max_row, column=4)
            verdict_cell.fill = _VERDICT_FILL.get(q["verdict"], _VERDICT_FILL["na"])
        for col, width in zip("ABCDEF", (12, 42, 28, 9, 60, 24), strict=True):
            ws.column_dimensions[col].width = width
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = _WRAP

    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
