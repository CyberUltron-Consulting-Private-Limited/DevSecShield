"""Shadow-AI findings report (xlsx / pdf) from a discovery :class:`ScanResult`.

Lists every discovered AI component, where it was found, and whether it is
sanctioned or UNSANCTIONED (per the allowlist diff). Format is chosen by the
output extension.
"""

from __future__ import annotations

from pathlib import Path

from aibom.emit._disclaimer import ADVISORY_DISCLAIMER
from aibom.model.result import ScanResult
from aibom.shadow.diff import SHADOW_KINDS


def _rows(result: ScanResult) -> list[dict[str, str]]:
    unsanctioned = {
        f.target for f in result.flags if f.code == "UNSANCTIONED_COMPONENT"
    }
    rows: list[dict[str, str]] = []
    for c in result.components:
        if c.kind not in SHADOW_KINDS:
            continue
        props = c.properties or {}
        rows.append(
            {
                "ref": c.bom_ref,
                "name": c.name,
                "kind": c.kind,
                "vendor": c.publisher or "",
                "source": props.get(
                    "discovery:source", props.get("discovery:host", "")
                ),
                "status": "UNSANCTIONED" if c.bom_ref in unsanctioned else "sanctioned",
            }
        )
    return sorted(
        rows, key=lambda r: (r["status"] != "UNSANCTIONED", r["kind"], r["name"])
    )


def write_findings(result: ScanResult, path: str | Path) -> None:
    """Write a shadow-AI findings report; format from the file extension."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = _rows(result)
    if p.suffix.lower() == ".pdf":
        _pdf(rows, result, p)
    else:
        _xlsx(rows, result, p)


def _xlsx(rows: list[dict[str, str]], result: ScanResult, path: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = "Shadow AI Findings"
    ws.append([f"Shadow-AI Findings — {result.subject.name}"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append([])
    headers = ["Component", "Kind", "Vendor", "Discovered in", "Status"]
    ws.append(headers)
    for c in ws[3]:
        c.font = Font(bold=True)
    red = PatternFill("solid", fgColor="FFC7CE")
    green = PatternFill("solid", fgColor="C6EFCE")
    for r in rows:
        ws.append([r["name"], r["kind"], r["vendor"], r["source"], r["status"]])
        ws.cell(row=ws.max_row, column=5).fill = (
            red if r["status"] == "UNSANCTIONED" else green
        )
    for col, w in zip("ABCDE", (28, 16, 16, 22, 14), strict=True):
        ws.column_dimensions[col].width = w
    ws.append([])
    ws.append([ADVISORY_DISCLAIMER])
    wb.save(path)


def _pdf(rows: list[dict[str, str]], result: ScanResult, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
    )

    styles = getSampleStyleSheet()
    n_unsanctioned = sum(1 for r in rows if r["status"] == "UNSANCTIONED")
    story = [
        Paragraph("Shadow-AI Findings Report", styles["Title"]),
        Paragraph(f"Subject: {result.subject.name}", styles["Heading2"]),
        Paragraph(
            f"{len(rows)} discovered AI component(s); "
            f"<b>{n_unsanctioned} UNSANCTIONED</b>.",
            styles["Normal"],
        ),
        Spacer(1, 10),
    ]
    data = [["Component", "Kind", "Vendor", "Discovered in", "Status"]]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#305496")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
    ]
    for i, r in enumerate(rows, start=1):
        data.append([r["name"], r["kind"], r["vendor"], r["source"], r["status"]])
        if r["status"] == "UNSANCTIONED":
            style.append(("BACKGROUND", (4, i), (4, i), colors.HexColor("#FFC7CE")))
    story.append(Table(data, hAlign="LEFT", colWidths=[150, 70, 70, 110, 80]))
    story += [
        Spacer(1, 10),
        Paragraph(f"<i>{ADVISORY_DISCLAIMER}</i>", styles["Italic"]),
    ]
    SimpleDocTemplate(str(path), pagesize=LETTER).build(story)


__all__ = ["write_findings"]
