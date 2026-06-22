"""PDF "AI BOM Compliance Readiness Report" — exec summary + per-framework gap
tables (coverage with NA shown separately) + advisory disclaimer. Generated
from ``ScanResult.compliance`` via ReportLab.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from aibom.deliverables import FRAMEWORK_TITLES, coverage_label, register_writer

_VERDICT_COLOR = {
    "pass": colors.HexColor("#C6EFCE"),
    "fail": colors.HexColor("#FFC7CE"),
    "na": colors.HexColor("#FFEB9C"),
}


@register_writer("pdf")
def write_pdf(compliance: dict[str, Any], path: Path, subject: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    cell = styles["BodyText"]
    cell.fontSize = 8
    cell.leading = 10
    story: list[Any] = [
        Paragraph("AI BOM Compliance Readiness Report", styles["Title"]),
        Paragraph(f"Subject: {subject}", styles["Heading2"]),
        Spacer(1, 8),
    ]

    # --- Executive summary ---
    story.append(Paragraph("Executive summary", styles["Heading2"]))
    summary = [["Framework", "Pass", "Fail", "N/A", "Coverage"]]
    for fw, title in FRAMEWORK_TITLES.items():
        b = compliance[fw]
        summary.append(
            [title, str(b["pass"]), str(b["fail"]), str(b["na"]),
             coverage_label(b["coverage"])]
        )
    t = Table(summary, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#305496")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story += [t, Spacer(1, 6)]
    story.append(
        Paragraph(
            "Coverage = pass / (pass + fail). N/A items are out of scope and "
            "excluded from coverage (shown separately).",
            styles["Italic"],
        )
    )
    story.append(Spacer(1, 12))

    # --- Per-framework detail ---
    for fw, title in FRAMEWORK_TITLES.items():
        b = compliance[fw]
        story.append(
            Paragraph(
                f"{title} — coverage {coverage_label(b['coverage'])} "
                f"({b['pass']} pass / {b['fail']} fail / {b['na']} N/A)",
                styles["Heading3"],
            )
        )
        rows = [["ID", "Requirement", "Source", "Verdict", "Evidence"]]
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E1F2")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i, q in enumerate(b["requirements"], start=1):
            evidence = q["evidence"]
            if q["refs"]:
                evidence += (
                    "<br/><font size=7 color='#666666'>refs: "
                    + ", ".join(q["refs"])
                    + "</font>"
                )
            rows.append(
                [
                    q["id"],
                    Paragraph(q["title"], cell),
                    Paragraph(q["source"], cell),  # regulatory citation (traceability)
                    q["verdict"].upper(),
                    Paragraph(evidence, cell),
                ]
            )
            style_cmds.append(
                ("BACKGROUND", (3, i), (3, i), _VERDICT_COLOR.get(q["verdict"]))
            )
        table = Table(
            rows,
            colWidths=[0.7 * inch, 1.8 * inch, 1.3 * inch, 0.6 * inch, 2.3 * inch],
        )
        table.setStyle(TableStyle(style_cmds))
        story += [table, Spacer(1, 10)]

    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f"<b>Disclaimer.</b> {compliance.get('disclaimer', '')}", styles["Italic"]
        )
    )

    SimpleDocTemplate(str(path), pagesize=LETTER).build(story)
