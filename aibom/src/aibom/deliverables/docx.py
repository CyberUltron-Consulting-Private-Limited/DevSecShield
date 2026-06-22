"""DOCX SaMD / PCCP readiness memo template. Generated from
``ScanResult.compliance`` via python-docx — a narrative memo a regulatory lead
fills in, pre-populated with the per-framework readiness the BOM evidences.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from docx import Document
from docx.shared import Pt

from aibom.deliverables import FRAMEWORK_TITLES, coverage_label, register_writer


@register_writer("docx")
def write_docx(compliance: dict[str, Any], path: Path, subject: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = Document()
    doc.add_heading("SaMD / PCCP Readiness Memo", level=0)
    doc.add_paragraph(f"Subject: {subject}")
    doc.add_paragraph(
        "This memo summarises the AI Bill of Materials compliance readiness for "
        "the above Software-as-a-Medical-Device. It is generated from the AI-BOM "
        "graph and is advisory; a qualified regulatory reviewer must complete and "
        "sign off each section."
    )

    doc.add_heading("1. Readiness summary", level=1)
    table = doc.add_table(rows=1, cols=5)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    for i, label in enumerate(("Framework", "Pass", "Fail", "N/A", "Coverage")):
        hdr[i].text = label
    for fw, title in FRAMEWORK_TITLES.items():
        b = compliance[fw]
        row = table.add_row().cells
        row[0].text = title
        row[1].text = str(b["pass"])
        row[2].text = str(b["fail"])
        row[3].text = str(b["na"])
        row[4].text = coverage_label(b["coverage"])

    doc.add_heading("2. Per-framework gaps & actions", level=1)
    for fw, title in FRAMEWORK_TITLES.items():
        b = compliance[fw]
        doc.add_heading(
            f"{title} — coverage {coverage_label(b['coverage'])}", level=2
        )
        gaps = [q for q in b["requirements"] if q["verdict"] == "fail"]
        nas = [q for q in b["requirements"] if q["verdict"] == "na"]
        if gaps:
            doc.add_paragraph("Open gaps (fail):", style="Intense Quote")
            for q in gaps:
                doc.add_paragraph(f"{q['id']} — {q['title']}: {q['evidence']}",
                                  style="List Bullet")
        else:
            doc.add_paragraph("No open gaps from BOM-evidenced checks.")
        if nas:
            p = doc.add_paragraph(
                "Requires manual evidence (N/A — not BOM-modelled): "
                + ", ".join(q["id"] for q in nas)
            )
            p.runs[0].font.size = Pt(9)

    doc.add_heading("3. PCCP modification protocol", level=1)
    doc.add_paragraph(
        "[Describe the Predetermined Change Control Plan: the scope of "
        "pre-authorised model modifications, the modification protocol, and the "
        "impact assessment — must stay within intended use and be risk-based.]"
    )

    doc.add_heading("Disclaimer", level=1)
    text = compliance.get("disclaimer", "") or (
        "Regulatory mappings are advisory only; a qualified regulatory reviewer "
        "must sign off."
    )
    # add_run() always creates exactly one run, so this is safe even if the
    # supplied disclaimer were empty (add_paragraph("").runs[0] would IndexError).
    doc.add_paragraph().add_run(text).italic = True

    doc.save(str(path))
