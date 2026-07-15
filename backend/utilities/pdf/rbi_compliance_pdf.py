"""RBI FREE-AI / CSF compliance appendix for BOM PDF exports."""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup


def _escape(s: Any) -> str:
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _compliance_blob(payload: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("ai_bom_compliance", "cbom_compliance", "sbom_compliance"):
        val = payload.get(key)
        if isinstance(val, dict) and val:
            return val
    return None


def append_rbi_compliance_pdf_section(
    story: list,
    scan_payload: dict[str, Any],
    heading_style: ParagraphStyle,
    normal_style: ParagraphStyle,
    small_style: ParagraphStyle,
) -> None:
    """Append RBI framework + CSF rollup tables when compliance data is present."""
    compliance = _compliance_blob(scan_payload)
    if not compliance:
        return

    rollup = scan_payload.get("rbi_csf_rollup")
    if not rollup and compliance:
        ai = scan_payload.get("ai_bom_compliance")
        cb = scan_payload.get("cbom_compliance")
        sb = scan_payload.get("sbom_compliance")
        rollup = build_rbi_csf_rollup(
            ai_bom_compliance=ai if isinstance(ai, dict) else None,
            cbom_compliance=cb if isinstance(cb, dict) else None,
            sbom_compliance=sb if isinstance(sb, dict) else None,
        )

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("RBI FREE-AI Compliance (Advisory)", heading_style))
    story.append(
        Paragraph(
            _escape(
                (rollup or {}).get("disclaimer")
                or "Advisory mapping only; does not satisfy regulatory obligations."
            ),
            small_style,
        )
    )

    frameworks = [
        (k, v)
        for k, v in compliance.items()
        if k != "disclaimer" and isinstance(v, dict)
    ]
    if frameworks:
        rows = [["Framework", "Pass", "Fail", "Coverage"]]
        for key, fw in frameworks:
            cov = fw.get("coverage")
            cov_s = "n/a" if cov is None else f"{round(float(cov) * 100)}%"
            rows.append(
                [
                    _escape(key),
                    str(fw.get("pass", 0)),
                    str(fw.get("fail", 0)),
                    cov_s,
                ]
            )
        table = Table(rows, colWidths=[2.4 * 72, 0.8 * 72, 0.8 * 72, 1.0 * 72])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        story.append(table)

    pillars = (rollup or {}).get("rbi_csf_rollup") if isinstance(rollup, dict) else None
    if isinstance(pillars, dict) and pillars:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("RBI CSF Pillar Rollup", heading_style))
        prow = [["Pillar", "Pass", "Fail", "Coverage"]]
        for pname, pdata in pillars.items():
            if not isinstance(pdata, dict):
                continue
            cov = pdata.get("coverage")
            cov_s = "n/a" if cov is None else f"{round(float(cov) * 100)}%"
            prow.append(
                [
                    _escape(pname),
                    str(pdata.get("pass", 0)),
                    str(pdata.get("fail", 0)),
                    cov_s,
                ]
            )
        ptable = Table(prow, colWidths=[2.4 * 72, 0.8 * 72, 0.8 * 72, 1.0 * 72])
        ptable.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14532D")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ]
            )
        )
        story.append(ptable)
