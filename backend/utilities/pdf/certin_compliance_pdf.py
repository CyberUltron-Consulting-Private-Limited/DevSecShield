"""CERT-In Technical Guidelines compliance appendix for BOM PDF exports."""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

_CERTIN_DISCLAIMER = (
    "Advisory mapping to CERT-In Technical Guidelines on SBOM, QBOM & CBOM, "
    "AIBOM and HBOM v2.0 (09.07.2025). Does not constitute CERT-In certification "
    "or regulatory approval."
)


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


def append_certin_compliance_pdf_section(
    story: list,
    scan_payload: dict[str, Any],
    heading_style: ParagraphStyle,
    normal_style: ParagraphStyle,
    small_style: ParagraphStyle,
) -> None:
    """Append CERT-In framework tables when ``cert_in_*`` keys are present."""
    compliance = _compliance_blob(scan_payload)
    if not compliance:
        return

    frameworks = [
        (k, v)
        for k, v in compliance.items()
        if k.startswith("cert_in_") and isinstance(v, dict)
    ]
    if not frameworks:
        return

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("CERT-In Technical Guidelines (Advisory)", heading_style))
    story.append(Paragraph(_escape(_CERTIN_DISCLAIMER), small_style))

    rows = [["Framework", "Pass", "Fail", "NBE", "Coverage"]]
    for key, fw in frameworks:
        cov = fw.get("coverage")
        cov_s = "n/a" if cov is None else f"{round(float(cov) * 100)}%"
        rows.append(
            [
                _escape(key),
                str(int(fw.get("pass", 0)) + int(fw.get("pass_with_evidence", 0) or 0)),
                str(fw.get("fail", 0)),
                str(fw.get("not_bom_evidenceable", 0)),
                cov_s,
            ]
        )
    table = Table(rows, colWidths=[2.2 * 72, 0.7 * 72, 0.7 * 72, 0.7 * 72, 0.9 * 72])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F766E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(table)

    # Optional: first few attested / NBE rows for audit trail
    for key, fw in frameworks:
        reqs = [
            r
            for r in (fw.get("requirements") or [])
            if isinstance(r, dict)
            and r.get("verdict") in ("pass_with_evidence", "not_bom_evidenceable")
        ][:8]
        if not reqs:
            continue
        story.append(Spacer(1, 0.1 * inch))
        story.append(
            Paragraph(_escape(f"{key} — sample requirements"), normal_style)
        )
        for r in reqs:
            story.append(
                Paragraph(
                    _escape(
                        f"{r.get('id')}: {r.get('verdict')} — {r.get('title') or ''}"
                    ),
                    small_style,
                )
            )
