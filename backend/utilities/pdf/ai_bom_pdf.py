"""
AI-BOM (AI Bill of Materials) Scan Results PDF Generator.

Generates a PDF report from AI-BOM scan results using reportlab.

Input: a list of AI asset dicts (agent output), each with fields:
  title, asset_name (or component_name), asset_type (or component_type), provider (or source),
  framework, version, license_type (or license), risk_category, location, snippet, impact,
  compliance_controls, owasp_top_10, owasp_top_10_llm, suggested_fix
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape(s: Any) -> str:
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


IMPACT_TO_RISK: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
}


def _impact_color(impact: str) -> colors.Color:
    mapping = {
        "critical": colors.HexColor("#DC2626"),
        "high": colors.HexColor("#F97316"),
        "medium": colors.HexColor("#FBBF24"),
        "low": colors.HexColor("#10B981"),
    }
    return mapping.get((impact or "").strip().lower(), colors.HexColor("#6B7280"))


def _asset_name(v: dict) -> str:
    """Tolerate both frontend (asset_name) and stored (component_name) field names."""
    return v.get("asset_name") or v.get("component_name") or ""


def _asset_type(v: dict) -> str:
    """Tolerate both frontend (asset_type) and stored (component_type) field names."""
    return v.get("asset_type") or v.get("component_type") or ""


def _provider(v: dict) -> str:
    """Tolerate both frontend (provider) and stored (source) field names."""
    return v.get("provider") or v.get("source") or ""


def _license_type(v: dict) -> str:
    """Tolerate both frontend (license_type) and stored (license) field names."""
    return v.get("license_type") or v.get("license") or ""


def _normalize_results(scan_results: Union[list, dict]) -> List[dict]:
    """Accept either a list of findings or a dict that contains them."""
    if isinstance(scan_results, list):
        return scan_results
    if isinstance(scan_results, dict):
        if "results" in scan_results:
            return scan_results["results"] or []
    return []


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None) -> str:
    """
    Generate an AI-BOM scan results PDF.

    Args:
        scan_results: list of AI-BOM asset dicts produced by the worker agent.
        output_path:  file path for the PDF. Auto-generated when None.

    Returns:
        Path to the written PDF.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"ai_bom_scan_report_{timestamp}.pdf"

    assets = _normalize_results(scan_results)
    total = len(assets)

    # --- Aggregate statistics ---
    by_impact: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_risk_category: Dict[str, int] = {}
    unlicensed = 0
    risk_sum = 0.0

    for v in assets:
        impact = (v.get("impact") or "unknown").strip().lower()
        by_impact[impact] = by_impact.get(impact, 0) + 1
        risk_sum += IMPACT_TO_RISK.get(impact, 2.0)

        provider = (_provider(v) or "unknown").strip().lower()
        by_provider[provider] = by_provider.get(provider, 0) + 1

        asset_type = (_asset_type(v) or "unknown").strip().lower()
        by_type[asset_type] = by_type.get(asset_type, 0) + 1

        risk_cat = (v.get("risk_category") or "unknown").strip().lower()
        by_risk_category[risk_cat] = by_risk_category.get(risk_cat, 0) + 1

        lic = (_license_type(v) or "").strip().lower()
        if not lic or lic == "unknown":
            unlicensed += 1

    avg_risk = risk_sum / total if total > 0 else 0.0

    # --- Document ---
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=24,
    )

    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "AiBomTitle",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=12,
        spaceBefore=6,
        alignment=TA_LEFT,
        fontName="Helvetica-Bold",
        leading=28,
    )
    heading_style = ParagraphStyle(
        "AiBomHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=6,
        spaceBefore=10,
        fontName="Helvetica-Bold",
        leading=16,
    )
    subheading_style = ParagraphStyle(
        "AiBomSubHeading",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4,
        spaceBefore=8,
        fontName="Helvetica-Bold",
        leading=14,
    )
    normal_style = ParagraphStyle(
        "AiBomNormal",
        parent=styles["Normal"],
        fontSize=9,
        spaceAfter=4,
        spaceBefore=2,
        wordWrap="CJK",
        leading=12,
        textColor=colors.HexColor("#334155"),
        fontName="Helvetica",
    )
    small_style = ParagraphStyle(
        "AiBomSmall",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#64748B"),
        fontName="Helvetica",
        leading=10,
    )
    code_style = ParagraphStyle(
        "AiBomCode",
        parent=styles["Code"],
        fontSize=8,
        fontName="Courier",
        spaceAfter=4,
        spaceBefore=4,
        leftIndent=8,
        rightIndent=8,
        backColor=colors.HexColor("#F8FAFC"),
        leading=11,
    )

    # -----------------------------------------------------------------------
    # Title section
    # -----------------------------------------------------------------------
    story.append(Paragraph("AI-BOM Security Scan Report", title_style))
    story.append(Paragraph(
        f"<font color='#64748B'>AI Bill of Materials Analysis &nbsp;|&nbsp; "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</font>",
        normal_style,
    ))
    story.append(Spacer(1, 0.15 * inch))

    # -----------------------------------------------------------------------
    # Executive summary table
    # -----------------------------------------------------------------------
    story.append(Paragraph("Executive Summary", heading_style))

    summary_data = [
        ["Metric", "Value"],
        ["Total AI Assets", str(total)],
        ["Critical", str(by_impact.get("critical", 0))],
        ["High", str(by_impact.get("high", 0))],
        ["Medium", str(by_impact.get("medium", 0))],
        ["Low", str(by_impact.get("low", 0))],
        ["Unlicensed Assets", str(unlicensed)],
        ["External Providers", str(len(by_provider))],
        ["Average Risk Score", f"{avg_risk:.1f} / 10"],
    ]

    summary_table = Table(summary_data, colWidths=[3.2 * inch, 2.8 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Asset type breakdown
    # -----------------------------------------------------------------------
    if by_type:
        story.append(Paragraph("Asset Type Distribution", heading_style))
        type_data = [["Asset Type", "Count"]]
        for asset_type, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
            type_data.append([_escape(asset_type.title()), str(cnt)])
        type_table = Table(type_data, colWidths=[3.5 * inch, 1.5 * inch])
        type_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(type_table)
        story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Findings detail
    # -----------------------------------------------------------------------
    if assets:
        story.append(PageBreak())
        story.append(Paragraph("AI Asset Findings", heading_style))
        story.append(Spacer(1, 0.1 * inch))

        # Sort: critical first, then by asset name
        impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_assets = sorted(
            assets,
            key=lambda v: (
                impact_order.get((v.get("impact") or "low").strip().lower(), 4),
                (_asset_name(v) or "").lower(),
            ),
        )

        for i, v in enumerate(sorted_assets, start=1):
            title = _escape(v.get("title") or _asset_name(v) or f"Finding #{i}")
            impact = (v.get("impact") or "unknown").strip().lower()
            asset_name = _escape(_asset_name(v) or "—")
            asset_type = _escape(_asset_type(v) or "—")
            provider = _escape(_provider(v) or "—")
            framework = _escape(v.get("framework") or "—")
            version = _escape(v.get("version") or "—")
            license_type = _escape(_license_type(v) or "—")
            risk_category = _escape(v.get("risk_category") or "—")
            location = _escape(v.get("location") or "—")
            snippet = _escape(v.get("snippet") or "")
            description = _escape(v.get("description") or "")
            suggested_fix = _escape(v.get("suggested_fix") or "")
            compliance = v.get("compliance_controls") or {}
            owasp = v.get("owasp_top_10") or {}
            owasp_llm = v.get("owasp_top_10_llm") or {}

            impact_col = _impact_color(impact)

            # Finding header row (impact badge + title)
            header_data = [[
                Paragraph(f"<b>#{i} — {title}</b>", subheading_style),
                Paragraph(
                    f"<font color='white'><b> {impact.upper()} </b></font>",
                    ParagraphStyle("badge", parent=normal_style, backColor=impact_col,
                                   textColor=colors.white, alignment=TA_CENTER),
                ),
            ]]
            header_table = Table(header_data, colWidths=[5.3 * inch, 0.9 * inch])
            header_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))

            # Metadata grid
            meta_rows = [
                ["Asset", asset_name, "Type", asset_type],
                ["Provider", provider, "License", license_type],
                ["Framework", framework, "Version", version],
                ["Risk Category", risk_category, "Location", location],
            ]
            meta_table = Table(meta_rows, colWidths=[1.0 * inch, 2.2 * inch, 1.0 * inch, 2.0 * inch])
            meta_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569")),
                ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#475569")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]))

            section = [header_table, Spacer(1, 0.06 * inch), meta_table]

            if description:
                section.append(Spacer(1, 0.06 * inch))
                section.append(Paragraph("<b>Description:</b>", small_style))
                section.append(Paragraph(description, normal_style))

            if snippet:
                section.append(Spacer(1, 0.04 * inch))
                section.append(Paragraph("<b>Code Snippet:</b>", small_style))
                section.append(Paragraph(snippet[:500], code_style))

            if suggested_fix:
                section.append(Spacer(1, 0.04 * inch))
                section.append(Paragraph("<b>Suggested Fix:</b>", small_style))
                section.append(Paragraph(suggested_fix, normal_style))

            if compliance:
                # compliance_controls is serialized as {control_id: description}.
                # Render the descriptions (values), matching the OWASP display,
                # instead of the bare control IDs (dict keys).
                if isinstance(compliance, dict):
                    controls = [str(val) for val in compliance.values() if val]
                else:
                    controls = [str(c) for c in compliance if c]
                if controls:
                    controls_text = ", ".join(controls)
                    section.append(Spacer(1, 0.04 * inch))
                    section.append(Paragraph("<b>Compliance Controls:</b>", small_style))
                    section.append(Paragraph(_escape(controls_text), normal_style))

            if owasp and isinstance(owasp, dict):
                owasp_parts = []
                for k, val in owasp.items():
                    owasp_parts.append(f"{_escape(str(k))}: {_escape(str(val))}")
                if owasp_parts:
                    section.append(Spacer(1, 0.04 * inch))
                    section.append(Paragraph("<b>OWASP References:</b>", small_style))
                    section.append(Paragraph("; ".join(owasp_parts), normal_style))

            if owasp_llm and isinstance(owasp_llm, dict):
                owasp_llm_parts = []
                for k, val in owasp_llm.items():
                    owasp_llm_parts.append(f"{_escape(str(k))}: {_escape(str(val))}")
                if owasp_llm_parts:
                    section.append(Spacer(1, 0.04 * inch))
                    section.append(Paragraph("<b>OWASP Top 10 LLM References:</b>", small_style))
                    section.append(Paragraph("; ".join(owasp_llm_parts), normal_style))

            section.append(Spacer(1, 0.15 * inch))
            story.append(KeepTogether(section))
    else:
        story.append(Paragraph("No AI assets were detected.", normal_style))

    if isinstance(scan_results, dict):
        from backend.utilities.pdf.rbi_compliance_pdf import append_rbi_compliance_pdf_section

        append_rbi_compliance_pdf_section(
            story, scan_results, heading_style, normal_style, small_style
        )

    # --- Build ---
    doc.build(story)
    return output_path
