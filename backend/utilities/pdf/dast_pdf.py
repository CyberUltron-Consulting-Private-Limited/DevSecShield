"""
DAST Scan Results PDF Generator
Generates a comprehensive PDF report from DAST scan results using reportlab.
Supports DataSpecs.md format: results list with title, url, confidence, impact,
owasp_top_10, compliance_controls, description, suggested_fix, category.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    KeepTogether,
)
from reportlab.lib.enums import TA_LEFT
from reportlab.pdfgen import canvas


def _normalize_scan_data(scan_data: Any) -> Tuple[List[Dict[str, Any]], Optional[float], Optional[Dict]]:
    """
    Accept list of findings (as passed by export endpoint) or full payload with results/duration/metadata.
    Returns (results_list, duration_of_scan, metadata).
    """
    if isinstance(scan_data, list):
        return scan_data, None, None
    if isinstance(scan_data, dict):
        results = scan_data.get("results", [])
        if not isinstance(results, list):
            results = []
        duration = scan_data.get("duration_of_scan")
        metadata = scan_data.get("metadata")
        return results, duration, metadata
    return [], None, None


def _format_owasp_compliance_dict(d: Any) -> str:
    """Format owasp_top_10 or compliance_controls dict as comma-separated labels."""
    if not d or not isinstance(d, dict):
        return ""
    parts = [str(v).strip() for v in d.values() if v]
    return ", ".join(parts) if parts else ""


def _escape_html(s: str) -> str:
    """Escape &, <, > for ReportLab Paragraph (HTML-like) content."""
    if not s:
        return ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_impact_color(impact: str) -> colors.Color:
    """Get color based on impact level (Critical/High/Medium/Low)."""
    val = (impact or "").strip().upper()
    if val == "CRITICAL":
        return colors.HexColor("#DC2626")
    if val == "HIGH":
        return colors.HexColor("#EA580C")
    if val == "MEDIUM":
        return colors.HexColor("#CA8A04")
    if val == "LOW":
        return colors.HexColor("#2563EB")
    return colors.HexColor("#6B7280")


def create_title_page(
    canvas_obj: canvas.Canvas,
    doc: SimpleDocTemplate,
    title: str = "DAST Security Scan Report",
    subtitle: str = "Dynamic Application Security Testing Analysis",
) -> None:
    """Create a title page for the PDF."""
    canvas_obj.saveState()

    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        title,
    )

    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        subtitle,
    )

    logo_path = os.path.join(os.path.dirname(__file__), "Zero Shield Logo.png")
    if os.path.exists(logo_path):
        try:
            img_reader = ImageReader(logo_path)
            img_width, img_height = img_reader.getSize()
            max_width = 2.5 * inch
            scale_factor = max_width / img_width
            logo_width = max_width
            logo_height = img_height * scale_factor
            logo_x = (doc.pagesize[0] - logo_width) / 2.0
            logo_y = doc.pagesize[1] / 2.0 - 20 - logo_height
            canvas_obj.drawImage(logo_path, logo_x, logo_y, width=logo_width, height=logo_height)
        except Exception:
            pass

    canvas_obj.setFont("Helvetica", 12)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 - 120,
        f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
    )
    canvas_obj.restoreState()


def create_header_footer(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    """Create header and footer for regular pages."""
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica", 9)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        30,
        f"Page {canvas_obj.getPageNumber()}",
    )
    canvas_obj.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(72, 45, doc.pagesize[0] - 72, 45)
    canvas_obj.restoreState()


def generate_pdf(
    scan_data: dict,
    output_path: str,
    report_title: str = "DAST Security Scan Report",
    report_subtitle: str = "Dynamic Application Security Testing Analysis",
) -> str:
    """
    Generate a PDF report from DAST scan results.

    scan_data can be:
    - A list of findings (each with title, url, confidence, impact, owasp_top_10,
      compliance_controls, description, suggested_fix, category).
    - A dict with "results" (list), optional "duration_of_scan", optional "metadata"
      (urls_included, urls_excluded).

    Returns:
        Path to the generated PDF file.
    """
    results, duration_of_scan, metadata = _normalize_scan_data(scan_data)
    total_findings = len(results)

    by_impact: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    by_category: Dict[str, int] = {}

    for r in results:
        impact = (r.get("impact") or "Unknown").strip() or "Unknown"
        by_impact[impact] = by_impact.get(impact, 0) + 1
        conf = (r.get("confidence") or "Unknown").strip() or "Unknown"
        by_confidence[conf] = by_confidence.get(conf, 0) + 1
        cat = (r.get("category") or "Other").strip().replace("_", " ") or "Other"
        by_category[cat] = by_category.get(cat, 0) + 1

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18,
    )

    story: List[Any] = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=16,
        spaceBefore=8,
        alignment=TA_LEFT,
        wordWrap="CJK",
        fontName="Helvetica-Bold",
        leading=26,
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=8,
        spaceBefore=10,
        wordWrap="CJK",
        fontName="Helvetica-Bold",
        leading=16,
    )

    normal_style = ParagraphStyle(
        "CustomNormal",
        parent=styles["Normal"],
        fontSize=9,
        spaceAfter=8,
        spaceBefore=4,
        wordWrap="CJK",
        leading=12,
        textColor=colors.HexColor("#334155"),
        fontName="Helvetica",
    )

    desc_heading_style = ParagraphStyle(
        "DescHeading",
        parent=styles["Normal"],
        fontSize=10,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
        spaceBefore=0,
    )

    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("Executive Summary", title_style))
    story.append(Spacer(1, 0.3 * inch))

    summary_data = [["Metric", "Value"], ["Total Findings", str(total_findings)]]
    if duration_of_scan is not None:
        summary_data.append(["Duration (seconds)", f"{duration_of_scan:.1f}"])
    if metadata and isinstance(metadata, dict):
        urls_in = metadata.get("urls_included")
        urls_ex = metadata.get("urls_excluded")
        if isinstance(urls_in, list):
            summary_data.append(["URLs Included", str(len(urls_in))])
        if isinstance(urls_ex, list):
            summary_data.append(["URLs Excluded", str(len(urls_ex))])

    summary_table = Table(summary_data, colWidths=[3.5 * inch, 2.5 * inch], repeatRows=1)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                ("TOPPADDING", (0, 1), (-1, -1), 6),
            ]
        )
    )
    story.append(KeepTogether([summary_table]))
    story.append(Spacer(1, 0.4 * inch))

    # Findings by Impact
    story.append(Paragraph("Findings by Impact", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    impact_data = [["Impact", "Count"]]
    for level in ["Critical", "High", "Medium", "Low", "Unknown"]:
        count = by_impact.get(level, 0) or by_impact.get(level.upper(), 0)
        if count > 0:
            impact_data.append([level, str(count)])
    if len(impact_data) > 1:
        impact_table = Table(impact_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        impact_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 11),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                ]
            )
        )
        story.append(KeepTogether([impact_table]))
    story.append(Spacer(1, 0.3 * inch))

    # Findings by Confidence
    story.append(Paragraph("Findings by Confidence", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    conf_data = [["Confidence", "Count"]]
    for level in ["High", "Medium", "Low", "Unknown"]:
        count = by_confidence.get(level, 0)
        if count > 0:
            conf_data.append([level, str(count)])
    if len(conf_data) > 1:
        conf_table = Table(conf_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        conf_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 11),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                ]
            )
        )
        story.append(KeepTogether([conf_table]))
    story.append(Spacer(1, 0.3 * inch))

    # Findings by Category
    if by_category:
        story.append(Paragraph("Findings by Category", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        cat_data = [["Category", "Count"]]
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            cat_data.append([cat, str(count)])
        cat_table = Table(cat_data, colWidths=[3.5 * inch, 1.5 * inch], repeatRows=1)
        cat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 11),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                    ("TOPPADDING", (0, 1), (-1, -1), 6),
                ]
            )
        )
        story.append(KeepTogether([cat_table]))

    story.append(PageBreak())

    # Detailed Findings
    if total_findings == 0:
        story.append(Paragraph("No security findings detected.", normal_style))
    else:
        for idx, r in enumerate(results, 1):
            if idx > 1:
                story.append(PageBreak())

            title = (r.get("title") or "Finding").strip() or "Finding"
            url = (r.get("url") or "").strip() or "—"
            impact = (r.get("impact") or "Unknown").strip() or "Unknown"
            confidence = (r.get("confidence") or "—").strip() or "—"
            category = (r.get("category") or "—").strip().replace("_", " ") or "—"
            description = (r.get("description") or "No description available").strip() or "No description available"
            suggested_fix = (r.get("suggested_fix") or "").strip()
            owasp = r.get("owasp_top_10") or {}
            compliance = r.get("compliance_controls") or {}

            finding_title = f"Finding #{idx}: {title}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))

            finding_data = [["Property", "Value"]]
            finding_data.append(["Impact", impact])
            finding_data.append(["Confidence", confidence])
            finding_data.append(["Category", category])
            url_para = Paragraph(_escape_html(url[:250] + ("..." if len(url) > 250 else "")), normal_style)
            finding_data.append(["URL", url_para])

            owasp_str = _format_owasp_compliance_dict(owasp)
            if owasp_str:
                finding_data.append(
                    ["OWASP Top 10", Paragraph(_escape_html(owasp_str[:400]) + ("..." if len(owasp_str) > 400 else ""), normal_style)]
                )
            comp_str = _format_owasp_compliance_dict(compliance)
            if comp_str:
                finding_data.append(
                    ["Compliance", Paragraph(_escape_html(comp_str[:400]) + ("..." if len(comp_str) > 400 else ""), normal_style)]
                )

            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), get_impact_color(impact)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("ALIGN", (0, 0), (0, -1), "LEFT"),
                        ("ALIGN", (1, 0), (1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("TOPPADDING", (0, 0), (-1, 0), 8),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                        ("TOPPADDING", (0, 1), (-1, -1), 6),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ]
                )
            )
            story.append(KeepTogether([finding_table]))
            story.append(Spacer(1, 0.2 * inch))

            story.append(Paragraph("Description", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            story.append(Paragraph(_escape_html(description[:2000]) + ("..." if len(description) > 2000 else ""), normal_style))
            story.append(Spacer(1, 0.2 * inch))

            if suggested_fix:
                story.append(Paragraph("Suggested Fix", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                story.append(Paragraph(_escape_html(suggested_fix[:1500]) + ("..." if len(suggested_fix) > 1500 else ""), normal_style))

    doc.build(
        story,
        onFirstPage=lambda c, d: create_title_page(c, d, report_title, report_subtitle),
        onLaterPages=create_header_footer,
    )
    return output_path


if __name__ == "__main__":
    import json

    test_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "RabbitMQ",
        "dast_worker",
        "mock_data.json",
    )
    if os.path.exists(test_path):
        with open(test_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = f"dast_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path = generate_pdf(data, out)
        print(f"PDF generated: {path}")
    else:
        # Test with list-only (as export endpoint sends)
        findings = [
            {
                "title": "Sample XSS",
                "url": "https://example.com/page",
                "confidence": "high",
                "impact": "High",
                "category": "xss_and_client_side",
                "description": "Sample description.",
                "suggested_fix": "Encode output.",
                "owasp_top_10": {"INJECTION": "A03:2021 - Injection"},
                "compliance_controls": {},
            }
        ]
        out = f"dast_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path = generate_pdf(findings, out)
        print(f"PDF generated: {path}")
