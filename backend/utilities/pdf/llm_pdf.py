"""
LLM Benchmark Scan Results PDF Generator
Generates a PDF report from LLM benchmark scan results (FinalLLMBenchmarkingVulnerabilities).
Data: list of vulnerabilities or { "vulnerabilities": [...] } per worker/helpers/tools/llm_agent/main.py.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from reportlab.lib.enums import TA_LEFT


def _normalize_vulnerabilities(scan_results: Any) -> List[Dict[str, Any]]:
    """Accept list of vulns or dict with 'vulnerabilities' key."""
    if scan_results is None:
        return []
    if isinstance(scan_results, list):
        return scan_results if all(isinstance(x, dict) for x in scan_results) else []
    if isinstance(scan_results, dict) and "vulnerabilities" in scan_results:
        v = scan_results["vulnerabilities"]
        return v if isinstance(v, list) else []
    return []


def get_severity_color(impact: str) -> colors.Color:
    impact_upper = (impact or "").upper()
    if impact_upper == "CRITICAL":
        return colors.HexColor("#DC2626")
    if impact_upper == "HIGH":
        return colors.HexColor("#F97316")
    if impact_upper == "MEDIUM":
        return colors.HexColor("#FBBF24")
    if impact_upper == "LOW":
        return colors.HexColor("#10B981")
    return colors.HexColor("#6B7280")


def create_title_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        "LLM Benchmark Scan Report",
    )
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Large Language Model Security Benchmark Findings",
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
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica", 9)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))
    canvas_obj.drawCentredString(doc.pagesize[0] / 2.0, 30, f"Page {canvas_obj.getPageNumber()}")
    canvas_obj.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(72, 45, doc.pagesize[0] - 72, 45)
    canvas_obj.restoreState()


def _format_owasp_or_compliance(val: Any) -> str:
    if val is None:
        return "—"
    if isinstance(val, list):
        return ", ".join(
            str(x.get(list(x.keys())[0], list(x.keys())[0]) if isinstance(x, dict) and x else x)
            for x in val[:10]
        ) or "—"
    if isinstance(val, dict):
        return ", ".join(str(v) for v in list(val.values())[:10]) or "—"
    return str(val)


def generate_pdf(scan_results: Any, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from LLM benchmark scan results.
    scan_results: list of vulnerability dicts, or dict with "vulnerabilities" key.
    """
    if output_path is None:
        output_path = f"llm_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    vulnerabilities = _normalize_vulnerabilities(scan_results)
    total = len(vulnerabilities)

    by_impact: Dict[str, int] = {}
    for v in vulnerabilities:
        imp = (v.get("impact") or "Unknown").strip() or "Unknown"
        by_impact[imp] = by_impact.get(imp, 0) + 1

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

    story.append(PageBreak())

    story.append(Paragraph("Executive Summary", title_style))
    story.append(Spacer(1, 0.3 * inch))

    summary_data = [
        ["Metric", "Value"],
        ["Total Findings", str(total)],
    ]
    for imp in ["Critical", "High", "Medium", "Low"]:
        count = by_impact.get(imp, 0)
        if count > 0:
            summary_data.append([imp, str(count)])

    summary_table = Table(summary_data, colWidths=[3.5 * inch, 2.5 * inch], repeatRows=1)
    summary_table.setStyle(
        TableStyle([
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
        ])
    )
    story.append(KeepTogether([summary_table]))
    story.append(PageBreak())

    if total == 0:
        story.append(Paragraph("No vulnerability findings from this LLM benchmark scan.", normal_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            if idx > 1:
                story.append(PageBreak())

            title = (vuln.get("title") or "Untitled finding").strip() or "Untitled finding"
            impact = (vuln.get("impact") or "").strip() or "Unknown"
            description = (vuln.get("description") or "").strip()
            owasp_llm = vuln.get("owasp_top_10_llm")
            compliance = vuln.get("compliance_controls")
            suggested_fix = (vuln.get("suggested_fix") or "").strip()

            story.append(Paragraph(f"Finding #{idx}: {title[:80]}{'...' if len(title) > 80 else ''}", heading_style))
            story.append(Spacer(1, 0.2 * inch))

            finding_data = [["Property", "Value"]]
            finding_data.append(["Title", Paragraph(title[:500] + ("..." if len(title) > 500 else ""), normal_style)])
            finding_data.append(["Impact", impact])
            if description:
                finding_data.append(["Description", Paragraph(description[:1500] + ("..." if len(description) > 1500 else ""), normal_style)])
            if owasp_llm:
                finding_data.append(["OWASP Top 10 for LLM", _format_owasp_or_compliance(owasp_llm)])
            if compliance:
                finding_data.append(["Compliance controls", _format_owasp_or_compliance(compliance)])
            if suggested_fix:
                finding_data.append(["Suggested fix", Paragraph(suggested_fix[:1500] + ("..." if len(suggested_fix) > 1500 else ""), normal_style)])

            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), get_severity_color(impact)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
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
                ])
            )
            story.append(KeepTogether([finding_table]))

    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    return output_path


if __name__ == "__main__":
    import sys
    test_path = os.path.join(os.path.dirname(__file__), "..", "..", "RabbitMQ", "worker", "archive", "first_llm_agent_results_testing.json")
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
    try:
        with open(test_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = generate_pdf(data, f"llm_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        print(f"PDF generated: {out}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error: {e}")
