"""
IAC Scan Results PDF Generator
Generates a comprehensive PDF report from IAC scan results using reportlab.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
    Image, KeepTogether, Preformatted
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas


def _normalize_results(scan_results: Any) -> List[Dict[str, Any]]:
    """Accept either a list of findings (agent format) or a dict with 'results' key."""
    if isinstance(scan_results, list):
        return scan_results
    if isinstance(scan_results, dict):
        return scan_results.get("results", [])
    return []


def _is_agent_format(finding: Dict[str, Any]) -> bool:
    """True if finding has title/impact/owasp_top_10 (IAC agent format)."""
    return (
        isinstance(finding, dict)
        and ("title" in finding or "impact" in finding)
        and ("owasp_top_10" in finding or "compliance_controls" in finding)
    )


def get_severity_color(impact_or_severity: str) -> colors.Color:
    """Get color based on impact/severity level."""
    val = (impact_or_severity or "").strip().upper()
    if val == "CRITICAL":
        return colors.HexColor("#DC2626")  # Red
    elif val == "HIGH":
        return colors.HexColor("#F97316")  # Orange
    elif val == "MEDIUM":
        return colors.HexColor("#FBBF24")  # Yellow
    elif val == "LOW":
        return colors.HexColor("#10B981")  # Green
    else:
        return colors.HexColor("#6B7280")  # Gray


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


def get_relative_path(file_path: str) -> str:
    """Extract path from repo_xxxxxxx onwards for legacy location.filename."""
    try:
        repo_index = file_path.find("repo_")
        if repo_index != -1:
            return file_path[repo_index:]
        return file_path or ""
    except Exception:
        return file_path or ""


def create_title_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """Create a title page for the PDF."""
    canvas_obj.saveState()
    
    # Title text - positioned at top center
    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))  # Professional dark slate
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        "IAC Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Infrastructure as Code Security Analysis"
    )
    
    # Add logo below the title - smaller size
    logo_path = os.path.join(os.path.dirname(__file__), "Zero Shield Logo.png")
    if os.path.exists(logo_path):
        try:
            # Load and draw logo - smaller size (max width 2.5 inches)
            img_reader = ImageReader(logo_path)
            img_width, img_height = img_reader.getSize()
            
            # Scale to max width of 2.5 inches while maintaining aspect ratio
            max_width = 2.5 * inch
            scale_factor = max_width / img_width
            logo_width = max_width
            logo_height = img_height * scale_factor
            
            # Center the logo horizontally, position below title
            logo_x = (doc.pagesize[0] - logo_width) / 2.0
            logo_y = doc.pagesize[1] / 2.0 - 20 - logo_height
            
            canvas_obj.drawImage(logo_path, logo_x, logo_y, width=logo_width, height=logo_height)
        except Exception as e:
            # If logo can't be loaded, continue without it
            print(f"Warning: Could not load logo: {e}")
    
    # Generation date - positioned at bottom
    canvas_obj.setFont("Helvetica", 12)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 - 120,
        f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}"
    )
    canvas_obj.restoreState()


def create_header_footer(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """Create header and footer for regular pages."""
    canvas_obj.saveState()
    # Footer with professional styling
    canvas_obj.setFont("Helvetica", 9)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        30,
        f"Page {canvas_obj.getPageNumber()}"
    )
    # Add a subtle line above footer
    canvas_obj.setStrokeColor(colors.HexColor("#E2E8F0"))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(72, 45, doc.pagesize[0] - 72, 45)
    canvas_obj.restoreState()


def generate_pdf(scan_results: Any, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from IAC scan results.

    Supports IAC agent format: list of findings with title, description, impact,
    owasp_top_10, compliance_controls, suggested_fix, location, snippet, cves.
    Also accepts legacy dict with "results" key.

    Args:
        scan_results: List of findings (agent format) or dict with "results" key
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.

    Returns:
        Path to the generated PDF file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"iac_scan_report_{timestamp}.pdf"

    results = _normalize_results(scan_results)
    use_agent_format = len(results) > 0 and _is_agent_format(results[0])

    total_findings = len(results)
    by_impact = {}
    unique_locations = set()
    by_provider: dict = {}
    by_service: dict = {}

    for result in results:
        if use_agent_format:
            impact = (result.get("impact") or "Unknown").strip() or "Unknown"
            by_impact[impact] = by_impact.get(impact, 0) + 1
            loc = result.get("location")
            if isinstance(loc, str) and loc.strip():
                unique_locations.add(loc.strip())
        else:
            severity = result.get("severity", "UNKNOWN")
            by_impact[severity] = by_impact.get(severity, 0) + 1
            loc = result.get("location") or {}
            file_path = loc.get("filename", "") if isinstance(loc, dict) else ""
            if file_path:
                unique_locations.add(file_path)
            provider = result.get("rule_provider", "Unknown")
            by_provider[provider] = by_provider.get(provider, 0) + 1
            service = result.get("rule_service", "Unknown")
            by_service[service] = by_service.get(service, 0) + 1
    
    # Create PDF document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )
    
    # Container for the 'Flowable' objects
    story = []
    styles = getSampleStyleSheet()
    
    # Professional custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor("#1E293B"),  # Professional dark slate
        spaceAfter=16,
        spaceBefore=8,
        alignment=TA_LEFT,
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        leading=26
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor("#0F172A"),  # Very dark blue
        spaceAfter=8,
        spaceBefore=10,
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        leading=16
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=9,
        spaceAfter=8,
        spaceBefore=4,
        wordWrap='CJK',
        leading=12,
        textColor=colors.HexColor("#334155"),  # Dark gray
        fontName='Helvetica'
    )
    
    code_style = ParagraphStyle(
        'CustomCode',
        parent=styles['Code'],
        fontSize=8,
        fontName='Courier',
        spaceAfter=8,
        spaceBefore=4,
        leftIndent=12,
        rightIndent=12,
        backColor=colors.HexColor("#F8FAFC"),  # Light gray background
        borderColor=colors.HexColor("#E2E8F0"),  # Light border
        borderWidth=1,
        borderPadding=6,
        textColor=colors.HexColor("#1E293B"),
        leading=10
    )
    
    # Title page will be created by onFirstPage callback
    # Immediately break to page 2 for executive summary
    story.append(PageBreak())
    
    # Executive Summary (starts on page 2)
    story.append(Paragraph("Executive Summary", title_style))
    story.append(Spacer(1, 0.3 * inch))
    
    summary_data = [
        ["Metric", "Value"],
        ["Total Findings", str(total_findings)],
        ["Unique Locations", str(len(unique_locations))],
    ]
    
    summary_table = Table(summary_data, colWidths=[3.5 * inch, 2.5 * inch], repeatRows=1)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),  # Professional dark header
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),  # Subtle grid
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
    ]))
    story.append(KeepTogether([summary_table]))
    story.append(Spacer(1, 0.4 * inch))
    
    # Findings by Severity / Impact
    impact_label = "Impact" if use_agent_format else "Severity"
    story.append(Paragraph(f"Findings by {impact_label}", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    severity_data = [[impact_label, "Count"]]
    for level in ["Critical", "High", "Medium", "Low", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = by_impact.get(level, 0)
        if count > 0:
            severity_data.append([level, str(count)])
    
    if len(severity_data) > 1:
        severity_table = Table(severity_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),  # Professional dark header
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),  # Subtle grid
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(KeepTogether([severity_table]))
        story.append(Spacer(1, 0.3 * inch))
    
    # Breakdown by Provider (legacy format only)
    if not use_agent_format and by_provider:
        story.append(Paragraph("Findings by Provider", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        provider_data = [["Provider", "Count"]]
        for provider, count in sorted(by_provider.items(), key=lambda x: x[1], reverse=True):
            provider_data.append([provider.upper(), str(count)])
        
        provider_table = Table(provider_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        provider_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(KeepTogether([provider_table]))
        story.append(Spacer(1, 0.3 * inch))
    
    # Breakdown by Service (legacy format only)
    if not use_agent_format and by_service:
        story.append(Paragraph("Findings by Service", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        service_data = [["Service", "Count"]]
        for service, count in sorted(by_service.items(), key=lambda x: x[1], reverse=True):
            service_data.append([service.upper(), str(count)])
        
        service_table = Table(service_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(KeepTogether([service_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    desc_heading_style = ParagraphStyle(
        'DescHeading',
        parent=normal_style,
        fontSize=10,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6,
        spaceBefore=0
    )

    # Detailed Findings
    if total_findings == 0:
        story.append(Paragraph("No security findings detected.", normal_style))
    else:
        for idx, result in enumerate(results, 1):
            if idx > 1:
                story.append(PageBreak())

            if use_agent_format:
                # Agent format: title, impact, location (string), description, snippet, suggested_fix, OWASP, compliance, cves
                title = (result.get("title") or "Finding").strip() or "Finding"
                impact = (result.get("impact") or "Unknown").strip() or "Unknown"
                location_str = (result.get("location") or "").strip() or "—"
                description = (result.get("description") or "No description available").strip() or "No description available"
                snippet = (result.get("snippet") or "").strip()
                suggested_fix = (result.get("suggested_fix") or "").strip()
                owasp = result.get("owasp_top_10") or {}
                compliance = result.get("compliance_controls") or {}
                cves = result.get("cves") or {}

                finding_title = f"Finding #{idx}: {title}"
                story.append(Paragraph(finding_title, heading_style))
                story.append(Spacer(1, 0.2 * inch))

                finding_data = [["Property", "Value"]]
                finding_data.append(["Impact", impact])
                finding_data.append(["Location", Paragraph(_escape_html(location_str[:200] + ("..." if len(location_str) > 200 else "")), normal_style)])
                owasp_str = _format_owasp_compliance_dict(owasp)
                if owasp_str:
                    finding_data.append(["OWASP Top 10", Paragraph(owasp_str[:300] + ("..." if len(owasp_str) > 300 else ""), normal_style)])
                comp_str = _format_owasp_compliance_dict(compliance)
                if comp_str:
                    finding_data.append(["Compliance", Paragraph(comp_str[:300] + ("..." if len(comp_str) > 300 else ""), normal_style)])

                finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), get_severity_color(impact)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, 0), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(KeepTogether([finding_table]))
                story.append(Spacer(1, 0.2 * inch))

                story.append(Paragraph("Description", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                story.append(Paragraph(description[:2000] + ("..." if len(description) > 2000 else ""), normal_style))
                story.append(Spacer(1, 0.2 * inch))

                if snippet:
                    story.append(Paragraph("Code Snippet", desc_heading_style))
                    story.append(Spacer(1, 0.12 * inch))
                    story.append(Paragraph(f'<font face="Courier" size="8">{_escape_html(snippet[:1500])}{"..." if len(snippet) > 1500 else ""}</font>', normal_style))
                    story.append(Spacer(1, 0.2 * inch))

                if suggested_fix:
                    story.append(Paragraph("Suggested Fix", desc_heading_style))
                    story.append(Spacer(1, 0.12 * inch))
                    story.append(Paragraph(suggested_fix[:1500] + ("..." if len(suggested_fix) > 1500 else ""), normal_style))
                    story.append(Spacer(1, 0.2 * inch))

                if cves and isinstance(cves, dict):
                    cve_parts = []
                    for k, v in list(cves.items())[:10]:
                        cve_parts.append(f"{k}: {v}" if v else k)
                    if cve_parts:
                        story.append(Paragraph("CVEs", desc_heading_style))
                        story.append(Spacer(1, 0.12 * inch))
                        story.append(Paragraph(", ".join(cve_parts)[:500], normal_style))
            else:
                # Legacy format
                rule_id = result.get("rule_id", "Unknown")
                long_id = result.get("long_id", "Unknown")
                rule_description = result.get("rule_description", "No description")
                provider = result.get("rule_provider", "Unknown")
                service = result.get("rule_service", "Unknown")
                severity = result.get("severity", "UNKNOWN")
                resource = result.get("resource", "Unknown")
                location = result.get("location", {})
                file_path = get_relative_path(location.get("filename", "Unknown"))
                start_line = location.get("start_line", "?")
                end_line = location.get("end_line", "?")
                description = result.get("description", "No description available")
                impact = result.get("impact", "No impact information")
                resolution = result.get("resolution", "No resolution steps provided")
                links = result.get("links", [])

                finding_title = f"Finding #{idx}: {rule_description}"
                story.append(Paragraph(finding_title, heading_style))
                story.append(Spacer(1, 0.2 * inch))

                finding_data = [["Property", "Value"]]
                finding_data.append(["Rule ID", Paragraph(rule_id, normal_style)])
                finding_data.append(["Long ID", Paragraph(long_id[:80] + ("..." if len(long_id) > 80 else ""), normal_style)])
                finding_data.append(["Severity", severity])
                finding_data.append(["Provider", provider.upper()])
                finding_data.append(["Service", service.upper()])
                finding_data.append(["Resource", resource])
                finding_data.append(["File", Paragraph(file_path[:80] + ("..." if len(file_path) > 80 else ""), normal_style)])
                finding_data.append(["Location", f"Lines {start_line}-{end_line}"])

                finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), get_severity_color(severity)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, 0), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(KeepTogether([finding_table]))
                story.append(PageBreak())

                story.append(Paragraph("Description", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                story.append(Paragraph(description, normal_style))
                story.append(Spacer(1, 0.25 * inch))
                story.append(Paragraph("Impact", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                story.append(Paragraph(impact, normal_style))
                story.append(Spacer(1, 0.25 * inch))
                story.append(Paragraph("Resolution", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                story.append(Paragraph(resolution, normal_style))
                story.append(Spacer(1, 0.25 * inch))
                if links:
                    story.append(Paragraph("References", desc_heading_style))
                    story.append(Spacer(1, 0.12 * inch))
                    for ref in links[:5]:
                        ref_text = ref[:100] + ("..." if len(ref) > 100 else "")
                        story.append(Paragraph(f"• {ref_text}", normal_style))
                        story.append(Spacer(1, 0.05 * inch))
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\iac_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"iac_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

