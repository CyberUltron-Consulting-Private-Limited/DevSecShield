"""
SBOM/SCA Scan Results PDF Generator
Generates a comprehensive PDF report from SBOM/SCA scan results using reportlab.

Supports two input formats:
1. Agent output: a list of flat vulnerability objects (see worker_sbom_agent_results_testing.json)
   each with title, description, impact, owasp_top_10, compliance_controls, suggested_fix, dependencies, cves.
2. Legacy: a dict with "matches" where each match has "vulnerability" and "artifact" (Grype-style).
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
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


def get_relative_path(file_path: str) -> str:
    """Extract path from repo_xxxxxxx onwards."""
    try:
        repo_index = file_path.find("repo_")
        if repo_index != -1:
            return file_path[repo_index:]
        return file_path
    except:
        return file_path


def _escape(s: str) -> str:
    """Escape text for use inside ReportLab Paragraph (HTML-like markup)."""
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# Numeric risk (0-10) derived from impact/severity for average risk score
IMPACT_TO_RISK = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


def _impact_to_risk(impact: str) -> float:
    """Map impact/severity string to a numeric risk score (0-10). Unknown/other = 2.0."""
    if not impact:
        return 2.0
    return IMPACT_TO_RISK.get(impact.strip().lower(), 2.0)


def get_severity_color(severity: str) -> colors.Color:
    """Get color based on severity level."""
    severity_upper = (severity or "").upper()
    if severity_upper == "CRITICAL":
        return colors.HexColor("#DC2626")  # Red
    elif severity_upper == "HIGH":
        return colors.HexColor("#F97316")  # Orange
    elif severity_upper == "MEDIUM":
        return colors.HexColor("#FBBF24")  # Yellow
    elif severity_upper == "LOW":
        return colors.HexColor("#10B981")  # Green
    else:
        return colors.HexColor("#6B7280")  # Gray


def _normalize_sbom_results(scan_results: Union[dict, list]) -> List[Dict[str, Any]]:
    """
    Normalize scan results to a list of vulnerability dicts with a unified shape.
    - Agent format: scan_results is a list of items with title, description, impact,
      owasp_top_10, compliance_controls, suggested_fix, dependencies, cves.
    - Legacy format: scan_results is a dict with "matches"; each match has vulnerability + artifact.
    Returns list of dicts with keys: title, description, impact, suggested_fix, dependencies,
    cves, owasp_top_10, compliance_controls (and optionally package_name, package_version for legacy).
    """
    out: List[Dict[str, Any]] = []
    if isinstance(scan_results, list):
        # Agent output format (worker_sbom_agent_results_testing.json)
        for item in scan_results:
            if not isinstance(item, dict):
                continue
            out.append({
                "title": item.get("title") or "Untitled",
                "description": item.get("description") or "",
                "impact": item.get("impact") or "Unknown",
                "owasp_top_10": item.get("owasp_top_10") or {},
                "compliance_controls": item.get("compliance_controls") or {},
                "suggested_fix": item.get("suggested_fix") or "",
                "dependencies": item.get("dependencies") or [],
                "cves": item.get("cves") or {},
            })
        return out
    # Legacy: dict with "matches"
    matches = scan_results.get("matches", [])
    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vuln_id = vuln.get("id", "Unknown")
        description = vuln.get("description", "No description available")
        severity = vuln.get("severity", "UNKNOWN")
        fix = vuln.get("fix", {})
        fix_state = fix.get("state", "unknown")
        fix_versions = fix.get("versions", [])
        suggested_fix = f"Fix status: {fix_state}"
        if fix_versions:
            suggested_fix += f". Fixed in: {', '.join(fix_versions[:3])}"
        dependencies = []
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        if name:
            dependencies.append(f"{name}@{version}")
        cves = vuln.get("cves", {})
        if not isinstance(cves, dict):
            cves = {k: (v if isinstance(v, str) else str(v)) for k, v in (cves or {}).items()} if cves else {}
        out.append({
            "title": vuln_id,
            "description": description,
            "impact": severity,
            "owasp_top_10": vuln.get("owasp_top_10") or {},
            "compliance_controls": vuln.get("compliance_controls") or {},
            "suggested_fix": suggested_fix,
            "dependencies": dependencies,
            "cves": cves,
        })
    return out


def create_title_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """Create a title page for the PDF."""
    canvas_obj.saveState()
    
    # Title text - positioned at top center
    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))  # Professional dark slate
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        "SBOM/SCA Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Software Bill of Materials & Supply Chain Security Analysis"
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


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from SBOM/SCA scan results.
    Accepts either agent output (list of vulnerability objects) or legacy dict with "matches".

    Args:
        scan_results: List of vulnerability objects (agent format) or dict with "matches" (legacy).
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.

    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sbom_sca_scan_report_{timestamp}.pdf"

    # Normalize to unified list of vulnerability dicts
    vulnerabilities = _normalize_sbom_results(scan_results)

    # Calculate statistics from normalized list
    total_vulnerabilities = len(vulnerabilities)
    by_severity: Dict[str, int] = {}
    unique_packages: set = set()
    fixable_count = 0
    risk_sum = 0.0

    for v in vulnerabilities:
        impact = (v.get("impact") or "Unknown").strip()
        by_severity[impact] = by_severity.get(impact, 0) + 1
        risk_sum += _impact_to_risk(impact)
        for dep in v.get("dependencies") or []:
            if dep:
                unique_packages.add(dep if isinstance(dep, str) else str(dep))
        suggested = (v.get("suggested_fix") or "").lower()
        if "upgrade" in suggested or "fixed" in suggested or "update" in suggested:
            fixable_count += 1

    avg_risk = risk_sum / total_vulnerabilities if total_vulnerabilities > 0 else 0.0
    
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
    
    # Summary statistics table
    summary_data = [
        ["Metric", "Value"],
        ["Total Vulnerabilities", str(total_vulnerabilities)],
        ["Unique Packages Affected", str(len(unique_packages))],
        ["Fixable Vulnerabilities", str(fixable_count)],
        ["Average Risk Score", f"{avg_risk:.4f}" if avg_risk else "N/A"],
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
    
    # Vulnerabilities by Severity
    story.append(Paragraph("Vulnerabilities by Severity", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    severity_data = [["Severity", "Count"]]
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            severity_data.append([severity.upper(), str(count)])
    for severity, count in by_severity.items():
        if severity not in ("Critical", "High", "Medium", "Low") and count > 0:
            severity_data.append([(severity or "Unknown").upper(), str(count)])
    
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

    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings (unified from normalized vulnerabilities list)
    if total_vulnerabilities == 0:
        story.append(Paragraph("No vulnerabilities detected.", normal_style))
    else:
        sub_heading_style = ParagraphStyle(
            'SubHeading',
            parent=normal_style,
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=6,
            spaceBefore=12
        )
        for idx, v in enumerate(vulnerabilities, 1):
            if idx > 1:
                story.append(PageBreak())
            title = v.get("title") or "Untitled"
            description = v.get("description") or "No description available."
            impact = (v.get("impact") or "Unknown").strip()
            suggested_fix = v.get("suggested_fix") or ""
            dependencies = v.get("dependencies") or []
            cves = v.get("cves") or {}
            owasp = v.get("owasp_top_10") or {}
            compliance = v.get("compliance_controls") or {}

            finding_title = f"Vulnerability #{idx}: {title[:60]}{'...' if len(title) > 60 else ''}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))

            finding_data = [["Property", "Value"]]
            finding_data.append(["Title", Paragraph(_escape((title or "")[:200]), normal_style)])
            finding_data.append(["Impact", (impact or "Unknown").upper()])
            if dependencies:
                deps_str = "; ".join((d if isinstance(d, str) else str(d)) for d in dependencies[:10])
                if len(dependencies) > 10:
                    deps_str += f" (+{len(dependencies) - 10} more)"
                finding_data.append(["Dependencies", Paragraph(_escape(deps_str[:300]), normal_style)])
            if cves:
                cve_ids = list(cves.keys())[:5]
                finding_data.append(["CVE IDs", ", ".join(cve_ids)])

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

            story.append(Paragraph("Description", sub_heading_style))
            story.append(Paragraph(_escape(description[:2000]), normal_style))
            story.append(Spacer(1, 0.15 * inch))

            if suggested_fix:
                story.append(Paragraph("Suggested Fix", sub_heading_style))
                story.append(Paragraph(_escape(suggested_fix[:1500]), normal_style))
                story.append(Spacer(1, 0.15 * inch))

            if dependencies:
                story.append(Paragraph("Affected Dependencies", sub_heading_style))
                for d in dependencies[:20]:
                    story.append(Paragraph(f"• {_escape(d if isinstance(d, str) else str(d))}", normal_style))
                if len(dependencies) > 20:
                    story.append(Paragraph(f"... and {len(dependencies) - 20} more", normal_style))
                story.append(Spacer(1, 0.15 * inch))

            if owasp and isinstance(owasp, dict):
                story.append(Paragraph("OWASP Top 10", sub_heading_style))
                for k, val in list(owasp.items())[:10]:
                    story.append(Paragraph(f"<b>{_escape(str(k))}:</b> {_escape(str(val)[:200])}", normal_style))
                story.append(Spacer(1, 0.15 * inch))

            if compliance and isinstance(compliance, dict):
                story.append(Paragraph("Compliance Controls", sub_heading_style))
                for k, val in list(compliance.items())[:10]:
                    story.append(Paragraph(f"<b>{_escape(str(k))}:</b> {_escape(str(val)[:200])}", normal_style))
                story.append(Spacer(1, 0.15 * inch))

            if cves and isinstance(cves, dict):
                story.append(Paragraph("CVE Details", sub_heading_style))
                for cve_id, cve_desc in list(cves.items())[:10]:
                    desc_str = cve_desc if isinstance(cve_desc, str) else str(cve_desc)
                    story.append(Paragraph(f"<b>{_escape(cve_id)}</b>: {_escape(desc_str[:300])}", normal_style))
                if len(cves) > 10:
                    story.append(Paragraph(f"... and {len(cves) - 10} more CVEs", normal_style))

    if isinstance(scan_results, dict):
        from backend.utilities.pdf.rbi_compliance_pdf import append_rbi_compliance_pdf_section

        append_rbi_compliance_pdf_section(
            story, scan_results, heading_style, normal_style, small_style
        )

    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test with agent-format data (list of vulnerability objects)
    test_file_path = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "RabbitMQ", "worker", "worker_sbom_agent_results_testing.json"
    )
    test_file_path = os.path.normpath(test_file_path)
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"sbom_sca_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

