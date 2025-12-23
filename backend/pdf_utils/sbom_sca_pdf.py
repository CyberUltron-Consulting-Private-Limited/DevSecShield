"""
SBOM/SCA Scan Results PDF Generator
Generates a comprehensive PDF report from SBOM/SCA scan results using reportlab.
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


def get_severity_color(severity: str) -> colors.Color:
    """Get color based on severity level."""
    severity_upper = severity.upper()
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


def generate_pdf(scan_results: dict, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from SBOM/SCA scan results.
    
    Args:
        scan_results: Dictionary containing SBOM/SCA scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sbom_sca_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results
    matches = scan_results.get("matches", [])
    
    # Calculate statistics
    total_vulnerabilities = len(matches)
    by_severity = {}
    by_fix_status = {}
    risk_sum = 0.0
    unique_packages = set()
    fixable_count = 0
    
    for match in matches:
        vuln = match.get("vulnerability", {})
        severity = vuln.get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        fix = vuln.get("fix", {})
        fix_state = fix.get("state", "unknown")
        by_fix_status[fix_state] = by_fix_status.get(fix_state, 0) + 1
        if fix_state == "fixed":
            fixable_count += 1
        
        risk = vuln.get("risk", 0.0)
        if isinstance(risk, (int, float)):
            risk_sum += float(risk)
        
        artifact = match.get("artifact", {})
        package_name = artifact.get("name", "")
        package_version = artifact.get("version", "")
        if package_name:
            unique_packages.add(f"{package_name}@{package_version}")
    
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
        ["Average Risk Score", f"{avg_risk:.4f}"],
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
    
    # Breakdown by Fix Status
    if by_fix_status:
        story.append(Paragraph("Vulnerabilities by Fix Status", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        fix_data = [["Fix Status", "Count"]]
        for fix_status, count in sorted(by_fix_status.items(), key=lambda x: x[1], reverse=True):
            fix_data.append([fix_status.replace("-", " ").title(), str(count)])
        
        fix_table = Table(fix_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        fix_table.setStyle(TableStyle([
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
        story.append(KeepTogether([fix_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_vulnerabilities == 0:
        story.append(Paragraph("No vulnerabilities detected.", normal_style))
    else:
        # Process each vulnerability - each gets 2 pages
        for idx, match in enumerate(matches, 1):
            # Page break before each vulnerability (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            vuln = match.get("vulnerability", {})
            vuln_id = vuln.get("id", "Unknown")
            description = vuln.get("description", "No description available")
            severity = vuln.get("severity", "UNKNOWN")
            risk = vuln.get("risk", 0.0)
            cvss_list = vuln.get("cvss", [])
            epss_list = vuln.get("epss", [])
            cwes_list = vuln.get("cwes", [])
            fix = vuln.get("fix", {})
            fix_state = fix.get("state", "unknown")
            fix_versions = fix.get("versions", [])
            
            artifact = match.get("artifact", {})
            package_name = artifact.get("name", "Unknown")
            package_version = artifact.get("version", "Unknown")
            package_type = artifact.get("type", "Unknown")
            package_language = artifact.get("language", "Unknown")
            locations = artifact.get("locations", [])
            purl = artifact.get("purl", "")
            
            # Get first location path
            file_path = ""
            if locations and len(locations) > 0:
                file_path = get_relative_path(locations[0].get("path", ""))
            
            # Get primary CVSS score
            cvss_score = "N/A"
            cvss_vector = "N/A"
            if cvss_list and len(cvss_list) > 0:
                primary_cvss = cvss_list[0]
                metrics = primary_cvss.get("metrics", {})
                cvss_score = str(metrics.get("baseScore", "N/A"))
                cvss_vector = primary_cvss.get("vector", "N/A")
            
            # Get EPSS score
            epss_score = "N/A"
            if epss_list and len(epss_list) > 0:
                epss_score = f"{epss_list[0].get('epss', 0.0):.4f}"
            
            # Get CWE IDs
            cwe_ids = []
            for cwe in cwes_list:
                cwe_id = cwe.get("cwe", "")
                if cwe_id:
                    cwe_ids.append(cwe_id)
            cwe_str = ", ".join(cwe_ids[:5]) if cwe_ids else "N/A"
            
            # Get related vulnerabilities for CVE links
            related_vulns = match.get("relatedVulnerabilities", [])
            cve_ids = []
            urls = []
            for rel_vuln in related_vulns:
                rel_id = rel_vuln.get("id", "")
                if rel_id.startswith("CVE-"):
                    cve_ids.append(rel_id)
                rel_urls = rel_vuln.get("urls", [])
                urls.extend(rel_urls)
            
            # Vulnerability header
            finding_title = f"Vulnerability #{idx}: {vuln_id}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Vulnerability details table - wrap long text
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Vulnerability ID
            vuln_id_para = Paragraph(vuln_id[:80] + ("..." if len(vuln_id) > 80 else ""), normal_style)
            finding_data.append(["Vulnerability ID", vuln_id_para])
            
            # Severity
            finding_data.append(["Severity", severity.upper()])
            
            # Risk Score
            risk_str = f"{float(risk):.4f}" if isinstance(risk, (int, float)) else "N/A"
            finding_data.append(["Risk Score", risk_str])
            
            # CVSS Score
            finding_data.append(["CVSS Score", cvss_score])
            
            # EPSS Score
            finding_data.append(["EPSS Score", epss_score])
            
            # Fix Status
            finding_data.append(["Fix Status", fix_state.replace("-", " ").title()])
            
            # Package Name
            finding_data.append(["Package", f"{package_name}@{package_version}"])
            
            # Package Type/Language
            finding_data.append(["Type/Language", f"{package_type}/{package_language}"])
            
            # File Location
            if file_path:
                file_path_para = Paragraph(file_path[:80] + ("..." if len(file_path) > 80 else ""), normal_style)
                finding_data.append(["File Location", file_path_para])
            
            # CWE IDs
            if cwe_str != "N/A":
                cwe_para = Paragraph(cwe_str[:100] + ("..." if len(cwe_str) > 100 else ""), normal_style)
                finding_data.append(["CWE IDs", cwe_para])
            
            # CVE IDs
            if cve_ids:
                cve_str = ", ".join(cve_ids[:5])
                cve_para = Paragraph(cve_str[:100] + ("..." if len(cve_str) > 100 else ""), normal_style)
                finding_data.append(["CVE IDs", cve_para])
            
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
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),  # Subtle grid
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]))
            story.append(KeepTogether([finding_table]))
            
            # Page break after table - description and details go on next page
            story.append(PageBreak())
            
            # Description section (starts on page 2 of this vulnerability)
            desc_heading_style = ParagraphStyle(
                'DescHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Description", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            desc_para = Paragraph(description, normal_style)
            story.append(desc_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # CVSS Details
            if cvss_list:
                cvss_heading_style = ParagraphStyle(
                    'CVSSHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("CVSS Details", cvss_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                for cvss in cvss_list[:2]:  # Limit to 2 CVSS entries
                    cvss_type = cvss.get("type", "Unknown")
                    cvss_version = cvss.get("version", "Unknown")
                    metrics = cvss.get("metrics", {})
                    base_score = metrics.get("baseScore", "N/A")
                    vector = cvss.get("vector", "N/A")
                    cvss_info = f"<b>Type:</b> {cvss_type} | <b>Version:</b> {cvss_version} | <b>Base Score:</b> {base_score}<br/>"
                    cvss_info += f"<b>Vector:</b> {vector[:100]}{'...' if len(vector) > 100 else ''}"
                    cvss_para = Paragraph(cvss_info, normal_style)
                    story.append(cvss_para)
                    story.append(Spacer(1, 0.1 * inch))
                story.append(Spacer(1, 0.15 * inch))
            
            # EPSS Details
            if epss_list:
                epss_heading_style = ParagraphStyle(
                    'EPSSHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("EPSS Details", epss_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                for epss in epss_list[:2]:  # Limit to 2 EPSS entries
                    epss_score = epss.get("epss", 0.0)
                    percentile = epss.get("percentile", 0.0)
                    date = epss.get("date", "N/A")
                    epss_info = f"<b>EPSS:</b> {epss_score:.4f} | <b>Percentile:</b> {percentile:.4f} | <b>Date:</b> {date}"
                    epss_para = Paragraph(epss_info, normal_style)
                    story.append(epss_para)
                    story.append(Spacer(1, 0.1 * inch))
                story.append(Spacer(1, 0.15 * inch))
            
            # Fix Information
            if fix_state != "unknown":
                fix_heading_style = ParagraphStyle(
                    'FixHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Fix Information", fix_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                fix_info = f"<b>Status:</b> {fix_state.replace('-', ' ').title()}<br/>"
                if fix_versions:
                    fix_info += f"<b>Fixed Versions:</b> {', '.join(fix_versions[:5])}"
                else:
                    fix_info += "No fixed versions available."
                fix_para = Paragraph(fix_info, normal_style)
                story.append(fix_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # Package Details
            package_heading_style = ParagraphStyle(
                'PackageHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Package Details", package_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            package_info = f"<b>Name:</b> {package_name}<br/>"
            package_info += f"<b>Version:</b> {package_version}<br/>"
            package_info += f"<b>Type:</b> {package_type}<br/>"
            package_info += f"<b>Language:</b> {package_language}<br/>"
            if purl:
                package_info += f"<b>PURL:</b> {purl[:100]}{'...' if len(purl) > 100 else ''}"
            package_para = Paragraph(package_info, normal_style)
            story.append(package_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # References/URLs
            if urls:
                ref_heading_style = ParagraphStyle(
                    'RefHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("References", ref_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                for ref in urls[:5]:  # Limit to 5 references
                    # Wrap long URLs
                    ref_text = ref[:100] + ("..." if len(ref) > 100 else "")
                    ref_para = Paragraph(f"• {ref_text}", normal_style)
                    story.append(ref_para)
                    story.append(Spacer(1, 0.05 * inch))
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\sbom_results_testing.json"
    
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

