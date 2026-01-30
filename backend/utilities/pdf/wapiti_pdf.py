"""
DAST Scan Results PDF Generator
Generates a comprehensive PDF report from DAST scan results using reportlab.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from xml.sax.saxutils import escape as xml_escape
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


def escape_html(text: str) -> str:
    """Escape HTML entities in text to prevent parsing errors in Paragraph."""
    if not isinstance(text, str):
        text = str(text)
    # Escape HTML entities
    text = xml_escape(text)
    # Replace newlines with <br/> for proper rendering
    text = text.replace('\n', '<br/>')
    return text


def get_level_color(level: int) -> colors.Color:
    """Get color based on vulnerability level."""
    if level >= 4:
        return colors.HexColor("#DC2626")  # Red - Critical/High
    elif level >= 3:
        return colors.HexColor("#F97316")  # Orange - Medium-High
    elif level >= 2:
        return colors.HexColor("#FBBF24")  # Yellow - Medium
    elif level >= 1:
        return colors.HexColor("#10B981")  # Green - Low
    else:
        return colors.HexColor("#6B7280")  # Gray - Info


def create_title_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """Create a title page for the PDF."""
    canvas_obj.saveState()
    
    # Title text - positioned at top center
    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))  # Professional dark slate
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        "DAST Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Dynamic Application Security Testing - Security Analysis"
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
    Generate a PDF report from DAST scan results.
    
    Args:
        scan_results: Dictionary containing DAST scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"dast_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results
    classifications = scan_results.get("classifications", {})
    vulnerabilities = scan_results.get("vulnerabilities", {})
    anomalies = scan_results.get("anomalies", {})
    additionals = scan_results.get("additionals", {})
    infos = scan_results.get("infos", {})
    
    # Collect all findings
    all_findings = []
    by_type = {}
    by_level = {}
    unique_paths = set()
    
    # Process vulnerabilities
    for vuln_type, vuln_list in vulnerabilities.items():
        if vuln_list:
            by_type[vuln_type] = len(vuln_list)
            for vuln in vuln_list:
                level = vuln.get("level", 0)
                by_level[level] = by_level.get(level, 0) + 1
                path = vuln.get("path", "")
                if path:
                    unique_paths.add(path)
                all_findings.append(("vulnerability", vuln_type, vuln))
    
    # Process anomalies
    for anomaly_type, anomaly_list in anomalies.items():
        if anomaly_list:
            by_type[anomaly_type] = by_type.get(anomaly_type, 0) + len(anomaly_list)
            for anomaly in anomaly_list:
                level = anomaly.get("level", 0)
                by_level[level] = by_level.get(level, 0) + 1
                path = anomaly.get("path", "")
                if path:
                    unique_paths.add(path)
                all_findings.append(("anomaly", anomaly_type, anomaly))
    
    # Process additionals
    for additional_type, additional_list in additionals.items():
        if additional_list:
            by_type[additional_type] = by_type.get(additional_type, 0) + len(additional_list)
            for additional in additional_list:
                level = additional.get("level", 0)
                by_level[level] = by_level.get(level, 0) + 1
                path = additional.get("path", "")
                if path:
                    unique_paths.add(path)
                all_findings.append(("additional", additional_type, additional))
    
    total_findings = len(all_findings)
    target = infos.get("target", "Unknown")
    date = infos.get("date", "Unknown")
    version = infos.get("version", "Unknown")
    crawled_pages = infos.get("crawled_pages_nbr", 0)
    
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
        ["Total Findings", str(total_findings)],
        ["Unique Paths Tested", str(len(unique_paths))],
        ["Pages Crawled", str(crawled_pages)],
        ["Target", target[:60] + ("..." if len(target) > 60 else "")],
        ["Scan Date", date],
        ["Scanner Version", version],
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
    
    # Findings by Type
    if by_type:
        story.append(Paragraph("Findings by Type", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        type_data = [["Finding Type", "Count"]]
        for finding_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            type_data.append([finding_type, str(count)])
        
        type_table = Table(type_data, colWidths=[4.0 * inch, 2.0 * inch], repeatRows=1)
        type_table.setStyle(TableStyle([
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
        story.append(KeepTogether([type_table]))
        story.append(Spacer(1, 0.3 * inch))
    
    # Findings by Level
    if by_level:
        story.append(Paragraph("Findings by Severity Level", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        level_data = [["Severity Level", "Count"]]
        for level in sorted(by_level.keys(), reverse=True):
            count = by_level[level]
            level_name = f"Level {level}"
            if level >= 4:
                level_name += " (Critical/High)"
            elif level >= 3:
                level_name += " (Medium-High)"
            elif level >= 2:
                level_name += " (Medium)"
            elif level >= 1:
                level_name += " (Low)"
            else:
                level_name += " (Info)"
            level_data.append([level_name, str(count)])
        
        level_table = Table(level_data, colWidths=[3.5 * inch, 1.5 * inch], repeatRows=1)
        level_table.setStyle(TableStyle([
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
        story.append(KeepTogether([level_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_findings == 0:
        story.append(Paragraph("No security findings detected.", normal_style))
    else:
        # Process each finding - each gets 2 pages
        for idx, (finding_category, finding_type, finding) in enumerate(all_findings, 1):
            # Page break before each finding (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            method = finding.get("method", "Unknown")
            path = finding.get("path", "Unknown")
            info = finding.get("info", "No description available")
            level = finding.get("level", 0)
            parameter = finding.get("parameter")
            referer = finding.get("referer", "")
            module = finding.get("module", "")
            http_request = finding.get("http_request", "")
            curl_command = finding.get("curl_command", "")
            wstg = finding.get("wstg", [])
            
            # Get classification info if available
            classification_info = classifications.get(finding_type, {})
            desc = classification_info.get("desc", info)
            sol = classification_info.get("sol", "No solution provided")
            ref = classification_info.get("ref", {})
            
            # Finding header
            finding_title = f"Finding #{idx}: {finding_type}"
            if finding_category != "vulnerability":
                finding_title += f" ({finding_category.upper()})"
            story.append(Paragraph(escape_html(finding_title), heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Finding details table
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            finding_data.append(["Category", escape_html(finding_category.upper())])
            finding_data.append(["Type", escape_html(finding_type)])
            finding_data.append(["Severity Level", str(level)])
            
            # Path - wrap if too long
            path_para = Paragraph(escape_html(path[:80] + ("..." if len(path) > 80 else "")), normal_style)
            finding_data.append(["Path", path_para])
            
            finding_data.append(["Method", escape_html(method)])
            
            if parameter:
                param_para = Paragraph(escape_html(str(parameter)[:60] + ("..." if len(str(parameter)) > 60 else "")), normal_style)
                finding_data.append(["Parameter", param_para])
            
            if module:
                finding_data.append(["Module", escape_html(module)])
            
            if referer:
                referer_para = Paragraph(escape_html(referer[:60] + ("..." if len(referer) > 60 else "")), normal_style)
                finding_data.append(["Referer", referer_para])
            
            if wstg:
                wstg_str = ", ".join(wstg[:3])  # Limit to first 3
                if len(wstg) > 3:
                    wstg_str += f" (+{len(wstg) - 3} more)"
                wstg_para = Paragraph(escape_html(wstg_str), normal_style)
                finding_data.append(["WSTG", wstg_para])
            
            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), get_level_color(level)),
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
            
            # Description section (starts on page 2 of this finding)
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
            desc_para = Paragraph(escape_html(desc), normal_style)
            story.append(desc_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Solution section
            story.append(Paragraph("Solution", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            solution_para = Paragraph(escape_html(sol), normal_style)
            story.append(solution_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # HTTP Request if available
            if http_request:
                story.append(Paragraph("HTTP Request", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                # Truncate and format HTTP request
                http_text = http_request.strip()
                if len(http_text) > 500:
                    http_text = http_text[:500] + "..."
                http_lines = http_text.split('\n')[:10]  # Limit to 10 lines
                http_text = '\n'.join(http_lines)
                http_para = Preformatted(
                    http_text,
                    code_style,
                    maxLineLength=70
                )
                story.append(http_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # cURL Command if available
            if curl_command:
                story.append(Paragraph("cURL Command", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                curl_para = Preformatted(
                    curl_command[:200] + ("..." if len(curl_command) > 200 else ""),
                    code_style,
                    maxLineLength=70
                )
                story.append(curl_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # References if available
            if ref:
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
                ref_items = list(ref.items())[:5]  # Limit to 5 references
                for ref_name, ref_url in ref_items:
                    ref_text = f"{ref_name}: {ref_url}"[:100] + ("..." if len(f"{ref_name}: {ref_url}") > 100 else "")
                    ref_para = Paragraph(escape_html(f"• {ref_text}"), normal_style)
                    story.append(ref_para)
                    story.append(Spacer(1, 0.05 * inch))
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\backend\\api_routes\\dast_mock_results.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"dast_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

