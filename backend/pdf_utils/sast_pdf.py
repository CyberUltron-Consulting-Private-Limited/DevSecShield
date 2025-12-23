"""
SAST Scan Results PDF Generator
Generates a comprehensive PDF report from SAST scan results using reportlab.
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
    if severity_upper == "ERROR":
        return colors.HexColor("#DC2626")  # Red
    elif severity_upper == "WARNING":
        return colors.HexColor("#F97316")  # Orange
    elif severity_upper == "INFO":
        return colors.HexColor("#3B82F6")  # Blue
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
        "SAST Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Static Application Security Testing Analysis"
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
    Generate a PDF report from SAST scan results.
    
    Args:
        scan_results: Dictionary containing SAST scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sast_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results
    version = scan_results.get("version", "Unknown")
    results = scan_results.get("results", [])
    errors = scan_results.get("errors", [])
    scanned_paths = scan_results.get("paths", {}).get("scanned", [])
    skipped_paths = scan_results.get("paths", {}).get("skipped", [])
    engine_requested = scan_results.get("engine_requested", "Unknown")
    
    # Calculate statistics
    total_findings = len(results)
    by_severity = {}
    by_check = {}
    unique_files = set()
    
    for result in results:
        severity = result.get("severity") or result.get("extra", {}).get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        check_id = result.get("check_id", "Unknown")
        check_name = check_id.split('.')[-1] if '.' in check_id else check_id
        by_check[check_name] = by_check.get(check_name, 0) + 1
        
        file_path = result.get("path", "")
        if file_path:
            unique_files.add(get_relative_path(file_path))
    
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
    
    # Title page will be created by onFirstPage callback when building
    # Immediately break to page 2 for executive summary
    story.append(PageBreak())
    
    # Executive Summary (starts on page 2)
    story.append(Paragraph("Executive Summary", title_style))
    story.append(Spacer(1, 0.3 * inch))
    
    # Summary statistics table
    summary_data = [
        ["Metric", "Value"],
        ["Total Findings", str(total_findings)],
        ["Unique Files with Issues", str(len(unique_files))],
        ["Files Scanned", str(len(scanned_paths))],
        ["Files Skipped", str(len(skipped_paths))],
        ["Scan Engine", engine_requested],
        ["Semgrep Version", version],
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
    
    # Findings by Severity
    story.append(Paragraph("Findings by Severity", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    severity_data = [["Severity", "Count"]]
    for severity in ["ERROR", "WARNING", "INFO"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            severity_data.append([severity, str(count)])
    
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
    
    # Page break after executive summary
    story.append(PageBreak())
    
    if total_findings == 0:
        story.append(Paragraph("No security findings detected.", normal_style))
    else:
        # Process each finding - each gets its own page
        for idx, result in enumerate(results, 1):
            # Page break before each finding (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            check_id = result.get("check_id", "Unknown")
            check_name = check_id.split('.')[-1] if '.' in check_id else check_id
            file_path = get_relative_path(result.get("path", "Unknown"))
            start = result.get("start", {})
            line_num = start.get("line", "?")
            col_num = start.get("col", "?")
            
            extra = result.get("extra", {})
            message = extra.get("message", "No description available")
            metadata = extra.get("metadata", {})
            display_name = metadata.get("display-name", check_name)
            snippet = result.get("snippet") or extra.get("lines", "")
            severity_level = result.get("severity") or extra.get("severity", "UNKNOWN")
            
            # Finding header
            finding_title = f"Finding #{idx}: {display_name}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
                
            # Finding details table - wrap long text
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Check ID - wrap if too long
            check_id_para = Paragraph(check_id[:100] + ("..." if len(check_id) > 100 else ""), normal_style)
            finding_data.append(["Check ID", check_id_para])
            
            finding_data.append(["Severity", severity_level])
            
            # File path - wrap if too long
            file_path_para = Paragraph(file_path[:80] + ("..." if len(file_path) > 80 else ""), normal_style)
            finding_data.append(["File", file_path_para])
            
            finding_data.append(["Location", f"Line {line_num}, Column {col_num}"])
            
            # Add metadata if available
            if metadata.get("likelihood"):
                finding_data.append(["Likelihood", metadata["likelihood"]])
            if metadata.get("impact"):
                finding_data.append(["Impact", metadata["impact"]])
            if metadata.get("confidence"):
                finding_data.append(["Confidence", metadata["confidence"]])
            
            # Add CWE if available - wrap text
            cwe_list = metadata.get("cwe", [])
            if cwe_list:
                cwe_str = ", ".join(cwe_list[:2])  # Limit to first 2 for better display
                if len(cwe_list) > 2:
                    cwe_str += f" (+{len(cwe_list) - 2} more)"
                cwe_para = Paragraph(cwe_str, normal_style)
                finding_data.append(["CWE", cwe_para])
            
            # Add OWASP if available - wrap text
            owasp_list = metadata.get("owasp", [])
            if owasp_list:
                owasp_str = ", ".join(owasp_list)
                owasp_para = Paragraph(owasp_str, normal_style)
                finding_data.append(["OWASP", owasp_para])
            
            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), get_severity_color(severity_level)),
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
            
            # Message/Description - wrap text properly (starts on page 2 of this finding)
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
            # Split long messages into paragraphs if needed
            message_para = Paragraph(message, normal_style)
            story.append(message_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Code snippet if available
            if snippet:
                code_heading_style = ParagraphStyle(
                    'CodeHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Code Snippet", code_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                # Truncate and wrap code snippet
                code_text = snippet.strip()
                if len(code_text) > 500:
                    code_text = code_text[:500] + "..."
                # Split into lines and limit
                code_lines = code_text.split('\n')[:10]  # Limit to 10 lines
                code_text = '\n'.join(code_lines)
                code_para = Preformatted(
                    code_text,
                    code_style,
                    maxLineLength=70
                )
                story.append(code_para)
                story.append(Spacer(1, 0.2 * inch))
            
            # References if available
            references = metadata.get("references", [])
            if references:
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
                for ref in references[:5]:  # Limit to 5 references
                    # Wrap long URLs
                    ref_text = ref[:100] + ("..." if len(ref) > 100 else "")
                    ref_para = Paragraph(f"• {ref_text}", normal_style)
                    story.append(ref_para)
                    story.append(Spacer(1, 0.05 * inch))
            
            # Page break after this finding's description page
            # Next finding will start on a new page (handled by the if idx > 1 check at the start)
    
    # Scan Errors Section
    if errors:
        story.append(PageBreak())
        story.append(Paragraph("Scan Errors", title_style))
        story.append(Spacer(1, 0.3 * inch))
        
        error_data = [["Type", "Message", "File"]]
        for error in errors:
            error_type = error.get("type", "Unknown")
            error_message = error.get("message", "No message")
            error_path = get_relative_path(error.get("path", "Unknown"))
            # Wrap long messages
            error_msg_para = Paragraph(error_message[:150] + ("..." if len(error_message) > 150 else ""), normal_style)
            error_path_para = Paragraph(error_path[:60] + ("..." if len(error_path) > 60 else ""), normal_style)
            error_data.append([error_type, error_msg_para, error_path_para])
        
        error_table = Table(error_data, colWidths=[1.5 * inch, 3.5 * inch, 1.0 * inch], repeatRows=1)
        error_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#DC2626")),  # Red for errors
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
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
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#FEF2F2")]),
        ]))
        story.append(error_table)
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\sast_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"sast_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()
