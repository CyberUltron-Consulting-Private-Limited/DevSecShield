"""
MCP Scan Results PDF Generator
Generates a comprehensive PDF report from MCP scan results using reportlab.
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
        "MCP Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Model Context Protocol Security Analysis"
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
    Generate a PDF report from MCP scan results.
    
    Args:
        scan_results: Dictionary containing MCP scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"mcp_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results
    final_issues = scan_results.get("final_issues", [])
    error_messages = scan_results.get("error_messages", [])
    
    # Calculate statistics
    total_issues = len(final_issues)
    by_severity = {}
    by_issue_code = {}
    by_issue_type = {}
    by_server = {}
    unique_tools = set()
    
    for issue in final_issues:
        severity = issue.get("issue_severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        
        issue_code = issue.get("issue_code", "Unknown")
        by_issue_code[issue_code] = by_issue_code.get(issue_code, 0) + 1
        
        issue_type = issue.get("issue_type", "unknown")
        by_issue_type[issue_type] = by_issue_type.get(issue_type, 0) + 1
        
        server = issue.get("server", "Unknown")
        by_server[server] = by_server.get(server, 0) + 1
        
        tool = issue.get("tool")
        if tool and isinstance(tool, dict):
            tool_name = tool.get("name", "")
            if tool_name:
                unique_tools.add(tool_name)
    
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
        ["Total Issues Found", str(total_issues)],
        ["Unique Tools Affected", str(len(unique_tools))],
        ["Unique Servers Scanned", str(len(by_server))],
        ["Scan Errors", str(len(error_messages))],
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
    
    # Issues by Severity
    story.append(Paragraph("Issues by Severity", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    severity_data = [["Severity", "Count"]]
    for severity in ["critical", "high", "medium", "low", "unknown"]:
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
    
    # Breakdown by Issue Code
    if by_issue_code:
        story.append(Paragraph("Issues by Issue Code", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        issue_code_data = [["Issue Code", "Count"]]
        for issue_code, count in sorted(by_issue_code.items(), key=lambda x: x[1], reverse=True):
            issue_code_data.append([issue_code, str(count)])
        
        issue_code_table = Table(issue_code_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        issue_code_table.setStyle(TableStyle([
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
        story.append(KeepTogether([issue_code_table]))
    
    # Breakdown by Server - on separate page
    if by_server:
        story.append(PageBreak())
        story.append(Paragraph("Issues by Server", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        server_data = [["Server", "Count"]]
        for server, count in sorted(by_server.items(), key=lambda x: x[1], reverse=True):
            server_data.append([server, str(count)])
        
        server_table = Table(server_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        server_table.setStyle(TableStyle([
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
        story.append(KeepTogether([server_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_issues == 0:
        story.append(Paragraph("No security issues detected.", normal_style))
    else:
        # Process each issue - each gets 2 pages
        for idx, issue in enumerate(final_issues, 1):
            # Page break before each issue (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            issue_code = issue.get("issue_code", "Unknown")
            issue_message = issue.get("issue_message", "No message available")
            issue_type = issue.get("issue_type", "unknown")
            server = issue.get("server", "Unknown")
            tool = issue.get("tool")
            severity = issue.get("issue_severity", "unknown")
            
            # Extract tool information
            tool_name = "N/A"
            tool_description = "N/A"
            input_schema = None
            if tool and isinstance(tool, dict):
                tool_name = tool.get("name", "N/A")
                tool_description = tool.get("description", "N/A")
                input_schema = tool.get("input_schema")
            
            # Issue header
            finding_title = f"Issue #{idx}: {issue_code}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Issue details table - wrap long text
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Issue Code
            finding_data.append(["Issue Code", issue_code])
            
            # Severity
            finding_data.append(["Severity", severity.upper()])
            
            # Issue Type
            issue_type_display = issue_type.replace("_", " ").title() if issue_type != "unknown" else "Unknown"
            finding_data.append(["Issue Type", issue_type_display])
            
            # Server
            finding_data.append(["Server", server])
            
            # Tool Name
            finding_data.append(["Tool Name", tool_name])
            
            # Issue Message - wrap if too long
            message_para = Paragraph(issue_message[:150] + ("..." if len(issue_message) > 150 else ""), normal_style)
            finding_data.append(["Issue Message", message_para])
            
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
            
            # Full Issue Message section (starts on page 2 of this issue)
            message_heading_style = ParagraphStyle(
                'MessageHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Full Issue Message", message_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            full_message_para = Paragraph(issue_message, normal_style)
            story.append(full_message_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Tool Details if available
            if tool and isinstance(tool, dict) and tool_name != "N/A":
                tool_heading_style = ParagraphStyle(
                    'ToolHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Tool Details", tool_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                
                tool_info = f"<b>Tool Name:</b> {tool_name}<br/>"
                tool_info += f"<b>Description:</b> {tool_description}<br/>"
                
                if input_schema:
                    schema_type = input_schema.get("type", "N/A")
                    tool_info += f"<b>Input Schema Type:</b> {schema_type}<br/>"
                    properties = input_schema.get("properties", {})
                    if properties:
                        tool_info += f"<b>Properties:</b> {len(properties)} property/properties defined"
                
                tool_para = Paragraph(tool_info, normal_style)
                story.append(tool_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # Issue Type Details
            type_heading_style = ParagraphStyle(
                'TypeHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Issue Type Information", type_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            
            type_info = f"<b>Issue Type:</b> {issue_type_display}<br/>"
            type_info += f"<b>Issue Code:</b> {issue_code}<br/>"
            type_info += f"<b>Server:</b> {server}<br/>"
            type_info += f"<b>Severity:</b> {severity.upper()}"
            
            type_para = Paragraph(type_info, normal_style)
            story.append(type_para)
    
    # Scan Errors section (if any)
    if error_messages:
        story.append(PageBreak())
        story.append(Paragraph("Scan Errors", title_style))
        story.append(Spacer(1, 0.3 * inch))
        
        error_data = [["Error Message"]]
        for error_msg in error_messages:
            error_para = Paragraph(error_msg[:200] + ("..." if len(error_msg) > 200 else ""), normal_style)
            error_data.append([error_para])
        
        if len(error_data) > 1:
            error_table = Table(error_data, colWidths=[6.0 * inch], repeatRows=1)
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
            story.append(KeepTogether([error_table]))
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\mcp_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"mcp_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

