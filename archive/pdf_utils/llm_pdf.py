"""
LLM Scan Results PDF Generator
Generates a comprehensive PDF report from LLM scan results using reportlab.
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


def get_probe_display_name(probe_id: str, probe_display_names: Dict[str, str]) -> str:
    """Get user-friendly display name for a probe ID."""
    return probe_display_names.get(probe_id, probe_id)


def get_risk_color(risk: str) -> colors.Color:
    """Get color based on risk level."""
    risk_upper = risk.upper()
    if risk_upper == "HIGH" or risk_upper == "CRITICAL":
        return colors.HexColor("#DC2626")  # Red
    elif risk_upper == "MEDIUM":
        return colors.HexColor("#F97316")  # Orange
    elif risk_upper == "LOW":
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
        "LLM Security Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Large Language Model Security & Safety Analysis"
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
    Generate a PDF report from LLM scan results.
    
    Args:
        scan_results: Dictionary containing LLM scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"llm_scan_report_{timestamp}.pdf"
    
    # Load probe display names mapping
    probe_display_names = {}
    probe_names_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "probe_display_names.json")
    try:
        if os.path.exists(probe_names_path):
            with open(probe_names_path, 'r', encoding='utf-8') as f:
                probe_display_names = json.load(f)
    except Exception as e:
        print(f"Warning: Could not load probe display names: {e}")
    
    # Extract data from scan results
    status = scan_results.get("status", "unknown")
    model_name = scan_results.get("model_name", "Unknown")
    total_tests = scan_results.get("total_tests", 0)
    total_hits = scan_results.get("total_hits", 0)
    hit_rate_percent = scan_results.get("hit_rate_percent", 0.0)
    risk_level = scan_results.get("risk_level", "unknown")
    probes_used = scan_results.get("probes_used", [])
    probes_summary = scan_results.get("probes_summary", {})
    
    # Calculate statistics
    total_probes = len(probes_used)
    probes_with_hits = 0
    probes_with_no_hits = 0
    
    for key, probe_data in probes_summary.items():
        hit_rate = probe_data.get("hit_rate", 0.0)
        if hit_rate > 0.0:
            probes_with_hits += 1
        else:
            probes_with_no_hits += 1
    
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
        ["Model Name", model_name],
        ["Scan Status", status.title()],
        ["Total Tests", str(total_tests)],
        ["Total Hits", str(total_hits)],
        ["Hit Rate", f"{hit_rate_percent:.2f}%"],
        ["Risk Level", risk_level.upper()],
        ["Total Probes Used", str(total_probes)],
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
    
    # Probes Summary
    if probes_summary:
        story.append(Paragraph("Probes Summary", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        probe_summary_data = [["Probe", "Passed", "Total", "Hit Rate"]]
        for key, probe_data in probes_summary.items():
            probe_id = probe_data.get("probe", "Unknown")
            display_name = get_probe_display_name(probe_id, probe_display_names)
            passed = probe_data.get("passed", 0)
            total = probe_data.get("total", 0)
            hit_rate = probe_data.get("hit_rate", 0.0)
            probe_summary_data.append([
                display_name[:50] + ("..." if len(display_name) > 50 else ""),
                str(passed),
                str(total),
                f"{hit_rate:.2f}%"
            ])
        
        if len(probe_summary_data) > 1:
            probe_summary_table = Table(probe_summary_data, colWidths=[3.0 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch], repeatRows=1)
            probe_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),  # Professional dark header
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
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
            story.append(KeepTogether([probe_summary_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_probes == 0:
        story.append(Paragraph("No probes were executed.", normal_style))
    else:
        # Process each probe - each gets 2 pages
        probe_list = list(probes_summary.items())
        for idx, (key, probe_data) in enumerate(probe_list, 1):
            # Page break before each probe (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            probe_id = probe_data.get("probe", "Unknown")
            display_name = get_probe_display_name(probe_id, probe_display_names)
            passed = probe_data.get("passed", 0)
            total = probe_data.get("total", 0)
            hit_rate = probe_data.get("hit_rate", 0.0)
            failed = total - passed
            
            # Determine status based on hit rate
            if hit_rate > 0.0:
                status_text = "FAILED"
                status_color = get_risk_color("HIGH")
            else:
                status_text = "PASSED"
                status_color = get_risk_color("LOW")
            
            # Probe header
            finding_title = f"Probe #{idx}: {display_name}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Probe details table
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Probe Name (display name)
            probe_name_para = Paragraph(display_name[:80] + ("..." if len(display_name) > 80 else ""), normal_style)
            finding_data.append(["Probe Name", probe_name_para])
            
            # Probe ID (technical)
            probe_id_para = Paragraph(probe_id[:80] + ("..." if len(probe_id) > 80 else ""), normal_style)
            finding_data.append(["Probe ID", probe_id_para])
            
            # Status
            finding_data.append(["Status", status_text])
            
            # Test Results
            finding_data.append(["Tests Passed", str(passed)])
            finding_data.append(["Tests Failed", str(failed)])
            finding_data.append(["Total Tests", str(total)])
            
            # Hit Rate
            finding_data.append(["Hit Rate", f"{hit_rate:.2f}%"])
            
            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), status_color),
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
            
            # Page break after table - details go on next page
            story.append(PageBreak())
            
            # Detailed Results section (starts on page 2 of this probe)
            results_heading_style = ParagraphStyle(
                'ResultsHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Test Results Summary", results_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            
            results_info = f"<b>Probe:</b> {display_name}<br/>"
            results_info += f"<b>Technical ID:</b> {probe_id}<br/><br/>"
            results_info += f"<b>Total Tests Executed:</b> {total}<br/>"
            results_info += f"<b>Tests Passed:</b> {passed}<br/>"
            results_info += f"<b>Tests Failed:</b> {failed}<br/>"
            results_info += f"<b>Hit Rate:</b> {hit_rate:.2f}%<br/><br/>"
            
            if hit_rate > 0.0:
                results_info += f"<b>Status:</b> <font color='#DC2626'>FAILED</font><br/>"
                results_info += "This probe detected security issues or vulnerabilities in the LLM model."
            else:
                results_info += f"<b>Status:</b> <font color='#10B981'>PASSED</font><br/>"
                results_info += "This probe did not detect any security issues or vulnerabilities in the LLM model."
            
            results_para = Paragraph(results_info, normal_style)
            story.append(results_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Interpretation
            interpretation_heading_style = ParagraphStyle(
                'InterpretationHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Interpretation", interpretation_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            
            if hit_rate > 0.0:
                interpretation_text = (
                    "A hit rate greater than 0% indicates that the LLM model exhibited "
                    "vulnerable behavior when tested with this security probe. This suggests "
                    "that the model may be susceptible to the specific attack or vulnerability "
                    "that this probe is designed to detect. Immediate review and remediation "
                    "are recommended."
                )
            else:
                interpretation_text = (
                    "A hit rate of 0% indicates that the LLM model did not exhibit "
                    "vulnerable behavior when tested with this security probe. This suggests "
                    "that the model is resistant to the specific attack or vulnerability "
                    "that this probe is designed to detect. However, this does not guarantee "
                    "complete security, and regular testing with multiple probes is recommended."
                )
            
            interpretation_para = Paragraph(interpretation_text, normal_style)
            story.append(interpretation_para)
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\llm_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"llm_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

