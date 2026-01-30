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


def get_risk_color(risk: str) -> colors.Color:
    """Get color based on risk level."""
    risk_upper = risk.upper()
    if risk_upper == "HIGH":
        return colors.HexColor("#DC2626")  # Red
    elif risk_upper == "MEDIUM":
        return colors.HexColor("#F97316")  # Orange
    elif risk_upper == "LOW":
        return colors.HexColor("#FBBF24")  # Yellow
    elif risk_upper == "INFORMATIONAL":
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


def generate_pdf(scan_results: List[Dict], output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from DAST scan results.
    
    Args:
        scan_results: List of DAST alert objects
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"dast_scan_report_{timestamp}.pdf"
    
    # Calculate statistics (excluding alerts with "zap" in any field)
    filtered_alerts = []
    by_risk = {}
    by_confidence = {}
    by_plugin = {}
    unique_urls = set()
    
    for alert in scan_results:
        # Check if alert contains "zap" in any field
        alert_name = alert.get("name", alert.get("alert", "Unknown Alert"))
        description = alert.get("description", "No description available")
        solution = alert.get("solution", "No solution provided")
        reference = alert.get("reference", "")
        url = alert.get("url", "Unknown")
        method = alert.get("method", "Unknown")
        param = alert.get("param", "")
        evidence = alert.get("evidence", "")
        other = alert.get("other", "")
        
        # Skip alerts that contain "zap" in any field (case-insensitive)
        alert_text = " ".join([
            str(alert_name), str(description), str(solution), str(reference),
            str(url), str(method), str(param), str(evidence), str(other)
        ]).lower()
        
        if "zap" in alert_text:
            continue  # Skip this alert from statistics and PDF
        
        filtered_alerts.append(alert)
        
        risk = alert.get("risk", "Unknown")
        by_risk[risk] = by_risk.get(risk, 0) + 1
        
        confidence = alert.get("confidence", "Unknown")
        by_confidence[confidence] = by_confidence.get(confidence, 0) + 1
        
        plugin_id = alert.get("pluginId", "Unknown")
        by_plugin[plugin_id] = by_plugin.get(plugin_id, 0) + 1
        
        if url:
            unique_urls.add(url)
    
    total_alerts = len(filtered_alerts)
    
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
        ["Total Alerts", str(total_alerts)],
        ["Unique URLs Tested", str(len(unique_urls))],
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
    
    # Findings by Risk
    story.append(Paragraph("Findings by Risk Level", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    risk_data = [["Risk Level", "Count"]]
    for risk in ["High", "Medium", "Low", "Informational"]:
        count = by_risk.get(risk, 0)
        if count > 0:
            risk_data.append([risk, str(count)])
    
    if len(risk_data) > 1:
        risk_table = Table(risk_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        risk_table.setStyle(TableStyle([
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
        story.append(KeepTogether([risk_table]))
        story.append(Spacer(1, 0.3 * inch))
    
    # Findings by Confidence
    if by_confidence:
        story.append(Paragraph("Findings by Confidence", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        confidence_data = [["Confidence", "Count"]]
        for confidence, count in sorted(by_confidence.items(), key=lambda x: x[1], reverse=True):
            confidence_data.append([confidence, str(count)])
        
        confidence_table = Table(confidence_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        confidence_table.setStyle(TableStyle([
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
        story.append(KeepTogether([confidence_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_alerts == 0:
        story.append(Paragraph("No security alerts detected.", normal_style))
    else:
        # Process each alert - each gets 2 pages
        alert_idx = 0
        for alert in filtered_alerts:
            alert_name = alert.get("name", alert.get("alert", "Unknown Alert"))
            risk = alert.get("risk", "Unknown")
            confidence = alert.get("confidence", "Unknown")
            description = alert.get("description", "No description available")
            solution = alert.get("solution", "No solution provided")
            reference = alert.get("reference", "")
            url = alert.get("url", "Unknown")
            method = alert.get("method", "Unknown")
            param = alert.get("param", "")
            evidence = alert.get("evidence", "")
            cweid = alert.get("cweid", "")
            wascid = alert.get("wascid", "")
            plugin_id = alert.get("pluginId", "")
            alert_ref = alert.get("alertRef", "")
            other = alert.get("other", "")
            
            # Skip alerts that contain "zap" in any field (case-insensitive)
            alert_text = " ".join([
                str(alert_name), str(risk), str(confidence), str(description),
                str(solution), str(reference), str(url), str(method), str(param),
                str(evidence), str(cweid), str(wascid), str(plugin_id),
                str(alert_ref), str(other)
            ]).lower()
            
            if "zap" in alert_text:
                continue  # Skip this alert
            
            alert_idx += 1
            # Page break before each alert (except the first one)
            if alert_idx > 1:
                story.append(PageBreak())
            
            # Finding header
            finding_title = f"Alert #{alert_idx}: {alert_name}"
            story.append(Paragraph(escape_html(finding_title), heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Finding details table
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            finding_data.append(["Risk Level", escape_html(risk)])
            finding_data.append(["Confidence", escape_html(confidence)])
            
            # URL - wrap if too long
            url_para = Paragraph(escape_html(url[:80] + ("..." if len(url) > 80 else "")), normal_style)
            finding_data.append(["URL", url_para])
            
            finding_data.append(["Method", escape_html(method)])
            
            if param:
                param_para = Paragraph(escape_html(param[:60] + ("..." if len(param) > 60 else "")), normal_style)
                finding_data.append(["Parameter", param_para])
            
            if plugin_id:
                finding_data.append(["Plugin ID", escape_html(plugin_id)])
            
            if alert_ref:
                finding_data.append(["Alert Reference", escape_html(alert_ref)])
            
            if cweid and cweid != "-1":
                finding_data.append(["CWE ID", escape_html(cweid)])
            
            if wascid and wascid != "-1":
                finding_data.append(["WASC ID", escape_html(wascid)])
            
            if evidence:
                evidence_para = Paragraph(escape_html(evidence[:80] + ("..." if len(evidence) > 80 else "")), normal_style)
                finding_data.append(["Evidence", evidence_para])
            
            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), get_risk_color(risk)),
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
            
            # Description section (starts on page 2 of this alert)
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
            desc_para = Paragraph(escape_html(description), normal_style)
            story.append(desc_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Solution section
            story.append(Paragraph("Solution", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            solution_para = Paragraph(escape_html(solution), normal_style)
            story.append(solution_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Other Info if available
            if other:
                story.append(Paragraph("Additional Information", desc_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                other_para = Paragraph(escape_html(other[:500] + ("..." if len(other) > 500 else "")), normal_style)
                story.append(other_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # Reference if available
            if reference:
                ref_heading_style = ParagraphStyle(
                    'RefHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Reference", ref_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                # Split reference by newlines if it's multi-line
                ref_lines = reference.split('\n')[:5]  # Limit to 5 lines
                for ref_line in ref_lines:
                    ref_text = ref_line[:100] + ("..." if len(ref_line) > 100 else "")
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

