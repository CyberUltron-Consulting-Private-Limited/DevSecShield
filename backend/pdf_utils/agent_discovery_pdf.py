"""
Agent Discovery Scan Results PDF Generator
Generates a comprehensive PDF report from Agent Discovery scan results using reportlab.
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
        "Agent Discovery Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "AI Agent Discovery & Security Analysis"
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
    Generate a PDF report from Agent Discovery scan results.
    
    Args:
        scan_results: Dictionary with "results" key or list containing Agent Discovery scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"agent_discovery_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results - handle both dict and list formats
    if isinstance(scan_results, dict):
        results = scan_results.get("results", scan_results.get("data", []))
    elif isinstance(scan_results, list):
        results = scan_results
    else:
        results = []
    
    # Calculate statistics
    total_agents = len(results)
    by_risk = {}
    by_framework = {}
    all_tools = set()
    unique_files = set()
    
    for result in results:
        risk = result.get("risk", "unknown")
        by_risk[risk] = by_risk.get(risk, 0) + 1
        
        framework = result.get("framework", "Unknown")
        by_framework[framework] = by_framework.get(framework, 0) + 1
        
        tools = result.get("tools", [])
        if isinstance(tools, list):
            all_tools.update(tools)
        
        file_path = result.get("file_path", "")
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
    
    # Title page will be created by onFirstPage callback
    # Immediately break to page 2 for executive summary
    story.append(PageBreak())
    
    # Executive Summary (starts on page 2)
    story.append(Paragraph("Executive Summary", title_style))
    story.append(Spacer(1, 0.3 * inch))
    
    # Summary statistics table
    summary_data = [
        ["Metric", "Value"],
        ["Total Agents Discovered", str(total_agents)],
        ["Unique Files with Agents", str(len(unique_files))],
        ["Total Unique Tools", str(len(all_tools))],
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
    
    # Agents by Risk Level
    story.append(Paragraph("Agents by Risk Level", heading_style))
    story.append(Spacer(1, 0.15 * inch))
    risk_data = [["Risk Level", "Count"]]
    for risk in ["high", "medium", "low"]:
        count = by_risk.get(risk, 0)
        if count > 0:
            risk_data.append([risk.upper(), str(count)])
    
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
    
    # Breakdown by Framework
    if by_framework:
        story.append(Paragraph("Agents by Framework", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        framework_data = [["Framework", "Count"]]
        for framework, count in sorted(by_framework.items(), key=lambda x: x[1], reverse=True):
            framework_data.append([framework, str(count)])
        
        framework_table = Table(framework_data, colWidths=[2.5 * inch, 1.5 * inch], repeatRows=1)
        framework_table.setStyle(TableStyle([
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
        story.append(KeepTogether([framework_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_agents == 0:
        story.append(Paragraph("No agents discovered.", normal_style))
    else:
        # Process each finding - each gets 2 pages
        for idx, result in enumerate(results, 1):
            # Page break before each finding (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            agent_id = result.get("id", "Unknown")
            role = result.get("role", "Unknown")
            system_prompt = result.get("system_prompt", "No system prompt available")
            framework = result.get("framework", "Unknown")
            risk = result.get("risk", "unknown")
            risk_reason = result.get("risk_reason", "No risk reason provided")
            tools = result.get("tools", [])
            file_path = get_relative_path(result.get("file_path", "Unknown"))
            
            # Agent header
            finding_title = f"Agent #{idx}: {role}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Agent details table - wrap long text
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Agent ID (truncated)
            agent_id_para = Paragraph(agent_id[:60] + ("..." if len(agent_id) > 60 else ""), normal_style)
            finding_data.append(["Agent ID", agent_id_para])
            
            # Role
            finding_data.append(["Role", role])
            
            # Framework
            finding_data.append(["Framework", framework])
            
            # Risk
            finding_data.append(["Risk Level", risk.upper()])
            
            # File path - wrap if too long
            file_path_para = Paragraph(file_path[:80] + ("..." if len(file_path) > 80 else ""), normal_style)
            finding_data.append(["File Location", file_path_para])
            
            # Tools
            tools_str = ", ".join(tools) if isinstance(tools, list) and tools else "No tools"
            tools_para = Paragraph(tools_str[:100] + ("..." if len(tools_str) > 100 else ""), normal_style)
            finding_data.append(["Tools", tools_para])
            
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
            
            # System Prompt section (starts on page 2 of this finding)
            prompt_heading_style = ParagraphStyle(
                'PromptHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("System Prompt", prompt_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            prompt_para = Paragraph(system_prompt, normal_style)
            story.append(prompt_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Risk Reason section
            story.append(Paragraph("Risk Assessment", prompt_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            risk_info = f"<b>Risk Level:</b> {risk.upper()}<br/><br/>"
            risk_info += f"<b>Risk Reason:</b><br/>{risk_reason}"
            risk_para = Paragraph(risk_info, normal_style)
            story.append(risk_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Tools Details
            if tools and isinstance(tools, list) and len(tools) > 0:
                tools_heading_style = ParagraphStyle(
                    'ToolsHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Tools & Capabilities", tools_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                tools_info = f"<b>Total Tools:</b> {len(tools)}<br/><br/>"
                tools_info += "<b>Tool List:</b><br/>"
                for tool in tools:
                    tools_info += f"• {tool}<br/>"
                tools_para = Paragraph(tools_info, normal_style)
                story.append(tools_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # Additional Details
            details_heading_style = ParagraphStyle(
                'DetailsHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Additional Details", details_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            details_info = f"<b>Agent ID:</b> {agent_id}<br/>"
            details_info += f"<b>Framework:</b> {framework}<br/>"
            details_info += f"<b>File Location:</b> {file_path}"
            details_para = Paragraph(details_info, normal_style)
            story.append(details_para)
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\discovery_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"agent_discovery_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

