"""
Gitleaks (Data Leakage) Scan Results PDF Generator
Generates a comprehensive PDF report from Gitleaks scan results using reportlab.
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


def mask_secret(secret: str, show_length: int = 4) -> str:
    """Mask a secret, showing only first and last few characters."""
    if not secret or len(secret) <= show_length * 2:
        return "***" * len(secret) if secret else "N/A"
    return f"{secret[:show_length]}...{secret[-show_length:]}"


def get_entropy_color(entropy: float) -> colors.Color:
    """Get color based on entropy level."""
    if entropy >= 5.0:
        return colors.HexColor("#DC2626")  # Red - High entropy
    elif entropy >= 4.5:
        return colors.HexColor("#F97316")  # Orange - Medium-high entropy
    elif entropy >= 4.0:
        return colors.HexColor("#FBBF24")  # Yellow - Medium entropy
    else:
        return colors.HexColor("#10B981")  # Green - Low entropy


def create_title_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate):
    """Create a title page for the PDF."""
    canvas_obj.saveState()
    
    # Title text - positioned at top center
    canvas_obj.setFont("Helvetica-Bold", 32)
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))  # Professional dark slate
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 80,
        "Data Leakage Scan Report"
    )
    
    # Subtitle
    canvas_obj.setFont("Helvetica", 14)
    canvas_obj.setFillColor(colors.HexColor("#64748B"))  # Muted gray
    canvas_obj.drawCentredString(
        doc.pagesize[0] / 2.0,
        doc.pagesize[1] / 2.0 + 40,
        "Secret Detection & Data Leakage Analysis"
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
    Generate a PDF report from Gitleaks scan results.
    
    Args:
        scan_results: Dictionary with "results" key or list containing Gitleaks scan results
        output_path: Optional path to save the PDF. If None, generates a timestamped filename.
    
    Returns:
        Path to the generated PDF file
        
    """
    # Generate output filename if not provided
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"gitleaks_scan_report_{timestamp}.pdf"
    
    # Extract data from scan results - handle both dict and list formats
    if isinstance(scan_results, dict):
        results = scan_results.get("results", scan_results.get("data", []))
    elif isinstance(scan_results, list):
        results = scan_results
    else:
        results = []
    
    # Calculate statistics
    total_secrets = len(results)
    by_rule_type = {}
    high_entropy_count = 0
    entropy_sum = 0.0
    unique_files = set()
    
    for result in results:
        rule_id = result.get("RuleID", "Unknown")
        by_rule_type[rule_id] = by_rule_type.get(rule_id, 0) + 1
        
        entropy = result.get("Entropy", 0.0)
        if isinstance(entropy, (int, float)):
            entropy_sum += float(entropy)
            if float(entropy) >= 5.0:
                high_entropy_count += 1
        
        file_path = result.get("File", "")
        if file_path:
            unique_files.add(get_relative_path(file_path))
    
    avg_entropy = entropy_sum / total_secrets if total_secrets > 0 else 0.0
    
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
        ["Total Secrets Detected", str(total_secrets)],
        ["High Entropy Secrets (≥5.0)", str(high_entropy_count)],
        ["Average Entropy", f"{avg_entropy:.2f}"],
        ["Unique Files with Secrets", str(len(unique_files))],
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
    
    # Secrets by Rule Type
    if by_rule_type:
        story.append(Paragraph("Secrets by Rule Type", heading_style))
        story.append(Spacer(1, 0.15 * inch))
        rule_data = [["Rule Type", "Count"]]
        for rule_type, count in sorted(by_rule_type.items(), key=lambda x: x[1], reverse=True):
            rule_data.append([rule_type, str(count)])
        
        if len(rule_data) > 1:
            rule_table = Table(rule_data, colWidths=[4.0 * inch, 2.0 * inch], repeatRows=1)
            rule_table.setStyle(TableStyle([
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
            story.append(KeepTogether([rule_table]))
    
    # Page break after executive summary
    story.append(PageBreak())
    
    # Detailed Findings
    if total_secrets == 0:
        story.append(Paragraph("No secrets detected.", normal_style))
    else:
        # Process each finding - each gets 2 pages
        for idx, result in enumerate(results, 1):
            # Page break before each finding (except the first one)
            if idx > 1:
                story.append(PageBreak())
            
            rule_id = result.get("RuleID", "Unknown")
            description = result.get("Description", "No description available")
            file_path = get_relative_path(result.get("File", "Unknown"))
            start_line = result.get("StartLine", "?")
            end_line = result.get("EndLine", "?")
            start_column = result.get("StartColumn", "?")
            end_column = result.get("EndColumn", "?")
            secret = result.get("Secret", "")
            entropy = result.get("Entropy", 0.0)
            fingerprint = result.get("Fingerprint", "N/A")
            tags = result.get("Tags", [])
            commit = result.get("Commit", "")
            author = result.get("Author", "")
            email = result.get("Email", "")
            date = result.get("Date", "")
            message = result.get("Message", "")
            snippet = result.get("snippet", "")
            
            # Mask the secret for display
            masked_secret = mask_secret(secret)
            
            # Finding header
            finding_title = f"Secret #{idx}: {rule_id}"
            story.append(Paragraph(finding_title, heading_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # Finding details table - wrap long text
            finding_data = []
            finding_data.append(["Property", "Value"])
            
            # Rule ID
            rule_id_para = Paragraph(rule_id, normal_style)
            finding_data.append(["Rule ID", rule_id_para])
            
            # Description - wrap if too long
            desc_para = Paragraph(description[:150] + ("..." if len(description) > 150 else ""), normal_style)
            finding_data.append(["Description", desc_para])
            
            # Entropy with color coding
            entropy_value = float(entropy) if isinstance(entropy, (int, float)) else 0.0
            entropy_str = f"{entropy_value:.4f}"
            finding_data.append(["Entropy", entropy_str])
            
            # File path - wrap if too long
            file_path_para = Paragraph(file_path[:80] + ("..." if len(file_path) > 80 else ""), normal_style)
            finding_data.append(["File", file_path_para])
            
            finding_data.append(["Location", f"Line {start_line}, Columns {start_column}-{end_column}"])
            
            # Secret (masked)
            secret_para = Paragraph(masked_secret, normal_style)
            finding_data.append(["Secret (Masked)", secret_para])
            
            # Fingerprint
            fingerprint_para = Paragraph(fingerprint[:100] + ("..." if len(fingerprint) > 100 else ""), normal_style)
            finding_data.append(["Fingerprint", fingerprint_para])
            
            # Tags if available
            if tags:
                tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
                tags_para = Paragraph(tags_str[:100] + ("..." if len(tags_str) > 100 else ""), normal_style)
                finding_data.append(["Tags", tags_para])
            
            finding_table = Table(finding_data, colWidths=[1.8 * inch, 4.2 * inch], repeatRows=1)
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), get_entropy_color(entropy_value)),
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
            
            # Full Description section (starts on page 2 of this finding)
            desc_heading_style = ParagraphStyle(
                'DescHeading',
                parent=normal_style,
                fontSize=10,
                fontName='Helvetica-Bold',
                textColor=colors.HexColor("#1E293B"),
                spaceAfter=6,
                spaceBefore=0
            )
            story.append(Paragraph("Full Description", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            full_desc_para = Paragraph(description, normal_style)
            story.append(full_desc_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Secret Information (still masked)
            story.append(Paragraph("Secret Information", desc_heading_style))
            story.append(Spacer(1, 0.12 * inch))
            secret_info = f"<b>Masked Secret:</b> {masked_secret}<br/>"
            secret_info += f"<b>Full Length:</b> {len(secret)} characters<br/>"
            secret_info += f"<b>Entropy:</b> {entropy_value:.4f}"
            secret_para = Paragraph(secret_info, normal_style)
            story.append(secret_para)
            story.append(Spacer(1, 0.25 * inch))
            
            # Code Snippet if available
            if snippet:
                snippet_heading_style = ParagraphStyle(
                    'SnippetHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Code Snippet", snippet_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                # Limit snippet length
                snippet_text = snippet[:500] + ("..." if len(snippet) > 500 else "")
                snippet_lines = snippet_text.split('\n')[:10]  # Limit to 10 lines
                snippet_display = '\n'.join(snippet_lines)
                snippet_para = Preformatted(snippet_display, code_style)
                story.append(snippet_para)
                story.append(Spacer(1, 0.25 * inch))
            
            # Commit Information if available
            if commit or author or date:
                commit_heading_style = ParagraphStyle(
                    'CommitHeading',
                    parent=normal_style,
                    fontSize=10,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor("#1E293B"),
                    spaceAfter=6,
                    spaceBefore=0
                )
                story.append(Paragraph("Commit Information", commit_heading_style))
                story.append(Spacer(1, 0.12 * inch))
                commit_info = ""
                if commit:
                    commit_info += f"<b>Commit:</b> {commit[:50]}{'...' if len(commit) > 50 else ''}<br/>"
                if author:
                    commit_info += f"<b>Author:</b> {author}<br/>"
                if email:
                    commit_info += f"<b>Email:</b> {email}<br/>"
                if date:
                    commit_info += f"<b>Date:</b> {date}<br/>"
                if message:
                    commit_info += f"<b>Message:</b> {message[:200]}{'...' if len(message) > 200 else ''}"
                if commit_info:
                    commit_para = Paragraph(commit_info, normal_style)
                    story.append(commit_para)
    
    # Build PDF with proper page handlers
    doc.build(story, onFirstPage=create_title_page, onLaterPages=create_header_footer)
    
    return output_path


if __name__ == "__main__":
    # Test the PDF generation with the sample data
    test_file_path = "C:\\Users\\HP\\Desktop\\DevSecShield\\RabbitMQ\\worker\\gitleaks_results_testing.json"
    
    try:
        with open(test_file_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
        
        output_file = f"gitleaks_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = generate_pdf(scan_results, output_file)
        print(f"PDF generated successfully: {pdf_path}")
    except FileNotFoundError:
        print(f"Error: Could not find test file at {test_file_path}")
        print("Please ensure the file exists or provide a valid path.")
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()

