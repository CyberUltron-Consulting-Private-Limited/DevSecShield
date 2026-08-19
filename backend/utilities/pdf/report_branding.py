"""
Shared enterprise PDF branding — dashboard aesthetic matching the HTML report sample.

Visual language (mirrors Enterprise_Security_Report_Sample.html):
- Slate page chrome, white cards, soft gray-200 borders
- Soft severity pills (light bg + dark text)
- 4 KPI metric cards in the executive summary
- Premium tables: soft sticky-style headers, row rules (no heavy grid)
- Monospace for paths, CVEs, packages, snippets
- Dark evidence/code blocks
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

BRAND_NAME = "Zero Shield"
BRAND_URL = "zeroshield.ai"
BRAND_URL_FULL = "https://zeroshield.ai"
HEADER_HEIGHT = 42
FOOTER_HEIGHT = 40

REPORT_META: Dict[str, Dict[str, str]] = {
    "sast": {
        "title": "SAST Findings",
        "subtitle": "Static Application Security Testing",
        "footer_label": "SAST Report",
        "kicker": "Security Assessment",
        "intro": (
            "Static analysis findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Scan the catalog for priority items, then open matching detail cards "
            "for location, evidence, and remediation guidance."
        ),
    },
    "sbom_sca": {
        "title": "SBOM / SCA Dependencies",
        "subtitle": "Software Bill of Materials & Supply Chain Security",
        "footer_label": "SBOM/SCA Report",
        "kicker": "Security Assessment",
        "intro": (
            "Dependency and bill-of-materials vulnerabilities for this scan. "
            "Package impact and remediation guidance are listed below."
        ),
        "how_to_read": (
            "Use the catalog to identify affected packages, then review each "
            "detail card for CVE context and upgrade guidance."
        ),
    },
    "dast": {
        "title": "DAST Findings",
        "subtitle": "Dynamic Application Security Testing",
        "footer_label": "DAST Report",
        "kicker": "Security Assessment",
        "intro": (
            "Dynamic testing findings against live application endpoints. "
            "Severity, confidence, and remediation steps are included for each issue."
        ),
        "how_to_read": (
            "Filter priority by severity in the catalog, then review URL-level "
            "detail cards for description and recommended fixes."
        ),
    },
    "iac": {
        "title": "IAC Findings",
        "subtitle": "Infrastructure as Code Security Testing",
        "footer_label": "IAC Report",
        "kicker": "Security Assessment",
        "intro": (
            "Infrastructure-as-code findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Scan the catalog for priority misconfigurations, then open matching "
            "detail cards for location, evidence, and remediation guidance."
        ),
    },
    "mcp": {
        "title": "MCP Findings",
        "subtitle": "Model Context Protocol Security Testing",
        "footer_label": "MCP Report",
        "kicker": "Security Assessment",
        "intro": (
            "MCP tool, prompt, and resource findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Use the catalog to identify affected MCP resources, then review each "
            "detail card for description and recommended fixes."
        ),
    },
    "llm": {
        "title": "LLM Findings",
        "subtitle": "Large Language Model Security Benchmark",
        "footer_label": "LLM Report",
        "kicker": "Security Assessment",
        "intro": (
            "LLM benchmark findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Filter priority by severity in the catalog, then review each detail card "
            "for OWASP LLM mappings and remediation guidance."
        ),
    },
    "cbom": {
        "title": "CBOM Findings",
        "subtitle": "Cryptographic Bill of Materials",
        "footer_label": "CBOM Report",
        "kicker": "Security Assessment",
        "intro": (
            "Cryptographic inventory findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Use the catalog to identify weak or quantum-vulnerable algorithms, "
            "then review each detail card for location and upgrade guidance."
        ),
    },
    "ai_bom": {
        "title": "AI BOM Findings",
        "subtitle": "AI Bill of Materials",
        "footer_label": "AI BOM Report",
        "kicker": "Security Assessment",
        "intro": (
            "AI asset inventory findings for this scan. KPI summary first; "
            "catalog and per-finding detail follow."
        ),
        "how_to_read": (
            "Use the catalog to identify high-risk AI assets, then review each "
            "detail card for provider, license, and remediation guidance."
        ),
    },
}

SEVERITY_MEANING = {
    "CRITICAL": "Immediate remediation required — severe exploitability / impact.",
    "HIGH": "Remediate in the current cycle — significant risk if left open.",
    "MEDIUM": "Schedule remediation — real risk with moderate urgency.",
    "LOW": "Track and harden opportunistically — limited immediate impact.",
    "ERROR": "Remediate in the current cycle — significant risk if left open.",
    "WARNING": "Schedule remediation — real risk with moderate urgency.",
    "INFO": "Informational — review for hardening opportunities.",
    "UNKNOWN": "Unclassified — review manually.",
}

# Brand palette — navy + teal enterprise
BRAND_NAVY = colors.HexColor("#0B1F33")
BRAND_TEAL = colors.HexColor("#0F766E")

PILL_CRITICAL_BG = colors.HexColor("#FFF1F2")
PILL_CRITICAL_FG = colors.HexColor("#9F1239")
PILL_CRITICAL_BD = colors.HexColor("#FECDD3")
PILL_HIGH_BG = colors.HexColor("#FFF7ED")
PILL_HIGH_FG = colors.HexColor("#9A3412")
PILL_HIGH_BD = colors.HexColor("#FED7AA")
PILL_MEDIUM_BG = colors.HexColor("#FFFBEB")
PILL_MEDIUM_FG = colors.HexColor("#92400E")
PILL_MEDIUM_BD = colors.HexColor("#FDE68A")
PILL_LOW_BG = colors.HexColor("#ECFEFF")
PILL_LOW_FG = colors.HexColor("#0E7490")
PILL_LOW_BD = colors.HexColor("#A5F3FC")
PILL_UNKNOWN_BG = colors.HexColor("#F4F4F5")
PILL_UNKNOWN_FG = colors.HexColor("#52525B")
PILL_UNKNOWN_BD = colors.HexColor("#E4E4E7")

KPI_ACCENT_TOTAL = BRAND_TEAL
KPI_ACCENT_CRITICAL = colors.HexColor("#E11D48")
KPI_ACCENT_HIGH = colors.HexColor("#EA580C")
KPI_ACCENT_TIME = BRAND_NAVY
BAR_CRITICAL = colors.HexColor("#E11D48")
BAR_HIGH = colors.HexColor("#EA580C")
BAR_MEDIUM = colors.HexColor("#D97706")
BAR_LOW = colors.HexColor("#0891B2")

SEV_CRITICAL = PILL_CRITICAL_FG
SEV_HIGH = PILL_HIGH_FG
SEV_MEDIUM = PILL_MEDIUM_FG
SEV_LOW = PILL_LOW_FG
SEV_UNKNOWN = PILL_UNKNOWN_FG

COLOR_NAVY = BRAND_NAVY
COLOR_SLATE = colors.HexColor("#64748B")
COLOR_BODY = colors.HexColor("#334155")
COLOR_BORDER = colors.HexColor("#E2E8F0")
COLOR_BORDER_STRONG = colors.HexColor("#CBD5E1")
COLOR_CARD_BG = colors.HexColor("#FFFFFF")
COLOR_ROW_ALT = colors.HexColor("#F8FAFC")
COLOR_HEADER = BRAND_NAVY
COLOR_HEADER_SOFT = colors.HexColor("#F1F5F9")
COLOR_PAGE_BG = colors.HexColor("#F1F5F9")
COLOR_CODE_BG = colors.HexColor("#0B1F33")
COLOR_CODE_FG = colors.HexColor("#E2E8F0")
COLOR_WHITE = colors.white
COLOR_LABEL = BRAND_NAVY
CONTENT_WIDTH = 7.1 * inch


def logo_path() -> str:
    return os.path.join(os.path.dirname(__file__), "Zero Shield Logo.png")


def _draw_logo(canvas_obj: canvas.Canvas, x: float, y: float, *, max_height: float = 22) -> float:
    path = logo_path()
    if not os.path.exists(path):
        return 0.0
    try:
        img = ImageReader(path)
        iw, ih = img.getSize()
        scale = max_height / float(ih)
        w, h = iw * scale, ih * scale
        canvas_obj.drawImage(path, x, y, width=w, height=h, mask="auto", preserveAspectRatio=True)
        return float(w)
    except Exception:
        logger.warning("Enterprise report logo failed to draw; continuing without it", exc_info=True)
        return 0.0


def severity_color(severity: str) -> colors.Color:
    """Accent / text color for a severity (legacy API)."""
    val = (severity or "").strip().upper()
    if val in ("CRITICAL",):
        return PILL_CRITICAL_FG
    if val in ("HIGH", "ERROR"):
        return PILL_HIGH_FG
    if val in ("MEDIUM", "WARNING"):
        return PILL_MEDIUM_FG
    if val in ("LOW", "INFO"):
        return PILL_LOW_FG
    return PILL_UNKNOWN_FG


def severity_pill_colors(severity: str) -> Tuple[colors.Color, colors.Color, colors.Color]:
    val = (severity or "").strip().upper()
    if val in ("CRITICAL",):
        return PILL_CRITICAL_BG, PILL_CRITICAL_FG, PILL_CRITICAL_BD
    if val in ("HIGH", "ERROR"):
        return PILL_HIGH_BG, PILL_HIGH_FG, PILL_HIGH_BD
    if val in ("MEDIUM", "WARNING"):
        return PILL_MEDIUM_BG, PILL_MEDIUM_FG, PILL_MEDIUM_BD
    if val in ("LOW", "INFO"):
        return PILL_LOW_BG, PILL_LOW_FG, PILL_LOW_BD
    return PILL_UNKNOWN_BG, PILL_UNKNOWN_FG, PILL_UNKNOWN_BD


def severity_label(severity: str) -> str:
    val = (severity or "").strip()
    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    upper = val.upper()
    return mapping.get(upper, upper or "UNKNOWN")


def count_label(severity: str) -> str:
    """Canonical title-case label for KPI / breakdown counts (High, Medium, ...)."""
    return severity_label(severity).title()


def mapping_entries(val: Any) -> List[Tuple[str, str]]:
    """Normalize OWASP / compliance / CVE blobs to (key, value) pairs."""
    if val is None:
        return []
    out: List[Tuple[str, str]] = []
    if isinstance(val, dict) and not isinstance(val, list):
        for k, v in val.items():
            if v is None or (isinstance(v, str) and not str(v).strip()):
                continue
            out.append((str(k), str(v)))
        return out
    if isinstance(val, list):
        for item in val:
            if isinstance(item, dict) and item:
                k, v = next(iter(item.items()))
                if v is None or (isinstance(v, str) and not str(v).strip()):
                    continue
                out.append((str(k), str(v)))
            elif item is not None and str(item).strip():
                out.append(("", str(item)))
        return out
    if str(val).strip():
        return [("", str(val))]
    return []


def mapping_rows(val: Any, *, label: str, limit: int = 6) -> List[List[str]]:
    """Format mapping blobs as [label, 'key: value'] rows for finding cards."""
    rows: List[List[str]] = []
    for k, v in mapping_entries(val)[:limit]:
        text = f"{k}: {v}" if k else v
        rows.append([label, text])
    return rows


def make_enterprise_document(output_path: str) -> SimpleDocTemplate:
    return SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=56,
        bottomMargin=52,
    )


def append_bom_compliance_sections(
    story: List[Any],
    scan_results: Any,
    styles: Optional[Dict[str, ParagraphStyle]] = None,
) -> None:
    """Append RBI + CERT-In appendix when the scan payload is a dict.

    Failures are logged and swallowed so a missing appendix cannot break export.
    """
    if not isinstance(scan_results, dict):
        return
    styles = styles or get_report_styles()
    try:
        from backend.utilities.pdf.rbi_compliance_pdf import append_rbi_compliance_pdf_section
        from backend.utilities.pdf.certin_compliance_pdf import (
            append_certin_compliance_pdf_section,
        )

        append_rbi_compliance_pdf_section(
            story,
            scan_results,
            styles["heading"],
            styles["body"],
            styles["table_cell"],
        )
        append_certin_compliance_pdf_section(
            story,
            scan_results,
            styles["heading"],
            styles["body"],
            styles["table_cell"],
        )
    except Exception:
        logger.warning("BOM compliance appendix failed; continuing PDF export", exc_info=True)


def escape_html(text: Any) -> str:
    if text is None:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def mono(text: Any, *, size: int = 8) -> str:
    return f'<font face="Courier" size="{size}">{escape_html(text)}</font>'


def _count_sev(severity_counts: Dict[str, int], *keys: str) -> int:
    targets = {k.lower() for k in keys}
    total = 0
    seen = set()
    for raw, n in severity_counts.items():
        low = str(raw).strip().lower()
        if low in targets and low not in seen:
            total += int(n or 0)
            seen.add(low)
    return total


def get_report_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "DashTitle",
            parent=base["Heading1"],
            fontSize=18,
            textColor=COLOR_NAVY,
            spaceAfter=2,
            spaceBefore=0,
            fontName="Helvetica-Bold",
            leading=22,
        ),
        "kicker": ParagraphStyle(
            "DashKicker",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=COLOR_SLATE,
            spaceAfter=2,
            leading=10,
        ),
        "subtitle": ParagraphStyle(
            "DashSubtitle",
            parent=base["Normal"],
            fontSize=9,
            textColor=COLOR_SLATE,
            spaceAfter=8,
            leading=12,
            fontName="Helvetica",
        ),
        "heading": ParagraphStyle(
            "DashHeading",
            parent=base["Heading2"],
            fontSize=11,
            textColor=COLOR_LABEL,
            spaceAfter=6,
            spaceBefore=8,
            fontName="Helvetica-Bold",
            leading=14,
        ),
        "panel_title": ParagraphStyle(
            "DashPanelTitle",
            parent=base["Normal"],
            fontSize=11,
            textColor=COLOR_NAVY,
            fontName="Helvetica-Bold",
            leading=14,
        ),
        "panel_meta": ParagraphStyle(
            "DashPanelMeta",
            parent=base["Normal"],
            fontSize=8,
            textColor=COLOR_SLATE,
            fontName="Courier",
            leading=10,
            alignment=TA_CENTER,
        ),
        "finding_title": ParagraphStyle(
            "DashFindingTitle",
            parent=base["Normal"],
            fontSize=9.5,
            textColor=COLOR_LABEL,
            spaceAfter=0,
            spaceBefore=0,
            fontName="Helvetica-Bold",
            leading=12,
        ),
        "section": ParagraphStyle(
            "DashSection",
            parent=base["Normal"],
            fontSize=7.5,
            fontName="Helvetica-Bold",
            textColor=COLOR_SLATE,
            spaceAfter=3,
            spaceBefore=0,
            leading=9,
        ),
        "body": ParagraphStyle(
            "DashBody",
            parent=base["Normal"],
            fontSize=8.5,
            spaceAfter=4,
            spaceBefore=0,
            leading=11.5,
            textColor=COLOR_BODY,
            fontName="Helvetica",
            alignment=TA_JUSTIFY,
        ),
        "muted": ParagraphStyle(
            "DashMuted",
            parent=base["Normal"],
            fontSize=8,
            spaceAfter=6,
            spaceBefore=0,
            leading=11,
            textColor=COLOR_SLATE,
            fontName="Helvetica",
        ),
        "table_cell": ParagraphStyle(
            "DashTableCell",
            parent=base["Normal"],
            fontSize=8,
            leading=10.5,
            textColor=COLOR_BODY,
            fontName="Helvetica",
        ),
        "table_header": ParagraphStyle(
            "DashTableHeader",
            parent=base["Normal"],
            fontSize=7.5,
            leading=9,
            textColor=COLOR_SLATE,
            fontName="Helvetica-Bold",
        ),
        "table_label": ParagraphStyle(
            "DashTableLabel",
            parent=base["Normal"],
            fontSize=8,
            leading=10.5,
            textColor=COLOR_LABEL,
            fontName="Helvetica-Bold",
        ),
        "mono_cell": ParagraphStyle(
            "DashMonoCell",
            parent=base["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=COLOR_BODY,
            fontName="Courier",
        ),
        "badge": ParagraphStyle(
            "DashBadge",
            parent=base["Normal"],
            fontSize=6.5,
            leading=8,
            textColor=PILL_CRITICAL_FG,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "kpi_label": ParagraphStyle(
            "DashKpiLabel",
            parent=base["Normal"],
            fontSize=8,
            textColor=COLOR_SLATE,
            fontName="Helvetica-Bold",
            leading=10,
        ),
        "kpi_value": ParagraphStyle(
            "DashKpiValue",
            parent=base["Normal"],
            fontSize=20,
            textColor=COLOR_NAVY,
            fontName="Helvetica-Bold",
            leading=24,
        ),
        "kpi_hint": ParagraphStyle(
            "DashKpiHint",
            parent=base["Normal"],
            fontSize=7,
            textColor=COLOR_SLATE,
            fontName="Helvetica",
            leading=9,
        ),
        "meta_label": ParagraphStyle(
            "DashMetaLabel",
            parent=base["Normal"],
            fontSize=6.5,
            textColor=COLOR_SLATE,
            fontName="Helvetica-Bold",
            leading=8,
        ),
        "meta_value": ParagraphStyle(
            "DashMetaValue",
            parent=base["Normal"],
            fontSize=8.5,
            textColor=COLOR_NAVY,
            fontName="Helvetica-Bold",
            leading=11,
        ),
        "code": ParagraphStyle(
            "DashCode",
            parent=base["Code"],
            fontSize=7.5,
            fontName="Courier",
            spaceAfter=0,
            spaceBefore=0,
            leftIndent=0,
            rightIndent=0,
            backColor=COLOR_CODE_BG,
            borderColor=COLOR_CODE_BG,
            borderWidth=0,
            borderPadding=6,
            textColor=COLOR_CODE_FG,
            leading=9.5,
        ),
        "section_kicker": ParagraphStyle(
            "DashSectionKicker",
            parent=base["Normal"],
            fontSize=7,
            fontName="Helvetica-Bold",
            textColor=COLOR_SLATE,
            spaceAfter=2,
            leading=9,
        ),
    }


# ---------------------------------------------------------------------------
# Cover / footer / page chrome  (HTML-like slate canvas — no classic title cover)
# ---------------------------------------------------------------------------


def draw_page_background(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    page_width, page_height = doc.pagesize
    canvas_obj.saveState()
    canvas_obj.setFillColor(COLOR_PAGE_BG)
    canvas_obj.rect(0, 0, page_width, page_height, fill=1, stroke=0)
    canvas_obj.restoreState()


def draw_page_header(
    canvas_obj: canvas.Canvas,
    doc: SimpleDocTemplate,
    *,
    report_key: str = "sast",
) -> None:
    """Navy brand bar with Zero Shield logo + zeroshield.ai on every page."""
    meta = REPORT_META.get(report_key, REPORT_META["sast"])
    page_width, page_height = doc.pagesize
    margin = 36
    bar_h = HEADER_HEIGHT
    y0 = page_height - bar_h

    canvas_obj.saveState()
    canvas_obj.setFillColor(BRAND_NAVY)
    canvas_obj.rect(0, y0, page_width, bar_h, fill=1, stroke=0)
    canvas_obj.setFillColor(BRAND_TEAL)
    canvas_obj.rect(0, y0 - 2.5, page_width, 2.5, fill=1, stroke=0)

    logo_w = _draw_logo(canvas_obj, margin, y0 + 9, max_height=24)
    text_x = margin + (logo_w + 8 if logo_w else 0)

    canvas_obj.setFillColor(COLOR_WHITE)
    canvas_obj.setFont("Helvetica-Bold", 10)
    canvas_obj.drawString(text_x, y0 + 22, BRAND_NAME.upper())
    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#99F6E4"))
    canvas_obj.drawString(text_x, y0 + 10, BRAND_URL)

    canvas_obj.setFillColor(COLOR_WHITE)
    canvas_obj.setFont("Helvetica-Bold", 8)
    canvas_obj.drawRightString(page_width - margin, y0 + 22, meta["footer_label"])
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(colors.HexColor("#94A3B8"))
    canvas_obj.drawRightString(page_width - margin, y0 + 10, "CONFIDENTIAL")
    canvas_obj.restoreState()


def draw_standard_footer(
    canvas_obj: canvas.Canvas,
    doc: SimpleDocTemplate,
    *,
    report_key: str = "sast",
) -> None:
    """Footer with logo, zeroshield.ai, report label, page number."""
    meta = REPORT_META.get(report_key, REPORT_META["sast"])
    page_width, _ = doc.pagesize
    margin = 36

    canvas_obj.saveState()
    canvas_obj.setFillColor(COLOR_WHITE)
    canvas_obj.rect(0, 0, page_width, FOOTER_HEIGHT, fill=1, stroke=0)
    canvas_obj.setStrokeColor(COLOR_BORDER_STRONG)
    canvas_obj.setLineWidth(0.7)
    canvas_obj.line(margin, FOOTER_HEIGHT - 1, page_width - margin, FOOTER_HEIGHT - 1)

    logo_w = _draw_logo(canvas_obj, margin, 10, max_height=16)
    text_x = margin + (logo_w + 6 if logo_w else 0)

    canvas_obj.setFillColor(BRAND_NAVY)
    canvas_obj.setFont("Helvetica-Bold", 7)
    canvas_obj.drawString(text_x, 18, BRAND_NAME)
    canvas_obj.setFillColor(BRAND_TEAL)
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawString(text_x, 8, BRAND_URL_FULL)

    canvas_obj.setFillColor(COLOR_SLATE)
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawCentredString(page_width / 2.0, 14, f"{meta['footer_label']}  ·  Confidential")

    canvas_obj.setFillColor(BRAND_NAVY)
    canvas_obj.setFont("Helvetica-Bold", 8)
    canvas_obj.drawRightString(page_width - margin, 14, f"Page {canvas_obj.getPageNumber()}")
    canvas_obj.restoreState()


def draw_enterprise_cover_page(
    canvas_obj: canvas.Canvas,
    doc: SimpleDocTemplate,
    *,
    report_key: str,
    generated_at: Optional[datetime] = None,
) -> None:
    draw_page_background(canvas_obj, doc)
    draw_page_header(canvas_obj, doc, report_key=report_key)
    draw_standard_footer(canvas_obj, doc, report_key=report_key)


def make_cover_callback(report_key: str):
    def _on_first_page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
        draw_enterprise_cover_page(canvas_obj, doc, report_key=report_key)

    return _on_first_page


def make_footer_callback(report_key: str):
    def _on_later_pages(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
        draw_page_background(canvas_obj, doc)
        draw_page_header(canvas_obj, doc, report_key=report_key)
        draw_standard_footer(canvas_obj, doc, report_key=report_key)

    return _on_later_pages


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


def severity_badge(severity: str, styles: Dict[str, ParagraphStyle], *, width: float = 0.78 * inch) -> Table:
    """Soft pill badge — light background, dark text (HTML sample)."""
    label = severity_label(severity)
    bg, fg, bd = severity_pill_colors(severity)
    badge_style = ParagraphStyle(
        f"Pill_{label}",
        parent=styles["badge"],
        textColor=fg,
        fontSize=6.5,
        leading=8,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    badge = Table(
        [[Paragraph(escape_html(label), badge_style)]],
        colWidths=[width],
        rowHeights=[15],
    )
    badge.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.6, bd),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("ROUNDEDCORNERS", [6, 6, 6, 6]),
            ]
        )
    )
    return badge


def _base_table_style() -> List[Any]:
    """Premium table: soft header, bottom borders only (HTML-like)."""
    return [
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_SOFT),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_SLATE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, COLOR_BORDER_STRONG),
        ("LINEBELOW", (0, 1), (-1, -2), 0.5, COLOR_BORDER),
        ("BACKGROUND", (0, 1), (-1, -1), COLOR_WHITE),
        ("BOX", (0, 0), (-1, -1), 0.6, COLOR_BORDER),
    ]


def key_value_table(
    rows: Sequence[Tuple[str, str]],
    *,
    styles: Dict[str, ParagraphStyle],
    mono_labels: Optional[Sequence[str]] = None,
    label_width: float = 1.55 * inch,
    value_width: float = 4.85 * inch,
) -> Table:
    mono_set = {m.lower() for m in (mono_labels or [])}
    data = []
    for label, value in rows:
        if not value:
            continue
        value_style = styles["mono_cell"] if label.lower() in mono_set else styles["table_cell"]
        data.append(
            [
                Paragraph(escape_html(label), styles["table_label"]),
                Paragraph(escape_html(str(value)), value_style),
            ]
        )
    if not data:
        data = [[Paragraph("—", styles["muted"]), Paragraph("—", styles["muted"])]]
    table = Table(data, colWidths=[label_width, value_width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), COLOR_HEADER_SOFT),
                ("BACKGROUND", (1, 0), (1, -1), COLOR_WHITE),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, COLOR_BORDER),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def styled_data_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    styles: Dict[str, ParagraphStyle],
    col_widths: Optional[List[float]] = None,
    severity_col: Optional[int] = None,
) -> Table:
    header_row = [Paragraph(escape_html(h).upper(), styles["table_header"]) for h in headers]
    body: List[List[Any]] = [header_row]
    for row in rows:
        cells: List[Any] = []
        for i, cell in enumerate(row):
            if isinstance(cell, (Paragraph, Table, Flowable)):
                cells.append(cell)
            elif severity_col is not None and i == severity_col:
                cells.append(severity_badge(str(cell), styles, width=0.72 * inch))
            else:
                cells.append(Paragraph(escape_html(str(cell)), styles["table_cell"]))
        body.append(cells)
    table = Table(body, colWidths=col_widths, repeatRows=1)
    style_cmds = _base_table_style()
    if severity_col is not None:
        style_cmds.append(("ALIGN", (severity_col, 1), (severity_col, -1), "CENTER"))
        style_cmds.append(("VALIGN", (severity_col, 1), (severity_col, -1), "MIDDLE"))
    table.setStyle(TableStyle(style_cmds))
    return table


def card_shell(inner: Flowable, *, severity: str = "", content_width: float = CONTENT_WIDTH) -> Table:
    accent_w = 3.0
    if severity:
        shell = Table(
            [["", inner]],
            colWidths=[accent_w, content_width - accent_w],
        )
        shell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), severity_color(severity)),
                    ("BACKGROUND", (1, 0), (1, 0), COLOR_CARD_BG),
                    ("BOX", (0, 0), (-1, -1), 0.7, COLOR_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROUNDEDCORNERS", [8, 8, 8, 8]),
                ]
            )
        )
        return shell

    shell = Table([[inner]], colWidths=[content_width])
    shell.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, COLOR_BORDER),
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_CARD_BG),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROUNDEDCORNERS", [8, 8, 8, 8]),
            ]
        )
    )
    return shell


def padded_block(flowables: Sequence[Any], *, pad: float = 8, width: float = CONTENT_WIDTH - 14) -> Table:
    rows = [[f] for f in flowables]
    wrap = Table(rows, colWidths=[width])
    wrap.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), pad),
                ("RIGHTPADDING", (0, 0), (-1, -1), pad),
                ("TOPPADDING", (0, 0), (0, 0), pad),
                ("BOTTOMPADDING", (0, -1), (0, -1), pad),
                ("TOPPADDING", (0, 1), (0, -2), 0),
                ("BOTTOMPADDING", (0, 0), (0, -2), 2),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return wrap


def severity_meaning(severity: str) -> str:
    return SEVERITY_MEANING.get(severity_label(severity), SEVERITY_MEANING["UNKNOWN"])


def _kpi_card(label: str, value: str, hint: str, accent: colors.Color, styles: Dict[str, ParagraphStyle], width: float) -> Table:
    inner = Table(
        [
            [Paragraph(escape_html(label), styles["kpi_label"])],
            [Paragraph(escape_html(value), styles["kpi_value"])],
            [Paragraph(escape_html(hint), styles["kpi_hint"])],
        ],
        colWidths=[width - 6],
    )
    inner.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (0, 0), 10),
                ("BOTTOMPADDING", (0, -1), (0, -1), 10),
                ("TOPPADDING", (0, 1), (0, 1), 4),
                ("BOTTOMPADDING", (0, 0), (0, 1), 0),
                ("TOPPADDING", (0, 2), (0, 2), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    card = Table([["", inner]], colWidths=[3.0, width - 3.0])
    card.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), accent),
                ("BACKGROUND", (1, 0), (1, 0), COLOR_WHITE),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#E5E7EB")),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROUNDEDCORNERS", [8, 8, 8, 8]),
            ]
        )
    )
    return card


def build_kpi_grid(
    *,
    total_issues: int,
    critical: int,
    high: int,
    scan_time: str,
    styles: Dict[str, ParagraphStyle],
    total_hint: str = "Across this scan",
    risk_score: Optional[int] = None,
    risk_grade: Optional[str] = None,
    risk_band: Optional[str] = None,
) -> Table:
    gap = 6
    # Risk + 4 metrics — compress slightly when risk present
    if risk_score is not None:
        widths_ratio = [1.25, 0.95, 0.85, 0.85, 0.95]
        total_ratio = sum(widths_ratio)
        card_widths = [(CONTENT_WIDTH - 4 * gap) * (r / total_ratio) for r in widths_ratio]
        risk_inner_bits: List[Any] = []
        grade = risk_grade or "—"
        grade_bg = colors.HexColor("#ECFDF5")
        grade_fg = colors.HexColor("#047857")
        if grade in ("D", "F"):
            grade_bg, grade_fg = PILL_CRITICAL_BG, PILL_CRITICAL_FG
        elif grade == "C":
            grade_bg, grade_fg = PILL_MEDIUM_BG, PILL_MEDIUM_FG
        grade_cell = Table(
            [[Paragraph(escape_html(grade), ParagraphStyle("Grade", fontName="Helvetica-Bold", fontSize=16, textColor=grade_fg, alignment=TA_CENTER, leading=18))]],
            colWidths=[28],
            rowHeights=[28],
        )
        grade_cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), grade_bg),
                    ("BOX", (0, 0), (-1, -1), 0.5, grade_fg),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                ]
            )
        )
        risk_text = Table(
            [
                [Paragraph("Risk score", styles["kpi_label"])],
                [Paragraph(str(risk_score), styles["kpi_value"])],
                [Paragraph(escape_html(risk_band or ""), styles["kpi_hint"])],
            ],
            colWidths=[card_widths[0] - 40],
        )
        risk_text.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        risk_row = Table([[grade_cell, risk_text]], colWidths=[32, card_widths[0] - 38])
        risk_row.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (1, 0), (1, 0), 0),
                    ("LEFTPADDING", (1, 0), (1, 0), 8),
                ]
            )
        )
        # wrap risk as a fake kpi via accent card
        risk_pad = Table([[risk_row]], colWidths=[card_widths[0] - 6])
        risk_pad.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        risk_card = Table([["", risk_pad]], colWidths=[3.0, card_widths[0] - 3.0])
        risk_card.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), KPI_ACCENT_TIME),
                    ("BACKGROUND", (1, 0), (1, 0), COLOR_WHITE),
                    ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#E4E4E7")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROUNDEDCORNERS", [8, 8, 8, 8]),
                ]
            )
        )
        cards = [
            risk_card,
            _kpi_card("Total Issues", str(total_issues), total_hint, KPI_ACCENT_TOTAL, styles, card_widths[1]),
            _kpi_card("Critical", str(critical), "Immediate remediation", KPI_ACCENT_CRITICAL, styles, card_widths[2]),
            _kpi_card("High", str(high), "Current sprint priority", KPI_ACCENT_HIGH, styles, card_widths[3]),
            _kpi_card("Scan Time", scan_time or "—", "Completed successfully", KPI_ACCENT_TIME, styles, card_widths[4]),
        ]
        widths = card_widths
    else:
        card_w = (CONTENT_WIDTH - 3 * gap) / 4.0
        cards = [
            _kpi_card("Total Issues", str(total_issues), total_hint, KPI_ACCENT_TOTAL, styles, card_w),
            _kpi_card("Critical", str(critical), "Immediate remediation required", KPI_ACCENT_CRITICAL, styles, card_w),
            _kpi_card("High", str(high), "Prioritize in current sprint", KPI_ACCENT_HIGH, styles, card_w),
            _kpi_card("Scan Time", scan_time or "—", "Completed successfully", KPI_ACCENT_TIME, styles, card_w),
        ]
        widths = [card_w] * 4

    row: List[Any] = []
    col_widths: List[float] = []
    for i, c in enumerate(cards):
        if i:
            row.append("")
            col_widths.append(gap)
        row.append(c)
        col_widths.append(widths[i])
    grid = Table([row], colWidths=col_widths)
    grid.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return grid


def compute_risk_score(critical: int, high: int, medium: int, low: int) -> Tuple[int, str, str]:
    weighted = critical * 10 + high * 5 + medium * 2 + low * 1
    score = min(100, weighted * 4)
    if score >= 70:
        return score, "F", "Critical risk"
    if score >= 50:
        return score, "D", "High risk"
    if score >= 30:
        return score, "C", "Elevated risk"
    if score >= 15:
        return score, "B", "Moderate risk"
    return score, "A", "Low risk"


def build_severity_bar(
    *,
    critical: int,
    high: int,
    medium: int,
    low: int,
    styles: Dict[str, ParagraphStyle],
) -> Table:
    """CSS-flex-style stacked severity bar for PDF."""
    parts = [
        (critical, BAR_CRITICAL, "Critical"),
        (high, BAR_HIGH, "High"),
        (medium, BAR_MEDIUM, "Medium"),
        (low, BAR_LOW, "Low"),
    ]
    total = sum(n for n, _, _ in parts) or 1
    seg_row: List[Any] = []
    seg_widths: List[float] = []
    usable = CONTENT_WIDTH - 24
    for n, color, _ in parts:
        if n <= 0:
            continue
        w = max(usable * (n / total), 8)
        cell = Table([[""]], colWidths=[w], rowHeights=[10])
        cell.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), color),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        seg_row.append(cell)
        seg_widths.append(w)
    if not seg_row:
        seg_row = [""]
        seg_widths = [usable]
    track = Table([seg_row], colWidths=seg_widths)
    track.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("ROUNDEDCORNERS", [6, 6, 6, 6]),
            ]
        )
    )
    legend_bits = []
    for n, color, label in parts:
        legend_bits.append(
            Paragraph(
                f'<font color="{color.hexval()}"><b>■</b></font> {label} <b>{n}</b>',
                styles["kpi_hint"],
            )
        )
    legend = Table([legend_bits], colWidths=[CONTENT_WIDTH / 4.0] * 4)
    legend.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    head = Paragraph("Vulnerability breakdown", styles["panel_title"])
    inner = padded_block([head, Spacer(1, 8), track, legend], pad=12, width=CONTENT_WIDTH - 16)
    return card_shell(inner)


def build_meta_strip(
    chips: Sequence[Tuple[str, str]],
    *,
    styles: Dict[str, ParagraphStyle],
) -> Table:
    if not chips:
        return Table([[""]])
    n = len(chips)
    gap = 6
    chip_w = (CONTENT_WIDTH - gap * max(0, n - 1)) / float(n)
    cells: List[Any] = []
    widths: List[float] = []
    for i, (label, value) in enumerate(chips):
        if i:
            cells.append("")
            widths.append(gap)
        chip_inner = Table(
            [
                [Paragraph(escape_html(label).upper(), styles["meta_label"])],
                [Paragraph(escape_html(value), styles["meta_value"])],
            ],
            colWidths=[chip_w - 2],
        )
        chip_inner.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (0, 0), 8),
                    ("BOTTOMPADDING", (0, -1), (0, -1), 8),
                    ("TOPPADDING", (0, 1), (0, 1), 2),
                    ("BOTTOMPADDING", (0, 0), (0, 0), 0),
                ]
            )
        )
        chip = Table([[chip_inner]], colWidths=[chip_w])
        chip.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_WHITE),
                    ("BOX", (0, 0), (-1, -1), 0.6, COLOR_BORDER),
                    ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        cells.append(chip)
        widths.append(chip_w)
    strip = Table([cells], colWidths=widths)
    strip.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return strip


def append_report_masthead(
    story: List[Any],
    *,
    report_key: str,
    project_name: str = "Security Scan",
    org_label: str = "Zero Shield",
    styles: Optional[Dict[str, ParagraphStyle]] = None,
) -> None:
    """Dense title block under the canvas header (logo lives in header/footer)."""
    styles = styles or get_report_styles()
    meta = REPORT_META.get(report_key, REPORT_META["sast"])
    brand_style = ParagraphStyle(
        "BrandUrl",
        parent=styles["muted"],
        fontSize=8,
        textColor=BRAND_TEAL,
        fontName="Helvetica-Bold",
        alignment=TA_RIGHT,
        leading=10,
    )
    left = Table(
        [
            [Paragraph(escape_html(f"{org_label} · {meta.get('kicker', 'Security Assessment')}").upper(), styles["kicker"])],
            [Paragraph(escape_html(project_name), styles["title"])],
            [Paragraph(escape_html(meta["subtitle"]), styles["subtitle"])],
        ],
        colWidths=[CONTENT_WIDTH * 0.68],
    )
    left.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    right = Table(
        [
            [Paragraph(BRAND_URL, brand_style)],
            [Paragraph(escape_html(meta["footer_label"]), styles["panel_meta"])],
        ],
        colWidths=[CONTENT_WIDTH * 0.32],
    )
    right.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    row = Table([[left, right]], colWidths=[CONTENT_WIDTH * 0.68, CONTENT_WIDTH * 0.32])
    row.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(row)
    story.append(Spacer(1, 0.06 * inch))


def panel_wrap(title: str, meta: str, body: Flowable, *, styles: Dict[str, ParagraphStyle]) -> Table:
    head = Table(
        [
            [
                Paragraph(escape_html(title), styles["panel_title"]),
                Paragraph(escape_html(meta), styles["panel_meta"]),
            ]
        ],
        colWidths=[CONTENT_WIDTH * 0.72, CONTENT_WIDTH * 0.28],
    )
    head.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_WHITE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, 0), (-1, -1), 0.6, COLOR_BORDER),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ]
        )
    )
    wrap = Table([[head], [body]], colWidths=[CONTENT_WIDTH])
    wrap.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, COLOR_BORDER),
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_WHITE),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("ROUNDEDCORNERS", [8, 8, 8, 8]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return wrap


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def append_executive_summary(
    story: List[Any],
    *,
    report_key: str,
    overview_rows: Sequence[Tuple[str, str]],
    severity_counts: Dict[str, int],
    styles: Optional[Dict[str, ParagraphStyle]] = None,
    extra_tables: Optional[Sequence[Tuple[str, Sequence[str], Sequence[Sequence[Any]], Optional[List[float]]]]] = None,
    project_name: Optional[str] = None,
    scan_time: Optional[str] = None,
    meta_chips: Optional[Sequence[Tuple[str, str]]] = None,
) -> None:
    styles = styles or get_report_styles()
    meta = REPORT_META.get(report_key, REPORT_META["sast"])

    # Derive project name from overview if not provided
    proj = project_name or "Security Scan"
    for label, value in overview_rows:
        if label.lower() in {"project", "application", "target", "scan type"} and value:
            if not project_name and label.lower() != "scan type":
                proj = str(value)
            break

    append_report_masthead(
        story,
        report_key=report_key,
        project_name=proj if project_name else meta["title"],
        styles=styles,
    )

    # Meta chips — denser: up to 4 + always surface platform URL when space
    chips: List[Tuple[str, str]] = list(meta_chips or [])
    if not chips:
        prefer = ("project", "scan type", "report generated", "scan duration", "scan timestamp", "engine version", "scan engine")
        used = set()
        for want in prefer:
            for label, value in overview_rows:
                if label.lower() == want and value and label.lower() not in used:
                    chips.append((label, str(value)))
                    used.add(label.lower())
                    break
        chips = chips[:3]
        chips.append(("Platform", BRAND_URL))
    if chips:
        story.append(build_meta_strip(chips[:4], styles=styles))
        story.append(Spacer(1, 0.06 * inch))

    critical = _count_sev(severity_counts, "Critical")
    high = _count_sev(severity_counts, "High", "ERROR")
    medium = _count_sev(severity_counts, "Medium", "WARNING")
    low = _count_sev(severity_counts, "Low", "INFO")
    total = sum(int(v or 0) for v in severity_counts.values())
    if total == 0:
        total = critical + high + medium + low

    time_label = scan_time or "—"
    if not scan_time:
        for label, value in overview_rows:
            if "duration" in label.lower() or "scan time" in label.lower():
                time_label = str(value)
                break

    risk_score, risk_grade, risk_band = compute_risk_score(critical, high, medium, low)

    story.append(
        build_kpi_grid(
            total_issues=total,
            critical=critical,
            high=high,
            scan_time=time_label,
            styles=styles,
            total_hint=f"{critical} C · {high} H · {medium} M · {low} L",
            risk_score=risk_score,
            risk_grade=risk_grade,
            risk_band=risk_band,
        )
    )
    story.append(Spacer(1, 0.06 * inch))
    story.append(
        build_severity_bar(
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            styles=styles,
        )
    )
    story.append(Spacer(1, 0.05 * inch))

    # Dense guidance block: intro + how-to-read + severity meanings for present severities
    guide_bits: List[Any] = [
        Paragraph(meta["intro"], styles["body"]),
        Paragraph(f"<b>How to read:</b> {escape_html(meta.get('how_to_read', ''))}", styles["muted"]),
        Paragraph(
            f"<b>Platform:</b> {BRAND_NAME} · <font color='#0F766E'><b>{BRAND_URL}</b></font>",
            styles["muted"],
        ),
    ]
    present = []
    if critical:
        present.append(("Critical", severity_meaning("Critical")))
    if high:
        present.append(("High", severity_meaning("High")))
    if medium:
        present.append(("Medium", severity_meaning("Medium")))
    if low:
        present.append(("Low", severity_meaning("Low")))
    if present:
        guide_bits.append(Spacer(1, 3))
        guide_bits.append(Paragraph("SEVERITY GUIDANCE", styles["section_kicker"]))
        for label, meaning in present:
            guide_bits.append(
                Paragraph(
                    f"<b>{escape_html(label)}:</b> {escape_html(meaning)}",
                    styles["muted"],
                )
            )
    story.append(card_shell(padded_block(guide_bits, pad=8, width=CONTENT_WIDTH - 14)))
    story.append(Spacer(1, 0.06 * inch))

    if critical or high:
        parts = []
        if critical:
            parts.append(f"{critical} Critical")
        if high:
            parts.append(f"{high} High")
        note = padded_block(
            [
                Paragraph(
                    f"<b>Priority action:</b>  {' · '.join(parts)}  — remediate these items first. "
                    f"Full findings catalog and evidence follow. More at {BRAND_URL}.",
                    styles["body"],
                )
            ],
            pad=8,
            width=CONTENT_WIDTH - 16,
        )
        story.append(card_shell(note, severity="High" if high or critical else ""))
        story.append(Spacer(1, 0.06 * inch))

    if extra_tables:
        for title, headers, rows, widths in extra_tables:
            if not rows:
                continue
            story.append(Paragraph(title, styles["heading"]))
            story.append(styled_data_table(headers, rows, styles=styles, col_widths=widths))


def append_findings_catalog(
    story: List[Any],
    *,
    catalog_rows: Sequence[Sequence[Any]],
    styles: Optional[Dict[str, ParagraphStyle]] = None,
    col_widths: Optional[List[float]] = None,
    panel_title: str = "Findings Catalog",
) -> None:
    styles = styles or get_report_styles()
    if not catalog_rows:
        story.append(
            panel_wrap(
                panel_title,
                "0 issues",
                padded_block([Paragraph("No security findings were identified in this scan.", styles["body"])], pad=14, width=CONTENT_WIDTH - 8),
                styles=styles,
            )
        )
        return

    normalized: List[List[Any]] = []
    for row in catalog_rows:
        cells = list(row)
        if len(cells) >= 4 and not isinstance(cells[3], Table):
            loc = cells[3]
            if not isinstance(loc, Paragraph):
                cells[3] = Paragraph(escape_html(str(loc)), styles["mono_cell"])
        normalized.append(cells)

    table = styled_data_table(
        ["#", "Severity", "Finding", "Location"],
        normalized,
        styles=styles,
        col_widths=col_widths or [0.35 * inch, 0.85 * inch, 3.55 * inch, 2.25 * inch],
        severity_col=1,
    )
    # strip outer box from table — panel provides it
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0, COLOR_WHITE),
            ]
        )
    )
    story.append(panel_wrap(panel_title, f"{len(normalized)} issues", table, styles=styles))


def build_finding_section(
    *,
    index: int,
    title: str,
    severity: str,
    detail_rows: Sequence[Tuple[str, str]],
    description: str = "",
    evidence: str = "",
    recommended_fix: str = "",
    standards_rows: Optional[Sequence[Sequence[str]]] = None,
    styles: Optional[Dict[str, ParagraphStyle]] = None,
) -> KeepTogether:
    styles = styles or get_report_styles()
    blocks: List[Any] = []

    heading = f"#{index}  {title}" if index >= 1 else title
    header = Table(
        [
            [
                severity_badge(severity, styles),
                Paragraph(escape_html(heading), styles["finding_title"]),
            ]
        ],
        colWidths=[0.82 * inch, CONTENT_WIDTH - 3.0 - 0.82 * inch - 22],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    blocks.append(header)
    blocks.append(Spacer(1, 6))

    details = list(detail_rows)
    if not any(k.lower() == "severity" for k, _ in details):
        details.insert(0, ("Severity", severity_label(severity)))
    mono_labels = {
        "where it was found",
        "affected package(s)",
        "affected url",
        "cve ids",
        "rule / check",
        "file",
        "location",
        "packages",
        "url",
        "check id",
    }
    blocks.append(
        key_value_table(
            details,
            styles=styles,
            mono_labels=[k for k, _ in details if k.lower() in mono_labels],
            label_width=1.35 * inch,
            value_width=CONTENT_WIDTH - 3.0 - 1.35 * inch - 24,
        )
    )

    if description:
        blocks.append(Spacer(1, 6))
        blocks.append(Paragraph("DESCRIPTION", styles["section_kicker"]))
        blocks.append(Paragraph(escape_html(description), styles["body"]))

    if evidence:
        blocks.append(Spacer(1, 4))
        blocks.append(Paragraph("EVIDENCE", styles["section_kicker"]))
        code_text = evidence.strip()
        if len(code_text) > 700:
            code_text = code_text[:700] + "..."
        code_text = "\n".join(code_text.split("\n")[:14])
        code_box = Table(
            [[Preformatted(escape_html(code_text), styles["code"], maxLineLength=90)]],
            colWidths=[CONTENT_WIDTH - 3.0 - 28],
        )
        code_box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E293B")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                ]
            )
        )
        blocks.append(code_box)

    if recommended_fix:
        blocks.append(Spacer(1, 6))
        blocks.append(Paragraph("REMEDIATION", styles["section_kicker"]))
        blocks.append(Paragraph(escape_html(recommended_fix), styles["body"]))

    if standards_rows:
        blocks.append(Spacer(1, 6))
        blocks.append(Paragraph("MAPPINGS", styles["section_kicker"]))
        mapped: List[List[Any]] = []
        for row in standards_rows:
            if len(row) >= 2:
                mapped.append(
                    [
                        Paragraph(escape_html(str(row[0])), styles["table_label"]),
                        Paragraph(escape_html(str(row[1])), styles["mono_cell"]),
                    ]
                )
        if mapped:
            map_table = Table(mapped, colWidths=[1.35 * inch, CONTENT_WIDTH - 3.0 - 1.35 * inch - 24])
            map_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), COLOR_HEADER_SOFT),
                        ("LINEBELOW", (0, 0), (-1, -2), 0.4, COLOR_BORDER),
                        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            blocks.append(map_table)

    inner = padded_block(blocks, pad=12, width=CONTENT_WIDTH - 18)
    card = card_shell(inner, severity=severity)
    return KeepTogether([card, Spacer(1, 0.12 * inch)])


# ---------------------------------------------------------------------------
# Back-compat aliases
# ---------------------------------------------------------------------------


def styled_metric_table(rows: Sequence[Sequence[Any]], col_widths: Optional[List[float]] = None) -> Table:
    styles = get_report_styles()
    if not rows:
        return Table([[""]])
    headers = [str(c) for c in rows[0]]
    body = [list(r) for r in rows[1:]]
    return styled_data_table(headers, body, styles=styles, col_widths=col_widths)


def append_findings_index(
    story: List[Any],
    *,
    index_rows: Sequence[Sequence[Any]],
    styles: Optional[Dict[str, ParagraphStyle]] = None,
) -> None:
    rows = list(index_rows)
    catalog = rows[1:] if rows and str(rows[0][0]).strip() in {"#", "No."} else rows
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)


def build_finding_card(
    *,
    index: int,
    title: str,
    severity: str,
    meta_items: Sequence[Tuple[str, str]],
    description: str = "",
    evidence: str = "",
    recommended_fix: str = "",
    secondary_lines: Optional[Sequence[str]] = None,
    styles: Optional[Dict[str, ParagraphStyle]] = None,
) -> KeepTogether:
    standards: List[List[str]] = []
    if secondary_lines:
        for line in secondary_lines:
            if ":" in line:
                left, right = line.split(":", 1)
                standards.append([left.strip(), right.strip()])
            elif line:
                standards.append(["Note", line])
    return build_finding_section(
        index=index,
        title=title,
        severity=severity,
        detail_rows=list(meta_items),
        description=description,
        evidence=evidence,
        recommended_fix=recommended_fix,
        standards_rows=standards or None,
        styles=styles,
    )


def priority_note(by_severity: Dict[str, int], styles: Dict[str, ParagraphStyle]) -> Optional[Paragraph]:
    critical = by_severity.get("Critical", 0) + by_severity.get("CRITICAL", 0)
    high = by_severity.get("High", 0) + by_severity.get("HIGH", 0) + by_severity.get("ERROR", 0)
    if not critical and not high:
        return None
    parts = []
    if critical:
        parts.append(f"{critical} Critical")
    if high:
        parts.append(f"{high} High")
    return Paragraph(f"<b>Priority:</b>  {' · '.join(parts)}", styles["body"])
