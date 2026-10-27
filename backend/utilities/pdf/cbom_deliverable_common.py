"""Shared scaffolding for the six team-wide CBOM regulatory PDFs (WP2).

Helpers on top of ``report_branding`` (same palette, pills, KPI cards, header and footer) that
the six renderers (``cbom_*_pdf.py``) share:

* ``pdf_text`` / ``pdf_plain``: the ONLY way untrusted strings (certificate names, repository
  URLs, titles, attestation notes) may enter a document.  Scanned repositories are untrusted
  input and reportlab ``Paragraph`` parses mini-HTML (``<img src=...>``, ``<font>``, ``<a>``),
  so every data-derived string is sanitised, clamped and escaped here.
* ``fmt_utc_ist`` / ``fmt_date_utc`` / ``document_id``: deterministic dates and identifiers.
* ``build_document``: the document shell (metadata, page chrome, masthead, document-control
  table, Basis box, disclaimers, banners, "(assessor)" legend) around a renderer's ``body``.
* ``dense_table`` / ``kpi_strip`` / ``status_chip`` / ``manual_form`` / ``signoff_block``:
  the building blocks the renderers compose.

Escaping contract (read this before using a helper).  ``pdf_text`` returns text that is already
HTML-escaped: use it for ``Paragraph(...)``.  ``pdf_plain`` returns sanitised but NOT escaped
text: use it for report_branding helpers that call ``escape_html`` themselves and for PDF
metadata.  The helpers in this module take RAW values and sanitise them, so never pre-escape
what you hand to ``dense_table`` / ``kpi_strip`` / ``status_chip`` / ``manual_form`` (that would
double-escape).  Pass ready-made ``Paragraph`` objects when you need your own markup.

Hard rules: reportlab and the standard library only, no network, no language-model calls, no
wall clock (``generated_at`` / ``as_of`` come from the view), Helvetica/Courier only (so the
fonts match every existing report), Python 3.10 syntax.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from datetime import date, datetime, timedelta, timezone
from functools import cache, lru_cache
from io import BytesIO
from math import ceil
from typing import Any

from reportlab.lib import pagesizes
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.utilities.dashboard.cbom_team_rollup import (
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.report_branding import (
    BAR_LOW,
    BAR_MEDIUM,
    BAR_UNKNOWN,
    BRAND_NAME,
    BRAND_TEAL,
    BRAND_URL,
    COLOR_BORDER,
    COLOR_BORDER_STRONG,
    COLOR_HEADER_SOFT,
    COLOR_ROW_ALT,
    COLOR_WHITE,
    KPI_ACCENT_CRITICAL,
    KPI_ACCENT_HIGH,
    KPI_ACCENT_TOTAL,
    PILL_CRITICAL_BD,
    PILL_CRITICAL_BG,
    PILL_CRITICAL_FG,
    PILL_HIGH_BD,
    PILL_HIGH_BG,
    PILL_HIGH_FG,
    PILL_LOW_BD,
    PILL_LOW_BG,
    PILL_LOW_FG,
    PILL_MEDIUM_BD,
    PILL_MEDIUM_BG,
    PILL_MEDIUM_FG,
    PILL_UNKNOWN_BD,
    PILL_UNKNOWN_BG,
    PILL_UNKNOWN_FG,
    REPORT_META,
    _kpi_card,
    escape_html,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
)

TEMPLATE_VERSION = "1.0"

Styles = dict[str, ParagraphStyle]

_DASH = "\u2014"
_MARGIN_X = 36
_MARGIN_TOP = 56
_MARGIN_BOTTOM = 52
_DEFAULT_FORM_WIDTH = 540.0

# ---------------------------------------------------------------------------------------------
# Text sanitiser: str() -> strip controls -> NFC/NFKC -> WinAnsi map -> clamp -> escape
# ---------------------------------------------------------------------------------------------
# C0 controls (except TAB/LF/CR/VT/FF, which become spaces), DEL and C1 controls (except NEL).
_CTRL_RE = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x84\x86-\x9f]")
_SPACE_RE = re.compile("[\t\n\r\x0b\x0c\x85\u2028\u2029]")
# The printable characters of Windows-1252 beyond Latin-1 (what Helvetica's WinAnsi can draw).
_WINANSI_EXTRA = frozenset(
    "\u20ac\u201a\u0192\u201e\u2026\u2020\u2021\u02c6\u2030\u0160\u2039\u0152\u017d"
    "\u2018\u2019\u201c\u201d\u2022\u2013\u2014\u02dc\u2122\u0161\u203a\u0153\u017e\u0178"
)
# Symbols that appear in findings and reports but have no WinAnsi glyph (decision D-09).
_SYMBOL_MAP = {
    "\u2264": "<=",
    "\u2265": ">=",
    "\u2260": "!=",
    "\u2248": "~",
    "\u2192": "->",
    "\u2190": "<-",
    "\u2194": "<->",
    "\u21d2": "=>",
    "\u2713": "Yes",
    "\u2714": "Yes",
    "\u2717": "No",
    "\u2718": "No",
    "\u2715": "No",
    "\u2716": "No",
    "\u2212": "-",
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2015": "-",
    "\u2032": "'",
    "\u2033": '"',
    "\u2044": "/",
}
# Processing is bounded to this many input characters per output character allowed, so a
# megabyte-sized hostile string costs microseconds (NFKC and the map never expand more).
_WORK_FACTOR = 8


def _is_winansi(ch: str) -> bool:
    code = ord(ch)
    return 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF or ch in _WINANSI_EXTRA


def _fold_winansi(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if _is_winansi(ch):
            out.append(ch)
            continue
        mapped = _SYMBOL_MAP.get(ch)
        if mapped is not None:
            out.append(mapped)
            continue
        for part in unicodedata.normalize("NFKC", ch):
            out.append(part if _is_winansi(part) else _SYMBOL_MAP.get(part, "?"))
    return "".join(out)


def pdf_plain(value: object, *, limit: int = 300) -> str:
    """Sanitised, clamped, NOT escaped text (for helpers that escape, and PDF metadata).

    ``None`` becomes ``""``.  C0/C1 controls and NUL are removed; tabs and line breaks become a
    space; the text is NFC-composed and every character Helvetica cannot draw is folded to
    ASCII (``>=``, ``->``, ``Yes``) or ``?`` (one per code point).  Longer than ``limit``
    characters it is cut and ends with an ellipsis, so the result never exceeds ``limit``.
    """
    if limit <= 0:
        return ""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _SPACE_RE.sub(" ", _CTRL_RE.sub("", text))
    bound = limit * _WORK_FACTOR + 32
    if len(text) > bound:
        text = text[:bound]
    text = _fold_winansi(unicodedata.normalize("NFC", text))
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text


def pdf_text(value: object, *, limit: int = 300) -> str:
    """``pdf_plain`` followed by HTML escaping: safe to hand to ``Paragraph``.

    Escaping is the LAST step, so markup (``<img src=...>``, ``<font>``, ``&lt;``) and
    markup smuggled in through Unicode look-alikes (full-width ``<``) renders literally.
    """
    return escape_html(pdf_plain(value, limit=limit))


_NEWLINE_RE = re.compile(r"\r\n|\r|\n")


def pdf_multiline(value: object, *, limit: int = 300, max_lines: int = 12) -> str:
    """Like ``pdf_text`` but keeps line breaks: each ``\\n`` becomes a ``<br/>``.

    Every line is sanitised and escaped on its own, so ``<br/>`` is the only markup that can
    appear in the result.  ``limit`` is the TOTAL number of displayed characters across all
    lines and ``max_lines`` the number of lines; whichever is exceeded ends the text with an
    ellipsis.  Use it for Paragraph cells that deliberately span several lines (a certificate
    name over its file name, a list of locations).
    """
    if limit <= 0 or max_lines <= 0:
        return ""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _CTRL_RE.sub("", text)
    bound = limit * _WORK_FACTOR + 32
    if len(text) > bound:
        text = text[:bound]
    lines: list[str] = []
    remaining = limit
    cut = False
    for index, line in enumerate(_NEWLINE_RE.split(text)):
        if index >= max_lines or remaining <= 0:
            cut = True
            break
        clean = pdf_plain(line, limit=remaining)
        lines.append(clean)
        remaining -= len(clean)
    if cut and lines and not lines[-1].endswith("\u2026"):
        lines[-1] += "\u2026"
    return "<br/>".join(escape_html(line) for line in lines)


# ---------------------------------------------------------------------------------------------
# Dates and identifiers (no wall clock, no tz database: IST is a fixed +05:30 offset)
# ---------------------------------------------------------------------------------------------
_IST = timezone(timedelta(hours=5, minutes=30), "IST")


def _to_utc(dt: datetime) -> datetime:
    """Naive datetimes are UTC (Postgres returns naive UTC); aware ones are converted."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ymd(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}-{d.day:02d}"


def fmt_utc_ist(dt: datetime | date | None) -> str:
    """``2026-10-19 12:28 UTC (17:58 IST)``.

    Seconds are dropped.  When IST falls on a different calendar day the IST date is spelled
    out: ``2026-10-19 20:00 UTC (2026-10-20 01:30 IST)``.  A bare ``date`` renders as
    ``YYYY-MM-DD``; ``None`` or anything else as an em dash.
    """
    if isinstance(dt, datetime):
        try:
            utc = _to_utc(dt)
            ist = utc.astimezone(_IST)
        except (OverflowError, ValueError):
            return _DASH
        ist_clock = f"{ist.hour:02d}:{ist.minute:02d} IST"
        if ist.date() != utc.date():
            ist_clock = f"{_ymd(ist)} {ist_clock}"
        return f"{_ymd(utc)} {utc.hour:02d}:{utc.minute:02d} UTC ({ist_clock})"
    if isinstance(dt, date):
        return _ymd(dt)
    return _DASH


def fmt_date_utc(dt: datetime | date | None) -> str:
    """``YYYY-MM-DD`` in UTC (naive datetimes are UTC); an em dash when there is no date."""
    if isinstance(dt, datetime):
        try:
            return _ymd(_to_utc(dt))
        except (OverflowError, ValueError):
            return _DASH
    if isinstance(dt, date):
        return _ymd(dt)
    return _DASH


def document_id(view: TeamCbomView, number: int) -> str:
    """``CBOM-D07-T1-20261019-ab12cd34``: deliverable number, team, as-of day, data fingerprint.

    The fingerprint part is the first 8 hex characters of ``view.fingerprint`` (padded with
    zeros when it is shorter or empty), so the same scan set always yields the same ID.
    """
    fingerprint = re.sub(r"[^0-9a-f]", "", str(view.fingerprint or "").lower())[:8]
    day = view.as_of
    stamp = f"{day.year:04d}{day.month:02d}{day.day:02d}"
    return f"CBOM-D{int(number):02d}-T{int(view.team_id)}-{stamp}-{fingerprint.ljust(8, '0')}"


def _pdf_date(dt: datetime) -> str:
    utc = _to_utc(dt)
    return (
        f"D:{utc.year:04d}{utc.month:02d}{utc.day:02d}"
        f"{utc.hour:02d}{utc.minute:02d}{utc.second:02d}+00'00'"
    )


# ---------------------------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------------------------
def get_deliverable_styles() -> Styles:
    """``get_report_styles()`` plus the dense / box styles the deliverables use."""
    styles = get_report_styles()
    styles["dense_cell"] = ParagraphStyle(
        "DenseCell", parent=styles["table_cell"], fontSize=7, leading=8.6, splitLongWords=1
    )
    styles["dense_header"] = ParagraphStyle(
        "DenseHeader", parent=styles["table_header"], fontSize=6.8, leading=8.2
    )
    styles["dense_mono"] = ParagraphStyle(
        "DenseMono", parent=styles["mono_cell"], fontSize=6.5, leading=8, splitLongWords=1
    )
    styles["dense_muted"] = ParagraphStyle(
        "DenseMuted", parent=styles["muted"], fontSize=7, leading=8.6, spaceAfter=0
    )
    styles["box_title"] = ParagraphStyle(
        "BoxTitle", parent=styles["table_label"], fontSize=8.5, leading=11
    )
    styles["box_text"] = ParagraphStyle(
        "BoxText", parent=styles["table_cell"], fontSize=8, leading=10.5, alignment=TA_LEFT
    )
    # Same look as "heading", but it does not drag the next flowable along with it: a heading
    # followed by a long (splittable) table would otherwise jump to a new page and leave a gap.
    styles["section_heading"] = ParagraphStyle(
        "SectionHeading", parent=styles["heading"], keepWithNext=0
    )
    styles["masthead_label"] = ParagraphStyle(
        "MastheadLabel", parent=styles["panel_meta"], alignment=TA_RIGHT
    )
    return styles


def section_heading(text: object, styles: Styles, *, min_space: float = 90) -> list[Flowable]:
    """``[CondPageBreak, heading]``: a section heading that is never stranded at a page bottom.

    The page breaks only when less than ``min_space`` points remain (room for the heading plus
    a table header and a row); otherwise the heading and whatever follows start right here,
    however long it is.  Extend a body with ``*section_heading("2 Register", styles)``.
    """
    heading = Paragraph(pdf_text(text, limit=160), styles["section_heading"])
    return [CondPageBreak(min_space), heading]


@lru_cache(maxsize=1)
def _shared_styles() -> Styles:
    return get_deliverable_styles()


# ---------------------------------------------------------------------------------------------
# Chips, tones
# ---------------------------------------------------------------------------------------------
_CHIP_PALETTE = {
    "critical": (PILL_CRITICAL_BG, PILL_CRITICAL_FG, PILL_CRITICAL_BD),
    "high": (PILL_HIGH_BG, PILL_HIGH_FG, PILL_HIGH_BD),
    "medium": (PILL_MEDIUM_BG, PILL_MEDIUM_FG, PILL_MEDIUM_BD),
    "low": (PILL_LOW_BG, PILL_LOW_FG, PILL_LOW_BD),
    "unknown": (PILL_UNKNOWN_BG, PILL_UNKNOWN_FG, PILL_UNKNOWN_BD),
}
_KPI_ACCENT = {
    "critical": KPI_ACCENT_CRITICAL,
    "high": KPI_ACCENT_HIGH,
    "medium": BAR_MEDIUM,
    "low": BAR_LOW,
    "unknown": BAR_UNKNOWN,
}


def _tone_key(tone: object) -> str:
    key = tone.strip().lower() if isinstance(tone, str) else ""
    return key if key in _CHIP_PALETTE else "unknown"


def tone_for_impact(impact: object) -> str:
    """Chip tone for an impact bucket (``Critical``/``High``/``Medium``/``Low``)."""
    return _tone_key(impact)


@cache
def _chip_style(tone: str) -> ParagraphStyle:
    background, foreground, border = _CHIP_PALETTE[tone]
    return ParagraphStyle(
        f"Chip_{tone}",
        parent=_shared_styles()["badge"],
        fontName="Helvetica-Bold",
        fontSize=6.5,
        leading=8,
        alignment=TA_CENTER,
        textColor=foreground,
        backColor=background,
        borderColor=border,
        borderWidth=0.6,
        borderPadding=(1.5, 2, 1.5, 2),
        borderRadius=4,
    )


def status_chip(text: object, tone: str = "unknown") -> Paragraph:
    """A coloured pill that ALWAYS carries text (a state is never conveyed by colour alone).

    ``tone`` is ``critical|high|medium|low|unknown`` (anything else is ``unknown``).  Empty
    text falls back to the tone name.  Pass RAW text: it is sanitised and escaped here.
    """
    key = _tone_key(tone)
    label = pdf_plain(text, limit=40).strip() or key.upper()
    return Paragraph(escape_html(label), _chip_style(key))


# ---------------------------------------------------------------------------------------------
# dense_table
# ---------------------------------------------------------------------------------------------
_DENSE_PAD = 3
# The widest Helvetica glyphs (W, @) are about one em wide: 7 pt at the dense font size.  A
# cell whose worst-case wrapped height fits needs no measuring at all.
_WIDEST_GLYPH = 7.0
_TALL = 1_000_000.0


def _is_flowable_cell(value: Any) -> bool:
    if isinstance(value, Flowable):
        return True
    return (
        isinstance(value, (list, tuple))
        and len(value) > 0
        and all(isinstance(item, Flowable) for item in value)
    )


def _worst_case_lines(markup: str, usable: float) -> int:
    per_line = max(1, int(usable // _WIDEST_GLYPH))
    return sum(max(1, ceil(len(part) / per_line)) for part in markup.split("<br/>"))


def _fit_cell(value: Any, width: float, styles: Styles, limit: int, max_height: float) -> Any:
    """A dense Paragraph that is guaranteed not to be taller than ``max_height`` points.

    Table rows cannot split across pages, so one hostile cell (300 wide glyphs in a 20 pt
    column) must never be allowed to build a row taller than a page.  Normal cells are
    accepted on a cheap worst-case bound; only the rare long cell is measured, and if it is
    too tall the text is shortened (with an ellipsis) to the longest prefix that fits.
    """
    style = styles["dense_cell"]
    usable = max(float(width) - 2 * _DENSE_PAD, 1.0)
    markup = pdf_multiline(value, limit=limit)
    if _worst_case_lines(markup, usable) * style.leading <= max_height:
        return Paragraph(markup, style)
    paragraph = Paragraph(markup, style)
    if paragraph.wrap(usable, _TALL)[1] <= max_height:
        return paragraph
    low, high = 1, limit
    while low < high:
        mid = (low + high + 1) // 2
        trial = Paragraph(pdf_multiline(value, limit=mid), style)
        if trial.wrap(usable, _TALL)[1] <= max_height:
            low = mid
        else:
            high = mid - 1
    return Paragraph(pdf_multiline(value, limit=low), style)


def dense_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    col_widths: Sequence[float],
    *,
    manual_cols: Sequence[int] = (),
    repeat: int = 1,
    cell_limit: int = 300,
    max_cell_height: float = 180,
) -> Table:
    """Register-style table: 7 pt text, 3 pt padding, tinted header, repeated header rows.

    ``headers`` and ``rows`` hold RAW values: strings, numbers and ``None`` are sanitised,
    clamped to ``cell_limit`` characters and escaped (a ``\\n`` inside a string is a real line
    break); ready-made flowables (a ``status_chip``, your own ``Paragraph``) pass through
    untouched.  A text cell never grows taller than ``max_cell_height`` points: if it would
    (a long value in a narrow column) it is shortened with an ellipsis.  ``manual_cols`` are
    the indices of MANUAL columns: their header gains the ``(assessor)`` suffix (unless it
    already has it) and the whole column is amber-tinted and boxed so it reads as "fill in
    here".  With no rows the table shows a single spanned "No entries" line rather than a bare
    header.  ``repeat`` header rows are repeated on every page the table spans.
    """
    ncols = len(headers)
    if ncols == 0:
        raise ValueError("dense_table needs at least one column (headers is empty)")
    if len(col_widths) != ncols:
        raise ValueError(f"col_widths has {len(col_widths)} entries for {ncols} headers")
    body_rows = [list(row) for row in rows]
    for index, row in enumerate(body_rows):
        if len(row) != ncols:
            raise ValueError(f"row {index} has {len(row)} cells for {ncols} headers")
    manual = sorted({c for c in manual_cols if isinstance(c, int) and 0 <= c < ncols})
    styles = _shared_styles()

    head: list[Any] = []
    for col, header in enumerate(headers):
        label = pdf_plain(header, limit=80)
        if col in manual and authored.ASSESSOR_SUFFIX not in label:
            label = f"{label} {authored.ASSESSOR_SUFFIX}".strip()
        head.append(Paragraph(escape_html(label), styles["dense_header"]))
    data: list[list[Any]] = [head]
    commands: list[tuple] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), _DENSE_PAD),
        ("RIGHTPADDING", (0, 0), (-1, -1), _DENSE_PAD),
        ("TOPPADDING", (0, 0), (-1, -1), _DENSE_PAD),
        ("BOTTOMPADDING", (0, 0), (-1, -1), _DENSE_PAD),
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_SOFT),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, COLOR_BORDER_STRONG),
        ("LINEBELOW", (0, 1), (-1, -1), 0.4, COLOR_BORDER),
        ("BOX", (0, 0), (-1, -1), 0.6, COLOR_BORDER),
    ]
    if body_rows:
        for row in body_rows:
            data.append(
                [
                    value
                    if _is_flowable_cell(value)
                    else _fit_cell(value, width, styles, cell_limit, max_cell_height)
                    for value, width in zip(row, col_widths, strict=True)
                ]
            )
        commands.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_ROW_ALT]))
    else:
        placeholder = Paragraph(pdf_text(authored.EMPTY_TABLE_TEXT), styles["dense_muted"])
        data.append([placeholder] + [""] * (ncols - 1))
        commands.append(("BACKGROUND", (0, 1), (-1, 1), COLOR_WHITE))
        if ncols > 1:
            commands.append(("SPAN", (0, 1), (-1, 1)))
    for col in manual:
        commands.append(("BACKGROUND", (col, 0), (col, -1), PILL_MEDIUM_BG))
        commands.append(("BOX", (col, 0), (col, -1), 0.6, COLOR_BORDER_STRONG))
        commands.append(("INNERGRID", (col, 1), (col, -1), 0.4, COLOR_BORDER_STRONG))

    repeat_rows = max(0, min(int(repeat), len(data) - 1))
    table = Table(data, colWidths=list(col_widths), repeatRows=repeat_rows, hAlign="LEFT")
    table.setStyle(TableStyle(commands))
    return table


# ---------------------------------------------------------------------------------------------
# kpi_strip
# ---------------------------------------------------------------------------------------------
_KPI_GAP = 6


def _kpi_row(cards: list[tuple[str, str, str, Any]], width: float, styles: Styles) -> Table:
    card_width = (width - _KPI_GAP * (len(cards) - 1)) / len(cards)
    cells: list[Any] = []
    widths: list[float] = []
    for index, (label, value, hint, accent) in enumerate(cards):
        if index:
            cells.append("")
            widths.append(_KPI_GAP)
        cells.append(_kpi_card(label, value, hint, accent, styles, card_width))
        widths.append(card_width)
    row = Table([cells], colWidths=widths, hAlign="LEFT")
    row.setStyle(
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
    return row


def kpi_strip(
    cards: Sequence[Sequence[str]], width: float, *, max_per_row: int = 6
) -> Table:
    """A row of KPI cards (the existing report card look) spanning ``width`` points.

    Each card is ``(label, value, hint)`` or ``(label, value, hint, tone)`` with ``tone`` one of
    ``critical|high|medium|low|unknown`` (default: the brand teal).  More than ``max_per_row``
    cards wrap into evenly filled rows.  Pass RAW text: it is sanitised and clamped here
    (label 40, value 24, hint 120 characters) and escaped by the card.
    """
    styles = _shared_styles()
    normalised: list[tuple[str, str, str, Any]] = []
    for card in cards:
        parts = list(card) + [""] * (3 - len(card))
        tone = parts[3] if len(parts) > 3 else None
        accent = _KPI_ACCENT[_tone_key(tone)] if tone else KPI_ACCENT_TOTAL
        normalised.append(
            (
                pdf_plain(parts[0], limit=40),
                pdf_plain(parts[1], limit=24),
                pdf_plain(parts[2], limit=120),
                accent,
            )
        )
    if not normalised:
        return Table([[""]], colWidths=[width], hAlign="LEFT")
    per_row = max(1, int(max_per_row))
    row_count = ceil(len(normalised) / per_row)
    base, extra = divmod(len(normalised), row_count)
    rows: list[Table] = []
    start = 0
    for index in range(row_count):
        size = base + (1 if index < extra else 0)
        rows.append(_kpi_row(normalised[start : start + size], width, styles))
        start += size
    if len(rows) == 1:
        return rows[0]
    outer = Table([[row] for row in rows], colWidths=[width], hAlign="LEFT")
    outer.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (0, -2), _KPI_GAP),
                ("BOTTOMPADDING", (0, -1), (0, -1), 0),
            ]
        )
    )
    return outer


# ---------------------------------------------------------------------------------------------
# manual_form / signoff_block
# ---------------------------------------------------------------------------------------------
_FORM_ROW_HEIGHT = 22
_SIGNOFF_ROW_HEIGHT = 32


def _form_table(
    header: list[Any], blank_rows: list[list[Any]], widths: list[float], row_height: float
) -> Table:
    data = [header, *blank_rows]
    table = Table(
        data,
        colWidths=widths,
        repeatRows=1 if blank_rows else 0,
        minRowHeights=[0] + [row_height] * len(blank_rows),
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), _DENSE_PAD),
                ("RIGHTPADDING", (0, 0), (-1, -1), _DENSE_PAD),
                ("TOPPADDING", (0, 0), (-1, -1), _DENSE_PAD),
                ("BOTTOMPADDING", (0, 0), (-1, -1), _DENSE_PAD),
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_HEADER_SOFT),
                ("BACKGROUND", (0, 1), (-1, -1), PILL_MEDIUM_BG),
                ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_STRONG),
            ]
        )
    )
    return table


def _form_heading(title: str | None, styles: Styles) -> list[Flowable]:
    parts: list[Flowable] = []
    if title:
        parts.append(Paragraph(pdf_text(title, limit=120), styles["heading"]))
    parts.append(Paragraph(pdf_text(authored.MANUAL_CELL_NOTE), styles["muted"]))
    return parts


def manual_form(
    title: str, columns: Sequence[str], blank_rows: int, *, width: float | None = None
) -> Flowable:
    """A titled write-in table: ``columns`` headers over ``blank_rows`` empty amber rows.

    Always carries the note "To be completed by assessor".  ``width`` is the table width in
    points (default: a portrait page, 540); columns share it equally.  Kept together on one
    page when it fits.
    """
    styles = _shared_styles()
    labels = [pdf_plain(c, limit=60) for c in columns] or [""]
    total = float(width) if width else _DEFAULT_FORM_WIDTH
    header = [Paragraph(escape_html(label), styles["dense_header"]) for label in labels]
    blanks = [[""] * len(labels) for _ in range(max(0, int(blank_rows)))]
    table = _form_table(header, blanks, [total / len(labels)] * len(labels), _FORM_ROW_HEIGHT)
    return KeepTogether([*_form_heading(title, styles), table])


def signoff_block(
    roles: Sequence[str], *, title: str | None = "Sign-off", width: float | None = None
) -> Flowable:
    """Sign-off table: one row per role with blank Name, Role, Date and Signature cells.

    ``roles`` are the capacities that sign (for example ``Prepared by``).  With no roles one
    blank row is still offered.  Pass ``title=None`` when the caller already printed a heading.
    """
    styles = _shared_styles()
    labels = [pdf_plain(r, limit=80) for r in roles] or [""]
    total = float(width) if width else _DEFAULT_FORM_WIDTH
    header_labels = ["Sign-off", "Name", "Role", "Date", "Signature"]
    header = [Paragraph(escape_html(h), styles["dense_header"]) for h in header_labels]
    rows = [
        [Paragraph(escape_html(label), styles["table_label"]), "", "", "", ""]
        for label in labels
    ]
    shares = [0.26, 0.22, 0.20, 0.12, 0.20]
    table = _form_table(header, rows, [total * s for s in shares], _SIGNOFF_ROW_HEIGHT)
    return KeepTogether([*_form_heading(title, styles), table])


# ---------------------------------------------------------------------------------------------
# build_document: the shell around a renderer's body
# ---------------------------------------------------------------------------------------------
def _box(
    rows: list[Flowable],
    width: float,
    *,
    accent: Any,
    background: Any = COLOR_WHITE,
    border: Any = COLOR_BORDER,
) -> Table:
    """A card made of one row per flowable (so it can still split across pages)."""
    table = Table([[row] for row in rows], colWidths=[width], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.7, border),
                ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                ("TOPPADDING", (0, 0), (0, 0), 6),
                ("BOTTOMPADDING", (0, -1), (0, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _masthead(title: str, meta: dict[str, str], styles: Styles, width: float) -> Table:
    brand = ParagraphStyle(
        "DeliverableBrand",
        parent=styles["muted"],
        fontSize=8,
        textColor=BRAND_TEAL,
        fontName="Helvetica-Bold",
        alignment=TA_RIGHT,
        leading=10,
    )
    kicker = f"{BRAND_NAME} \u00b7 {meta['kicker']}".upper()
    left = Table(
        [
            [Paragraph(escape_html(kicker), styles["kicker"])],
            [Paragraph(pdf_text(title, limit=120), styles["title"])],
            [Paragraph(pdf_text(meta["subtitle"], limit=160), styles["subtitle"])],
        ],
        colWidths=[width * 0.68],
    )
    right = Table(
        [
            [Paragraph(escape_html(BRAND_URL), brand)],
            [Paragraph(pdf_text(meta["footer_label"]), styles["masthead_label"])],
        ],
        colWidths=[width * 0.32],
    )
    flat = TableStyle(
        [
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )
    left.setStyle(flat)
    right.setStyle(flat)
    row = Table([[left, right]], colWidths=[width * 0.68, width * 0.32], hAlign="LEFT")
    row.setStyle(flat)
    return row


def _banner(title: str, message: str, styles: Styles, width: float) -> Table:
    title_style = ParagraphStyle(
        "DeliverableBannerTitle", parent=styles["box_title"], textColor=PILL_MEDIUM_FG
    )
    return _box(
        [
            Paragraph(pdf_text(title), title_style),
            Paragraph(pdf_text(message, limit=600), styles["box_text"]),
        ],
        width,
        accent=BAR_MEDIUM,
        background=PILL_MEDIUM_BG,
        border=PILL_MEDIUM_BD,
    )


def _window_text(view: TeamCbomView) -> str:
    if view.window_start is None or view.window_end is None:
        return authored.DATA_WINDOW_NONE
    return f"{fmt_date_utc(view.window_start)} to {fmt_date_utc(view.window_end)} (UTC)"


def _control_table(
    view: TeamCbomView, number: int, title: str, styles: Styles, width: float
) -> Table:
    labels = authored.CONTROL_LABELS
    value, mono = styles["table_cell"], styles["mono_cell"]
    team = f"{pdf_plain(view.team_name, limit=80)} (ID {int(view.team_id)})"
    cells = [
        (labels["document"], pdf_text(title, limit=120), value),
        (labels["document_id"], pdf_text(document_id(view, number)), mono),
        (labels["team"], pdf_text(team, limit=100), value),
        (labels["generated"], pdf_text(fmt_utc_ist(view.generated_at)), value),
        (labels["window"], pdf_text(_window_text(view)), value),
        (labels["basis"], pdf_text(authored.BASIS_CONTROL_SUMMARY), value),
        (labels["template"], pdf_text(f"{TEMPLATE_VERSION} \u00b7 {authored.TOOL_NAME}"), value),
        (labels["fingerprint"], pdf_text(view.fingerprint or "n/a", limit=40), mono),
    ]
    data = []
    for index in range(0, len(cells), 2):
        row: list[Any] = []
        for label, text, style in cells[index : index + 2]:
            row += [Paragraph(escape_html(label), styles["table_label"]), Paragraph(text, style)]
        data.append(row)
    shares = [0.15, 0.35, 0.15, 0.35]
    table = Table(data, colWidths=[width * s for s in shares], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), COLOR_HEADER_SOFT),
                ("BACKGROUND", (2, 0), (2, -1), COLOR_HEADER_SOFT),
                ("BACKGROUND", (1, 0), (1, -1), COLOR_WHITE),
                ("BACKGROUND", (3, 0), (3, -1), COLOR_WHITE),
                ("BOX", (0, 0), (-1, -1), 0.6, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, COLOR_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _basis_box(
    view: TeamCbomView,
    styles: Styles,
    width: float,
    extra: Sequence[str] | None = None,
) -> Table:
    excluded = view.excluded or {}

    def count(key: str) -> int:
        return int(excluded.get(key, 0) or 0)

    scans = authored.BASIS_SCANS.format(
        included=int(view.included),
        eligible=int(view.eligible),
        failed=count(EXCLUDED_FAILURE),
        not_completed=count(EXCLUDED_NOT_COMPLETED),
        no_data=count(EXCLUDED_NO_DATA),
    )
    history = authored.BASIS_HISTORY.format(folded=int(view.included))
    if view.history_truncated:
        history += authored.BASIS_HISTORY_TRUNCATED.format(truncated=int(view.history_truncated))
    second = " \u00b7 ".join(
        [
            authored.BASIS_SOURCES.format(sources=len(view.sources)),
            authored.BASIS_FIDELITY.format(
                full=int(view.fidelity_full), reduced=int(view.fidelity_reduced)
            ),
            history,
        ]
    )
    body = styles["box_text"]
    rows: list[Flowable] = [
        Paragraph(pdf_text(authored.BASIS_HEADING), styles["box_title"]),
        Paragraph(pdf_text(scans), body),
        Paragraph(pdf_text(second), body),
        Paragraph(pdf_text(authored.BASIS_RULE), body),
    ]
    for line in extra or ():
        if line:
            rows.append(Paragraph(pdf_text(line, limit=600), body))
    return _box(rows, width, accent=BRAND_TEAL)


def _disclaimer_box(
    styles: Styles, width: float, paragraphs: Sequence[str] | None = None
) -> Table:
    chosen = authored.DISCLAIMER_PARAGRAPHS if paragraphs is None else paragraphs
    rows: list[Flowable] = [
        Paragraph(pdf_text(authored.DISCLAIMER_HEADING), styles["box_title"])
    ]
    rows += [
        Paragraph(pdf_text(paragraph, limit=600), styles["box_text"]) for paragraph in chosen
    ]
    return _box(rows, width, accent=BAR_UNKNOWN)


def _front_matter(
    view: TeamCbomView,
    number: int,
    title: str,
    meta: dict[str, str],
    styles: Styles,
    width: float,
    basis_extra: Sequence[str] | None = None,
    disclaimer_paragraphs: Sequence[str] | None = None,
    extra_banners: Sequence[tuple[str, str]] | None = None,
) -> list[Flowable]:
    gap = Spacer(1, 6)
    story: list[Flowable] = [_masthead(title, meta, styles, width), Spacer(1, 8)]
    if view.is_empty:
        banner = _banner(authored.BANNER_EMPTY_TITLE, authored.BANNER_EMPTY_TEXT, styles, width)
        story += [banner, gap]
    elif view.fidelity_full == 0 and view.fidelity_reduced > 0:
        banner = _banner(
            authored.BANNER_REDUCED_TITLE, authored.BANNER_REDUCED_TEXT, styles, width
        )
        story += [banner, gap]
    for banner_title, banner_message in extra_banners or ():
        story += [_banner(banner_title, banner_message, styles, width), gap]
    story += [
        _control_table(view, number, title, styles, width),
        gap,
        _basis_box(view, styles, width, basis_extra),
        gap,
        _disclaimer_box(styles, width, disclaimer_paragraphs),
        Spacer(1, 4),
        Paragraph(pdf_text(authored.MANUAL_LEGEND, limit=400), styles["muted"]),
        Spacer(1, 8),
    ]
    return story


def build_document(
    *,
    view: TeamCbomView,
    number: int,
    report_key: str,
    title: str,
    landscape: bool,
    body: Callable[[Styles, float], Iterable[Flowable]],
    basis_extra: Sequence[str] | None = None,
    disclaimer_paragraphs: Sequence[str] | None = None,
    extra_banners: Sequence[tuple[str, str]] | None = None,
) -> bytes:
    """Build one deliverable PDF in memory and return its bytes.

    ``body(styles, width)`` returns the document-specific flowables; ``width`` is the usable
    frame width in points (540 portrait, 720 landscape).  The shell adds the page chrome of
    ``report_key`` (its OWN ``REPORT_META`` header and footer label), the masthead, the
    document-control table, the Basis box, the disclaimers, the "NO COMPLETED CBOM SCANS" or
    reduced-fidelity banner when it applies, and the "(assessor)" legend.  PDF metadata
    (Title, Author, Subject, Keywords, Creator, language, creation date) is set from the view,
    and the output is byte-identical for the same view and body.

    ``basis_extra`` lines are appended to the Basis box. ``disclaimer_paragraphs`` replaces
    the default disclaimer tuple when it is not ``None``. ``extra_banners`` is a sequence of
    ``(title, message)`` pairs drawn under the masthead. All three default to ``None``, which
    leaves the six existing documents unchanged.

    Raises ``ValueError`` for a ``report_key`` that has no ``REPORT_META`` entry (an unknown
    key would silently print the SAST header and footer).
    """
    if report_key not in REPORT_META:
        raise ValueError(f"unknown report_key {report_key!r}: add it to REPORT_META")
    meta = REPORT_META[report_key]
    styles = get_deliverable_styles()
    doc_id = document_id(view, number)
    team = pdf_plain(view.team_name, limit=80)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=pagesizes.landscape(pagesizes.letter) if landscape else pagesizes.letter,
        leftMargin=_MARGIN_X,
        rightMargin=_MARGIN_X,
        topMargin=_MARGIN_TOP,
        bottomMargin=_MARGIN_BOTTOM,
        title=pdf_plain(f"{title} - {team}", limit=150),
        author=authored.TOOL_NAME,
        subject=pdf_plain(f"{title} ({doc_id})", limit=200),
        keywords=pdf_plain(
            f"CBOM, cryptographic bill of materials, regulatory deliverable, {title}", limit=250
        ),
        creator=f"{authored.TOOL_NAME} (template {TEMPLATE_VERSION})",
        invariant=1,
        displayDocTitle=1,
        lang="en-US",
    )
    width = float(doc.width)
    story = _front_matter(
        view,
        number,
        title,
        meta,
        styles,
        width,
        basis_extra,
        disclaimer_paragraphs,
        extra_banners,
    )
    story.extend(body(styles, width))

    stamp = _pdf_date(view.generated_at)
    cover = make_cover_callback(report_key)

    def on_first_page(canvas_obj: Any, doc_obj: Any) -> None:
        canvas_obj.setDateFormatter(lambda *_parts: stamp)
        cover(canvas_obj, doc_obj)

    doc.build(story, onFirstPage=on_first_page, onLaterPages=make_footer_callback(report_key))
    return buffer.getvalue()


__all__ = [
    "TEMPLATE_VERSION",
    "Styles",
    "build_document",
    "dense_table",
    "document_id",
    "fmt_date_utc",
    "fmt_utc_ist",
    "get_deliverable_styles",
    "kpi_strip",
    "manual_form",
    "pdf_multiline",
    "pdf_plain",
    "pdf_text",
    "section_heading",
    "signoff_block",
    "status_chip",
    "tone_for_impact",
]
