"""Certificate Estate Register (deliverable #7): one landscape PDF row per UNIQUE certificate.

``build_pdf(view)`` renders a ``TeamCbomView`` (``backend.utilities.dashboard.cbom_team_rollup``)
into the register described in plan section 5.4:

1. Summary KPI strip (certificates, expired, <=30 days, <=90 days, weak crypto, self-signed
   leaf, issuer not found);
2. validity-band table;
3. the register itself (14 columns, dense style, repeated header, sorted by expiry urgency);
4. "Previously seen, not in latest scan" (only when such a certificate exists);
5. discovery limits and manual-field guidance;
6. reviewer sign-off.

Rules this renderer follows (they are the point of the document, so they are tested):

* Certificates are de-duplicated by the aggregator (plan 4.4); one row per ``CertAgg`` however
  many sources, paths and scans it was seen in.  The row says how many ("3 locations",
  "4 scans").  Only certificates present in their source's CURRENT scan are rows; the others
  go to the "previously seen" appendix and are excluded from every count.
* Expiry is computed HERE from ``notAfter`` and ``view.as_of`` (plan F-03: the scanner never
  raises a near-expiry finding), not read from the view.  When the scan recorded a different
  expired flag than the one computed now, the row says "scan-time flag differs".
* Weakness comes from ``finding_codes`` / ``impact`` (plan F-04); a certificate row's ``weak``
  and ``crypto_strength`` fields ignore certificate findings, so they are never used.
* Owner and Business system are MANUAL columns: always blank, headed "(assessor)".  Nothing is
  inferred about ownership.
* Chain flags are factual.  "Signed by <file>" needs an issuer certificate in the estate (a
  scan-time ``signed_by`` edge, else an issuer name that matches the subject of a current
  certificate); "Issuer not in estate" means neither exists.

How cells are drawn.  A 1 000-row register has 14 000 cells.  Building, wrapping and drawing
that many ``Paragraph`` objects (each one parses mini-HTML) is what makes big tables slow, so
the register's text cells are ``_TextBlock`` flowables: the text is sanitised
(``pdf_plain``: controls stripped, folded to WinAnsi, clamped), wrapped to the column here
(``_wrap``, which also breaks over-wide host names, paths and identifiers at punctuation
instead of mid-word) and drawn straight onto the canvas.  There is no markup to interpret, so
hostile certificate fields (``<img src=...>``, ``<font ...>``) are printed literally.  The
status chips and the table chrome are the shared ``cbom_deliverable_common`` helpers.

Hard rules (plan 5.1 / 6.5): reportlab + standard library + ``backend.utilities.pdf`` +
``backend.utilities.dashboard.cbom_team_rollup`` only; no network, no language model, no wall
clock (everything is a function of the view); Helvetica/Courier; Python 3.10 syntax.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import lru_cache
from typing import NamedTuple

from reportlab.lib.colors import Color
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Spacer, Table

from backend.utilities.dashboard.cbom_team_rollup import (
    EXPIRED,
    EXPIRY_BANDS,
    IMPACT_LEVELS,
    LE_30,
    LE_90,
    NEAR_EXPIRY_DAYS,
    TIER_C,
    UNKNOWN,
    VALID,
    CertAgg,
    ExpiryBand,
    TeamCbomView,
    classify_expiry,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    fmt_date_utc,
    kpi_strip,
    pdf_plain,
    pdf_text,
    section_heading,
    signoff_block,
    status_chip,
    tone_for_impact,
)
from backend.utilities.pdf.report_branding import COLOR_BODY, COLOR_SLATE, REPORT_META

REPORT_KEY = "cbom_cert_register"
NUMBER = 7
TITLE = REPORT_META[REPORT_KEY]["title"]

MAX_REGISTER_ROWS = 2000  # decision D-04: table cap for the certificate and PQC registers

# How much of a long list one cell prints before "+N more"; keeps a row far below a page.
MAX_LOCATIONS_SHOWN = 3
MAX_FILES_SHOWN = 3
MAX_FINDINGS_SHOWN = 4
MAX_ISSUER_FILES_SHOWN = 3

_DASH = "\u2014"
_BULLET = "\u2022"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_PAD = 3  # dense_table cell padding (left and right), points
_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"
_FONT_SIZE = 7.0  # the dense cell font size ...
_LEADING = 8.6  # ... and line height of cbom_deliverable_common's "dense_cell" style
_BULLET_INDENT = 6.0
_MIN_PIECE = 3  # a word is not broken at punctuation earlier than this many characters in

# Register columns, left to right: (header, width in points).  The widths sum to the 720 pt
# landscape frame; ``_column_widths`` rescales them for any other frame width.
_COLUMNS = (
    ("#", 22),
    ("Certificate", 91),
    ("Issuer CN", 56),
    ("Public key", 38),
    ("Signature algorithm", 50),
    ("Valid from", 43),
    ("Valid to", 43),
    ("Expiry", 46),
    ("CA / self-signed / chain", 50),
    ("Findings", 76),
    ("Where found", 69),
    ("Seen (first -> last)", 52),
    ("Owner (assessor)", 42),
    ("Business system (assessor)", 42),
)
(
    _COL_NUMBER,
    _COL_CERT,
    _COL_ISSUER,
    _COL_KEY,
    _COL_SIG,
    _COL_FROM,
    _COL_TO,
    _COL_EXPIRY,
    _COL_CHAIN,
    _COL_FINDINGS,
    _COL_WHERE,
    _COL_SEEN,
    _COL_OWNER,
    _COL_SYSTEM,
) = range(len(_COLUMNS))
MANUAL_COLUMNS = (_COL_OWNER, _COL_SYSTEM)  # filled in by the assessor, never by the platform

# Appendix ("previously seen") columns.
_APPENDIX_COLUMNS = (
    ("#", 24),
    ("Certificate", 150),
    ("Issuer CN", 120),
    ("Public key", 70),
    ("Valid to", 60),
    ("Last seen", 60),
    ("Scans", 36),
    ("Where last found", 200),
)

# Local wording (plan 8.3: a renderer keeps its document-specific paragraphs in its own module).
NO_FINDINGS = "No findings"
# Pre-reconcile (tier C) scans never recorded finding codes, so "No findings" would be a claim.
FINDINGS_NOT_RECORDED = "Not recorded (legacy scan)"
SELF_SIGNED_NO_CA_FLAG = "Self-signed (CA flag not recorded)"
CA_CERTIFICATE = "CA certificate"
CHAIN_NOT_RECORDED = "Chain not recorded"
EXPIRY_NOT_RECORDED = "expiry not recorded"
REGISTER_INTRO = (
    "One row per unique certificate in the current state of the team's sources (the latest "
    "successful scan of each source). Rows are sorted by expiry urgency (expired first, then "
    "{le30}, then {le90}), then by impact, valid-to date and subject. Expiry is computed from "
    "the notAfter date as of {as_of}; the Findings column shows what the scan recorded, and a "
    "row marked '{differs}' was flagged differently when it was scanned because time has "
    "passed since."
)
MANUAL_GUIDANCE = (
    "Owner and Business system are intentionally blank. Record the accountable owner and the "
    "business system each certificate protects from your PKI or CMDB inventory; do not infer "
    "ownership from the file path or the name of the source."
)
OMITTED_NOTICE = (
    "{omitted} further {noun} omitted. The register is limited to {max_rows} rows and lists "
    "the most urgent certificates first."
)
APPENDIX_INTRO = (
    "These certificates were found in earlier scans of a source but are not in that source's "
    "latest scan. They are excluded from every count and from the register above."
)
SIGNOFF_ROLES = ("Prepared by", "Reviewed by", "Approved by")

# Per-field character budgets (longer text is cut with an ellipsis); an X.509 common name is at
# most 64 characters, so real certificates are never cut.
_NAME_CHARS = 64
_LOCATION_CHARS = 120
_FINDING_CHARS = 110

# Certificate public-key algorithm names (as recorded from the X.509 SubjectPublicKeyInfo).
_KEY_FAMILIES = {
    "rsaencryption": "RSA",
    "rsa": "RSA",
    "rsassa-pss": "RSA-PSS",
    "ecpublickey": "EC",
    "id-ecpublickey": "EC",
    "ec": "EC",
    "ecdsa": "EC",
    "dsaencryption": "DSA",
    "dsa": "DSA",
    "ed25519": "Ed25519",
    "id-ed25519": "Ed25519",
    "ed448": "Ed448",
    "id-ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
}
_FIXED_SIZE_FAMILIES = frozenset({"Ed25519", "Ed448", "X25519", "X448"})

# Expiry urgency groups first; everything else shares the last group (then impact decides).
_URGENCY = {EXPIRED: 0, LE_30: 1, LE_90: 2}
_NOT_URGENT = 3
_IMPACT_RANK = {level: rank for rank, level in enumerate(IMPACT_LEVELS)}

# Line-break opportunities inside a word that is wider than its column: after punctuation, or at
# a lower-case/digit -> upper-case change ("sha256With|RSAEncryption").
_BREAK_AFTER = frozenset("-._/@:;,+=&?#")


# ---------------------------------------------------------------------------------------------
# Row model
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class RegisterRow:
    """One register row: a unique current certificate plus everything derived for display."""

    number: int  # 1-based position in the sorted register
    cert: CertAgg
    band: ExpiryBand  # computed from notAfter and view.as_of (never trusted from the view)
    expiry_note: str  # "35 days ago", "20 days left", "expiry not recorded"
    flag_differs: bool  # the scan recorded a different expired flag than the one computed now
    public_key: str  # "RSA 2048", "EC P-256", "" when nothing was recorded
    # root_ca | self_signed_leaf | self_signed | signed_by | issuer_not_in_estate | unrecorded
    chain_kind: str
    chain_lines: tuple[str, ...]


def _fold(text: str | None) -> str:
    return (text or "").strip().casefold()


def _count_noun(count: int, noun: str) -> str:
    """``1 scan`` / ``4 scans``."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _valid_to_ordinal(cert: CertAgg) -> int:
    try:
        return date.fromisoformat((cert.not_after or "").strip()[:10]).toordinal()
    except ValueError:
        return date.max.toordinal()  # no usable notAfter: after every dated certificate


def _impact_rank(impact: str | None) -> int:
    return _IMPACT_RANK.get(impact or "", len(IMPACT_LEVELS))


def _join_limited(items: Sequence[str], limit: int) -> str:
    shown = ", ".join(items[:limit])
    return f"{shown} +{len(items) - limit} more" if len(items) > limit else shown


def _estate_index(certs: Sequence[CertAgg]) -> dict[str, list[CertAgg]]:
    """Current certificates by casefolded subject CN: the 'estate' an issuer is looked up in."""
    index: dict[str, list[CertAgg]] = {}
    for cert in certs:
        if cert.subject_cn and cert.subject_cn.strip():
            index.setdefault(_fold(cert.subject_cn), []).append(cert)
    return index


def _chain(cert: CertAgg, estate: dict[str, list[CertAgg]]) -> tuple[str, tuple[str, ...]]:
    """``(kind, display lines)`` of the CA / self-signed / chain column."""
    labels = authored.CERT_CHAIN_LABELS
    self_signed = cert.self_signed
    if (
        self_signed is None
        and cert.subject_cn
        and cert.issuer_cn
        and _fold(cert.subject_cn) == _fold(cert.issuer_cn)
    ):
        self_signed = True  # self-issued by name; the flag itself was not recorded
    if self_signed:
        if cert.is_ca is True:
            return "root_ca", (labels["root_ca"],)
        if cert.is_ca is False:
            return "self_signed_leaf", (labels["self_signed_leaf"],)
        return "self_signed", (SELF_SIGNED_NO_CA_FLAG,)
    lines: list[str] = []
    if cert.is_ca is True:
        lines.append(CA_CERTIFICATE)
    issuers = list(cert.signed_by)
    if not issuers and cert.issuer_cn:
        found = estate.get(_fold(cert.issuer_cn), ())
        issuers = sorted({other.name for other in found if other.key != cert.key})
    if issuers:
        issuer_file = _join_limited(issuers, MAX_ISSUER_FILES_SHOWN)
        lines.append(labels["signed_by"].format(issuer_file=issuer_file))
        return "signed_by", tuple(lines)
    if cert.issuer_cn and cert.issuer_cn.strip():
        lines.append(labels["issuer_not_in_estate"])
        return "issuer_not_in_estate", tuple(lines)
    lines.append(CHAIN_NOT_RECORDED)
    return "unrecorded", tuple(lines)


def _public_key(cert: CertAgg) -> str:
    raw = (cert.public_key_algorithm or "").strip()
    family = _KEY_FAMILIES.get(raw.casefold(), raw)
    curve = (cert.curve or "").strip()
    size = (cert.key_size or "").strip()
    if family == "EC":
        detail = curve or (f"{size}-bit" if size else "")
    elif family in _FIXED_SIZE_FAMILIES:
        detail = ""
    elif family:
        detail = size
    else:
        detail = curve or (f"{size}-bit" if size else "")
    return " ".join(part for part in (family, detail) if part)


def _days_text(band: ExpiryBand) -> str:
    days = band.days_left
    if band.band == UNKNOWN or days is None:
        return EXPIRY_NOT_RECORDED
    if days < 0:
        return f"{-days} day{'s' if days != -1 else ''} ago"
    if days == 0:
        return "expires today"
    return f"{days} day{'s' if days != 1 else ''} left"


def _flag_differs(cert: CertAgg, band: ExpiryBand) -> bool:
    recorded = cert.scan_time_expired  # None on legacy tiers: nothing to compare
    return recorded is not None and recorded != (band.band == EXPIRED)


def register_rows(view: TeamCbomView) -> list[RegisterRow]:
    """The register's rows: every CURRENT unique certificate, sorted, numbered from 1.

    Sort key (plan 5.4): expiry urgency (EXPIRED, then <=30 days, then <=90 days; every other
    certificate shares the last group), then impact (Critical first), then valid-to ascending,
    then subject.  The certificate key is the final tie-break, so the order is total and the
    PDF byte-stable.
    """
    current = [cert for cert in view.certs if cert.current]
    estate = _estate_index(current)
    staged = []
    for cert in current:
        band = classify_expiry(cert.not_after, view.as_of)
        key = (
            _URGENCY.get(band.band, _NOT_URGENT),
            _impact_rank(cert.impact),
            _valid_to_ordinal(cert),
            _fold(cert.subject_cn or cert.name),
            cert.key,
        )
        staged.append((key, cert, band))
    staged.sort(key=lambda item: item[0])
    rows = []
    for number, (_key, cert, band) in enumerate(staged, start=1):
        kind, lines = _chain(cert, estate)
        rows.append(
            RegisterRow(
                number=number,
                cert=cert,
                band=band,
                expiry_note=_days_text(band),
                flag_differs=_flag_differs(cert, band),
                public_key=_public_key(cert),
                chain_kind=kind,
                chain_lines=lines,
            )
        )
    return rows


def previously_seen(view: TeamCbomView) -> list[CertAgg]:
    """Certificates found in earlier scans but absent from every source's current scan."""
    gone = [cert for cert in view.certs if not cert.current]
    gone.sort(key=lambda c: (_fold(c.subject_cn or c.name), c.key))
    gone.sort(key=lambda c: (c.last_seen or _EPOCH).timestamp(), reverse=True)  # stable
    return gone


# ---------------------------------------------------------------------------------------------
# Text fitting: wrap to the column, breaking over-wide words at natural boundaries
# ---------------------------------------------------------------------------------------------
def _is_boundary(text: str, index: int) -> bool:
    """May a line end after ``text[:index]``?  (``0 < index < len(text)``)"""
    before, after = text[index - 1], text[index]
    if before in _BREAK_AFTER:
        return True
    if (before.islower() or before.isdigit()) and after.isupper():  # sha256With|RSA
        return True
    # an upper-case run before a capitalised word: RSA|Encryption
    return before.isupper() and after.isupper() and text[index + 1 : index + 2].islower()


@lru_cache(maxsize=16384)
def _width(text: str, font: str) -> float:
    """Width of ``text`` at the dense font size.  Cached: registers repeat the same words."""
    return stringWidth(text, font, _FONT_SIZE)


def _fitting_prefix(text: str, usable: float, font: str) -> int:
    """How many leading characters fit in ``usable`` points (at least one)."""
    total = 0.0
    for index, char in enumerate(text):
        total += _width(char, font)
        if total > usable:
            return max(1, index)
    return len(text)


def _break_word(word: str, usable: float, font: str) -> list[str]:
    """Split one over-wide word into pieces that fit, preferring punctuation / case changes."""
    pieces: list[str] = []
    rest = word
    while rest and _width(rest, font) > usable:
        fits = _fitting_prefix(rest, usable, font)
        cut = fits
        for index in range(min(fits, len(rest) - 1), _MIN_PIECE - 1, -1):
            if _is_boundary(rest, index):
                cut = index
                break
        pieces.append(rest[:cut])
        rest = rest[cut:]
    if rest:
        pieces.append(rest)
    return pieces


def _clip(lines: list[str], max_lines: int, usable: float, font: str) -> list[str]:
    if len(lines) <= max_lines:
        return lines
    kept = lines[:max_lines]
    last = kept[-1]
    while last and _width(last + "\u2026", font) > usable:
        last = last[:-1]
    kept[-1] = last.rstrip() + "\u2026"
    return kept


def _wrap(text: str, usable: float, font: str = _FONT, *, max_lines: int = 8) -> list[str]:
    """Greedy word wrap of sanitised ``text`` into lines of at most ``usable`` points.

    Explicit ``\\n`` starts a new line.  A word wider than the column is broken at punctuation or
    a case change where there is one (``chain-`` / ``root.crt``), else at the last character that
    fits; ``Paragraph`` would cut it anywhere.  At most ``max_lines`` lines are returned, the
    last one ending in an ellipsis when text was dropped.
    """
    usable = max(usable, 1.0)
    space = _width(" ", font)
    lines: list[str] = []
    for chunk in text.split("\n"):
        line, line_width = "", 0.0
        for word in chunk.split(" "):
            if not word:
                continue
            width = _width(word, font)
            pieces = [word] if width <= usable else _break_word(word, usable, font)
            for index, piece in enumerate(pieces):
                piece_width = width if len(pieces) == 1 else _width(piece, font)
                if index == 0 and line and line_width + space + piece_width <= usable:
                    line, line_width = f"{line} {piece}", line_width + space + piece_width
                else:  # the pieces of a broken word each start a line
                    if line:
                        lines.append(line)
                    line, line_width = piece, piece_width
        lines.append(line)
    return _clip(lines, max_lines, usable, font)


class _Line(NamedTuple):
    text: str
    font: str
    color: Color
    x: float  # left offset inside the cell (hanging indent of a bulleted entry)
    bullet: bool  # draw a bullet at x=0 before this line


class _TextBlock(Flowable):
    """The pre-wrapped text lines of one table cell, drawn straight onto the canvas.

    The text has already been sanitised and wrapped to the column, so nothing here parses markup:
    hostile text is printed literally.  Height is ``lines x leading`` (the same line height as the
    ``dense_cell`` paragraph style) and the first baseline sits one font size below the top,
    like a ``Paragraph``.
    """

    def __init__(self, lines: Sequence[_Line]) -> None:
        super().__init__()
        self.lines = tuple(lines)
        self._block_height = len(self.lines) * _LEADING

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:
        return availWidth, self._block_height

    def draw(self) -> None:
        canv = self.canv
        font: str | None = None
        color: Color | None = None
        for index, line in enumerate(self.lines):
            if line.font != font:
                font = line.font
                canv.setFont(font, _FONT_SIZE)
            if line.color is not color:
                color = line.color
                canv.setFillColor(color)
            baseline = self._block_height - _FONT_SIZE - index * _LEADING
            if line.bullet:
                canv.drawString(0, baseline, _BULLET)
            canv.drawString(line.x, baseline, line.text)

    def getPlainText(self) -> str:
        return "\n".join(line.text for line in self.lines)


def _lines(
    text: object,
    usable: float,
    *,
    font: str = _FONT,
    color: Color = COLOR_BODY,
    limit: int = _NAME_CHARS,
    max_lines: int = 8,
    bullet: bool = False,
) -> list[_Line]:
    """Sanitise, clamp and wrap ``text`` into drawable lines (a bulleted entry hangs its text)."""
    plain = pdf_plain(text, limit=limit)
    indent = _BULLET_INDENT if bullet else 0.0
    wrapped = _wrap(plain, usable - indent, font, max_lines=max_lines)
    return [_Line(part, font, color, indent, bullet and i == 0) for i, part in enumerate(wrapped)]


def _block(*groups: list[_Line]) -> _TextBlock:
    return _TextBlock([line for group in groups for line in group])


def _dash_if_empty(text: object) -> str:
    value = "" if text is None else str(text)
    return value if value.strip() else _DASH


def _date_text(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return _DASH
    head = text[:10]
    try:
        date.fromisoformat(head)
    except ValueError:
        return pdf_plain(text, limit=20)
    return head


def _seen_parts(cert: CertAgg) -> list[str]:
    """The Seen cell, one string per line: first -> last date, then the scan count."""
    first, last = fmt_date_utc(cert.first_seen), fmt_date_utc(cert.last_seen)
    span = [first] if first == last else [f"{first} ->", last]
    count = int(cert.scan_count or 0)
    latest = cert.latest_scan_id
    if latest is None:
        return [*span, _count_noun(count, "scan")]
    if count == 1:
        return [*span, f"1 scan (#{latest})"]
    return [*span, _count_noun(count, "scan"), f"latest #{latest}"]


# ---------------------------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------------------------
def _certificate_cell(cert: CertAgg, usable: float) -> _TextBlock:
    """Subject CN in bold, the file name(s) under it, a note when the identity is weak."""
    groups = [_lines(cert.subject_cn or cert.name, usable, font=_FONT_BOLD, max_lines=4)]
    if cert.subject_cn:
        names = [pdf_plain(name, limit=40) for name in cert.file_names] or [cert.name]
        files = _join_limited(names, MAX_FILES_SHOWN)
        groups.append(_lines(files, usable, color=COLOR_SLATE, max_lines=3))
    if not cert.identity_strong:
        groups.append(_lines(authored.IDENTITY_WEAK_NOTE, usable, color=COLOR_SLATE, max_lines=3))
    return _block(*groups)


def _expiry_cell(row: RegisterRow, usable: float) -> list[Flowable]:
    band = row.band.band
    chip = status_chip(
        authored.EXPIRY_BAND_CHIP_TEXT.get(band, band),
        authored.EXPIRY_BAND_TONE.get(band, "unknown"),
    )
    groups = [_lines(row.expiry_note, usable)]
    if row.flag_differs:
        groups.append(_lines(authored.CERT_SCAN_FLAG_DIFFERS, usable, color=COLOR_SLATE))
    return [chip, Spacer(1, 2), _block(*groups)]


def _chain_cell(row: RegisterRow, usable: float) -> _TextBlock:
    return _block(*(_lines(text, usable, limit=120, max_lines=8) for text in row.chain_lines))


def _findings_cell(cert: CertAgg, usable: float) -> list[Flowable]:
    impact = (cert.impact or "Low").strip() or "Low"
    chip = status_chip(impact.upper(), tone_for_impact(impact))
    codes = list(cert.finding_codes)
    if not codes:
        text = FINDINGS_NOT_RECORDED if cert.tier == TIER_C else NO_FINDINGS
        return [chip, Spacer(1, 2), _block(_lines(text, usable, color=COLOR_SLATE))]
    many = len(codes) > 1
    groups = [
        _lines(
            f"{authored.finding_label(code)} ({pdf_plain(code, limit=40)})",
            usable,
            limit=_FINDING_CHARS,
            max_lines=5,
            bullet=many,
        )
        for code in codes[:MAX_FINDINGS_SHOWN]
    ]
    if len(codes) > MAX_FINDINGS_SHOWN:
        groups.append(_lines(f"+{len(codes) - MAX_FINDINGS_SHOWN} more", usable, color=COLOR_SLATE))
    return [chip, Spacer(1, 2), _block(*groups)]


def _where_cell(cert: CertAgg, usable: float) -> _TextBlock:
    """``source: path`` per location (newest first), preceded by a count when there are several."""
    shown = cert.locations[:MAX_LOCATIONS_SHOWN]
    total = max(int(cert.locations_total or 0), len(cert.locations))
    many = total > 1
    groups: list[list[_Line]] = []
    if many:
        groups.append(_lines(f"{total} locations", usable, font=_FONT_BOLD))
    for label, path in shown:
        groups.append(
            _lines(
                f"{label}: {path}",
                usable,
                limit=_LOCATION_CHARS,
                max_lines=8,
                bullet=many,
            )
        )
    if total > len(shown):
        groups.append(_lines(f"+{total - len(shown)} more", usable, color=COLOR_SLATE))
    return _block(*groups) if groups else _block(_lines(_DASH, usable))


def _text_cell(text: object, usable: float, *, limit: int = _NAME_CHARS) -> _TextBlock:
    return _block(_lines(_dash_if_empty(text), usable, limit=limit))


def _column_widths(columns: Sequence[tuple[str, int]], width: float) -> list[float]:
    """The column widths scaled to ``width`` points (the remainder lands on the last column)."""
    base = float(sum(w for _name, w in columns))
    if abs(width - base) < 1e-6:
        return [float(w) for _name, w in columns]
    widths = [round(w * width / base, 2) for _name, w in columns[:-1]]
    return [*widths, round(width - sum(widths), 2)]


def _row_cells(row: RegisterRow, usable: Sequence[float]) -> list[object]:
    cert = row.cert
    return [
        _text_cell(row.number, usable[_COL_NUMBER]),
        _certificate_cell(cert, usable[_COL_CERT]),
        _text_cell(cert.issuer_cn, usable[_COL_ISSUER]),
        _text_cell(row.public_key, usable[_COL_KEY]),
        _text_cell(cert.signature_algorithm, usable[_COL_SIG], limit=40),
        _text_cell(_date_text(cert.not_before), usable[_COL_FROM]),
        _text_cell(_date_text(cert.not_after), usable[_COL_TO]),
        _expiry_cell(row, usable[_COL_EXPIRY]),
        _chain_cell(row, usable[_COL_CHAIN]),
        _findings_cell(cert, usable[_COL_FINDINGS]),
        _where_cell(cert, usable[_COL_WHERE]),
        _block(*(_lines(part, usable[_COL_SEEN], max_lines=2) for part in _seen_parts(cert))),
        _TextBlock(()),  # Owner (assessor): MANUAL, never pre-filled
        _TextBlock(()),  # Business system (assessor): MANUAL, never pre-filled
    ]


def register_table(rows: Sequence[RegisterRow], width: float, *, as_of: date) -> Table:
    """The 14-column register for ``rows`` (already sorted and capped by the caller)."""
    widths = _column_widths(_COLUMNS, width)
    usable = [w - 2 * _PAD for w in widths]
    headers = [name for name, _w in _COLUMNS]
    headers[_COL_EXPIRY] = f"Expiry as of {fmt_date_utc(as_of)}"
    return dense_table(
        headers,
        [_row_cells(row, usable) for row in rows],
        widths,
        manual_cols=MANUAL_COLUMNS,
    )


def _appendix_table(certs: Sequence[CertAgg], width: float) -> Table:
    widths = _column_widths(_APPENDIX_COLUMNS, width)
    usable = [w - 2 * _PAD for w in widths]
    body = []
    for number, cert in enumerate(certs, start=1):
        groups: list[list[_Line]] = []
        if cert.locations:
            label, path = cert.locations[0]
            groups.append(_lines(f"{label}: {path}", usable[7], limit=_LOCATION_CHARS))
        more = max(int(cert.locations_total or 0), len(cert.locations)) - 1
        if more > 0:
            groups.append(_lines(f"+{more} more", usable[7], color=COLOR_SLATE))
        body.append(
            [
                _text_cell(number, usable[0]),
                _certificate_cell(cert, usable[1]),
                _text_cell(cert.issuer_cn, usable[2]),
                _text_cell(_public_key(cert), usable[3]),
                _text_cell(_date_text(cert.not_after), usable[4]),
                _text_cell(fmt_date_utc(cert.last_seen), usable[5]),
                _text_cell(int(cert.scan_count or 0), usable[6]),
                _block(*groups) if groups else _text_cell(None, usable[7]),
            ]
        )
    return dense_table([name for name, _w in _APPENDIX_COLUMNS], body, widths)


# ---------------------------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------------------------
def _kpi_cards(rows: Sequence[RegisterRow]) -> list[tuple[str, ...]]:
    bands = Counter(row.band.band for row in rows)
    chips = authored.EXPIRY_BAND_CHIP_TEXT
    weak = sum(1 for r in rows if any(c.startswith("WEAK_") for c in r.cert.finding_codes))
    leaf = sum(1 for r in rows if r.chain_kind == "self_signed_leaf")
    orphan = sum(1 for r in rows if r.chain_kind == "issuer_not_in_estate")
    # hints stay on one line (about 20 characters) so the cards of the strip are equally tall
    return [
        ("Certificates", str(len(rows)), "Unique, all sources"),
        ("Expired", str(bands[EXPIRED]), "Past notAfter date", "critical"),
        (chips[LE_30], str(bands[LE_30]), "Due in 0 to 30 days", "high"),
        (chips[LE_90], str(bands[LE_90]), "Due in 31 to 90 days", "medium"),
        ("Weak crypto", str(weak), "Weak key or signature", "high"),
        ("Self-signed leaf", str(leaf), "Self-signed, not a CA", "medium"),
        ("Issuer not found", str(orphan), "Issuer not in estate", "unknown"),
    ]


def _band_definitions(as_of: date) -> dict[str, str]:
    return {
        EXPIRED: f"notAfter date is before {fmt_date_utc(as_of)}",
        LE_30: "Expires in 0 to 30 days",
        LE_90: f"Expires in 31 to {NEAR_EXPIRY_DAYS} days",
        VALID: f"Expires in more than {NEAR_EXPIRY_DAYS} days",
        UNKNOWN: "notAfter date missing or unreadable",
    }


def _bands_table(rows: Sequence[RegisterRow], as_of: date, width: float) -> Table:
    counts = Counter(row.band.band for row in rows)
    definitions = _band_definitions(as_of)
    # the UNKNOWN row only appears when some certificate has no readable notAfter
    bands = [band for band in EXPIRY_BANDS if band != UNKNOWN or counts[UNKNOWN]]
    body = [
        [
            status_chip(
                authored.EXPIRY_BAND_CHIP_TEXT[band], authored.EXPIRY_BAND_TONE.get(band, "unknown")
            ),
            definitions.get(band, ""),
            str(counts[band]),
        ]
        for band in bands
    ]
    widths = [width * 0.18, width * 0.64, width * 0.18]
    return dense_table(["Validity band", "Definition", "Certificates"], body, widths)


def _bullets(items: Sequence[str], styles: Styles) -> list[Flowable]:
    style = ParagraphStyle(
        "CertRegisterBullet", parent=styles["body"], leftIndent=12, bulletIndent=2
    )
    return [Paragraph(pdf_text(item, limit=700), style, bulletText=_BULLET) for item in items]


def _omitted_notice(omitted: int, cap: int) -> str:
    noun = "row" if omitted == 1 else "rows"
    return OMITTED_NOTICE.format(omitted=omitted, noun=noun, max_rows=cap)


def _body(view: TeamCbomView, max_rows: int) -> Callable[[Styles, float], list[Flowable]]:
    def body(styles: Styles, width: float) -> list[Flowable]:
        rows = register_rows(view)
        earlier = previously_seen(view)
        cap = max(0, int(max_rows))
        shown = rows[:cap]
        as_of_text = fmt_date_utc(view.as_of)
        unique = _count_noun(len(rows), "unique certificate")
        story: list[Flowable] = []
        section = 0

        def heading(title: str, min_space: float = 90) -> list[Flowable]:
            """The next numbered section heading (numbers stay consecutive when 4 is absent)."""
            nonlocal section
            section += 1
            return section_heading(f"{section}. {title}", styles, min_space=min_space)

        story.extend(heading("Summary"))
        story.append(kpi_strip(_kpi_cards(rows), width, max_per_row=7))
        story.append(Spacer(1, 6))

        # the band table is five rows: keep it, its lead and its heading on one page
        bands_heading = heading(f"Validity bands as of {as_of_text}")[-1]
        bands_lead = Paragraph(pdf_text(f"{unique}, validity as of {as_of_text}."), styles["muted"])
        story.append(
            KeepTogether([bands_heading, bands_lead, _bands_table(rows, view.as_of, width)])
        )
        story.append(Spacer(1, 6))

        story.extend(heading("Certificate register", min_space=150))
        if not rows:
            lead = "No certificates were found in the current scans."
        elif len(shown) < len(rows):
            lead = f"Showing {len(shown)} of {unique}."
        else:
            lead = f"Showing all {unique}."
        intro = REGISTER_INTRO.format(
            le30=authored.EXPIRY_BAND_CHIP_TEXT[LE_30],
            le90=authored.EXPIRY_BAND_CHIP_TEXT[LE_90],
            as_of=as_of_text,
            differs=authored.CERT_SCAN_FLAG_DIFFERS,
        )
        story.append(Paragraph(pdf_text(f"{lead} {intro}", limit=900), styles["muted"]))
        story.append(register_table(shown, width, as_of=view.as_of))
        if len(rows) > len(shown):
            story.append(Spacer(1, 4))
            notice = _omitted_notice(len(rows) - len(shown), cap)
            story.append(Paragraph(pdf_text(notice, limit=400), styles["muted"]))
        story.append(Spacer(1, 6))

        if earlier:
            story.extend(heading(authored.PREVIOUSLY_SEEN_TITLE, min_space=120))
            story.append(Paragraph(pdf_text(APPENDIX_INTRO, limit=400), styles["muted"]))
            story.append(_appendix_table(earlier[:cap], width))
            if len(earlier) > cap:
                notice = _omitted_notice(len(earlier) - cap, cap)
                story.append(Paragraph(pdf_text(notice, limit=400), styles["muted"]))
            story.append(Spacer(1, 6))

        story.extend(heading("Discovery limits and manual-field guidance"))
        story.extend(_bullets([*authored.CERT_DISCOVERY_LIMITS, MANUAL_GUIDANCE], styles))
        story.append(Paragraph(pdf_text(authored.CERT_CHAIN_NOTE, limit=500), styles["muted"]))
        story.append(Spacer(1, 6))

        story.extend(heading("Reviewer sign-off", min_space=140))
        story.append(signoff_block(SIGNOFF_ROLES, title=None, width=width))
        return story

    return body


def build_pdf(view: TeamCbomView, *, max_rows: int = MAX_REGISTER_ROWS) -> bytes:
    """Render the Certificate Estate Register for ``view`` and return the PDF bytes.

    ``max_rows`` caps the register (and the "previously seen" table) at that many rows; the rows
    left out are announced ("N further rows omitted") and the KPI strip and validity bands still
    count every certificate.  An empty team still gets a complete document: the "NO COMPLETED
    CBOM SCANS" banner, zero counts and an empty register, never a failure.
    """
    return build_document(
        view=view,
        number=NUMBER,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=True,
        body=_body(view, max_rows),
    )


__all__ = [
    "MANUAL_COLUMNS",
    "MAX_REGISTER_ROWS",
    "NUMBER",
    "REPORT_KEY",
    "TITLE",
    "RegisterRow",
    "build_pdf",
    "previously_seen",
    "register_rows",
    "register_table",
]
