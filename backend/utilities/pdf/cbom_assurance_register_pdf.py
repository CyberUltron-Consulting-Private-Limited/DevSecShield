"""Third-Party Cryptographic Assurance & Attestation Register (#10): landscape PDF (WP3d).

One of the six team-wide CBOM regulatory deliverables.  It answers two questions for an assessor:
which third-party cryptographic components does the team rely on, and for which controls does the
BOM need an attestation that someone still has to supply?  Everything is read from the
``TeamCbomView`` built by ``backend.utilities.dashboard.cbom_team_rollup``; nothing is re-derived
from raw scan blobs.

Sections (plan 5.4, in order)::

    A  Third-party cryptographic components  - one row per library, current state
       A.1 Previously seen, not in latest scan - only when such libraries exist
    B  Control attestation ledger            - one row per (framework, requirement) that needs
                                               attestation, with "Attested k/n"
    C  Attestation summary                   - KPI cards (controls, fully / partly attested, %)
    D  Vendor attestation register           - blank manual rows
    E  Sign-off                              - blank manual block

Data rules the sections rely on.

* Libraries: the engine records a library's name and where it was found, nothing else.  The
  version column is therefore a blank MANUAL column (header "Version (not captured)"), as are the
  four vendor-assurance columns; nothing is ever made up.
* Ledger: ``RequirementAgg`` rows with at least one source whose verdict is "not evidenceable from
  BOM" or "pass with evidence".  ``Attested k/n``: n = sources that need the control, k = those
  already evidenced by an attestation.  Only the CURRENT, full-fidelity scan of each source feeds
  the roll-up, so an attestation stored on a superseded scan is not counted.
* Caps (plan 4.7 / D-04): 1 000 library rows and 1 000 ledger rows, each with an explicit
  "N further rows omitted" notice.  The summary cards always use the true totals.

Hard rules (enforced by ``test_cbom_deliverable_assurance_register.py``): reportlab and the
standard library only, plus ``backend.utilities.pdf.*`` and the roll-up module; no network and
no language-model calls; no wall clock (every date comes from the view); every data-derived
string passes through ``pdf_text`` / ``pdf_plain`` before it reaches a Paragraph; Python 3.10
syntax.  Table helpers take RAW values and sanitise them, so values are never pre-escaped.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import Flowable, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    VERDICT_NA,
    VERDICT_OUT_OF_SCOPE,
    LibAgg,
    RequirementAgg,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    fmt_date_utc,
    kpi_strip,
    manual_form,
    pdf_plain,
    pdf_text,
    section_heading,
    signoff_block,
    status_chip,
)
from backend.utilities.pdf.report_branding import REPORT_META

DOCUMENT_NUMBER = 10  # "#10" in the 16-item regulatory set (Document ID ...-D10-...)
REPORT_KEY = "cbom_assurance_register"  # REPORT_META key: its own header and footer label

MAX_LIBRARY_ROWS = 1000  # decision D-04: libraries table cap
MAX_LEDGER_ROWS = 1000  # plan 5.4: "thousands of NBE rows capped at 1 000 with notice"
VENDOR_BLANK_ROWS = 12  # plan 5.4: vendor attestation register, 12 blank rows

_MAX_SOURCES_SHOWN = 4  # source labels listed in one cell before "+N more"
_LABEL_LIMIT = 120
_ID_LIMIT = 80
_FILE_LIMIT = 80
_NOTE_LIMIT = 160
_CELL_PADDING = 6.0  # dense_table pads every cell by 3 pt on each side
# A section starts a new page unless its heading, notes and a few table rows still fit (no widows)
_MIN_SPACE_COMPONENTS = 150
_MIN_SPACE_LEDGER = 190  # the ledger has two intro notes and taller rows
_DASH = "\u2014"

# ---------------------------------------------------------------------------------------------
# Text local to this document.  Product text: it describes the behaviour of the roll-up
# (cbom_team_rollup.RequirementAgg) and of the attestation flow (certin_attest: an uploaded
# attestation flips "not evidenceable from BOM" to "pass with evidence").
# ---------------------------------------------------------------------------------------------
_HEAD_A = "A. Third-party cryptographic components"
_HEAD_A1 = "A.1 " + authored.PREVIOUSLY_SEEN_TITLE
_HEAD_B = "B. Control attestation ledger"
_HEAD_C = "C. Attestation summary"
_HEAD_D = "D. Vendor attestation register"
_HEAD_E = "E. Sign-off"
_SIGNOFF_ROLES = ("Prepared by", "Reviewed by", "Approved by")

_LIBRARY_SUMMARY = (
    "{libraries} found in {with_libs} of {sources}; {multi} used by more than one source."
)
_LIBRARY_NONE = "No cryptographic libraries were recorded in the current scans."
_LEDGER_INTRO = (
    "Controls the BOM cannot evidence on its own ({nbe}) or that an uploaded attestation has "
    "already evidenced ({pwe}), rolled up across the current scan of each source. Attested k/n "
    "means k of the n sources that need the control have an attestation on file; sources where "
    "the control does not apply are not counted."
)
_LEDGER_BASIS = (
    "Pooled over {pooled} current full-fidelity {sources}; legacy-format sources not pooled "
    "(they carry no compliance results): {legacy}."
)
_LEDGER_NONE_POOLED = (
    "No control in the pooled scans needs an attestation: the BOM evidences every control "
    "that applies, or none applies."
)
_LEDGER_NONE_LEGACY = (
    "Legacy-format scans carry no compliance results, so no control can be listed. "
    "Re-scan the affected sources to populate this ledger."
)
_LEDGER_NONE_SCANS = "No compliance results are available yet: no CBOM scan has completed."
_CAP_NOTICE = (
    "{omitted} further rows omitted: showing the first {shown} of {total} {noun} "
    "(cap {cap} rows)."
)
_KPI_COUNTS_ALL = "The summary counts all {total} controls, including the rows omitted above."

# Column layouts: header labels (the "(assessor)" suffix is added by dense_table to manual
# columns) and relative widths, scaled to the frame width.
_LIB_COLUMNS = (
    "Library",
    "#Sources",
    "Sources",
    "First seen",
    "Last seen",
    "Version (not captured)",
    "Vendor",
    "FIPS 140-3 / CMVP cert #",
    "SOC 2 / ISO 27001 ref",
    "PQC statement",
    "Attestation status",
)
_LIB_WEIGHTS = (100, 38, 168, 48, 48, 46, 54, 60, 60, 46, 52)  # Sources fits the longest label
_LIB_MANUAL = tuple(range(5, len(_LIB_COLUMNS)))  # version + vendor-assurance columns
_PREVIOUS_COLUMNS = _LIB_COLUMNS[:5]
_PREVIOUS_WEIGHTS = (150, 50, 320, 100, 100)
_LEDGER_COLUMNS = (
    "Framework",
    "Req ID",
    "Title",
    "Source citation",
    "Sources in scope",
    "Attested k/n",
    "Latest attestation (file \u00b7 note \u00b7 date)",
)
_LEDGER_WEIGHTS = (114, 100, 148, 96, 44, 66, 152)  # Framework fits "CERT-In CBOM (...v2.0)"
_ID_COLUMN = 1  # index of "Req ID" in _LEDGER_COLUMNS

_FRAMEWORK_RANK = {key: index for index, key in enumerate(authored.FRAMEWORK_LABELS)}
_DIGIT_RUN = re.compile(r"(\d+)")
_ISO_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_ID_PIECE = re.compile(r"[^-/._]+[-/._]*|[-/._]+")  # a word plus the delimiter that follows it


# ---------------------------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------------------------
def _widths(weights: Sequence[float], width: float) -> list[float]:
    """Column widths in points: ``weights`` scaled to exactly ``width``."""
    total = float(sum(weights))
    scaled = [round(weight * width / total, 2) for weight in weights]
    widest = scaled.index(max(scaled))
    scaled[widest] = round(scaled[widest] + (width - sum(scaled)), 2)
    return scaled


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _natural_key(text: str) -> tuple[tuple[int, int, str], ...]:
    """Sort key that orders digit runs numerically: ``8.4.1.2`` before ``8.4.1.10``."""
    key: list[tuple[int, int, str]] = []
    for index, part in enumerate(_DIGIT_RUN.split(text.casefold())):
        if not part:
            continue
        if index % 2:  # a digit run: compare by length, then digits (no int(): hostile sizes)
            digits = part.lstrip("0") or "0"
            key.append((0, len(digits), digits))
        else:
            key.append((1, 0, part))
    return tuple(key)


def _non_negative(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _attested_counts(req: RequirementAgg) -> tuple[int, int]:
    """``(k, n)``: n sources need the control, k of them are attested (k never exceeds n)."""
    needing = _non_negative(req.attestable_sources)
    return min(_non_negative(req.attested_sources), needing), needing


def _attest_tone(attested: int, needing: int) -> str:
    """Chip tone: complete = low (green), partial = medium (amber), none = high (orange)."""
    if attested >= needing:
        return "low"
    return "medium" if attested > 0 else "high"


def _ledger_sort_key(req: RequirementAgg) -> tuple:
    framework, req_id = str(req.framework), str(req.req_id)
    rank = _FRAMEWORK_RANK.get(framework, len(_FRAMEWORK_RANK))
    return (rank, framework, _natural_key(req_id), req_id)


def _attestable(view: TeamCbomView) -> list[RequirementAgg]:
    """Ledger rows: controls with at least one source needing (or already holding) attestation."""
    rows = [req for req in view.requirements if _attested_counts(req)[1] > 0]
    return sorted(rows, key=_ledger_sort_key)


def _sorted_libs(libs: Sequence[LibAgg]) -> list[LibAgg]:
    return sorted(libs, key=lambda lib: (str(lib.key), str(lib.name)))


def _source_labels(lib: LibAgg, *, current: bool) -> list[str]:
    """Display labels of the sources a library is used in (current scans, or all history)."""
    names = dict(zip(lib.source_keys, lib.source_labels, strict=False))
    keys = lib.current_source_keys if current else lib.source_keys
    return [pdf_plain(names.get(key, key), limit=_LABEL_LIMIT) for key in keys]


def _sources_cell(labels: Sequence[str]) -> str:
    shown = list(labels[:_MAX_SOURCES_SHOWN])
    if len(labels) > len(shown):
        shown.append(f"+{len(labels) - len(shown)} more")
    return "\n".join(shown)


def _attestation_date(raw: str | None) -> str:
    text = pdf_plain(raw, limit=40).strip()
    match = _ISO_DAY.match(text)
    return match.group(0) if match else text


def _latest_attestation(req: RequirementAgg) -> str:
    """``file / note / date`` on separate lines; the note is dropped when it repeats the file."""
    name = pdf_plain(req.latest_attestation_file, limit=_FILE_LIMIT).strip()
    note = pdf_plain(req.latest_attestation_note, limit=_NOTE_LIMIT).strip()
    lines = [name, note if note != name else "", _attestation_date(req.latest_attestation_at)]
    kept = [line for line in lines if line]
    return "\n".join(kept) if kept else _DASH


def _break_identifier(text: str, font: str, size: float, max_width: float) -> str:
    """Wrap an identifier onto lines of at most ``max_width`` points, breaking only after a
    hyphen, slash, dot or underscore.

    reportlab breaks a long word anywhere (``T9-Certificates-Ex`` / ``tension``); a requirement
    id such as ``T9-Certificates-Subject-Public-Key-Reference`` reads far better as
    ``T9-Certificates-Subject-`` / ``Public-Key-Reference``.  A single piece wider than the
    column is left whole and reportlab splits it.  The text itself is unchanged (``\\n`` only
    stands where a line ends), so removing the line breaks restores the id.
    """
    lines: list[str] = []
    line = ""
    for piece in _ID_PIECE.findall(text):
        if line and stringWidth(line + piece, font, size) > max_width:
            lines.append(line)
            line = piece
        else:
            line += piece
    if line:
        lines.append(line)
    return "\n".join(lines)


def _cap_notice(omitted: int, shown: int, total: int, noun: str, cap: int) -> str:
    return _CAP_NOTICE.format(omitted=omitted, shown=shown, total=total, noun=noun, cap=cap)


def _note(text: str, styles: Styles, *, style: str = "muted") -> Paragraph:
    return Paragraph(pdf_text(text, limit=700), styles[style])


# ---------------------------------------------------------------------------------------------
# A. Third-party cryptographic components
# ---------------------------------------------------------------------------------------------
def _library_row(lib: LibAgg) -> list[object]:
    labels = _source_labels(lib, current=True)
    return [
        lib.name,
        str(len(labels)),
        _sources_cell(labels),
        fmt_date_utc(lib.first_seen),
        fmt_date_utc(lib.last_seen),
        *([""] * len(_LIB_MANUAL)),  # version + vendor assurance: left for the assessor
    ]


def _previous_row(lib: LibAgg) -> list[object]:
    labels = _source_labels(lib, current=False)
    return [
        lib.name,
        str(len(labels)),
        _sources_cell(labels),
        fmt_date_utc(lib.first_seen),
        fmt_date_utc(lib.last_seen),
    ]


def _library_summary(view: TeamCbomView, current: Sequence[LibAgg]) -> str:
    if not current:
        return _LIBRARY_NONE
    with_libs = len({key for lib in current for key in lib.current_source_keys})
    sources = max(len(view.sources), with_libs)
    multi = sum(1 for lib in current if len(lib.current_source_keys) > 1)
    return _LIBRARY_SUMMARY.format(
        libraries=_plural(len(current), "cryptographic library", "cryptographic libraries"),
        with_libs=with_libs,
        sources=_plural(sources, "source", "sources"),
        multi=multi,
    )


def _components_section(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    libs = _sorted_libs(view.libs)
    current = [lib for lib in libs if lib.current]
    previous = [lib for lib in libs if not lib.current]
    shown = current[:MAX_LIBRARY_ROWS]

    story: list[Flowable] = [
        *section_heading(_HEAD_A, styles, min_space=_MIN_SPACE_COMPONENTS),
        _note(authored.ASSURANCE_LIBRARY_NOTE, styles),
        _note(_library_summary(view, current), styles, style="body"),
        dense_table(
            _LIB_COLUMNS,
            [_library_row(lib) for lib in shown],
            _widths(_LIB_WEIGHTS, width),
            manual_cols=_LIB_MANUAL,
        ),
    ]
    if len(current) > len(shown):
        notice = _cap_notice(
            len(current) - len(shown), len(shown), len(current), "libraries", MAX_LIBRARY_ROWS
        )
        story += [Spacer(1, 3), _note(notice, styles)]
    if previous:
        old = previous[:MAX_LIBRARY_ROWS]
        story += [
            *section_heading(_HEAD_A1, styles, min_space=_MIN_SPACE_COMPONENTS),
            dense_table(
                _PREVIOUS_COLUMNS,
                [_previous_row(lib) for lib in old],
                _widths(_PREVIOUS_WEIGHTS, width),
            ),
        ]
        if len(previous) > len(old):
            notice = _cap_notice(
                len(previous) - len(old), len(old), len(previous), "libraries", MAX_LIBRARY_ROWS
            )
            story += [Spacer(1, 3), _note(notice, styles)]
    story.append(Spacer(1, 8))
    return story


# ---------------------------------------------------------------------------------------------
# B. Control attestation ledger
# ---------------------------------------------------------------------------------------------
def _ledger_row(req: RequirementAgg, styles: Styles, id_width: float) -> list[object]:
    attested, needing = _attested_counts(req)
    cell = styles["dense_cell"]
    req_id = _break_identifier(
        pdf_plain(req.req_id, limit=_ID_LIMIT), cell.fontName, cell.fontSize, id_width
    )
    in_scope = sum(
        1 for verdict in req.verdicts.values() if verdict not in (VERDICT_OUT_OF_SCOPE, VERDICT_NA)
    )
    chip = status_chip(
        authored.ATTESTED_TEMPLATE.format(attested=attested, attestable=needing),
        _attest_tone(attested, needing),
    )
    return [
        authored.framework_label(req.framework),
        req_id,
        req.title or _DASH,
        req.citation or _DASH,
        str(max(needing, in_scope)),  # a source that needs the control always has it in scope
        chip,
        _latest_attestation(req),
    ]


def _ledger_empty_note(view: TeamCbomView) -> str:
    if _non_negative(view.compliance_sources_pooled) > 0:
        return _LEDGER_NONE_POOLED
    if _non_negative(view.compliance_legacy_excluded) > 0:
        return _LEDGER_NONE_LEGACY
    return _LEDGER_NONE_SCANS


def _ledger_section(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    rows = _attestable(view)
    shown = rows[:MAX_LEDGER_ROWS]
    pooled = _non_negative(view.compliance_sources_pooled)
    intro = _LEDGER_INTRO.format(
        nbe=authored.VERDICT_LABELS["not_bom_evidenceable"],
        pwe=authored.VERDICT_LABELS["pass_with_evidence"],
    )
    basis = _LEDGER_BASIS.format(
        pooled=pooled,
        sources="source" if pooled == 1 else "sources",
        legacy=_non_negative(view.compliance_legacy_excluded),
    )
    story: list[Flowable] = [
        *section_heading(_HEAD_B, styles, min_space=_MIN_SPACE_LEDGER),
        _note(intro, styles),
        _note(basis, styles),
    ]
    if not rows:
        story.append(_note(_ledger_empty_note(view), styles, style="body"))
    widths = _widths(_LEDGER_WEIGHTS, width)
    id_width = widths[_ID_COLUMN] - _CELL_PADDING - 1  # 1 pt of slack against rounding
    story.append(
        dense_table(
            _LEDGER_COLUMNS,
            [_ledger_row(req, styles, id_width) for req in shown],
            widths,
        )
    )
    if len(rows) > len(shown):
        notice = _cap_notice(
            len(rows) - len(shown), len(shown), len(rows), "controls", MAX_LEDGER_ROWS
        )
        story += [Spacer(1, 3), _note(notice, styles)]
    story.append(Spacer(1, 8))
    return story


# ---------------------------------------------------------------------------------------------
# C. Attestation summary
# ---------------------------------------------------------------------------------------------
def _summary_section(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    counts = [_attested_counts(req) for req in _attestable(view)]
    total = len(counts)
    fully = sum(1 for attested, needing in counts if attested >= needing)
    partly = sum(1 for attested, needing in counts if 0 < attested < needing)
    attested_sources = sum(attested for attested, _needing in counts)
    needing_sources = sum(needing for _attested, needing in counts)
    percent = f"{100.0 * attested_sources / needing_sources:.1f}%" if needing_sources else "n/a"
    sources_hint = (
        f"{attested_sources} of {needing_sources} source-level attestations"
        if needing_sources
        else "no control needs attestation"
    )
    cards = [
        (
            "Controls needing attestation",
            str(total),
            "framework/requirement pairs the BOM cannot evidence",
        ),
        ("Fully attested", str(fully), "attested in every source that needs the control"),
        ("Partly attested", str(partly), "attested in some, but not all, sources"),
        ("Attested (source level)", percent, sources_hint),
    ]
    story: list[Flowable] = [
        *section_heading(_HEAD_C, styles, min_space=130),
        kpi_strip(cards, width),
    ]
    if total > MAX_LEDGER_ROWS:
        story += [Spacer(1, 3), _note(_KPI_COUNTS_ALL.format(total=total), styles)]
    story.append(Spacer(1, 8))
    return story


# ---------------------------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------------------------
def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """The document body: sections A to E.  ``width`` is the usable frame width in points.

    Public so tests (and the registry) can inspect the flowables; ``build_pdf`` wraps it in the
    shared document shell (masthead, control table, Basis box, disclaimers, banners).
    """
    return [
        _note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        *_components_section(view, styles, width),
        *_ledger_section(view, styles, width),
        *_summary_section(view, styles, width),
        manual_form(_HEAD_D, authored.ASSURANCE_VENDOR_COLUMNS, VENDOR_BLANK_ROWS, width=width),
        Spacer(1, 10),
        signoff_block(_SIGNOFF_ROLES, title=_HEAD_E, width=width),
    ]


def build_pdf(view: TeamCbomView) -> bytes:
    """Render the register for ``view`` as a landscape PDF (bytes, deterministic for a view)."""
    return build_document(
        view=view,
        number=DOCUMENT_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=True,
        body=lambda styles, width: build_story(view, styles, width),
    )


__all__ = ["build_pdf"]
