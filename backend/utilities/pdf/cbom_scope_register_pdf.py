"""Scope Baseline & Asset Population Register (deliverable #1): the team-wide PDF renderer.

One portrait PDF that records WHAT was assessed for a team: the sources (repositories, archives,
uploaded CBOM files) behind its completed CBOM scans, the cryptographic asset population found in
them, how every scan was treated, and the parts of the scope a static scan cannot know, which are
left as blank forms for the assessor.  Sections, in order:

    A. Assessment boundary            manual: boundary items, boundary statement and approver
    B. Sources assessed               live: one row per source, Owner / Business system blank
    C. Asset population               live: by type x impact, and by source
    D. Exclusions and data quality    live: every scan accounted for, why some were left out
    E. Outside static visibility      manual: checklist with blank status / owner / evidence
    F. Sign-off                       manual: blank

Contract (plan 5.2 / 5.4): ``build_pdf(view: TeamCbomView) -> bytes`` is a pure function of the
view.  ``build_body(view, styles, width)`` returns the document-specific flowables and is public
only so tests can inspect the structure (for example that a manual cell is truly empty).

Rules this module keeps (enforced by the T-1 tests and the T-NOLLM guards):

* reportlab and the standard library only, plus ``backend.utilities.pdf.*`` and the aggregator
  module ``backend.utilities.dashboard.cbom_team_rollup``; never a router, never anything that
  could reach a language model or the network.
* No wall clock: every date comes from the view (``generated_at`` / ``as_of`` and the scan
  dates), so the same view gives byte-identical output.
* Every data-derived string (labels, URLs, branches, titles, statuses) reaches a Paragraph only
  through ``pdf_text`` or a ``dense_table`` / ``status_chip`` helper, which sanitise, clamp and
  escape it.  Scanned repositories are untrusted input.
* Repository URLs are sanitised once more at render time, so a credential could not reach the
  page even through a hand-built view.
* Manual cells ("(assessor)") are empty.  Nothing is pre-filled, guessed or marked "N/A".
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timezone

from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    ASSET_CERTIFICATE,
    ASSET_MATERIAL,
    ASSET_OTHER,
    ASSET_PROTOCOL,
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    FIDELITY_FULL,
    IMPACT_LEVELS,
    INFO,
    SOURCE_FILE,
    SOURCE_REPO,
    SOURCE_SCAN,
    SOURCE_ZIP,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    ScanFacts,
    SourceAgg,
    TeamCbomView,
    sanitize_repo_url,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    fmt_date_utc,
    kpi_strip,
    pdf_text,
    section_heading,
    signoff_block,
    status_chip,
)
from backend.utilities.pdf.report_branding import REPORT_META

REPORT_KEY = "cbom_scope_register"
DELIVERABLE_NUMBER = 1
TITLE = REPORT_META[REPORT_KEY]["title"]

# Table caps (plan 4.7): an explicit omission notice is printed whenever a cap bites.
MAX_SOURCE_ROWS = 500
MAX_EXCLUDED_ROWS = 100
_MAX_NAMED_SOURCES = 10  # legacy sources spelled out in the data-quality table

_DASH = "\u2014"
_WRITE_IN_HEIGHT = 16  # points of blank room in a manual cell (row = this + padding)
_STATEMENT_HEIGHT = 36

# ---------------------------------------------------------------------------------------------
# Authored text.  Product wording specific to THIS document (it describes what the register
# does; it makes no standards or regulatory claim).  Shared wording, and every sentence that
# cites a public source, lives in ``cbom_deliverable_text`` (banners, disclaimers, boundary
# items, the outside-visibility checklist, the failed-latest template).
# ---------------------------------------------------------------------------------------------
# Product text: how a source is identified (cbom_team_rollup.source_key_for, plan 4.3).
_SOURCES_INTRO = (
    "Sources assessed: {sources}. Completed scans included: {included}. A source is one "
    "repository branch, one uploaded archive or one uploaded CBOM file; its current state is "
    "its latest successful scan."
)
_SOURCES_NONE = (
    "No sources have been assessed: no completed CBOM scan exists for this team, so there is "
    "nothing to list."
)
_SOURCES_LIMITS = (
    "Limits: the same repository on two branches is two sources; two uploaded archives with "
    "the same title are one source."
)
_ASSETS_LEGEND = (
    "Assets: algorithms / certificates / protocols / key material / libraries, counted in the "
    "source's current scan."
)
_LEGACY_LEGEND = (
    "Legacy: the scan predates the current CBOM engine (reduced fidelity). Certificate "
    "details, compliance results and post-quantum target sizing may be incomplete; re-scan "
    "the source to restore full detail."
)
# Plan 4.5 failed-latest rule.  A failed attempt uses the authored SOURCE_FAILED_LATEST; the
# two other ways a newest attempt can differ from the scan the figures come from get the same
# shape, so the register never calls a queued or empty scan "failed".
_ATTEMPT_NOT_COMPLETED = (
    "most recent attempt has not completed (scan #{attempt_id}, {attempt_date}); "
    "figures reflect scan #{current_id} of {current_date}"
)
_ATTEMPT_NO_DATA = (
    "most recent attempt completed without usable data (scan #{attempt_id}, {attempt_date}); "
    "figures reflect scan #{current_id} of {current_date}"
)

# Product text: what the counts mean (cbom_team_rollup: assets are never merged across sources).
_POPULATION_BASIS = (
    "Counts describe the current state: the latest successful scan of each source. An asset is "
    "one finding row of a scan. The same algorithm used in two sources is counted twice "
    "because each source's use is a separate exposure; certificates are also de-duplicated "
    "across sources in the {cert_register}."
)
_LIBRARIES_LINE = (
    "Crypto libraries: {unique} unique across sources ({occurrences} source-level "
    "occurrences). They are listed in the {assurance_register}."
)
_EXCLUSIONS_INTRO = (
    "Only successful scans that returned data contribute to this register. The table below "
    "accounts for every CBOM scan of the team; scans of other types and of other teams are "
    "never read."
)
_NO_EXCLUDED = "No scans were excluded."
_EXCLUDED_REASONS = {
    EXCLUDED_FAILURE: "The scan failed, so no data was read.",
    EXCLUDED_NOT_COMPLETED: "The scan had not completed, so no data was read.",
    EXCLUDED_NO_DATA: "The scan completed but its result holds no usable data.",
}
_EXCLUDED_REASON_DEFAULT = "The scan was not included in this register."

_BOUNDARY_INTRO = (
    "The platform records what the scanned sources contain. Which applications, "
    "infrastructure, APIs, cloud accounts and third parties fall inside the assessment "
    "boundary is an assessor decision: complete the shaded cells below. Nothing in them is "
    "pre-filled from scan data."
)
_VISIBILITY_INTRO = (
    "A static scan of repositories and uploaded artefacts cannot see the items below. For each "
    "one, record how it is assessed, who owns it and where the evidence is kept."
)
_SIGNOFF_ROLES = ("Prepared by", "Reviewed by", "Approved by")

_KIND_LABELS = {
    SOURCE_REPO: "Repository",
    SOURCE_ZIP: "Zip upload",
    SOURCE_FILE: "CBOM file upload",
    SOURCE_SCAN: "Scan",
    "sources": "CBOM Sources collection",  # cbom_team_rollup.SOURCE_SOURCES (merge_collections)
}
_TYPE_LABELS = {
    ASSET_ALGORITHM: "Algorithms",
    ASSET_CERTIFICATE: "Certificates",
    ASSET_PROTOCOL: "Protocols",
    ASSET_MATERIAL: "Key material",
}
_MAIN_TYPES = tuple(_TYPE_LABELS)
_OTHER_IMPACT = "Other"

# Column widths in points for a 540 pt frame; ``_scaled`` stretches them to the real width.
_SOURCE_HEADERS = (
    "#",
    "Source",
    "Repository (sanitised)",
    "Scans",
    "First scanned",
    "Last scanned (age)",
    "Last attempt",
    "Fidelity",
    "Assets",
    "Owner",
    "Business system",
)
_SOURCE_WIDTHS = (14, 74, 82, 28, 46, 50, 78, 38, 42, 44, 44)
_SOURCE_MANUAL = (9, 10)
_BASIS_WIDTHS = (440, 100)
_EXCLUDED_HEADERS = ("Scan", "Title", "Source", "Created", "Status", "Reason")
_EXCLUDED_WIDTHS = (34, 100, 150, 52, 66, 138)
_QUALITY_WIDTHS = (230, 310)
_BOUNDARY_WIDTHS = (150, 270, 120)
_STATEMENT_WIDTHS = (300, 160, 80)
_CHECKLIST_WIDTHS = (108, 188, 80, 80, 84)
_BY_SOURCE_FIXED = {  # numeric columns of the population-by-source table
    "Algorithms": 44,
    "Certificates": 46,
    "Protocols": 40,
    "Key material": 40,
    "Other types": 40,
    "Total": 34,
    "Libraries": 46,
    "Critical": 36,
    "High": 30,
    "Medium": 36,
    "Low": 30,
    INFO: 28,  # clean inventory (no finding), shown only when present
    _OTHER_IMPACT: 30,
}


# ---------------------------------------------------------------------------------------------
# Small total helpers (hand-built views may carry odd values; nothing here may raise)
# ---------------------------------------------------------------------------------------------
def _num(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _count(counts: Mapping[str, int] | None, key: str) -> int:
    return _num(counts.get(key, 0)) if isinstance(counts, Mapping) else 0


def _extra(counts: Mapping[str, int] | None, known: Sequence[str]) -> int:
    """Sum of the buckets of ``counts`` that are not one of the ``known`` keys."""
    if not isinstance(counts, Mapping):
        return 0
    return sum(_num(value) for key, value in counts.items() if key not in known)


def _scaled(base: Sequence[float], width: float) -> list[float]:
    total = float(sum(base))
    return [part * width / total for part in base]


def _day(moment: object) -> date | None:
    """The UTC calendar day of a datetime (naive values are UTC), or of a date."""
    if isinstance(moment, datetime):
        aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).date()
    return moment if isinstance(moment, date) else None


def _age_text(as_of: date, moment: object) -> str:
    """``today`` / ``1 day ago`` / ``N days ago``; empty for a missing or future date."""
    day = _day(moment)
    if day is None:
        return ""
    days = (as_of - day).days
    if days < 0:
        return ""
    if days == 0:
        return "today"
    return "1 day ago" if days == 1 else f"{days} days ago"


def _para(text: str, style: ParagraphStyle, *, limit: int = 1500) -> Paragraph:
    return Paragraph(pdf_text(text, limit=limit), style)


def _blank(height: float) -> Spacer:
    """An empty cell with room to write; carries no text at all."""
    return Spacer(1, height)


def _sub(text: str, styles: Styles) -> Paragraph:
    return Paragraph(pdf_text(text, limit=160), styles["box_title"])


def _sub_with_room(text: str, styles: Styles, room: float = 90) -> list[Flowable]:
    """A sub-heading for a table that may be long: it starts a new page rather than being left
    alone at the foot of one (``room`` = heading plus the table header and a couple of rows)."""
    return [CondPageBreak(room), _sub(text, styles)]


def _notice_sources(omitted: int) -> str:
    noun = "source is" if omitted == 1 else "sources are"
    return f"{omitted} further {noun} not listed; the totals still include every source."


def _notice_excluded(omitted: int) -> str:
    noun = "excluded scan is" if omitted == 1 else "excluded scans are"
    return f"{omitted} further {noun} not listed."


def _unique_libraries(view: TeamCbomView) -> int:
    return sum(1 for lib in view.libs if lib.current)


def _unique_certificates(view: TeamCbomView) -> int:
    return sum(1 for cert in view.certs if cert.current)


# ---------------------------------------------------------------------------------------------
# Intro
# ---------------------------------------------------------------------------------------------
def _intro(styles: Styles) -> list[Flowable]:
    meta = REPORT_META[REPORT_KEY]
    return [_para(meta["intro"], styles["body"]), _para(meta["how_to_read"], styles["muted"])]


# ---------------------------------------------------------------------------------------------
# A. Assessment boundary (manual)
# ---------------------------------------------------------------------------------------------
def _section_boundary(styles: Styles, width: float) -> list[Flowable]:
    items = [
        [item, _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT)]
        for item in authored.SCOPE_BOUNDARY_ITEMS
    ]
    boundary = dense_table(
        authored.SCOPE_BOUNDARY_COLUMNS, items, _scaled(_BOUNDARY_WIDTHS, width), manual_cols=(1, 2)
    )
    statement = dense_table(
        ("Boundary statement", "Approver, name and role", "Date"),
        [[_blank(_STATEMENT_HEIGHT) for _ in range(3)]],
        _scaled(_STATEMENT_WIDTHS, width),
        manual_cols=(0, 1, 2),
    )
    return [
        *section_heading("A. Assessment boundary", styles, min_space=180),
        _para(_BOUNDARY_INTRO, styles["muted"]),
        _para(authored.MANUAL_CELL_NOTE, styles["muted"]),
        KeepTogether([_sub("Boundary items", styles), boundary]),
        Spacer(1, 6),
        KeepTogether([_sub(authored.SCOPE_BOUNDARY_STATEMENT, styles), statement]),
    ]


# ---------------------------------------------------------------------------------------------
# B. Sources assessed
# ---------------------------------------------------------------------------------------------
def _attempt_parts(source: SourceAgg) -> tuple[str, str, str]:
    """``(chip text, chip tone, detail)`` for a source's most recent attempt (plan 4.5)."""
    current_id, attempt_id = _num(source.current_scan_id), _num(source.last_attempt_scan_id)
    if attempt_id == current_id:
        return "SUCCESS", "low", f"scan #{current_id}"
    status = str(source.last_attempt_status or "").strip().lower()
    attempt_date = fmt_date_utc(source.last_attempt_at)
    current_date = fmt_date_utc(source.last_scanned)
    if status == STATUS_FAILURE:
        detail = authored.SOURCE_FAILED_LATEST.format(
            failed_date=attempt_date,
            failed_scan_id=attempt_id,
            current_scan_id=current_id,
            current_date=current_date,
        )
        return "FAILED", "critical", detail
    template, chip = (
        (_ATTEMPT_NO_DATA, "NO DATA")
        if status == STATUS_SUCCESS
        else (_ATTEMPT_NOT_COMPLETED, "NOT COMPLETED")
    )
    detail = template.format(
        attempt_id=attempt_id,
        attempt_date=attempt_date,
        current_id=current_id,
        current_date=current_date,
    )
    return chip, "medium", detail


def _attempt_cell(source: SourceAgg, styles: Styles) -> list[Flowable]:
    chip, tone, detail = _attempt_parts(source)
    return [
        status_chip(chip, tone),
        Spacer(1, 2),
        Paragraph(pdf_text(detail, limit=400), styles["dense_cell"]),
    ]


def _compact_assets(source: SourceAgg) -> str:
    counts = source.asset_counts
    parts = [_count(counts, kind) for kind in _MAIN_TYPES] + [_num(source.library_count)]
    text = "/".join(str(part) for part in parts)
    other = _extra(counts, _MAIN_TYPES)
    return f"{text}\n+{other} other" if other else text


def _source_row(
    index: int, source: SourceAgg, view: TeamCbomView, styles: Styles
) -> list[object]:
    label = source.label or source.key or _DASH
    repo = [sanitize_repo_url(source.repo_url) or _DASH]
    if source.branch:
        repo.append(f"branch: {source.branch}")
    scanned = [fmt_date_utc(source.last_scanned)]
    age = _age_text(view.as_of, source.last_scanned)
    if age:
        scanned.append(age)
    full = source.current_fidelity == FIDELITY_FULL
    return [
        str(index),
        f"{label}\n{_KIND_LABELS.get(source.kind, 'Source')}",
        "\n".join(repo),
        str(_num(source.scan_count)),
        fmt_date_utc(source.first_scanned),
        "\n".join(scanned),
        _attempt_cell(source, styles),
        status_chip("FULL" if full else "LEGACY", "low" if full else "medium"),
        _compact_assets(source),
        "",  # Owner (assessor)
        "",  # Business system (assessor)
    ]


def _section_sources(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    sources = list(view.sources)
    shown = sources[: max(0, MAX_SOURCE_ROWS)]
    intro = (
        _SOURCES_INTRO.format(sources=len(sources), included=_num(view.included))
        if sources
        else _SOURCES_NONE
    )
    table = dense_table(
        _SOURCE_HEADERS,
        [_source_row(i, source, view, styles) for i, source in enumerate(shown, start=1)],
        _scaled(_SOURCE_WIDTHS, width),
        manual_cols=_SOURCE_MANUAL,
    )
    story: list[Flowable] = [
        *section_heading("B. Sources assessed", styles, min_space=160),
        _para(intro, styles["muted"]),
        table,
        Spacer(1, 4),
    ]
    if len(sources) > len(shown):
        story.append(_para(_notice_sources(len(sources) - len(shown)), styles["muted"]))
    notes = [_SOURCES_LIMITS, _ASSETS_LEGEND]
    if any(source.current_fidelity != FIDELITY_FULL for source in sources):
        notes.append(_LEGACY_LEGEND)
    story += [_para(note, styles["dense_muted"]) for note in notes]
    return story


# ---------------------------------------------------------------------------------------------
# C. Asset population
# ---------------------------------------------------------------------------------------------
def _type_bucket(asset_type: object) -> str:
    known = isinstance(asset_type, str) and asset_type in _TYPE_LABELS
    return str(asset_type) if known else ASSET_OTHER


def _impact_bucket(impact: object) -> str:
    known = isinstance(impact, str) and impact in (*IMPACT_LEVELS, INFO)
    return str(impact) if known else _OTHER_IMPACT


def _impact_columns(present: Iterable[str]) -> list[str]:
    """The four severities, then Info (clean inventory, no finding) and Other only when some asset has them."""
    seen = set(present)
    return list(IMPACT_LEVELS) + [extra for extra in (INFO, _OTHER_IMPACT) if extra in seen]


def _population_kpis(view: TeamCbomView) -> list[tuple[str, str, str]]:
    by_type = view.assets_by_type
    return [
        ("Sources", str(len(view.sources)), "with a completed scan"),
        ("Asset occurrences", str(_num(view.asset_occurrences)), "current state"),
        ("Algorithms", str(_count(by_type, ASSET_ALGORITHM)), "occurrences"),
        (
            "Certificates",
            str(_count(by_type, ASSET_CERTIFICATE)),
            f"{_unique_certificates(view)} unique",
        ),
        ("Protocols", str(_count(by_type, ASSET_PROTOCOL)), "occurrences"),
        ("Key material", str(_count(by_type, ASSET_MATERIAL)), "occurrences"),
    ]


def _by_type_table(view: TeamCbomView, width: float) -> Flowable:
    """Current assets by type (rows) and impact (columns), with a total row."""
    cells: Counter[tuple[str, str]] = Counter()
    for asset in view.assets:
        if asset.current:
            cells[(_type_bucket(asset.asset_type), _impact_bucket(asset.impact))] += 1
    types = list(_MAIN_TYPES) + ([ASSET_OTHER] if any(t == ASSET_OTHER for t, _ in cells) else [])
    impacts = _impact_columns(i for _, i in cells)
    rows: list[list[object]] = []
    for kind in types:
        counts = [cells.get((kind, impact), 0) for impact in impacts]
        label = _TYPE_LABELS.get(kind, "Other types")
        rows.append([label, *(str(n) for n in counts), str(sum(counts))])
    totals = [sum(cells.get((kind, impact), 0) for kind in types) for impact in impacts]
    rows.append(["All asset types", *(str(n) for n in totals), str(sum(totals))])
    numeric = (540.0 - 150.0) / (len(impacts) + 1)
    base = [150.0, *([numeric] * (len(impacts) + 1))]
    return dense_table(["Asset type", *impacts, "Total"], rows, _scaled(base, width))


def _by_source_table(view: TeamCbomView, shown: Sequence[SourceAgg], width: float) -> Flowable:
    """Current assets per source; the total row covers EVERY source, shown or not."""
    sources = list(view.sources)
    extra_types = any(_extra(s.asset_counts, _MAIN_TYPES) for s in sources)
    known = (*IMPACT_LEVELS, INFO)
    has_info = any(_count(s.impact_counts, INFO) for s in sources)
    extra_impacts = any(_extra(s.impact_counts, known) for s in sources)
    levels = [*IMPACT_LEVELS, INFO] if has_info else list(IMPACT_LEVELS)

    headers = ["#", "Source", *_TYPE_LABELS.values()]
    if extra_types:
        headers.append("Other types")
    headers += ["Total", "Libraries", *levels]
    if extra_impacts:
        headers.append(_OTHER_IMPACT)

    def type_counts(source: SourceAgg) -> list[int]:
        counts = [_count(source.asset_counts, kind) for kind in _MAIN_TYPES]
        return [*counts, _extra(source.asset_counts, _MAIN_TYPES)] if extra_types else counts

    def impact_counts(source: SourceAgg) -> list[int]:
        counts = [_count(source.impact_counts, level) for level in levels]
        return [*counts, _extra(source.impact_counts, known)] if extra_impacts else counts

    def line(
        index: str, label: str, types: list[int], libraries: str, impacts: list[int]
    ) -> list[object]:
        # Total = every asset type of the row, so the columns always add up
        return [
            index,
            label,
            *(str(n) for n in types),
            str(sum(types)),
            libraries,
            *(str(n) for n in impacts),
        ]

    rows = [
        line(
            str(index),
            source.label or source.key,
            type_counts(source),
            str(_num(source.library_count)),
            impact_counts(source),
        )
        for index, source in enumerate(shown, start=1)
    ]
    if sources:
        type_totals = [sum(col) for col in zip(*(type_counts(s) for s in sources), strict=True)]
        impact_totals = [sum(c) for c in zip(*(impact_counts(s) for s in sources), strict=True)]
        # libraries are de-duplicated across sources, so the cell is the unique count
        libraries = f"{_unique_libraries(view)} unique"
        rows.append(line("", "All sources", type_totals, libraries, impact_totals))
    fixed = [float(_BY_SOURCE_FIXED[name]) for name in headers[2:] if name in _BY_SOURCE_FIXED]
    widths = [14.0, 540.0 - 14.0 - sum(fixed), *fixed]
    return dense_table(headers, rows, _scaled(widths, width))


def _section_population(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    shown = list(view.sources)[: max(0, MAX_SOURCE_ROWS)]
    occurrences = sum(_num(source.library_count) for source in view.sources)
    basis = _POPULATION_BASIS.format(cert_register=REPORT_META["cbom_cert_register"]["title"])
    libraries = _LIBRARIES_LINE.format(
        unique=_unique_libraries(view),
        occurrences=occurrences,
        assurance_register=REPORT_META["cbom_assurance_register"]["title"],
    )
    story: list[Flowable] = [
        *section_heading("C. Asset population", styles, min_space=200),
        _para(basis, styles["muted"]),
        kpi_strip(_population_kpis(view), width),
        Spacer(1, 8),
        KeepTogether([_sub("Assets by type and impact", styles), _by_type_table(view, width)]),
        Spacer(1, 8),
        *_sub_with_room("Asset population by source", styles),
        _by_source_table(view, shown, width),
        Spacer(1, 4),
    ]
    if len(view.sources) > len(shown):
        omitted = len(view.sources) - len(shown)
        story.append(_para(_notice_sources(omitted), styles["dense_muted"]))
    story.append(_para(libraries, styles["dense_muted"]))
    return story


# ---------------------------------------------------------------------------------------------
# D. Exclusions and data quality
# ---------------------------------------------------------------------------------------------
def _basis_rows(view: TeamCbomView) -> list[list[object]]:
    excluded = view.excluded if isinstance(view.excluded, Mapping) else {}
    return [
        ["CBOM scans of the team", str(_num(view.scans_total))],
        ["Eligible: completed successfully", str(_num(view.eligible))],
        ["Included in this register", str(_num(view.included))],
        ["Excluded: failed", str(_count(excluded, EXCLUDED_FAILURE))],
        [
            "Excluded: not completed (queued, running or retrying)",
            str(_count(excluded, EXCLUDED_NOT_COMPLETED)),
        ],
        ["Excluded: completed without usable data", str(_count(excluded, EXCLUDED_NO_DATA))],
        ["Older scans not folded (history window)", str(_num(view.history_truncated))],
    ]


def _excluded_row(facts: ScanFacts) -> list[object]:
    return [
        f"#{_num(facts.scan_id)}",
        facts.title,
        facts.source_label,
        fmt_date_utc(facts.created_at),
        facts.status,
        _EXCLUDED_REASONS.get(facts.exclusion or "", _EXCLUDED_REASON_DEFAULT),
    ]


def _quality_rows(view: TeamCbomView) -> list[list[object]]:
    legacy = [s.label or s.key for s in view.sources if s.current_fidelity != FIDELITY_FULL]
    if legacy:
        named = "; ".join(legacy[:_MAX_NAMED_SOURCES])
        if len(legacy) > _MAX_NAMED_SOURCES:
            named += f"; and {len(legacy) - _MAX_NAMED_SOURCES} more"
        legacy_result = f"{len(legacy)}: {named}"
    else:
        legacy_result = "0"
    older_only = sum(1 for asset in view.assets if not asset.current)
    weak_identity = sum(1 for cert in view.certs if not cert.identity_strong)
    return [
        ["Sources represented by a legacy-format scan", legacy_result],
        ["Asset occurrences seen only in older scans", str(older_only)],
        ["Certificates identified without X.509 fields", str(weak_identity)],
        ["Input records skipped or corrected", str(len(view.warnings))],
    ]


def _section_exclusions(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    excluded = [facts for facts in view.scans if facts.exclusion is not None]
    shown = excluded[: max(0, MAX_EXCLUDED_ROWS)]
    story: list[Flowable] = [
        *section_heading("D. Exclusions and data quality", styles, min_space=200),
        _para(_EXCLUSIONS_INTRO, styles["muted"]),
        KeepTogether(
            [
                _sub("How each CBOM scan was treated", styles),
                dense_table(("Measure", "Scans"), _basis_rows(view), _scaled(_BASIS_WIDTHS, width)),
            ]
        ),
        Spacer(1, 8),
    ]
    if shown:
        story += [
            *_sub_with_room("Scans not included", styles),
            dense_table(
                _EXCLUDED_HEADERS,
                [_excluded_row(facts) for facts in shown],
                _scaled(_EXCLUDED_WIDTHS, width),
            ),
        ]
        if len(excluded) > len(shown):
            story += [
                Spacer(1, 2),
                _para(_notice_excluded(len(excluded) - len(shown)), styles["dense_muted"]),
            ]
    else:
        story += [_sub("Scans not included", styles), _para(_NO_EXCLUDED, styles["muted"])]
    story += [
        Spacer(1, 8),
        KeepTogether(
            [
                _sub("Data-quality checks", styles),
                dense_table(
                    ("Check", "Result"), _quality_rows(view), _scaled(_QUALITY_WIDTHS, width)
                ),
            ]
        ),
    ]
    return story


# ---------------------------------------------------------------------------------------------
# E. Outside static visibility (manual) and F. Sign-off (manual)
# ---------------------------------------------------------------------------------------------
def _section_visibility(styles: Styles, width: float) -> list[Flowable]:
    rows = [
        [item, why, _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT)]
        for item, why in authored.MANUAL_DISCOVERY_ITEMS
    ]
    table = dense_table(
        authored.MANUAL_DISCOVERY_COLUMNS,
        rows,
        _scaled(_CHECKLIST_WIDTHS, width),
        manual_cols=(2, 3, 4),
    )
    return [
        *section_heading("E. Outside static visibility", styles, min_space=160),
        _para(_VISIBILITY_INTRO, styles["muted"]),
        _para(authored.MANUAL_CELL_NOTE, styles["muted"]),
        table,
    ]


def _section_signoff(styles: Styles, width: float) -> list[Flowable]:
    return [
        *section_heading("F. Sign-off", styles, min_space=170),
        signoff_block(_SIGNOFF_ROLES, title=None, width=width),
    ]


# ---------------------------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------------------------
def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """The document-specific flowables (everything below the shared front matter)."""
    story: list[Flowable] = []
    story += _intro(styles)
    story += _section_boundary(styles, width)
    story += _section_sources(view, styles, width)
    story += _section_population(view, styles, width)
    story += _section_exclusions(view, styles, width)
    story += _section_visibility(styles, width)
    story += _section_signoff(styles, width)
    return story


def build_pdf(view: TeamCbomView) -> bytes:
    """Render deliverable #1 for ``view`` and return the PDF bytes (pure, deterministic)."""
    return build_document(
        view=view,
        number=DELIVERABLE_NUMBER,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=False,
        body=lambda styles, width: build_body(view, styles, width),
    )


__all__ = [
    "DELIVERABLE_NUMBER",
    "MAX_EXCLUDED_ROWS",
    "MAX_SOURCE_ROWS",
    "REPORT_KEY",
    "TITLE",
    "build_body",
    "build_pdf",
]
