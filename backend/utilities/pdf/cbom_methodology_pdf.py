"""#3 Cryptographic Discovery Methodology & Evidence Plan (team-wide CBOM deliverable, WP3b).

``build_pdf(view)`` renders one portrait PDF from a ``TeamCbomView``.  The document has eleven
numbered sections and an appendix:

1.  Purpose and scope             live: sources, scans, assets by type, KPI cards
2.  Automated discovery           the nine registered scanners, pinned to the engine registry
3.  Manual discovery checklist    what a static scan cannot see; status / owner / evidence BLANK
4.  Evidence sources and traceability   live "present for N of M" evidence counts
5.  Validation approach           authored: deterministic rules, schema validation, no ML
6.  Coverage methodology          authored tri-state semantics + live pooled table (13 frameworks)
7.  Confidence classification     authored scheme and its honest limit
8.  Ownership and responsibilities (RACI)   BLANK
9.  Evidence retention and versioning       what is stored per scan; retention period BLANK
10. Limits of the method
11. Sign-off                      BLANK
    Appendix A  every scan the edition considered, with its disposition

Everything a regulator reads as *words* comes from ``cbom_deliverable_text`` (authored, with
provenance); this module only adds the document-specific lead-in sentences, which describe the
renderer's own layout.  Figures come from the view and nowhere else.  Headline numbers are read
from ``view.*`` as they are; the only counting done here is of rows of ``view.certs`` (the
unique-certificates card) and of ``view.assets`` / ``view.certs`` (the "present for N of M"
evidence table), never a new aggregate such as a score or a grade.

Manual cells ("Status", "Owner", RACI, retention period, sign-off) are rendered as empty tinted
cells carrying the ``(assessor)`` suffix in their header.  They are never pre-filled.

Hard rules (enforced by ``test_cbom_deliverable_methodology.py``): reportlab and the standard
library only, plus ``backend.utilities.pdf.*`` and the roll-up types; no network, no language
model, no wall clock (every date comes from the view); every data-derived string reaches a
``Paragraph`` through ``pdf_text`` (scanned repositories are untrusted input); Helvetica and
Courier only; Python 3.10 syntax.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    ASSET_OTHER,
    ASSET_TYPES,
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    FIDELITY_FULL,
    HISTORY_WINDOW,
    SOURCE_FILE,
    SOURCE_REPO,
    SOURCE_SCAN,
    SOURCE_ZIP,
    FrameworkPool,
    ScanFacts,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_deliverable_common import (
    TEMPLATE_VERSION,
    Styles,
    build_document,
    dense_table,
    document_id,
    fmt_date_utc,
    kpi_strip,
    pdf_text,
    section_heading,
    signoff_block,
)
from backend.utilities.pdf.report_branding import REPORT_META

SLUG = "methodology-evidence-plan"
NUMBER = 3  # "D03" in the Document ID
REPORT_KEY = "cbom_methodology"  # REPORT_META key: page header and footer label
TITLE = REPORT_META[REPORT_KEY]["title"]

# Appendix A lists at most this many scans (newest first); the rest get a one-line notice.
MAX_SCAN_ROWS = 500

SECTION_TITLES = (
    "Purpose and scope",
    "Automated discovery",
    "Manual discovery checklist",
    "Evidence sources and traceability",
    "Validation approach",
    "Coverage methodology",
    "Confidence classification",
    "Ownership and responsibilities (RACI)",
    "Evidence retention and versioning",
    "Limits of the method",
    "Sign-off",
)
APPENDIX_TITLE = "Appendix A. Scans considered"
SIGNOFF_ROLES = ("Prepared by", "Reviewed by (CISO)", "Approved by")

# Document-specific lead-in sentences.  Provenance (plan 5.7): none of them is a standards or
# regulatory claim; each describes this document's own tables or the product's behaviour, so
# each carries a "Product text:" comment naming the code it describes.
#
# Product text: plan 4.6 (empty team) - the same stance as the "NO COMPLETED CBOM SCANS" banner.
EMPTY_SCOPE = (
    "No completed CBOM scan is available for this team yet, so this edition reports no live "
    "figures. The method below applies to every scan the team runs."
)
# Product text: the checklist columns are left blank by design (cbom_deliverable_text
# MANUAL_DISCOVERY_ITEMS); nothing in the platform records manual discovery.
MANUAL_INTRO = (
    "These discovery activities cannot be performed by static analysis. Record the status, "
    "owner and evidence reference for each one; the platform leaves them blank."
)
# Product text: ownership is not stored anywhere in the platform.
RACI_INTRO = (
    "Name who is responsible, accountable, consulted and informed for each activity. The "
    "platform does not pre-fill this table."
)
# Product text: the pooled counts and the coverage of backend/utilities/dashboard/
# cbom_team_rollup.py FrameworkPool (aibom compliance engine rule: pass / (pass + fail)).
COVERAGE_FORMULA_NOTE = (
    "Coverage = (Pass + Pass with evidence) / (Pass + Pass with evidence + Fail). Not "
    "evidenceable and out-of-scope requirements are shown as their own counts and are never "
    "counted as passes."
)
# Product text: asset occurrences are per source, certificates are de-duplicated (plan 4.4).
ASSET_TABLE_NOTE = (
    "Occurrences are counted per source and file and are not merged, because each source's "
    "usage is a separate exposure. A certificate found in several places is several "
    "occurrences here but one unique certificate in the card above."
)
# Product text: current / history-only scans and exclusions (plan 4.1 and 4.5).
SCAN_APPENDIX_INTRO = (
    "Every CBOM scan of this team that this edition considered, newest first. 'Current for "
    "source' marks the scan that defines a source's present state; 'History only' scans "
    "contribute first-seen and last-seen dates; excluded scans contribute nothing."
)

# ---------------------------------------------------------------------------------------------
# Small private helpers
# ---------------------------------------------------------------------------------------------
_DASH = "\u2014"
_BULLET = "\u2022"
_TEXT_LIMIT = 2000  # authored paragraphs are long; pdf_text's default (300) would cut them
_CELL_LIMIT = 700  # scanner descriptions run to ~290 characters; leave generous headroom
_BLANK_HEIGHT = 18  # write-in cells are at least this tall (points)

_ASSET_TYPE_LABELS = {
    "algorithm": "Algorithm",
    "certificate": "Certificate",
    "protocol": "Protocol",
    "related-crypto-material": "Related crypto material",
    ASSET_OTHER: "Other",
}
_SOURCE_KIND_NOUNS = (
    (SOURCE_REPO, "repository", "repositories"),
    (SOURCE_ZIP, "zip upload", "zip uploads"),
    (SOURCE_FILE, "uploaded CBOM file", "uploaded CBOM files"),
    (SOURCE_SCAN, "other scan", "other scans"),
)
_EXCLUSION_TEXT = {
    EXCLUDED_FAILURE: "Excluded: failed",
    EXCLUDED_NOT_COMPLETED: "Excluded: not completed",
    EXCLUDED_NO_DATA: "Excluded: no data",
}
_EVIDENCE_COLUMNS = ("Evidence recorded", "Present for", "Out of", "Share")
_POOL_COLUMNS = (
    "Framework",
    "Pass",
    "Pass with evidence",
    "Fail",
    "Not evidenceable",
    "Out of scope",
    "Coverage",
    "Sources pooled",
)
_APPENDIX_COLUMNS = (
    "Scan",
    "Title",
    "Source",
    "Created (UTC)",
    "Disposition",
    "Fidelity",
    "Assets",
)


def _count(number: int, singular: str, plural: str | None = None) -> str:
    """``1 scan`` / ``8 scans`` (``plural`` overrides the regular ``+s``)."""
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def _join_and(parts: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _share(part: int, whole: int) -> str:
    return "n/a" if whole <= 0 else f"{100.0 * part / whole:.1f}%"


def _percent(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{100.0 * ratio:.1f}%"


def _para(text: object, style: ParagraphStyle) -> Paragraph:
    """The only way a sentence becomes a Paragraph: sanitised, clamped and escaped."""
    return Paragraph(pdf_text(text, limit=_TEXT_LIMIT), style)


def _blank() -> Flowable:
    """An empty write-in cell of a sensible height (an empty Paragraph would be ~0 pt tall)."""
    return Spacer(1, _BLANK_HEIGHT)


def _local_styles(styles: Styles) -> dict[str, ParagraphStyle]:
    return {
        "bullet": ParagraphStyle(
            "MethodologyBullet",
            parent=styles["body"],
            alignment=TA_LEFT,
            leftIndent=14,
            bulletIndent=3,
            spaceAfter=2,
        ),
        "strong": ParagraphStyle(
            "MethodologyStrong", parent=styles["dense_cell"], fontName="Helvetica-Bold"
        ),
        "caption": ParagraphStyle(
            "MethodologyCaption", parent=styles["muted"], spaceBefore=3, spaceAfter=4
        ),
    }


def _heading_text(number: int) -> str:
    return f"{number}. {SECTION_TITLES[number - 1]}"


def _section(
    number: int, styles: Styles, content: Sequence[Flowable], *, together: bool
) -> list[Flowable]:
    """Heading plus content.  ``together`` keeps a short section on one page, heading included."""
    heading = _heading_text(number)
    if not together:
        return [*section_heading(heading, styles), *content]
    return [
        KeepTogether([Paragraph(pdf_text(heading, limit=160), styles["section_heading"]), *content])
    ]


# ---------------------------------------------------------------------------------------------
# 1. Purpose and scope (live)
# ---------------------------------------------------------------------------------------------
def _framework_keys(view: TeamCbomView) -> list[str]:
    """The registered frameworks in engine order, then any key the view has that we do not know."""
    known = list(authored.FRAMEWORK_LABELS)
    extra = sorted({pool.framework for pool in view.frameworks} - set(known))
    return [*known, *extra]


def _kpis(view: TeamCbomView) -> list[tuple[str, str, str]]:
    pooled = int(view.compliance_sources_pooled)
    unique_certs = sum(1 for cert in view.certs if cert.current)
    pooled_hint = f"pooled over {_count(pooled, 'source')}" if pooled else "no results pooled"
    return [
        ("Sources", str(len(view.sources)), "assessed in this edition"),
        (
            "Scans included",
            str(int(view.included)),
            f"of {_count(int(view.eligible), 'successful scan')}",
        ),
        ("Crypto assets", str(int(view.asset_occurrences)), "current occurrences"),
        ("Unique certificates", str(unique_certs), "de-duplicated across sources"),
        ("Frameworks", str(len(_framework_keys(view))), pooled_hint),
        ("Requirements", str(len(view.requirements)), "tracked across frameworks"),
    ]


def _beyond_window(older: int, singular_tail: str, plural_tail: str) -> str:
    """``3 older successful scans fall outside the history window of 200 scans and <tail>``."""
    noun = _count(older, "older successful scan")
    if older == 1:
        return (
            f"{noun} falls outside the history window of {HISTORY_WINDOW} scans and {singular_tail}"
        )
    return f"{noun} fall outside the history window of {HISTORY_WINDOW} scans and {plural_tail}"


def _scope_text(view: TeamCbomView) -> str:
    if view.is_empty:
        return EMPTY_SCOPE
    excluded = view.excluded or {}
    included = int(view.included)
    first = (
        f"This edition reflects {_count(included, 'completed scan')} of "
        f"{_count(len(view.sources), 'source')} as of {fmt_date_utc(view.as_of)}: "
        f"{int(view.fidelity_full)} full-fidelity and {int(view.fidelity_reduced)} legacy-format."
    )
    second = (
        f"Of {_count(int(view.scans_total), 'CBOM scan')} recorded for this team, "
        f"{int(view.eligible)} completed successfully and {included} "
        f"{'is' if included == 1 else 'are'} included; "
        f"left out: {int(excluded.get(EXCLUDED_FAILURE, 0) or 0)} failed, "
        f"{int(excluded.get(EXCLUDED_NOT_COMPLETED, 0) or 0)} not completed and "
        f"{int(excluded.get(EXCLUDED_NO_DATA, 0) or 0)} completed without data."
    )
    parts = [first, second]
    older = int(view.history_truncated)
    if older > 0:
        tail = "not read, so first-seen dates may be later than the true first scan."
        parts.append(_beyond_window(older, f"was {tail}", f"were {tail}"))
    return " ".join(parts)


def _asset_type_table(view: TeamCbomView, local: dict[str, ParagraphStyle]) -> Flowable:
    counts = view.assets_by_type or {}
    keys = [k for k in ASSET_TYPES if k != ASSET_OTHER or counts.get(k, 0)]
    keys += sorted(k for k in counts if k not in ASSET_TYPES)
    rows: list[list[object]] = [
        [_ASSET_TYPE_LABELS.get(key, key), str(int(counts.get(key, 0)))] for key in keys
    ]
    rows.append(
        [
            Paragraph(pdf_text("Total"), local["strong"]),
            Paragraph(pdf_text(str(int(view.asset_occurrences))), local["strong"]),
        ]
    )
    return dense_table(["Asset type", "Occurrences"], rows, [170, 90])


def _purpose(
    view: TeamCbomView, styles: Styles, width: float, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    body = styles["body"]
    asset_block = KeepTogether(
        [
            _para("Current asset occurrences by type", styles["table_label"]),
            Spacer(1, 2),
            _asset_type_table(view, local),
            _para(ASSET_TABLE_NOTE, local["caption"]),
        ]
    )
    content: list[Flowable] = [
        _para(authored.METHOD_PURPOSE, body),
        kpi_strip(_kpis(view), width, max_per_row=3),
        Spacer(1, 6),
        _para(_scope_text(view), body),
        asset_block,
    ]
    return _section(1, styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 2. Automated discovery (scanner table pinned to the registry)
# ---------------------------------------------------------------------------------------------
def _automated(styles: Styles) -> list[Flowable]:
    rows = [
        [
            Paragraph(pdf_text(spec.name), styles["dense_mono"]),
            str(spec.order),
            spec.discovers,
            spec.evidence,
        ]
        for spec in authored.CBOM_SCANNERS
    ]
    table = dense_table(
        ["Scanner", "Order", "Discovers", "Evidence recorded"],
        rows,
        [84, 30, 236, 190],
        cell_limit=_CELL_LIMIT,
    )
    content = [_para(authored.CBOM_SCANNER_INTRO, styles["body"]), table, Spacer(1, 4)]
    return _section(2, styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 3. Manual discovery checklist (blank)
# ---------------------------------------------------------------------------------------------
def _manual(styles: Styles) -> list[Flowable]:
    rows = [
        [item, reason, _blank(), _blank(), _blank()]
        for item, reason in authored.MANUAL_DISCOVERY_ITEMS
    ]
    table = dense_table(
        list(authored.MANUAL_DISCOVERY_COLUMNS),
        rows,
        [118, 192, 70, 80, 80],
        manual_cols=(2, 3, 4),
    )
    content = [_para(MANUAL_INTRO, styles["body"]), table, Spacer(1, 4)]
    return _section(3, styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 4. Evidence sources and traceability (live)
# ---------------------------------------------------------------------------------------------
def _sources_sentence(view: TeamCbomView) -> str:
    if not view.sources:
        return "No source has been assessed yet."
    kinds = Counter(source.kind for source in view.sources)
    parts = [
        _count(kinds[kind], singular, plural)
        for kind, singular, plural in _SOURCE_KIND_NOUNS
        if kinds.get(kind)
    ]
    unknown = len(view.sources) - sum(kinds.get(kind, 0) for kind, _s, _p in _SOURCE_KIND_NOUNS)
    if unknown:
        parts.append(_count(unknown, "other source"))
    return f"Evidence is drawn from {_count(len(view.sources), 'source')}: {_join_and(parts)}."


def _evidence(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    live = [asset for asset in view.assets if asset.current]
    located = sum(1 for asset in live if (asset.location or "").strip())
    certs = [cert for cert in view.certs if cert.current]
    identified = sum(1 for cert in certs if cert.identity_strong)
    algorithms = [asset for asset in live if asset.asset_type == ASSET_ALGORITHM]
    graded = sum(1 for asset in algorithms if asset.quantum_vulnerable is not None)
    pooled, sources = int(view.compliance_sources_pooled), len(view.sources)
    rows = [
        [
            "Repository-relative location of each asset occurrence",
            located,
            len(live),
            _share(located, len(live)),
        ],
        [
            "Certificates identified from parsed X.509 fields",
            identified,
            len(certs),
            _share(identified, len(certs)),
        ],
        [
            "Algorithm occurrences graded for quantum exposure",
            graded,
            len(algorithms),
            _share(graded, len(algorithms)),
        ],
        [
            "Sources whose latest scan carries compliance results",
            pooled,
            sources,
            _share(pooled, sources),
        ],
    ]
    table = dense_table(list(_EVIDENCE_COLUMNS), rows, [286, 80, 80, 94])
    content = [
        _para(authored.METHOD_EVIDENCE_TRACE, styles["body"]),
        _para(_sources_sentence(view), styles["body"]),
        table,
        Spacer(1, 4),
    ]
    return _section(4, styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 5. Validation approach
# ---------------------------------------------------------------------------------------------
def _validation(styles: Styles) -> list[Flowable]:
    return _section(5, styles, [_para(authored.METHOD_VALIDATION, styles["body"])], together=True)


# ---------------------------------------------------------------------------------------------
# 6. Coverage methodology (tri-state + live pooled table)
# ---------------------------------------------------------------------------------------------
def _pool_note(view: TeamCbomView) -> str:
    pooled = int(view.compliance_sources_pooled)
    legacy = int(view.compliance_legacy_excluded)
    legacy_sources = _count(legacy, "legacy-format source")
    if pooled:
        note = (
            f"Pooled over {pooled} of {_count(len(view.sources), 'source')} whose latest scan "
            "is full-fidelity"
        )
        if not legacy:
            return note + "."
        verb = (
            "is excluded because it carries" if legacy == 1 else "are excluded because they carry"
        )
        return f"{note}; {legacy_sources} {verb} no compliance results."
    note = "No compliance results are pooled: no source has a latest scan that is full-fidelity."
    if legacy:
        note += f" {legacy_sources} {'carries' if legacy == 1 else 'carry'} no compliance results."
    return note


def _pool_row(label: str, pool: FrameworkPool | None) -> list[object]:
    if pool is None:
        return [label, *([_DASH] * 7)]
    return [
        label,
        int(pool.passed),
        int(pool.passed_with_evidence),
        int(pool.failed),
        int(pool.not_bom_evidenceable),
        int(pool.out_of_scope),
        _percent(pool.coverage),
        int(pool.sources_pooled),
    ]


def _pool_table(view: TeamCbomView, local: dict[str, ParagraphStyle]) -> Flowable:
    pools = {pool.framework: pool for pool in view.frameworks}
    rows = [
        _pool_row(authored.framework_label(key), pools.get(key)) for key in _framework_keys(view)
    ]
    live = list(pools.values())
    totals = [
        "All frameworks",
        sum(int(p.passed) for p in live),
        sum(int(p.passed_with_evidence) for p in live),
        sum(int(p.failed) for p in live),
        sum(int(p.not_bom_evidenceable) for p in live),
        sum(int(p.out_of_scope) for p in live),
        _DASH,
        _DASH,
    ]
    rows.append([Paragraph(pdf_text(cell), local["strong"]) for cell in totals])
    return dense_table(list(_POOL_COLUMNS), rows, [160, 42, 62, 40, 66, 54, 56, 60])


def _coverage(
    view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    body = styles["body"]
    block: list[Flowable] = [_para(_pool_note(view), local["caption"]), _pool_table(view, local)]
    not_applicable = sum(int(pool.na) for pool in view.frameworks)
    if not_applicable:
        verb = "is" if not_applicable == 1 else "are"
        block.append(
            _para(
                f"{_count(not_applicable, 'requirement')} marked not applicable {verb} "
                "excluded from every column.",
                local["caption"],
            )
        )
    content = [
        _para(authored.METHOD_COVERAGE, body),
        _para(COVERAGE_FORMULA_NOTE, body),
        KeepTogether(block),
        Spacer(1, 4),
    ]
    return _section(6, styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 7. Confidence classification
# ---------------------------------------------------------------------------------------------
def _confidence(styles: Styles) -> list[Flowable]:
    table = dense_table(
        ["Detection class", "Meaning"],
        [[name, meaning] for name, meaning in authored.METHOD_CONFIDENCE_SCHEME],
        [130, 410],
    )
    content = [table, Spacer(1, 4), _para(authored.METHOD_CONFIDENCE_LIMIT, styles["body"])]
    return _section(7, styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 8. Ownership and responsibilities (RACI, blank)
# ---------------------------------------------------------------------------------------------
def _raci(styles: Styles) -> list[Flowable]:
    rows = [
        [activity, _blank(), _blank(), _blank(), _blank()] for activity in authored.RACI_ACTIVITIES
    ]
    table = dense_table(
        ["Activity", *authored.RACI_COLUMNS],
        rows,
        [180, 90, 90, 90, 90],
        manual_cols=(1, 2, 3, 4),
    )
    content = [_para(RACI_INTRO, styles["body"]), table, Spacer(1, 4)]
    return _section(8, styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 9. Evidence retention and versioning
# ---------------------------------------------------------------------------------------------
def _versioning_text(view: TeamCbomView) -> str:
    return (
        f"Versioning: this edition is Document ID {document_id(view, NUMBER)} with data "
        f"fingerprint {view.fingerprint or 'n/a'} and template version {TEMPLATE_VERSION}. "
        "Regenerating it from the same scans gives the same fingerprint; a new successful scan "
        "or an attestation upload changes it. The roll-up reads up to "
        f"{HISTORY_WINDOW} of the newest successful scans for first-seen and last-seen history, "
        "plus the latest scan of every source."
    )


def _retention(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    table = dense_table(
        ["Item", "Value"],
        [
            [authored.METHOD_RETENTION_PERIOD_LABEL, _blank()],
            [authored.METHOD_EVIDENCE_STORE_LABEL, _blank()],
        ],
        [200, 340],
        manual_cols=(1,),
    )
    content = [
        _para(authored.METHOD_RETENTION, styles["body"]),
        _para(_versioning_text(view), styles["body"]),
        table,
    ]
    return _section(9, styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 10. Limits of the method
# ---------------------------------------------------------------------------------------------
def _limits(styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    content: list[Flowable] = [
        Paragraph(pdf_text(limit, limit=_TEXT_LIMIT), local["bullet"], bulletText=_BULLET)
        for limit in authored.METHOD_LIMITS
    ]
    return _section(10, styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 11. Sign-off (blank)
# ---------------------------------------------------------------------------------------------
def _signoff(width: float) -> list[Flowable]:
    # signoff_block is already a KeepTogether that carries its own heading.  Never wrap it in
    # another KeepTogether: reportlab reports a nested one as ~16 million points tall, which
    # would push the block onto a page of its own however much room is left.
    return [signoff_block(SIGNOFF_ROLES, title=_heading_text(11), width=width)]


# ---------------------------------------------------------------------------------------------
# Appendix A. Scans considered
# ---------------------------------------------------------------------------------------------
def _disposition(facts: ScanFacts) -> str:
    if facts.exclusion is not None:
        return _EXCLUSION_TEXT.get(facts.exclusion, "Excluded")
    return "Current for source" if facts.is_current else "History only"


def _scan_row(facts: ScanFacts, labels: dict[str, str]) -> list[object]:
    included = facts.exclusion is None
    fidelity = _DASH if not included else ("Full" if facts.fidelity == FIDELITY_FULL else "Legacy")
    return [
        f"#{facts.scan_id}",
        facts.title,
        labels.get(facts.source_key, facts.source_label),
        fmt_date_utc(facts.created_at),
        _disposition(facts),
        fidelity,
        str(int(facts.asset_count or 0)) if included else _DASH,
    ]


def _appendix(
    view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    labels = {source.key: source.label for source in view.sources}
    listed = view.scans[: max(0, int(MAX_SCAN_ROWS))]
    table = dense_table(
        list(_APPENDIX_COLUMNS),
        [_scan_row(facts, labels) for facts in listed],
        [34, 112, 170, 58, 74, 46, 46],
    )
    content: list[Flowable] = [_para(SCAN_APPENDIX_INTRO, styles["body"]), table]
    omitted = len(view.scans) - len(listed)
    if omitted > 0:
        content.append(
            _para(
                f"{_count(omitted, 'further scan')} omitted; the first {len(listed)} of "
                f"{len(view.scans)} are listed.",
                local["caption"],
            )
        )
    older = int(view.history_truncated)
    if older > 0:
        content.append(
            _para(_beyond_window(older, "is not listed.", "are not listed."), local["caption"])
        )
    return [*section_heading(APPENDIX_TITLE, styles, min_space=200), *content]


# ---------------------------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------------------------
def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """The document-specific flowables (everything after the shared front matter)."""
    local = _local_styles(styles)
    story: list[Flowable] = []
    story += _purpose(view, styles, width, local)
    story += _automated(styles)
    story += _manual(styles)
    story += _evidence(view, styles)
    story += _validation(styles)
    story += _coverage(view, styles, local)
    story += _confidence(styles)
    story += _raci(styles)
    story += _retention(view, styles)
    story += _limits(styles, local)
    story += _signoff(width)
    story += _appendix(view, styles, local)
    return story


def build_pdf(view: TeamCbomView) -> bytes:
    """Render deliverable #3 for ``view`` and return the PDF bytes (byte-stable for a view)."""
    return build_document(
        view=view,
        number=NUMBER,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=False,
        body=lambda styles, width: build_body(view, styles, width),
    )


__all__ = [
    "APPENDIX_TITLE",
    "MAX_SCAN_ROWS",
    "NUMBER",
    "REPORT_KEY",
    "SECTION_TITLES",
    "SIGNOFF_ROLES",
    "SLUG",
    "TITLE",
    "build_body",
    "build_pdf",
]
