"""T-1: Scope Baseline & Asset Population Register (deliverable #1), WP3a.

Covers ``backend/utilities/pdf/cbom_scope_register_pdf.py``: ``build_pdf(view) -> bytes`` and the
``build_body(view, styles, width)`` flowables behind it.

ORACLE RULE (plan 8.4).  Every expected number below is a literal taken from plan Appendix B or
from a stdlib-only probe that read the committed raw fixture ``cbom_team_rollup_scans.json`` with
plain loops (per-source type counts, impact counts and the type x impact cross-tab of the current
scans).  Nothing is recomputed with the product aggregator.  The aggregator is used for exactly two
things: to build the ``TeamCbomView`` the renderer consumes, and, in the reconciliation tests, as
the other side of "the printed counts equal what the view says".

Two levels of evidence, on purpose:

* STRUCTURE: the flowables ``build_body`` returns are walked, so a "blank" manual cell is proven
  to be a cell with no text at all, and a column header is proven to be the header of the table
  it names.  A PDF text dump alone cannot prove a cell is empty.
* RENDERED: the real PDF bytes are read back with a small pure-Python content-stream reader (no
  poppler, no network), so the claim "the document says X" is checked on what a person would read.

Fixture scans (plan Appendix B): 1 payments v1 / 2 payments v2 (current) / 3 identity-gateway /
4 crypto-misuse-lab / 5 pqc-pilot / 6 cert-lifecycle-lab (zip) / 7 vendor-sdk-manifests /
8 legacy-billing (Tier B) / 9 payments FAILED / 10 queued / 11 running / 12 sbom_sca (other
type) / 13 success-but-empty / 14 other team.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import html
import json
import re
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Table

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    AssetAgg,
    CertAgg,
    ScanFacts,
    ScanHead,
    SourceAgg,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf import cbom_scope_register_pdf as scope  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import (  # noqa: E402
    document_id,
    get_deliverable_styles,
)
from backend.utilities.pdf.cbom_scope_register_pdf import build_body, build_pdf  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # 17:58 IST; the fixture's frozen "now"
AS_OF = date(2026, 10, 19)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FRAME_WIDTH = 540.0  # portrait Letter minus 36 pt margins
DASH = "\u2014"

# Strings that live ONLY in raw scan blobs / raw metadata and must never reach a document.
CANARIES = (
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
    "other-org",
)
# Words that belong to the AI-BOM / healthcare disclaimer and the stale internal engine name
# (plan R-01).  "AIBOM" without the space is deliberately NOT here: it is part of the official
# title of the CERT-In guideline that the shared disclaimer cites.
LEAKED_WORDS = ("AI BOM", "FDA", "HIPAA", "clinithread")

SECTION_HEADINGS = (
    "A. Assessment boundary",
    "B. Sources assessed",
    "C. Asset population",
    "D. Exclusions and data quality",
    "E. Outside static visibility",
    "F. Sign-off",
)
SUB_HEADINGS = (
    "Boundary items",
    "Assessment boundary statement and approver",
    "Assets by type and impact",
    "Asset population by source",
    "How each CBOM scan was treated",
    "Scans not included",
    "Data-quality checks",
)

SOURCES_HEADER = [
    "#",
    "Source",
    "Repository (sanitised)",
    "Scans",
    "First scanned",
    "Last scanned (age)",
    "Last attempt",
    "Fidelity",
    "Assets",
    "Owner (assessor)",
    "Business system (assessor)",
]
BY_SOURCE_HEADER = [
    "#",
    "Source",
    "Algorithms",
    "Certificates",
    "Protocols",
    "Key material",
    "Total",
    "Libraries",
    "Critical",
    "High",
    "Medium",
    "Low",
]
BY_TYPE_HEADER = ["Asset type", "Critical", "High", "Medium", "Low", "Total"]
BASIS_HEADER = ["Measure", "Scans"]
EXCLUDED_HEADER = ["Scan", "Title", "Source", "Created", "Status", "Reason"]
QUALITY_HEADER = ["Check", "Result"]
BOUNDARY_HEADER = [
    "Boundary item",
    "Description or identifiers (assessor)",
    "Owner (assessor)",
]
STATEMENT_HEADER = [
    "Boundary statement (assessor)",
    "Approver, name and role (assessor)",
    "Date (assessor)",
]
CHECKLIST_HEADER = [
    "Item",
    "Why a static scan cannot see it",
    "Status (assessor)",
    "Owner (assessor)",
    "Evidence ref (assessor)",
]
SIGNOFF_HEADER = ["Sign-off", "Name", "Role", "Date", "Signature"]


# ---------------------------------------------------------------------------------------------
# Oracle: the seven sources of plan Appendix B.  Order = the view's order (label, casefolded).
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Expect:
    label: str
    kind: str
    url: str | None  # sanitised repository URL, None for archives
    branch: str | None
    scans: int
    first: str
    last: str
    age: str  # as of 2026-10-19 (plan Appendix B "Age (d)")
    scan_id: int  # the scan the figures come from
    fidelity: str
    types: tuple[int, int, int, int]  # algorithms, certificates, protocols, key material
    libs: int
    impacts: tuple[int, int, int, int]  # Critical, High, Medium, Low

    @property
    def total(self) -> int:
        return sum(self.types)

    @property
    def compact(self) -> str:
        return "/".join(str(n) for n in (*self.types, self.libs))


SOURCES = (
    Expect("github.com/e2e-demo/crypto-misuse-lab (main)", "Repository",
           "https://github.com/e2e-demo/crypto-misuse-lab", "main", 1,
           "2026-10-09", "2026-10-09", "10 days ago", 4, "FULL",
           (8, 0, 0, 9), 2, (0, 6, 0, 11)),
    Expect("github.com/e2e-demo/identity-gateway (main)", "Repository",
           "https://github.com/e2e-demo/identity-gateway", "main", 1,
           "2026-10-05", "2026-10-05", "14 days ago", 3, "FULL",
           (0, 12, 0, 0), 0, (1, 4, 1, 6)),
    Expect("github.com/e2e-demo/legacy-billing (main)", "Repository",
           "https://github.com/e2e-demo/legacy-billing", "main", 1,
           "2026-08-20", "2026-08-20", "60 days ago", 8, "LEGACY",
           (9, 1, 1, 1), 4, (0, 6, 1, 5)),
    Expect("github.com/e2e-demo/payments-service (main)", "Repository",
           "https://github.com/e2e-demo/payments-service", "main", 2,
           "2026-09-28", "2026-10-12", "7 days ago", 2, "FULL",
           (9, 2, 1, 2), 4, (0, 6, 1, 7)),
    Expect("github.com/e2e-demo/pqc-pilot (release)", "Repository",
           "https://github.com/e2e-demo/pqc-pilot", "release", 1,
           "2026-10-14", "2026-10-14", "5 days ago", 5, "FULL",
           (11, 0, 0, 0), 0, (0, 0, 1, 10)),
    Expect("github.com/e2e-demo/vendor-sdk-manifests (main)", "Repository",
           "https://github.com/e2e-demo/vendor-sdk-manifests", "main", 1,
           "2026-10-17", "2026-10-17", "2 days ago", 7, "FULL",
           (0, 0, 0, 0), 18, (0, 0, 0, 0)),
    Expect("Zip upload: cert-lifecycle-lab", "Zip upload", None, None, 1,
           "2026-10-16", "2026-10-16", "3 days ago", 6, "FULL",
           (0, 2, 0, 0), 0, (0, 1, 1, 0)),
)  # fmt: skip
PAYMENTS = SOURCES[3]

# Plan Appendix B headline numbers + the raw-fixture cross-tab (rows: type; cols: C/H/M/L).
HEADLINE_OCCURRENCES = 68
HEADLINE_BY_TYPE = (37, 17, 2, 12)  # algorithms, certificates, protocols, key material
HEADLINE_BY_IMPACT = (1, 23, 5, 39)  # Critical, High, Medium, Low
UNIQUE_CERTIFICATES = 14
UNIQUE_LIBRARIES = 23
CROSS_TAB = (
    ("Algorithms", (0, 10, 3, 24)),
    ("Certificates", (1, 5, 2, 9)),
    ("Protocols", (0, 2, 0, 0)),
    ("Key material", (0, 6, 0, 6)),
)

FAILED_LATEST_SENTENCE = (
    "most recent attempt failed on 2026-10-18 (scan #9); "
    "figures reflect scan #2 of 2026-10-12"
)
GIT_SUFFIX = re.compile(r"[A-Za-z0-9_-]\.git(?![A-Za-z0-9])")  # "<repo>.git" left in a URL


# ---------------------------------------------------------------------------------------------
# PDF reading helpers (pure Python: ASCII85 + Flate content streams, WinAnsi strings)
# ---------------------------------------------------------------------------------------------
_PDF_STRING = rb"\((?:\\.|[^\\()])*\)"
_PDF_BREAK_OPS = rb"(?<![A-Za-z0-9/])(?:T\*|Td|TD|Tm|ET|BT)(?![A-Za-z0-9*])"
_PDF_TOKEN = re.compile(_PDF_STRING + rb"|" + _PDF_BREAK_OPS, re.S)
_SIMPLE_ESCAPES = {110: b"\n", 114: b"\r", 116: b"\t", 98: b"\b", 102: b"\f"}


def _pdf_unescape(literal: bytes) -> str:
    body, out, i = literal[1:-1], bytearray(), 0
    while i < len(body):
        byte = body[i]
        if byte != 0x5C or i + 1 >= len(body):
            out.append(byte)
            i += 1
            continue
        nxt = body[i + 1]
        if 0x30 <= nxt <= 0x37:  # octal escape, up to three digits
            j, digits = i + 1, b""
            while j < len(body) and len(digits) < 3 and 0x30 <= body[j] <= 0x37:
                digits += bytes([body[j]])
                j += 1
            out.append(int(digits, 8) & 0xFF)
            i = j
        elif nxt in (0x0A, 0x0D):  # line continuation
            i += 2
        else:
            out += _SIMPLE_ESCAPES.get(nxt, bytes([nxt]))
            i += 2
    return out.decode("cp1252", errors="replace")


def _content_streams(raw: bytes) -> list[bytes]:
    streams: list[bytes] = []
    for match in re.finditer(rb"(?<!end)stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        with contextlib.suppress(ValueError, OverflowError):
            data = base64.a85decode(data, adobe=True)
        with contextlib.suppress(zlib.error):
            data = zlib.decompress(data)
        streams.append(data)
    return streams


def pdf_pages_text(raw: bytes) -> list[str]:
    """Text of each page content stream; a text-positioning operator starts a new line."""
    pages: list[str] = []
    for stream in _content_streams(raw):
        if b" Tf" not in stream or b"BT" not in stream:
            continue
        lines: list[str] = []
        pending: list[str] = []
        for token in _PDF_TOKEN.finditer(stream):
            value = token.group(0)
            if value.startswith(b"("):
                pending.append(_pdf_unescape(value))
            elif pending:
                lines.append("".join(pending))
                pending = []
        if pending:
            lines.append("".join(pending))
        pages.append("\n".join(lines))
    return pages


def pdf_text(raw: bytes) -> str:
    return "\n".join(pdf_pages_text(raw))


def norm(value: str) -> str:
    """Collapse whitespace runs (line wraps inside a cell) to single spaces."""
    return re.sub(r"\s+", " ", value).strip()


def squash(value: str) -> str:
    """Drop ALL whitespace: for unbreakable tokens (URLs) the cell wrap may cut mid-token."""
    return re.sub(r"\s+", "", value)


def page_count(raw: bytes) -> int:
    return max(int(n) for n in re.findall(rb"/Count\s+(\d+)", raw))


def media_boxes(raw: bytes) -> set[tuple[float, float]]:
    found = re.findall(rb"/MediaBox\s*\[\s*0\s+0\s+([\d.]+)\s+([\d.]+)\s*\]", raw)
    return {(float(w), float(h)) for w, h in found}


def info_field(raw: bytes, name: str) -> str | None:
    match = re.search(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\()])*)\)", raw)
    return _pdf_unescape(b"(" + match.group(1) + b")") if match else None


def fonts_used(raw: bytes) -> set[str]:
    return {m.decode() for m in re.findall(rb"/BaseFont\s*/([A-Za-z0-9\-]+)", raw)}


def image_count(raw: bytes) -> int:
    """Embedded image XObjects: the brand logo in the page chrome is the only legitimate one."""
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


# ---------------------------------------------------------------------------------------------
# Flowable (structure) helpers
# ---------------------------------------------------------------------------------------------
def para_text(paragraph: Paragraph) -> str:
    """Paragraph text with ``<br/>`` as a newline and entities decoded (``getPlainText`` drops
    the line breaks, which this suite needs to tell a cell's first line from its second)."""
    markup = re.sub(r"<br\s*/?>", "\n", paragraph.text)
    return html.unescape(re.sub(r"<[^>]+>", "", markup))


def deep_text(item) -> str:
    """All text under a flowable / cell value, depth first, one chunk per line."""
    if isinstance(item, Paragraph):
        return para_text(item)
    if isinstance(item, str):
        return item
    if isinstance(item, Table):
        parts = (deep_text(cell) for row in item._cellvalues for cell in row)
        return "\n".join(p for p in parts if p)
    if isinstance(item, KeepTogether):
        return "\n".join(p for p in (deep_text(c) for c in item._content) if p)
    if isinstance(item, (list, tuple)):
        return "\n".join(p for p in (deep_text(c) for c in item) if p)
    return ""  # Spacer, CondPageBreak, images: no text


def iter_tables(flowables):
    """Tables that sit directly in the story or inside ``KeepTogether`` (not nested in cells)."""
    for item in flowables:
        if isinstance(item, KeepTogether):
            yield from iter_tables(item._content)
        elif isinstance(item, Table):
            yield item


def header_of(table: Table) -> list[str]:
    return [deep_text(cell) for cell in table._cellvalues[0]]


def rows_of(table: Table) -> list[list[str]]:
    return [[deep_text(cell) for cell in row] for row in table._cellvalues[1:]]


def find_table(flowables, header: list[str]) -> Table:
    found = [t for t in iter_tables(flowables) if header_of(t) == header]
    assert len(found) == 1, f"expected exactly one table with header {header}, got {len(found)}"
    return found[0]


def column(table: Table, index: int) -> list[str]:
    return [row[index] for row in rows_of(table)]


def story_texts(flowables) -> list[str]:
    return [deep_text(item) for item in flowables]


# ---------------------------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------------------------
def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _head(scan: dict) -> ScanHead:
    return ScanHead(
        id=scan["id"],
        team_id=scan["team_id"],
        scan_type=scan["scan_type"],
        title=scan["title"],
        status=scan["status"],
        created_at=_ts(scan["created_at"]),
        last_updated=_ts(scan["last_updated"]),
        scan_metadata=scan["scan_metadata"],
    )


def fold(scans, *, team_id=1, name="E2E Demo Team", now=NOW) -> TeamCbomView:
    """Fold fixture-shaped scan dicts exactly as the product loader would."""
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        [_head(s) for s in scans],
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=team_id,
        team_name=name,
        now=now,
    )


@pytest.fixture(scope="session")
def raw_fixture():
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def view(raw_fixture) -> TeamCbomView:
    """All 14 fixture scans folded for team 1 (other-team / sbom_sca / failed ones included)."""
    return fold(raw_fixture["scans"])


@pytest.fixture(scope="module")
def pdf(view) -> bytes:
    return build_pdf(view)


@pytest.fixture(scope="module")
def text(pdf) -> str:
    return pdf_text(pdf)


@pytest.fixture(scope="module")
def story(view) -> list[Flowable]:
    return list(build_body(view, get_deliverable_styles(), FRAME_WIDTH))


def make_source(i: int = 1, **overrides) -> SourceAgg:
    fields = {
        "key": f"repo:example.test/org/repo{i}@main",
        "label": f"example.test/org/repo{i} (main)",
        "kind": "repo",
        "repo_url": f"https://example.test/org/repo{i}",
        "branch": "main",
        "scan_ids": (i,),
        "scan_count": 1,
        "first_scanned": NOW - timedelta(days=3),
        "last_scanned": NOW - timedelta(days=3),
        "current_scan_id": i,
        "current_tier": "A",
        "current_fidelity": "full",
        "last_attempt_scan_id": i,
        "last_attempt_status": "success",
        "last_attempt_at": NOW - timedelta(days=3),
        "asset_counts": {"algorithm": 2, "certificate": 1},
        "impact_counts": {"High": 1, "Low": 2},
        "library_count": 1,
    }
    fields.update(overrides)
    return SourceAgg(**fields)


def make_excluded(scan_id: int, status: str, exclusion: str | None, **overrides) -> ScanFacts:
    fields = {
        "scan_id": scan_id,
        "title": f"excluded {scan_id}",
        "status": status,
        "created_at": NOW - timedelta(days=1, minutes=scan_id),
        "last_updated": NOW - timedelta(days=1, minutes=scan_id),
        "source_key": f"repo:example.test/org/x{scan_id}@main",
        "source_label": f"example.test/org/x{scan_id} (main)",
        "source_kind": "repo",
        "exclusion": exclusion,
    }
    fields.update(overrides)
    return ScanFacts(**fields)


def make_view(**overrides) -> TeamCbomView:
    sources = overrides.pop("sources", (make_source(1), make_source(2)))
    fields = {
        "team_id": 7,
        "team_name": "Hand Built Team",
        "generated_at": NOW,
        "as_of": AS_OF,
        "scans_total": len(sources),
        "eligible": len(sources),
        "included": len(sources),
        "fidelity_full": len(sources),
        "window_start": NOW - timedelta(days=3),
        "window_end": NOW - timedelta(days=3),
        "fingerprint": "0123456789ab",
        "sources": tuple(sources),
        "asset_occurrences": 3 * len(sources),
        "assets_by_type": {"algorithm": 2 * len(sources), "certificate": len(sources)},
        "assets_by_impact": {"High": len(sources), "Low": 2 * len(sources)},
    }
    fields.update(overrides)
    return TeamCbomView(**fields)


def body_of(view: TeamCbomView) -> list[Flowable]:
    return list(build_body(view, get_deliverable_styles(), FRAME_WIDTH))


def sources_table(flowables) -> Table:
    return find_table(flowables, SOURCES_HEADER)


# =============================================================================================
# The document as a whole
# =============================================================================================
def test_build_pdf_returns_a_valid_portrait_letter_document(pdf):
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert media_boxes(pdf) == {(612.0, 792.0)}  # portrait US Letter on every page
    assert 2 <= page_count(pdf) <= 12


def test_document_identity_title_footer_and_metadata(view, pdf, text):
    meta = REPORT_META["cbom_scope_register"]
    assert scope.REPORT_KEY == "cbom_scope_register"
    assert scope.DELIVERABLE_NUMBER == 1
    assert scope.TITLE == meta["title"] == "Scope Baseline & Asset Population Register"
    assert info_field(pdf, "Title") == f"{scope.TITLE} - E2E Demo Team"
    expected_id = document_id(view, 1)
    assert expected_id == f"CBOM-D01-T1-20261019-{view.fingerprint[:8]}"
    assert expected_id in norm(text)
    assert expected_id in (info_field(pdf, "Subject") or "")
    assert authored.TOOL_NAME in norm(text)
    flat = norm(text)
    assert scope.TITLE in flat
    # every page carries THIS document's footer label, never the SAST fallback
    pages = pdf_pages_text(pdf)
    assert len(pages) == page_count(pdf)
    assert all(meta["footer_label"] in norm(page) for page in pages)
    assert "SAST Report" not in flat


def test_body_starts_with_the_register_intro_and_how_to_read(story):
    first = story_texts(story)[:2]
    meta = REPORT_META["cbom_scope_register"]
    assert norm(first[0]) == norm(meta["intro"])
    assert norm(first[1]) == norm(meta["how_to_read"])


def test_sections_a_to_f_appear_once_each_and_in_order(text):
    flat = norm(text)
    positions = []
    for heading in SECTION_HEADINGS:
        assert flat.count(heading) == 1, heading
        positions.append(flat.index(heading))
    assert positions == sorted(positions)


def _team_views(raw_fixture) -> dict[str, TeamCbomView]:
    scans = raw_fixture["scans"]
    return {
        "full fixture": fold(scans),
        "empty team": fold([], team_id=3, name="Empty Team"),
        "legacy only": fold([s for s in scans if s["id"] == 8]),
        "failed and queued only": fold([s for s in scans if s["id"] in (9, 10, 11)]),
    }


@pytest.mark.parametrize(
    "which", ["full fixture", "empty team", "legacy only", "failed and queued only"]
)
def test_no_page_ends_on_a_heading_that_belongs_to_the_next_page(raw_fixture, which):
    """A heading left alone at the foot of a page is a layout defect; page text is drawn in
    reading order, so the last line of a page's content stream is its last visible line."""
    headings = {*SECTION_HEADINGS, *SUB_HEADINGS}
    pages = pdf_pages_text(build_pdf(_team_views(raw_fixture)[which]))
    assert len(pages) >= 3
    for number, page in enumerate(pages, start=1):
        last = [line.strip() for line in page.split("\n") if line.strip()][-1]
        assert last not in headings, f"page {number} ends with the heading {last!r}"


def test_no_leaked_ai_bom_text_canaries_placeholders_or_python_junk(text):
    flat = norm(text)
    for word in LEAKED_WORDS:
        assert not re.search(rf"\b{re.escape(word)}\b", flat, re.IGNORECASE), word
    for canary in CANARIES:
        assert canary not in flat, canary
    assert not re.search(r"\bNone\b|\bnan\b|Traceback|[{}]", text)
    assert "FAILED-SCAN-CANARY" not in text  # the failed scan blob was never read


def test_only_helvetica_and_courier_fonts_are_used(pdf):
    fonts = fonts_used(pdf)
    assert fonts and all(f.startswith(("Helvetica", "Courier")) for f in fonts), fonts


def test_only_the_brand_logo_is_embedded_and_nothing_links_out(pdf):
    assert 1 <= image_count(pdf) <= page_count(pdf)  # the logo in the page chrome, nothing else
    assert image_count(pdf) == image_count(build_pdf(make_view()))
    assert link_count(pdf) == 0


def test_output_is_byte_identical_for_the_same_view_and_follows_generated_at(
    raw_fixture, view, pdf
):
    assert build_pdf(view) == pdf
    assert build_pdf(fold(raw_fixture["scans"])) == pdf  # an independently folded equal view
    moved = build_pdf(fold(raw_fixture["scans"], now=NOW + timedelta(days=2)))
    assert moved != pdf
    assert "2026-10-21" in pdf_text(moved)  # as_of moved, so the ages and the Document ID moved


def test_build_body_does_not_mutate_the_view_and_is_repeatable(view):
    before = copy.deepcopy(view)
    first = story_texts(body_of(view))
    second = story_texts(body_of(view))
    assert first == second
    assert view == before


# =============================================================================================
# B. Sources assessed
# =============================================================================================
def test_seven_source_rows_in_the_views_alphabetical_order(story, view):
    table = sources_table(story)
    rows = rows_of(table)
    assert len(rows) == 7
    assert [row[1].split("\n")[0] for row in rows] == [s.label for s in SOURCES]
    assert [row[1].split("\n")[0] for row in rows] == [s.label for s in view.sources]
    assert column(table, 0) == [str(n) for n in range(1, 8)]
    assert len(table._cellvalues) == 8  # header + 7: no placeholder, no total row


@pytest.mark.parametrize("expected", SOURCES, ids=[s.label for s in SOURCES])
def test_each_source_row_matches_plan_appendix_b(story, expected):
    rows = {row[1].split("\n")[0]: row for row in rows_of(sources_table(story))}
    row = rows[expected.label]
    assert row[1].split("\n") == [expected.label, expected.kind]
    if expected.url is None:
        assert row[2] == DASH
    else:
        assert row[2].split("\n") == [expected.url, f"branch: {expected.branch}"]
    assert row[3] == str(expected.scans)
    assert row[4] == expected.first
    assert row[5].split("\n") == [expected.last, expected.age]
    assert row[7] == expected.fidelity
    assert row[8] == expected.compact
    # the scan the figures come from is named in the attempt cell (or, for payments, the note)
    assert f"#{expected.scan_id}" in row[6]


def test_repo_urls_are_sanitised_everywhere_in_the_document(story, text):
    urls = [s.url for s in SOURCES if s.url]
    assert column(sources_table(story), 2)[0].startswith("https://github.com/e2e-demo/")
    flat = squash(text)
    for url in urls:
        assert squash(url) in flat, url
    for leak in ("NOT-A-REAL-TOKEN-CANARY", "x-access-token", "@github.com"):
        assert leak not in flat, leak
    assert not GIT_SUFFIX.search(flat)  # the legacy scan stored ".../legacy-billing.git"
    for url in urls:  # no trailing slash, no scheme-less duplicate, lower-case host
        assert not url.endswith("/") and url.startswith("https://github.com/")


def test_the_renderer_strips_credentials_again_even_from_a_hand_built_view():
    secret = "ghp_AbCdEf0123456789SECRETTOKEN"
    source = make_source(
        1,
        repo_url=f"https://x-access-token:{secret}@github.com/Org/Repo.git/",
        label="github.com/Org/Repo (main)",
    )
    raw = build_pdf(make_view(sources=(source,)))
    flat = squash(pdf_text(raw))
    assert secret not in flat and "x-access-token" not in flat
    assert "https://github.com/Org/Repo" in flat  # path case kept, .git and slash dropped
    assert not GIT_SUFFIX.search(flat)


def test_unparseable_repository_url_is_shown_as_a_dash_not_echoed():
    source = make_source(1, repo_url="not a url\twith spaces", branch="main")
    row = rows_of(sources_table(body_of(make_view(sources=(source,)))))[0]
    assert row[2].split("\n")[0] == DASH
    assert "not a url" not in deep_text(row)


def test_manual_owner_and_business_system_cells_are_blank_for_every_source(story):
    table = sources_table(story)
    assert header_of(table)[-2:] == ["Owner (assessor)", "Business system (assessor)"]
    for row in rows_of(table):
        assert row[9] == "" and row[10] == ""


def test_payments_row_says_the_latest_attempt_failed_and_figures_reflect_scan_2(story, text):
    rows = {row[1].split("\n")[0]: row for row in rows_of(sources_table(story))}
    attempt = rows[PAYMENTS.label][6].split("\n")
    assert attempt[0] == "FAILED"
    assert norm(attempt[1]) == FAILED_LATEST_SENTENCE
    # authored template, verbatim
    authored_sentence = authored.SOURCE_FAILED_LATEST.format(
        failed_date="2026-10-18", failed_scan_id=9, current_scan_id=2, current_date="2026-10-12"
    )
    assert authored_sentence == FAILED_LATEST_SENTENCE
    assert FAILED_LATEST_SENTENCE in norm(text)  # and on the rendered page
    assert norm(text).count("most recent attempt") == 1  # only payments has the situation
    scan_of = {s.label: s.scan_id for s in SOURCES}
    for label, row in rows.items():
        if label != PAYMENTS.label:
            assert row[6].split("\n") == ["SUCCESS", f"scan #{scan_of[label]}"], label


def test_legacy_source_is_flagged_and_the_others_are_full(story):
    fidelity = {row[1].split("\n")[0]: row[7] for row in rows_of(sources_table(story))}
    assert [label for label, chip in fidelity.items() if chip == "LEGACY"] == [
        "github.com/e2e-demo/legacy-billing (main)"
    ]
    assert list(fidelity.values()).count("FULL") == 6


def test_source_limits_and_legends_are_printed(text):
    flat = norm(text)
    assert "the same repository on two branches is two sources" in flat
    assert "two uploaded archives with the same title are one source" in flat
    assert "Assets: algorithms / certificates / protocols / key material / libraries" in flat
    assert "Legacy: the scan predates the current CBOM engine" in flat


# =============================================================================================
# C. Asset population
# =============================================================================================
def test_headline_counts_are_the_plan_numbers_and_reconcile_with_the_aggregator(view):
    assert view.asset_occurrences == HEADLINE_OCCURRENCES
    types = ("algorithm", "certificate", "protocol", "related-crypto-material")
    impacts = ("Critical", "High", "Medium", "Low")
    assert tuple(view.assets_by_type.get(t, 0) for t in types) == HEADLINE_BY_TYPE
    assert tuple(view.assets_by_impact.get(i, 0) for i in impacts) == HEADLINE_BY_IMPACT
    assert sum(1 for c in view.certs if c.current) == UNIQUE_CERTIFICATES
    assert sum(1 for lib in view.libs if lib.current) == UNIQUE_LIBRARIES


def test_population_kpi_strip_shows_the_headline_numbers(story):
    strips = [
        item
        for item in story
        if isinstance(item, Table) and "Asset occurrences" in deep_text(item)
    ]
    assert len(strips) == 1
    lines = deep_text(strips[0]).split("\n")

    def value_after(label: str) -> str:
        return lines[lines.index(label) + 1]

    assert value_after("Sources") == "7"
    assert value_after("Asset occurrences") == "68"
    assert value_after("Algorithms") == "37"
    assert value_after("Certificates") == "17"
    assert value_after("Protocols") == "2"
    assert value_after("Key material") == "12"
    assert f"{UNIQUE_CERTIFICATES} unique" in lines  # the certificate card's hint


def test_assets_by_type_and_impact_matrix_equals_the_raw_fixture_cross_tab(story):
    rows = rows_of(find_table(story, BY_TYPE_HEADER))
    assert [row[0] for row in rows] == [name for name, _ in CROSS_TAB] + ["All asset types"]
    for row, (name, impacts) in zip(rows, CROSS_TAB, strict=False):
        assert row[1:5] == [str(n) for n in impacts], name
        assert row[5] == str(sum(impacts)), name
    assert rows[-1][1:] == [str(n) for n in HEADLINE_BY_IMPACT] + [str(HEADLINE_OCCURRENCES)]


@pytest.mark.parametrize("expected", SOURCES, ids=[s.label for s in SOURCES])
def test_population_by_source_row_matches_the_raw_fixture(story, expected):
    rows = {row[1]: row for row in rows_of(find_table(story, BY_SOURCE_HEADER))}
    row = rows[expected.label]
    assert row[2:6] == [str(n) for n in expected.types]
    assert row[6] == str(expected.total)
    assert row[7] == str(expected.libs)
    assert row[8:12] == [str(n) for n in expected.impacts]


def test_population_by_source_total_row_reconciles_with_the_rows_and_the_headline(story, view):
    table = find_table(story, BY_SOURCE_HEADER)
    rows = rows_of(table)
    assert len(rows) == 8  # seven sources + the total row
    body, total = rows[:-1], rows[-1]
    assert [row[1] for row in body] == [s.label for s in SOURCES]
    assert total[1] == "All sources"
    for index in (2, 3, 4, 5, 6, 8, 9, 10, 11):  # everything except the libraries column
        assert total[index] == str(sum(int(row[index]) for row in body)), index
    assert total[2:6] == [str(n) for n in HEADLINE_BY_TYPE]
    assert total[6] == str(HEADLINE_OCCURRENCES)
    assert total[8:12] == [str(n) for n in HEADLINE_BY_IMPACT]
    # libraries are de-duplicated across sources: 23 unique, not the sum of the rows
    assert total[7] == f"{UNIQUE_LIBRARIES} unique"
    assert sum(int(row[7]) for row in body) == 28 > UNIQUE_LIBRARIES
    # the printed figures are the aggregator's own (renderer neither recomputes nor drops)
    for source in view.sources:
        row = next(r for r in body if r[1] == source.label)
        assert row[2:6] == [str(source.asset_counts.get(t, 0)) for t in (
            "algorithm", "certificate", "protocol", "related-crypto-material")]
        assert row[8:12] == [str(source.impact_counts.get(i, 0)) for i in (
            "Critical", "High", "Medium", "Low")]


def test_population_basis_and_library_statements(text):
    flat = norm(text)
    assert "latest successful scan of each source" in flat
    assert "counted twice because each source's use is a separate exposure" in flat
    assert f"Crypto libraries: {UNIQUE_LIBRARIES} unique across sources (28 source-level" in flat


# =============================================================================================
# D. Exclusions and data quality
# =============================================================================================
def test_basis_table_counts_every_scan_exactly_as_the_plan_says(story):
    rows = rows_of(find_table(story, BASIS_HEADER))
    assert rows == [
        ["CBOM scans of the team", "12"],
        ["Eligible: completed successfully", "9"],
        ["Included in this register", "8"],
        ["Excluded: failed", "1"],
        ["Excluded: not completed (queued, running or retrying)", "2"],
        ["Excluded: completed without usable data", "1"],
        ["Older scans not folded (history window)", "0"],
    ]


def test_basis_table_reconciles_with_the_aggregators_invariants(story, view):
    counts = {label: int(n) for label, n in rows_of(find_table(story, BASIS_HEADER))}
    eligible = counts["Eligible: completed successfully"]
    included = counts["Included in this register"]
    no_data = counts["Excluded: completed without usable data"]
    assert eligible == included + no_data + counts["Older scans not folded (history window)"]
    assert counts["CBOM scans of the team"] == (
        eligible + counts["Excluded: failed"]
        + counts["Excluded: not completed (queued, running or retrying)"]
    )
    assert (counts["CBOM scans of the team"], eligible, included) == (
        view.scans_total, view.eligible, view.included)


def test_excluded_scan_list_names_the_four_scans_newest_first(story):
    table = find_table(story, EXCLUDED_HEADER)
    rows = rows_of(table)
    assert [(r[0], r[1], r[4]) for r in rows] == [
        ("#11", "running", "started"),
        ("#10", "queued", "NOT_STARTED"),
        ("#9", "payments-service (FAILED)", "failure"),
        ("#13", "success-but-empty", "success"),
    ]
    assert [r[2] for r in rows] == [
        "github.com/e2e-demo/running (main)",
        "github.com/e2e-demo/queued (main)",
        "github.com/e2e-demo/payments-service (main)",
        "github.com/e2e-demo/empty (main)",
    ]
    assert [r[3] for r in rows] == ["2026-10-19", "2026-10-19", "2026-10-18", "2026-10-15"]
    reasons = [r[5] for r in rows]
    assert reasons[0] == reasons[1] == "The scan had not completed, so no data was read."
    assert reasons[2] == "The scan failed, so no data was read."
    assert reasons[3] == "The scan completed but its result holds no usable data."


def test_scans_of_other_teams_and_types_are_not_listed_anywhere(text):
    flat = norm(text)
    for stranger in ("sbom noise", "other-team scan", "sbom-noise"):
        assert stranger not in flat, stranger


def test_data_quality_table_flags_the_legacy_source_and_reports_zeros(story):
    rows = rows_of(find_table(story, QUALITY_HEADER))
    assert [r[0] for r in rows] == [
        "Sources represented by a legacy-format scan",
        "Asset occurrences seen only in older scans",
        "Certificates identified without X.509 fields",
        "Input records skipped or corrected",
    ]
    assert rows[0][1] == "1: github.com/e2e-demo/legacy-billing (main)"
    assert [r[1] for r in rows[1:]] == ["0", "0", "0"]


# =============================================================================================
# A / E / F. The manual parts are present and BLANK
# =============================================================================================
def test_boundary_form_lists_the_five_items_and_leaves_the_rest_blank(story, text):
    table = find_table(story, BOUNDARY_HEADER)
    rows = rows_of(table)
    assert [r[0] for r in rows] == list(authored.SCOPE_BOUNDARY_ITEMS)
    assert len(rows) == 5
    for row in rows:
        assert row[1] == "" and row[2] == ""
    assert authored.MANUAL_CELL_NOTE in norm(text)


def test_boundary_statement_and_approver_form_is_blank(story, text):
    table = find_table(story, STATEMENT_HEADER)
    rows = rows_of(table)
    assert rows == [["", "", ""]]
    assert authored.SCOPE_BOUNDARY_STATEMENT in norm(text)


def test_outside_static_visibility_checklist_has_six_items_and_blank_status_owner_evidence(
    story,
):
    table = find_table(story, CHECKLIST_HEADER)
    rows = rows_of(table)
    assert [(r[0], r[1]) for r in rows] == list(authored.MANUAL_DISCOVERY_ITEMS)
    assert len(rows) == 6
    for row in rows:
        assert row[2:] == ["", "", ""]


def test_signoff_block_names_three_roles_with_blank_name_role_date_signature(story):
    table = find_table(story, SIGNOFF_HEADER)
    rows = rows_of(table)
    assert [r[0] for r in rows] == ["Prepared by", "Reviewed by", "Approved by"]
    for row in rows:
        assert row[1:] == ["", "", "", ""]


def test_every_assessor_column_carries_the_suffix_and_every_assessor_cell_is_empty(story):
    seen = 0
    for table in iter_tables(story):
        header = header_of(table)
        manual = [i for i, h in enumerate(header) if h.endswith(authored.ASSESSOR_SUFFIX)]
        if not manual:
            continue
        seen += 1
        for row in rows_of(table):
            for index in manual:
                assert row[index] == "", (header[index], row)
    assert seen == 4  # sources, boundary items, statement form, checklist (sign-off has none)


def test_nothing_in_the_manual_parts_is_pre_filled_with_a_placeholder_word(text):
    """No 'TBD', 'N/A', 'n/a', 'Pending' etc. stands in for an assessor's answer."""
    flat = norm(text)
    for word in ("TBD", "N/A", "n/a", "To be determined", "Pending", "Unknown"):
        assert word not in flat, word


# =============================================================================================
# Degraded teams: nothing is ever a 500, nothing is a fabricated grade
# =============================================================================================
def test_works_with_zero_scans():
    empty = fold([], team_id=3, name="Empty Team")
    assert empty.is_empty and empty.scans_total == 0
    raw = build_pdf(empty)
    assert raw.startswith(b"%PDF-") and raw.rstrip().endswith(b"%%EOF")
    flat = norm(pdf_text(raw))
    assert authored.BANNER_EMPTY_TITLE in flat
    assert "not evidence that no cryptographic assets exist" in flat
    assert "CBOM-D01-T3-20261019-" in flat
    for heading in SECTION_HEADINGS:  # the manual parts and every section still print
        assert heading in flat
    story = body_of(empty)
    # live tables degrade to the helper's single "No entries" line; every count is zero
    assert rows_of(sources_table(story)) == [[authored.EMPTY_TABLE_TEXT] + [""] * 10]
    assert rows_of(find_table(story, BASIS_HEADER))[:3] == [
        ["CBOM scans of the team", "0"],
        ["Eligible: completed successfully", "0"],
        ["Included in this register", "0"],
    ]
    placeholder = authored.EMPTY_TABLE_TEXT
    assert rows_of(find_table(story, BY_SOURCE_HEADER)) == [[placeholder] + [""] * 11]
    zeros = ["All asset types", "0", "0", "0", "0", "0"]
    assert rows_of(find_table(story, BY_TYPE_HEADER))[-1] == zeros
    manual_forms = (BOUNDARY_HEADER, CHECKLIST_HEADER)  # still printed for an empty team
    assert [len(rows_of(find_table(story, h))) for h in manual_forms] == [5, 6]
    assert "Crypto libraries: 0 unique" in flat
    assert "No sources have been assessed" in flat
    body_text = norm("\n".join(story_texts(story)))
    assert not re.search(r"\bgrade\b|NOT ASSESSED", body_text, re.IGNORECASE)  # never grades


def test_team_with_only_failed_and_queued_scans_explains_why_it_is_empty(raw_fixture):
    chosen = [s for s in raw_fixture["scans"] if s["id"] in (9, 10, 11)]
    only_bad = fold(chosen)
    assert only_bad.is_empty and only_bad.scans_total == 3
    raw = build_pdf(only_bad)
    flat = norm(pdf_text(raw))
    assert authored.BANNER_EMPTY_TITLE in flat
    story = body_of(only_bad)
    rows = {label: n for label, n in rows_of(find_table(story, BASIS_HEADER))}
    assert rows["CBOM scans of the team"] == "3"
    assert rows["Excluded: failed"] == "1"
    assert rows["Excluded: not completed (queued, running or retrying)"] == "2"
    assert rows["Included in this register"] == "0"
    assert [r[0] for r in rows_of(find_table(story, EXCLUDED_HEADER))] == ["#11", "#10", "#9"]
    assert "FAILED-SCAN-CANARY" not in flat


def test_legacy_only_team_gets_the_reduced_fidelity_banner(raw_fixture):
    legacy = fold([s for s in raw_fixture["scans"] if s["id"] == 8])
    assert (legacy.fidelity_full, legacy.fidelity_reduced) == (0, 1)
    raw = build_pdf(legacy)
    flat = norm(pdf_text(raw))
    assert authored.BANNER_REDUCED_TITLE in flat
    assert "NOT-A-REAL-TOKEN-CANARY" not in flat and "x-access-token" not in flat
    story = body_of(legacy)
    (row,) = rows_of(sources_table(story))
    assert row[7] == "LEGACY" and row[8] == "9/1/1/1/4"
    assert find_table(story, QUALITY_HEADER) is not None


def test_a_source_whose_latest_attempt_did_not_complete_or_had_no_data_is_explained():
    running = make_source(
        1,
        last_attempt_scan_id=11,
        last_attempt_status="started",
        last_attempt_at=NOW - timedelta(hours=1),
        current_scan_id=5,
        last_scanned=NOW - timedelta(days=4),
    )
    nodata = make_source(
        2,
        last_attempt_scan_id=12,
        last_attempt_status="success",
        last_attempt_at=NOW - timedelta(days=2),
        current_scan_id=6,
        last_scanned=NOW - timedelta(days=9),
    )
    story = body_of(make_view(sources=(running, nodata)))
    one, two = (row[6].split("\n") for row in rows_of(sources_table(story)))
    assert one[0] == "NOT COMPLETED"
    assert norm(one[1]) == (
        "most recent attempt has not completed (scan #11, 2026-10-19); "
        "figures reflect scan #5 of 2026-10-15"
    )
    assert two[0] == "NO DATA"
    assert norm(two[1]) == (
        "most recent attempt completed without usable data (scan #12, 2026-10-17); "
        "figures reflect scan #6 of 2026-10-10"
    )


@pytest.mark.parametrize(
    ("last_scanned", "age"),
    [
        (NOW, "today"),
        (NOW - timedelta(days=1), "1 day ago"),
        (NOW - timedelta(days=2), "2 days ago"),
        (NOW + timedelta(days=3), ""),  # clock skew: a date, never a negative age
    ],
)
def test_age_wording(last_scanned, age):
    source = make_source(1, last_scanned=last_scanned, first_scanned=last_scanned)
    cell = rows_of(sources_table(body_of(make_view(sources=(source,)))))[0][5]
    expected_date = f"{last_scanned:%Y-%m-%d}"
    assert cell.split("\n") == ([expected_date, age] if age else [expected_date])


def test_zip_file_and_bare_scan_sources_use_their_kind_labels_and_no_repository():
    no_repo = {"repo_url": None, "branch": None}
    zip_, file_, bare = (
        make_source(1, key="zip:a", label="Zip upload: a", kind="zip", **no_repo),
        make_source(2, key="file:b", label="Uploaded CBOM: b", kind="file", **no_repo),
        make_source(3, key="scan:3", label="Scan #3", kind="scan", **no_repo),
    )
    rows = rows_of(sources_table(body_of(make_view(sources=(zip_, file_, bare)))))
    assert [r[1].split("\n")[1] for r in rows] == ["Zip upload", "CBOM file upload", "Scan"]
    assert [r[2] for r in rows] == [DASH, DASH, DASH]


def test_unknown_asset_types_and_impacts_still_reconcile_through_an_other_bucket():
    source = make_source(
        1,
        asset_counts={"algorithm": 2, "other": 3},
        impact_counts={"High": 1, "Low": 2, "Severe": 2},
    )
    view = make_view(
        sources=(source,),
        asset_occurrences=5,
        assets_by_type={"algorithm": 2, "other": 3},
        assets_by_impact={"High": 1, "Low": 2, "Severe": 2},
    )
    header = [*BY_SOURCE_HEADER[:6], "Other types", *BY_SOURCE_HEADER[6:], "Other"]
    table = find_table(body_of(view), header)
    row = rows_of(table)[0]
    assert row[6] == "3" and row[7] == "5"  # the extra type column and the total add up
    assert row[-1] == "2"


# =============================================================================================
# Caps, hostile input, geometry, performance
# =============================================================================================
def test_source_rows_are_capped_with_an_omission_notice(monkeypatch):
    monkeypatch.setattr(scope, "MAX_SOURCE_ROWS", 3)
    sources = tuple(make_source(i) for i in range(1, 8))
    flowables = body_of(make_view(sources=sources))
    assert len(rows_of(sources_table(flowables))) == 3
    by_source = rows_of(find_table(flowables, BY_SOURCE_HEADER))
    assert len(by_source) == 3 + 1  # the capped rows + the total row
    assert by_source[-1][1] == "All sources"
    assert by_source[-1][6] == "21"  # the total still covers all seven sources (7 x 3 assets)
    notice = norm("\n".join(story_texts(flowables)))
    # one notice under the sources table AND one under the population-by-source table
    assert notice.count("4 further sources are not listed") == 2
    assert notice.count("the totals still include every source") == 2


def test_excluded_scan_rows_are_capped_with_an_omission_notice(monkeypatch):
    monkeypatch.setattr(scope, "MAX_EXCLUDED_ROWS", 2)
    scans = tuple(make_excluded(100 + i, "failure", EXCLUDED_FAILURE) for i in range(5))
    flowables = body_of(make_view(scans=scans, scans_total=5, excluded={EXCLUDED_FAILURE: 5}))
    assert len(rows_of(find_table(flowables, EXCLUDED_HEADER))) == 2
    assert "3 further excluded scans are not listed" in norm("\n".join(story_texts(flowables)))


def make_asset(title: str, asset_type: str, impact: str, *, current: bool) -> AssetAgg:
    return AssetAgg(
        source_key="repo:example.test/org/repo1@main",
        source_label="example.test/org/repo1 (main)",
        asset_type=asset_type,
        ident=f"ident-{title}",
        title=title,
        location="app.py",
        impact=impact,
        current=current,
    )


def test_assets_seen_only_in_older_scans_stay_out_of_the_matrix_and_are_counted_as_quality():
    assets = (
        make_asset("RSA-2048", "algorithm", "High", current=True),
        make_asset("cert.pem", "certificate", "Low", current=True),
        make_asset("DES", "algorithm", "Critical", current=False),  # resolved since
        make_asset("old.pem", "certificate", "High", current=False),
    )
    flowables = body_of(make_view(assets=assets))
    rows = {r[0]: r[1:] for r in rows_of(find_table(flowables, BY_TYPE_HEADER))}
    assert rows["Algorithms"] == ["0", "1", "0", "0", "1"]  # only the current RSA-2048
    assert rows["Certificates"] == ["0", "0", "0", "1", "1"]
    assert rows["All asset types"] == ["0", "1", "0", "1", "2"]
    quality = dict(rows_of(find_table(flowables, QUALITY_HEADER)))
    assert quality["Asset occurrences seen only in older scans"] == "2"


def test_data_quality_counts_certificates_without_x509_fields_and_input_warnings():
    weak = CertAgg(key="name:a.pem|repo:x", identity_strong=False, name="a.pem")
    strong = CertAgg(key="0123456789abcdef", identity_strong=True, name="b.pem")
    view = make_view(certs=(weak, weak, strong), warnings=("scan #1: row 3 skipped", "w2", "w3"))
    quality = dict(rows_of(find_table(body_of(view), QUALITY_HEADER)))
    assert quality["Certificates identified without X.509 fields"] == "2"
    assert quality["Input records skipped or corrected"] == "3"


def test_many_legacy_sources_are_named_up_to_a_limit_then_counted():
    legacy = tuple(
        make_source(i, current_fidelity="reduced", label=f"legacy-{i:02d} (main)")
        for i in range(1, 13)
    )
    quality = dict(rows_of(find_table(body_of(make_view(sources=legacy)), QUALITY_HEADER)))
    named = "; ".join(f"legacy-{i:02d} (main)" for i in range(1, 11))
    assert quality["Sources represented by a legacy-format scan"] == f"12: {named}; and 2 more"


def test_other_asset_types_in_a_source_are_summarised_in_the_compact_cell():
    source = make_source(1, asset_counts={"algorithm": 2, "other": 3}, library_count=4)
    row = rows_of(sources_table(body_of(make_view(sources=(source,)))))[0]
    assert row[8].split("\n") == ["2/0/0/0/4", "+3 other"]


@pytest.mark.parametrize(
    ("exclusion", "status", "reason"),
    [
        (EXCLUDED_FAILURE, "failure", "The scan failed, so no data was read."),
        (EXCLUDED_NOT_COMPLETED, "started", "The scan had not completed, so no data was read."),
        (EXCLUDED_NO_DATA, "success", "The scan completed but its result holds no usable data."),
        ("something-new", "success", "The scan was not included in this register."),
    ],
)
def test_each_exclusion_kind_has_its_own_reason_and_unknown_kinds_degrade(
    exclusion, status, reason
):
    scan = make_excluded(40, status, exclusion)
    rows = rows_of(find_table(body_of(make_view(scans=(scan,))), EXCLUDED_HEADER))
    assert rows == [["#40", "excluded 40", scan.source_label, f"{scan.created_at:%Y-%m-%d}",
                     status, reason]]  # fmt: skip


def test_included_scans_in_view_scans_are_never_listed_as_excluded():
    included = make_excluded(41, "success", None, title="kept")  # exclusion=None: it was folded
    excluded = make_excluded(42, "failure", EXCLUDED_FAILURE)
    flowables = body_of(make_view(scans=(included, excluded)))
    rows = rows_of(find_table(flowables, EXCLUDED_HEADER))
    assert [r[0] for r in rows] == ["#42"]


def test_no_excluded_scans_prints_a_sentence_instead_of_an_empty_table():
    flowables = body_of(make_view())
    assert not [t for t in iter_tables(flowables) if header_of(t) == EXCLUDED_HEADER]
    assert "No scans were excluded." in norm("\n".join(story_texts(flowables)))


def test_history_truncation_is_reported_in_the_basis_table():
    view = make_view(history_truncated=5, eligible=7, scans_total=7)
    rows = dict(rows_of(find_table(body_of(view), BASIS_HEADER)))
    assert rows["Older scans not folded (history window)"] == "5"


HOSTILE = '<img src="file:///etc/hostname"> & <font color=red>x</font> &lt;b&gt;'


def test_hostile_strings_render_literally_and_embed_nothing():
    baseline = build_pdf(make_view())
    source = make_source(
        1,
        label=HOSTILE,
        branch="<script>alert(1)</script>",
        repo_url="https://example.test/<b>x</b>/repo",
    )
    excluded = make_excluded(
        9, "failure", EXCLUDED_FAILURE, title=HOSTILE, source_label=HOSTILE
    )
    view = make_view(
        team_name=HOSTILE,
        sources=(source,),
        scans=(excluded,),
        scans_total=2,
        excluded={EXCLUDED_FAILURE: 1},
    )
    raw = build_pdf(view)
    flat = squash(pdf_text(raw))
    assert squash(HOSTILE) in flat  # label, title and source label all print the markup as text
    assert squash("branch: <script>alert(1)</script>") in flat
    assert squash("https://example.test/<b>x</b>/repo") in flat
    # the brand logo is the only image (a logo with transparency is two XObjects); the hostile
    # <img src=...> was not turned into one, and nothing became a link
    assert image_count(raw) == image_count(baseline) >= 1
    assert link_count(raw) == 0


def test_control_characters_nul_and_huge_strings_cannot_break_the_document():
    nasty = "a\x00b\x1b[31m" + "W" * 5000 + "\u0928\u092e\u0938\u094d\u0924\u0947 \U0001f600"
    source = make_source(1, label=nasty, branch=nasty)
    excluded = make_excluded(2, "failure", EXCLUDED_FAILURE, title=nasty, source_label=nasty)
    raw = build_pdf(make_view(sources=(source,), scans=(excluded,), excluded={EXCLUDED_FAILURE: 1}))
    assert raw.startswith(b"%PDF-") and raw.rstrip().endswith(b"%%EOF")
    flat = pdf_text(raw)
    assert "\x00" not in flat and "\x1b" not in flat
    assert len(raw) < 400_000


def test_every_table_fits_inside_the_frame(story):
    tables = list(iter_tables(story))
    assert len(tables) == 11  # KPI strip + 10 data / form tables
    for table in tables:
        assert sum(table._colWidths) <= FRAME_WIDTH + 0.01, header_of(table)


def test_a_full_size_register_builds_quickly_and_stays_portrait():
    sources = tuple(make_source(i) for i in range(1, scope.MAX_SOURCE_ROWS + 21))
    started = time.perf_counter()
    raw = build_pdf(make_view(sources=sources))
    elapsed = time.perf_counter() - started
    assert elapsed < 30, elapsed
    assert media_boxes(raw) == {(612.0, 792.0)}
    assert "20 further sources are not listed" in norm(pdf_text(raw))


# =============================================================================================
# Hard constraints: in-house only, no clock, import discipline
# =============================================================================================
_SOURCE = Path(scope.__file__).read_text(encoding="utf-8")
_TREE = ast.parse(_SOURCE)
_ALLOWED_BACKEND = (
    "backend.utilities.pdf",
    "backend.utilities.dashboard.cbom_team_rollup",
)
_FORBIDDEN_ROOTS = {
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "openai", "anthropic",
    "requests", "httpx", "urllib3", "aiohttp", "socket", "subprocess", "smtplib", "ftplib",
    "http", "urllib", "celery", "kombu", "pymongo", "msal", "sqlmodel", "sqlalchemy", "fastapi",
}  # fmt: skip


def _imported_modules() -> list[str]:
    """Every dotted name an import statement can load, ``from a.b import c`` giving ``a.b.c``."""
    found: list[str] = []
    for node in ast.walk(_TREE):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append(node.module)
            found += [f"{node.module}.{alias.name}" for alias in node.names]
    return found


def _under(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


def test_imports_are_stdlib_reportlab_and_the_two_allowed_backend_packages():
    names = _imported_modules()
    assert "backend.utilities.pdf.cbom_deliverable_common" in names  # the helpers are reused
    assert "backend.utilities.dashboard.cbom_team_rollup" in names
    for name in names:
        root = name.split(".")[0]
        assert root not in _FORBIDDEN_ROOTS, name
        if root == "backend":
            assert _under(name, _ALLOWED_BACKEND), name
            assert not _under(name, ("backend.routers", "backend.utilities.ai")), name
        else:
            assert root in sys.stdlib_module_names or root == "reportlab", name


def test_renderer_never_reads_the_wall_clock():
    calls = {
        node.func.attr
        for node in ast.walk(_TREE)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not calls & {"now", "utcnow", "today", "time", "monotonic", "perf_counter", "ctime"}
    for token in ("get_llm", "bedrock", "anthropic", "openai", "ChatBedrock"):
        assert token not in _SOURCE, token


# The plan 6.5 (T-NOLLM-2) list: nothing that can reach a language model or the network may be
# loaded by importing the renderer.  (stdlib http / urllib / socket are loaded by reportlab and
# urllib.parse itself, so they are policed through this module's OWN imports above instead.)
_RUNTIME_FORBIDDEN = (
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
    "openai", "anthropic", "instructor", "requests", "httpx", "urllib3", "aiohttp", "msal",
    "celery", "kombu", "pymongo",
)  # fmt: skip


def test_importing_the_renderer_in_a_fresh_interpreter_loads_no_network_or_llm_module():
    script = "\n".join(
        [
            f"import sys; sys.path.insert(0, {str(_REPO_ROOT)!r})",
            "import backend.utilities.pdf.cbom_scope_register_pdf  # noqa",
            f"forbidden = {_RUNTIME_FORBIDDEN!r}",
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in forbidden or "
            "m.startswith(('backend.utilities.ai', 'backend.routers')))",
            "print('BAD=' + ','.join(bad))",
        ]
    )
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().splitlines()[-1] == "BAD=", done.stdout


def test_module_exports_the_registry_contract():
    assert callable(scope.build_pdf) and callable(scope.build_body)
    assert {"build_pdf", "build_body"} <= set(scope.__all__)
    assert scope.MAX_SOURCE_ROWS == 500
    assert scope.MAX_EXCLUDED_ROWS >= 50
