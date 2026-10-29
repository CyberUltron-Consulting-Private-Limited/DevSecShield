"""T-3: tests for the Discovery Methodology & Evidence Plan renderer (WP3b, deliverable #3).

``backend.utilities.pdf.cbom_methodology_pdf.build_pdf(view) -> bytes`` is a pure function of a
``TeamCbomView``.  Every view here is built by feeding the committed fixture
``cbom_team_rollup_scans.json`` (plain JSON, real engine run-objects) through ``fold_scans``, or by
editing a folded view; nothing needs a database, a network, a language model or the wall clock.

ORACLE RULE (plan 8.4): every expected NUMBER in this module is a literal taken from plan Appendix
B (hand / openssl derived) or computed with plain loops over the raw fixture JSON - never with the
product aggregator or the renderer.  The scanner table is pinned to ``cbom_scanner_registry.json``
(drift lock T-CON-6).  Authored sentences are imported from ``cbom_deliverable_text`` because the
point there is only that the renderer prints them.

PDFs are inspected with a small pure-Python content-stream reader (ASCII85 + Flate), so the suite
needs nothing beyond ``reportlab``.  The page chrome (header and footer text that the shell draws
at the top of every page, ending with ``Page N``) is stripped before the body is analysed, so a
table that crosses a page boundary does not break a text-adjacency assertion.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import dataclasses
import functools
import json
import re
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest
from reportlab.platypus import KeepTogether

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    FrameworkPool,
    ScanHead,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf import cbom_methodology_pdf as methodology  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles  # noqa: E402
from backend.utilities.pdf.cbom_methodology_pdf import build_pdf  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # the fixture's frozen "now"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

HEADINGS = (
    "1. Purpose and scope",
    "2. Automated discovery",
    "3. Manual discovery checklist",
    "4. Evidence sources and traceability",
    "5. Validation approach",
    "6. Coverage methodology",
    "7. Confidence classification",
    "8. Ownership and responsibilities (RACI)",
    "9. Evidence retention and versioning",
    "10. Limits of the method",
    "11. Sign-off",
)
APPENDIX = "Appendix A. Scans considered"

# Plan Appendix B, "Compliance pooled over 6 of 7 current scans (legacy excluded)":
# pass / fail / not evidenceable / out of scope / coverage.  Order = engine framework order.
POOLED = {
    "NIST SP 1800-38B": (13, 2, 5, 4, "86.7%"),
    "NIST SP 800-57": (22, 8, 5, 7, "73.3%"),
    "OMB M-23-02": (8, 2, 5, 3, "80.0%"),
    "EU CRA": (7, 3, 5, 3, "70.0%"),
    "EU DORA": (8, 2, 5, 3, "80.0%"),
    "PCI-DSS 4.0": (11, 4, 5, 4, "73.3%"),
    "FIPS 140-3": (11, 4, 5, 4, "73.3%"),
    "BSI TR-02102": (10, 5, 5, 4, "66.7%"),
    "NIST SP 1800-38C": (12, 3, 5, 4, "80.0%"),
    "CNSA 2.0": (13, 2, 5, 4, "86.7%"),
    "RBI FREE-AI (Protection)": (24, 6, 10, 8, "80.0%"),
    "CERT-In CBOM (Guidelines v2.0)": (114, 4, 97, 43, "96.6%"),
    "SEBI CSCRF (CBOM)": (36, 4, 50, 18, "90.0%"),
}

# Strings that live only in blobs / raw metadata of scans that must never reach a document.
CANARIES = (
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
    "other-org",
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
)
BANNED = (
    "clinithread",
    "FDA",
    "HIPAA",
    "AI BOM",
    "EU AI Act",
    "524B",
    "creates visibility, not assurance",
)

# ---------------------------------------------------------------------------------------------
# PDF inspection helpers (pure Python, no poppler)
# ---------------------------------------------------------------------------------------------
_LITERAL = rb"\((?:\\.|[^\\()])*\)"
_TEXT_OPS = rb"(?<![A-Za-z0-9/])(?:T\*|Td|TD|Tm|ET|BT)(?![A-Za-z0-9*])"
_TOKEN_RE = re.compile(_LITERAL + rb"|" + _TEXT_OPS, re.S)
_SIMPLE_ESCAPES = {110: b"\n", 114: b"\r", 116: b"\t", 98: b"\b", 102: b"\f"}


def _unescape(literal: bytes) -> str:
    body = literal[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c != 0x5C or i + 1 >= len(body):
            out.append(c)
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


def _decoded_streams(raw: bytes) -> list[bytes]:
    chunks: list[bytes] = []
    for match in re.finditer(rb"(?<!end)stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        with contextlib.suppress(ValueError, OverflowError):
            data = base64.a85decode(data, adobe=True)
        with contextlib.suppress(zlib.error):
            data = zlib.decompress(data)
        chunks.append(data)
    return chunks


def pdf_pages_text(raw: bytes) -> list[str]:
    """Text of every page content stream, one string per page, text runs joined by ``\\n``."""
    pages: list[str] = []
    for chunk in _decoded_streams(raw):
        if b" Tf" not in chunk or b"BT" not in chunk:
            continue
        lines: list[str] = []
        current: list[str] = []
        for token in _TOKEN_RE.finditer(chunk):
            value = token.group(0)
            if value.startswith(b"("):
                current.append(_unescape(value))
            elif current:
                lines.append("".join(current))
                current = []
        if current:
            lines.append("".join(current))
        pages.append("\n".join(lines))
    return pages


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def full_text(raw: bytes) -> str:
    """Every text run of every page (chrome included), whitespace-normalised."""
    return norm("\n".join(pdf_pages_text(raw)))


def body_pages(raw: bytes) -> list[list[str]]:
    """Per page, the text runs after the page chrome (everything up to and incl. ``Page N``)."""
    pages: list[list[str]] = []
    for page in pdf_pages_text(raw):
        lines = [line.strip() for line in page.split("\n")]
        for index, line in enumerate(lines):
            if re.fullmatch(r"Page \d+", line):
                lines = lines[index + 1 :]
                break
        pages.append([line for line in lines if line])
    return pages


def body_text(raw: bytes) -> str:
    return norm("\n".join(line for page in body_pages(raw) for line in page))


def info_field(raw: bytes, name: str) -> str | None:
    match = re.search(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\()])*)\)", raw)
    return _unescape(b"(" + match.group(1) + b")") if match else None


def page_count(raw: bytes) -> int:
    return max(int(n) for n in re.findall(rb"/Count\s+(\d+)", raw))


def media_box(raw: bytes) -> tuple[float, float]:
    match = re.search(rb"/MediaBox\s*\[\s*0\s+0\s+([\d.]+)\s+([\d.]+)\s*\]", raw)
    assert match, "no MediaBox"
    return float(match.group(1)), float(match.group(2))


def fonts_used(raw: bytes) -> set[str]:
    return {m.decode() for m in re.findall(rb"/BaseFont\s*/([A-Za-z0-9\-]+)", raw)}


def image_count(raw: bytes) -> int:
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


def section(text: str, number: int) -> str:
    """Normalised body text of section ``number`` (heading excluded), up to the next heading."""
    heading = HEADINGS[number - 1]
    start = text.index(heading) + len(heading)
    following = HEADINGS[number] if number < len(HEADINGS) else APPENDIX
    return text[start : text.index(following, start)].strip()


def appendix(text: str) -> str:
    return text[text.index(APPENDIX) + len(APPENDIX) :].strip()


# ---------------------------------------------------------------------------------------------
# Views (the committed fixture folded by the real aggregator; or edited copies of such a view)
# ---------------------------------------------------------------------------------------------
@functools.cache
def _raw_fixture() -> dict:
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@functools.cache
def _registry() -> dict:
    return json.loads((FIXTURES / "cbom_scanner_registry.json").read_text(encoding="utf-8"))


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


def fold(ids=None, *, team_id: int = 1, name: str | None = None) -> TeamCbomView:
    """Fold the fixture scans ``ids`` (default: all 14, incl. other-team and sbom_sca noise)."""
    raw = _raw_fixture()
    scans = [s for s in raw["scans"] if ids is None or s["id"] in ids]
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        [_head(s) for s in scans],
        lambda wanted: {i: blobs[i] for i in wanted if i in blobs},
        team_id=team_id,
        team_name=name or raw["team"]["name"],
        now=NOW,
    )


def fixture_cbom_scans(team: int = 1) -> list[dict]:
    """The team's own cbom scans of the fixture (plain JSON): 12 for team 1."""
    return [s for s in _raw_fixture()["scans"] if s["team_id"] == team and s["scan_type"] == "cbom"]


@pytest.fixture(scope="module")
def view() -> TeamCbomView:
    return fold()


@pytest.fixture(scope="module")
def pdf(view) -> bytes:
    return build_pdf(view)


@pytest.fixture(scope="module")
def text(pdf) -> str:
    return body_text(pdf)


VIEW_BUILDERS = {
    "full": lambda: fold(),
    "empty": lambda: fold([], team_id=3, name="Empty Team"),
    # every field at its default (what a hand-made view in another test looks like)
    "minimal": lambda: TeamCbomView(
        team_id=1, team_name="Minimal", generated_at=NOW, as_of=NOW.date()
    ),
    "failed-only": lambda: fold({9, 10, 11}),
    "legacy-only": lambda: fold({8}),
    "single": lambda: fold({2}),
}


@pytest.fixture(scope="module", params=sorted(VIEW_BUILDERS))
def any_view(request) -> TeamCbomView:
    return VIEW_BUILDERS[request.param]()


@pytest.fixture(scope="module")
def any_pdf(any_view) -> bytes:
    return build_pdf(any_view)


# ---------------------------------------------------------------------------------------------
# Harness self-checks: the helpers must be able to FAIL, and the oracle must match the fixture
# ---------------------------------------------------------------------------------------------
def test_harness_fixture_is_the_appendix_b_seed():
    view = fold()
    assert (view.scans_total, view.eligible, view.included) == (12, 9, 8)
    assert len(view.sources) == 7
    assert view.compliance_sources_pooled == 6
    assert view.asset_occurrences == 68


def test_harness_pooled_literals_cover_the_thirteen_registry_frameworks():
    assert len(POOLED) == 13
    assert len(_registry()["frameworks"]) == 13


def test_harness_chrome_is_stripped_but_body_text_is_kept(pdf):
    assert "Zero Shield" in full_text(pdf)
    assert "Zero Shield" not in body_text(pdf)
    assert "Page 1" in full_text(pdf)
    assert re.search(r"\bPage \d+\b", body_text(pdf)) is None
    assert HEADINGS[0] in body_text(pdf)


# ---------------------------------------------------------------------------------------------
# The document itself
# ---------------------------------------------------------------------------------------------
def test_build_pdf_returns_a_portrait_letter_pdf(pdf):
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert media_box(pdf) == (612.0, 792.0)
    assert 3 <= page_count(pdf) <= 14


def test_module_constants_identify_deliverable_three():
    assert methodology.SLUG == "methodology-evidence-plan"
    assert methodology.NUMBER == 3
    assert methodology.REPORT_KEY == "cbom_methodology"
    assert methodology.TITLE == "Cryptographic Discovery Methodology & Evidence Plan"
    assert methodology.MAX_SCAN_ROWS == 500


def test_pdf_metadata_and_document_control_name_the_methodology(view, pdf):
    title = info_field(pdf, "Title")
    assert title and "Cryptographic Discovery Methodology & Evidence Plan" in title
    assert "E2E Demo Team" in title
    subject = info_field(pdf, "Subject")
    assert subject and f"CBOM-D03-T1-20261019-{view.fingerprint[:8]}" in subject
    everything = full_text(pdf)
    assert f"CBOM-D03-T1-20261019-{view.fingerprint[:8]}" in everything
    assert "Cryptographic Discovery Methodology & Evidence Plan" in everything


def test_page_chrome_uses_the_methodology_footer_not_the_sast_one(pdf):
    everything = full_text(pdf)
    assert "CBOM Discovery Methodology" in everything
    assert "SAST Report" not in everything
    pages = pdf_pages_text(pdf)
    assert all("CBOM Discovery Methodology" in page for page in pages)


def test_headings_1_to_11_are_present_once_and_in_order(pdf):
    lines = [line for page in body_pages(pdf) for line in page]
    positions = []
    for heading in HEADINGS:
        hits = [i for i, line in enumerate(lines) if line == heading]
        assert len(hits) == 1, f"{heading!r} appears {len(hits)} times"
        positions.append(hits[0])
    assert positions == sorted(positions)
    appendix_hits = [i for i, line in enumerate(lines) if line == APPENDIX]
    assert len(appendix_hits) == 1
    assert appendix_hits[0] > positions[-1]
    assert not [line for line in lines if re.match(r"1[2-9]\. |[2-9][0-9]\. ", line)]


def test_no_heading_is_stranded_at_the_bottom_of_a_page(pdf):
    headings = {*HEADINGS, APPENDIX}
    for number, lines in enumerate(body_pages(pdf), start=1):
        assert not lines or lines[-1] not in headings, f"page {number} ends with {lines[-1]!r}"


# --- 1 Purpose and scope (live) ----------------------------------------------------------------
def test_purpose_paragraph_and_live_scope_sentences(text):
    one = section(text, 1)
    assert norm(authored.METHOD_PURPOSE) in one
    assert (
        "This edition reflects 8 completed scans of 7 sources as of 2026-10-19: "
        "7 full-fidelity and 1 legacy-format." in one
    )
    assert (
        "Of 12 CBOM scans recorded for this team, 9 completed successfully and 8 are included; "
        "left out: 1 failed, 2 not completed and 1 completed without data." in one
    )
    assert "fall outside the history window" not in one  # nothing was truncated


def test_live_kpi_cards(text):
    one = section(text, 1)
    for card in (
        "Sources 7 assessed in this edition",
        "Scans included 8 of 9 successful scans",
        "Crypto assets 68 current occurrences",
        "Unique certificates 14 de-duplicated across sources",
        "Frameworks 13 pooled over 6 sources",
        "Requirements 109 tracked across frameworks",
    ):
        assert card in one, card


def test_assets_by_type_table_reconciles_with_appendix_b(text):
    one = section(text, 1)
    assert (
        "Current asset occurrences by type Asset type Occurrences Algorithm 37 Certificate 17 "
        "Protocol 2 Related crypto material 12 Total 68" in one
    )
    # 17 certificate occurrences but 14 unique certificates: the note explains the difference
    assert norm(methodology.ASSET_TABLE_NOTE) in one
    assert "Unique certificates 14" in one


# --- 2 Automated discovery (scanner table pinned to the registry) ----------------------------
def test_scanner_table_equals_the_registry_fixture_names_and_orders(text):
    two = section(text, 2)
    registry = _registry()["scanners"]
    assert len(registry) == 18
    crypto = [s["name"] for s in registry if s["name"].startswith("crypto_")]
    assert re.findall(r"\bcrypto_[a-z]+\b", two) == crypto
    assert "Scanner Order Discovers Evidence recorded" in two
    for scanner in registry:
        assert f"{scanner['name']} {scanner['order']} " in two, scanner


def test_scanner_rows_carry_the_authored_description_and_evidence(text):
    two = section(text, 2)
    assert norm(authored.CBOM_SCANNER_INTRO) in two
    by_name = {spec.name: spec for spec in authored.CBOM_SCANNERS}
    for scanner in _registry()["scanners"]:
        spec = by_name[scanner["name"]]
        assert spec.order == scanner["order"]
        row = f"{spec.name} {spec.order} {spec.discovers} {spec.evidence}"
        assert norm(row) in two, spec.name


def test_unregistered_scanner_modules_are_never_described(any_pdf):
    everything = full_text(any_pdf).lower()
    for module in _registry()["unregistered_scanner_modules"]:
        assert module.lower() not in everything, module
    for token in ("jvm_go", "native_crypto", "web_native"):
        assert token not in everything, token


# --- 3 Manual discovery checklist (blank) ------------------------------------------------------
def test_manual_checklist_rows_are_listed_and_the_manual_cells_are_blank(text):
    three = section(text, 3)
    assert norm(methodology.MANUAL_INTRO) in three
    assert (
        "Item Why a static scan cannot see it Status (assessor) Owner (assessor) "
        "Evidence ref (assessor)" in three
    )
    assert len(authored.MANUAL_DISCOVERY_ITEMS) == 6
    rows = " ".join(f"{item} {reason}" for item, reason in authored.MANUAL_DISCOVERY_ITEMS)
    # Row after row with nothing between them: no text sits in Status / Owner / Evidence ref.
    assert norm(rows) in three
    assert three.endswith(norm(authored.MANUAL_DISCOVERY_ITEMS[-1][1]))


# --- 4 Evidence sources and traceability (live) -----------------------------------------------
def test_evidence_section_prints_the_trace_paragraph_and_live_presence_counts(text):
    four = section(text, 4)
    assert norm(authored.METHOD_EVIDENCE_TRACE) in four
    assert "Evidence is drawn from 7 sources: 6 repositories and 1 zip upload." in four
    assert (
        "Evidence recorded Present for Out of Share "
        "Repository-relative location of each asset occurrence 68 68 100.0% "
        "Certificates identified from parsed X.509 fields 14 14 100.0% "
        "Algorithm occurrences graded for quantum exposure 37 37 100.0% "
        "Sources whose latest scan carries compliance results 6 7 85.7%" in four
    )


# --- 5 Validation approach ---------------------------------------------------------------------
def test_validation_section_states_deterministic_checks_and_no_ml(text):
    five = section(text, 5)
    assert five == norm(authored.METHOD_VALIDATION)
    assert "No machine-learning or large-language-model component is used." in five


# --- 6 Coverage methodology (tri-state + live pooled table) ------------------------------------
def test_coverage_section_prints_the_tri_state_methodology(text):
    six = section(text, 6)
    assert norm(authored.METHOD_COVERAGE) in six
    assert norm(methodology.COVERAGE_FORMULA_NOTE) in six


def test_pooled_table_lists_thirteen_frameworks_in_engine_order_with_oracle_numbers(text):
    six = section(text, 6)
    assert (
        "Framework Pass Pass with evidence Fail Not evidenceable Out of scope Coverage "
        "Sources pooled" in six
    )
    assert (
        "Pooled over 6 of 7 sources whose latest scan is full-fidelity; 1 legacy-format source "
        "is excluded because it carries no compliance results." in six
    )
    positions = []
    for label, (passed, failed, nbe, oos, coverage) in POOLED.items():
        row = f"{label} {passed} 0 {failed} {nbe} {oos} {coverage} 6"
        assert row in six, row
        positions.append(six.index(row))
    assert positions == sorted(positions)


def test_pooled_table_tri_state_totals_equal_the_sum_of_the_oracle_rows(text):
    six = section(text, 6)
    passed = sum(row[0] for row in POOLED.values())
    failed = sum(row[1] for row in POOLED.values())
    nbe = sum(row[2] for row in POOLED.values())
    oos = sum(row[3] for row in POOLED.values())
    assert (passed, failed, nbe, oos) == (289, 49, 207, 109)
    # 109 requirements evaluated in each of the 6 pooled scans
    assert passed + failed + nbe + oos == 109 * 6
    assert f"All frameworks {passed} 0 {failed} {nbe} {oos} \u2014 \u2014" in six


# --- 7 Confidence classification ---------------------------------------------------------------
def test_confidence_scheme_and_honest_limit(text):
    seven = section(text, 7)
    assert len(authored.METHOD_CONFIDENCE_SCHEME) == 3
    for name, meaning in authored.METHOD_CONFIDENCE_SCHEME:
        assert norm(f"{name} {meaning}") in seven, name
    assert norm(authored.METHOD_CONFIDENCE_LIMIT) in seven
    assert seven.index(norm(authored.METHOD_CONFIDENCE_LIMIT)) > seven.index(
        norm(authored.METHOD_CONFIDENCE_SCHEME[-1][1])
    )


# --- 8 Ownership / RACI (blank) ----------------------------------------------------------------
def test_raci_table_is_blank(text):
    eight = section(text, 8)
    assert norm(methodology.RACI_INTRO) in eight
    assert (
        "Activity Responsible (assessor) Accountable (assessor) Consulted (assessor) "
        "Informed (assessor)" in eight
    )
    assert len(authored.RACI_ACTIVITIES) == 4
    activities = norm(" ".join(authored.RACI_ACTIVITIES))
    assert activities in eight
    assert eight.endswith(norm(authored.RACI_ACTIVITIES[-1]))


# --- 9 Evidence retention and versioning --------------------------------------------------------
def test_retention_paragraph_versioning_and_blank_retention_fields(view, text):
    nine = section(text, 9)
    assert norm(authored.METHOD_RETENTION) in nine
    assert f"Document ID CBOM-D03-T1-20261019-{view.fingerprint[:8]}" in nine
    assert f"data fingerprint {view.fingerprint}" in nine
    assert "template version 1.0" in nine
    assert "a new successful scan or an attestation upload changes it" in nine
    assert (
        "The roll-up reads up to 200 of the newest successful scans for first-seen and "
        "last-seen history, plus the latest scan of every source." in nine
    )
    assert nine.endswith("Item Value (assessor) Retention period Evidence store location")
    assert nine.count("Retention period") == 1
    assert nine.count("Evidence store location") == 1


# --- 10 Limits ---------------------------------------------------------------------------------
def test_limits_section_lists_every_authored_limit_in_order(text):
    ten = section(text, 10)
    assert len(authored.METHOD_LIMITS) == 7
    positions = []
    for limit in authored.METHOD_LIMITS:
        assert norm(limit) in ten, limit
        positions.append(ten.index(norm(limit)))
    assert positions == sorted(positions)


# --- 11 Sign-off (blank) -----------------------------------------------------------------------
def test_signoff_block_has_blank_name_role_date_and_signature(text):
    eleven = section(text, 11)
    assert authored.MANUAL_CELL_NOTE in eleven
    assert eleven.endswith(
        "Sign-off Name Role Date Signature Prepared by Reviewed by (CISO) Approved by"
    )


# --- Appendix: scans considered ----------------------------------------------------------------
def test_scan_appendix_lists_every_team_scan_newest_first_with_its_disposition(text):
    listing = appendix(text)
    expected_order = sorted(fixture_cbom_scans(), key=lambda s: (s["created_at"], s["id"]))
    expected_order.reverse()
    assert [s["id"] for s in expected_order] == [11, 10, 9, 7, 6, 13, 5, 2, 4, 3, 1, 8]
    disposition = {
        1: "History only",
        2: "Current for source",
        3: "Current for source",
        4: "Current for source",
        5: "Current for source",
        6: "Current for source",
        7: "Current for source",
        8: "Current for source",
        9: "Excluded: failed",
        10: "Excluded: not completed",
        11: "Excluded: not completed",
        13: "Excluded: no data",
    }
    fidelity = {8: "Legacy", 9: "\u2014", 10: "\u2014", 11: "\u2014", 13: "\u2014"}
    included = {1, 2, 3, 4, 5, 6, 7, 8}
    positions = []
    for scan in expected_order:
        sid = scan["id"]
        # asset rows of an included scan = len(results) in the raw JSON (plain loop, no product)
        assets = str(len(scan["scan_data"]["results"])) if sid in included else "\u2014"
        row = re.compile(
            rf"#{sid} {re.escape(scan['title'])} (?P<source>.+?) {scan['created_at'][:10]} "
            rf"{re.escape(disposition[sid])} {fidelity.get(sid, 'Full')} {assets}(?= #\d+ |$)"
        )
        match = row.search(listing)
        assert match, f"scan #{sid}: no row with the expected cells"
        assert " #" not in match.group("source"), match.group(0)  # the row did not run on
        positions.append(match.start())
    assert positions == sorted(positions)
    assert "Scan Title Source Created (UTC) Disposition Fidelity Assets" in listing


def test_scan_appendix_never_lists_other_teams_or_other_scan_types(text):
    listing = appendix(text)
    assert "#12 " not in listing  # sbom_sca noise
    assert "#14 " not in listing  # other team
    assert "sbom noise" not in listing
    assert "other-team scan" not in listing


def test_scan_appendix_uses_the_canonical_source_label(text):
    listing = appendix(text)
    # scan #1 was recorded as github.com/E2E-Demo/...; the source is the lower-cased one
    assert "github.com/E2E-Demo" not in listing
    assert "#1 payments-service #1 github.com/e2e-demo/payments-service (main)" in listing
    assert "github.com/e2e-demo/queued (main)" in listing  # excluded-only source keeps its label


def test_history_beyond_the_window_is_disclosed_in_scope_and_appendix(view):
    base = body_text(build_pdf(view))
    assert "outside the history window" not in base
    everything = body_text(build_pdf(dataclasses.replace(view, history_truncated=3)))
    assert (
        "3 older successful scans fall outside the history window of 200 scans and were not "
        "read, so first-seen dates may be later than the true first scan." in section(everything, 1)
    )
    assert (
        "3 older successful scans fall outside the history window of 200 scans and are not "
        "listed." in appendix(everything)
    )


def test_history_beyond_the_window_uses_singular_wording(view):
    everything = body_text(build_pdf(dataclasses.replace(view, history_truncated=1)))
    assert (
        "1 older successful scan falls outside the history window of 200 scans and was not "
        "read, so first-seen dates may be later than the true first scan." in section(everything, 1)
    )
    assert (
        "1 older successful scan falls outside the history window of 200 scans and is not "
        "listed." in appendix(everything)
    )


def test_scan_appendix_cap_prints_an_omission_notice(view, monkeypatch):
    monkeypatch.setattr(methodology, "MAX_SCAN_ROWS", 5)
    listing = appendix(body_text(build_pdf(view)))
    assert "7 further scans omitted; the first 5 of 12 are listed." in listing
    assert "#11 " in listing
    assert "#8 " not in listing  # the oldest scan is beyond the cap


def test_scan_appendix_cap_singular_notice(view, monkeypatch):
    monkeypatch.setattr(methodology, "MAX_SCAN_ROWS", 11)
    assert "1 further scan omitted; the first 11 of 12 are listed." in appendix(
        body_text(build_pdf(view))
    )


def test_five_hundred_twenty_scans_build_quickly_and_are_capped(view):
    template = view.scans[0]
    scans = tuple(
        dataclasses.replace(template, scan_id=10_000 + i, title=f"bulk scan {i}")
        for i in range(520)
    )
    big = dataclasses.replace(view, scans=scans)
    started = time.perf_counter()
    raw = build_pdf(big)
    assert time.perf_counter() - started < 15.0
    listing = appendix(body_text(raw))
    assert "20 further scans omitted; the first 500 of 520 are listed." in listing
    assert "#10499 " in listing
    assert "#10500 " not in listing


# ---------------------------------------------------------------------------------------------
# Invariants over every kind of view (works with 0 scans)
# ---------------------------------------------------------------------------------------------
def test_every_view_builds_a_valid_pdf_with_all_eleven_sections(any_pdf):
    assert any_pdf.startswith(b"%PDF-")
    lines = [line for page in body_pages(any_pdf) for line in page]
    for heading in (*HEADINGS, APPENDIX):
        assert lines.count(heading) == 1, heading


def test_every_view_pins_the_scanner_table_to_the_registry(any_pdf):
    two = section(body_text(any_pdf), 2)
    scanners = _registry()["scanners"]
    crypto = [s["name"] for s in scanners if s["name"].startswith("crypto_")]
    assert re.findall(r"\bcrypto_[a-z]+\b", two) == crypto
    for scanner in scanners:
        assert f"{scanner['name']} {scanner['order']} " in two


def test_every_view_prints_thirteen_framework_rows(any_pdf):
    six = section(body_text(any_pdf), 6)
    for label in POOLED:
        assert label in six, label


def test_every_view_keeps_manual_sections_blank(any_pdf):
    everything = body_text(any_pdf)
    assert section(everything, 3).endswith(norm(authored.MANUAL_DISCOVERY_ITEMS[-1][1]))
    assert section(everything, 8).endswith(norm(authored.RACI_ACTIVITIES[-1]))
    assert section(everything, 9).endswith("Retention period Evidence store location")
    assert section(everything, 11).endswith("Prepared by Reviewed by (CISO) Approved by")


def test_no_aibom_fda_hipaa_or_clinithread_text_in_any_view(any_pdf):
    cleaned = full_text(any_pdf).replace(norm(authored.CERTIN_DISCLAIMER), "")
    for banned in BANNED:
        assert banned not in cleaned, banned
    assert "aibom" not in cleaned.lower()
    assert b"clinithread" not in any_pdf.lower()


def test_no_placeholder_artefacts_leak_into_any_view(any_pdf):
    everything = full_text(any_pdf)
    assert re.search(r"\b(None|nan|NaN|null|undefined)\b", everything) is None
    assert "{" not in everything
    assert "}" not in everything


def test_canary_strings_of_excluded_scans_never_appear(any_pdf):
    everything = full_text(any_pdf)
    for canary in CANARIES:
        assert canary not in everything, canary


def test_pdf_uses_only_the_standard_helvetica_and_courier_fonts(any_pdf):
    assert fonts_used(any_pdf)
    assert all(font.startswith(("Helvetica", "Courier")) for font in fonts_used(any_pdf))


def test_same_view_builds_byte_identical_pdf(any_view, any_pdf):
    assert build_pdf(any_view) == any_pdf


# ---------------------------------------------------------------------------------------------
# Edge views
# ---------------------------------------------------------------------------------------------
def test_empty_team_states_no_live_figures_and_shows_the_banner():
    raw = build_pdf(fold([], team_id=3, name="Empty Team"))
    everything = body_text(raw)
    assert authored.BANNER_EMPTY_TITLE in full_text(raw)
    one = section(everything, 1)
    assert (
        "No completed CBOM scan is available for this team yet, so this edition reports no live "
        "figures. The method below applies to every scan the team runs." in one
    )
    assert "This edition reflects" not in one
    assert "Sources 0 assessed in this edition" in one
    assert "Frameworks 13 no results pooled" in one
    assert "No source has been assessed yet." in section(everything, 4)
    assert "Low risk" not in everything
    six = section(everything, 6)
    assert (
        "No compliance results are pooled: no source has a latest scan that is full-fidelity."
        in six
    )
    assert "BSI TR-02102 \u2014 \u2014 \u2014 \u2014 \u2014 \u2014 \u2014" in six
    assert "All frameworks 0 0 0 0 0 \u2014 \u2014" in six
    assert "No entries" in appendix(everything)


def test_empty_team_evidence_table_has_zero_denominators():
    four = section(body_text(build_pdf(fold([], team_id=3, name="Empty Team"))), 4)
    assert (
        "Repository-relative location of each asset occurrence 0 0 n/a "
        "Certificates identified from parsed X.509 fields 0 0 n/a "
        "Algorithm occurrences graded for quantum exposure 0 0 n/a "
        "Sources whose latest scan carries compliance results 0 0 n/a" in four
    )


def test_failed_only_team_lists_the_excluded_scans_and_no_live_figures():
    raw = build_pdf(fold({9, 10, 11}))
    everything = body_text(raw)
    assert "This edition reflects" not in everything
    assert "No completed CBOM scan is available for this team yet" in section(everything, 1)
    listing = appendix(everything)
    rows = listing.split("Disposition Fidelity Assets", 1)[1]  # the table, without the intro
    assert "Excluded: failed" in rows
    assert rows.count("Excluded: not completed") == 2
    assert "Current for source" not in rows
    assert "History only" not in rows
    assert authored.BANNER_EMPTY_TITLE in full_text(raw)


def test_legacy_only_team_says_no_compliance_results_are_pooled():
    raw = build_pdf(fold({8}))
    everything = body_text(raw)
    one = section(everything, 1)
    assert (
        "This edition reflects 1 completed scan of 1 source as of 2026-10-19: "
        "0 full-fidelity and 1 legacy-format." in one
    )
    six = section(everything, 6)
    assert (
        "No compliance results are pooled: no source has a latest scan that is full-fidelity. "
        "1 legacy-format source carries no compliance results." in six
    )
    assert "NIST SP 1800-38B \u2014 \u2014 \u2014 \u2014 \u2014 \u2014 \u2014" in six
    assert authored.BANNER_REDUCED_TITLE in full_text(raw)
    assert "Sources whose latest scan carries compliance results 0 1 0.0%" in section(everything, 4)


def test_single_scan_team_uses_singular_wording():
    everything = body_text(build_pdf(fold({2})))
    one = section(everything, 1)
    assert (
        "This edition reflects 1 completed scan of 1 source as of 2026-10-19: "
        "1 full-fidelity and 0 legacy-format." in one
    )
    assert (
        "Of 1 CBOM scan recorded for this team, 1 completed successfully and 1 is included; "
        "left out: 0 failed, 0 not completed and 0 completed without data." in one
    )
    assert "Evidence is drawn from 1 source: 1 repository." in section(everything, 4)
    assert "Pooled over 1 of 1 source whose latest scan is full-fidelity." in section(everything, 6)
    assert "Frameworks 13 pooled over 1 source" in one


def test_attested_requirements_show_pass_with_evidence_and_coverage_as_given(view):
    pools = list(view.frameworks)
    pools[0] = dataclasses.replace(
        pools[0], passed=5, passed_with_evidence=2, failed=3, coverage=0.7
    )
    pools[1] = dataclasses.replace(
        pools[1], passed=0, passed_with_evidence=0, failed=0, coverage=None
    )
    edited = dataclasses.replace(view, frameworks=tuple(pools))
    six = section(body_text(build_pdf(edited)), 6)
    assert "NIST SP 1800-38B 5 2 3 5 4 70.0% 6" in six
    assert "NIST SP 800-57 0 0 0 5 7 n/a 6" in six


def test_not_applicable_requirements_are_disclosed_when_present(view):
    pools = list(view.frameworks)
    pools[2] = dataclasses.replace(pools[2], na=3)
    edited = dataclasses.replace(view, frameworks=tuple(pools))
    six = section(body_text(build_pdf(edited)), 6)
    assert "3 requirements marked not applicable are excluded from every column." in six
    assert "not applicable" not in section(body_text(build_pdf(view)), 6)


def test_unknown_framework_keys_are_appended_after_the_registered_thirteen(view):
    extra = FrameworkPool(
        framework="zz_future_fw", passed=1, failed=1, coverage=0.5, sources_pooled=6
    )
    edited = dataclasses.replace(view, frameworks=(*view.frameworks, extra))
    everything = body_text(build_pdf(edited))
    six = section(everything, 6)
    assert "zz future fw 1 0 1 0 0 50.0% 6" in six
    assert six.index("SEBI CSCRF (CBOM)") < six.index("zz future fw")
    assert "Frameworks 14 pooled over 6 sources" in section(everything, 1)


def test_source_kinds_are_counted_in_the_evidence_sentence(view):
    sources = tuple(
        dataclasses.replace(source, kind="file" if index == 0 else source.kind)
        for index, source in enumerate(view.sources)
    )
    four = section(body_text(build_pdf(dataclasses.replace(view, sources=sources))), 4)
    assert (
        "Evidence is drawn from 7 sources: 5 repositories, 1 zip upload and "
        "1 uploaded CBOM file." in four
    )


# ---------------------------------------------------------------------------------------------
# Hostile data: scan titles and source labels are untrusted input
# ---------------------------------------------------------------------------------------------
HOSTILE = (
    '<img src="file:///etc/hostname">',
    '<font color="red" size="40">BIG</font>',
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    '<a href="https://evil.example/x">click</a>',
    "100% & <not> markup",
)


def test_hostile_scan_titles_and_source_labels_render_literally(view):
    baseline = build_pdf(view)
    scans = list(view.scans)
    for index, title in enumerate(HOSTILE[:4]):
        scans[index] = dataclasses.replace(scans[index], title=title)
    sources = list(view.sources)
    sources[0] = dataclasses.replace(sources[0], label=HOSTILE[4])
    hostile_key = sources[0].key
    edited = dataclasses.replace(view, scans=tuple(scans), sources=tuple(sources))
    raw = build_pdf(edited)
    listing = appendix(body_text(raw)).replace(" ", "")  # a long token may wrap inside a cell
    for title in HOSTILE[:4]:
        assert title.replace(" ", "") in listing, title
    assert any(s.source_key == hostile_key for s in view.scans)
    assert HOSTILE[4].replace(" ", "") in listing
    # nothing was interpreted as markup: same images and no links
    assert image_count(raw) == image_count(baseline) >= 1
    assert link_count(raw) == 0


def test_unexpected_scan_fields_degrade_gracefully_in_the_appendix(view):
    scans = list(view.scans)
    scans[0] = dataclasses.replace(
        scans[0], exclusion="mystery", title=None, source_label="", asset_count=None
    )
    scans[1] = dataclasses.replace(
        scans[1], exclusion=None, fidelity="surprising", asset_count=None
    )
    listing = appendix(body_text(build_pdf(dataclasses.replace(view, scans=tuple(scans)))))
    assert re.search(rf"#{scans[0].scan_id} .*Excluded \u2014 \u2014", listing)
    assert re.search(rf"#{scans[1].scan_id} .*Legacy 0", listing)


def test_hostile_scan_title_cannot_break_out_of_its_cell(view):
    scans = list(view.scans)
    scans[0] = dataclasses.replace(scans[0], title="W" * 5000)
    raw = build_pdf(dataclasses.replace(view, scans=tuple(scans)))
    assert raw.startswith(b"%PDF-")
    assert page_count(raw) < 40


# ---------------------------------------------------------------------------------------------
# Determinism, hermeticity, performance
# ---------------------------------------------------------------------------------------------
def test_concurrent_builds_are_identical(view, pdf):
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _i: build_pdf(view), range(5)))
    assert all(result == pdf for result in results)


def test_pdf_dates_come_from_the_view_not_the_wall_clock(pdf):
    assert info_field(pdf, "CreationDate") == "D:20261019122800+00'00'"


def test_building_never_touches_the_network_or_subprocesses(view, monkeypatch):
    import socket
    import subprocess

    def refuse(*_args, **_kwargs):
        raise AssertionError("network/process access attempted")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, refuse)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    assert build_pdf(view).startswith(b"%PDF-")


def test_full_team_build_is_fast(view):
    started = time.perf_counter()
    build_pdf(view)
    assert time.perf_counter() - started < 3.0


# ---------------------------------------------------------------------------------------------
# Module hygiene (hard constraints: in-house, no network/LLM, no wall clock, pdf_text rule)
# ---------------------------------------------------------------------------------------------
_FORBIDDEN_IMPORT_ROOTS = {
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
    "openai", "anthropic", "instructor", "litellm", "requests", "httpx", "urllib3", "aiohttp",
    "socket", "smtplib", "ftplib", "subprocess", "zoneinfo", "pytz", "dateutil", "celery",
    "kombu", "pymongo", "msal",
}  # fmt: skip
_ALLOWED_BACKEND_PREFIXES = (
    "backend.utilities.pdf",
    "backend.utilities.dashboard.cbom_team_rollup",
)
_FORBIDDEN_TOKENS = ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai")


def _module_source() -> str:
    return Path(methodology.__file__).read_text(encoding="utf-8")


def test_module_imports_only_stdlib_reportlab_and_allowed_backend_packages():
    source = _module_source()
    allowed_roots = set(sys.stdlib_module_names) | {"reportlab", "backend", "__future__"}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [("." * node.level) + (node.module or "")]
        else:
            continue
        for name in names:
            assert not name.startswith("."), f"relative import {name}"
            root = name.split(".")[0]
            assert root not in _FORBIDDEN_IMPORT_ROOTS, name
            assert root in allowed_roots, name
            if root == "backend":
                assert name.startswith(_ALLOWED_BACKEND_PREFIXES), name
            assert not name.startswith(("backend.routers", "backend.utilities.ai")), name
    lowered = source.lower()
    for token in _FORBIDDEN_TOKENS:
        assert token not in lowered, token


def test_module_never_reads_the_wall_clock():
    offenders = []
    for node in ast.walk(ast.parse(_module_source())):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr, owner = node.func.attr, node.func.value
        owner_name = owner.id if isinstance(owner, ast.Name) else ""
        if attr in {"now", "utcnow", "today", "fromtimestamp"} and owner_name in {
            "datetime",
            "date",
            "dt",
        }:
            offenders.append(f"{owner_name}.{attr}")
        if owner_name == "time" and attr in {"time", "monotonic", "perf_counter", "localtime"}:
            offenders.append(f"time.{attr}")
    assert offenders == []
    assert "import time" not in _module_source()


def test_every_paragraph_is_built_from_pdf_text():
    """The pdf_text rule: no string reaches a Paragraph without being sanitised and escaped."""
    calls = [
        node
        for node in ast.walk(ast.parse(_module_source()))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Paragraph"
    ]
    assert calls, "the renderer is expected to build Paragraphs"
    for call in calls:
        first = call.args[0] if call.args else None
        assert (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Name)
            and first.func.id in {"pdf_text", "pdf_multiline"}
        ), f"line {call.lineno}: Paragraph() not fed by pdf_text()"


def _assert_no_nested_keep_together(flowables, inside: bool = False) -> None:
    for item in flowables:
        if isinstance(item, KeepTogether):
            assert not inside, "KeepTogether inside KeepTogether"
            _assert_no_nested_keep_together(getattr(item, "_content", []), True)


@pytest.mark.parametrize("name", sorted(VIEW_BUILDERS))
def test_keep_together_blocks_are_never_nested(name):
    """reportlab sizes a KeepTogether at ~16 million points, so an outer one holding an inner
    one can never fit and always forces a page break: the sign-off once landed on a page of its
    own because of exactly this."""
    story = methodology.build_body(VIEW_BUILDERS[name](), get_deliverable_styles(), 540.0)
    _assert_no_nested_keep_together(story)


def test_signoff_shares_a_page_with_the_limits_section(pdf):
    """The sign-off block follows section 10 on the same page rather than starting a new one."""
    pages = body_pages(pdf)
    holder = [i for i, lines in enumerate(pages) if "11. Sign-off" in lines]
    assert len(holder) == 1
    assert "10. Limits of the method" in pages[holder[0]]


def test_build_pdf_is_the_public_entry_point():
    import inspect

    signature = inspect.signature(build_pdf)
    assert list(signature.parameters) == ["view"]
    assert signature.return_annotation in {"bytes", bytes}
