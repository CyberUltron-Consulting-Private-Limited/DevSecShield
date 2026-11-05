"""T-10: tests for the Third-Party Cryptographic Assurance & Attestation Register (#10, WP3d).

Renderer under test: ``backend/utilities/pdf/cbom_assurance_register_pdf.py`` (landscape PDF).

ORACLE RULE (plan 8.4).  Every expected number is a literal from plan Appendix B, or it is
recomputed from the RAW fixture ``cbom_team_rollup_scans.json`` with plain loops (the ``oracle_*``
helpers below).  Nothing is recomputed with the product aggregator, so an aggregator bug cannot
hide a register bug.  Views are built by the real ``fold_scans``, PDFs by the real ``build_pdf``,
and attestations are injected through the real production flow (``certin_attest``).

Fixture scans (Appendix B): 1 payments v1 (history) / 2 payments v2 (current) / 3 identity-gateway
/ 4 crypto-misuse-lab / 5 pqc-pilot / 6 cert-lifecycle-lab (zip) / 7 vendor-sdk-manifests /
8 legacy-billing (reduced fidelity: no compliance blob) / 9-14 excluded or foreign.

Two ways of looking at a document are used.  White-box: ``build_story`` hands back the flowables,
so cell values (including blank manual cells) are read straight from the tables.  Black-box: the
PDF bytes are decoded with a small pure-Python content-stream reader (no poppler, no packages).
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import dataclasses
import html
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import time
import zlib
from collections.abc import Iterator
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Table

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.compliance import certin_attest  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    LibAgg,
    RequirementAgg,
    ScanHead,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_assurance_register_pdf as register  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import (  # noqa: E402
    get_deliverable_styles,
    pdf_plain,
)
from backend.utilities.pdf.report_branding import (  # noqa: E402
    PILL_HIGH_BG,
    PILL_LOW_BG,
    PILL_MEDIUM_BG,
    REPORT_META,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # 17:58 IST; the fixture's frozen "now"
WIDTH = 720.0  # usable frame width of a landscape letter page (792 - 2 x 36)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cbom_team_rollup_scans.json"
MODULE_PATH = _REPO_ROOT / "backend" / "utilities" / "pdf" / "cbom_assurance_register_pdf.py"

# Appendix B: which fixture scans are in play for the register.
INCLUDED_SCAN_IDS = (1, 2, 3, 4, 5, 6, 7, 8)  # folded (history window)
CURRENT_SCAN_IDS = (2, 3, 4, 5, 6, 7, 8)  # latest scan of each of the 7 sources
POOLED_SCAN_IDS = (2, 3, 4, 5, 6, 7)  # current AND full fidelity (legacy #8 has no compliance)

# Headers are literals on purpose: they are the contract with plan 5.4, not a re-export.
LIB_HEADERS = (
    "Library",
    "#Sources",
    "Sources",
    "First seen",
    "Last seen",
    "Version (not captured) (assessor)",
    "Vendor (assessor)",
    "FIPS 140-3 / CMVP cert # (assessor)",
    "SOC 2 / ISO 27001 ref (assessor)",
    "PQC statement (assessor)",
    "Attestation status (assessor)",
)
MANUAL_LIB_COLUMNS = LIB_HEADERS[5:]
PREVIOUS_HEADERS = LIB_HEADERS[:5]
LATEST_HEADER = "Latest attestation (file \u00b7 note \u00b7 date)"
LEDGER_HEADERS = (
    "Framework",
    "Req ID",
    "Title",
    "Source citation",
    "Sources in scope",
    "Attested k/n",
    LATEST_HEADER,
)
VENDOR_HEADERS = ("Vendor", "Service", "Crypto function", "Evidence ref", "Valid until", "Owner")
SIGNOFF_HEADERS = ("Sign-off", "Name", "Role", "Date", "Signature")
DASH = "\u2014"

HEAD_A = "A. Third-party cryptographic components"
HEAD_A1 = "A.1 Previously seen, not in latest scan"
HEAD_B = "B. Control attestation ledger"
HEAD_C = "C. Attestation summary"
HEAD_D = "D. Vendor attestation register"
HEAD_E = "E. Sign-off"

CERT_IN = "CERT-In CBOM (Guidelines v2.0)"
LABEL_TO_KEY = {label: key for key, label in authored.FRAMEWORK_LABELS.items()}

# Canary strings that live only in excluded scans / raw metadata and must never be printed.
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


# ---------------------------------------------------------------------------------------------
# PDF inspection (pure Python, no poppler).  Same reader as test_cbom_deliverable_common.py; kept
# local because every deliverable test module is self-contained (L-11).
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
    """Text of every page content stream, one string per page, line breaks as ``\\n``."""
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


def pdf_full_text(raw: bytes) -> str:
    return "\n".join(pdf_pages_text(raw))


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def media_box(raw: bytes) -> tuple[float, float]:
    match = re.search(rb"/MediaBox\s*\[\s*0\s+0\s+([\d.]+)\s+([\d.]+)\s*\]", raw)
    assert match, "no MediaBox"
    return float(match.group(1)), float(match.group(2))


def info_field(raw: bytes, name: str) -> str | None:
    match = re.search(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\()])*)\)", raw)
    return _unescape(b"(" + match.group(1) + b")") if match else None


def fonts_used(raw: bytes) -> set[str]:
    return {m.decode() for m in re.findall(rb"/BaseFont\s*/([A-Za-z0-9\-]+)", raw)}


def image_count(raw: bytes) -> int:
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


# ---------------------------------------------------------------------------------------------
# Flowable inspection (white-box)
# ---------------------------------------------------------------------------------------------
def cell_text(cell: object) -> str:
    """Literal text of a table cell: Paragraph markup is turned back into plain text."""
    if isinstance(cell, Paragraph):
        marked = re.sub(r"<br\s*/?>", "\n", cell.text)
        return html.unescape(re.sub(r"<[^>]+>", "", marked))
    if isinstance(cell, (list, tuple)):
        return "\n".join(cell_text(item) for item in cell)
    if isinstance(cell, Flowable):
        return ""
    return "" if cell is None else str(cell)


def iter_tables(node: object) -> Iterator[Table]:
    if isinstance(node, Table):
        yield node
        for row in node._cellvalues:
            for cell in row:
                yield from iter_tables(cell)
    elif isinstance(node, KeepTogether):
        yield from iter_tables(node._content)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_tables(item)


def headers_of(table: Table) -> tuple[str, ...]:
    return tuple(cell_text(cell) for cell in table._cellvalues[0])


def find_table(story: list[Flowable], headers: tuple[str, ...]) -> Table:
    matches = [t for t in iter_tables(story) if t._cellvalues and headers_of(t) == headers]
    assert len(matches) == 1, f"{len(matches)} tables with headers {headers}"
    return matches[0]


def has_table(story: list[Flowable], headers: tuple[str, ...]) -> bool:
    return any(t._cellvalues and headers_of(t) == headers for t in iter_tables(story))


def body_rows(table: Table) -> list[list[object]]:
    rows = [list(row) for row in table._cellvalues[1:]]
    if len(rows) == 1 and cell_text(rows[0][0]) == "No entries":  # dense_table's empty line
        return []
    return rows


def records(table: Table) -> list[dict[str, str]]:
    """Body rows keyed by header.  A wrapped ``Req ID`` cell is also unwrapped into the id."""
    heads = headers_of(table)
    rows = [
        dict(zip(heads, (cell_text(cell) for cell in row), strict=True)) for row in body_rows(table)
    ]
    for row in rows:
        if "Req ID" in row:
            row["Req ID lines"] = row["Req ID"]
            row["Req ID"] = row["Req ID"].replace("\n", "")
    return rows


def kpi_cards(story: list[Flowable]) -> dict[str, tuple[str, str]]:
    """``{label: (value, hint)}`` of every KPI card in the story."""
    cards: dict[str, tuple[str, str]] = {}
    for table in iter_tables(story):
        rows = table._cellvalues
        if (
            len(rows) == 3
            and all(len(row) == 1 and isinstance(row[0], Paragraph) for row in rows)
            and rows[0][0].style.name == "DashKpiLabel"
        ):
            cards[cell_text(rows[0][0])] = (cell_text(rows[1][0]), cell_text(rows[2][0]))
    return cards


def story_texts(story: list[Flowable]) -> list[str]:
    """Plain text of every top-level Paragraph (headings, notes) of the story."""
    return [cell_text(item) for item in story if isinstance(item, Paragraph)]


def only(items):
    items = list(items)
    assert len(items) == 1, items
    return items[0]


# ---------------------------------------------------------------------------------------------
# Views from the fixture (real aggregator) and plain-loop oracles (raw JSON only)
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


def make_view(scans: list[dict], *, team_id: int = 1, name: str = "E2E Demo Team") -> TeamCbomView:
    blobs = {scan["id"]: scan["scan_data"] for scan in scans}
    return fold_scans(
        [_head(scan) for scan in scans],
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=team_id,
        team_name=name,
        now=NOW,
    )


def blank_view(**overrides) -> TeamCbomView:
    """A minimal hand-made view that is not 'empty' (so no empty-team banner)."""
    base = {
        "team_id": 7,
        "team_name": "Hand-made Team",
        "generated_at": NOW,
        "as_of": NOW.date(),
        "scans_total": 1,
        "eligible": 1,
        "included": 1,
        "fidelity_full": 1,
        "fingerprint": "0123456789ab",
        "window_start": NOW,
        "window_end": NOW,
        "compliance_sources_pooled": 1,
    }
    base.update(overrides)
    return TeamCbomView(**base)


def make_lib(name: str, sources: int = 1, *, current: bool = True) -> LibAgg:
    keys = tuple(f"repo:example.test/org/r{i}@main" for i in range(sources))
    labels = tuple(f"example.test/org/r{i} (main)" for i in range(sources))
    return LibAgg(
        key=name.casefold(),
        name=name,
        source_keys=keys,
        source_labels=labels,
        current_source_keys=keys if current else (),
        current=current,
        first_seen=NOW,
        last_seen=NOW,
        scan_count=sources,
        scan_ids=tuple(range(1, sources + 1)),
        latest_scan_id=sources,
    )


def make_requirement(index: int, *, attestable: int = 1, attested: int = 0) -> RequirementAgg:
    keys = [f"repo:example.test/org/r{i}@main" for i in range(attestable)]
    verdicts = {
        key: ("pass_with_evidence" if i < attested else "not_bom_evidenceable")
        for i, key in enumerate(keys)
    }
    return RequirementAgg(
        framework="cert_in_cbom",
        req_id=f"REQ-{index:04d}",
        title=f"Control number {index}",
        citation=f"Clause {index}",
        verdict="not_bom_evidenceable",
        verdicts=verdicts,
        attestable_sources=attestable,
        attested_sources=attested,
    )


def oracle_source(scan: dict) -> tuple[str, str]:
    """``(source key, label)`` for the fixture's two source shapes (plan 4.3), plain regexes."""
    meta = scan["scan_metadata"] or {}
    url = meta.get("repo_url")
    if url:
        where = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://([^@/]*@)?", "", url.strip()).rstrip("/")
        where = where[:-4] if where.endswith(".git") else where
        branch = meta.get("branch") or "default"
        return f"repo:{where}@{branch}".lower(), f"{where} ({branch})"
    slug = re.sub(r"[^a-z0-9]+", "-", scan["title"].lower()).strip("-")
    return f"zip:{slug}", f"Zip upload: {scan['title']}"


def oracle_libraries(scans: list[dict]) -> dict[str, dict]:
    """``{casefolded library name: {"labels": {...}, "first": date, "last": date}}``."""
    by_id = {scan["id"]: scan for scan in scans}
    label_of = dict(oracle_source(by_id[scan_id]) for scan_id in CURRENT_SCAN_IDS)
    found: dict[str, dict] = {}
    for scan_id in INCLUDED_SCAN_IDS:
        scan = by_id[scan_id]
        key, _label = oracle_source(scan)
        day = date.fromisoformat(scan["created_at"][:10])
        for comp in scan["scan_data"]["cbom_json"]["components"]:
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            if comp.get("type") != "library" and props.get("crypto:role") != "library":
                continue
            entry = found.setdefault(
                comp["name"].casefold(), {"labels": set(), "first": day, "last": day}
            )
            entry["labels"].add(label_of[key])
            entry["first"] = min(entry["first"], day)
            entry["last"] = max(entry["last"], day)
    return found


def oracle_ledger(scans: list[dict]) -> dict[tuple[str, str], dict]:
    """``{(framework, req_id): {n, k, in_scope, title, citation}}`` for controls with n > 0."""
    by_id = {scan["id"]: scan for scan in scans}
    rows: dict[tuple[str, str], dict] = {}
    for scan_id in POOLED_SCAN_IDS:
        compliance = by_id[scan_id]["scan_data"]["cbom_compliance"]
        for framework, block in compliance.items():
            if not isinstance(block, dict):
                continue
            for req in block["requirements"]:
                fresh = {"n": 0, "k": 0, "in_scope": 0}
                entry = rows.setdefault((framework, req["id"]), fresh)
                entry["title"], entry["citation"] = req["title"], req["source"]
                verdict = req["verdict"]
                entry["n"] += verdict in ("not_bom_evidenceable", "pass_with_evidence")
                entry["k"] += verdict == "pass_with_evidence"
                entry["in_scope"] += verdict not in ("out_of_scope", "na")
    return {key: value for key, value in rows.items() if value["n"] > 0}


def stamp(filename: str, note: str | None = None, at: str = "2026-10-16T09:00:00Z") -> dict:
    """One attestation entry exactly as ``upsert_attestation`` stores it."""
    return {"filename": filename, "note": note or filename, "uploaded_at": at}


def attest(scans: list[dict], scan_id: int, attestations: dict) -> None:
    """Attach attestations to a scan through the REAL production flow (certin_attest)."""
    scan = next(s for s in scans if s["id"] == scan_id)
    scan["scan_data"] = certin_attest.recompute_compliance_for_scan(
        "cbom", scan["scan_data"], attestations
    )


def ledger_record(story: list[Flowable], framework_label: str, req_id: str) -> dict[str, str]:
    rows = records(find_table(story, LEDGER_HEADERS))
    return only(r for r in rows if (r["Framework"], r["Req ID"]) == (framework_label, req_id))


def build_story(view: TeamCbomView) -> list[Flowable]:
    return register.build_story(view, get_deliverable_styles(), WIDTH)


def add_library(scans: list[dict], scan_id: int, name: str, source: str = "requirements.txt"):
    scan = next(s for s in scans if s["id"] == scan_id)
    scan["scan_data"]["cbom_json"]["components"].append(
        {
            "type": "library",
            "bom-ref": f"crypto-lib-{len(name)}-{scan_id}",
            "name": name,
            "properties": [
                {"name": "crypto:role", "value": "library"},
                {"name": "discovery:source", "value": source},
            ],
        }
    )


# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def raw_scans() -> list[dict]:
    with FIXTURE.open(encoding="utf-8") as handle:
        return json.load(handle)["scans"]


@pytest.fixture(scope="module")
def base_view(raw_scans) -> TeamCbomView:
    return make_view(raw_scans)


@pytest.fixture(scope="module")
def base_story(base_view) -> list[Flowable]:
    return build_story(base_view)


@pytest.fixture(scope="module")
def base_pdf(base_view) -> bytes:
    return register.build_pdf(base_view)


@pytest.fixture(scope="module")
def base_text(base_pdf) -> str:
    return norm(pdf_full_text(base_pdf))


@pytest.fixture
def no_network(monkeypatch):
    """Stdlib-only tripwire (T-NOLLM-3 style): any socket connect, DNS lookup or process spawn."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("network/process access attempted")

    for target in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, target, refuse)
    for target in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, target, refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)


# ---------------------------------------------------------------------------------------------
# Oracle sanity (the oracles themselves must agree with the plan before anything is compared)
# ---------------------------------------------------------------------------------------------
def test_oracles_match_the_plan_literals(raw_scans):
    libs = oracle_libraries(raw_scans)
    # Appendix B said 23; the WP13 regeneration adds Node.js crypto (stdlib) (require() import,
    # ab0a446) and the two WP3a advisory components cryptography@42.0.5 / golang.org/x/crypto@v0.24.0
    assert len(libs) == 26
    multi = {name for name, entry in libs.items() if len(entry["labels"]) > 1}
    assert multi == {"hashlib (stdlib)", "pyca/cryptography", "pyopenssl", "ssl (stdlib)"}
    ledger = oracle_ledger(raw_scans)
    assert len(ledger) == 48  # plain-loop probe of the raw fixture: unique controls with NBE/PWE
    assert sum(entry["n"] for entry in ledger.values()) == 207
    assert sum(entry["k"] for entry in ledger.values()) == 0  # nothing attested in the fixture


# ---------------------------------------------------------------------------------------------
# Module contract
# ---------------------------------------------------------------------------------------------
def test_module_constants_follow_the_plan():
    assert register.DOCUMENT_NUMBER == 10
    assert register.REPORT_KEY == "cbom_assurance_register"
    assert register.REPORT_KEY in REPORT_META
    assert register.MAX_LEDGER_ROWS == 1000  # plan 5.4: ledger capped at 1 000 rows
    assert register.MAX_LIBRARY_ROWS == 1000  # decision D-04
    assert register.VENDOR_BLANK_ROWS == 12  # plan 5.4: "x12 blank rows"
    assert "build_pdf" in register.__all__


def test_build_story_returns_flowables_only(base_story):
    assert base_story
    assert all(isinstance(item, Flowable) for item in base_story)


# ---------------------------------------------------------------------------------------------
# Black-box: the PDF
# ---------------------------------------------------------------------------------------------
def test_build_pdf_is_a_valid_landscape_pdf(base_pdf):
    assert base_pdf.startswith(b"%PDF-")
    assert base_pdf.rstrip().endswith(b"%%EOF")
    assert media_box(base_pdf) == (792.0, 612.0)  # letter, landscape


def test_document_identity_metadata_and_footer(base_pdf, base_text):
    title = REPORT_META["cbom_assurance_register"]["title"]
    assert title == "Third-Party Cryptographic Assurance & Attestation Register"
    assert title in (info_field(base_pdf, "Title") or "")
    assert "E2E Demo Team" in (info_field(base_pdf, "Title") or "")
    assert "CBOM-D10-T1-20261019" in (info_field(base_pdf, "Subject") or "")
    assert re.search(r"CBOM-D10-T1-20261019-[0-9a-f]{8}", base_text)
    assert "CBOM Third-Party Assurance Register" in base_text  # its OWN footer label
    assert "SAST Report" not in base_text  # never the silent REPORT_META fallback
    assert "2026-10-19 12:28 UTC (17:58 IST)" in base_text  # from the view, not the clock


def test_front_matter_basis_legend_and_lead_in(base_text):
    assert "Scans: 8 included of 9 eligible" in base_text  # Appendix B
    assert "Cells marked (assessor) are MANUAL" in base_text
    assert norm(REPORT_META["cbom_assurance_register"]["how_to_read"]) in base_text


def test_sections_appear_in_plan_order(base_text):
    positions = [base_text.index(head) for head in (HEAD_A, HEAD_B, HEAD_C, HEAD_D, HEAD_E)]
    assert positions == sorted(positions), positions
    assert HEAD_A1 not in base_text  # every library is current in the fixture


def test_fonts_stay_within_the_existing_report_family(base_pdf):
    fonts = fonts_used(base_pdf)
    assert fonts
    assert all(f.startswith(("Helvetica", "Courier")) for f in fonts), fonts


def test_output_is_deterministic_for_the_same_view(base_view, base_pdf):
    assert register.build_pdf(base_view) == base_pdf


def test_no_hygiene_violations_or_leaked_canaries(base_text):
    for canary in CANARIES:
        assert canary not in base_text, canary
    assert not re.search(r"\b(None|nan)\b", base_text)
    for banned in (r"unknown", r"ai bom", r"fda", r"hipaa", r"clinithread"):
        assert not re.search(rf"\b{banned}\b", base_text, re.I), banned


# ---------------------------------------------------------------------------------------------
# A. Third-party cryptographic components
# ---------------------------------------------------------------------------------------------
def test_components_table_lists_26_unique_libraries_four_with_several_sources(
    base_story, raw_scans
):
    rows = records(find_table(base_story, LIB_HEADERS))
    assert len(rows) == 26  # Appendix B as regenerated in WP13 (see test_oracles_match_the_plan_literals)
    oracle = oracle_libraries(raw_scans)
    assert [r["Library"].casefold() for r in rows] == sorted(oracle)  # one row each, A to Z
    multi = [r["Library"] for r in rows if int(r["#Sources"]) > 1]
    assert sorted(m.casefold() for m in multi) == [
        "hashlib (stdlib)",
        "pyca/cryptography",
        "pyopenssl",
        "ssl (stdlib)",
    ]
    assert len(multi) == 4


def test_each_library_row_matches_the_plain_loop_oracle(base_story, raw_scans):
    oracle = oracle_libraries(raw_scans)
    for row in records(find_table(base_story, LIB_HEADERS)):
        entry = oracle[row["Library"].casefold()]
        assert int(row["#Sources"]) == len(entry["labels"]), row["Library"]
        assert set(row["Sources"].split("\n")) == entry["labels"], row["Library"]
        assert row["First seen"] == entry["first"].isoformat(), row["Library"]
        assert row["Last seen"] == entry["last"].isoformat(), row["Library"]


def test_multi_source_rows_list_every_source_label(base_story):
    rows = {r["Library"]: r for r in records(find_table(base_story, LIB_HEADERS))}
    assert rows["pyca/cryptography"]["#Sources"] == "3"
    assert rows["pyca/cryptography"]["Sources"].split("\n") == [
        "github.com/e2e-demo/crypto-misuse-lab (main)",
        "github.com/e2e-demo/legacy-billing (main)",
        "github.com/e2e-demo/payments-service (main)",
    ]
    # first seen in legacy scan #8 (60 d before the run date), last in payments #2 (7 d)
    assert (rows["pyca/cryptography"]["First seen"], rows["pyca/cryptography"]["Last seen"]) == (
        "2026-08-20",
        "2026-10-12",
    )
    assert rows["Bouncy Castle"]["Sources"] == "github.com/e2e-demo/vendor-sdk-manifests (main)"
    assert rows["secrets (stdlib)"]["First seen"] == "2026-10-09"


def test_version_column_says_not_captured_and_every_manual_cell_is_blank(base_story, base_text):
    table = find_table(base_story, LIB_HEADERS)
    assert LIB_HEADERS[5].startswith("Version (not captured)")
    assert "Version (not captured) (assessor)" in base_text  # and so does the printed header
    for row in body_rows(table):
        for column in range(5, len(LIB_HEADERS)):
            assert cell_text(row[column]) == "", (LIB_HEADERS[column], cell_text(row[0]))
    # nothing invented: no version-looking value in the component rows except inside the name the
    # engine gave an advisory component (``<package>@<version>``, crypto_advisory_scan.py)
    flat = "\n".join(cell_text(c) for row in body_rows(table) for c in row[1:])
    assert not re.search(r"\b\d+\.\d+\.\d+\b", flat)
    versioned = sorted(
        cell_text(row[0]) for row in body_rows(table) if re.search(r"\d+\.\d+\.\d+", cell_text(row[0]))
    )
    assert versioned == ["cryptography@42.0.5", "golang.org/x/crypto@v0.24.0"]
    # the version column is a blank MANUAL column like the four vendor-assurance ones
    assert all("(assessor)" in header for header in MANUAL_LIB_COLUMNS)


def test_library_note_and_summary_line_are_printed(base_text):
    assert norm(authored.ASSURANCE_LIBRARY_NOTE) in base_text
    summary = "26 cryptographic libraries found in 4 of 7 sources; 4 used by more than one source."
    assert summary in base_text


def test_library_seen_only_in_a_superseded_scan_goes_to_a_previously_seen_appendix(raw_scans):
    scans = copy.deepcopy(raw_scans)
    add_library(scans, 1, "ObsoleteCryptoKit")  # scan 1 = payments v1, replaced by scan 2
    view = make_view(scans)
    assert len(view.libs) == 27  # the aggregator keeps it, flagged current=False
    story = build_story(view)
    assert len(body_rows(find_table(story, LIB_HEADERS))) == 26  # headline unchanged
    old = records(find_table(story, PREVIOUS_HEADERS))
    assert len(old) == 1
    assert old[0]["Library"] == "ObsoleteCryptoKit"
    assert old[0]["#Sources"] == "1"
    assert old[0]["Sources"] == "github.com/e2e-demo/payments-service (main)"
    assert (old[0]["First seen"], old[0]["Last seen"]) == ("2026-09-28", "2026-09-28")
    assert HEAD_A1 in norm(pdf_full_text(register.build_pdf(view)))
    assert "26 cryptographic libraries found in 4 of 7 sources" in " ".join(story_texts(story))


def test_many_sources_are_capped_per_cell_with_a_plus_more_line():
    view = blank_view(libs=(make_lib("widely-used", 6),))
    row = only(records(find_table(build_story(view), LIB_HEADERS)))
    assert row["#Sources"] == "6"
    assert row["Sources"].split("\n") == [
        "example.test/org/r0 (main)",
        "example.test/org/r1 (main)",
        "example.test/org/r2 (main)",
        "example.test/org/r3 (main)",
        "+2 more",
    ]


# ---------------------------------------------------------------------------------------------
# B. Control attestation ledger
# ---------------------------------------------------------------------------------------------
def test_ledger_headers_follow_the_plan(base_story):
    assert headers_of(find_table(base_story, LEDGER_HEADERS)) == LEDGER_HEADERS


def test_long_requirement_ids_wrap_after_a_delimiter_and_every_line_fits(base_story):
    cell = get_deliverable_styles()["dense_cell"]
    table = find_table(base_story, LEDGER_HEADERS)
    usable = table._colWidths[1] - 6  # dense tables pad each cell by 3 pt a side

    def width(text: str) -> float:
        return stringWidth(text, cell.fontName, cell.fontSize)

    wrapped = too_wide = 0
    for row in records(table):
        lines = row["Req ID lines"].split("\n")
        assert "".join(lines) == row["Req ID"]  # line breaks only, the id itself is untouched
        for line in lines[:-1]:
            assert line.endswith(("-", "/", ".", "_")), lines  # never a break inside a word
        for line in lines:
            assert width(line) <= usable, lines
        wrapped += len(lines) > 1
        too_wide += width(row["Req ID"]) > usable
    assert wrapped == too_wide >= 4  # an id wraps exactly when it does not fit on one line
    long_id = ledger_record(base_story, CERT_IN, "T9-Certificates-Subject-Public-Key-Reference")
    first, *rest = long_id["Req ID lines"].split("\n")
    assert first.endswith("-") and rest


def test_fixture_labels_fit_their_columns_without_wrapping(base_story):
    cell = get_deliverable_styles()["dense_cell"]

    def fits(text: str, table: Table, column: int) -> bool:
        return stringWidth(text, cell.fontName, cell.fontSize) <= table._colWidths[column] - 6

    components = find_table(base_story, LIB_HEADERS)
    for row in records(components):
        for label in row["Sources"].split("\n"):
            assert fits(label, components, 2), label
    ledger = find_table(base_story, LEDGER_HEADERS)
    for label in authored.FRAMEWORK_LABELS.values():
        assert fits(label, ledger, 0), label
    assert abs(sum(components._colWidths) - WIDTH) < 0.01
    assert abs(sum(ledger._colWidths) - WIDTH) < 0.01  # the tables use the whole frame width


def test_ledger_row_count_equals_the_unique_framework_requirements_with_nbe_or_pwe(
    base_story, raw_scans
):
    oracle = oracle_ledger(raw_scans)
    rows = records(find_table(base_story, LEDGER_HEADERS))
    keys = [(LABEL_TO_KEY[r["Framework"]], r["Req ID"]) for r in rows]
    assert len(rows) == len(oracle) == 48
    assert len(set(keys)) == len(keys)  # each control exactly once
    assert set(keys) == set(oracle)


def test_each_ledger_row_matches_the_oracle(base_story, raw_scans):
    oracle = oracle_ledger(raw_scans)
    for row in records(find_table(base_story, LEDGER_HEADERS)):
        entry = oracle[(LABEL_TO_KEY[row["Framework"]], row["Req ID"])]
        assert row["Attested k/n"] == f"Attested {entry['k']}/{entry['n']}", row
        assert row["Sources in scope"] == str(entry["in_scope"]), row
        assert row["Title"] == pdf_plain(entry["title"]), row
        assert row["Source citation"] == pdf_plain(entry["citation"]), row
        assert row[LATEST_HEADER] == DASH, row  # nothing attested yet


def test_sources_in_scope_is_not_the_same_as_sources_needing_attestation(base_story):
    mode = ledger_record(base_story, CERT_IN, "T9-Algorithms-Mode")
    assert (mode["Sources in scope"], mode["Attested k/n"]) == ("5", "Attested 0/2")
    first = ledger_record(base_story, CERT_IN, "8.4.1.1")
    assert (first["Sources in scope"], first["Attested k/n"]) == ("5", "Attested 0/5")
    assert first["Title"] == "Require CBOM in procurements"


def test_ledger_is_in_framework_order_then_natural_requirement_order(base_story):
    rows = records(find_table(base_story, LEDGER_HEADERS))
    frameworks: list[str] = []
    for row in rows:
        if not frameworks or frameworks[-1] != row["Framework"]:
            frameworks.append(row["Framework"])
    assert frameworks == list(authored.FRAMEWORK_LABELS.values())  # engine order, no repeats
    ids = {fw: [r["Req ID"] for r in rows if r["Framework"] == fw] for fw in frameworks}
    assert ids[CERT_IN] == [
        *(f"8.4.1.{n}" for n in range(1, 14)),  # 8.4.1.2 before 8.4.1.10: numeric, not text
        "T9-Algorithms-Crypto-Functions",
        "T9-Algorithms-List",
        "T9-Algorithms-Mode",
        "T9-Algorithms-OID",
        "T9-Certificates-Certificate-Extension",
        "T9-Certificates-Certificate-Format",
        "T9-Certificates-Signature-Algorithm-Reference",
        "T9-Certificates-Subject-Public-Key-Reference",
        "T9-Keys-Activation-Date",
        "T9-Keys-Creation-Date",
        "T9-Keys-Id",
        "T9-Keys-State",
        "T9-Protocols-OID",
    ]
    assert ids["SEBI CSCRF (CBOM)"] == [
        "CSCRF-DS-3",
        "CSCRF-DS-4",
        "CSCRF-DS-5",
        "CSCRF-QC-3",
        "CSCRF-QC-5",
        "CSCRF-QC-6",
        "CSCRF-QC-7",
        "CSCRF-QC-8",
        "CSCRF-QC-10",
        "CSCRF-RA-1",
    ]
    assert ids["RBI FREE-AI (Protection)"] == ["FREEAI-PROT-7", "FREEAI-PROT-8"]


def test_ledger_explains_what_k_over_n_means_and_what_was_pooled(base_text):
    assert "k of the n sources" in base_text
    assert "Pooled over 6 current full-fidelity sources" in base_text  # Appendix B: 6 of 7
    assert "not pooled (they carry no compliance results): 1" in base_text


def test_ledger_header_repeats_on_every_page_it_spans(base_pdf):
    pages = [page for page in pdf_pages_text(base_pdf) if "Source citation" in page]
    assert len(pages) >= 2  # 48 rows do not fit on one landscape page


def test_attestation_in_scan_2_shows_attested_1_of_5_with_file_note_and_date(raw_scans):
    file_name = "payments-procurement-policy.pdf"
    note = "CBOM clause in vendor contracts signed off by CISO"
    scans = copy.deepcopy(raw_scans)
    done = stamp(file_name, note, "2026-10-15T09:30:00Z")
    attest(scans, 2, {"cert_in_cbom": {"8.4.1.1": done}})
    view = make_view(scans)
    story = build_story(view)

    row = ledger_record(story, CERT_IN, "8.4.1.1")
    assert row["Attested k/n"] == "Attested 1/5"
    assert row[LATEST_HEADER].split("\n") == [file_name, note, "2026-10-15"]
    others = [
        r
        for r in records(find_table(story, LEDGER_HEADERS))
        if (r["Framework"], r["Req ID"]) != (CERT_IN, "8.4.1.1")
    ]
    assert len(others) == 47  # the attested control stays in the ledger (pass_with_evidence)
    assert all(r["Attested k/n"].startswith("Attested 0/") for r in others)
    assert all(r[LATEST_HEADER] == DASH for r in others)

    text = norm(pdf_full_text(register.build_pdf(view)))  # and the same facts reach the PDF
    for expected in ("Attested 1/5", file_name, note, "2026-10-15"):
        assert expected in text, expected


DOCUMENT_ID_RE = re.compile(r"CBOM-D10-T1-20261019-[0-9a-f]{8}")


def document_ids(raw_pdf: bytes) -> set[str]:
    """Every distinct #10 Document ID printed anywhere in the PDF (control table, footers)."""
    return set(DOCUMENT_ID_RE.findall(norm(pdf_full_text(raw_pdf))))


def test_document_id_changes_when_an_attestation_is_uploaded(raw_scans, base_view, base_pdf):
    # addendum A-2: the upload route never touches Scan.last_updated, so the data fingerprint (and
    # the Document ID suffix built from it) has to see the attestation record itself
    before = "CBOM-D10-T1-20261019-6a1e31ae"  # the attestation-free fixture: the pre-A-2 value
    assert base_view.fingerprint == "6a1e31ae946c"
    assert document_ids(base_pdf) == {before}
    scans = copy.deepcopy(raw_scans)
    done = stamp("payments-policy.pdf", "signed off by the CISO", "2026-10-15T09:30:00Z")
    attest(scans, 2, {"cert_in_cbom": {"8.4.1.1": done}})  # the real production flow
    view = make_view(scans)
    assert view.fingerprint != base_view.fingerprint
    after = document_ids(register.build_pdf(view))
    assert len(after) == 1 and after != {before}
    (after_id,) = after
    assert after_id == f"CBOM-D10-T1-20261019-{view.fingerprint[:8]}"
    assert after_id.rsplit("-", 1)[0] == before.rsplit("-", 1)[0]  # only the suffix moved
    # the same upload, rebuilt from scratch, is the same document; one more record is a new one
    again = copy.deepcopy(raw_scans)
    attest(again, 2, {"cert_in_cbom": {"8.4.1.1": done}})
    assert make_view(again).fingerprint == view.fingerprint
    minutes = stamp("minutes.pdf", None, "2026-10-17T08:00:00Z")
    attest(again, 3, {"bsi_tr_02102": {"BSI-4": minutes}})
    assert make_view(again).fingerprint not in (view.fingerprint, base_view.fingerprint)


def test_a_note_equal_to_the_file_name_is_printed_once(raw_scans):
    scans = copy.deepcopy(raw_scans)
    name = "board-minutes-extract.pdf"
    attest(scans, 3, {"bsi_tr_02102": {"BSI-4": stamp(name, None, "2026-10-17T08:00:00Z")}})
    row = ledger_record(build_story(make_view(scans)), "BSI TR-02102", "BSI-4")
    assert row["Attested k/n"] == "Attested 1/5"
    assert row[LATEST_HEADER].split("\n") == [name, "2026-10-17"]


def test_latest_attestation_is_the_most_recent_upload_across_sources(raw_scans):
    scans = copy.deepcopy(raw_scans)
    newer = stamp("newer.pdf", "newer note", "2026-10-18T11:00:00Z")
    older = stamp("older.pdf", "older note", "2026-10-10T10:00:00Z")
    attest(scans, 2, {"cert_in_cbom": {"8.4.1.2": newer}})  # newer upload, LOWER scan id
    attest(scans, 3, {"cert_in_cbom": {"8.4.1.2": older}})
    row = ledger_record(build_story(make_view(scans)), CERT_IN, "8.4.1.2")
    assert row["Attested k/n"] == "Attested 2/5"
    assert row[LATEST_HEADER].split("\n") == ["newer.pdf", "newer note", "2026-10-18"]


def test_attestation_in_a_superseded_scan_is_ignored(raw_scans):
    scans = copy.deepcopy(raw_scans)
    ghost = stamp("ghost.pdf", "ghost", "2026-09-29T09:00:00Z")
    attest(scans, 1, {"cert_in_cbom": {"8.4.1.1": ghost}})  # scan 1 = payments v1 (not current)
    view = make_view(scans)
    row = ledger_record(build_story(view), CERT_IN, "8.4.1.1")
    assert row["Attested k/n"] == "Attested 0/5"
    assert row[LATEST_HEADER] == DASH
    assert "ghost.pdf" not in norm(pdf_full_text(register.build_pdf(view)))


def test_chip_colour_tracks_how_complete_the_attestation_is(raw_scans):
    scans = copy.deepcopy(raw_scans)
    for scan_id in (3, 4, 5, 6):  # with scan 2 below: every source that needs 8.4.1.1
        attest(scans, scan_id, {"cert_in_cbom": {"8.4.1.1": stamp(f"s{scan_id}.pdf")}})
    attest(
        scans,
        2,
        {"cert_in_cbom": {"8.4.1.1": stamp("s2.pdf"), "8.4.1.2": stamp("partial.pdf")}},
    )
    table = find_table(build_story(make_view(scans)), LEDGER_HEADERS)
    chips = {
        (cell_text(row[0]), cell_text(row[1]).replace("\n", "")): (
            cell_text(row[5]),
            row[5].style.backColor,
        )
        for row in body_rows(table)
    }
    assert chips[(CERT_IN, "8.4.1.1")] == ("Attested 5/5", PILL_LOW_BG)  # complete
    assert chips[(CERT_IN, "8.4.1.2")] == ("Attested 1/5", PILL_MEDIUM_BG)  # partial
    assert chips[(CERT_IN, "8.4.1.3")] == ("Attested 0/5", PILL_HIGH_BG)  # none
    assert len({c.hexval() for c in (PILL_LOW_BG, PILL_MEDIUM_BG, PILL_HIGH_BG)}) == 3


def test_ledger_of_a_legacy_only_team_explains_why_it_is_empty(raw_scans):
    legacy = [s for s in copy.deepcopy(raw_scans) if s["id"] == 8]
    view = make_view(legacy)
    story = build_story(view)
    assert body_rows(find_table(story, LEDGER_HEADERS)) == []
    text = norm(pdf_full_text(register.build_pdf(view)))
    assert "REDUCED-FIDELITY DATA" in text  # shell banner: every included scan is legacy
    assert "Legacy-format scans carry no compliance results" in text
    assert "Re-scan the affected sources to populate this ledger." in text
    assert len(body_rows(find_table(story, LIB_HEADERS))) == 4  # libraries survive in cbom_json


def test_full_fidelity_team_with_nothing_to_attest_says_so(raw_scans):
    manifests = [s for s in copy.deepcopy(raw_scans) if s["id"] == 7]
    story = build_story(make_view(manifests))
    assert body_rows(find_table(story, LEDGER_HEADERS)) == []
    # R-08: 19 libraries (+ the WP3a golang.org/x/crypto@v0.24.0 advisory component), 1 asset row
    assert len(body_rows(find_table(story, LIB_HEADERS))) == 19
    notes = story_texts(story)
    assert any("No control in the pooled scans needs an attestation" in t for t in notes)


# ---------------------------------------------------------------------------------------------
# C. Summary KPIs
# ---------------------------------------------------------------------------------------------
def test_summary_kpis_for_the_unattested_fixture(base_story):
    cards = kpi_cards(base_story)
    assert cards["Controls needing attestation"][0] == "48"
    assert cards["Fully attested"][0] == "0"
    assert cards["Partly attested"][0] == "0"
    assert cards["Attested (source level)"][0] == "0.0%"
    assert "0 of 207" in cards["Attested (source level)"][1]


def test_summary_kpis_follow_an_injected_attestation(raw_scans):
    scans = copy.deepcopy(raw_scans)
    attest(scans, 2, {"cert_in_cbom": {"8.4.1.1": stamp("a.pdf", "n", "2026-10-15T09:30:00Z")}})
    cards = kpi_cards(build_story(make_view(scans)))
    assert cards["Controls needing attestation"][0] == "48"
    assert cards["Fully attested"][0] == "0"
    assert cards["Partly attested"][0] == "1"
    assert cards["Attested (source level)"][0] == "0.5%"  # 1 of 207
    assert "1 of 207" in cards["Attested (source level)"][1]


def test_summary_kpis_count_fully_attested_controls(raw_scans):
    scans = copy.deepcopy(raw_scans)
    for scan_id in (2, 3, 4, 5, 6):
        attest(scans, scan_id, {"cert_in_cbom": {"8.4.1.1": stamp("x.pdf", "n")}})
    cards = kpi_cards(build_story(make_view(scans)))
    assert cards["Fully attested"][0] == "1"
    assert cards["Partly attested"][0] == "0"
    assert cards["Attested (source level)"][0] == "2.4%"  # 5 of 207


# ---------------------------------------------------------------------------------------------
# D / E. Manual forms
# ---------------------------------------------------------------------------------------------
def test_vendor_register_is_twelve_blank_rows_with_the_plan_columns(base_story, base_text):
    table = find_table(base_story, VENDOR_HEADERS)
    assert headers_of(table) == tuple(authored.ASSURANCE_VENDOR_COLUMNS) == VENDOR_HEADERS
    rows = body_rows(table)
    assert len(rows) == 12
    assert all(cell_text(cell) == "" for row in rows for cell in row)
    assert "To be completed by assessor" in base_text


def test_signoff_block_is_blank_apart_from_the_roles(base_story):
    rows = body_rows(find_table(base_story, SIGNOFF_HEADERS))
    assert [cell_text(row[0]) for row in rows] == ["Prepared by", "Reviewed by", "Approved by"]
    assert all(cell_text(cell) == "" for row in rows for cell in row[1:])


# ---------------------------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------------------------
def test_ledger_over_1000_rows_is_capped_with_a_notice():
    view = blank_view(requirements=tuple(make_requirement(i) for i in range(1200)))
    started = time.perf_counter()
    raw = register.build_pdf(view)
    elapsed = time.perf_counter() - started
    assert elapsed < 20, f"1 000-row register took {elapsed:.1f}s"  # plan 4.7 budget
    story = build_story(view)
    assert len(body_rows(find_table(story, LEDGER_HEADERS))) == 1000
    assert kpi_cards(story)["Controls needing attestation"][0] == "1200"  # KPIs use the true total
    assert any("200 further rows omitted" in t for t in story_texts(story))
    assert "200 further rows omitted" in norm(pdf_full_text(raw))


def test_ledger_at_exactly_the_cap_has_no_notice():
    view = blank_view(requirements=tuple(make_requirement(i) for i in range(1000)))
    story = build_story(view)
    assert len(body_rows(find_table(story, LEDGER_HEADERS))) == 1000
    assert not any("further rows omitted" in t for t in story_texts(story))


def test_caps_are_read_at_call_time_and_each_table_has_its_own_notice(monkeypatch):
    monkeypatch.setattr(register, "MAX_LEDGER_ROWS", 5)
    monkeypatch.setattr(register, "MAX_LIBRARY_ROWS", 3)
    view = blank_view(
        requirements=tuple(make_requirement(i) for i in range(9)),
        libs=tuple(make_lib(f"lib-{i:02d}") for i in range(8)),
    )
    story = build_story(view)
    assert len(body_rows(find_table(story, LEDGER_HEADERS))) == 5
    assert len(body_rows(find_table(story, LIB_HEADERS))) == 3
    notices = [t for t in story_texts(story) if "further rows omitted" in t]
    assert len(notices) == 2
    ledger_notice = only(t for t in notices if "controls" in t)
    library_notice = only(t for t in notices if "libraries" in t)
    assert ledger_notice.startswith("4 further rows omitted")  # 9 - 5
    assert "first 5 of 9 controls" in ledger_notice
    assert library_notice.startswith("5 further rows omitted")  # 8 - 3
    assert "first 3 of 8 libraries" in library_notice


# ---------------------------------------------------------------------------------------------
# Empty and degraded teams
# ---------------------------------------------------------------------------------------------
def test_empty_team_still_produces_a_complete_document():
    view = make_view([], team_id=3, name="Empty Team")
    assert view.is_empty
    raw = register.build_pdf(view)
    text = norm(pdf_full_text(raw))
    assert "NO COMPLETED CBOM SCANS" in text
    story = build_story(view)
    assert body_rows(find_table(story, LIB_HEADERS)) == []
    assert body_rows(find_table(story, LEDGER_HEADERS)) == []
    cards = kpi_cards(story)
    assert cards["Controls needing attestation"][0] == "0"
    assert cards["Attested (source level)"][0] == "n/a"
    assert "no control needs attestation" in cards["Attested (source level)"][1]
    assert any("No compliance results are available yet" in t for t in story_texts(story))
    assert any("No cryptographic libraries were recorded" in t for t in story_texts(story))
    assert len(body_rows(find_table(story, VENDOR_HEADERS))) == 12  # manual forms remain
    assert has_table(story, SIGNOFF_HEADERS)
    for head in (HEAD_A, HEAD_B, HEAD_C, HEAD_D, HEAD_E):
        assert head in text
    assert "Attested 0/" not in text  # no invented chips


def test_a_team_with_only_failed_queued_running_or_empty_scans_gets_the_empty_document(raw_scans):
    wanted = {9, 10, 11, 13}  # failed, queued, running, success-but-{}
    scans = [s for s in copy.deepcopy(raw_scans) if s["id"] in wanted]
    view = make_view(scans)
    assert view.is_empty
    text = norm(pdf_full_text(register.build_pdf(view)))
    assert "NO COMPLETED CBOM SCANS" in text
    assert "Scans: 0 included of 1 eligible" in text
    assert "excluded: 1 failed, 2 not completed, 1 without data" in text
    for canary in CANARIES:
        assert canary not in text, canary


def test_unknown_framework_keys_degrade_to_a_readable_label_and_sort_last():
    known = make_requirement(1)
    odd = dataclasses.replace(make_requirement(2), framework="future_framework_x")
    view = blank_view(requirements=(odd, known))  # handed over in the "wrong" order
    rows = records(find_table(build_story(view), LEDGER_HEADERS))
    assert [(r["Framework"], r["Req ID"]) for r in rows] == [
        (CERT_IN, "REQ-0001"),
        ("future framework x", "REQ-0002"),
    ]


def test_inconsistent_counts_are_clamped_and_controls_nobody_needs_are_not_listed():
    over = dataclasses.replace(make_requirement(1, attestable=3), attested_sources=9)  # k > n
    nobody = dataclasses.replace(make_requirement(2), attestable_sources=0)
    rows = records(find_table(build_story(blank_view(requirements=(over, nobody))), LEDGER_HEADERS))
    assert [(r["Req ID"], r["Attested k/n"]) for r in rows] == [("REQ-0001", "Attested 3/3")]


# ---------------------------------------------------------------------------------------------
# Hostile input (scanned repositories and attestation notes are untrusted)
# ---------------------------------------------------------------------------------------------
HOSTILE = (
    '<img src="file:///etc/hostname"> <font color="red">red</font> &lt;b&gt; '
    '<a href="http://x.test">go</a>'
)


def test_hostile_strings_render_literally_and_embed_nothing(raw_scans, base_pdf):
    scans = copy.deepcopy(raw_scans)
    add_library(scans, 2, HOSTILE + "\x00 tail", "evil.py")
    for scan in scans:  # the roll-up keeps the first title it meets, so poison every pooled scan
        if scan["id"] in POOLED_SCAN_IDS:
            for block in scan["scan_data"]["cbom_compliance"].values():
                if isinstance(block, dict):
                    for req in block["requirements"]:
                        if req["id"] == "8.4.1.1":
                            req["title"], req["source"] = HOSTILE, HOSTILE
    hostile_file = '<b>boom</b><img src="file:///etc/passwd">.pdf'
    attest(scans, 2, {"cert_in_cbom": {"8.4.1.1": stamp(hostile_file, HOSTILE)}})
    view = make_view(scans)
    raw = register.build_pdf(view)
    text = norm(pdf_full_text(raw))
    assert raw.startswith(b"%PDF-")
    assert norm(HOSTILE) in text  # printed as characters, not interpreted
    assert hostile_file in text
    assert image_count(raw) == image_count(base_pdf)  # no <img> fetched or embedded
    assert link_count(raw) == link_count(base_pdf)  # no <a> turned into a link
    row = ledger_record(build_story(view), CERT_IN, "8.4.1.1")
    assert row["Title"] == HOSTILE  # white-box: literal text, nothing parsed away
    assert row[LATEST_HEADER].split("\n") == [hostile_file, HOSTILE, "2026-10-16"]
    names = [r["Library"] for r in records(find_table(build_story(view), LIB_HEADERS))]
    assert HOSTILE + " tail" in names  # NUL stripped, the rest literal


def test_one_megabyte_names_are_clamped_and_fast(raw_scans):
    scans = copy.deepcopy(raw_scans)
    add_library(scans, 2, "L" * 1_000_000)
    view = make_view(scans)
    started = time.perf_counter()
    raw = register.build_pdf(view)
    assert time.perf_counter() - started < 20
    assert len(raw) < 3_000_000
    rows = records(find_table(build_story(view), LIB_HEADERS))
    huge = only(r for r in rows if r["Library"].startswith("LLLL"))
    assert len(huge["Library"]) <= 300
    assert huge["Library"].endswith("\u2026")


def test_non_latin_names_degrade_to_question_marks_without_failing(raw_scans):
    scans = copy.deepcopy(raw_scans)
    name = "\u0915\u094d\u0930\u093f\u092a\u094d\u091f\u094b-lib \u202eevil \U0001f510"
    add_library(scans, 2, name)
    raw = register.build_pdf(make_view(scans))
    assert raw.startswith(b"%PDF-")
    assert "-lib" in pdf_full_text(raw)


# ---------------------------------------------------------------------------------------------
# Hard constraints: import rules, no wall clock, escape-everything, no network / no LLM
# ---------------------------------------------------------------------------------------------
def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def _imported_modules(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import"
            found.add(node.module or "")
    return found


FORBIDDEN_IMPORTS = {
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
    "openai", "anthropic", "instructor", "litellm", "requests", "httpx", "urllib3", "aiohttp",
    "socket", "http", "urllib", "smtplib", "ftplib", "subprocess", "celery", "kombu", "pymongo",
    "sqlmodel", "sqlalchemy", "fastapi", "starlette",
}  # fmt: skip
ALLOWED_BACKEND_PREFIXES = (
    "backend.utilities.pdf",
    "backend.utilities.dashboard.cbom_team_rollup",
)


def test_imports_follow_the_renderer_import_rules():
    modules = _imported_modules(_module_tree())
    assert modules, "module imports nothing?"
    for name in modules:
        root = name.split(".")[0]
        assert root not in FORBIDDEN_IMPORTS, name
        assert root in sys.stdlib_module_names or root in {"reportlab", "backend"}, name
        if root == "backend":
            assert name.startswith(ALLOWED_BACKEND_PREFIXES), name
            assert not name.startswith(("backend.utilities.ai", "backend.routers")), name


def test_source_has_no_llm_tokens():
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    for token in ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai"):
        assert token not in source, token


def test_no_wall_clock_reads_in_the_renderer():
    clock_calls = {"now", "utcnow", "today", "time", "localtime", "gmtime", "monotonic"}
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in clock_calls, ast.dump(node.func)


def test_every_paragraph_in_the_renderer_is_built_from_pdf_text():
    """The pdf_text rule (plan 5.5.1): data-derived text never reaches Paragraph unescaped."""
    paragraphs = 0
    for node in ast.walk(_module_tree()):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "Paragraph":
            continue
        paragraphs += 1
        first = node.args[0]
        assert isinstance(first, ast.Call), ast.dump(first)
        inner = first.func.id if isinstance(first.func, ast.Name) else ""
        assert inner in {"pdf_text", "pdf_multiline"}, ast.dump(first)
    assert paragraphs >= 1


def test_fresh_interpreter_import_loads_no_network_or_llm_module():
    script = textwrap.dedent(
        """
        import importlib, json, sys
        importlib.import_module("backend.utilities.pdf.cbom_assurance_register_pdf")
        forbidden = {"boto3", "botocore", "langchain", "langchain_core", "langchain_aws",
                     "langchain_openai", "openai", "anthropic", "instructor", "requests",
                     "httpx", "urllib3", "aiohttp", "msal", "celery", "kombu", "pymongo"}
        bad = sorted(m for m in sys.modules if m.split(".")[0] in forbidden)
        ai = sorted(m for m in sys.modules
                    if m.startswith("backend.utilities.ai") or m == "backend.routers.scans")
        print(json.dumps({"forbidden": bad, "ai": ai}))
        """
    )
    env = dict(os.environ, PYTHONPATH=str(_REPO_ROOT))
    done = subprocess.run(
        [sys.executable, "-c", script], cwd=_REPO_ROOT, env=env, capture_output=True, text=True,
        timeout=180, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    report = json.loads(done.stdout.strip().splitlines()[-1])
    assert report == {"forbidden": [], "ai": []}


def test_builds_with_the_network_and_process_spawning_blocked(no_network, base_view, base_pdf):
    with pytest.raises(AssertionError, match="network/process access attempted"):
        socket.create_connection(("127.0.0.1", 9))  # control: the tripwire really trips
    assert register.build_pdf(base_view) == base_pdf


def test_rendering_does_not_mutate_the_view(raw_scans):
    view = make_view(raw_scans)
    before = copy.deepcopy(view)
    register.build_pdf(view)
    assert view == before
