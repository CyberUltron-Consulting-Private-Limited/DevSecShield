"""T-15: hermetic tests for the PQC Migration Roadmap renderer (#15, WP3e).

ORACLE RULE (plan 8.4).  Every expected number and sentence in this module is a literal taken
from plan Appendix B (hand / openssl derived), decision D-06 and Appendix C (timeline wording and
URLs), or from a stdlib probe of the committed raw fixture.  Nothing is recomputed with the
renderer.  The headline facts of team 1 (Appendix B): 5 current quantum-vulnerable occurrences
(payments RSA-1024 + RSA-2048, pqc-pilot RSA-2048, legacy-billing RSA-1024 + RSA-2048), 32
quantum-safe, readiness 86.5 %, 3 of the 5 rows from full-fidelity scans and 2 from the legacy
(Tier B) scan, which has no sized target.

The document is a pure function of a ``TeamCbomView``: the fixture view is produced by the real
aggregator (``fold_scans``) over the committed team fixture, and edge cases use hand-made views.
No DB, network, LLM or wall clock; PDFs are inspected with a small pure-Python content-stream
reader (ASCII85 + Flate), so the suite needs nothing beyond ``reportlab``.  Table structure
(blank manual cells, column order) is asserted on the flowables the renderer returns, wording on
the extracted PDF text.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import inspect
import json
import random
import re
import sys
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from reportlab.platypus import Paragraph, Table

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    AssetAgg,
    ScanHead,
    SourceAgg,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_deliverable_text as text  # noqa: E402
from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import (  # noqa: E402
    build_document,
    get_deliverable_styles,
)
from backend.utilities.pdf.report_branding import (  # noqa: E402
    COLOR_BORDER,
    COLOR_HEADER_SOFT,
    COLOR_ROW_ALT,
    COLOR_WHITE,
    PILL_HIGH_BG,
    PILL_MEDIUM_BG,
    REPORT_META,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # the fixture's frozen "now" (17:58 IST)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE_PATH = _REPO_ROOT / "backend" / "utilities" / "pdf" / "cbom_pqc_roadmap_pdf.py"

# --- literals (plan Appendix B, decision D-06, Appendix C) -----------------------------------
DASH = "\u2014"
FAMILY_PKE = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
FAMILY_SIGNATURE = "ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)"
FAMILY_KEM = "ML-KEM (FIPS 203)"
SIZED_768 = "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"
UNAVAILABLE = "not available \u2014 legacy scan"
ORDER_NOTE = "Order = current scanner impact, not a migration sequence."
PAYMENTS = "github.com/e2e-demo/payments-service (main)"
PQC_PILOT = "github.com/e2e-demo/pqc-pilot (release)"
LEGACY = "github.com/e2e-demo/legacy-billing (main)"

ROADMAP_HEADERS = [
    "#",
    "Algorithm",
    "Key/curve",
    "Classical strength (bits)",
    "NIST QSL",
    "Target family",
    "Sized target",
    "Impact",
    "Where found",
    "Seen",
    "Wave (assessor)",
    "Target date (assessor)",
    "Owner / status (assessor)",
]
TIMELINE_HEADERS = ["When", "Milestone", "Status", "Source", "Source URL"]
FAMILY_HEADERS = ["Target family", "Primitive", "Occurrences", "Sources"]
LEVEL_HEADERS = ["NIST quantum security level", "Occurrences", "Of which hybrid"]
URL_PQC = "https://www.nist.gov/pqcrypto"
URL_IR8547 = "https://csrc.nist.gov/pubs/ir/8547/ipd"
URL_CNSA = "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF"
IR8547 = "NIST IR 8547 (initial public draft)"
TIMELINE_ROWS = [
    (
        "Aug 2024",
        "NIST publishes the first post-quantum standards: FIPS 203 (ML-KEM), FIPS 204 "
        "(ML-DSA) and FIPS 205 (SLH-DSA).",
        "FINAL",
        "NIST post-quantum cryptography project",
        URL_PQC,
    ),
    (
        "Nov 2024",
        "NIST IR 8547 initial public draft published: proposed transition timeline for "
        "quantum-vulnerable public-key algorithms.",
        "DRAFT",
        IR8547,
        URL_IR8547,
    ),
    (
        "After 2030",
        "Quantum-vulnerable public-key algorithms with 112 bits of security strength (for "
        "example RSA-2048) are deprecated (NIST IR 8547 initial public draft).",
        "DRAFT",
        IR8547,
        URL_IR8547,
    ),
    (
        "After 2035",
        "All quantum-vulnerable public-key algorithms are disallowed (NIST IR 8547 initial "
        "public draft).",
        "DRAFT",
        IR8547,
        URL_IR8547,
    ),
    (
        "2025 to 2035",
        "CNSA 2.0 NSS milestones: software/firmware signing 2025, networking 2030, all NSS "
        "by 2033-2035. Verify against the NSA advisory before submission.",
        "ADVISORY",
        "NSA CNSA 2.0 advisory",
        URL_CNSA,
    ),
]
TIMELINE_FOOTNOTE = (
    "NIST IR 8547 remains an initial public draft and its dates may change in the final "
    "publication. FIPS 203, 204 and 205 are final."
)
# (algorithm, key, strength, source, path, impact, sized): the 5 rows of team 1, in print order
# (impact rank, key size, name, then source label).
FIXTURE_ROWS = [
    ("RSA-1024", "1024 bits", DASH, LEGACY, "crypto_app.py", "HIGH", UNAVAILABLE),
    ("RSA-1024", "1024 bits", "80", PAYMENTS, "crypto_app.py", "HIGH", SIZED_768),
    ("RSA-2048", "2048 bits", DASH, LEGACY, "crypto_app.py", "MEDIUM", UNAVAILABLE),
    ("RSA-2048", "2048 bits", "112", PAYMENTS, "crypto_app.py", "MEDIUM", SIZED_768),
    ("RSA-2048", "2048 bits", "112", PQC_PILOT, "pqc_app.py", "MEDIUM", SIZED_768),
]
# stdlib probe of the committed fixture: quantum-safe current algorithm rows by NIST level
FIXTURE_LEVELS = {
    "Level 1": ("1", "0"),
    "Level 2": ("3", "0"),
    "Level 3": ("2", "1"),
    "Level 4": ("1", "0"),
    "Level 5": ("6", "1"),
    "Not recorded": ("19", "0"),
    "Total quantum-safe": ("32", "2"),
}
FIXTURE_KPIS = {
    "Quantum-vulnerable": "5",
    "Distinct kinds": "2",
    "Quantum readiness": "86.5%",
    "Quantum-safe": "32",
    "Hybrid": "2",
    "Not gradeable": "0",
}
CANARIES = (
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
    "AIBOM-DISCLAIMER",
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
    """Collapse whitespace (a wrapped sentence reads as one line)."""
    return re.sub(r"\s+", " ", value).strip()


def squash(value: str) -> str:
    """Drop ALL whitespace: robust against a long token hard-wrapped by a narrow column."""
    return re.sub(r"\s+", "", value)


def has(haystack: str, needle: str) -> bool:
    return squash(needle) in squash(haystack)


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
    """Embedded image XObjects (the brand logo in the page chrome is the only legitimate one)."""
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


# ---------------------------------------------------------------------------------------------
# Flowable inspection helpers (structure of the story the renderer builds)
# ---------------------------------------------------------------------------------------------
def walk(obj):
    """Every flowable reachable from ``obj``, descending into table cells and containers."""
    if isinstance(obj, (list, tuple)):
        for item in obj:
            yield from walk(item)
        return
    yield obj
    if isinstance(obj, Table):
        for row in obj._cellvalues:
            for cell in row:
                yield from walk(cell)
    else:
        yield from walk(list(getattr(obj, "_content", None) or []))


def plain(cell) -> str:
    if isinstance(cell, Paragraph):
        return cell.getPlainText()
    if isinstance(cell, (list, tuple)):
        return "".join(plain(item) for item in cell)
    return "" if cell is None else str(cell)


def tables(flowables) -> list[Table]:
    return [item for item in walk(flowables) if isinstance(item, Table)]


def header_texts(table: Table) -> list[str]:
    return [plain(cell) for cell in table._cellvalues[0]]


def data_rows(table: Table) -> list[list[str]]:
    return [[plain(cell) for cell in row] for row in table._cellvalues[1:]]


def find_tables(flowables, headers: list[str]) -> list[Table]:
    return [t for t in tables(flowables) if header_texts(t) == headers]


def roadmap_tables(flowables) -> list[Table]:
    return find_tables(flowables, ROADMAP_HEADERS)


def paragraphs(flowables, style_name: str) -> list[str]:
    return [
        item.getPlainText()
        for item in walk(flowables)
        if isinstance(item, Paragraph) and item.style.name == style_name
    ]


def section_titles(flowables) -> list[str]:
    return paragraphs(flowables, "SectionHeading")


def kpi_cards(flowables) -> dict[str, tuple[str, str]]:
    """label -> (value, hint) of every KPI card (cards are label, value, hint paragraphs)."""
    labels = paragraphs(flowables, "DashKpiLabel")
    values = paragraphs(flowables, "DashKpiValue")
    hints = paragraphs(flowables, "DashKpiHint")
    return {label: (value, hint) for label, value, hint in zip(labels, values, hints, strict=True)}


def group_headings(flowables) -> list[str]:
    pattern = re.compile(r"\u00b7 \d+ occurrences?$")
    return [
        item.getPlainText()
        for item in walk(flowables)
        if isinstance(item, Paragraph) and pattern.search(item.getPlainText())
    ]


def body_of(view: TeamCbomView, **kwargs):
    return roadmap.build_body(view, get_deliverable_styles(), 720.0, **kwargs)


# ---------------------------------------------------------------------------------------------
# Views: the real aggregator over the committed fixture, and hand-made ones
# ---------------------------------------------------------------------------------------------
def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


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


def fold(scans: list[dict], *, name: str = "E2E Demo Team") -> TeamCbomView:
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        [_head(s) for s in scans],
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=1,
        team_name=name,
        now=NOW,
    )


def _result_row(title, *, ref, vulnerable, key_size=None, impact="Low", primitive="pke"):
    return {
        "title": title,
        "asset_type": "algorithm",
        "bom_ref": ref,
        "location": "app.py",
        "impact": impact,
        "finding_codes": ["QUANTUM_VULNERABLE"] if vulnerable else [],
        "description": f"{title} finding text",
        "primitive": primitive,
        "key_size": key_size,
        "quantum_vulnerable": vulnerable,
        "quantum_safe": not vulnerable,
        "hybrid": False,
        "security_strength_bits": 112 if vulnerable else 256,
        "nist_quantum_security_level": 0 if vulnerable else 5,
        "pqc_migration_target": FAMILY_PKE if vulnerable else None,
        "pqc_migration_roadmap": SIZED_768 if vulnerable else None,
    }


def _full_blob(rows: list[dict]) -> dict:
    """A full-fidelity (Tier A) run-object: typed rows, BOM, distributions, compliance."""
    requirement = {
        "id": "KM-1",
        "title": "Key sizes",
        "source": "SP 800-57",
        "verdict": "pass",
        "attestable": False,
        "evidence": "e",
        "refs": [],
    }
    framework = {
        "pass": 1,
        "pass_with_evidence": 0,
        "fail": 0,
        "out_of_scope": 0,
        "not_bom_evidenceable": 0,
        "na": 0,
        "coverage": None,
        "requirements": [requirement],
    }
    return {
        "results": rows,
        "cbom_json": {"specVersion": "1.6", "components": []},
        "cbom_distributions": {"pqc": {}},
        "cbom_compliance": {"nist_800_57": framework, "disclaimer": "AIBOM-DISCLAIMER"},
    }


def _scan(sid: int, days_ago: int, rows: list[dict]) -> dict:
    created = NOW - timedelta(days=days_ago)
    return {
        "id": sid,
        "team_id": 1,
        "scan_type": "cbom",
        "title": f"scan-{sid}",
        "status": "success",
        "created_at": _iso(created),
        "last_updated": _iso(created + timedelta(minutes=2)),
        "scan_metadata": {"zip_file_used": False, "repo_url": "https://github.com/o/r"},
        "scan_data": _full_blob(rows),
    }


def algo(
    title,
    *,
    key_size="2048",
    curve=None,
    impact="Medium",
    primitive="pke",
    family=FAMILY_PKE,
    sized=SIZED_768,
    bits=112,
    level=0,
    vulnerable=True,
    hybrid=False,
    tier="A",
    current=True,
    source="example.test/org/repo1 (main)",
    location="app.py",
    scans=1,
    first=None,
    last=None,
    ident=None,
) -> AssetAgg:
    slug = re.sub(r"[^a-z0-9]+", "-", source.lower())
    return AssetAgg(
        source_key=f"repo:{slug}",
        source_label=source,
        asset_type="algorithm",
        ident=ident or f"{title}#{location}#{source}",
        title=title,
        location=location,
        impact=impact,
        finding_codes=("QUANTUM_VULNERABLE",) if vulnerable else (),
        primitive=primitive,
        key_size=key_size,
        curve=curve,
        security_strength_bits=bits,
        quantum_vulnerable=vulnerable,
        quantum_safe=None if vulnerable is None else not vulnerable,
        hybrid=hybrid,
        nist_quantum_security_level=level,
        pqc_migration_target=family,
        pqc_migration_roadmap=sized,
        tier=tier,
        current=current,
        first_seen=first or NOW - timedelta(days=30),
        last_seen=last or NOW - timedelta(days=2),
        scan_count=scans,
        scan_ids=(1,),
        latest_scan_id=1,
    )


def _source(i: int) -> SourceAgg:
    return SourceAgg(
        key=f"repo:example.test/org/repo{i}@main",
        label=f"example.test/org/repo{i} (main)",
        kind="repo",
        repo_url=f"https://example.test/org/repo{i}",
        branch="main",
        scan_ids=(i,),
        scan_count=1,
        first_scanned=NOW,
        last_scanned=NOW,
        current_scan_id=i,
        current_tier="A",
        current_fidelity="full",
        last_attempt_scan_id=i,
        last_attempt_status="success",
        last_attempt_at=NOW,
    )


def make_view(assets=(), **overrides) -> TeamCbomView:
    """A hand-made view; the headline PQC counts are derived from ``assets`` (test input only)."""
    algorithms = [a for a in assets if a.current and a.asset_type == "algorithm"]
    vulnerable = sum(1 for a in algorithms if a.quantum_vulnerable is True)
    safe = sum(1 for a in algorithms if a.quantum_vulnerable is False)
    fields = {
        "team_id": 1,
        "team_name": "E2E Demo Team",
        "generated_at": NOW,
        "as_of": NOW.date(),
        "scans_total": 3,
        "eligible": 3,
        "included": 3,
        "fidelity_full": 3,
        "fidelity_reduced": 0,
        "window_start": NOW - timedelta(days=30),
        "window_end": NOW - timedelta(days=2),
        "fingerprint": "ab12cd34ef56",
        "sources": tuple(_source(i) for i in range(1, 4)),
        "assets": tuple(assets),
        "asset_occurrences": len(algorithms),
        "pqc_vulnerable": vulnerable,
        "pqc_safe": safe,
        "pqc_hybrid": sum(1 for a in algorithms if a.quantum_vulnerable is False and a.hybrid),
        "pqc_ungraded": len(algorithms) - vulnerable - safe,
        "readiness_pct": (
            round(100.0 * safe / (safe + vulnerable), 1) if safe + vulnerable else None
        ),
    }
    fields.update(overrides)
    return TeamCbomView(**fields)


def make_empty_view() -> TeamCbomView:
    return make_view(
        scans_total=0,
        eligible=0,
        included=0,
        fidelity_full=0,
        fidelity_reduced=0,
        window_start=None,
        window_end=None,
        sources=(),
    )


def mixed_assets() -> list[AssetAgg]:
    """Ten vulnerable occurrences over every primitive group, deliberately NOT in print order."""
    return [
        algo("RSA-4096", key_size="4096", impact="Medium", ident="a1"),
        algo("RSA-1024", key_size="1024", impact="High", ident="a2"),
        algo("DH-2048", primitive="key-agree", family=FAMILY_KEM, impact="High", ident="a3"),
        algo(
            "ECDSA P-256",
            primitive="signature",
            family=FAMILY_SIGNATURE,
            key_size="256",
            curve="P-256",
            impact="Medium",
            ident="a4",
        ),
        algo("RSA-2048", impact="Critical", ident="a5"),
        algo(
            "DSA-1024",
            primitive="signature",
            family=FAMILY_SIGNATURE,
            key_size="1024",
            impact="Critical",
            ident="a6",
        ),
        algo(
            "Mystery-KEX",
            primitive=None,
            family=None,
            sized=None,
            key_size=None,
            bits=None,
            level=None,
            impact="Low",
            tier="C",
            ident="a7",
        ),
        algo(
            "Custom KEM",
            primitive="kem",
            family=FAMILY_KEM,
            key_size=None,
            impact="Low",
            ident="a8",
        ),
        algo("RSA-2048", impact="Medium", ident="a9"),
        algo("DH-2048", impact="Medium", ident="a10"),
    ]


# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def raw_scans():
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def team_view(raw_scans):
    """ALL 14 fixture scans folded for team 1 (failed / queued / other-team canaries included)."""
    return fold(raw_scans["scans"])


@pytest.fixture(scope="module")
def team_pdf(team_view):
    return roadmap.build_pdf(team_view)


@pytest.fixture(scope="module")
def team_text(team_pdf):
    return pdf_full_text(team_pdf)


@pytest.fixture(scope="module")
def team_body(team_view):
    return body_of(team_view)


@pytest.fixture(scope="module")
def mixed_body():
    return body_of(make_view(mixed_assets()))


# =============================================================================================
# Public contract
# =============================================================================================
def test_public_contract_matches_the_registry_expectations():
    assert roadmap.NUMBER == 15
    assert roadmap.SLUG == "pqc-migration-roadmap"  # plan 0: the slug the router serves
    assert roadmap.REPORT_KEY == "cbom_pqc_roadmap"
    assert roadmap.REPORT_KEY in REPORT_META
    assert roadmap.TITLE == "PQC Migration Roadmap"
    assert REPORT_META[roadmap.REPORT_KEY]["title"] == roadmap.TITLE
    assert roadmap.MAX_ROWS == 2000
    params = inspect.signature(roadmap.build_pdf).parameters
    assert next(iter(params)) == "view"  # the registry calls spec.build(view)
    assert params["max_rows"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["max_rows"].default == roadmap.MAX_ROWS


def test_build_pdf_is_a_landscape_pdf_with_its_own_identity(team_view, team_pdf, team_text):
    assert team_pdf.startswith(b"%PDF-")
    assert team_pdf.rstrip().endswith(b"%%EOF")
    assert media_box(team_pdf) == (792.0, 612.0)  # letter landscape
    assert info_field(team_pdf, "Title") == "PQC Migration Roadmap - E2E Demo Team"
    assert info_field(team_pdf, "Author") == "DevSecShield CBOM engine"
    assert "CBOM PQC Migration Roadmap" in team_text  # its OWN footer label ...
    assert "SAST Report" not in team_text  # ... never the fallback one
    match = re.search(r"CBOM-D15-T1-20261019-([0-9a-f]{8})", team_text)
    assert match, "Document ID missing"
    assert match.group(1) == team_view.fingerprint[:8]


def test_shell_basis_box_reports_the_appendix_b_scan_counts(team_text):
    assert has(
        team_text,
        "Scans: 8 included of 9 eligible \u00b7 excluded: 1 failed, 2 not completed, "
        "1 without data",
    )


def test_pdf_is_deterministic(team_view, team_pdf):
    assert roadmap.build_pdf(team_view) == team_pdf


def test_pdf_does_not_depend_on_the_order_of_view_assets():
    assets = mixed_assets()
    shuffled = list(assets)
    random.Random(15).shuffle(shuffled)
    assert roadmap.build_pdf(make_view(assets)) == roadmap.build_pdf(make_view(shuffled))
    assert roadmap.build_pdf(make_view(assets)) == roadmap.build_pdf(make_view(assets[::-1]))


# =============================================================================================
# Section order
# =============================================================================================
def test_sections_are_numbered_in_the_planned_order(team_body):
    assert section_titles(team_body) == [
        "1 Summary",
        "2 Regulatory timeline",
        "3 Target families",
        "4 Per-asset roadmap",
        "5 Already quantum-safe and hybrid",
        "6 Notes",
    ]


# =============================================================================================
# Summary KPIs (readiness 86.5 %)
# =============================================================================================
def test_kpi_strip_carries_the_appendix_b_numbers(team_body):
    cards = kpi_cards(team_body)
    assert {label: value for label, (value, _hint) in cards.items()} == FIXTURE_KPIS
    assert list(cards) == list(FIXTURE_KPIS)  # the planned order


def test_readiness_is_86_5_percent_in_the_pdf_text(team_text):
    assert has(team_text, "86.5%")
    assert has(team_text, "Quantum readiness")


def test_readiness_is_not_available_when_nothing_is_gradeable():
    safe_only = make_view([algo("AES-256-GCM", vulnerable=False, primitive="block-cipher")])
    assert kpi_cards(body_of(safe_only))["Quantum readiness"][0] == "100.0%"
    nothing = make_view([], readiness_pct=None)
    assert kpi_cards(body_of(nothing))["Quantum readiness"][0] == "n/a"


# =============================================================================================
# Per-asset roadmap: 5 rows = 3 full + 2 legacy
# =============================================================================================
def test_roadmap_header_is_the_planned_thirteen_columns(team_body):
    (table,) = roadmap_tables(team_body)
    assert header_texts(table) == ROADMAP_HEADERS


def test_roadmap_has_exactly_five_rows_in_print_order(team_body):
    (table,) = roadmap_tables(team_body)  # all five are pke => ONE group => ONE table
    rows = data_rows(table)
    assert len(rows) == 5
    col = {name: i for i, name in enumerate(ROADMAP_HEADERS)}
    assert [r[col["#"]] for r in rows] == ["1", "2", "3", "4", "5"]
    for row, (name, key, strength, source, path, impact, sized) in zip(
        rows, FIXTURE_ROWS, strict=True
    ):
        assert row[col["Algorithm"]] == name
        assert key in row[col["Key/curve"]]
        assert row[col["Classical strength (bits)"]] == strength
        assert row[col["NIST QSL"]] == "0"
        assert row[col["Target family"]] == FAMILY_PKE
        assert row[col["Sized target"]] == sized
        assert row[col["Impact"]] == impact
        assert source in row[col["Where found"]]
        assert path in row[col["Where found"]]


def test_three_rows_carry_a_sized_target_and_two_legacy_rows_say_not_available(team_body):
    (table,) = roadmap_tables(team_body)
    sized = [row[ROADMAP_HEADERS.index("Sized target")] for row in data_rows(table)]
    assert sized.count(SIZED_768) == 3
    assert sized.count(UNAVAILABLE) == 2
    where = [row[ROADMAP_HEADERS.index("Where found")] for row in data_rows(table)]
    legacy_rows = [w for w, s in zip(where, sized, strict=True) if s == UNAVAILABLE]
    assert len(legacy_rows) == 2
    assert all(LEGACY in w for w in legacy_rows)  # exactly the legacy-billing (Tier B) source


def test_sized_and_unavailable_wording_reaches_the_pdf(team_text):
    flat = squash(team_text)
    assert flat.count(squash(SIZED_768)) == 3  # one per full-fidelity row, nowhere else
    assert flat.count(squash(UNAVAILABLE)) == 2  # one per legacy row, nowhere else


def test_seen_column_shows_first_last_and_scan_count(team_body):
    (table,) = roadmap_tables(team_body)
    where_col = ROADMAP_HEADERS.index("Where found")
    seen_col = ROADMAP_HEADERS.index("Seen")
    by_source: dict[str, list[str]] = {}
    for row in data_rows(table):
        label = next(s for s in (LEGACY, PAYMENTS, PQC_PILOT) if s in row[where_col])
        by_source.setdefault(label, []).append(row[seen_col])
    assert {k: len(v) for k, v in by_source.items()} == {LEGACY: 2, PAYMENTS: 2, PQC_PILOT: 1}
    for seen in by_source[PAYMENTS]:  # two scans: first 2026-09-28, last 2026-10-12
        assert "2026-09-28" in seen
        assert "2026-10-12" in seen
        assert "2 scans" in seen
    for seen in by_source[LEGACY]:  # a single scan: one date, singular noun
        assert "2026-08-20" in seen
        assert "1 scan" in seen
        assert "1 scans" not in seen
    assert "2026-10-14" in by_source[PQC_PILOT][0]


def test_impact_cells_are_chips_in_the_existing_report_palette(team_body):
    (table,) = roadmap_tables(team_body)
    col = ROADMAP_HEADERS.index("Impact")
    chips = [row[col] for row in table._cellvalues[1:]]
    assert all(isinstance(chip, Paragraph) for chip in chips)
    assert [chip.getPlainText() for chip in chips] == ["HIGH", "HIGH"] + ["MEDIUM"] * 3
    assert [chip.style.backColor for chip in chips] == [PILL_HIGH_BG] * 2 + [PILL_MEDIUM_BG] * 3


# ---------------------------------------------------------------------------------------------
# Grouping by primitive
# ---------------------------------------------------------------------------------------------
def test_rows_are_grouped_by_primitive_in_catalogue_order(mixed_body):
    assert group_headings(mixed_body) == [
        "pke \u00b7 Public-key encryption and key transport (for example RSA) \u00b7 5 occurrences",
        "signature \u00b7 Digital signatures (for example RSA, ECDSA, DSA) \u00b7 2 occurrences",
        "key-agree \u00b7 Key agreement (for example Diffie-Hellman, ECDH) \u00b7 1 occurrence",
        "kem \u00b7 Key encapsulation \u00b7 1 occurrence",
        "other \u00b7 Other or unclassified primitive \u00b7 1 occurrence",
    ]
    assert len(roadmap_tables(mixed_body)) == 5  # one table per non-empty group


def test_rows_inside_a_group_sort_by_impact_then_key_size_then_name(mixed_body):
    groups = [data_rows(t) for t in roadmap_tables(mixed_body)]
    algorithm = ROADMAP_HEADERS.index("Algorithm")
    impact = ROADMAP_HEADERS.index("Impact")
    assert [(r[algorithm], r[impact]) for r in groups[0]] == [
        ("RSA-2048", "CRITICAL"),
        ("RSA-1024", "HIGH"),
        ("DH-2048", "MEDIUM"),  # same impact and key size as RSA-2048: the name decides
        ("RSA-2048", "MEDIUM"),
        ("RSA-4096", "MEDIUM"),  # larger key last
    ]
    assert [(r[algorithm], r[impact]) for r in groups[1]] == [
        ("DSA-1024", "CRITICAL"),
        ("ECDSA P-256", "MEDIUM"),
    ]
    assert [r[algorithm] for r in groups[2]] == ["DH-2048"]
    assert [r[algorithm] for r in groups[3]] == ["Custom KEM"]
    assert [r[algorithm] for r in groups[4]] == ["Mystery-KEX"]


def test_row_numbers_run_on_across_groups(mixed_body):
    numbers = [r[0] for t in roadmap_tables(mixed_body) for r in data_rows(t)]
    assert numbers == [str(i) for i in range(1, 11)]


def test_ec_rows_show_key_size_and_curve(mixed_body):
    signature = data_rows(roadmap_tables(mixed_body)[1])
    cell = signature[1][ROADMAP_HEADERS.index("Key/curve")]
    assert "256 bits" in cell
    assert "P-256" in cell


def test_key_sizes_sort_numerically_with_unknown_sizes_last():
    # as text "1024" < "256" < "4096"; as numbers 256 < 1024 < 4096
    assets = [
        algo("RSA-4096", key_size="4096", ident="1"),
        algo("Odd-Size", key_size="weird", ident="2"),
        algo("RSA-1024", key_size="1024", ident="3"),
        algo("No-Size", key_size=None, ident="4"),
        algo("EC-256", key_size="256", ident="5"),
        algo("Huge", key_size="9" * 5000, ident="6"),  # beyond int() limits: still just text
    ]
    (table,) = roadmap_tables(body_of(make_view(assets)))
    names = [r[ROADMAP_HEADERS.index("Algorithm")] for r in data_rows(table)]
    assert names == ["EC-256", "RSA-1024", "RSA-4096", "Huge", "No-Size", "Odd-Size"]


def test_only_current_quantum_vulnerable_algorithm_assets_become_rows():
    certificate = algo("cert.pem", ident="c")
    certificate.asset_type = "certificate"
    protocol = algo("TLS 1.0", ident="p")
    protocol.asset_type = "protocol"
    safe = algo("AES-256-GCM", vulnerable=False, primitive="block-cipher", ident="s")
    old = algo("RSA-1024", current=False, ident="o")
    keep = algo("RSA-2048", ident="k")
    body = body_of(make_view([certificate, protocol, safe, old, keep]))
    (table,) = roadmap_tables(body)
    assert [r[1] for r in data_rows(table)] == ["RSA-2048"]


def test_algorithms_without_a_quantum_status_are_counted_apart_and_never_listed():
    assets = [
        algo("RSA-2048", ident="v"),
        algo("AES-256-GCM", vulnerable=False, primitive="block-cipher", family=None, ident="s"),
        algo("Mystery", vulnerable=None, primitive=None, family=None, sized=None, ident="u"),
    ]
    view = make_view(assets)
    body = body_of(view)
    cards = {label: value for label, (value, _hint) in kpi_cards(body).items()}
    assert (cards["Quantum-vulnerable"], cards["Quantum-safe"]) == ("1", "1")
    assert cards["Not gradeable"] == "1"
    assert cards["Quantum readiness"] == "50.0%"  # the ungradeable one is not in the denominator
    (table,) = roadmap_tables(body)
    assert [r[1] for r in data_rows(table)] == ["RSA-2048"]
    (levels,) = find_tables(body, LEVEL_HEADERS)
    assert data_rows(levels)[-1] == ["Total quantum-safe", "1", "0"]
    out = pdf_full_text(roadmap.build_pdf(view))
    assert has(out, "left out of the readiness figure (count: 1)")


# ---------------------------------------------------------------------------------------------
# Target families (exact strings)
# ---------------------------------------------------------------------------------------------
def test_target_family_strings_are_exact_per_primitive(mixed_body):
    families = {
        (r[0], r[1]): r[2:] for t in find_tables(mixed_body, FAMILY_HEADERS) for r in data_rows(t)
    }
    assert families == {
        (FAMILY_PKE, "pke"): ["5", "1"],
        (FAMILY_SIGNATURE, "signature"): ["2", "1"],
        (FAMILY_KEM, "key-agree"): ["1", "1"],
        (FAMILY_KEM, "kem"): ["1", "1"],
        (UNAVAILABLE, "other"): ["1", "1"],  # a legacy row without a family is never invented
    }
    order = [r[1] for t in find_tables(mixed_body, FAMILY_HEADERS) for r in data_rows(t)]
    assert order == ["pke", "signature", "key-agree", "kem", "other"]
    per_row = [
        r[ROADMAP_HEADERS.index("Target family")]
        for t in roadmap_tables(mixed_body)
        for r in data_rows(t)
    ]
    assert per_row == ([FAMILY_PKE] * 5 + [FAMILY_SIGNATURE] * 2 + [FAMILY_KEM] * 2 + [UNAVAILABLE])


def test_family_summary_of_team_1_is_one_family_over_three_sources(team_body):
    (table,) = find_tables(team_body, FAMILY_HEADERS)
    assert data_rows(table) == [[FAMILY_PKE, "pke", "5", "3"]]


def test_a_legacy_row_without_a_sized_target_says_so_and_a_current_format_gap_says_not_recorded():
    legacy = algo("RSA-2048", tier="B", sized=None, bits=None, level=None, ident="b")
    gap = algo("RSA-3072", key_size="3072", tier="A", sized=None, ident="g")
    view = make_view([legacy, gap])
    rows = {r[1]: r for r in data_rows(roadmap_tables(body_of(view))[0])}
    sized = ROADMAP_HEADERS.index("Sized target")
    assert rows["RSA-2048"][sized] == UNAVAILABLE
    assert rows["RSA-3072"][sized] == "not recorded"
    assert rows["RSA-2048"][ROADMAP_HEADERS.index("NIST QSL")] == DASH
    assert rows["RSA-2048"][ROADMAP_HEADERS.index("Classical strength (bits)")] == DASH


# =============================================================================================
# Regulatory timeline: exact D-06 wording + URL text
# =============================================================================================
def test_timeline_table_rows_are_exactly_the_d06_wording(team_body):
    (table,) = find_tables(team_body, TIMELINE_HEADERS)
    assert [tuple(r) for r in data_rows(table)] == TIMELINE_ROWS


def test_timeline_wording_and_urls_reach_the_pdf_text(team_text):
    for when, milestone, status, source, url in TIMELINE_ROWS:
        for part in (when, milestone, status, source, url):
            assert has(team_text, part), part
    assert has(team_text, TIMELINE_FOOTNOTE)


def test_every_timeline_url_stays_on_one_line_and_is_not_a_link_annotation(
    team_view, team_pdf, team_text
):
    lines = team_text.split("\n")
    for url in (URL_PQC, URL_IR8547, URL_CNSA):
        assert any(url in line for line in lines), f"{url} was wrapped"
    # printable text only: the page chrome of an EMPTY body already has this many annotations
    chrome = build_document(
        view=team_view,
        number=15,
        report_key="cbom_pqc_roadmap",
        title="PQC Migration Roadmap",
        landscape=True,
        body=lambda styles, width: [],
    )
    assert link_count(team_pdf) == link_count(chrome)


def test_timeline_covers_every_authored_row(team_body):
    (table,) = find_tables(team_body, TIMELINE_HEADERS)
    assert len(data_rows(table)) == len(text.PQC_TIMELINE_ROWS) == 5


def test_ir_8547_is_always_draft_qualified_and_the_engine_sentence_is_never_printed(team_text):
    flat = norm(team_text)
    mentions = list(re.finditer(r"NIST IR 8547", flat))
    assert len(mentions) >= 5  # four timeline rows + the footnote
    for mention in mentions:
        window = flat[mention.start() : mention.start() + 60]
        assert "draft" in window, window
    # the engine constant over-simplifies (RSA/ECC/DH after 2030) and rows embed it (D-06)
    assert "RSA/ECC/DH" not in team_text
    assert "SP 1800-38" not in team_text


# =============================================================================================
# Notes and the "not a migration sequence" statement
# =============================================================================================
def test_order_note_is_printed_inside_the_roadmap_section(team_text):
    assert has(team_text, ORDER_NOTE)
    flat = squash(team_text)
    assert flat.index(squash("4 Per-asset roadmap")) < flat.index(squash(ORDER_NOTE))
    assert flat.index(squash(ORDER_NOTE)) < flat.index(squash("5 Already quantum-safe"))
    assert text.PQC_ROADMAP_ORDER_NOTE == ORDER_NOTE


def test_notes_explain_readiness_and_the_dash_and_the_manual_fields(team_text):
    flat = norm(team_text)
    assert "Readiness = quantum-safe / (quantum-safe + quantum-vulnerable)" in flat
    assert "A dash (\u2014) means the value is not recorded" in flat
    assert "it does not sequence the migration" in flat
    assert "not de-duplicated across sources" in flat


# =============================================================================================
# Manual columns: Wave / Target date / Owner-status blank
# =============================================================================================
def test_manual_columns_are_labelled_assessor_and_left_blank(team_body, mixed_body):
    for body in (team_body, mixed_body):
        for table in roadmap_tables(body):
            headers = header_texts(table)
            assert headers[-3:] == ROADMAP_HEADERS[-3:]
            assert not any("(assessor)" in h for h in headers[:-3])
            assert data_rows(table)
            assert all(row[-3:] == ["", "", ""] for row in data_rows(table))
            last = len(headers) - 1
            tinted = {
                cmd[1][0]
                for cmd in table._bkgrndcmds
                if cmd[0] == "BACKGROUND" and cmd[3] == PILL_MEDIUM_BG and cmd[1][0] == cmd[2][0]
            }
            assert tinted == {last - 2, last - 1, last}


def test_manual_headers_reach_the_pdf(team_text):
    for header in ROADMAP_HEADERS[-3:]:
        assert has(team_text, header)
    assert "(assessor) (assessor)" not in norm(team_text)


# =============================================================================================
# Already quantum-safe / hybrid by NIST level
# =============================================================================================
def test_quantum_safe_levels_table_matches_the_fixture_probe(team_body):
    (table,) = find_tables(team_body, LEVEL_HEADERS)
    rows = {r[0]: (r[1], r[2]) for r in data_rows(table)}
    assert rows == FIXTURE_LEVELS
    assert [r[0] for r in data_rows(table)][-1] == "Total quantum-safe"


def test_no_quantum_safe_occurrence_prints_a_sentence_not_an_empty_table():
    view = make_view([algo("RSA-2048")])
    body = body_of(view)
    assert find_tables(body, LEVEL_HEADERS) == []
    out = pdf_full_text(roadmap.build_pdf(view))
    assert has(out, "No quantum-safe algorithm occurrences are recorded")


# =============================================================================================
# No quantum-vulnerable assets: an explicit section, not an empty table
# =============================================================================================
@pytest.fixture(scope="module")
def clean_view():
    return make_view(
        [
            algo(
                "AES-256-GCM",
                vulnerable=False,
                primitive="block-cipher",
                family=None,
                sized=None,
                level=5,
                bits=256,
            ),
            algo(
                "SHA-256",
                vulnerable=False,
                primitive="hash",
                family=None,
                sized=None,
                level=2,
                bits=128,
            ),
            algo(
                "ML-KEM-768",
                vulnerable=False,
                primitive="kem",
                family=None,
                sized=None,
                level=3,
                bits=None,
            ),
        ]
    )


def test_no_vulnerable_assets_prints_an_explicit_section(clean_view):
    body = body_of(clean_view)
    assert section_titles(body) == [
        "1 Summary",
        "2 Regulatory timeline",
        "3 No quantum-vulnerable assets",
        "4 Already quantum-safe and hybrid",
        "5 Notes",
    ]
    assert roadmap_tables(body) == []  # NOT an empty table
    assert find_tables(body, FAMILY_HEADERS) == []
    out = pdf_full_text(roadmap.build_pdf(clean_view))
    assert has(out, "No quantum-vulnerable assets")
    assert has(out, text.PQC_NO_VULNERABLE_TEXT)
    assert "No entries" not in out
    assert has(out, "Aug 2024")  # the timeline is still useful context
    assert kpi_cards(body)["Quantum-vulnerable"][0] == "0"
    assert kpi_cards(body)["Quantum readiness"][0] == "100.0%"


def test_the_no_vulnerable_section_is_absent_when_there_are_rows(team_text):
    assert "No quantum-vulnerable assets" not in team_text


# =============================================================================================
# Empty team and legacy-only team
# =============================================================================================
def test_empty_team_gets_the_shell_banner_and_no_false_all_clear():
    view = make_empty_view()
    body = body_of(view)
    out = pdf_full_text(roadmap.build_pdf(view))
    assert "NO COMPLETED CBOM SCANS" in out
    assert "No quantum-vulnerable assets" not in out  # no scan, so no such finding
    assert has(out, "Roadmap not available")
    assert has(out, "No CBOM scan has completed")
    assert has(out, "This is not evidence that no quantum-vulnerable assets exist")
    cards = kpi_cards(body)
    assert cards["Quantum readiness"][0] == "n/a"
    assert cards["Quantum-vulnerable"][0] == "0"
    assert roadmap_tables(body) == []
    assert section_titles(body) == [
        "1 Summary",
        "2 Regulatory timeline",
        "3 Roadmap not available",
        "4 Notes",
    ]
    assert has(out, "Aug 2024")  # the static timeline still prints


def test_legacy_only_team_shows_the_reduced_fidelity_banner_and_no_sized_targets(raw_scans):
    legacy_only = [s for s in raw_scans["scans"] if s["id"] == 8]
    view = fold(legacy_only)
    assert (view.fidelity_full, view.fidelity_reduced) == (0, 1)
    body = body_of(view)
    (table,) = roadmap_tables(body)
    sized = {r[ROADMAP_HEADERS.index("Sized target")] for r in data_rows(table)}
    assert sized == {UNAVAILABLE}
    assert len(data_rows(table)) == 2
    out = pdf_full_text(roadmap.build_pdf(view))
    assert "REDUCED-FIDELITY DATA" in out
    assert squash(out).count(squash(UNAVAILABLE)) == 2


# =============================================================================================
# Previously seen, not in latest scan
# =============================================================================================
@pytest.fixture(scope="module")
def history_view():
    """One source, two scans: RSA-2048 was in the older scan only (-> current=False)."""
    older = [
        _result_row("RSA-1024", ref="r1024", vulnerable=True, key_size="1024", impact="High"),
        _result_row("RSA-2048", ref="r2048", vulnerable=True, key_size="2048", impact="Medium"),
        _result_row("AES-256-GCM", ref="aes", vulnerable=False, primitive="block-cipher"),
    ]
    newer = [older[0], older[2]]
    return fold([_scan(1, 20, older), _scan(2, 3, newer)])


def test_previously_seen_appendix_lists_the_resolved_asset_only(history_view):
    body = body_of(history_view)
    assert section_titles(body) == [
        "1 Summary",
        "2 Regulatory timeline",
        "3 Target families",
        "4 Per-asset roadmap",
        "5 Already quantum-safe and hybrid",
        "6 Previously seen, not in latest scan",
        "7 Notes",
    ]
    (table,) = roadmap_tables(body)
    assert [r[1] for r in data_rows(table)] == ["RSA-1024"]  # only the CURRENT one
    (seen,) = [
        t
        for t in tables(body)
        if header_texts(t)[:1] == ["Algorithm"] and "Last seen" in header_texts(t)
    ]
    rows = data_rows(seen)
    assert len(rows) == 1
    assert rows[0][0] == "RSA-2048"
    assert "2026-09-29" in rows[0][header_texts(seen).index("First seen")]
    assert "2026-09-29" in rows[0][header_texts(seen).index("Last seen")]
    assert rows[0][header_texts(seen).index("Scans")] == "1"


def test_previously_seen_assets_are_excluded_from_every_count(history_view):
    cards = kpi_cards(body_of(history_view))
    assert cards["Quantum-vulnerable"][0] == "1"
    assert cards["Distinct kinds"][0] == "1"
    assert cards["Quantum readiness"][0] == "50.0%"  # 1 safe / (1 safe + 1 vulnerable)
    (families,) = find_tables(body_of(history_view), FAMILY_HEADERS)
    assert data_rows(families) == [[FAMILY_PKE, "pke", "1", "1"]]


def test_previously_seen_title_and_explanation_reach_the_pdf(history_view):
    out = pdf_full_text(roadmap.build_pdf(history_view))
    assert has(out, "Previously seen, not in latest scan")
    assert has(out, "excluded from every count")


def test_previously_seen_appendix_is_absent_when_nothing_was_resolved(team_text):
    assert "Previously seen" not in team_text


def test_only_a_previously_seen_asset_still_reports_no_current_vulnerable():
    older = [_result_row("RSA-2048", ref="r2048", vulnerable=True, key_size="2048")]
    newer = [_result_row("AES-256-GCM", ref="aes", vulnerable=False, primitive="block-cipher")]
    body = body_of(fold([_scan(1, 20, older), _scan(2, 3, newer)]))
    titles = section_titles(body)
    assert "3 No quantum-vulnerable assets" in titles
    assert "5 Previously seen, not in latest scan" in titles


# =============================================================================================
# Layout: small blocks are never split across pages
# =============================================================================================
def test_small_tables_stay_whole_on_one_page(team_view, history_view):
    """A 5-row table must not strand its last row (and a repeated header) on the next page."""
    for view in (team_view, history_view):
        pages = pdf_pages_text(roadmap.build_pdf(view))
        levels = [p for p in pages if "NIST quantum security level" in p]
        assert len(levels) == 1
        assert "Total quantum-safe" in levels[0]
        timeline = [p for p in pages if "Source URL" in p]
        assert len(timeline) == 1
        assert URL_CNSA in timeline[0]
        assert has(timeline[0], TIMELINE_FOOTNOTE)
        families = [p for p in pages if "Target family" in p and "Primitive" in p]
        assert len(families) == 1
        notes = [p for p in pages if "Readiness = quantum-safe" in p]
        assert len(notes) == 1
        assert has(notes[0], "it does not sequence the migration")


# =============================================================================================
# Row cap
# =============================================================================================
def test_max_rows_caps_the_table_and_says_how_many_rows_were_omitted():
    assets = [algo(f"RSA-{2048 + i}", key_size=str(2048 + i), ident=f"x{i}") for i in range(12)]
    view = make_view(assets)
    body = body_of(view, max_rows=5)
    assert sum(len(data_rows(t)) for t in roadmap_tables(body)) == 5
    out = pdf_full_text(roadmap.build_pdf(view, max_rows=5))
    assert has(out, "7 further rows omitted")
    assert kpi_cards(body)["Quantum-vulnerable"][0] == "12"  # headline counts stay true


def test_a_single_omitted_row_uses_the_singular():
    assets = [algo(f"RSA-{2048 + i}", key_size=str(2048 + i), ident=f"x{i}") for i in range(4)]
    out = pdf_full_text(roadmap.build_pdf(make_view(assets), max_rows=3))
    assert has(out, "1 further row omitted")
    assert not has(out, "1 further rows omitted")


def test_no_omission_notice_when_everything_fits(team_text):
    assert "further row" not in team_text


def test_cap_applies_across_groups_in_print_order():
    body = body_of(make_view(mixed_assets()), max_rows=6)
    algorithms = [r[1] for t in roadmap_tables(body) for r in data_rows(t)]
    assert algorithms == [
        "RSA-2048", "RSA-1024", "DH-2048", "RSA-2048", "RSA-4096",  # all of pke
        "DSA-1024",  # first of signature
    ]  # fmt: skip
    assert len(group_headings(body)) == 2  # no heading for a group that prints no rows


# =============================================================================================
# Hostile input and hygiene
# =============================================================================================
HOSTILE = '<img src="file:///etc/hostname"><font color="red">x</font> &lt;b&gt; \x00 \U0001f600'


def test_hostile_strings_render_literally_and_stay_inert():
    clean = roadmap.build_pdf(make_view([algo("RSA-2048")]))
    hostile = algo(
        HOSTILE, source=HOSTILE, location=HOSTILE, family=HOSTILE, sized=HOSTILE, impact=HOSTILE
    )
    previous = algo(HOSTILE, current=False, source=HOSTILE, location=HOSTILE, ident="old")
    raw = roadmap.build_pdf(make_view([hostile, previous]))
    out = pdf_full_text(raw)
    assert raw.startswith(b"%PDF-")
    # printed as text; a narrow column may wrap it, hence the whitespace-insensitive match
    assert has(out, '<img src="file:///etc/hostname">')
    assert has(out, '<font color="red">x</font>')
    assert image_count(raw) == image_count(clean)
    assert link_count(raw) == link_count(clean)


def test_unusual_values_never_break_the_build():
    odd = [
        algo("RSA-2048", key_size=None, curve=None, bits=None, level=None, ident="n1"),
        algo("RSA-1024", key_size="not-a-number", ident="n2"),
        algo("X" * 5000, key_size="9" * 400, ident="n3"),
        algo("RSA-3072", first=None, last=None, scans=0, ident="n4"),
    ]
    odd[3].first_seen = None
    odd[3].last_seen = None
    raw = roadmap.build_pdf(make_view(odd))
    assert raw.startswith(b"%PDF-")
    assert not re.search(r"\bNone\b|\bnan\b", pdf_full_text(raw))


def test_no_foreign_product_text_or_canaries_reach_the_pdf(team_text):
    for needle in CANARIES:
        assert needle not in team_text, needle
    flat = norm(team_text)
    # the shell's CERT-In disclaimer legitimately names the guideline "SBOM, QBOM & CBOM, AIBOM
    # and HBOM v2.0"; that sentence is the only place the engine-internal name may appear
    disclaimer = norm(text.CERTIN_DISCLAIMER)
    assert disclaimer in flat
    flat = flat.replace(disclaimer, "")
    assert not re.search(r"\bAI BOM\b|\bFDA\b|\bHIPAA\b", flat)
    assert not re.search(r"clinithread|aibom", flat, re.IGNORECASE)
    assert not re.search(r"\bNone\b|\bnan\b", flat)


def test_timeline_and_labels_stay_inside_winansi(team_pdf):
    # the page text decodes as cp1252; an unmappable character would have become '?'
    out = pdf_full_text(team_pdf)
    assert "?" not in out


# =============================================================================================
# Styling parity with the existing CBOM PDF
# =============================================================================================
def test_tables_reuse_the_existing_report_palette(team_body, mixed_body):
    for body in (team_body, mixed_body):
        for table in roadmap_tables(body):
            commands = table._bkgrndcmds
            assert any(
                c[0] == "BACKGROUND" and c[1] == (0, 0) and c[2] == (-1, 0)
                and c[3] == COLOR_HEADER_SOFT
                for c in commands
            )  # fmt: skip
            assert any(
                c[0] == "ROWBACKGROUNDS" and list(c[3]) == [COLOR_WHITE, COLOR_ROW_ALT]
                for c in commands
            )
            assert table.repeatRows == 1
            outer = [c for c in table._linecmds if c[0] == "BOX"]
            assert outer
            assert (outer[0][3], outer[0][4]) == (0.6, COLOR_BORDER)  # (weight, colour)


def test_fonts_stay_within_what_the_existing_cbom_export_uses(team_pdf, tmp_path):
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    fixture = json.loads((FIXTURES / "cbom_export_scandata.json").read_text(encoding="utf-8"))
    existing = tmp_path / "existing_cbom_export.pdf"
    generate_pdf(fixture, str(existing))
    assert fonts_used(team_pdf) <= fonts_used(existing.read_bytes())


# =============================================================================================
# Performance
# =============================================================================================
def test_four_hundred_row_roadmap_builds_within_budget():
    assets = [
        algo(
            f"RSA-{1024 + i}",
            key_size=str(1024 + i),
            impact=("Critical", "High", "Medium", "Low")[i % 4],
            source=f"example.test/org/repo{i % 7} (main)",
            location=f"services/svc-{i}/crypto/keys.py",
            ident=f"p{i}",
        )
        for i in range(400)
    ]
    started = time.perf_counter()
    raw = roadmap.build_pdf(make_view(assets))
    elapsed = time.perf_counter() - started
    assert raw.startswith(b"%PDF-")
    assert elapsed < 15.0, f"400-row roadmap took {elapsed:.1f}s"


# =============================================================================================
# Static rules for the renderer module (plan 5.1 import rules, 5.5 escaping, no wall clock)
# =============================================================================================
def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def test_module_imports_only_stdlib_reportlab_and_the_allowed_backend_modules():
    allowed_backend = (
        "backend.utilities.pdf",
        "backend.utilities.dashboard.cbom_team_rollup",
    )
    seen: list[str] = []
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            names = [node.module or ""]
        else:
            continue
        for name in names:
            seen.append(name)
            root = name.split(".")[0]
            assert root in sys.stdlib_module_names or root in {"reportlab", "backend"}, name
            if root == "backend":
                assert name.startswith(allowed_backend), name
            assert not name.startswith(("backend.routers", "backend.utilities.ai")), name
    assert "backend.utilities.pdf.cbom_deliverable_common" in seen


def test_module_never_reads_the_wall_clock():
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"now", "utcnow", "today", "time", "monotonic"}, (
                f"line {node.lineno}: wall-clock read"
            )


def test_every_paragraph_in_the_module_is_built_from_pdf_text_or_pdf_multiline():
    calls = [
        node
        for node in ast.walk(_module_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Paragraph"
    ]
    assert calls, "expected the module to build its own paragraphs"
    for call in calls:
        first = call.args[0]
        assert isinstance(first, ast.Call) and isinstance(first.func, ast.Name), call.lineno
        assert first.func.id in {"pdf_text", "pdf_multiline"}, f"line {call.lineno}"


def test_module_has_no_network_llm_or_process_calls():
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    for token in ("bedrock", "anthropic", "openai", "boto3", "langchain", "requests", "httpx",
                  "subprocess", "socket"):  # fmt: skip
        assert token not in source, token
