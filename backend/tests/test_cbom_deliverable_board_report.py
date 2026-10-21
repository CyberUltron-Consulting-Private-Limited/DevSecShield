"""T-16: tests for the Board / IT Strategy Committee report renderer (plan 6.3, WP3f).

ORACLE RULE (plan 8.4): every expected number in this module is a literal taken from plan
Appendix B (hand / openssl-DER-fingerprint derived) or comes from a stdlib-only probe that reads
the committed raw fixture ``cbom_team_rollup_scans.json`` with plain loops.  NOTHING is
recomputed with the product aggregator or with the renderer under test.  The view under test is
built by feeding ``ScanHead`` objects and the fixture blobs into ``fold_scans``.

PDFs are inspected with a small pure-Python content-stream reader (ASCII85 + Flate), the same
approach as ``test_cbom_deliverable_common.py``, so the suite needs nothing beyond reportlab.
Text comes back in drawing order: table cells are drawn row by row, so a table row reads as its
cell texts one after the other.

Fixture scans (Appendix B): 1 payments v1 / 2 payments v2 (current) / 3 identity-gateway /
4 crypto-misuse-lab / 5 pqc-pilot / 6 cert-lifecycle-lab (zip) / 7 vendor-sdk-manifests /
8 legacy-billing (Tier B, reduced) / 9 failed / 10 queued / 11 started / 12 sbom_sca (other
type) / 13 success-but-empty / 14 other team.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import json
import re
import socket
import subprocess
import sys
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    ScanHead,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_board_report_pdf as board  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf.cbom_board_report_pdf import build_pdf  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # 17:58 IST; the fixture's frozen "now"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Scans whose data is CURRENT in the fixture (newest data-bearing scan of each of the 7 sources)
CURRENT_SCAN_IDS = (2, 3, 4, 5, 6, 7, 8)
# ... of which scan 8 (legacy-billing) is reduced fidelity and left out of compliance pooling
POOLED_SCAN_IDS = (2, 3, 4, 5, 6, 7)

H1 = "1. Executive summary"
H2 = "2. Material risks (top 10)"
H3 = "3. Quantum readiness"
H4 = "4. Certificate and key-material posture"
H5 = "5. Regulatory exposure"
H6 = "6. Remediation priorities"
H7 = "7. Post-quantum roadmap summary"
H8 = "8. Governance actions and decisions required"
H9 = "9. Sign-off"
HA = "Appendix A. Grade formula"
HB = "Appendix B. Scans included"
HC = "Appendix C. Disclaimers and limits"
HEADINGS = (H1, H2, H3, H4, H5, H6, H7, H8, H9, HA, HB, HC)

IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Appendix B, "Compliance pooled over 6 of 7 current scans": pass / fail / NBE / OOS / coverage,
# keyed by (framework label as printed, engine order).
EXPOSURE = (
    ("NIST SP 1800-38B", 13, 2, 5, 4, "86.7%"),
    ("NIST SP 800-57", 22, 8, 5, 7, "73.3%"),
    ("OMB M-23-02", 8, 2, 5, 3, "80.0%"),
    ("EU CRA", 7, 3, 5, 3, "70.0%"),
    ("EU DORA", 8, 2, 5, 3, "80.0%"),
    ("PCI-DSS 4.0", 11, 4, 5, 4, "73.3%"),
    ("FIPS 140-3", 11, 4, 5, 4, "73.3%"),
    ("BSI TR-02102", 10, 5, 5, 4, "66.7%"),
    ("NIST SP 1800-38C", 12, 3, 5, 4, "80.0%"),
    ("CNSA 2.0", 13, 2, 5, 4, "86.7%"),
    ("RBI FREE-AI (Protection)", 24, 6, 10, 8, "80.0%"),
    ("CERT-In CBOM (Guidelines v2.0)", 114, 4, 97, 43, "96.6%"),
    ("SEBI CSCRF (CBOM)", 36, 4, 50, 18, "90.0%"),
)

FINDING_LABELS = {
    "EXPIRED_CERTIFICATE": "Expired certificate",
    "HARDCODED_KEY": "Hard-coded key material",
    "QUANTUM_VULNERABLE": "Quantum-vulnerable public-key algorithm",
    "REUSED_NONCE": "Reused nonce",
    "SELF_SIGNED_LEAF": "Self-signed leaf certificate",
    "STATIC_IV": "Static or predictable IV",
    "WEAK_ALGORITHM": "Weak or deprecated algorithm",
    "WEAK_CERTIFICATE_KEY": "Certificate with an undersized key",
    "WEAK_CERTIFICATE_SIGNATURE": "Certificate signed with a weak hash",
    "WEAK_CIPHER_MODE": "Weak cipher mode (ECB)",
    "WEAK_PROTOCOL": "Weak protocol version",
    "WEAK_RNG": "Non-cryptographic random number generator",
}
# Appendix B, "Finding codes (current)": occurrences per code over the 68 current assets
FINDING_COUNTS = {
    "EXPIRED_CERTIFICATE": 1,
    "HARDCODED_KEY": 1,
    "QUANTUM_VULNERABLE": 5,
    "REUSED_NONCE": 1,
    "SELF_SIGNED_LEAF": 3,
    "STATIC_IV": 1,
    "WEAK_ALGORITHM": 8,
    "WEAK_CERTIFICATE_KEY": 3,
    "WEAK_CERTIFICATE_SIGNATURE": 3,
    "WEAK_CIPHER_MODE": 2,
    "WEAK_PROTOCOL": 2,
    "WEAK_RNG": 3,
}

# Reason texts printed instead of a grade
REASON_NO_SCANS = "No completed CBOM scans are available for this team."
REASON_NO_ASSETS = "The completed scans inventoried no cryptographic assets."
REASON_LEGACY = "Every latest scan is in legacy format and carries no finding data."


# ---------------------------------------------------------------------------------------------
# PDF inspection helpers (pure Python, no poppler; mirrors test_cbom_deliverable_common.py)
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


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def full_text(raw: bytes) -> str:
    return "\n".join(pdf_pages_text(raw))


def page_count(raw: bytes) -> int:
    return max(int(n) for n in re.findall(rb"/Count\s+(\d+)", raw))


def media_box(raw: bytes) -> tuple[float, float]:
    match = re.search(rb"/MediaBox\s*\[\s*0\s+0\s+([\d.]+)\s+([\d.]+)\s*\]", raw)
    assert match, "no MediaBox"
    return float(match.group(1)), float(match.group(2))


def info_field(raw: bytes, name: str) -> str | None:
    match = re.search(rb"/" + name.encode() + rb"\s*\(((?:\\.|[^\\()])*)\)", raw)
    return _unescape(b"(" + match.group(1) + b")") if match else None


def image_count(raw: bytes) -> int:
    """Embedded image XObjects (the brand logo in the page chrome is the only legitimate one)."""
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


# The page header / footer drawn on every page (not part of any section)
_CHROME = {
    norm(text)
    for text in (
        "ZERO SHIELD",
        "zeroshield.ai",
        "CBOM Board Report",
        "CONFIDENTIAL",
        "Zero Shield",
        "https://zeroshield.ai",
        "CBOM Board Report  \u00b7  Confidential",
    )
}
_PAGE_RE = re.compile(r"^Page \d+$")


def page_lines(raw: bytes) -> list[list[str]]:
    """Body lines of every page in drawing order, page chrome removed."""
    pages: list[list[str]] = []
    for page in pdf_pages_text(raw):
        kept = []
        for line in page.split("\n"):
            text = line.strip()
            if text and norm(text) not in _CHROME and not _PAGE_RE.match(text):
                kept.append(text)
        pages.append(kept)
    return pages


def clean_lines(raw: bytes) -> list[str]:
    """Body lines of the whole document in drawing order, page chrome removed."""
    return [line for page in page_lines(raw) for line in page]


def split_sections(lines: list[str]) -> dict[str, list[str]]:
    """``{heading: lines under it}``; fails unless every heading appears exactly once, in order."""
    positions = []
    for heading in HEADINGS:
        hits = [i for i, line in enumerate(lines) if line == heading]
        assert len(hits) == 1, f"heading {heading!r} found {len(hits)} times"
        positions.append(hits[0])
    assert positions == sorted(positions), "section headings are out of order"
    ends = [*positions[1:], len(lines)]
    return {
        heading: lines[start + 1 : end]
        for heading, start, end in zip(HEADINGS, positions, ends, strict=True)
    }


def value_after(block: list[str], label: str) -> str:
    assert label in block, f"{label!r} not found in {block[:12]}..."
    return block[block.index(label) + 1]


def joined(block: list[str]) -> str:
    return norm(" ".join(block))


# ---------------------------------------------------------------------------------------------
# Raw-fixture probes (plain loops, independent of the product aggregator)
# ---------------------------------------------------------------------------------------------
def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def scan_by_id(raw: dict, sid: int) -> dict:
    return next(s for s in raw["scans"] if s["id"] == sid)


def current_rows(raw: dict) -> list[dict]:
    return [row for sid in CURRENT_SCAN_IDS for row in scan_by_id(raw, sid)["scan_data"]["results"]]


def expected_top_titles(raw: dict, limit: int = 10) -> list[str]:
    """Plan 3.2: issue assets by impact rank, then risk_score desc (absent last), then name."""

    def key(row: dict):
        score = row.get("risk_score")
        return (
            IMPACT_RANK.get(row["impact"], 9),
            0 if score is not None else 1,
            -(score or 0.0),
            row["title"].casefold(),
        )

    issues = sorted((r for r in current_rows(raw) if r.get("finding_codes")), key=key)
    return [row["title"] for row in issues[:limit]]


def _source_of(scan: dict) -> tuple:
    meta = scan["scan_metadata"] or {}
    repo = (meta.get("repo_url") or "").lower().removesuffix(".git").rstrip("/")
    return (repo, (meta.get("branch") or "").lower()) if repo else ("title", scan["title"])


def expected_first_seen(raw: dict, title: str) -> str:
    """Date of the oldest successful scan of the SAME source that holds the same asset."""
    current = next(
        (sid, row)
        for sid in CURRENT_SCAN_IDS
        for row in scan_by_id(raw, sid)["scan_data"]["results"]
        if row["title"] == title and row.get("finding_codes")
    )
    source = _source_of(scan_by_id(raw, current[0]))
    stamps = [
        scan["created_at"][:10]
        for scan in raw["scans"]
        if scan["team_id"] == 1
        and scan["scan_type"] == "cbom"
        and scan["status"] == "success"
        and isinstance(scan["scan_data"], dict)
        and _source_of(scan) == source
        and any(
            r["title"] == title and r["location"] == current[1]["location"]
            for r in scan["scan_data"].get("results", [])
        )
    ]
    return min(stamps)


def expected_remediation(raw: dict) -> list[tuple[str, int, str]]:
    """``[(code, occurrences, highest impact)]`` by impact rank, then count desc, then label."""
    stats: dict[str, list] = {}
    for row in current_rows(raw):
        for code in row.get("finding_codes") or []:
            entry = stats.setdefault(code, [0, 9, ""])
            entry[0] += 1
            rank = IMPACT_RANK.get(row["impact"], 9)
            if rank < entry[1]:
                entry[1], entry[2] = rank, row["impact"]
    ordered = sorted(
        stats.items(),
        key=lambda item: (item[1][1], -item[1][0], FINDING_LABELS[item[0]].casefold(), item[0]),
    )
    return [(code, entry[0], entry[2]) for code, entry in ordered]


def outstanding_requirements(raw: dict) -> int:
    """Distinct (framework, requirement) pairs that some current full-fidelity scan could not
    evidence from the BOM (verdict not_bom_evidenceable)."""
    pairs = set()
    for sid in POOLED_SCAN_IDS:
        compliance = scan_by_id(raw, sid)["scan_data"]["cbom_compliance"]
        for framework, block in compliance.items():
            if not isinstance(block, dict):
                continue
            for requirement in block.get("requirements", []):
                if requirement["verdict"] == "not_bom_evidenceable":
                    pairs.add((framework, requirement["id"]))
    return len(pairs)


# ---------------------------------------------------------------------------------------------
# View builders
# ---------------------------------------------------------------------------------------------
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


def run_fold(scans, *, team_id=1, name="E2E Demo Team", now=NOW) -> TeamCbomView:
    blobs = {s["id"]: s["scan_data"] for s in scans}

    def load(ids):
        return {i: blobs[i] for i in ids if i in blobs}

    return fold_scans([_head(s) for s in scans], load, team_id=team_id, team_name=name, now=now)


def empty_view() -> TeamCbomView:
    return fold_scans([], lambda ids: {}, team_id=3, team_name="Empty Team", now=NOW)


def _row(title, *, asset_type="algorithm", impact="Low", codes=(), location="app.py", **extra):
    row = {
        "title": title,
        "asset_type": asset_type,
        "impact": impact,
        "finding_codes": list(codes),
        "location": location,
        "description": f"{title} finding text",
        "bom_ref": f"ref-{asset_type}-{title}-{location}",
        "quantum_vulnerable": False,
        "quantum_safe": True,
        "hybrid": False,
        "key_size": None,
    }
    row.update(extra)
    return row


def _cert_component(name, subject, *, not_after="2030-01-01T00:00:00Z"):
    props = {
        "crypto:assetType": "certificate",
        "crypto:subjectName": subject,
        "crypto:issuerName": subject,
        "crypto:notValidBefore": "2026-01-01T00:00:00Z",
        "crypto:notValidAfter": not_after,
        "crypto:signatureAlgorithm": "sha256WithRSAEncryption",
        "crypto:publicKeyAlgorithm": "rsaEncryption",
        "crypto:keySize": "2048",
        "crypto:selfSigned": "false",
        "crypto:isCertificateAuthority": "false",
        "discovery:source": name,
    }
    return {
        "bom-ref": f"ref-cert-{name}",
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"assetType": "certificate"},
        "properties": [{"name": k, "value": v} for k, v in props.items()],
    }


def _cert_row(name, **extra):
    """The results[] row that pairs with ``_cert_component(name, ...)`` (same bom-ref)."""
    row = _row(name, asset_type="certificate", location=name, **extra)
    row["bom_ref"] = f"ref-cert-{name}"
    row.update({"expired": False, "not_valid_after": "2030-01-01T00:00:00Z"})
    return row


def _compliance(verdicts):
    """A Tier-A ``cbom_compliance`` for one framework from ``{requirement id: verdict}``."""
    states = ("pass", "pass_with_evidence", "fail", "out_of_scope", "not_bom_evidenceable", "na")
    block = {state: sum(1 for v in verdicts.values() if v == state) for state in states}
    block["coverage"] = None
    block["requirements"] = [
        {"id": rid, "title": f"Title {rid}", "source": "Cite", "verdict": verdict,
         "attestable": verdict == "not_bom_evidenceable", "evidence": "e", "refs": []}
        for rid, verdict in verdicts.items()
    ]  # fmt: skip
    return {
        "nist_800_57": block,
        "disclaimer": "AIBOM-DISCLAIMER-MUST-NEVER-BE-PRINTED",
    }


def full_blob(rows=(), components=(), verdicts=None):
    """A Tier-A scan_data: typed rows, cbom_json, distributions and compliance."""
    return {
        "results": list(rows),
        "cbom_json": {"specVersion": "1.6", "components": list(components)},
        "cbom_distributions": {"pqc": {}},
        "cbom_compliance": _compliance(verdicts or {"KM-1": "pass"}),
    }


def synth(sid, data, *, age_days=1, title=None, repo=None, zip_title=None, status="success"):
    created = NOW - timedelta(days=age_days)
    if zip_title:
        meta = {"zip_file_used": True, "repo_url": None, "branch": None}
    else:
        meta = {"zip_file_used": False, "repo_url": repo or f"https://github.com/o/r{sid}",
                "branch": "main"}  # fmt: skip
    return {
        "id": sid, "team_id": 1, "scan_type": "cbom", "title": title or zip_title or f"scan-{sid}",
        "status": status, "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_updated": (created + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_metadata": meta, "scan_data": data,
    }  # fmt: skip


# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="session")
def raw():
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def view(raw):
    return run_fold(raw["scans"])


@pytest.fixture(scope="module")
def pdf(view):
    return build_pdf(view)


@pytest.fixture(scope="module")
def lines(pdf):
    return clean_lines(pdf)


@pytest.fixture(scope="module")
def sec(lines):
    return split_sections(lines)


@pytest.fixture(scope="module")
def empty_pdf():
    return build_pdf(empty_view())


# =============================================================================================
# Document shell
# =============================================================================================
def test_returns_a_valid_portrait_pdf(pdf):
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert 3 <= page_count(pdf) <= 10
    assert media_box(pdf) == (612.0, 792.0)


def test_metadata_and_document_id(pdf):
    title = info_field(pdf, "Title") or ""
    subject = info_field(pdf, "Subject") or ""
    assert "Board / IT Strategy Committee Regulatory & Executive Report" in title
    assert "E2E Demo Team" in title
    assert re.search(r"CBOM-D16-T1-20261019-[0-9a-f]{8}", subject), subject
    assert (info_field(pdf, "Author") or "") == authored.TOOL_NAME


def test_uses_its_own_report_meta_chrome(pdf):
    assert REPORT_META["cbom_board_report"]["footer_label"] == "CBOM Board Report"
    text = full_text(pdf)
    assert "CBOM Board Report" in text
    assert "SAST Report" not in text


def test_headings_present_once_and_in_order(sec):
    assert list(sec) == list(HEADINGS)


def test_no_heading_is_stranded_at_the_bottom_of_a_page(pdf, empty_pdf):
    for document in (pdf, empty_pdf):
        for number, page in enumerate(page_lines(document), start=1):
            assert page, f"page {number} has no body text"
            assert page[-1] not in HEADINGS, (number, page[-1])


def test_no_heading_is_stranded_whatever_the_length_of_the_content():
    """Sweep the remediation table (one row per finding code) so every section start slides
    through every position on the page; a heading must never end up alone at a page bottom."""
    for extra in range(0, 41, 2):
        rows = [_row("RC4", impact="High", codes=("WEAK_ALGORITHM",))]
        rows += [_row(f"X{i}", impact="Low", codes=(f"NEW_CODE_{i}",)) for i in range(extra)]
        out = build_pdf(run_fold([synth(1, full_blob(rows))]))
        for number, page in enumerate(page_lines(out), start=1):
            assert page[-1] not in HEADINGS, (extra, number, page[-1])


def test_front_matter_is_the_shared_shell(pdf, lines):
    text = joined(lines)
    assert "Scans: 8 included of 9 eligible" in text
    assert "excluded: 1 failed, 2 not completed, 1 without data" in text
    assert "Sources: 7" in text
    assert re.search(r"CBOM-D16-T1-20261019-[0-9a-f]{8}", text)
    assert "NO COMPLETED CBOM SCANS" not in text
    assert "REDUCED-FIDELITY DATA" not in text  # 7 of 8 scans are full fidelity


# =============================================================================================
# 1. Executive summary: KPIs equal Appendix B
# =============================================================================================
def test_executive_kpis_equal_appendix_b(sec):
    block = sec[H1]
    assert value_after(block, "Crypto assets") == "68"
    assert value_after(block, "Issue assets") == "29"
    assert value_after(block, "Sources") == "7"
    assert value_after(block, "Scans included") == "8"
    assert value_after(block, "Unique certificates") == "14"
    assert value_after(block, "Quantum readiness") == "86.5%"
    assert "Critical 1 \u00b7 High 23 \u00b7 Medium 5 \u00b7 Low 0" in joined(block)
    assert "of 9 eligible" in joined(block)


def test_grade_card_shows_grade_f_score_100_and_band(sec):
    block = sec[H1]
    start = block.index("Posture grade")
    assert block[start : start + 5] == ["Posture grade", "F", "Risk score", "100", "Critical risk"]
    # independent arithmetic: (10*1 + 5*23 + 2*5) = 135 weighted points; min(100, 4*135) = 100
    assert 10 * 1 + 5 * 23 + 2 * 5 == 135 and min(100, 4 * 135) == 100


def test_executive_sentences_carry_the_live_numbers(sec):
    text = joined(sec[H1])
    assert "7 sources and 8 completed scans" in text
    assert "68 cryptographic asset occurrences" in text
    assert "Findings were raised on 29 of them: Critical 1, High 23, Medium 5, Low 0." in text
    assert "Posture grade F (Critical risk, score 100 of 100)" in text
    assert "not a regulatory rating" in text
    assert "Quantum readiness is 86.5%: 5 of 37 gradeable algorithm occurrences" in text
    assert "1 certificate has expired and 1 expires within 90 days." in text


# =============================================================================================
# 2. Material risks
# =============================================================================================
def test_material_risks_pdf_lists_the_top_10_critical_first(raw, sec):
    block = sec[H2]
    expected = expected_top_titles(raw)
    assert expected[0] == "rsa1024_sha1.pem" and len(expected) == 10
    pointer = block.index("First seen") + 1  # last header cell
    chunks = []
    for rank in range(1, 11):
        at = next(i for i in range(pointer, len(block)) if block[i] == str(rank))
        chunks.append(at)
        pointer = at + 1
    assert "11" not in block
    bounds = [*chunks, len(block)]
    previous_rank = -1
    for index, title in enumerate(expected):
        chunk = block[bounds[index] + 1 : bounds[index + 1]]
        assert norm(title) in joined(chunk), (index + 1, title)
        chip = next(line for line in chunk if line in IMPACT_RANK)
        assert IMPACT_RANK[chip] >= previous_rank  # Critical first, never out of order
        previous_rank = IMPACT_RANK[chip]
    for index, title in enumerate(expected):  # first seen = the earliest scan of that source
        chunk = joined(block[bounds[index] + 1 : bounds[index + 1]])
        assert expected_first_seen(raw, title) in chunk, (index + 1, title)
    first = joined(block[bounds[0] + 1 : bounds[1]])
    assert "Critical" in first
    assert "Certificate with an undersized key" in first
    assert "Certificate signed with a weak hash" in first
    assert "github.com/e2e-demo/identity-gateway (main)" in first
    assert scan_by_id(raw, 3)["created_at"][:10] in first  # first seen = identity-gateway scan


def test_material_risks_helper_orders_like_the_plan(view, raw):
    risks = board.material_risks(view)
    assert [a.title for a in risks] == expected_top_titles(raw)
    assert all(a.current and a.finding_codes for a in risks)
    ranks = [IMPACT_RANK[a.impact] for a in risks]
    assert ranks == sorted(ranks)


def test_material_risks_note_counts_the_issue_assets(sec):
    text = joined(sec[H2])
    assert "Top 10 of 29 issue assets" in text


def test_material_risks_exclude_non_current_and_inventory_only_assets():
    clean = full_blob([_row("AES-256-GCM"), _row("SHA-256")])
    old = full_blob([_row("RC4", impact="High", codes=("WEAK_ALGORITHM",), bom_ref=None)])
    scans = [
        synth(1, old, age_days=9, repo="https://github.com/o/r"),
        synth(2, clean, age_days=1, repo="https://github.com/o/r"),  # RC4 resolved in the rescan
    ]
    risks = board.material_risks(run_fold(scans))
    assert risks == []  # RC4 is no longer in the source's current scan; the rest has no findings


def test_material_risks_stop_at_ten_and_report_the_rest():
    rows = [_row(f"RC{i:02d}", impact="Medium", codes=("WEAK_ALGORITHM",)) for i in range(25)]
    view = run_fold([synth(1, full_blob(rows))])
    assert len(board.material_risks(view)) == 10
    text = joined(split_sections(clean_lines(build_pdf(view)))[H2])
    assert "Top 10 of 25 issue assets" in text


# =============================================================================================
# 3. Quantum readiness
# =============================================================================================
def test_quantum_readiness_numbers(raw, sec):
    block = sec[H3]
    hybrid = sum(
        1
        for row in current_rows(raw)
        if row.get("asset_type") == "algorithm" and row.get("hybrid") is True
    )
    assert value_after(block, "Readiness") == "86.5%"
    assert value_after(block, "Quantum-vulnerable") == "5"
    assert value_after(block, "Quantum-safe") == "32"
    assert value_after(block, "Not gradeable") == "0"
    assert f"of which {hybrid} hybrid" in joined(block)


# =============================================================================================
# 4. Certificate and key-material posture
# =============================================================================================
def test_certificate_posture_counts(raw, sec):
    block = sec[H4]
    # Appendix B: 14 unique, bands 1 EXPIRED / 1 <=30 d / 12 VALID; SELF_SIGNED_LEAF 3.
    # Weak = WEAK_CERTIFICATE_KEY (3) union WEAK_CERTIFICATE_SIGNATURE (3), sharing exactly one
    # certificate (rsa1024_sha1.pem, the Critical one) => 5 distinct certificates.
    assert value_after(block, "Unique certificates in the estate") == "14"
    assert value_after(block, "Expired") == "1"
    assert value_after(block, "Expiring within 30 days") == "1"
    assert value_after(block, "Expiring in 31 to 90 days") == "0"
    assert value_after(block, "Valid for more than 90 days") == "12"
    assert value_after(block, "Validity date not recorded") == "0"
    assert value_after(block, "Weak signature hash or undersized key") == "5"
    assert value_after(block, "Self-signed leaf certificates") == "3"
    material = [r for r in current_rows(raw) if r.get("asset_type") == "related-crypto-material"]
    assert value_after(block, "Key and secret material occurrences") == str(len(material))
    flagged = sum(1 for r in material if r.get("finding_codes"))
    assert value_after(block, "With a key-misuse finding") == str(flagged)
    assert (len(material), flagged) == (12, 6)
    assert "as of 2026-10-19" in joined(block)


def test_certificate_bands_follow_the_view_date_not_the_wall_clock(raw):
    later = datetime(2026, 12, 31, 9, 0, tzinfo=UTC)  # soon-cert (notAfter 2026-11-08) expired
    block = split_sections(clean_lines(build_pdf(run_fold(raw["scans"], now=later))))[H4]
    assert value_after(block, "Expired") == "2"
    assert value_after(block, "Expiring within 30 days") == "0"
    assert "as of 2026-12-31" in joined(block)


# =============================================================================================
# 5. Regulatory exposure
# =============================================================================================
def test_regulatory_exposure_has_all_13_frameworks_with_pooled_numbers(sec):
    block = sec[H5]
    at = -1
    for label, passed, failed, nbe, oos, coverage in EXPOSURE:
        assert block.count(label) == 1, label
        index = block.index(label)
        assert index > at, f"{label} is out of engine order"
        at = index
        cells = block[index + 1 : index + 7]
        assert cells == [coverage, str(passed), str(failed), str(nbe), str(oos), "6"], label


def test_regulatory_exposure_uses_the_labels_the_plan_names(sec):
    block = sec[H5]
    for label in (
        "CERT-In CBOM (Guidelines v2.0)",
        "RBI FREE-AI (Protection)",
        "SEBI CSCRF (CBOM)",
    ):
        assert label in block


def test_pooling_basis_sentence(sec):
    assert "6 of 7 sources pooled (1 legacy excluded)" in joined(sec[H5])


def test_rbi_mapping_note_present_and_no_q_safe_anywhere(pdf, sec):
    assert norm(authored.RBI_MAPPING_NOTE) in joined(sec[H5])
    assert "q-safe" not in full_text(pdf).lower()


def test_coverage_definition_is_printed(sec):
    assert norm(authored.METHOD_COVERAGE) in joined(sec[H5])


def test_pass_column_includes_requirements_passed_on_evidence():
    # hand-computed: 1 pass + 1 pass_with_evidence + 1 fail => Pass 2, Fail 1, coverage 2/3
    verdicts = {"R1": "pass", "R2": "pass_with_evidence", "R3": "fail", "R4": "out_of_scope"}
    data = full_blob([_row("AES-256-GCM")], verdicts=verdicts)
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, data)]))))[H5]
    index = block.index("NIST SP 800-57")
    assert block[index + 1 : index + 7] == ["66.7%", "2", "1", "0", "1", "1"]


def test_coverage_is_na_when_nothing_passed_or_failed():
    data = full_blob([_row("AES-256-GCM")], verdicts={"R1": "not_bom_evidenceable"})
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, data)]))))[H5]
    index = block.index("NIST SP 800-57")
    assert block[index + 1 : index + 7] == ["n/a", "0", "0", "1", "0", "1"]


def test_legacy_only_team_reports_that_no_compliance_could_be_pooled():
    legacy = {"results": [{"algorithm_name": "RSA", "algorithm_type": "pke", "impact": "High",
                           "location": "a.py", "quantum_safe": False}]}  # fmt: skip
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, legacy)]))))[H5]
    text = joined(block)
    assert "0 of 1 sources pooled (1 legacy excluded)" in text
    assert "NIST SP 800-57" not in block


def test_unknown_framework_key_degrades_to_a_readable_label():
    data = full_blob([_row("AES-256-GCM")])
    data["cbom_compliance"]["zz_future_framework"] = data["cbom_compliance"]["nist_800_57"]
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, data)]))))[H5]
    assert "zz future framework" in block
    assert "NIST SP 800-57" in block


# =============================================================================================
# 6. Remediation priorities
# =============================================================================================
def test_remediation_priorities_are_ordered_and_counted(raw, sec):
    block = sec[H6]
    expected = expected_remediation(raw)
    assert [code for code, _count, _impact in expected] == [
        "WEAK_CERTIFICATE_SIGNATURE",
        "WEAK_CERTIFICATE_KEY",
        *[c for c, _n, _i in expected[2:]],
    ]
    assert {code: n for code, n, _i in expected} == FINDING_COUNTS  # Appendix B
    at = -1
    for position, (code, count, impact) in enumerate(expected):
        label = FINDING_LABELS[code]
        assert block.count(label) == 1, label
        index = block.index(label)
        assert index > at, f"{label} is out of order"
        at = index
        assert block[index + 1] == str(count), label
        assert block[index + 2] == impact, label
        end = (
            block.index(FINDING_LABELS[expected[position + 1][0]])
            if position + 1 < len(expected)
            else len(block)
        )
        action = norm(authored.finding_action(code))
        assert action in joined(block[index + 3 : end]), code


def test_every_authored_action_is_printed_whole():
    codes = sorted(authored.FINDING_ACTIONS)
    assert len(codes) >= 16
    rows = [_row(f"asset-{i}", impact="High", codes=(code,)) for i, code in enumerate(codes)]
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, full_blob(rows))]))))[H6]
    text = joined(block)
    for code in codes:
        assert norm(authored.FINDING_ACTIONS[code]) in text, code
        assert authored.FINDING_LABELS[code] in block, code
    assert "\u2026" not in text


def test_unknown_finding_code_gets_a_label_and_the_generic_action():
    rows = [_row("X1", impact="High", codes=("NEW_UNSEEN_CODE",))]
    block = split_sections(clean_lines(build_pdf(run_fold([synth(1, full_blob(rows))]))))[H6]
    assert "New unseen code" in block
    assert norm(authored.GENERIC_FINDING_ACTION) in joined(block)


# =============================================================================================
# 7. Post-quantum roadmap summary
# =============================================================================================
def test_pqc_summary_families_and_timeline(sec):
    block = sec[H7]
    family = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    index = block.index(family)
    # Appendix B: 5 quantum-vulnerable occurrences (payments 2, pqc-pilot 1, legacy 2) in 3 sources
    assert block[index + 1 : index + 3] == ["5", "3"]
    text = joined(block)
    for when, status in (
        ("Aug 2024", "Final"),
        ("Nov 2024", "Draft"),
        ("After 2030", "Draft"),
        ("After 2035", "Draft"),
        ("2025 to 2035", "Advisory"),
    ):
        assert when in block, when
        assert status in block, status
    for row in authored.PQC_TIMELINE_ROWS:
        assert norm(row.milestone) in text
    assert norm(authored.PQC_TIMELINE_FOOTNOTE) in text
    assert "initial public draft" in text
    assert "not a migration sequence" in text.lower() or "PQC Migration Roadmap" in text


def test_pqc_summary_for_a_team_without_vulnerable_assets():
    view = run_fold([synth(1, full_blob([_row("AES-256-GCM")]))])
    block = split_sections(clean_lines(build_pdf(view)))[H7]
    assert norm(authored.PQC_NO_VULNERABLE_TEXT) in joined(block)
    assert "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)" not in block  # no family row is invented
    assert "Aug 2024" in block  # the regulatory timeline is static and always printed


# =============================================================================================
# 8. Governance actions
# =============================================================================================
def test_governance_actions_carry_live_metrics(raw, sec):
    block = sec[H8]
    attestations = outstanding_requirements(raw)
    assert attestations == 48
    expected_rows = [
        (
            "Assign an accountable owner to each of the 14 unique certificates in the estate.",
            "14 unique certificates",
        ),
        (
            f"Collect attestation evidence for the {attestations} requirements that a bill of "
            "materials cannot evidence.",
            f"{attestations} requirements outstanding",
        ),
        (
            "Approve a post-quantum migration plan covering the 5 quantum-vulnerable asset "
            "occurrences.",
            "5 quantum-vulnerable occurrences",
        ),
        (
            "Re-scan the 1 source whose latest scan is in legacy format.",
            "1 source in legacy format",
        ),
    ]
    start = block.index("Decision (assessor)") + 1
    body = joined(block[start:])
    assert body.startswith(" ".join(f"{a} {m}" for a, m in expected_rows)), body
    for header in ("Action", "Live metric", "Owner (assessor)", "Due (assessor)"):
        assert header in joined(block[:start])


def test_governance_rows_leave_the_manual_cells_blank(view):
    rows = board.governance_rows(view)
    assert len(rows) == 4
    for row in rows:
        assert len(row) == 5
        assert row[0] and row[1]
        assert row[2:] == ["", "", ""]  # owner, due date, decision: the board's to fill


def test_governance_metrics_helper(view, raw):
    metrics = board.governance_metrics(view)
    assert (metrics.unique_certs, metrics.quantum_vulnerable, metrics.legacy_scans) == (14, 5, 1)
    assert metrics.attestations_outstanding == outstanding_requirements(raw)


def test_governance_wording_is_singular_for_one():
    comp = _cert_component("only.pem", "only.test")
    view = run_fold(
        [synth(1, full_blob([_cert_row("only.pem")], [comp], {"KM-1": "not_bom_evidenceable"}))]
    )
    text = " ".join(" ".join(row) for row in board.governance_rows(view))
    assert "1 unique certificate in the estate" in text
    assert "1 requirement that a bill of materials" in text
    assert "1 unique certificates" not in text and "1 requirements" not in text


# =============================================================================================
# 9. Sign-off, appendices
# =============================================================================================
def test_signoff_block_is_blank(sec):
    expected = (
        "To be completed by assessor Sign-off Name Role Date Signature "
        "Prepared by CISO review Board IT Strategy Committee approval"
    )
    assert joined(sec[H9]) == expected


def test_appendix_a_prints_the_formula_and_the_worked_calculation(sec):
    block = sec[HA]
    text = joined(block)
    assert norm(authored.GRADE_FORMULA) in text
    assert norm(authored.GRADE_INPUT) in text
    assert norm(authored.GRADE_DISCLAIMER) in text
    assert "10 x Critical + 5 x High + 2 x Medium + 1 x Low" in text
    assert "Weighted points: 135. Score = min(100, 4 x 135) = 100. Grade F (Critical risk)." in text
    for level, count, weight, points in (
        ("Critical", "1", "10", "10"),
        ("High", "23", "5", "115"),
        ("Medium", "5", "2", "10"),
        ("Low", "0", "1", "0"),
    ):
        at = block.index(level)
        assert block[at : at + 4] == [level, count, weight, points], level


def test_appendix_b_lists_exactly_the_included_scans(raw, sec):
    block = sec[HB]
    marks = [i for i, line in enumerate(block) if re.fullmatch(r"#\d+", line)]
    ids = sorted(int(block[i][1:]) for i in marks)
    assert ids == [1, 2, 3, 4, 5, 6, 7, 8]  # 9 failed, 10/11 not completed, 13 no data: absent
    bounds = [*marks, len(block)]
    chunks = {}
    for start, end in zip(bounds, bounds[1:], strict=False):
        chunks[int(block[start][1:])] = joined(block[start + 1 : end])
    for sid in ids:
        assert scan_by_id(raw, sid)["created_at"][:10] in chunks[sid], sid
    assert "Current" in chunks[2] and "History" in chunks[1]
    assert "Legacy format" in chunks[8] and "Full" in chunks[3]
    # scans 1 and 2 are one source: both rows carry the source's current label, not scan 1's
    assert block.count("github.com/e2e-demo/payments-service (main)") == 2
    assert "E2E-Demo" not in joined(block)
    # grouped by source, newest first inside a source: #2 (7 days old) before #1 (21 days old)
    assert [block[i] for i in marks].index("#2") + 1 == [block[i] for i in marks].index("#1")
    # roles: exactly one Current row per source (7 sources)
    assert sum(1 for line in block if line == "Current") == 7


def test_appendix_c_repeats_the_disclaimers_and_limits(lines, sec):
    text = joined(sec[HC])
    front = joined(lines[: lines.index(HA)])
    for paragraph in authored.DISCLAIMER_PARAGRAPHS:
        assert norm(paragraph) in text
        assert norm(paragraph) in front  # also in the shared disclaimer box on page 1
    assert norm(authored.GRADE_DISCLAIMER) in text
    assert norm(authored.PQC_TIMELINE_FOOTNOTE) in text


# =============================================================================================
# Text hygiene
# =============================================================================================
def test_no_forbidden_or_placeholder_text(pdf):
    text = full_text(pdf)
    for forbidden in ("AI BOM", "HIPAA", "clinithread", "AIBOM-DISCLAIMER-MUST-NEVER-BE-PRINTED"):
        assert forbidden.lower() not in text.lower(), forbidden
    assert not re.search(r"\bFDA\b", text)
    assert not re.search(r"\b(None|nan|null|undefined)\b", text)
    assert "{" not in text and "}" not in text  # no unformatted template field
    assert "&amp;" not in text and "&lt;" not in text and "<br" not in text  # no double escaping


def test_authored_text_is_not_clamped(lines):
    text = joined(lines)  # page chrome removed, so a paragraph that crosses a page is whole again
    assert "\u2026" not in text  # the sanitiser's ellipsis would mark a cut sentence
    for paragraph in (authored.METHOD_COVERAGE, authored.GRADE_FORMULA, authored.RBI_MAPPING_NOTE):
        assert norm(paragraph) in text


# =============================================================================================
# NOT ASSESSED: never a grade A / "Low risk" without evidence (plan F-06, D-03)
# =============================================================================================
_BAND_WORDS = ("Low risk", "Moderate risk", "Elevated risk", "High risk", "Critical risk")


def _assert_not_assessed(raw_pdf: bytes, reason: str) -> None:
    text = full_text(raw_pdf)
    lines = clean_lines(raw_pdf)
    block = split_sections(lines)[H1]
    start = block.index("Posture grade")
    assert block[start : start + 4] == ["Posture grade", "NOT ASSESSED", "Risk score", "n/a"]
    assert reason in joined(block)
    for band in _BAND_WORDS:
        assert band not in text, band
    assert "A" not in block  # no grade-A letter box
    assert "Grade A" not in text and "grade A" not in text
    appendix = joined(split_sections(lines)[HA])
    assert "No grade was assigned" in appendix and reason in appendix
    assert "Weighted points:" not in appendix  # no worked calculation that could imply 0 = A


def test_empty_team_is_not_assessed(empty_pdf):
    _assert_not_assessed(empty_pdf, REASON_NO_SCANS)
    text = full_text(empty_pdf)
    assert "NO COMPLETED CBOM SCANS" in text


def test_empty_team_keeps_every_section_and_prints_no_numbers_as_findings(empty_pdf):
    lines = clean_lines(empty_pdf)
    sections = split_sections(lines)
    assert value_after(sections[H1], "Quantum readiness") == "n/a"
    assert value_after(sections[H1], "Crypto assets") == "0"
    assert value_after(sections[H1], "Scans included") == "0"
    assert joined(sections[H9]).endswith("Board IT Strategy Committee approval")
    for framework in ("NIST SP 800-57", "CERT-In CBOM (Guidelines v2.0)"):
        assert framework not in sections[H5]  # nothing to pool, nothing invented
    assert not [line for line in sections[H2] if line in IMPACT_RANK]


def test_only_failed_and_queued_scans_is_not_assessed():
    scans = [
        synth(1, {"results": [{"title": "FAILED-CANARY"}]}, status="failure"),
        synth(2, {}, status="NOT_STARTED"),
    ]
    out = build_pdf(run_fold(scans))
    _assert_not_assessed(out, REASON_NO_SCANS)
    assert "FAILED-CANARY" not in full_text(out)


def test_completed_scans_without_any_asset_are_not_assessed():
    manifest_only = full_blob([], [])  # clean repo / manifest-only repo: valid scan, 0 assets
    view = run_fold([synth(1, manifest_only)])
    assert view.included == 1 and view.asset_occurrences == 0
    _assert_not_assessed(build_pdf(view), REASON_NO_ASSETS)


def test_legacy_only_scans_without_finding_data_are_not_assessed():
    legacy = {
        "results": [
            {
                "algorithm_name": "RSA",
                "algorithm_type": "pke",
                "impact": "High",
                "location": "a.py",
                "key_size": 1024,
                "quantum_safe": False,
            },
        ]  # fmt: skip
    }
    view = run_fold([synth(1, legacy)])
    assert view.included == 1 and view.asset_occurrences == 1 and not view.issue_by_impact
    _assert_not_assessed(build_pdf(view), REASON_LEGACY)


def test_sections_for_an_empty_team_say_there_is_no_data(empty_pdf):
    sections = split_sections(clean_lines(empty_pdf))
    for heading in (H2, H3, H4, H5, H6, H7, H8):
        assert "No data: no completed CBOM scans." in joined(sections[heading]), heading
    assert "Aug 2024" in sections[H7]  # the regulatory timeline does not depend on scan data
    assert norm(authored.PQC_NO_VULNERABLE_TEXT) not in joined(sections[H7])  # nothing was scanned


def test_sections_for_a_clean_inventory_say_there_is_nothing_to_fix():
    view = run_fold([synth(1, full_blob([_row("AES-256-GCM"), _row("SHA-256")]))])
    sections = split_sections(clean_lines(build_pdf(view)))
    assert "No current asset carries a finding." in joined(sections[H2])
    assert "No findings to remediate." in joined(sections[H6])
    assert value_after(sections[H1], "Issue assets") == "0"
    assert value_after(sections[H1], "Quantum readiness") == "100.0%"


def test_resolved_findings_and_certificates_do_not_count_in_the_headline_or_the_grade():
    gone = _cert_component("gone.pem", "gone.test")
    family = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    old_rows = [
        *[_row(f"RC{i}", impact="High", codes=("WEAK_ALGORITHM",)) for i in range(3)],
        _row("RSA-2048", quantum_vulnerable=True, quantum_safe=False, pqc_migration_target=family),
        _row("old-iv", asset_type="related-crypto-material", impact="High", codes=("STATIC_IV",)),
    ]
    old = full_blob([*old_rows, _row("AES-256-GCM"), _cert_row("gone.pem")], [gone])
    new = full_blob([_row("AES-256-GCM"), *[_row(f"SHA-{i}") for i in range(5)]])
    repo = "https://github.com/o/r"
    view = run_fold([synth(1, old, age_days=9, repo=repo), synth(2, new, age_days=1, repo=repo)])
    sections = split_sections(clean_lines(build_pdf(view)))
    block = sections[H1]
    assert value_after(block, "Scans included") == "2"  # both scans are in the history window
    assert value_after(block, "Sources") == "1"
    assert value_after(block, "Crypto assets") == "6"  # the current scan only: AES + 5 x SHA
    assert value_after(block, "Issue assets") == "0"
    assert value_after(block, "Unique certificates") == "0"  # gone.pem left the estate
    start = block.index("Posture grade")
    assert block[start : start + 5] == ["Posture grade", "A", "Risk score", "0", "Low risk"]
    assert "No findings to remediate." in joined(sections[H6])
    assert "No current asset carries a finding." in joined(sections[H2])
    assert value_after(sections[H4], "Unique certificates in the estate") == "0"
    assert value_after(sections[H4], "Key and secret material occurrences") == "0"
    assert "0 unique certificates" in joined(sections[H8])
    assert value_after(sections[H3], "Quantum-vulnerable") == "0"
    assert family not in sections[H7]  # the RSA-2048 left the source with the rescan
    assert norm(authored.PQC_NO_VULNERABLE_TEXT) in joined(sections[H7])


def test_a_clean_inventory_earns_grade_a_only_because_assets_were_assessed():
    # six Low inventory-only assets: were they graded as issues they would weigh 6 points => B
    view = run_fold([synth(1, full_blob([_row(f"SHA-{i}") for i in range(6)]))])
    posture = board.posture_grade(view)
    assert (posture.assessed, posture.grade, posture.score, posture.band) == (
        True,
        "A",
        0,
        "Low risk",
    )
    block = split_sections(clean_lines(build_pdf(view)))[H1]
    start = block.index("Posture grade")
    assert block[start : start + 5] == ["Posture grade", "A", "Risk score", "0", "Low risk"]


def test_posture_grade_helper_matches_the_documented_formula(view):
    posture = board.posture_grade(view)
    assert posture.assessed and (posture.grade, posture.score) == ("F", 100)
    assert posture.band == "Critical risk"
    assert (posture.critical, posture.high, posture.medium, posture.low) == (1, 23, 5, 0)
    assert posture.weighted_points == 135
    none = board.posture_grade(empty_view())
    assert (none.assessed, none.grade, none.score, none.band) == (
        False,
        "NOT ASSESSED",
        None,
        None,
    )
    assert none.reason == REASON_NO_SCANS


# =============================================================================================
# Robustness, determinism, guards
# =============================================================================================
def test_hostile_strings_render_literally(pdf):
    hostile = '<img src="file:///etc/hostname"> <font color="red">X</font> &lt;b&gt;'
    rows = [
        _row(hostile, impact="High", codes=("WEAK_ALGORITHM",), location=hostile),
        _row("ok", impact="Low"),
    ]
    scans = [synth(1, full_blob(rows), zip_title=hostile)]
    out = build_pdf(run_fold(scans))
    text = full_text(out)
    squeeze = re.compile(r"\s+")
    assert squeeze.sub("", hostile) in squeeze.sub("", text)  # printed as text, not as markup
    assert image_count(out) == image_count(pdf)  # no <img> was honoured
    uris = re.findall(rb"/URI\s*\(([^)]*)\)", out)
    assert all(uri.startswith(b"https://zeroshield.ai") for uri in uris)  # only the brand link
    assert b"file:///etc/hostname" not in b"".join(uris)
    assert "&amp;lt;" not in text


def test_non_latin_and_control_characters_do_not_break_the_build():
    nasty = "\u0930\u0939\u0938\u094d\u092f\x00\x07 \u2265 \U0001f512 \u202eRTL"
    rows = [_row(nasty, impact="High", codes=("WEAK_ALGORITHM",), location=nasty)]
    out = build_pdf(run_fold([synth(1, full_blob(rows), title=nasty)]))
    assert out.startswith(b"%PDF-")
    assert ">=" in full_text(out)  # the WinAnsi fold, not a missing glyph


def test_a_very_long_name_never_breaks_a_table_row():
    rows = [_row("W" * 4000, impact="High", codes=("WEAK_ALGORITHM",), location="L" * 4000)]
    out = build_pdf(run_fold([synth(1, full_blob(rows), title="T" * 4000)]))
    assert out.startswith(b"%PDF-")


def test_unknown_impact_and_missing_optional_fields_are_tolerated():
    rows = [
        _row("odd", impact="Catastrophic", codes=("WEAK_ALGORITHM",)),
        _row("bare", impact="Low", codes=("WEAK_RNG",), bom_ref=None),
    ]
    rows[1].pop("description")
    out = build_pdf(run_fold([synth(1, full_blob(rows))]))
    text = full_text(out)
    assert "Catastrophic" in text  # kept verbatim, ranked last
    assert not re.search(r"\b(None|nan)\b", text)


def test_build_is_deterministic_and_does_not_mutate_the_view(view):
    before = copy.deepcopy(view)
    first, second = build_pdf(view), build_pdf(view)
    assert first == second
    assert view == before


def test_build_makes_no_network_or_process_calls(view, monkeypatch):
    def deny(*_args, **_kwargs):
        raise AssertionError("network/process access attempted")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(subprocess, "Popen", deny)
    assert build_pdf(view).startswith(b"%PDF-")


def test_two_hundred_scans_build_quickly():
    scans = []
    for sid in range(1, 201):
        rows = [
            _row(f"A{sid}-{n}", impact=("High", "Medium", "Low")[n % 3],
                 codes=("WEAK_ALGORITHM",) if n % 3 == 0 else (), location=f"f{n}.py")
            for n in range(15)
        ]  # fmt: skip
        repo = f"https://h/o/r{sid % 40}"
        scans.append(synth(sid, full_blob(rows), age_days=200 - sid, repo=repo))
    view = run_fold(scans)
    started = time.perf_counter()
    out = build_pdf(view)
    elapsed = time.perf_counter() - started
    assert out.startswith(b"%PDF-")
    assert elapsed < 8.0, f"{elapsed:.1f}s"
    block = split_sections(clean_lines(out))[HB]
    assert "further scans omitted" in joined(block)  # appendix B is capped


# ---------------------------------------------------------------------------------------------
# Static guards (plan 8.4 / 6.5): the module imports, clock use and escaping rule
# ---------------------------------------------------------------------------------------------
_SOURCE = Path(board.__file__).read_text(encoding="utf-8")
_TREE = ast.parse(_SOURCE)
_ALLOWED_ROOTS = set(sys.stdlib_module_names) | {"reportlab", "backend"}
_FORBIDDEN_ROOTS = {
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "openai", "anthropic",
    "requests", "httpx", "urllib3", "aiohttp", "socket", "subprocess", "smtplib", "ftplib",
    "http", "urllib", "pymongo", "celery", "kombu", "msal",
}  # fmt: skip


def _imported_modules() -> list[str]:
    found = []
    for node in ast.walk(_TREE):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append(node.module)
    return found


def test_imports_are_reportlab_stdlib_and_the_two_backend_packages_only():
    for module in _imported_modules():
        root = module.split(".")[0]
        assert root in _ALLOWED_ROOTS, module
        assert root not in _FORBIDDEN_ROOTS, module
        if root == "backend":
            assert module.startswith("backend.utilities.pdf") or (
                module == "backend.utilities.dashboard.cbom_team_rollup"
            ), module
            assert "backend.utilities.ai" not in module and "routers" not in module
    lowered = _SOURCE.lower()
    for token in ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai"):
        assert token not in lowered, token


def test_the_module_never_reads_the_wall_clock():
    banned = {("datetime", "now"), ("datetime", "utcnow"), ("date", "today"), ("time", "time")}
    for node in ast.walk(_TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name):
                assert (owner.id, node.func.attr) not in banned, ast.dump(node)
    assert "time.time" not in _SOURCE and ".now(" not in _SOURCE and ".today(" not in _SOURCE


def test_every_paragraph_is_built_from_escaped_text():
    """The pdf_text rule: Paragraph(...) is only ever fed pdf_text / pdf_multiline / escape_html."""
    allowed = {"pdf_text", "pdf_multiline", "escape_html"}
    checked = 0
    for node in ast.walk(_TREE):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Paragraph":
            first = node.args[0]
            assert isinstance(first, ast.Call) and getattr(first.func, "id", None) in allowed, (
                ast.get_source_segment(_SOURCE, node)
            )
            checked += 1
    assert checked > 0


def test_public_surface():
    assert callable(build_pdf)
    assert "build_pdf" in board.__all__
