"""T-7: tests for the Certificate Estate Register renderer (WP3c, plan 5.4 / 6.3).

``backend.utilities.pdf.cbom_cert_register_pdf.build_pdf(view)`` renders deliverable #7, a
landscape PDF with one row per UNIQUE certificate of the team-wide roll-up.

ORACLE RULE (plan 8.4): the expected numbers and names below are literals taken from plan
Appendix B (hand / openssl-fingerprint derived) and from the committed fixture
``cbom_team_rollup_scans.json`` read as plain JSON (14 unique certificates, one EXPIRED, one
``<=30 DAYS`` at +20 d, the 4-scan duplicate ``synthetic-crypto-app.test``, the chain
``chain-leaf.crt`` -> ``chain-root.crt``).  Nothing is recomputed with the product aggregator
except building the view the renderer receives.

No DB, network, language model or wall clock: views are folded from the fixture (or from small
hand-made run-objects) with an injected ``now``.  PDFs are inspected with a small pure-Python
content-stream reader, so the suite needs nothing beyond ``reportlab``.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import json
import random
import re
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from reportlab.pdfbase.pdfmetrics import stringWidth

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    EXPIRED,
    LE_30,
    LE_90,
    UNKNOWN,
    VALID,
    CertAgg,
    ExpiryBand,
    ScanHead,
    SourceAgg,
    TeamCbomView,
    fold_scans,
)
from backend.utilities.pdf import cbom_cert_register_pdf as register  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf.cbom_cert_register_pdf import (  # noqa: E402
    MAX_REGISTER_ROWS,
    build_pdf,
    previously_seen,
    register_rows,
)
from backend.utilities.pdf.report_branding import (  # noqa: E402
    PILL_CRITICAL_BG,
    PILL_HIGH_BG,
    PILL_LOW_BG,
    PILL_MEDIUM_BG,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # the fixture's frozen "now" (17:58 IST)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
LANDSCAPE = (792.0, 612.0)

# Register order for the Appendix-B team view at NOW: expiry urgency first (EXPIRED, <=30 d,
# <=90 d), then impact (Critical first), then valid-to ascending, then subject.
EXPECTED_ORDER = [
    "expired-api.e2e.test",  # EXPIRED (-35 d), High
    "expiring-soon.e2e.test",  # <=30 DAYS (+20 d), Medium
    "legacy-internal.test",  # Critical: rsa1024_sha1.pem (RSA-1024 + SHA-1)
    "weak-rsa1024-ca.test",  # High, valid to 2036-06-28
    "weak-sha1-ca.test",  # High, valid to 2036-06-28
    "weak-keysize.test",  # High, valid to 2081-04-03
    "weak-sig.test",  # High, valid to 2081-04-03
    "selfsigned-leaf.test",  # Medium
    "synthetic-crypto-app.test",  # Low, valid to 2027-06-29
    "chain.leaf.test",  # Low, valid to 2036-06-28
    "DevSecShield Test Root CA",
    "ec-p256-ca.test",
    "ecdsa-service.test",  # Low, valid to 2046-06-26
    "strong-control.test",  # Low, valid to 2081-04-03
]
CANARIES = (
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
)
SECTION_RE = re.compile(r"^\d+\. [A-Z]")


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


def page_texts(raw: bytes) -> list[list[str]]:
    """Text lines of every page content stream (one list per page; a cell line is one entry)."""
    pages: list[list[str]] = []
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
        pages.append(lines)
    return pages


def text_lines(raw: bytes) -> list[str]:
    return [line for page in page_texts(raw) for line in page]


def full_text(raw: bytes) -> str:
    return "\n".join(text_lines(raw))


def squash(value: str) -> str:
    """Remove every whitespace character: wrapped words and cells compare as one string."""
    return re.sub(r"\s+", "", value)


def norm(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


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


def fonts_used(raw: bytes) -> set[str]:
    return {m.decode() for m in re.findall(rb"/BaseFont\s*/([A-Za-z0-9\-]+)", raw)}


def section_lines(lines: list[str], number: int) -> list[str]:
    """Lines from the ``<number>. `` heading up to the next section heading."""
    start = next((i for i, line in enumerate(lines) if line.startswith(f"{number}. ")), None)
    assert start is not None, f"section {number} heading not found"
    end = next((i for i in range(start + 1, len(lines)) if SECTION_RE.match(lines[i])), len(lines))
    return lines[start:end]


def find_row_start(lines: list[str], number: int, subject: str, cursor: int = 0) -> int | None:
    """Index of the ``#`` cell of register row ``number`` (followed by its subject), or None."""
    want = squash(subject)[:12]
    for i in range(cursor, len(lines) - 2):
        if lines[i].strip() == str(number) and squash("".join(lines[i + 1 : i + 3])).startswith(
            want
        ):
            return i
    return None


def register_segments(lines: list[str], subjects: list[str]) -> list[list[str]]:
    """One list of text lines per register row, anchored on the ``#`` cell and the subject."""
    starts: list[int] = []
    cursor = 0
    for number, subject in enumerate(subjects, start=1):
        found = find_row_start(lines, number, subject, cursor)
        if found is None:
            pytest.fail(f"register row {number} ({subject!r}) was not found in the PDF text")
        starts.append(found)
        cursor = found + 1
    stop = next(
        (i for i in range(starts[-1] + 1, len(lines)) if SECTION_RE.match(lines[i])), len(lines)
    )
    bounds = [*starts[1:], stop]
    return [lines[a:b] for a, b in zip(starts, bounds, strict=True)]


# ---------------------------------------------------------------------------------------------
# Views: the Appendix-B fixture, and small hand-made run-objects
# ---------------------------------------------------------------------------------------------
def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def fold_fixture(scans: list[dict], *, now: datetime = NOW, team_id: int = 1) -> TeamCbomView:
    heads = [
        ScanHead(
            id=s["id"],
            team_id=s["team_id"],
            scan_type=s["scan_type"],
            title=s["title"],
            status=s["status"],
            created_at=_ts(s["created_at"]),
            last_updated=_ts(s["last_updated"]),
            scan_metadata=s["scan_metadata"],
        )
        for s in scans
    ]
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        heads,
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=team_id,
        team_name="E2E Demo Team",
        now=now,
    )


@pytest.fixture(scope="module")
def raw_fixture() -> dict:
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def view(raw_fixture) -> TeamCbomView:
    return fold_fixture(raw_fixture["scans"])


@pytest.fixture(scope="module")
def pdf(view) -> bytes:
    return build_pdf(view)


@pytest.fixture(scope="module")
def lines(pdf) -> list[str]:
    return text_lines(pdf)


@pytest.fixture(scope="module")
def rows(lines) -> list[list[str]]:
    return register_segments(lines, EXPECTED_ORDER)


def row_of(rows: list[list[str]], subject: str) -> str:
    """The squashed text of the register row whose subject is ``subject``."""
    return squash("\n".join(rows[EXPECTED_ORDER.index(subject)]))


def _props(items: dict) -> list[dict]:
    return [{"name": k, "value": v} for k, v in items.items() if v is not None]


def cert(
    name,
    subject,
    *,
    issuer=None,
    not_before="2026-01-01T00:00:00Z",
    not_after="2030-01-01T00:00:00Z",
    sig="sha256WithRSAEncryption",
    pk="rsaEncryption",
    size="2048",
    curve=None,
    self_signed="false",
    ca="false",
    path=None,
    impact="Low",
    codes=(),
    expired=False,
):
    """``(cbom_json component, results[] row)`` of one certificate."""
    props = {
        "crypto:assetType": "certificate",
        "crypto:subjectName": subject,
        "crypto:issuerName": issuer or subject,
        "crypto:notValidBefore": not_before,
        "crypto:notValidAfter": not_after,
        "crypto:signatureAlgorithm": sig,
        "crypto:publicKeyAlgorithm": pk,
        "crypto:keySize": size,
        "crypto:curve": curve,
        "crypto:selfSigned": self_signed,
        "crypto:isCertificateAuthority": ca,
        "discovery:source": path or name,
    }
    component = {
        "bom-ref": f"ref-cert-{name}",
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"assetType": "certificate"},
        "properties": _props(props),
    }
    row = {
        "title": name,
        "asset_type": "certificate",
        "impact": impact,
        "finding_codes": list(codes),
        "location": path or name,
        "bom_ref": f"ref-cert-{name}",
        "expired": expired,
        "self_signed": self_signed == "true",
        "not_valid_after": not_after,
        "key_size": size,
        "description": f"{name} finding text",
        "quantum_vulnerable": False,
        "quantum_safe": True,
    }
    return component, row


def blob(*pairs, edges=()):
    """A full-fidelity (Tier A) ``scan_data`` holding the given ``cert(...)`` pairs."""
    data = {
        "results": [row for _component, row in pairs],
        "cbom_json": {"specVersion": "1.6", "components": [c for c, _row in pairs]},
        "cbom_distributions": {"pqc": {}},
        "cbom_compliance": {"nist_800_57": {"pass": 1, "fail": 0, "requirements": []}},
    }
    if edges:
        data["cbom_graph"] = {
            "nodes": [],
            "edges": [
                {"source": f"ref-cert-{a}", "target": f"ref-cert-{b}", "rel": "signed_by"}
                for a, b in edges
            ],
        }
    return data


def fold(*scans, now: datetime = NOW, team_name: str = "Synthetic Team") -> TeamCbomView:
    """Fold ``(scan_id, age_days, scan_data[, repo_url])`` tuples (all successful, team 1)."""
    heads, blobs = [], {}
    for scan_id, age_days, data, *extra in scans:
        created = now - timedelta(days=age_days)
        heads.append(
            ScanHead(
                id=scan_id,
                team_id=1,
                scan_type="cbom",
                title=f"scan-{scan_id}",
                status="success",
                created_at=created,
                last_updated=created + timedelta(minutes=2),
                scan_metadata={
                    "zip_file_used": False,
                    "repo_url": extra[0] if extra else "https://github.com/o/r",
                    "branch": "main",
                },
            )
        )
        blobs[scan_id] = data
    return fold_scans(
        heads,
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=1,
        team_name=team_name,
        now=now,
    )


def empty_view() -> TeamCbomView:
    return fold(now=NOW)


def cert_agg(index: int, **overrides) -> CertAgg:
    """A hand-made, fully populated ``CertAgg`` (no fold) for volume and edge tests."""
    fields = {
        "key": f"k{index:06d}",
        "identity_strong": True,
        "name": f"cert-{index}.pem",
        "file_names": (f"cert-{index}.pem",),
        "subject_cn": f"svc-{index}.corp.example.com",
        "issuer_cn": "Corp Issuing CA 1",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2029-01-01T00:00:00Z",
        "public_key_algorithm": "rsaEncryption",
        "key_size": "2048",
        "signature_algorithm": "sha256WithRSAEncryption",
        "self_signed": False,
        "is_ca": False,
        "signed_by": ("corp-issuing-ca.pem",),
        "impact": "Low",
        "tier": "A",
        "source_keys": ("repo:example.test/org/app@main",),
        "current_source_keys": ("repo:example.test/org/app@main",),
        "locations": (("example.test/org/app (main)", f"tls/cert-{index}.pem"),),
        "locations_total": 1,
        "current": True,
        "first_seen": NOW - timedelta(days=30),
        "last_seen": NOW - timedelta(days=2),
        "scan_count": 3,
        "scan_ids": (9, 5, 2),
        "latest_scan_id": 9,
    }
    fields.update(overrides)
    return CertAgg(**fields)


def view_with(*certs: CertAgg, **overrides) -> TeamCbomView:
    source = SourceAgg(
        key="repo:example.test/org/app@main",
        label="example.test/org/app (main)",
        kind="repo",
        repo_url="https://example.test/org/app",
        branch="main",
        scan_ids=(9,),
        scan_count=1,
        first_scanned=NOW,
        last_scanned=NOW,
        current_scan_id=9,
        current_tier="A",
        current_fidelity="full",
        last_attempt_scan_id=9,
        last_attempt_status="success",
        last_attempt_at=NOW,
    )
    fields = {
        "team_id": 1,
        "team_name": "Volume Team",
        "generated_at": NOW,
        "as_of": NOW.date(),
        "scans_total": 1,
        "eligible": 1,
        "included": 1,
        "fidelity_full": 1,
        "fidelity_reduced": 0,
        "window_start": NOW - timedelta(days=2),
        "window_end": NOW - timedelta(days=2),
        "fingerprint": "ab12cd34ef56",
        "sources": (source,),
        "certs": tuple(certs),
    }
    fields.update(overrides)
    return TeamCbomView(**fields)


# =============================================================================================
# 1. Document shape (Appendix-B team view)
# =============================================================================================
def test_build_pdf_returns_a_landscape_pdf_with_register_chrome(pdf):
    assert pdf.startswith(b"%PDF-")
    assert media_box(pdf) == LANDSCAPE
    assert page_count(pdf) >= 2
    assert "Certificate Estate Register" in (info_field(pdf, "Title") or "")
    text = full_text(pdf)
    assert "CBOM Certificate Estate Register" in text  # the REPORT_META footer label
    assert "SAST Report" not in text


def test_build_is_deterministic(view, pdf):
    assert build_pdf(view) == pdf


def test_sections_appear_in_order_without_a_previously_seen_section(lines):
    headings = [line for line in lines if SECTION_RE.match(line)]
    assert [h.split(". ", 1)[0] for h in headings] == ["1", "2", "3", "4", "5"]
    titles = [h.split(". ", 1)[1] for h in headings]
    assert titles[0] == "Summary"
    assert titles[1].startswith("Validity bands as of 2026-10-19")
    assert titles[2] == "Certificate register"
    assert titles[3] == "Discovery limits and manual-field guidance"
    assert titles[4] == "Reviewer sign-off"
    assert authored.PREVIOUSLY_SEEN_TITLE not in "\n".join(lines)


# =============================================================================================
# 2. The register: 14 unique rows, sorted, with the documented cells
# =============================================================================================
def test_fourteen_unique_certificates_become_fourteen_rows_in_the_documented_order(view):
    computed = register_rows(view)
    assert len(computed) == 14
    assert [r.cert.subject_cn for r in computed] == EXPECTED_ORDER
    assert [r.number for r in computed] == list(range(1, 15))
    assert len({r.cert.key for r in computed}) == 14


def test_the_pdf_register_lists_every_certificate_once_in_order(rows):
    assert len(rows) == 14  # register_segments found rows 1..14, each anchored on '#' + subject


def test_sort_puts_expired_first_then_near_expiry_then_impact_then_valid_to(view):
    computed = register_rows(view)
    assert [r.band.band for r in computed[:2]] == [EXPIRED, LE_30]
    assert [r.expiry_note for r in computed[:2]] == ["35 days ago", "20 days left"]
    assert [r.band.days_left for r in computed[:2]] == [-35, 20]
    assert all(r.band.band == VALID for r in computed[2:])
    impacts = [r.cert.impact for r in computed[2:]]
    order = ["Critical", "High", "Medium", "Low"]
    assert impacts == sorted(impacts, key=order.index)
    assert computed[2].cert.impact == "Critical"  # rsa1024_sha1.pem is the only Critical row


def test_sort_tie_breaks_unknown_impact_and_missing_dates_come_last():
    same_day = "2029-01-01T00:00:00Z"
    certs = [
        cert_agg(1, subject_cn="b-odd-impact", impact="Odd", not_after=same_day),
        cert_agg(2, subject_cn="a-no-date", impact="Low", not_after=None),
        cert_agg(3, subject_cn="c-dated", impact="Low", not_after="2029-06-01T00:00:00Z"),
        cert_agg(4, subject_cn="B-low-same-day", impact="Low", not_after=same_day),
        cert_agg(5, subject_cn="a-low-same-day", impact="Low", not_after=same_day),
        cert_agg(6, subject_cn="z-critical", impact="Critical", not_after="2030-01-01T00:00:00Z"),
    ]
    order = [r.cert.subject_cn for r in register_rows(view_with(*certs))]
    assert order == [
        "z-critical",  # impact first
        "a-low-same-day",  # then valid-to ascending, then subject (case-insensitive)
        "B-low-same-day",
        "c-dated",
        "a-no-date",  # no notAfter: after every dated certificate of the same impact
        "b-odd-impact",  # an impact outside Critical/High/Medium/Low sorts last
    ]


def test_summary_kpis_match_the_appendix_b_quantities(lines):
    block = section_lines(lines, 1)
    expected = {
        "Certificates": "14",
        "Expired": "1",
        authored.EXPIRY_BAND_CHIP_TEXT["LE_30"]: "1",
        authored.EXPIRY_BAND_CHIP_TEXT["LE_90"]: "0",
        "Weak crypto": "5",  # weak key 3 + weak signature 3, rsa1024_sha1.pem in both
        "Self-signed leaf": "3",
        "Issuer not found": "0",
    }
    for label, value in expected.items():
        assert label in block, f"KPI label {label!r} missing (or wrapped) in {block}"
        assert block[block.index(label) + 1] == value, label


def test_validity_band_table_counts(lines):
    block = section_lines(lines, 2)
    chips = authored.EXPIRY_BAND_CHIP_TEXT
    counts = {}
    for i, line in enumerate(block):
        if line in chips.values():
            counts[line] = block[i + 2]  # chip, definition, count
    # no certificate has an unreadable notAfter, so the UNKNOWN band is not listed
    assert counts == {
        chips["EXPIRED"]: "1",
        chips["LE_30"]: "1",
        chips["LE_90"]: "0",
        chips["VALID"]: "12",
    }
    assert sum(int(n) for n in counts.values()) == 14
    assert "14 unique certificates" in norm(" ".join(block))


def test_expired_certificate_row_has_the_expired_chip_and_days(rows):
    text = row_of(rows, "expired-api.e2e.test")
    assert "EXPIRED" in text
    assert "35daysago" in text
    assert "2025-09-14" in text and "2026-09-14" in text
    assert "-35" not in text  # 'ago' carries the direction, the number is never negative
    assert squash("Expired certificate (EXPIRED_CERTIFICATE)") in text
    assert squash("Self-signed leaf certificate (SELF_SIGNED_LEAF)") in text
    assert "Self-signedleaf" in text  # the chain cell
    assert "HIGH" in text  # impact chip: expired + self-signed leaf
    assert "1scan(#6)" in text  # a certificate seen once names its scan


def test_near_expiry_certificate_gets_the_le_30_chip(rows):
    text = row_of(rows, "expiring-soon.e2e.test")
    assert squash(authored.EXPIRY_BAND_CHIP_TEXT["LE_30"]) in text  # '<=30 DAYS'
    assert "20daysleft" in text
    assert "EXPIRED" not in text
    assert "scan-timeflagdiffers" not in text
    assert "2026-11-08" in text


def test_weak_key_signature_and_self_signed_leaf_labels_carry_the_raw_code(rows):
    both = row_of(rows, "legacy-internal.test")  # rsa1024_sha1.pem
    assert squash("Certificate with an undersized key (WEAK_CERTIFICATE_KEY)") in both
    assert squash("Certificate signed with a weak hash (WEAK_CERTIFICATE_SIGNATURE)") in both
    assert "CRITICAL" in both
    assert "RSA1024" in both and "sha1WithRSAEncryption" in both
    key_only = row_of(rows, "weak-rsa1024-ca.test")
    assert squash("Certificate with an undersized key (WEAK_CERTIFICATE_KEY)") in key_only
    assert "WEAK_CERTIFICATE_SIGNATURE" not in key_only
    sig_only = row_of(rows, "weak-sha1-ca.test")
    assert squash("Certificate signed with a weak hash (WEAK_CERTIFICATE_SIGNATURE)") in sig_only
    assert "WEAK_CERTIFICATE_KEY" not in sig_only
    leaf = row_of(rows, "selfsigned-leaf.test")
    assert squash("Self-signed leaf certificate (SELF_SIGNED_LEAF)") in leaf
    assert "MEDIUM" in leaf


def test_clean_certificate_row_says_no_findings_with_a_low_chip(rows):
    text = row_of(rows, "strong-control.test")
    assert "Nofindings" in text and "LOW" in text
    assert "(WEAK_" not in text and "SELF_SIGNED_LEAF" not in text


def test_duplicated_certificate_is_one_row_with_three_locations_and_four_scans(view, rows):
    app_rows = [r for r in register_rows(view) if r.cert.subject_cn == "synthetic-crypto-app.test"]
    assert len(app_rows) == 1
    text = row_of(rows, "synthetic-crypto-app.test")
    assert "3locations" in text
    assert "4scans" in text
    assert "latest#2" in text
    assert "cert.pem" in text and "payments-ca.pem" in text  # both file names
    assert "2026-08-20" in text and "2026-10-12" in text  # first seen (#8) -> last seen (#2)
    for place in (
        "github.com/e2e-demo/payments-service(main):cert.pem",
        "github.com/e2e-demo/identity-gateway(main):certs/imported/payments-ca.pem",
        "github.com/e2e-demo/legacy-billing(main):cert.pem",
    ):
        assert place in text, place
    assert "RootCA" in text  # self-signed CA:TRUE


def test_chain_leaf_is_signed_by_the_root_in_the_estate(rows):
    leaf = row_of(rows, "chain.leaf.test")
    assert "Signedbychain-root.crt" in leaf
    assert "2locations" in leaf and "2scans" in leaf
    assert "server.crt" in leaf and "chain-leaf.crt" in leaf
    root = row_of(rows, "DevSecShield Test Root CA")
    assert "RootCA" in root and "Signedby" not in root and "chain-root.crt" in root


def test_public_key_column_shows_algorithm_with_size_or_curve(rows, view):
    assert "ECP-256" in row_of(rows, "ec-p256-ca.test")  # squashed 'EC P-256'
    assert "ECP-256" in row_of(rows, "ecdsa-service.test")
    assert "RSA2048" in row_of(rows, "strong-control.test")
    assert "RSA1024" in row_of(rows, "weak-keysize.test")
    keys = {r.cert.subject_cn: r.public_key for r in register_rows(view)}
    assert keys["ec-p256-ca.test"] == "EC P-256"
    assert keys["strong-control.test"] == "RSA 2048"
    assert keys["weak-keysize.test"] == "RSA 1024"


def test_chain_column_labels_follow_the_estate(view):
    kinds = {r.cert.subject_cn: (r.chain_kind, r.chain_lines) for r in register_rows(view)}
    assert kinds["chain.leaf.test"] == ("signed_by", ("Signed by chain-root.crt",))
    assert kinds["DevSecShield Test Root CA"] == ("root_ca", ("Root CA",))
    assert kinds["selfsigned-leaf.test"] == ("self_signed_leaf", ("Self-signed leaf",))
    assert kinds["expired-api.e2e.test"][0] == "self_signed_leaf"
    assert kinds["expiring-soon.e2e.test"][0] == "self_signed_leaf"
    assert sum(1 for kind, _lines in kinds.values() if kind == "self_signed_leaf") == 3
    assert not any(kind == "issuer_not_in_estate" for kind, _lines in kinds.values())


def test_chips_follow_the_severity_palette_and_always_carry_text(view):
    computed = {r.cert.subject_cn: r for r in register_rows(view)}

    def expiry_chip(subject):
        return register._expiry_cell(computed[subject], 40.0)[0]

    def impact_chip(subject):
        return register._findings_cell(computed[subject].cert, 70.0)[0]

    assert expiry_chip("expired-api.e2e.test").style.backColor == PILL_CRITICAL_BG
    assert expiry_chip("expiring-soon.e2e.test").style.backColor == PILL_HIGH_BG
    assert expiry_chip("strong-control.test").style.backColor == PILL_LOW_BG
    assert impact_chip("legacy-internal.test").style.backColor == PILL_CRITICAL_BG
    assert impact_chip("weak-sig.test").style.backColor == PILL_HIGH_BG
    assert impact_chip("selfsigned-leaf.test").style.backColor == PILL_MEDIUM_BG
    assert impact_chip("strong-control.test").style.backColor == PILL_LOW_BG
    # a chip is never colour-only
    assert expiry_chip("expired-api.e2e.test").getPlainText() == "EXPIRED"
    assert impact_chip("legacy-internal.test").getPlainText() == "CRITICAL"


def test_owner_and_business_system_are_assessor_columns_and_blank(view):
    computed = register_rows(view)
    table = register.register_table(computed, 720.0, as_of=view.as_of)
    header = [cell.getPlainText() for cell in table._cellvalues[0]]
    assert len(header) == 14
    assert header[-2] == "Owner (assessor)"
    assert header[-1] == "Business system (assessor)"
    body = table._cellvalues[1:]
    assert len(body) == 14
    for cells in body:
        assert len(cells) == 14
        assert cells[-2].getPlainText().strip() == ""
        assert cells[-1].getPlainText().strip() == ""
    assert abs(sum(table._colWidths) - 720.0) < 1e-6
    # both manual columns carry the amber "fill in here" tint, and nothing else does
    tinted = {
        cmd[1][0]
        for cmd in table._bkgrndcmds
        if cmd[0] == "BACKGROUND" and cmd[1][0] == cmd[2][0] and cmd[1][1] == 0
    }
    assert {12, 13} <= tinted


def test_the_register_scales_to_any_frame_width(view):
    computed = register_rows(view)
    for width in (540.0, 700.5, 900.0):
        table = register.register_table(computed, width, as_of=view.as_of)
        assert abs(sum(table._colWidths) - width) < 1e-6
        assert len(table._cellvalues) == 15


def test_register_header_names_every_column(lines):
    header = squash("".join(section_lines(lines, 3)))
    for name in (
        "Certificate",
        "IssuerCN",
        "Publickey",
        "Signaturealgorithm",
        "Validfrom",
        "Validto",
        "Expiryasof2026-10-19",
        "CA/self-signed/chain",
        "Findings",
        "Wherefound",
        "Owner(assessor)",
        "Businesssystem(assessor)",
    ):
        assert name in header, name


# =============================================================================================
# 3. Expiry is computed by the renderer (plan F-03 / F-04)
# =============================================================================================
def test_expiry_band_is_recomputed_from_not_after_and_not_trusted_from_the_view():
    stale = cert_agg(1, not_after="2026-01-01T00:00:00Z", expiry=ExpiryBand(VALID, 999))
    view_ = view_with(stale)
    (row,) = register_rows(view_)
    assert row.band.band == EXPIRED and row.band.days_left == (date(2026, 1, 1) - NOW.date()).days
    text = squash(full_text(build_pdf(view_)))
    assert "EXPIRED" in text and "291daysago" in text


@pytest.mark.parametrize(
    ("not_after", "band", "days"),
    [
        ("2026-10-18T23:59:59Z", EXPIRED, -1),
        ("2026-10-19T00:00:01Z", LE_30, 0),
        ("2026-11-18T00:00:00Z", LE_30, 30),
        ("2026-11-19T00:00:00Z", LE_90, 31),
        ("2027-01-17T00:00:00Z", LE_90, 90),
        ("2027-01-18T00:00:00Z", VALID, 91),
        (None, UNKNOWN, None),
        ("not-a-date", UNKNOWN, None),
    ],
)
def test_band_edges(not_after, band, days):
    (row,) = register_rows(view_with(cert_agg(1, not_after=not_after)))
    assert (row.band.band, row.band.days_left) == (band, days)


def test_unknown_expiry_is_labelled_not_recorded():
    view_ = view_with(cert_agg(1, not_after=None, subject_cn="no-expiry.example.test"), cert_agg(2))
    pdf_ = build_pdf(view_)
    text = squash(full_text(pdf_))
    assert "UNKNOWN" in text and "expirynotrecorded" in text
    # the band table lists the UNKNOWN band as soon as one certificate falls in it
    block = section_lines(text_lines(pdf_), 2)
    unknown_chip = authored.EXPIRY_BAND_CHIP_TEXT["UNKNOWN"]
    assert block[block.index(unknown_chip) + 2] == "1"


def test_findings_come_from_codes_and_impact_not_from_a_weak_flag():
    # F-04: a certificate row carries weak=false / crypto_strength=strong yet impact Critical
    view_ = view_with(
        cert_agg(
            1,
            impact="Critical",
            finding_codes=("WEAK_CERTIFICATE_SIGNATURE", "WEAK_CERTIFICATE_KEY"),
        )
    )
    text = squash(full_text(build_pdf(view_)))
    assert "CRITICAL" in text
    assert squash("Certificate signed with a weak hash (WEAK_CERTIFICATE_SIGNATURE)") in text


def test_scan_time_flag_differs_note_appears_only_when_the_flags_disagree(view, raw_fixture):
    assert not any(r.flag_differs for r in register_rows(view))
    later = fold_fixture(raw_fixture["scans"], now=NOW + timedelta(days=400))  # 2027-11-23
    by_subject = {r.cert.subject_cn: r for r in register_rows(later)}
    differing = sorted(s for s, r in by_subject.items() if r.flag_differs)
    # the scan said "not expired"; 400 days later notAfter 2027-06-29 / 2026-11-08 has passed
    assert differing == ["expiring-soon.e2e.test", "synthetic-crypto-app.test"]
    assert by_subject["expired-api.e2e.test"].band.band == EXPIRED  # scan also said expired
    assert not by_subject["expired-api.e2e.test"].flag_differs
    later_lines = text_lines(build_pdf(later))
    later_rows = register_segments(later_lines, [r.cert.subject_cn for r in register_rows(later)])
    names = [r.cert.subject_cn for r in register_rows(later)]
    for subject in differing:
        assert "scan-timeflagdiffers" in squash("\n".join(later_rows[names.index(subject)]))
    other = squash("\n".join(later_rows[names.index("expired-api.e2e.test")]))
    assert "scan-timeflagdiffers" not in other
    base_rows = register_segments(text_lines(build_pdf(view)), EXPECTED_ORDER)
    assert all("scan-timeflagdiffers" not in squash("\n".join(r)) for r in base_rows)


# =============================================================================================
# 4. Chain, identity and degradation
# =============================================================================================
def test_issuer_not_in_estate_is_stated_and_counted():
    orphan = cert("orphan.pem", "orphan.example.test", issuer="Vanished Root CA")
    view_ = fold((1, 3, blob(orphan)))
    (row,) = register_rows(view_)
    assert row.chain_kind == "issuer_not_in_estate"
    assert row.chain_lines == ("Issuer not in estate",)
    lines_ = text_lines(build_pdf(view_))
    block = section_lines(lines_, 1)
    assert block[block.index("Issuer not found") + 1] == "1"
    assert "Issuernotinestate" in squash("\n".join(section_lines(lines_, 3)))


def test_issuer_found_by_name_without_a_graph_edge_is_signed_by_that_file():
    leaf = cert("leaf.pem", "app.example.test", issuer="Known Root CA")
    root = cert("known-root.pem", "Known Root CA", self_signed="true", ca="true")
    by_subject = {r.cert.subject_cn: r for r in register_rows(fold((1, 3, blob(leaf, root))))}
    assert by_subject["app.example.test"].chain_lines == ("Signed by known-root.pem",)
    assert by_subject["Known Root CA"].chain_lines == ("Root CA",)


def test_an_issuer_that_only_exists_in_an_earlier_scan_is_not_in_the_estate():
    leaf = cert("leaf.pem", "app.example.test", issuer="Retired Root CA")
    root = cert("retired-root.pem", "Retired Root CA", self_signed="true", ca="true")
    view_ = fold((1, 20, blob(leaf, root)), (2, 5, blob(leaf)))  # the root left the latest scan
    (row,) = register_rows(view_)
    assert row.cert.subject_cn == "app.example.test"
    assert row.chain_kind == "issuer_not_in_estate"


def test_graph_edge_wins_over_name_matching():
    leaf = cert("leaf.pem", "app.example.test", issuer="Shared CA")
    root = cert("root-a.pem", "Shared CA", self_signed="true", ca="true")
    twin = cert(
        "root-b.pem", "Shared CA", self_signed="true", ca="true", not_after="2031-01-01T00:00:00Z"
    )
    view_ = fold((1, 3, blob(leaf, root, twin, edges=[("leaf.pem", "root-a.pem")])))
    by_name = {r.cert.name: r for r in register_rows(view_)}
    assert by_name["leaf.pem"].chain_lines == ("Signed by root-a.pem",)


def test_intermediate_ca_is_called_out_before_its_issuer():
    mid = cert("mid.pem", "Issuing CA", issuer="Root CA", ca="true")
    root = cert("root.pem", "Root CA", self_signed="true", ca="true")
    by_subject = {r.cert.subject_cn: r for r in register_rows(fold((1, 3, blob(mid, root))))}
    assert by_subject["Issuing CA"].chain_lines == ("CA certificate", "Signed by root.pem")


def test_self_signed_certificate_without_a_ca_flag_is_not_called_root_or_leaf():
    pair = cert("x.pem", "x.example.test", self_signed="true", ca=None)
    (row,) = register_rows(fold((1, 3, blob(pair))))
    assert row.chain_kind == "self_signed"
    assert "Root CA" not in row.chain_lines[0] and "leaf" not in row.chain_lines[0].lower()


def test_previously_seen_section_lists_certificates_missing_from_the_latest_scan():
    keep = cert("keep.pem", "keep.example.test")
    gone = cert(
        "gone.pem", "gone.example.test", issuer="Gone Root CA", not_after="2031-02-03T00:00:00Z"
    )
    view_ = fold((1, 20, blob(keep, gone)), (2, 5, blob(keep)))
    assert [c.subject_cn for c in previously_seen(view_)] == ["gone.example.test"]
    assert [r.cert.subject_cn for r in register_rows(view_)] == ["keep.example.test"]
    lines_ = text_lines(build_pdf(view_))
    headings = [line for line in lines_ if SECTION_RE.match(line)]
    assert [h.split(". ", 1)[0] for h in headings] == ["1", "2", "3", "4", "5", "6"]
    assert headings[3] == f"4. {authored.PREVIOUSLY_SEEN_TITLE}"
    appendix = squash("\n".join(section_lines(lines_, 4)))
    assert "gone.example.test" in appendix and "gone.pem" in appendix
    assert "2031-02-03" in appendix
    assert "keep.example.test" not in appendix
    register_text = squash("\n".join(section_lines(lines_, 3)))
    assert "gone.example.test" not in register_text
    block = section_lines(lines_, 1)
    assert block[block.index("Certificates") + 1] == "1"  # headline counts exclude it


def test_previously_seen_certificates_are_listed_newest_last_seen_first():
    stay = cert("stay.pem", "stay.example.test")
    old = cert("old.pem", "old.example.test")
    older = cert("older.pem", "older.example.test")
    recent = cert("recent.pem", "recent.example.test")
    view_ = fold(
        (1, 40, blob(stay, older)),
        (2, 30, blob(stay, old)),
        (3, 20, blob(stay, recent)),
        (4, 5, blob(stay)),
    )
    names = [c.subject_cn for c in previously_seen(view_)]
    assert names == ["recent.example.test", "old.example.test", "older.example.test"]
    assert all(not c.current for c in previously_seen(view_))


def test_tier_c_certificate_without_x509_fields_is_marked_weak_identity():
    row = {
        "title": "legacy.pem",
        "algorithm_name": "legacy.pem",
        "algorithm_type": "certificate",
        "impact": "Low",
        "location": "certs/legacy.pem",
        "description": "certificate",
    }
    view_ = fold((1, 4, {"results": [row]}))
    (computed,) = register_rows(view_)
    assert not computed.cert.identity_strong
    text = squash(full_text(build_pdf(view_)))
    assert squash(authored.IDENTITY_WEAK_NOTE) in text
    assert "legacy.pem" in text
    # pre-reconcile scans never recorded finding codes: do not claim "No findings"
    assert squash(register.FINDINGS_NOT_RECORDED) in text
    assert "Nofindings" not in text
    assert computed.band.band == UNKNOWN and computed.expiry_note == "expiry not recorded"


def test_more_than_three_locations_are_summarised_with_a_plus_n_more_line():
    places = tuple((f"example.test/org/app{j} (main)", "tls/spread.pem") for j in range(5))
    spread = cert_agg(1, subject_cn="spread.example.test", locations=places, locations_total=5)
    text = squash(full_text(build_pdf(view_with(spread))))
    assert "5locations" in text and "+2more" in text
    assert "example.test/org/app2(main):tls/spread.pem" in text
    assert "app3(main)" not in text  # only the first three are spelled out
    # the aggregator keeps at most 12 locations but still counts them all
    capped = cert_agg(
        2,
        subject_cn="everywhere.example.test",
        locations=tuple(("example.test/org/app (main)", f"tls/{j}.pem") for j in range(12)),
        locations_total=40,
    )
    text = squash(full_text(build_pdf(view_with(capped))))
    assert "40locations" in text and "+37more" in text


# =============================================================================================
# 5. Empty, legacy-only, caps
# =============================================================================================
def test_empty_team_prints_the_banner_and_an_empty_register():
    pdf_ = build_pdf(empty_view())
    text = full_text(pdf_)
    assert authored.BANNER_EMPTY_TITLE in text
    assert "not evidence that no cryptographic assets exist" in norm(text)
    assert authored.EMPTY_TABLE_TEXT in text  # the register's "No entries" line
    assert register_rows(empty_view()) == []
    block = section_lines(text_lines(pdf_), 1)
    assert block[block.index("Certificates") + 1] == "0"
    assert media_box(pdf_) == LANDSCAPE
    for grade_word in ("Low risk", "Critical risk", "NOT ASSESSED"):
        assert grade_word not in text


def test_legacy_only_team_prints_the_reduced_fidelity_banner(raw_fixture):
    legacy = [s for s in raw_fixture["scans"] if s["id"] == 8]
    view_ = fold_fixture(legacy)
    assert view_.fidelity_full == 0 and view_.fidelity_reduced == 1
    pdf_ = build_pdf(view_)
    text = full_text(pdf_)
    assert authored.BANNER_REDUCED_TITLE in text
    assert authored.BANNER_EMPTY_TITLE not in text
    (row,) = register_rows(view_)
    assert row.cert.subject_cn == "synthetic-crypto-app.test"
    assert "synthetic-crypto-app.test" in squash(text)
    # the legacy row never recorded an expired flag: there is nothing to disagree with
    assert row.cert.scan_time_expired is None and row.flag_differs is False
    assert "Showing all 1 unique certificate." in norm(text)  # singular, not '1 certificates'
    assert "1 unique certificate, validity as of 2026-10-19." in norm(text)


def test_max_rows_caps_the_register_and_says_how_many_rows_were_omitted(view):
    assert MAX_REGISTER_ROWS == 2000
    pdf_ = build_pdf(view, max_rows=5)
    lines_ = text_lines(pdf_)
    shown = register_segments(lines_, EXPECTED_ORDER[:5])
    assert len(shown) == 5
    assert find_row_start(lines_, 6, EXPECTED_ORDER[5]) is None  # row 6 is not printed
    text = norm(full_text(pdf_))
    assert "9 further rows omitted" in text
    assert "Showing 5 of 14" in text
    block = section_lines(lines_, 1)
    assert block[block.index("Certificates") + 1] == "14"  # the KPIs are never capped
    assert "weak-sig.test" not in squash("\n".join(section_lines(lines_, 3)))


@pytest.mark.parametrize("max_rows", [0, -3])
def test_a_zero_or_negative_cap_prints_no_rows_but_still_builds(view, max_rows):
    text = norm(full_text(build_pdf(view, max_rows=max_rows)))
    assert "14 further rows omitted" in text
    assert authored.EMPTY_TABLE_TEXT in text


def test_a_single_omitted_row_is_not_pluralised(view):
    text = norm(full_text(build_pdf(view, max_rows=13)))
    assert "1 further row omitted" in text and "further rows omitted" not in text


def test_no_cap_notice_when_every_row_fits(pdf):
    assert "further row" not in full_text(pdf)


# =============================================================================================
# 6. Hostile strings (scanned repositories are untrusted input)
# =============================================================================================
HOSTILE_SUBJECT = '<img src="file:///etc/hostname">'
HOSTILE_ISSUER = '<font color="red">x</font> &lt;b&gt;'
HOSTILE_FILE = '<a href="http://evil.example/">x</a>.pem'
HOSTILE_PATH = "certs/<script>alert(1)</script>/x.pem"


def test_hostile_certificate_fields_render_literally_and_never_build_markup():
    benign = build_pdf(view_with(cert_agg(1)))
    hostile = cert_agg(
        2,
        subject_cn=HOSTILE_SUBJECT,
        issuer_cn=HOSTILE_ISSUER,
        name=HOSTILE_FILE,
        file_names=(HOSTILE_FILE,),
        locations=((HOSTILE_ISSUER, HOSTILE_PATH),),
        signed_by=(),
    )
    pdf_ = build_pdf(view_with(cert_agg(1), hostile))
    text = squash(full_text(pdf_))
    assert squash(HOSTILE_SUBJECT) in text
    assert squash(HOSTILE_ISSUER) in text
    assert squash(HOSTILE_FILE) in text
    assert squash(HOSTILE_PATH) in text
    assert image_count(pdf_) == image_count(benign)
    assert link_count(pdf_) == link_count(benign)
    assert fonts_used(pdf_) <= {
        "Helvetica",
        "Helvetica-Bold",
        "Helvetica-Oblique",
        "Helvetica-BoldOblique",
        "Courier",
    }


def test_control_characters_wide_glyphs_and_non_latin_text_do_not_break_the_layout():
    nasty = "evil\x00name\x07 \u202egpj.exe " + "W" * 400 + " \U0001f600 \u0930\u0942"
    hostile = cert_agg(
        1,
        subject_cn=nasty,
        issuer_cn="I" * 1000,
        name="N" * 500,
        file_names=("W" * 300, "M" * 300, "@" * 300, "extra.pem"),
        locations=tuple(("S" * 200, "P" * 400) for _ in range(12)),
        locations_total=40,
        finding_codes=tuple(f"X_{'W' * 80}_{i}" for i in range(9)),
        impact="Weird<b>impact</b>",
        signature_algorithm="s" * 600,
        public_key_algorithm="k" * 300,
        key_size="9" * 100,
    )
    pdf_ = build_pdf(view_with(hostile, cert_agg(2)))
    text = full_text(pdf_)
    assert "\x00" not in text and "\x07" not in text
    assert "?" in text  # the non-Latin letters degrade to '?' (WinAnsi only)
    assert pdf_.startswith(b"%PDF-")


def test_view_without_optional_facts_still_renders_every_cell():
    bare = CertAgg(key="bare", identity_strong=False, name="bare.pem", current=True)
    pdf_ = build_pdf(view_with(bare))
    text = full_text(pdf_)
    assert "bare.pem" in text
    assert re.search(r"\bNone\b|\bnan\b|\bNaN\b", text) is None


_FUZZ_ALPHABET = (
    list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    + list("-._/@:;,+=&?#()[]{}<>\"'\\% \t\n")
    + ["\x00", "\x07", "\x1b", "\u202e", "\u200b", "\u00e9", "\u00fc", "\u2026", "\u2014"]
    + ["\U0001f600", "\u0930", "\u4e2d", "\u05d0", "<br/>", "&amp;", "<b>", "</font>"]
)


def _fuzz_text(rng, *, longest: int = 300) -> str | None:
    roll = rng.random()
    if roll < 0.1:
        return None
    if roll < 0.2:
        return ""
    size = rng.choice([1, 3, 8, 20, 64, longest])
    return "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(size))


def _fuzz_cert(rng, index: int) -> CertAgg:
    moment = NOW - timedelta(days=rng.randint(0, 900))
    when = rng.choice([None, moment])
    not_after = rng.choice(
        [
            None,
            "",
            "garbage",
            "9999-12-31T23:59:59Z",
            "0001-01-01T00:00:00Z",
            (NOW + timedelta(days=rng.randint(-400, 4000))).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ]
    )
    return CertAgg(
        key=f"fuzz{index:05d}",
        identity_strong=rng.random() < 0.7,
        name=_fuzz_text(rng) or f"f{index}.pem",
        file_names=tuple(_fuzz_text(rng) or "x" for _ in range(rng.randint(0, 5))),
        subject_cn=_fuzz_text(rng),
        issuer_cn=_fuzz_text(rng),
        not_before=rng.choice([None, "garbage", "2020-01-01T00:00:00Z"]),
        not_after=not_after,
        public_key_algorithm=rng.choice([None, "rsaEncryption", "ecPublicKey", _fuzz_text(rng)]),
        key_size=rng.choice([None, "2048", "256", _fuzz_text(rng, longest=20)]),
        curve=rng.choice([None, "P-256", _fuzz_text(rng, longest=20)]),
        signature_algorithm=_fuzz_text(rng),
        self_signed=rng.choice([None, True, False]),
        is_ca=rng.choice([None, True, False]),
        signed_by=tuple(_fuzz_text(rng) or "s" for _ in range(rng.randint(0, 5))),
        scan_time_expired=rng.choice([None, True, False]),
        impact=rng.choice(["Low", "Medium", "High", "Critical", _fuzz_text(rng) or ""]),
        finding_codes=tuple(
            rng.choice(["WEAK_CERTIFICATE_KEY", "SELF_SIGNED_LEAF", _fuzz_text(rng) or "X"])
            for _ in range(rng.randint(0, 6))
        ),
        tier=rng.choice(["A", "B", "C"]),
        locations=tuple(
            (_fuzz_text(rng) or "src", _fuzz_text(rng) or "p") for _ in range(rng.randint(0, 12))
        ),
        locations_total=rng.choice([0, 1, 3, 12, 400]),
        current=rng.random() < 0.8,
        first_seen=when,
        last_seen=when,
        scan_count=rng.choice([0, 1, 4, 10**6]),
        latest_scan_id=rng.choice([None, 1, 987654]),
    )


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_random_certificate_fields_never_break_the_build(seed):
    rng = random.Random(seed)
    certs = [_fuzz_cert(rng, i) for i in range(60)]
    view_ = view_with(*certs)
    pdf_ = build_pdf(view_)
    assert pdf_.startswith(b"%PDF-") and media_box(pdf_) == LANDSCAPE
    text = full_text(pdf_)
    assert "\x00" not in text and "\x07" not in text and "\x1b" not in text
    current = [c for c in certs if c.current]
    assert len(register_rows(view_)) == len(current)
    assert len(previously_seen(view_)) == len(certs) - len(current)
    block = section_lines(text_lines(pdf_), 1)
    assert block[block.index("Certificates") + 1] == str(len(current))
    capped = build_pdf(view_, max_rows=7)
    assert capped.startswith(b"%PDF-")


def test_concurrent_builds_are_independent_and_identical(view, pdf):
    with ThreadPoolExecutor(max_workers=4) as pool:
        built = list(pool.map(lambda _i: build_pdf(view), range(8)))
    assert all(item == pdf for item in built)


# =============================================================================================
# 7. Hygiene: no Python artefacts, no AIBOM text, no leaked canaries
# =============================================================================================
def _assert_clean(text: str) -> None:
    # word-bounded: the data fingerprint is hex and may contain 'fda' inside a longer word
    assert re.search(r"\bNone\b", text) is None, "Python None printed"
    assert re.search(r"\bnan\b", text, re.I) is None, "NaN printed"
    # case-insensitive: none of these documents has a certificate with an unreadable notAfter,
    # so neither the 'UNKNOWN' chip nor a lower-case 'unknown' default may appear
    assert "unknown" not in text.lower(), "'unknown' printed"
    assert re.search(r"\b(FDA|HIPAA)\b", text) is None, "AIBOM regulatory text printed"
    assert "ai bom" not in text.lower() and "clinithread" not in text.lower()
    for canary in CANARIES:
        assert canary not in text, canary


def test_the_team_register_carries_no_python_artefacts_aibom_text_or_canaries(pdf):
    _assert_clean(full_text(pdf))


def test_the_empty_legacy_and_capped_documents_are_clean_too(raw_fixture, view):
    legacy = fold_fixture([s for s in raw_fixture["scans"] if s["id"] == 8])
    for built in (build_pdf(empty_view()), build_pdf(legacy), build_pdf(view, max_rows=3)):
        _assert_clean(full_text(built))


def test_other_teams_and_excluded_scans_never_reach_the_register(raw_fixture):
    team1 = fold_fixture(raw_fixture["scans"], team_id=1)
    subjects = {r.cert.subject_cn for r in register_rows(team1)}
    assert "other-team-canary.test" not in subjects
    other = fold_fixture(raw_fixture["scans"], team_id=2)
    assert {r.cert.subject_cn for r in register_rows(other)} == {"other-team-canary.test"}


# =============================================================================================
# 8. Module rules (plan 5.1 import rules, no clock reads, no language-model code)
# =============================================================================================
def _module_tree() -> ast.Module:
    return ast.parse(Path(register.__file__).read_text(encoding="utf-8"))


def test_imports_are_stdlib_reportlab_and_the_pdf_and_rollup_packages_only():
    allowed = set(sys.stdlib_module_names) | {"reportlab", "backend"}
    for node in ast.walk(_module_tree()):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        for name in names:
            assert name.split(".")[0] in allowed, name
            if name.startswith("backend"):
                assert name.startswith(
                    ("backend.utilities.pdf", "backend.utilities.dashboard.cbom_team_rollup")
                ), name


def test_the_module_never_reads_a_clock_and_names_no_language_model_client():
    source = Path(register.__file__).read_text(encoding="utf-8")
    forbidden_calls = {"now", "today", "utcnow", "time", "monotonic", "perf_counter", "gmtime"}
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_calls, ast.dump(node.func)
    for token in ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai", "subprocess"):
        assert token not in source.lower(), token


def test_the_module_does_not_build_paragraph_markup_from_unsanitised_data():
    # Paragraph() takes markup, so its first argument must never be an f-string or a '+' / '%'
    # expression: data goes through pdf_text / pdf_multiline first, then is joined.
    source = Path(register.__file__).read_text(encoding="utf-8")
    assert "escape_html(" not in source  # sanitising is pdf_text / pdf_multiline only
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Paragraph" and node.args:
            first = node.args[0]
            assert not isinstance(first, (ast.JoinedStr, ast.BinOp)), ast.dump(first)[:120]


# =============================================================================================
# 9. Text fitting: the register wraps its own text so identifiers break at punctuation
# =============================================================================================
@pytest.mark.parametrize(
    ("text", "usable", "font", "expected"),
    [
        ("sha256WithRSAEncryption", 44.0, "Helvetica", ["sha256With", "RSA", "Encryption"]),
        ("sha1WithRSAEncryption", 44.0, "Helvetica", ["sha1WithRSA", "Encryption"]),
        ("(WEAK_CERTIFICATE_KEY)", 74.0, "Helvetica", ["(WEAK_", "CERTIFICATE_KEY)"]),
        ("synthetic-crypto-app.test", 85.0, "Helvetica-Bold", ["synthetic-crypto-app.test"]),
        ("synthetic-crypto-app.test", 50.0, "Helvetica", ["synthetic-", "crypto-app.test"]),
        ("Signed by chain-root.crt", 44.0, "Helvetica", ["Signed by", "chain-root.crt"]),
        ("DevSecShield Test Root CA", 50.0, "Helvetica", ["DevSecShield", "Test Root CA"]),
        ("a b  c", 30.0, "Helvetica", ["a b c"]),
        ("short", 30.0, "Helvetica", ["short"]),
        ("", 30.0, "Helvetica", [""]),
    ],
)
def test_wrap_breaks_over_wide_words_at_natural_boundaries(text, usable, font, expected):
    assert register._wrap(text, usable, font) == expected


HOSTILE_WRAP_INPUTS = [
    "W" * 200,
    "i" * 500,
    "a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p",
    "/" * 80 + "x",
    "MixedCaseIdentifierWithoutAnyPunctuationAtAllJustCamelCase",
    "ALLCAPSALLCAPSALLCAPSALLCAPSALLCAPS",
    "sha256WithRSAEncryption " * 6,
    "github.com/e2e-demo/identity-gateway (main): certs/imported/payments-ca.pem",
    "\u2026\u2022\u2014 mixed \u00e9\u00fc glyphs",
    "word " * 60,
]


@pytest.mark.parametrize("text", HOSTILE_WRAP_INPUTS)
@pytest.mark.parametrize("usable", [12.0, 30.0, 44.0, 74.0])
def test_wrap_never_loses_text_and_never_overflows_the_column(text, usable):
    lines_ = register._wrap(text, usable, max_lines=10_000)
    assert squash("".join(lines_)) == squash(text)  # nothing dropped or invented
    for line in lines_:
        assert stringWidth(line, "Helvetica", 7.0) <= usable or len(line) == 1, line


def test_a_word_is_not_broken_after_one_or_two_characters_when_it_can_fill_the_line():
    pieces = register._break_word("a-bcdefghijklmnopqrstuvwxyz", 40.0, "Helvetica")
    assert pieces[0] != "a-" and len(pieces[0]) >= 3
    assert "".join(pieces) == "a-bcdefghijklmnopqrstuvwxyz"


def test_wrap_clips_to_max_lines_with_an_ellipsis():
    lines_ = register._wrap("W" * 400, 40.0, max_lines=3)
    assert len(lines_) == 3 and lines_[-1].endswith("\u2026")
    assert all(stringWidth(line, "Helvetica", 7.0) <= 40.0 for line in lines_)


def test_bulleted_entries_hang_their_text_under_one_bullet():
    place = "github.com/e2e-demo/identity-gateway (main): cert.pem"
    entry = register._lines(place, 59.0, bullet=True)
    assert len(entry) > 2
    assert [line.bullet for line in entry] == [True] + [False] * (len(entry) - 1)
    assert register._BULLET_INDENT > 0
    assert {line.x for line in entry} == {register._BULLET_INDENT}
    plain = register._lines(place, 59.0)
    assert not any(line.bullet or line.x for line in plain)


def test_a_text_block_is_as_tall_as_its_lines_and_prints_plain_text():
    block = register._block(register._lines("one two three four five six", 30.0))
    width, height = block.wrap(30.0, 1000.0)
    assert width == 30.0 and height == pytest.approx(len(block.lines) * register._LEADING)
    assert block.getPlainText() == "\n".join(line.text for line in block.lines)
    empty = register._TextBlock(())
    assert empty.wrap(30.0, 1000.0) == (30.0, 0)
    assert empty.getPlainText() == ""


def test_the_band_table_is_never_split_across_pages(pdf):
    pages = page_texts(pdf)
    with_heading = [p for p in pages if any(line.startswith("2. Validity bands") for line in p)]
    assert len(with_heading) == 1
    page = with_heading[0]
    for band in ("EXPIRED", "LE_30", "LE_90", "VALID"):
        chip = authored.EXPIRY_BAND_CHIP_TEXT[band]
        assert chip in page, chip  # every listed band is on the heading's page
    assert "14 unique certificates, validity as of 2026-10-19." in page


# =============================================================================================
# 10. Volume and density (plan: 1 000-row build < 6 s)
# =============================================================================================
def _volume_certs(count: int, *, typical: bool = False) -> list[CertAgg]:
    """``count`` distinct certificates across every expiry band.

    Default: a heavy mix (one to three locations each, some with two findings).  ``typical``:
    one location and, for one in eleven, a single finding: what most real estates look like.
    """
    impacts = ("Low", "Low", "Low", "Medium", "High", "Critical")
    certs = []
    for i in range(count):
        days = (i * 7) % 900 - 60  # -60 .. +839 days: every band
        not_after = (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        weak = i % 11 == 0
        places = 1 if typical else 1 + i % 3
        codes = ("WEAK_CERTIFICATE_KEY",)
        if not typical:
            codes += ("SELF_SIGNED_LEAF",)
        certs.append(
            cert_agg(
                i,
                not_after=not_after,
                impact=impacts[i % len(impacts)] if weak or not typical else "Low",
                finding_codes=codes if weak else (),
                self_signed=weak,
                signed_by=() if weak else ("corp-issuing-ca.pem",),
                locations=tuple(
                    (f"example.test/org/app{j} (main)", f"tls/cert-{i}.pem") for j in range(places)
                ),
                locations_total=places,
            )
        )
    return certs


def test_a_thousand_row_register_builds_in_under_six_seconds():
    view_ = view_with(*_volume_certs(1000))
    started = time.perf_counter()
    pdf_ = build_pdf(view_)
    elapsed = time.perf_counter() - started
    assert elapsed < 6.0, f"1000-row register took {elapsed:.2f}s"
    assert sum(1 for line in text_lines(pdf_) if SECTION_RE.match(line)) >= 5


def test_typical_rows_are_dense_about_ten_or_more_to_a_landscape_page():
    pdf_ = build_pdf(view_with(*_volume_certs(1000, typical=True)))
    assert page_count(pdf_) <= 110, page_count(pdf_)


def test_over_the_cap_is_announced_with_exact_counts():
    certs = _volume_certs(40)
    text = norm(full_text(build_pdf(view_with(*certs), max_rows=25)))
    assert "15 further rows omitted" in text and "Showing 25 of 40" in text
