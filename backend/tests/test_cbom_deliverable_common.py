"""T-COM: hermetic tests for the CBOM deliverable PDF scaffolding (WP2).

Covers ``cbom_deliverable_common`` (text sanitiser, date/ID formatting, document shell and the
table / KPI / chip / form helpers), ``cbom_deliverable_text`` (authored constants and their
provenance) and the six additive ``REPORT_META`` keys in ``report_branding``.

No DB, network, LLM or wall clock: every document is built from a hand-made ``TeamCbomView``
with an injected ``generated_at``.  PDFs are inspected with a small pure-Python content-stream
reader (ASCII85 + Flate), so the suite needs nothing beyond ``reportlab``.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import json
import os
import re
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from reportlab.platypus import Flowable, Paragraph, Table

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    SourceAgg,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as text  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import (  # noqa: E402
    TEMPLATE_VERSION,
    build_document,
    dense_table,
    document_id,
    fmt_date_utc,
    fmt_utc_ist,
    get_deliverable_styles,
    kpi_strip,
    manual_form,
    pdf_multiline,
    pdf_plain,
    pdf_text,
    section_heading,
    signoff_block,
    status_chip,
    tone_for_impact,
)
from backend.utilities.pdf.report_branding import (  # noqa: E402
    PILL_MEDIUM_BG,
    REPORT_META,
    compute_risk_score,
    get_report_styles,
)

_TESTS_DIR = Path(__file__).resolve().parent
_FIXTURES = _TESTS_DIR / "fixtures"
_NOW = datetime(2026, 10, 19, 12, 28, tzinfo=timezone.utc)

NEW_KEYS = (
    "cbom_scope_register",
    "cbom_methodology",
    "cbom_cert_register",
    "cbom_assurance_register",
    "cbom_pqc_roadmap",
    "cbom_board_report",
)
ORIGINAL_FOOTERS = {
    "sast": "SAST Report",
    "sbom_sca": "SBOM/SCA Report",
    "dast": "DAST Report",
    "iac": "IAC Report",
    "mcp": "MCP Report",
    "llm": "LLM Report",
    "cbom": "CBOM Report",
    "ai_bom": "AI BOM Report",
}
BODY_MARK = "@@BODY@@"

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


def fonts_used(raw: bytes) -> set[str]:
    return {m.decode() for m in re.findall(rb"/BaseFont\s*/([A-Za-z0-9\-]+)", raw)}


def image_count(raw: bytes) -> int:
    """Embedded image XObjects (the brand logo in the page chrome is the only legitimate one)."""
    return len(re.findall(rb"/Subtype\s*/Image", raw))


def link_count(raw: bytes) -> int:
    return len(re.findall(rb"/URI|/Subtype\s*/Link", raw))


# ---------------------------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------------------------
def _source(i: int) -> SourceAgg:
    return SourceAgg(
        key=f"repo:example.test/org/repo{i}@main",
        label=f"example.test/org/repo{i} (main)",
        kind="repo",
        repo_url=f"https://example.test/org/repo{i}",
        branch="main",
        scan_ids=(i,),
        scan_count=1,
        first_scanned=_NOW,
        last_scanned=_NOW,
        current_scan_id=i,
        current_tier="A",
        current_fidelity="full",
        last_attempt_scan_id=i,
        last_attempt_status="success",
        last_attempt_at=_NOW,
    )


def make_view(**overrides) -> TeamCbomView:
    fields = {
        "team_id": 1,
        "team_name": "E2E Demo Team",
        "generated_at": _NOW,
        "as_of": _NOW.date(),
        "scans_total": 8,
        "eligible": 7,
        "included": 6,
        "excluded": {"failure": 1, "not_completed": 2, "no_data": 1},
        "fidelity_full": 5,
        "fidelity_reduced": 1,
        "window_start": _NOW - timedelta(days=60),
        "window_end": _NOW - timedelta(days=2),
        "fingerprint": "ab12cd34ef56",
        "sources": tuple(_source(i) for i in range(1, 8)),
    }
    fields.update(overrides)
    return TeamCbomView(**fields)


def make_empty_view(**overrides) -> TeamCbomView:
    fields = {
        "scans_total": 0,
        "eligible": 0,
        "included": 0,
        "excluded": {"failure": 0, "not_completed": 0, "no_data": 0},
        "fidelity_full": 0,
        "fidelity_reduced": 0,
        "window_start": None,
        "window_end": None,
        "sources": (),
    }
    fields.update(overrides)
    return make_view(**fields)


def _marker_body(*extra):
    def body(styles, width):
        return [Paragraph(BODY_MARK, styles["body"]), *extra]

    return body


def build(
    view: TeamCbomView | None = None,
    *,
    number: int = 7,
    key: str = "cbom_cert_register",
    title: str = "Certificate Estate Register",
    landscape: bool = False,
    body=None,
) -> bytes:
    return build_document(
        view=view or make_view(),
        number=number,
        report_key=key,
        title=title,
        landscape=landscape,
        body=body or _marker_body(),
    )


def after_body(raw: bytes) -> str:
    return norm(pdf_full_text(raw).split(BODY_MARK, 1)[1])


def _walk_strings(obj):
    """Every string reachable from ``obj`` (containers and dataclass records)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _walk_strings(key)
            yield from _walk_strings(value)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            yield from _walk_strings(item)
    elif hasattr(obj, "__dataclass_fields__") and not isinstance(obj, type):
        for name in obj.__dataclass_fields__:
            yield from _walk_strings(getattr(obj, name))


def _module_strings(module, skip_prefixes=("PINNED_",)):
    for name, value in vars(module).items():
        if name.startswith("_") or name.startswith(skip_prefixes):
            continue
        yield from _walk_strings(value)


def _tables_in(flowable) -> list[Table]:
    found, stack = [], [flowable]
    while stack:
        item = stack.pop()
        if isinstance(item, Table):
            found.append(item)
        stack.extend(getattr(item, "_content", None) or [])
    return found


def _plain(cell) -> str:
    return cell.getPlainText() if isinstance(cell, Paragraph) else str(cell)


# ---------------------------------------------------------------------------------------------
# harness self-check: the extractor must be able to FAIL
# ---------------------------------------------------------------------------------------------
def test_harness_sees_unescaped_markup_as_markup():
    """Control: raw ``<b>`` is interpreted, so the literal-render tests prove something."""

    def body(styles, width):
        return [Paragraph(BODY_MARK, styles["body"]), Paragraph("<b>ctl-bold</b>", styles["body"])]

    out = after_body(build(body=body))
    assert "ctl-bold" in out
    assert "<b>" not in out


# ---------------------------------------------------------------------------------------------
# pdf_text / pdf_plain
# ---------------------------------------------------------------------------------------------
_KEEP = "caf\u00e9 \u00b7 \u2014 \u2022 \u2026 \u20ac \u00b5 \u00bd"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("RSA-2048", "RSA-2048"),
        ("", ""),
        (None, ""),
        (42, "42"),
        (["a", "<b>"], "['a', '&lt;b&gt;']"),
        # D-09 WinAnsi map
        ("key size \u2265 2048", "key size &gt;= 2048"),
        ("days \u2264 30", "days &lt;= 30"),
        ("a \u2192 b", "a -&gt; b"),
        ("a \u2190 b", "a &lt;- b"),
        ("ok \u2713", "ok Yes"),
        ("bad \u2717", "bad No"),
        ("a \u2260 b", "a != b"),
        ("minus \u2212 sign", "minus - sign"),
        ("non\u2011breaking", "non-breaking"),
        ("dash\u2015bar", "dash-bar"),
        # WinAnsi-encodable characters survive untouched (NFKC must not turn mu into Greek mu)
        (_KEEP, _KEEP),
        # everything else is one '?' per code point (emoji, RTL, CJK)
        ("\u65e5\u672c\u8a9e", "???"),
        ("\U0001f600", "?"),
        ("\u05e9\u05dc\u05d5\u05dd", "????"),
        ("\ud800", "?"),  # lone surrogate must never reach the PDF writer
        # NFKC folds compatibility forms before the map
        ("\uff21\uff22\uff23", "ABC"),
        ("\ufb01le", "file"),
        ("Mu\u0308ller", "M\u00fcller"),  # decomposed umlaut recomposes to a WinAnsi character
    ],
)
def test_pdf_text_table(raw, expected):
    assert pdf_text(raw) == expected


def test_pdf_text_strips_nul_and_c0_c1_controls():
    assert pdf_text("a\x00b\x01c\x1fd\x7fe") == "abcde"
    assert pdf_text("tab\there\nnew\rline\x0bvt\x0cff") == "tab here new line vt ff"
    assert pdf_text("x\x80\x9fy") == "xy"
    assert pdf_text("\u2028para\u2029sep") == " para sep"


@pytest.mark.parametrize(
    ("raw", "limit", "expected"),
    [
        ("x" * 300, 300, "x" * 300),
        ("x" * 301, 300, "x" * 299 + "\u2026"),
        ("x" * 1000, 300, "x" * 299 + "\u2026"),
        ("hello world", 5, "hell\u2026"),
        ("hello world", 7, "hello\u2026"),  # the cut point is rstripped before the ellipsis
        ("hello", 1, "\u2026"),
        ("hello", 5, "hello"),
        ("hello", 0, ""),
        ("hello", -3, ""),
    ],
)
def test_pdf_text_clamp(raw, limit, expected):
    assert pdf_text(raw, limit=limit) == expected


def test_pdf_text_clamp_counts_displayed_characters_not_entities():
    out = pdf_text("<" * 1000)
    assert out.count("&lt;") == 299
    assert out.endswith("\u2026")


def test_pdf_text_one_megabyte_inputs_are_fast_and_bounded():
    started = time.perf_counter()
    assert len(pdf_text("A" * 1_000_000)) == 300
    assert pdf_text("\x00" * 1_000_000 + "tail") == "tail"
    assert pdf_text("\U0001f600" * 1_000_000) == "?" * 299 + "\u2026"
    assert pdf_text("<" * 1_000_000).count("&lt;") == 299
    assert time.perf_counter() - started < 5.0


HOSTILE = [
    '<img src="file:///etc/hostname">',
    "<img src=file:///etc/hostname>",
    '<font color="red" size="40">BIG</font>',
    "<font color=#ff0000>x</font>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    '<a href="https://evil.example/x">click</a>',
    "<b>bold</b><i>it</i><u>u</u><br/><strike>s</strike>",
    "<para backColor=red><seq id='x'/>",
    "<![CDATA[x]]>",
    "&#60;b&#62; &amp; &nbsp; &copy;",
    "100% & <not> markup",
]


@pytest.mark.parametrize("raw", HOSTILE)
def test_hostile_markup_is_inert_in_escaped_output(raw):
    out = pdf_text(raw)
    assert "<" not in out
    assert ">" not in out
    assert not re.search(r"&(?!amp;|lt;|gt;)", out)
    # What the Paragraph parser hands back is exactly what was typed.
    style = get_report_styles()["body"]
    assert Paragraph(out, style).getPlainText() == raw


def test_nfkc_lookalike_angle_brackets_are_escaped_after_folding():
    assert pdf_text("\uff1cimg src=x\uff1e") == "&lt;img src=x&gt;"


def test_hostile_strings_render_literally_in_pdf_and_embed_nothing():
    def body(styles, width):
        return [
            Paragraph(BODY_MARK, styles["body"]),
            dense_table(["Hostile"], [[item] for item in HOSTILE], [500]),
        ]

    raw = build(body=body)
    rendered = after_body(raw)
    for item in HOSTILE:
        assert norm(item) in rendered, item
    # no markup was interpreted: the only image is the brand logo, and there are no links
    assert image_count(raw) == image_count(build()) >= 1
    assert link_count(raw) == 0


def test_hostile_team_name_and_title_render_literally():
    hostile = '<img src="file:///etc/hostname"> & <font color=red>x</font>'
    raw = build(make_view(team_name=hostile), title="<b>Title</b> & co")
    rendered = norm(pdf_full_text(raw))
    assert norm(hostile) in rendered
    assert "<b>Title</b> & co" in rendered
    assert image_count(raw) == image_count(build())
    assert link_count(raw) == 0


def test_emoji_rtl_and_cjk_render_as_question_marks_without_crashing():
    cell = "\U0001f600 \u05e9\u05dc\u05d5\u05dd \u0645\u0631\u062d\u0628\u0627 \u65e5\u672c"

    def body(styles, width):
        return [Paragraph(BODY_MARK, styles["body"]), dense_table(["Name"], [[cell]], [300])]

    assert "? ???? ????? ??" in after_body(build(body=body))


def test_pdf_plain_sanitises_without_escaping():
    assert pdf_plain("a<b & c \u2265 d") == "a<b & c >= d"
    assert pdf_plain("x" * 400, limit=10) == "x" * 9 + "\u2026"
    assert pdf_plain(None) == ""
    assert pdf_plain("nul\x00gone") == "nulgone"


@pytest.mark.parametrize(
    ("raw", "kwargs", "expected"),
    [
        ("a\nb", {}, "a<br/>b"),
        ("a\r\nb\rc", {}, "a<br/>b<br/>c"),
        ("a\x00\nb", {}, "a<br/>b"),
        (None, {}, ""),
        ("one line", {}, "one line"),
        ("<b>x</b>\n&", {}, "&lt;b&gt;x&lt;/b&gt;<br/>&amp;"),
        ("1\n2\n3\n4", {"max_lines": 2}, "1<br/>2\u2026"),
        ("x" * 1000, {"limit": 10}, "x" * 9 + "\u2026"),
        ("a\nb", {"max_lines": 0}, ""),
        ("a\nb", {"limit": 0}, ""),
        ("\u2265\n\u2192", {}, "&gt;=<br/>-&gt;"),
    ],
)
def test_pdf_multiline_turns_newlines_into_breaks_and_stays_inert(raw, kwargs, expected):
    assert pdf_multiline(raw, **kwargs) == expected


def test_pdf_multiline_only_ever_emits_its_own_line_breaks():
    for raw in HOSTILE:
        out = pdf_multiline(raw + "\n" + raw)
        assert out.count("<br/>") == 1
        assert "<" not in out.replace("<br/>", "")
        assert ">" not in out.replace("<br/>", "")


# ---------------------------------------------------------------------------------------------
# fmt_utc_ist / fmt_date_utc / document_id
# ---------------------------------------------------------------------------------------------
def test_fmt_utc_ist_reference_example():
    assert fmt_utc_ist(_NOW) == "2026-10-19 12:28 UTC (17:58 IST)"


def test_fmt_utc_ist_naive_is_utc_and_foreign_zone_is_converted():
    assert fmt_utc_ist(datetime(2026, 10, 19, 12, 28)) == "2026-10-19 12:28 UTC (17:58 IST)"
    local = datetime(2026, 10, 19, 7, 28, tzinfo=timezone(timedelta(hours=-5)))
    assert fmt_utc_ist(local) == "2026-10-19 12:28 UTC (17:58 IST)"


def test_fmt_utc_ist_truncates_seconds_and_shows_the_ist_date_on_rollover():
    assert fmt_utc_ist(datetime(2026, 1, 2, 3, 4, 59, tzinfo=timezone.utc)) == (
        "2026-01-02 03:04 UTC (08:34 IST)"
    )
    assert fmt_utc_ist(datetime(2026, 10, 19, 20, 0, tzinfo=timezone.utc)) == (
        "2026-10-19 20:00 UTC (2026-10-20 01:30 IST)"
    )
    assert fmt_utc_ist(datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)) == (
        "2026-12-31 23:59 UTC (2027-01-01 05:29 IST)"
    )
    assert fmt_utc_ist(datetime(5, 1, 1, 0, 0, tzinfo=timezone.utc)).startswith("0005-01-01 00:00")


def test_fmt_utc_ist_missing_values_use_a_dash():
    assert fmt_utc_ist(None) == "\u2014"
    assert fmt_utc_ist("2026-10-19") == "\u2014"  # type: ignore[arg-type]


def test_fmt_date_utc():
    assert fmt_date_utc(_NOW) == "2026-10-19"
    late_ist = datetime(2026, 10, 19, 23, 30, tzinfo=timezone(timedelta(hours=5.5)))
    assert fmt_date_utc(late_ist) == "2026-10-19"
    assert fmt_date_utc(date(2026, 3, 4)) == "2026-03-04"
    assert fmt_date_utc(None) == "\u2014"


def test_document_id_format():
    view = make_view(fingerprint="ab12cd34ef56")
    assert document_id(view, 7) == "CBOM-D07-T1-20261019-ab12cd34"
    assert document_id(view, 16) == "CBOM-D16-T1-20261019-ab12cd34"
    assert document_id(view, 1) == "CBOM-D01-T1-20261019-ab12cd34"
    assert document_id(make_view(team_id=42), 3).startswith("CBOM-D03-T42-")
    pattern = re.compile(r"^CBOM-D\d{2}-T\d+-\d{8}-[0-9a-f]{8}$")
    for number in (1, 3, 7, 10, 15, 16):
        assert pattern.match(document_id(view, number))


def test_document_id_is_deterministic_and_tolerates_missing_fingerprint():
    assert document_id(make_view(), 7) == document_id(make_view(), 7)
    assert document_id(make_view(fingerprint=""), 7).endswith("-00000000")
    assert document_id(make_view(fingerprint="AB12-CD34!zz"), 7).endswith("-ab12cd34")
    assert document_id(make_view(fingerprint="abc"), 7).endswith("-abc00000")


def test_document_id_changes_with_the_data_fingerprint():
    first = document_id(make_view(fingerprint="aaaaaaaa1111"), 7)
    assert first != document_id(make_view(fingerprint="bbbbbbbb2222"), 7)


# ---------------------------------------------------------------------------------------------
# REPORT_META (additive)
# ---------------------------------------------------------------------------------------------
def test_report_meta_original_entries_are_untouched_and_first():
    assert list(REPORT_META)[: len(ORIGINAL_FOOTERS)] == list(ORIGINAL_FOOTERS)
    for key, footer in ORIGINAL_FOOTERS.items():
        assert REPORT_META[key]["footer_label"] == footer


def test_report_meta_new_keys_exist_complete_and_distinct():
    assert list(REPORT_META)[len(ORIGINAL_FOOTERS) :] == list(NEW_KEYS)
    labels = []
    for key in NEW_KEYS:
        meta = REPORT_META[key]
        assert set(meta) == set(REPORT_META["cbom"])
        assert all(isinstance(v, str) and v.strip() for v in meta.values())
        labels.append(meta["footer_label"])
    assert len(set(labels)) == len(labels)
    assert set(labels).isdisjoint(ORIGINAL_FOOTERS.values())


def _long_body(styles, width):
    filler = [
        Paragraph(f"Filler paragraph number {i} for pagination.", styles["body"])
        for i in range(140)
    ]
    return [Paragraph(BODY_MARK, styles["body"]), *filler]


@pytest.mark.parametrize("key", NEW_KEYS)
def test_each_new_key_renders_its_own_footer_label(key):
    label = REPORT_META[key]["footer_label"]
    raw = build(key=key, body=_long_body)
    pages = pdf_pages_text(raw)
    assert len(pages) >= 2
    assert "SAST Report" not in pdf_full_text(raw)
    for index, page in enumerate(pages, start=1):
        assert page.count(label) >= 2, (key, index)  # header bar + footer line
        assert f"Page {index}" in page


def test_unknown_report_key_is_rejected_instead_of_falling_back_to_sast():
    with pytest.raises(ValueError, match="report_key"):
        build(key="cbom_cert_registry")


# ---------------------------------------------------------------------------------------------
# build_document: shell, metadata, determinism
# ---------------------------------------------------------------------------------------------
def test_build_document_page_geometry_and_body_arguments():
    seen = {}

    def probe(flag):
        def body(styles, width):
            seen[flag] = (width, set(styles))
            return [Paragraph(BODY_MARK, styles["body"])]

        return body

    portrait = build(body=probe("portrait"))
    landscape = build(landscape=True, body=probe("landscape"))
    assert portrait.startswith(b"%PDF-")
    assert media_box(portrait) == (612.0, 792.0)
    assert media_box(landscape) == (792.0, 612.0)
    assert seen["portrait"][0] == pytest.approx(540.0)
    assert seen["landscape"][0] == pytest.approx(720.0)
    for _width, names in seen.values():
        assert {"body", "muted", "heading", "table_cell", "dense_cell", "dense_header"} <= names


def test_build_document_front_matter_contents():
    view = make_view()
    full = norm(pdf_full_text(build(view)))
    for label in (
        "Document",
        "Document ID",
        "Team",
        "Generated (UTC+IST)",
        "Data window",
        "Basis",
        "Template version",
        "Data fingerprint",
    ):
        assert label in full, label
    for value in (
        "Certificate Estate Register",
        document_id(view, 7),
        "E2E Demo Team",
        "2026-10-19 12:28 UTC (17:58 IST)",
        "ab12cd34ef56",
        TEMPLATE_VERSION,
        text.TOOL_NAME,
    ):
        assert value in full, value
    # Basis box: the exact segments of plan 5.4
    assert (
        "Scans: 6 included of 7 eligible \u00b7 excluded: 1 failed, 2 not completed, "
        "1 without data" in full
    )
    assert "Sources: 7" in full
    assert "Fidelity: 5 full / 1 legacy-format" in full
    assert "History: 6 scans folded" in full
    assert (
        "Rule: current state = latest successful scan per source; first/last seen over "
        "history; certificates de-duplicated across sources" in full
    )
    assert "Cells marked (assessor) are MANUAL" in full


def test_basis_box_reports_history_truncation():
    full = norm(pdf_full_text(build(make_view(history_truncated=3))))
    assert "History: 6 scans folded (truncated: 3 older not folded)" in full


def test_disclaimer_box_carries_all_three_sentences_and_no_aibom_text():
    full = norm(pdf_full_text(build()))
    for sentence in text.DISCLAIMER_PARAGRAPHS:
        assert norm(sentence) in full, sentence
    for banned in ("clinithread", "FDA", "HIPAA", "AI BOM", "524B"):
        assert banned not in full, banned


def test_front_matter_reading_order():
    full = pdf_full_text(build())
    order = [full.index(m) for m in ("Document ID", "Scans: 6", "Advisory mapping", BODY_MARK)]
    assert order == sorted(order)


def test_empty_team_gets_banner_and_no_grade_language():
    full = norm(pdf_full_text(build(make_empty_view())))
    assert text.BANNER_EMPTY_TITLE == "NO COMPLETED CBOM SCANS"
    assert text.BANNER_EMPTY_TITLE in full
    assert "Scans: 0 included of 0 eligible" in full
    assert "No completed CBOM scans" in full  # the data-window cell
    assert "Low risk" not in full


def test_empty_banner_absent_when_data_exists():
    assert text.BANNER_EMPTY_TITLE not in pdf_full_text(build())


def test_reduced_fidelity_banner_only_when_every_included_scan_is_legacy():
    legacy_only = pdf_full_text(build(make_view(fidelity_full=0, fidelity_reduced=6)))
    assert text.BANNER_REDUCED_TITLE in legacy_only
    assert text.BANNER_REDUCED_TITLE not in pdf_full_text(build(make_view()))
    assert text.BANNER_REDUCED_TITLE not in pdf_full_text(build(make_empty_view()))


def test_pdf_metadata_present_and_not_library_defaults():
    view = make_view()
    raw = build(view)
    title = info_field(raw, "Title")
    assert title and "Certificate Estate Register" in title and "E2E Demo Team" in title
    assert info_field(raw, "Author") == "DevSecShield CBOM engine"
    subject = info_field(raw, "Subject")
    assert subject and document_id(view, 7) in subject
    keywords = info_field(raw, "Keywords")
    assert keywords and "CBOM" in keywords
    creator = info_field(raw, "Creator")
    assert creator and "DevSecShield CBOM engine" in creator
    for name in ("Title", "Author", "Subject", "Creator"):
        assert info_field(raw, name) not in {"untitled", "anonymous", "unspecified"}, name
    assert b"clinithread" not in raw.lower()
    # the viewer shows the document title, and the language is declared
    assert re.search(rb"/DisplayDocTitle\s+true", raw)
    assert re.search(rb"/Lang\s*\(en-US\)", raw)


def test_pdf_dates_come_from_the_view_not_the_wall_clock():
    raw = build()
    assert info_field(raw, "CreationDate") == "D:20261019122800+00'00'"
    assert info_field(raw, "ModDate") == "D:20261019122800+00'00'"
    later = build(make_view(generated_at=_NOW + timedelta(days=3, hours=1)))
    assert info_field(later, "CreationDate") == "D:20261022132800+00'00'"


def test_same_view_builds_byte_identical_pdf():
    first = build()
    assert first == build()
    assert first != build(make_view(fingerprint="ffffffffffff"))


def test_concurrent_builds_are_identical():
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _i: build(), range(5)))
    assert all(r == results[0] for r in results)


def test_hostile_metadata_inputs_cannot_break_the_pdf_structure():
    raw = build(make_view(team_name="Team ) /Title (pwned) \\ \x00 <x>"))
    assert raw.startswith(b"%PDF-")
    assert info_field(raw, "Author") == "DevSecShield CBOM engine"
    assert b"/Title (pwned)" not in raw


def test_body_returning_nothing_still_produces_a_valid_pdf():
    raw = build(body=lambda styles, width: [])
    assert raw.startswith(b"%PDF-")
    assert page_count(raw) == 1


def test_body_exceptions_propagate_instead_of_producing_a_partial_pdf():
    def body(styles, width):
        raise RuntimeError("renderer bug")

    with pytest.raises(RuntimeError, match="renderer bug"):
        build(body=body)


def test_fonts_stay_within_the_existing_report_family(tmp_path):
    def body(styles, width):
        return [
            Paragraph(BODY_MARK, styles["body"]),
            kpi_strip([("Certs", "14", "unique")], width),
            dense_table(["A", "B"], [["x", ""]], [100, 100], manual_cols=(1,)),
            status_chip("EXPIRED", "critical"),
            manual_form("Form", ["c1", "c2"], 2),
            signoff_block(["Prepared by"]),
        ]

    mine = fonts_used(build(body=body))
    assert mine <= {"Helvetica", "Helvetica-Bold", "Courier"}
    # ...and that family is a subset of what an existing single-scan CBOM export already uses
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    fixture = json.loads((_FIXTURES / "cbom_export_scandata.json").read_text(encoding="utf-8"))
    out_path = tmp_path / "existing_cbom_export.pdf"
    generate_pdf(fixture, str(out_path))
    assert mine <= fonts_used(out_path.read_bytes())


# ---------------------------------------------------------------------------------------------
# dense_table
# ---------------------------------------------------------------------------------------------
def test_dense_table_zero_rows_is_valid_and_says_so():
    table = dense_table(["Name", "Value"], [], [200, 200])
    assert isinstance(table, Table)
    assert len(table._cellvalues) == 2  # header + placeholder row
    out = after_body(build(body=_marker_body(table)))
    assert "No entries" in out
    assert "Name" in out
    assert "Value" in out


def test_dense_table_one_row():
    table = dense_table(["Name", "Value"], [["alpha", 7]], [200, 200])
    assert len(table._cellvalues) == 2
    out = after_body(build(body=_marker_body(table)))
    assert "alpha" in out
    assert "7" in out
    assert "No entries" not in out


def test_dense_table_many_rows_repeats_the_header_on_every_page():
    rows = [[f"row-{i}", f"value-{i}", "x"] for i in range(220)]
    table = dense_table(["Alpha col", "Beta col", "Gamma col"], rows, [200, 200, 100])
    assert table.repeatRows == 1
    pages = pdf_pages_text(build(body=_marker_body(table)))
    assert len(pages) >= 3
    for index, page in enumerate(pages, start=1):
        assert "Alpha col" in page, f"header missing on page {index}"
    full = norm("\n".join(pages))
    assert "row-0" in full
    assert "row-219" in full


def test_dense_table_repeat_zero_disables_repeating():
    assert dense_table(["A"], [["x"]], [100], repeat=0).repeatRows == 0


def test_dense_table_headers_keep_their_case_and_manual_columns_carry_assessor():
    table = dense_table(
        ["Certificate", "Owner", "Business system (assessor)"],
        [["a.pem", "", ""]],
        [150, 100, 100],
        manual_cols=(1, 2),
    )
    out = after_body(build(body=_marker_body(table)))
    assert "Certificate" in out
    assert "Owner (assessor)" in out
    assert "Business system (assessor)" in out
    assert "(assessor) (assessor)" not in out  # no double suffix
    assert "Certificate (assessor)" not in out


def test_dense_table_manual_columns_are_tinted():
    table = dense_table(["A", "B"], [["1", ""], ["2", ""]], [100, 100], manual_cols=(1,))
    tinted = [
        cmd
        for cmd in table._bkgrndcmds
        if cmd[0] == "BACKGROUND" and cmd[1][0] == 1 and cmd[2][0] == 1
    ]
    assert tinted, "manual column must carry its own background command"
    assert all(cmd[3] == PILL_MEDIUM_BG for cmd in tinted)


def test_dense_table_uses_dense_metrics():
    table = dense_table(["A", "B"], [["1", "2"]], [100, 100])
    cell = table._cellStyles[1][0]
    assert (cell.leftPadding, cell.rightPadding) == (3, 3)
    assert (cell.topPadding, cell.bottomPadding) == (3, 3)
    paragraph = table._cellvalues[1][0]
    assert isinstance(paragraph, Paragraph)
    assert paragraph.style.fontSize == 7


def test_dense_table_escapes_raw_values_once_and_passes_flowables_through():
    chip = status_chip("OK", "low")
    table = dense_table(["A", "B"], [["<b>x</b> & y", chip]], [200, 100])
    assert table._cellvalues[1][1] is chip
    out = after_body(build(body=_marker_body(table)))
    assert "<b>x</b> & y" in out
    assert "&amp;" not in out


def test_dense_table_validates_shape():
    with pytest.raises(ValueError, match="col_widths"):
        dense_table(["A", "B"], [], [100])
    with pytest.raises(ValueError, match="row"):
        dense_table(["A", "B"], [["only-one"]], [100, 100])
    with pytest.raises(ValueError, match="row"):
        dense_table(["A"], [["1", "2"]], [100])


def test_dense_table_clamps_giant_cells():
    table = dense_table(["A"], [["B" * 1_000_000]], [200])
    assert len(table._cellvalues[1][0].getPlainText()) == 300


def test_dense_table_newlines_in_raw_cells_are_real_line_breaks():
    table = dense_table(["Cert"], [["subject.example.test\nfile-name.pem"]], [200])
    page = pdf_full_text(build(body=_marker_body(table)))
    assert "subject.example.test\nfile-name.pem" in page


def test_dense_table_multiline_cells_stay_inert():
    table = dense_table(["Cert"], [['<b>x</b>\n<img src="file:///etc/hostname">']], [300])
    raw = build(body=_marker_body(table))
    assert '<b>x</b>\n<img src="file:///etc/hostname">' in pdf_full_text(raw)
    assert image_count(raw) == image_count(build())


def test_dense_table_cell_limit_adapts_to_column_width_so_hostile_cells_cannot_overflow():
    """A 300-character unbreakable cell in a very narrow column must not crash the layout."""
    for glyph, width in (("W", 45), ("@", 22), ("M", 30)):
        table = dense_table(["#", "Name"], [[glyph * 300, "ok"]], [width, 300])
        assert len(table._cellvalues[1][0].getPlainText()) < 300
        raw = build(landscape=True, body=_marker_body(table))
        assert raw.startswith(b"%PDF-")


def test_dense_table_wide_columns_keep_the_full_cell_limit():
    table = dense_table(["Path"], [["p" * 250]], [400])
    assert len(table._cellvalues[1][0].getPlainText()) == 250


def test_dense_table_rejects_zero_columns_and_tolerates_odd_cells():
    with pytest.raises(ValueError, match="headers"):
        dense_table([], [], [])
    table = dense_table(["A", "B", "C"], [[("x", "y"), ["z"], None]], [100, 100, 100])
    assert [_plain(c) for c in table._cellvalues[1]] == ["('x', 'y')", "['z']", ""]
    paragraph = Paragraph("kept", get_deliverable_styles()["body"])
    table = dense_table(["A"], [[[paragraph]]], [100])
    assert table._cellvalues[1][0] == [paragraph]


def test_dense_table_thousand_rows_build_within_budget():
    rows = [
        [
            str(i),
            f"svc-{i}.example.test",
            "CN=Example Issuing CA",
            "RSA 2048",
            "sha256WithRSAEncryption",
            "2026-01-01",
            "2027-01-01",
            f"repo/path/to/cert-{i}.pem",
        ]
        for i in range(1000)
    ]
    headers = ["#", "Subject", "Issuer", "Key", "Signature", "From", "To", "Where"]
    widths = [30, 130, 110, 60, 90, 60, 60, 180]
    started = time.perf_counter()
    raw = build(landscape=True, body=_marker_body(dense_table(headers, rows, widths)))
    elapsed = time.perf_counter() - started
    assert raw.startswith(b"%PDF-")
    assert elapsed < 12.0, f"1000-row register took {elapsed:.1f}s"


# ---------------------------------------------------------------------------------------------
# section_heading
# ---------------------------------------------------------------------------------------------
def test_section_heading_is_a_guarded_inert_paragraph():
    from reportlab.platypus import CondPageBreak

    styles = get_deliverable_styles()
    guard, heading = section_heading("<b>2</b> Register & more", styles)
    assert isinstance(guard, CondPageBreak)
    assert guard.height == 90
    assert isinstance(heading, Paragraph)
    assert heading.getPlainText() == "<b>2</b> Register & more"
    assert heading.style.keepWithNext == 0
    assert section_heading("x", styles, min_space=140)[0].height == 140


def test_section_heading_lets_a_long_table_start_on_the_current_page():
    rows = [[f"row-{i}", "x"] for i in range(200)]

    def body(styles, width):
        return [
            Paragraph(BODY_MARK, styles["body"]),
            *section_heading("2 Register", styles),
            dense_table(["Alpha col", "Beta col"], rows, [300, 200]),
        ]

    pages = pdf_pages_text(build(body=body))
    assert "2 Register" in pages[0]
    assert "Alpha col" in pages[0]
    assert "row-0" in pages[0]


def test_section_heading_is_never_stranded_at_the_bottom_of_a_page():
    """Sweep the amount of filler so the heading lands everywhere near the page bottom."""
    for filler in range(8, 28):

        def body(styles, width, filler=filler):
            lines = [Paragraph(f"filler {i}", styles["body"]) for i in range(filler)]
            return [
                Paragraph(BODY_MARK, styles["body"]),
                *lines,
                *section_heading("Stranded heading", styles),
                Paragraph("text after heading", styles["body"]),
            ]

        pages = pdf_pages_text(build(body=body))
        owner = next(i for i, page in enumerate(pages) if "Stranded heading" in page)
        assert "text after heading" in pages[owner], f"heading stranded with {filler} fillers"


# ---------------------------------------------------------------------------------------------
# kpi_strip / status_chip / tone_for_impact
# ---------------------------------------------------------------------------------------------
def test_kpi_strip_renders_every_card_and_fits_the_width():
    cards = [
        ("Unique certificates", "14", "across 7 sources"),
        ("Expired", "1", "as of 2026-10-19", "critical"),
        ("Within 30 days", "1", "renew now", "high"),
        ("Within 90 days", "2", "plan renewal", "medium"),
    ]
    strip = kpi_strip(cards, 540)
    assert isinstance(strip, Table)
    width, _height = strip.wrap(540, 700)
    assert width <= 540.01
    out = after_body(build(body=_marker_body(strip)))
    for label, value, hint, *_tone in cards:
        assert label in out
        assert value in out
        assert hint in out


def test_kpi_strip_wraps_into_rows_and_handles_empty():
    cards = [(f"Metric {i}", str(i), "hint") for i in range(7)]
    strip = kpi_strip(cards, 720, max_per_row=4)
    assert len(strip._cellvalues) == 2  # 4 + 3
    width, _height = strip.wrap(720, 700)
    assert width <= 720.01
    assert len(kpi_strip(cards[:3], 540)._cellvalues) == 1
    assert isinstance(kpi_strip([], 540), Table)


def test_kpi_strip_escapes_exactly_once_and_clamps():
    strip = kpi_strip([("A & B <i>", "1 < 2", "x" * 500)], 300)
    out = after_body(build(body=_marker_body(strip)))
    assert "A & B <i>" in out
    assert "1 < 2" in out
    assert "&amp;" not in out
    assert "x" * 400 not in out


@pytest.mark.parametrize("tone", ["critical", "high", "medium", "low", "unknown"])
def test_status_chip_always_carries_text_and_tone_colours(tone):
    chip = status_chip("EXPIRED", tone)
    assert isinstance(chip, Paragraph)
    assert chip.getPlainText() == "EXPIRED"
    assert chip.style.backColor is not None
    assert chip.style.textColor is not None


def test_status_chip_tones_are_visually_distinct_and_unknown_is_the_fallback():
    palette = {
        tone: (status_chip("X", tone).style.backColor, status_chip("X", tone).style.textColor)
        for tone in ("critical", "high", "medium", "low", "unknown")
    }
    assert len(set(palette.values())) == 5
    assert status_chip("X", "bogus").style.backColor == palette["unknown"][0]
    assert status_chip("X", None).style.backColor == palette["unknown"][0]  # type: ignore[arg-type]


def test_status_chip_text_is_never_empty_and_is_sanitised():
    assert status_chip("", "high").getPlainText() == "HIGH"
    assert status_chip(None, "bogus").getPlainText() == "UNKNOWN"  # type: ignore[arg-type]
    assert status_chip("\u226430 DAYS", "high").getPlainText() == "<=30 DAYS"
    assert status_chip("<b>x</b>", "low").getPlainText() == "<b>x</b>"
    assert len(status_chip("L" * 500, "low").getPlainText()) <= 40


def test_tone_for_impact():
    assert tone_for_impact("Critical") == "critical"
    assert tone_for_impact("high") == "high"
    assert tone_for_impact(" MEDIUM ") == "medium"
    assert tone_for_impact("Low") == "low"
    assert tone_for_impact("Weird") == "unknown"
    assert tone_for_impact(None) == "unknown"


# ---------------------------------------------------------------------------------------------
# manual_form / signoff_block
# ---------------------------------------------------------------------------------------------
def test_manual_form_title_note_columns_and_blank_rows():
    form = manual_form("Assessment boundary", ["Item", "Description", "Owner"], 4)
    assert isinstance(form, Flowable)
    (table,) = _tables_in(form)
    assert len(table._cellvalues) == 1 + 4
    for row in table._cellvalues[1:]:
        assert all(_plain(cell) == "" for cell in row)
    out = after_body(build(body=_marker_body(form)))
    assert "Assessment boundary" in out
    assert text.MANUAL_CELL_NOTE == "To be completed by assessor"
    assert text.MANUAL_CELL_NOTE in out
    for column in ("Item", "Description", "Owner"):
        assert column in out


def test_manual_form_zero_rows_and_hostile_text():
    form = manual_form("<b>T</b> & U", ["<i>c</i>"], 0)
    (table,) = _tables_in(form)
    assert len(table._cellvalues) == 1
    out = after_body(build(body=_marker_body(form)))
    assert "<b>T</b> & U" in out
    assert "<i>c</i>" in out


def test_signoff_block_lists_roles_and_blank_fields():
    roles = ["Prepared by", "CISO review", "Board IT Strategy Committee approval"]
    block = signoff_block(roles)
    assert isinstance(block, Flowable)
    (table,) = _tables_in(block)
    assert len(table._cellvalues) == 1 + len(roles)
    out = after_body(build(body=_marker_body(block)))
    for role in roles:
        assert role in out
    for column in ("Name", "Role", "Date", "Signature"):
        assert column in out
    assert text.MANUAL_CELL_NOTE in out
    for row in table._cellvalues[1:]:  # everything except the role label is blank
        assert [_plain(cell) for cell in row[1:]] == [""] * (len(row) - 1)


def test_signoff_block_with_no_roles_still_offers_one_blank_row():
    (table,) = _tables_in(signoff_block([]))
    assert len(table._cellvalues) == 2


# ---------------------------------------------------------------------------------------------
# cbom_deliverable_text
# ---------------------------------------------------------------------------------------------
ENGINE_FINDING_CODES = (
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PROTOCOL",
    "WEAK_CIPHER_SUITE",
    "WEAK_RNG",
    "STATIC_IV",
    "REUSED_NONCE",
    "HARDCODED_KEY",
    "WEAK_PADDING",
    "WEAK_CERTIFICATE_SIGNATURE",
    "WEAK_CERTIFICATE_KEY",
    "SELF_SIGNED_LEAF",
    "EXPIRED_CERTIFICATE",
    "CERT_NEAR_EXPIRY",
    "QUANTUM_VULNERABLE",
)

# Every public source the authored text may cite (plan Appendix C plus the sources verified for
# WP2).  A new URL in cbom_deliverable_text.py must be added here deliberately.
ALLOWED_SOURCE_URLS = {
    "https://csrc.nist.gov/pubs/ir/8547/ipd",
    "https://www.nist.gov/pqcrypto",
    "https://csrc.nist.gov/pubs/fips/203/final",
    "https://csrc.nist.gov/pubs/fips/204/final",
    "https://csrc.nist.gov/pubs/fips/205/final",
    "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF",
    "https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf",
    "https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms",
    "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
    "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
    "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    "https://csrc.nist.gov/pubs/sp/800/38/a/final",
    "https://csrc.nist.gov/pubs/sp/800/38/d/final",
    "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm",
    "https://www.rfc-editor.org/rfc/rfc8996",
    "https://www.rfc-editor.org/rfc/rfc7465",
    "https://www.rfc-editor.org/rfc/rfc7568",
    "https://www.rfc-editor.org/rfc/rfc6151",
    "https://www.rfc-editor.org/rfc/rfc5280",
    "https://www.rfc-editor.org/rfc/rfc8017",
    "https://cwe.mitre.org/data/definitions/321.html",
    "https://cwe.mitre.org/data/definitions/323.html",
    "https://cwe.mitre.org/data/definitions/329.html",
    "https://cwe.mitre.org/data/definitions/338.html",
    "https://cwe.mitre.org/data/definitions/780.html",
    "https://cyclonedx.org/capabilities/cbom/",
    "https://cyclonedx.org/docs/1.6/json/",
}
_URL_RE = re.compile(r"https?://[^\s\"')>\]]+")


def _text_source() -> str:
    return Path(text.__file__).read_text(encoding="utf-8")


def _registry() -> dict:
    return json.loads((_FIXTURES / "cbom_scanner_registry.json").read_text(encoding="utf-8"))


def _fixture_scans() -> list[dict]:
    path = _FIXTURES / "cbom_team_rollup_scans.json"
    return json.loads(path.read_text(encoding="utf-8"))["scans"]


def test_tool_identity_is_devsecshield_cbom_engine_and_never_the_internal_package_name():
    assert text.TOOL_NAME == "DevSecShield CBOM engine"
    for module in (text, common):
        source = Path(module.__file__).read_text(encoding="utf-8").lower()
        assert "clinithread" not in source
    assert not [s for s in _module_strings(text) if "clinithread" in s.lower()]


def test_every_printable_mention_of_ir_8547_is_draft_qualified():
    mentions = [s for s in _module_strings(text) if "8547" in s and not s.startswith("http")]
    assert mentions, "the timeline must cite IR 8547"
    for sentence in mentions:
        assert "draft" in sentence.lower(), sentence


def test_pqc_timeline_rows_follow_decision_d06():
    rows = text.PQC_TIMELINE_ROWS
    assert rows
    assert all(r.url.startswith("https://") for r in rows)
    assert {r.url for r in rows} <= ALLOWED_SOURCE_URLS
    after_2030 = [r for r in rows if r.when == "After 2030"]
    after_2035 = [r for r in rows if r.when == "After 2035"]
    assert len(after_2030) == 1
    assert len(after_2035) == 1
    assert "112" in after_2030[0].milestone
    assert "RSA-2048" in after_2030[0].milestone
    assert "deprecated" in after_2030[0].milestone.lower()
    assert "all quantum-vulnerable" in after_2035[0].milestone.lower()
    assert "disallowed" in after_2035[0].milestone.lower()
    assert after_2030[0].status == after_2035[0].status == "Draft"
    assert after_2030[0].url == after_2035[0].url == "https://csrc.nist.gov/pubs/ir/8547/ipd"
    fips = [r for r in rows if "FIPS 203" in r.milestone]
    assert len(fips) == 1
    assert "FIPS 204" in fips[0].milestone
    assert "FIPS 205" in fips[0].milestone
    assert fips[0].when == "Aug 2024"
    assert fips[0].status == "Final"
    cnsa = [r for r in rows if text.CNSA_2_0_SENTENCE in r.milestone]
    assert len(cnsa) == 1
    assert text.CNSA_VERIFY_NOTE in cnsa[0].milestone
    footnote = text.PQC_TIMELINE_FOOTNOTE.lower()
    assert "draft" in footnote
    assert "8547" in footnote


def test_timeline_sentences_are_pinned_to_the_engine_text():
    descriptions = [
        m["description"]
        for scan in _fixture_scans()
        if isinstance(scan.get("scan_data"), dict)
        for m in ((scan["scan_data"].get("cbom_distributions") or {}).get("pqc") or {}).get(
            "migration", []
        )
    ]
    assert descriptions, "fixture must carry migration rows"
    for description in descriptions:
        assert text.CNSA_2_0_SENTENCE in description
        assert text.PINNED_ENGINE_NIST_TIMELINE in description
    registry = _registry()
    assert registry["pqc_timeline"]["cnsa"] == text.CNSA_2_0_SENTENCE
    assert registry["pqc_timeline"]["nist"] == text.PINNED_ENGINE_NIST_TIMELINE


def test_disclaimers_equal_the_existing_product_constants():
    from backend.utilities.dashboard import rbi_posture
    from backend.utilities.pdf import certin_compliance_pdf

    assert text.CERTIN_DISCLAIMER == certin_compliance_pdf._CERTIN_DISCLAIMER
    assert text.RBI_BOM_DISCLAIMER == rbi_posture._ADVISORY_DISCLAIMER
    assert "static analysis" in text.SCOPE_OF_METHOD.lower()
    assert text.DISCLAIMER_PARAGRAPHS == (
        text.CERTIN_DISCLAIMER,
        text.RBI_BOM_DISCLAIMER,
        text.SCOPE_OF_METHOD,
    )


def _frontend_framework_labels() -> dict[str, str]:
    path = Path(_REPO_ROOT) / "frontend/components/compliance/frameworkLabels.ts"
    block = path.read_text(encoding="utf-8").split("FRAMEWORK_LABELS", 1)[1].split("};", 1)[0]
    return dict(re.findall(r'^\s+(\w+):\s*"([^"]+)",', block, re.M))


def test_framework_labels_cover_the_fixture_frameworks_and_equal_the_frontend():
    frameworks = _registry()["frameworks"]
    frontend = _frontend_framework_labels()
    assert len(frameworks) == 13
    for key in frameworks:
        assert text.FRAMEWORK_LABELS[key] == frontend[key], key
        assert text.framework_label(key) == frontend[key]
    assert set(text.FRAMEWORK_LABELS) == set(frameworks)
    assert text.framework_label("brand_new_framework") == "brand new framework"
    assert text.framework_label(None) == ""


def test_rbi_note_describes_the_free_ai_mapping_without_naming_other_programmes():
    note = text.RBI_MAPPING_NOTE
    assert "FREE-AI" in note
    assert "RBI" in note
    assert "Q-SAFE" not in note.upper()


def test_every_engine_finding_code_has_a_label_and_an_action():
    for code in ENGINE_FINDING_CODES:
        assert text.finding_label(code)
        assert text.finding_label(code) != code
        assert text.finding_action(code)
        assert text.finding_action(code) != text.GENERIC_FINDING_ACTION, code
    assert set(text.CERT_FINDING_CODES) == {
        "WEAK_CERTIFICATE_SIGNATURE",
        "WEAK_CERTIFICATE_KEY",
        "SELF_SIGNED_LEAF",
        "EXPIRED_CERTIFICATE",
        "CERT_NEAR_EXPIRY",
    }


def test_fixture_finding_codes_are_all_covered():
    codes = {
        code
        for scan in _fixture_scans()
        if isinstance(scan.get("scan_data"), dict)
        for row in scan["scan_data"].get("results", [])
        if isinstance(row, dict)
        for code in row.get("finding_codes") or []
    }
    assert codes, "fixture must carry finding codes"
    assert codes <= set(text.FINDING_LABELS)
    assert codes <= set(text.FINDING_ACTIONS)


def test_unknown_finding_codes_degrade_gracefully():
    assert text.finding_label("SOME_NEW_CODE") == "Some new code"
    assert text.finding_action("SOME_NEW_CODE") == text.GENERIC_FINDING_ACTION
    assert text.finding_label(None) == ""
    assert text.finding_action(None) == text.GENERIC_FINDING_ACTION


def test_grade_constants_are_pinned_to_compute_risk_score():
    assert text.GRADE_NOT_ASSESSED == "NOT ASSESSED"
    levels = ("Critical", "High", "Medium", "Low")
    samples = [
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (0, 1, 0, 0),
        (0, 0, 1, 0),
        (0, 0, 0, 5),
        (1, 23, 5, 0),
        (0, 0, 8, 0),
        (0, 0, 4, 0),
        (2, 0, 0, 0),
        (10, 10, 10, 10),
        (0, 3, 0, 0),
    ]
    for counts in samples:
        weighted = sum(
            text.GRADE_WEIGHTS[level] * n for level, n in zip(levels, counts, strict=True)
        )
        score = min(text.GRADE_SCORE_CAP, weighted * text.GRADE_SCORE_MULTIPLIER)
        grade, band = next((g, b) for floor, g, b in text.GRADE_BANDS if score >= floor)
        assert compute_risk_score(*counts) == (score, grade, band), counts
    disclaimer = text.GRADE_DISCLAIMER.lower()
    assert "platform posture grade" in disclaimer
    assert "not a regulatory rating" in disclaimer


def test_scanner_table_equals_the_engine_registry_and_omits_unwired_modules():
    registry = _registry()
    authored = [(s.name, s.order) for s in text.CBOM_SCANNERS]
    assert authored == [(s["name"], s["order"]) for s in registry["scanners"]]
    assert authored == sorted(authored, key=lambda pair: pair[1])
    assert all(s.discovers and s.evidence for s in text.CBOM_SCANNERS)
    joined = " ".join(_module_strings(text)).lower()
    for unwired in (*registry["unregistered_scanner_modules"], "jvm_go", "native_crypto"):
        assert unwired not in joined
    assert "web_native" not in joined


def test_manual_and_legend_texts():
    assert text.MANUAL_CELL_NOTE == "To be completed by assessor"
    assert text.ASSESSOR_SUFFIX == "(assessor)"
    assert "(assessor)" in text.MANUAL_LEGEND
    assert "MANUAL" in text.MANUAL_LEGEND


def test_expiry_chip_text_uses_winansi_safe_labels():
    assert set(text.EXPIRY_BAND_CHIP_TEXT) == {"EXPIRED", "LE_30", "LE_90", "VALID", "UNKNOWN"}
    for label in text.EXPIRY_BAND_CHIP_TEXT.values():
        assert pdf_plain(label) == label


def test_authored_text_is_helvetica_safe():
    """Nothing authored for Helvetica may silently turn into '?' in the sanitiser."""
    for sentence in _module_strings(text):
        if "?" in sentence:
            continue
        assert "?" not in pdf_plain(sentence, limit=len(sentence) + 16), sentence


def test_every_source_url_is_allow_listed_and_has_a_provenance_comment():
    source = _text_source()
    urls = {u.rstrip(".,;") for u in _URL_RE.findall(source)}
    assert urls, "authored text must cite public sources"
    assert urls <= ALLOWED_SOURCE_URLS, sorted(urls - ALLOWED_SOURCE_URLS)
    comment_lines = [ln for ln in source.splitlines() if ln.lstrip().startswith("# Source:")]
    assert len(comment_lines) >= 15
    commented = {u.rstrip(".,;") for ln in comment_lines for u in _URL_RE.findall(ln)}
    assert urls <= commented, sorted(urls - commented)


# ---------------------------------------------------------------------------------------------
# Module hygiene (hard constraints: in-house, no network/LLM, no wall clock, no zoneinfo)
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


def _module_paths():
    return [Path(common.__file__), Path(text.__file__)]


def _imports(tree: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names.append(("." * node.level) + (node.module or ""))
    return names


@pytest.mark.parametrize("path", _module_paths(), ids=lambda p: p.name)
def test_new_modules_import_only_stdlib_reportlab_and_allowed_backend_packages(path):
    source = path.read_text(encoding="utf-8")
    allowed_roots = set(sys.stdlib_module_names) | {"reportlab", "backend", "__future__"}
    for name in _imports(ast.parse(source)):
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


@pytest.mark.parametrize("path", _module_paths(), ids=lambda p: p.name)
def test_new_modules_never_read_the_wall_clock(path):
    offenders = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr, owner = node.func.attr, node.func.value
        owner_name = owner.id if isinstance(owner, ast.Name) else ""
        clock_on_datetime = attr in {"now", "utcnow", "today", "fromtimestamp"}
        if clock_on_datetime and owner_name in {"datetime", "date", "dt"}:
            offenders.append(f"{owner_name}.{attr}")
        if owner_name == "time" and attr in {"time", "monotonic", "perf_counter", "localtime"}:
            offenders.append(f"time.{attr}")
    assert offenders == []


def test_ist_is_a_fixed_offset_without_zoneinfo():
    source = Path(common.__file__).read_text(encoding="utf-8")
    assert "zoneinfo" not in source
    assert "pytz" not in source
    assert "timedelta(hours=5, minutes=30)" in source


def test_building_documents_never_touches_the_network_or_subprocesses(monkeypatch):
    import socket
    import subprocess

    def refuse(*_args, **_kwargs):
        raise AssertionError("network/process access attempted")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, refuse)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    raw = build(
        body=_marker_body(
            dense_table(["A"], [["x"]], [100]),
            kpi_strip([("k", "1", "h")], 300),
            signoff_block(["Prepared by"]),
        )
    )
    assert raw.startswith(b"%PDF-")


def test_template_version_constant():
    assert TEMPLATE_VERSION == "1.0"
