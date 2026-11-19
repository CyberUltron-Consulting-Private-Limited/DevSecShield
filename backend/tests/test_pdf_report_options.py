"""PDF export options: defaults change nothing; each option does exactly what it says.

The default-output guard compares today's text with ``fixtures/pdf_default_text.json``, which
was captured from the generators before report options existed (``fixtures/
make_pdf_default_text.py`` on dev 57459dcc).
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS / "fixtures"))

import make_pdf_default_text as baseline  # noqa: E402
import test_pdf_export_smoke as smoke  # noqa: E402
from support.pdf_text import pdf_pages_text  # noqa: E402

from backend.utilities.pdf.branding_input import branding_from_png  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload  # noqa: E402
from backend.utilities.pdf.report_context import ReportContext  # noqa: E402
from backend.utilities.pdf.report_options import (  # noqa: E402
    ReportOptionsError,
    parse_report_options,
)

SCAN_TYPES = baseline.SCAN_TYPES


def _build(scan_type, payload, tmp_path, ctx=None, name="out"):
    out = str(tmp_path / f"{scan_type}-{name}.pdf")
    kwargs = {} if ctx is None else {"ctx": ctx}
    generate_pdf_for_type(scan_type, prepare_pdf_export_payload(scan_type, payload), out, **kwargs)
    raw = Path(out).read_bytes()
    return raw, [baseline.mask(page) for page in pdf_pages_text(raw)]


def _text(pages):
    return "\n".join(pages)


def _png(color=(10, 40, 90, 255), size=(240, 80)):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGBA", size, color).save(buf, format="PNG")
    return buf.getvalue()


# -- default output is unchanged ----------------------------------------------------------------

def test_default_output_matches_the_pre_change_baseline():
    expected = json.loads((_TESTS / "fixtures" / "pdf_default_text.json").read_text(encoding="utf-8"))

    def gen(scan_type, payload, out):
        generate_pdf_for_type(scan_type, prepare_pdf_export_payload(scan_type, payload), out)

    assert baseline.build_all(gen) == expected


def test_a_default_context_renders_the_same_as_no_context(tmp_path):
    for scan_type in SCAN_TYPES:
        payload = smoke._typical_payload(scan_type)
        _, plain = _build(scan_type, payload, tmp_path, name="none")
        _, with_ctx = _build(scan_type, payload, tmp_path, ReportContext(), name="ctx")
        assert plain == with_ctx, scan_type


# -- options parsing ----------------------------------------------------------------------------

@pytest.mark.parametrize("params,field", [
    ({"severities": ""}, "severities"),
    ({"severities": "high,,low"}, "severities"),
    ({"severities": "info"}, "severities"),
    ({"statuses": "open"}, "statuses"),
    ({"preset": "summary"}, "preset"),
    ({"label": "secret"}, "label"),
    ({"hide_evidence": "yes"}, "hide_evidence"),
    ({"prepared_for": "x" * 121}, "prepared_for"),
    ({"title": "y" * 141}, "title"),
    ({"prepared_for": "株式会社"}, "prepared_for"),
    ({"prepared_for": "line\nbreak"}, "prepared_for"),
    ({"title": "a‮b"}, "title"),
    ({"sections": "bogus"}, "sections"),
])
def test_bad_scan_options_name_the_field(params, field):
    with pytest.raises(ReportOptionsError) as err:
        parse_report_options(params, "scan", scan_type="sast")
    assert err.value.field == field


def test_family_rules():
    with pytest.raises(ReportOptionsError) as err:
        parse_report_options({"statuses": "fixed"}, "run")
    assert err.value.field == "statuses"
    with pytest.raises(ReportOptionsError):
        parse_report_options({"hide_evidence": "true"}, "run")
    with pytest.raises(ReportOptionsError):
        parse_report_options({"severities": "high"}, "deliverable")
    with pytest.raises(ReportOptionsError):
        parse_report_options({"label": "internal"}, "pack")
    assert parse_report_options({"label": "internal", "prepared_for": " Acme Bank "}, "deliverable").prepared_for == "Acme Bank"


def test_repeated_keys_are_refused():
    with pytest.raises(ReportOptionsError) as err:
        parse_report_options([("label", "internal"), ("label", "public")], "scan")
    assert err.value.field == "label"


def test_full_sets_mean_no_filter_and_presets_intersect_the_type():
    opts = parse_report_options({"severities": "critical,high,medium,low,other",
                                 "statuses": "not_started,in_progress,fixed,ignored"}, "scan")
    assert opts.severities is None and opts.statuses is None and opts.is_default
    assert parse_report_options({"preset": "executive"}, "scan", scan_type="sbom_sca").sections == {"summary", "compliance"}
    # SAST has no compliance appendix: executive keeps the summary only
    assert parse_report_options({"preset": "executive"}, "scan", scan_type="sast").sections == {"summary"}
    assert parse_report_options({"preset": "full"}, "scan", scan_type="sast").sections is None
    with pytest.raises(ReportOptionsError):
        parse_report_options({"sections": "inventory"}, "scan", scan_type="sast")


def test_unrelated_query_keys_are_left_alone():
    assert parse_report_options({"utm": "x"}, "scan").is_default


# -- options change the report as they say ----------------------------------------------------

def _rows_payload(scan_type):
    payload = smoke._typical_payload(scan_type)
    return payload


def test_sast_severity_filter_keeps_numbering_and_says_so(tmp_path):
    payload = {"results": [{
        "logical_component_title": "api",
        "vulnerabilities": [
            {"title": "Low thing", "impact": "Low", "location": "a.py:1", "description": "d1", "snippet": "x=1"},
            {"title": "Critical thing", "impact": "Critical", "location": "b.py:2", "description": "d2", "snippet": "eval(x)"},
            {"title": "High thing", "impact": "High", "location": "c.py:3", "description": "d3"},
        ],
    }]}
    opts = parse_report_options({"severities": "critical"}, "scan", scan_type="sast")
    _, pages = _build("sast", payload, tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "Critical thing" in text and "Low thing" not in text and "High thing" not in text
    assert "#2" in text  # the original number survives filtering
    assert "REPORT SCOPE" in text and "Showing 1 of 3 findings" in text
    assert "1 of 3 issues (filtered)" in text
    assert "SAST Report · Filtered" in text


def test_a_filter_that_matches_nothing_never_claims_a_clean_scan(tmp_path):
    payload = {"results": [{"logical_component_title": "api", "vulnerabilities": [
        {"title": "Critical thing", "impact": "Critical", "location": "b.py:2", "description": "d2"}]}]}
    opts = parse_report_options({"severities": "low"}, "scan", scan_type="sast")
    _, pages = _build("sast", payload, tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "No security findings were identified" not in text
    assert "No findings match the selected filters (1 in the full scan)" in text


def test_hide_evidence_removes_snippets_only(tmp_path):
    payload = {"results": [{"logical_component_title": "api", "vulnerabilities": [
        {"title": "Critical thing", "impact": "Critical", "location": "b.py:2",
         "description": "dangerous call", "snippet": "eval(user_input)", "suggested_fix": "use ast"}]}]}
    opts = parse_report_options({"hide_evidence": "true"}, "scan", scan_type="sast")
    _, pages = _build("sast", payload, tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "eval(user_input)" not in text and "EVIDENCE" not in text
    assert "dangerous call" in text and "use ast" in text and "b.py:2" in text
    assert "Code snippets hidden" in text


def test_executive_preset_leaves_out_catalog_and_cards(tmp_path):
    payload = {"results": [{"logical_component_title": "api", "vulnerabilities": [
        {"title": "Critical thing", "impact": "Critical", "location": "b.py:2", "description": "d2"}]}]}
    opts = parse_report_options({"preset": "executive"}, "scan", scan_type="sast")
    _, pages = _build("sast", payload, tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "Findings Catalog" not in text and "Detailed Findings" not in text
    assert "Preset: Executive" in text and "Left out:" in text
    assert "Export the Technical or Full report" in text
    assert len(pages) == 1


def test_cover_fields_and_label(tmp_path):
    opts = parse_report_options({"prepared_for": "Acme <Bank> & Co", "title": "Q3 review",
                                 "label": "internal"}, "scan", scan_type="sast")
    _, pages = _build("sast", smoke._typical_payload("sast"), tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "Prepared for Acme <Bank> & Co" in text
    assert "Q3 review" in text
    assert "INTERNAL" in text and "CONFIDENTIAL" not in text
    assert "REPORT SCOPE" not in text  # cover-only options do not change the content


def test_public_label_prints_no_marking(tmp_path):
    opts = parse_report_options({"label": "public"}, "scan", scan_type="sast")
    _, pages = _build("sast", smoke._typical_payload("sast"), tmp_path, ReportContext(options=opts))
    text = _text(pages)
    assert "CONFIDENTIAL" not in text and "Confidential" not in text


def _image_count(raw: bytes) -> int:
    return len(re.findall(rb"/Subtype\s*/Image", raw))


@pytest.mark.parametrize("scan_type", SCAN_TYPES)
def test_team_logo_adds_one_shared_image(scan_type, tmp_path):
    payload = smoke._typical_payload(scan_type)
    plain, _ = _build(scan_type, payload, tmp_path, ReportContext(), name="plain")
    rgb = io.BytesIO()
    from PIL import Image

    Image.new("RGB", (300, 90), (12, 60, 120)).save(rgb, format="PNG")
    branded, pages = _build(scan_type, payload, tmp_path,
                            ReportContext(branding=branding_from_png(rgb.getvalue())), name="logo")
    # an opaque (RGB) logo is one image object, stored once however many pages draw it
    assert _image_count(branded) == _image_count(plain) + 1
    # the logo adds no text (it can move a heading to the next page: compare the lines, not the flow)
    again = _build(scan_type, payload, tmp_path, ReportContext(), name="again")[1]
    assert sorted(_text(pages).splitlines()) == sorted(_text(again).splitlines())


def test_light_logo_and_alpha_logo_build(tmp_path):
    light = branding_from_png(_png(color=(250, 250, 250, 255)), tone="light")
    alpha = branding_from_png(_png(color=(20, 20, 20, 128)))
    for i, branding in enumerate((light, alpha)):
        raw, _ = _build("sbom_sca", smoke._typical_payload("sbom_sca"), tmp_path,
                        ReportContext(branding=branding), name=f"b{i}")
        assert raw.startswith(b"%PDF-")


def test_broken_logo_bytes_are_skipped_not_fatal(tmp_path):
    branding = branding_from_png(b"\x89PNG\r\n\x1a\nnot really")
    assert branding.status == "skipped"
    raw, _ = _build("sast", smoke._typical_payload("sast"), tmp_path, ReportContext(branding=branding))
    assert raw.startswith(b"%PDF-")
