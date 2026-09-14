"""Hermetic unit tests for enterprise PDF branding helpers.

These lock the Copilot/review blockers that are real (hash hex in Paragraph
markup, Unknown KPI honesty, mapping remainder, appendix swallow-and-log)
without building a full export PDF. Runtime PDF builds live in
``test_pdf_export_smoke.py`` / ``test_bom_export.py``.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, List

from reportlab.lib import colors
from reportlab.platypus import KeepTogether, Paragraph, Table

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.pdf.report_branding import (  # noqa: E402
    _count_sev,
    append_bom_compliance_sections,
    append_executive_summary,
    build_severity_bar,
    color_to_hex,
    compute_risk_score,
    finding_location,
    format_scan_duration,
    get_report_styles,
    mapping_rows,
    relative_scan_path,
    split_scan_payload,
    with_scan_duration,
)


def _walk_markup(obj: Any, acc: List[str] | None = None) -> List[str]:
    acc = acc if acc is not None else []
    if obj is None:
        return acc
    if isinstance(obj, Paragraph):
        acc.append(getattr(obj, "text", "") or obj.getPlainText())
        return acc
    if isinstance(obj, Table):
        for row in obj._cellvalues:
            for cell in row:
                _walk_markup(cell, acc)
        return acc
    if isinstance(obj, KeepTogether):
        _walk_markup(getattr(obj, "_content", None), acc)
        return acc
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _walk_markup(item, acc)
    return acc


def test_color_to_hex_is_hash_rrggbb_never_0x():
    color = colors.HexColor("#EA580C")
    hex_str = color_to_hex(color)
    assert hex_str.startswith("#"), hex_str
    assert not hex_str.lower().startswith("0x"), hex_str
    assert len(hex_str) == 7, hex_str
    assert hex_str.lower() == "#ea580c"
    # Documents why we do not use Color.hexval() in Paragraph markup.
    assert color.hexval().lower().startswith("0x")


def test_count_sev_sums_case_variant_keys():
    assert _count_sev({"High": 3, "HIGH": 2}, "High") == 5
    assert _count_sev({"High": 3, "ERROR": 1}, "High", "ERROR") == 4
    assert _count_sev({"Unknown": 2}, "High") == 0


def test_mapping_rows_keeps_limit_and_appends_remainder():
    blob = {f"A{i:02d}": f"value-{i}" for i in range(8)}
    rows = mapping_rows(blob, label="OWASP Top 10", limit=6)
    assert len(rows) == 7
    assert all(r[0] == "OWASP Top 10" for r in rows[:6])
    remainder = rows[-1]
    assert remainder[0] == "OWASP Top 10"
    assert "2 more" in remainder[1]


def test_append_executive_summary_unknown_counts_in_total_not_risk():
    styles = get_report_styles()
    story: List[Any] = []
    append_executive_summary(
        story,
        report_key="sast",
        overview_rows=[("Scan type", "SAST")],
        severity_counts={"Unknown": 2, "High": 1},
        styles=styles,
        project_name="KPI fixture",
        scan_time="1s",
        meta_chips=[("Scan type", "SAST")],
    )
    markup = " ".join(_walk_markup(story))
    assert "Unknown" in markup
    assert "2 U" in markup or "Unknown" in markup
    # Total issues = 3; High KPI stays 1 (Unknown is not High).
    assert "3" in markup
    risk_score, risk_grade, risk_band = compute_risk_score(0, 1, 0, 0)
    assert risk_score == 20
    assert risk_grade == "B"
    assert risk_band == "Moderate risk"
    assert str(risk_score) in markup
    assert risk_grade in markup


def test_severity_bar_legend_uses_hash_hex_and_unknown_segment():
    styles = get_report_styles()
    bar = build_severity_bar(
        critical=1,
        high=1,
        medium=0,
        low=0,
        unknown=2,
        styles=styles,
    )
    markup = " ".join(_walk_markup(bar))
    assert "Unknown" in markup
    assert "0x" not in markup.lower()
    assert 'color="#' in markup or "color='#" in markup or 'color="#' in markup.replace(" ", "")


def test_appendix_modules_import():
    from backend.utilities.pdf import certin_compliance_pdf, rbi_compliance_pdf

    assert callable(rbi_compliance_pdf.append_rbi_compliance_pdf_section)
    assert callable(certin_compliance_pdf.append_certin_compliance_pdf_section)


def test_appendix_failure_is_logged_and_export_continues(monkeypatch, caplog):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("appendix exploded")

    monkeypatch.setattr(
        "backend.utilities.pdf.rbi_compliance_pdf.append_rbi_compliance_pdf_section",
        _boom,
    )
    story: List[Any] = []
    with caplog.at_level(logging.WARNING, logger="backend.utilities.pdf.report_branding"):
        append_bom_compliance_sections(story, {"results": []})
    assert any("BOM compliance appendix failed" in rec.message for rec in caplog.records)


def test_format_scan_duration_matches_sample():
    assert format_scan_duration(134) == "2m 14s"
    assert format_scan_duration(45) == "45s"
    assert format_scan_duration(0.4) == "<1s"
    assert format_scan_duration(None) == "—"
    assert format_scan_duration("not-a-number") == "—"
    assert format_scan_duration(3661) == "1h 1m"


def test_relative_scan_path_strips_tmp_repo_prefix():
    raw = "/tmp/repo_42_7x86a/18-forkify/final/package-lock.json"
    assert relative_scan_path(raw) == "18-forkify/final/package-lock.json"
    assert relative_scan_path("src/app.py") == "src/app.py"
    assert relative_scan_path("") == ""


def test_relative_scan_path_does_not_truncate_repo_utils():
    assert relative_scan_path("src/repo_utils/foo.py") == "src/repo_utils/foo.py"
    assert relative_scan_path("repo_utils/clone.py") == "repo_utils/clone.py"


def test_relative_scan_path_strips_long_leading_clone_id():
    # mkdtemp is 8 chars today; stored UUID-style dirs are longer.
    assert (
        relative_scan_path("repo_a1b2c3d4e5f60789/src/app.py") == "src/app.py"
    )


def test_finding_location_prefers_dependency_over_dash():
    assert finding_location({"dependency": "core-js==3.6.5"}) == "core-js==3.6.5"
    assert finding_location({"location": "app.py:12"}) == "app.py:12"
    assert finding_location({"location": {"filename": "sg.tf", "start_line": 9}}) == "sg.tf:9"
    assert finding_location({}) == "—"
    path_title = "/tmp/repo_42_7x86a/17-Modern-JS-Modules-Tooling/final/package-lock.json"
    assert finding_location({"title": path_title}) == (
        "17-Modern-JS-Modules-Tooling/final/package-lock.json"
    )


def test_with_scan_duration_prefers_worker_value_over_wall_clock():
    started = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    ended = datetime(2026, 9, 1, 10, 10, 0, tzinfo=timezone.utc)
    payload = {"results": [], "duration_of_scan": 12}
    out = with_scan_duration(payload, started, ended)
    assert out["duration_of_scan"] == 12
    wrapped = with_scan_duration([{"title": "a"}], started, ended)
    assert wrapped["results"] == [{"title": "a"}]
    assert wrapped["duration_of_scan"] == 600.0


def test_split_scan_payload_unwraps_results_and_duration():
    inner, dur, raw = split_scan_payload(
        {"results": [{"title": "a"}], "duration_of_scan": 134}
    )
    assert inner == [{"title": "a"}]
    assert dur == 134.0
    assert raw["duration_of_scan"] == 134
    listed, listed_dur, listed_raw = split_scan_payload([{"title": "b"}])
    assert listed == [{"title": "b"}]
    assert listed_dur is None
    assert listed_raw == {}


def test_missing_logo_asset_is_skipped_without_raising(tmp_path, monkeypatch):
    """Branding chrome must degrade gracefully when the logo file is absent."""
    from reportlab.pdfgen import canvas as rl_canvas
    from backend.utilities.pdf import report_branding as branding

    missing = tmp_path / "does-not-exist.png"
    monkeypatch.setattr(branding, "logo_path", lambda: str(missing))
    c = rl_canvas.Canvas(str(tmp_path / "nologo.pdf"))
    assert branding._draw_logo(c, 36, 750) == 0.0
    c.save()
