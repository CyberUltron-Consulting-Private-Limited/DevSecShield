"""PR #500 re-review 6064703319 (backend, round 6).

4. The PDF findings table labels each test-code and each unconfirmed row, as the results page's badges do.
5. A CBOM scan or Sources run that did not succeed has no score: ``risk_score`` / ``risk_grade`` / ``risk_label`` /
   ``risk_posture`` null and ``risk_posture_status`` "not_scored" (shown "—"), as #505's ``risk_scale.posture_field``,
   so it never matches the "Low (A)" filter. A successful one says "scored".
"""
from __future__ import annotations

import io
import types

import pytest

from tests.test_cbom_d3_review_6063599094 import APP, TEST_ONLY, _row

NOT_SCORED = {"risk_score": None, "risk_grade": None, "risk_label": None, "risk_posture": None,
              "risk_posture_status": "not_scored"}


def _scan(rows: list[dict], status: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=1, scan_data={"results": rows, "duration_of_scan": 1.0}, scan_status=status, scan_metadata={},
        title="t", created_at=None, last_updated=None, credit_consumed=0, info=None, team_id=1,
        owner_user=types.SimpleNamespace(email="e@example.com", first_name="a", last_name="b", full_name="a b"))


def _surfaces(rows: list[dict], status: str, monkeypatch) -> dict[str, dict]:
    from backend.utilities.dashboard import scan as dashboard
    from backend.utilities.db.scan_list_item import return_cbom_list_item

    monkeypatch.setattr(dashboard, "get_findings_for_scan_id", lambda *a, **k: [])
    return {
        "list_row": return_cbom_list_item(_scan(rows, status)),
        "results_tile": dashboard.generate_scan_dashboard("cbom", scan_object=_scan(rows, status))["card_data"],
    }


def _risk(s: dict) -> dict:
    return {k: s.get(k) for k in NOT_SCORED}


@pytest.mark.parametrize("status", ["failure", "failed", "started", "running", "pending", "cancelled"])
def test_a_scan_that_did_not_succeed_is_not_scored(status, monkeypatch):
    for rows in ([], APP):
        for name, s in _surfaces(rows, status, monkeypatch).items():
            assert _risk(s) == NOT_SCORED, (status, name)


def test_a_successful_scan_is_scored_and_a_clean_one_is_zero_a(monkeypatch):
    for name, s in _surfaces([], "success", monkeypatch).items():
        assert (s["risk_score"], s["risk_grade"], s["risk_posture_status"]) == (0, "A", "scored"), name
    for name, s in _surfaces(APP, "success", monkeypatch).items():
        assert s["risk_posture_status"] == "scored" and s["risk_grade"] != "A", name
        assert s["risk_posture"]["score"] == s["risk_score"], name


def _run(status: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(id=5, created_at=None, last_updated=None, finished_at=None, status=status,
                                 credits_charged_c=0, credits_refunded_c=0, scan_id=None, schedule_id=None,
                                 trigger="manual")


@pytest.mark.parametrize(("status", "scored"), [("queued", False), ("running", False), ("failed", False),
                                                ("cancelled", False), ("done", True)])
def test_a_sources_run_row_is_scored_only_when_it_finished(status, scored, monkeypatch):
    from backend.utilities.cbom_sources import run_list

    monkeypatch.setattr(run_list, "run_trigger", lambda run: "manual")
    counts = {"risk_data": {"total_critical": 0, "total_high": 0, "total_medium": 0, "total_low": 0},
              "asset_count": 0, "endpoints_probed": 0}
    jobs = {"sources": {}, "rows": [], "jobs_total": 0, "jobs_done": 0}
    row = run_list.run_row(_run(status), counts, jobs, None)
    if scored:
        assert (row["risk_score"], row["risk_grade"], row["risk_posture_status"]) == (0, "A", "scored")
    else:
        assert _risk(row) == NOT_SCORED, status


def _pdf_text(data: dict, tmp_path) -> str:
    pypdf = pytest.importorskip("pypdf")
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    out = tmp_path / "d3.pdf"
    generate_pdf(data, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return " ".join(" ".join(page.extract_text() or "" for page in reader.pages).split())


def test_the_pdf_labels_each_test_code_and_unconfirmed_row(tmp_path):
    rows = APP + [_row("SHA-1", "Low", "tests/test_h.py", code_context="test"),
                  _row("DES", "Low", "app/conf.py", config_status="unconfirmed", confidence="low",
                       config_binding="cipher")]
    text = _pdf_text({"results": rows, "duration_of_scan": 1.0}, tmp_path)
    # the findings table: the row's title carries the label, as the results page's badge
    assert "SHA-1 · test code" in text
    assert "DES · unconfirmed (configuration only)" in text
    assert "MD5 · test code" not in text and "MD5 · unconfirmed" not in text
    # the finding card says why it is not scored
    assert "Scoring Listed, not scored: test code" in text
    assert "Scoring Listed, not scored: unconfirmed (configuration only)" in text


def test_the_test_rows_stay_out_of_the_pdf_headline(tmp_path):
    # round 7: an unconfirmed setting alone is no longer 0 / A (re-review 6066152368); test code alone still is
    text = _pdf_text({"results": TEST_ONLY, "duration_of_scan": 1.0}, tmp_path)
    assert "A Risk score 0 Low risk" in text
