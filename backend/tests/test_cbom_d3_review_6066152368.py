"""PR #500 re-review 6066152368 (backend, round 7): #505's posture-status rule on every CBOM surface.

- A scan whose only weak crypto is unconfirmed gets the worst-case score, status "unverified", never a clean A.
- Confirmed plus unconfirmed shows the confirmed score with ``risk_unverified`` (the note "unverified: N unconfirmed
  settings (worst: X)" and the worst case the lists' filter and sort read).
- Test code stays fully unscored.
- A partial Sources run is "incomplete" (no score), as #505.
"""
from __future__ import annotations

import pytest

from tests.test_cbom_d3_review_6063599094 import TEST_ONLY, _row
from tests.test_cbom_d3_review_6064703319 import _pdf_text, _run, _surfaces

UNCONFIRMED_HIGH = [_row("MD5", "Low", "app/conf.py", config_status="unconfirmed", confidence="low",
                         config_binding="checksum", unverified_severity="high")]
CONFIRMED_LOW = [_row("SHA-1", "Low", "app/sig.py")]


def _posture(**counts) -> int:
    from backend.utilities.cbom_sources.cbom_metrics import risk_posture

    return risk_posture(counts)["risk_score"]


def test_unconfirmed_only_is_its_worst_case_marked_unverified(monkeypatch):
    for name, s in _surfaces(UNCONFIRMED_HIGH, "success", monkeypatch).items():
        assert s["risk_posture_status"] == "unverified", name
        assert s["risk_score"] == _posture(high=1) and s["risk_grade"] != "A", name
        assert s["risk_posture"]["score"] == s["risk_score"], name
        assert s["risk_unverified"]["note"] == "unverified: 1 unconfirmed setting (worst: High)", name


def test_confirmed_plus_unconfirmed_shows_the_confirmed_score_and_the_worst_case(monkeypatch):
    for name, s in _surfaces(CONFIRMED_LOW + UNCONFIRMED_HIGH, "success", monkeypatch).items():
        assert s["risk_posture_status"] == "scored", name
        assert s["risk_score"] == _posture(low=1), name
        unverified = s["risk_unverified"]
        assert (unverified["count"], unverified["worst"]) == (1, "high"), name
        assert unverified["worst_case"]["score"] == _posture(high=1, low=1), name


def test_test_code_stays_unscored(monkeypatch):
    for name, s in _surfaces(TEST_ONLY, "success", monkeypatch).items():
        assert (s["risk_score"], s["risk_grade"], s["risk_posture_status"]) == (0, "A", "scored"), name
        assert s["risk_unverified"] is None, name


def test_a_row_stored_without_its_worst_case_uses_its_impact(monkeypatch):
    old = [_row("MD5", "Medium", "app/conf.py", config_status="unconfirmed", confidence="low")]
    for name, s in _surfaces(old, "success", monkeypatch).items():
        assert (s["risk_posture_status"], s["risk_score"]) == ("unverified", _posture(medium=1)), name


@pytest.mark.parametrize(("status", "want"), [("done", "scored"), ("partial", "incomplete")])
def test_a_partial_sources_run_is_incomplete(status, want, monkeypatch):
    from backend.utilities.cbom_sources import run_list

    monkeypatch.setattr(run_list, "run_trigger", lambda run: "manual")
    counts = {"risk_data": {"total_critical": 0, "total_high": 1, "total_medium": 0, "total_low": 0},
              "asset_count": 1, "endpoints_probed": 0}
    jobs = {"sources": {}, "rows": [], "jobs_total": 1, "jobs_done": 1}
    row = run_list.run_row(_run(status), counts, jobs, None)
    assert row["risk_posture_status"] == want
    if want == "incomplete":
        assert (row["risk_score"], row["risk_grade"], row["risk_posture"]) == (None, None, None)
    else:
        assert row["risk_score"] == _posture(high=1)


def test_the_pdf_shows_the_unverified_score_note_and_rule(tmp_path):
    text = _pdf_text({"results": UNCONFIRMED_HIGH, "duration_of_scan": 1.0}, tmp_path)
    assert "A Risk score 0" not in text
    assert "unverified: 1 unconfirmed setting (worst: High)" in text
    assert "marked \"unverified\"" in text  # the methodology states the rule
