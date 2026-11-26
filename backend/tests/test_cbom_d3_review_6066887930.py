"""PR #500 re-review 6066887930 (backend, round 8): the contract #505 builds on (#500 merges first).

``risk_unverified`` = ``{"kind": "unconfirmed_setting", "count", "worst", "worst_case": {score, grade, label, band},
"note"}`` on every CBOM surface, and one public counting helper, ``cbom_metrics.unverified_counts(rows)``: the
worst-case severity counts of a scan's unconfirmed settings (test code and clean inventory never counted), the
numbers #505's team roll-up and Board Report read.
"""
from __future__ import annotations

from tests.test_cbom_d3_review_6063599094 import TEST_ONLY, _row
from tests.test_cbom_d3_review_6064703319 import _surfaces
from tests.test_cbom_d3_review_6066152368 import CONFIRMED_LOW, UNCONFIRMED_HIGH

CLEAN_UNCONFIRMED = [{"title": "AES-256-GCM", "algorithm_name": "AES-256-GCM", "impact": None, "finding_codes": [],
                      "weak": False, "crypto_strength": "strong", "location": "app/conf.py",
                      "config_status": "unconfirmed", "confidence": "low", "config_binding": "cipher"}]
OLD_ROW = [_row("SHA-1", "Medium", "app/old.py", config_status="unconfirmed", confidence="low")]


def test_unverified_counts_is_the_public_worst_case_counter():
    from backend.utilities.cbom_sources.cbom_metrics import unverified_counts

    rows = CONFIRMED_LOW + UNCONFIRMED_HIGH + TEST_ONLY + CLEAN_UNCONFIRMED + OLD_ROW
    assert unverified_counts(rows) == {"critical": 0, "high": 1, "medium": 1, "low": 0}
    assert unverified_counts([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert unverified_counts([None, "x", {"config_status": "unconfirmed", "finding_codes": []}]) == {
        "critical": 0, "high": 0, "medium": 0, "low": 0}


def test_the_summary_counts_with_the_public_helper():
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows, unverified_counts

    rows = CONFIRMED_LOW + UNCONFIRMED_HIGH + OLD_ROW
    assert summarize_code_rows(rows).unverified == unverified_counts(rows)


def test_risk_unverified_has_the_contract_shape_on_every_surface(monkeypatch):
    for name, s in _surfaces(CONFIRMED_LOW + UNCONFIRMED_HIGH, "success", monkeypatch).items():
        unverified = s["risk_unverified"]
        assert set(unverified) == {"kind", "count", "worst", "worst_case", "note"}, name
        assert unverified["kind"] == "unconfirmed_setting", name
        assert set(unverified["worst_case"]) == {"score", "grade", "label", "band"}, name
