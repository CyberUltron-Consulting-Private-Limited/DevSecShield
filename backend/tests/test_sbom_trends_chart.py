"""SBOM dashboard: vulnerability_trends_over_time keyed by finding created_at.

Hermetic — stubs Mongo findings; runs real generate_scan_dashboard sbom_sca branch.
"""

from __future__ import annotations

import os
import sys
import types
from datetime import datetime, timezone

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard import scan as scan_mod  # noqa: E402
from backend.utilities.dashboard.scan import (  # noqa: E402
    _to_date_key,
    generate_scan_dashboard,
)


def _result_row(*, impact: str = "high", dependency: str = "pkg==1.0") -> dict:
    return {
        "dependency": dependency,
        "title": f"Finding {dependency}",
        "description": "test",
        "impact": impact,
        "reachability": "not_reachable",
        "license_type": "permissive",
        "dependency_type": "direct",
        "cves": {},
        "compliance_controls": {},
        "owasp_top_10": {},
        "suggested_fix": "n/a",
    }


def test_to_date_key_datetime_and_string() -> None:
    dt = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
    assert _to_date_key(dt) == "2026-08-09"
    assert _to_date_key("2026-08-09T15:00:00Z") == "2026-08-09"
    assert _to_date_key(None) is None


def test_sbom_trends_populated_from_created_at(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = [
        {
            "finding_data": {"impact": "critical", "title": "a"},
            "finding_status": "not_started",
            "created_at": datetime(2026, 8, 8, tzinfo=timezone.utc),
            "fixed_at": None,
            "ignored_at": None,
        },
        {
            "finding_data": {"impact": "high", "title": "b"},
            "finding_status": "not_started",
            "created_at": "2026-08-08T10:00:00Z",
            "fixed_at": None,
            "ignored_at": None,
        },
        {
            "finding_data": {"impact": "low", "title": "c"},
            "finding_status": "not_started",
            "created_at": datetime(2026, 8, 9, tzinfo=timezone.utc),
            "fixed_at": None,
            "ignored_at": None,
        },
    ]
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: findings)
    monkeypatch.setattr(
        scan_mod,
        "get_issue_status_metrics",
        lambda *a, **k: {
            "fixed": 0,
            "in_progress": 0,
            "not_started": 3,
            "ignored": 0,
        },
    )

    fake = types.SimpleNamespace(
        id=72,
        scan_data={
            "results": [
                _result_row(impact="critical"),
                _result_row(impact="high"),
                _result_row(impact="low"),
            ],
            "duration_of_scan": 1.0,
        },
    )
    dash = generate_scan_dashboard("sbom_sca", scan_object=fake)
    trends = dash["vulnerability_trends_over_time"]
    assert trends, "trends empty — chart would show No findings yet"
    assert list(trends.keys()) == ["2026-08-08", "2026-08-09"]
    assert trends["2026-08-08"]["critical"] == 1
    assert trends["2026-08-08"]["high"] == 1
    assert trends["2026-08-09"]["low"] == 1
    # Fresh not_started findings still produce data (no Fixed/Ignored required)
    assert sum(sum(v.values()) for v in trends.values()) == 3


def test_sbom_trends_empty_without_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(
        scan_mod,
        "get_issue_status_metrics",
        lambda *a, **k: {
            "fixed": 0,
            "in_progress": 0,
            "not_started": 0,
            "ignored": 0,
        },
    )
    fake = types.SimpleNamespace(id=1, scan_data={"results": [], "duration_of_scan": 0.1})
    dash = generate_scan_dashboard("sbom_sca", scan_object=fake)
    assert dash["vulnerability_trends_over_time"] == {}
