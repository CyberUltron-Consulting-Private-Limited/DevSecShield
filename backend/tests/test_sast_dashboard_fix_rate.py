"""#36: the SAST dashboard's "Fix rate" was the hard-coded text "0% Fix Rate". The list dashboard now sends the two
numbers it is made of: the findings marked Fixed and all stored findings of the team's SAST scans (the same findings
the Remediation Metrics section reads). A SAST finding becomes fixed only when someone marks it Fixed on the scan's
results page (routers/scans.py -> finding_state.mark_finding_fixed); the re-scan path that also marks findings fixed
(cbom_sources/drift.on_code_scan_success) runs for CBOM scans only. Ignored and in-progress findings are not fixed.
Mongo is stubbed; nothing else is.
Failing-first on origin/dev dd9c2293: the dashboard had no "fixed_findings" or "total_findings" key.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.dashboard.scan_list import generate_sast_dashboard_data

REPO = Path(__file__).resolve().parents[2]
CREATED = dt.datetime(2026, 11, 16, 9, 30, tzinfo=dt.timezone.utc)
FIXED_AT = dt.datetime(2026, 11, 16, 12, 0, tzinfo=dt.timezone.utc)


def _vulnerability(title: str, impact: str) -> dict:
    return {"title": title, "impact": impact, "owasp_top_10": {"0": "A03:2021 - Injection"},
            "compliance_controls": {"0": "PCI DSS - 6.2.4"}}


VULNERABILITIES = [_vulnerability("SQL injection", "Critical"), _vulnerability("XSS", "High"),
                   _vulnerability("Weak hash", "Medium"), _vulnerability("Verbose error", "Low")]


def _scan(scan_id: int, status: str = "success", vulnerabilities: list[dict] | None = None) -> SimpleNamespace:
    results = [{"logical_component_title": "api", "vulnerabilities": list(vulnerabilities or [])}]
    return SimpleNamespace(
        id=scan_id, title=f"scan {scan_id}", scan_type="sast", scan_status=status, created_at=CREATED,
        last_updated=CREATED, info=None,
        scan_metadata={"repo_url": "https://github.com/acme/payments-api", "app_lang": "python"},
        scan_data={"results": results} if status == "success" else {},
    )


def _finding(scan_id: int, vulnerability: dict, status: str) -> dict:
    # what create_findings.py stores for each SAST vulnerability, after a status change on the results page
    return {"scan_id": scan_id, "finding_data": dict(vulnerability), "finding_status": status, "created_at": CREATED,
            "fixed_at": FIXED_AT if status == "fixed" else None,
            "ignored_at": FIXED_AT if status == "ignored" else None}


def _stub(monkeypatch: pytest.MonkeyPatch, by_scan: dict[int, list[dict]]) -> None:
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id",
                        lambda scan_id=None, *a, **k: list(by_scan.get(scan_id, [])))


def test_fixed_and_all_findings_are_counted(monkeypatch: pytest.MonkeyPatch):
    statuses = ["fixed", "ignored", "in_progress", "not_started"]
    _stub(monkeypatch, {
        7: [_finding(7, v, s) for v, s in zip(VULNERABILITIES, statuses)],
        8: [_finding(8, VULNERABILITIES[0], "fixed"), _finding(8, VULNERABILITIES[1], "not_started")],
    })
    data = generate_sast_dashboard_data([_scan(7, vulnerabilities=VULNERABILITIES),
                                         _scan(8, vulnerabilities=VULNERABILITIES[:2]), _scan(9, "failure")])
    assert data["fixed_findings"] == 2, "fixed: one in each scan; ignored and in progress are not fixed"
    assert data["total_findings"] == 6, "every stored finding of the team's SAST scans"
    # the Remediation Metrics section reads the same findings: both fixed ones are the Critical SQL injection
    assert data["remediation_metrics"]["critical_issues_fixed"] == 2


def test_no_findings_gives_zero_of_zero(monkeypatch: pytest.MonkeyPatch):
    _stub(monkeypatch, {})
    data = generate_sast_dashboard_data([_scan(7, "failure"), _scan(8, "pending")])
    assert (data["fixed_findings"], data["total_findings"]) == (0, 0), "the page shows a dash, not 0%"
    assert generate_sast_dashboard_data([])["total_findings"] == 0


def test_only_the_manual_toggle_marks_a_sast_finding_fixed():
    # what the tooltip on the page says counts as fixed must stay true
    drift = (REPO / "backend" / "utilities" / "cbom_sources" / "drift.py").read_text(encoding="utf-8")
    start = drift[drift.index("def on_code_scan_success"):]
    assert 'scan.scan_type != "cbom"' in start[:1500], "the re-scan auto-fix now also runs for SAST: update the tooltip"
    scans = (REPO / "backend" / "routers" / "scans.py").read_text(encoding="utf-8")
    assert 'if data.state == "fixed":' in scans and "mark_finding_fixed(scan_findings_collection, target_finding" in scans
