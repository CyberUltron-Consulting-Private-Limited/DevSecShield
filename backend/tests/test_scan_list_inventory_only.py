"""#46: an SCA + SBOM scan's inventoried packages are its SBOM, not Low vulnerabilities.

The worker stores every package Syft and cdxgen found next to the vulnerability rows (``_finalize_sbom``,
RabbitMQ/worker/scan_worker.py), each as ``impact: Low``, ``reachability: not_reachable``, ``inventory_only: true``
(merge_inventory.inventory_to_finding_rows), and every row also becomes a stored finding (create_findings.py). These
tests run the real list-item builder, the list dashboard and the per-scan dashboard on the issue's repro: one
vulnerable package and three packages with no known vulnerability (two of them under copyleft licenses). Mongo is
stubbed; nothing else is.
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest

from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.dashboard.scan import generate_scan_dashboard
from backend.utilities.dashboard.scan_list import generate_sbom_sca_dashboard_data
from backend.utilities.db.scan_list_item import return_sbom_sca_list_item

CREATED = dt.datetime(2026, 11, 16, 9, 30, tzinfo=dt.timezone.utc)

VULNERABLE = {
    "dependency": "acme-parser@2.1.0",
    "title": "Prototype pollution in acme-parser",
    "description": "Crafted input changes Object.prototype.",
    "impact": "High",
    "reachability": "reachable",
    "license_type": "weak_copyleft",
    "dependency_type": "direct",
    "cves": {"CVE-2026-0001": "Prototype pollution"},
    "owasp_top_10": {"0": "A06:2021 - Vulnerable and Outdated Components"},
    "compliance_controls": {"0": "PCI DSS - 6.3.3"},
    "suggested_fix": "Upgrade acme-parser to 2.1.1",
}


def _inventory(name: str, version: str, spdx: str, category: str) -> dict:
    # exactly what merge_inventory.inventory_to_finding_rows stores for a package with no known vulnerability
    return {
        "dependency": f"{name}=={version}",
        "title": f"Inventory: {name}",
        "description": f"Inventoried component {name}=={version}",
        "impact": "Low",
        "reachability": "not_reachable",
        "license": spdx,
        "license_type": category,
        "cves": {},
        "owasp_top_10": {},
        "compliance_controls": {},
        "suggested_fix": "n/a — inventory row",
        "dependency_type": "direct",
        "inventory_only": True,
        "vuln_assessed": True,
    }


CLEAN = [
    _inventory("left-pad", "1.3.0", "MIT", "permissive"),
    _inventory("gpl-thing", "4.0.0", "GPL-3.0-only", "strong_copyleft"),
    _inventory("agpl-thing", "0.9.1", "AGPL-3.0-only", "network_copyleft"),
]


def _scan(results: list[dict], status: str = "success", scan_id: int = 46) -> SimpleNamespace:
    return SimpleNamespace(
        id=scan_id, title="payments-api", scan_type="sbom_sca", scan_status=status, created_at=CREATED,
        last_updated=CREATED, credit_consumed=0.01, info=None,
        owner_user=SimpleNamespace(email="o@example.test", first_name="O", last_name="Wner"),
        scan_metadata={"repo_url": "https://github.com/acme/payments-api", "branch": "main"},
        scan_data={"results": results, "duration_of_scan": 1.0},
    )


def _findings(rows: list[dict], scan_id: int = 46) -> list[dict]:
    # every stored row becomes a not-started finding (create_findings.py, sbom_sca branch)
    return [{"scan_id": scan_id, "finding_data": dict(r), "finding_status": "not_started", "created_at": CREATED,
             "fixed_at": None, "ignored_at": None} for r in rows]


@pytest.fixture
def stored(monkeypatch: pytest.MonkeyPatch):
    """Mongo: the stored findings of the repro scan (1 vulnerability + 3 inventory rows)."""
    docs = _findings([VULNERABLE, *CLEAN])
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: list(docs))
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: list(docs))
    return docs


# ------------------------------------------------------------------------------------------------ list table row
def test_list_row_counts_the_vulnerable_package_only():
    item = return_sbom_sca_list_item(_scan([VULNERABLE, *CLEAN]))
    assert item["risk_data"] == {"total_critical": 0, "total_high": 1, "total_medium": 0, "total_low": 0}
    # the Risk score cell averages the one High vulnerability (0-10 scale, #35), not 1 High + 3 Low
    assert item["average_risk_score"] == 7.5


def test_list_row_without_a_vulnerability_has_no_risk_score():
    item = return_sbom_sca_list_item(_scan(list(CLEAN)))
    assert item["risk_data"] == {"total_critical": 0, "total_high": 0, "total_medium": 0, "total_low": 0}
    assert item["average_risk_score"] is None  # shown as "—" and kept out of every Risk score tier, not 0


# ------------------------------------------------------------------------------------------------ list dashboard
def test_list_dashboard_counts_vulnerabilities_not_inventory(stored):
    dash = generate_sbom_sca_dashboard_data([_scan([VULNERABLE, *CLEAN])])
    card = dash["card_data"]
    assert card["total_vulnerabilities"] == 1
    assert card["total_critical_vulnerabilities"] == 0
    assert card["total_reachable_issues"] == 1
    assert card["total_policy_violations"] == 1
    # license risks only from the vulnerable package (LGPL-like weak copyleft), not the clean GPL / AGPL packages
    assert card["total_license_risks"] == 1
    assert card["total_high_risk_licenses"] == 0
    assert card["average_risk_score"] == 7.5
    assert dash["severity_distribution"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert dash["reachability_distribution"] == {"not_reachable": 0, "potentially_reachable": 0, "reachable": 1,
                                                 "not_assessed": 0}
    assert dash["vulnerability_trends_over_time"] == {"2026-11-16": {"critical": 0, "high": 1, "medium": 0, "low": 0}}
    assert sum(dash["licenses_distribution"].values()) == 1
    assert dash["licenses_distribution"]["weak_copyleft"] == 1
    assert [t["dependency"] for t in dash["top_vulnerabilities_by_risk_score"]] == ["acme-parser@2.1.0"]
    assert dash["average_risk_score_per_reachability_level"] == {"reachable": 7.5, "potentially_reachable": 0.0,
                                                                 "not_reachable": 0.0, "not_assessed": 0.0}
    # the remediation card counts the stored vulnerability findings, not the three stored inventory rows
    assert dash["remediation_actions_required"]["total_findings"] == 1
    assert dash["remediation_actions_required"]["total_not_started"] == 1


def test_list_dashboard_with_inventory_only_scan_is_empty(monkeypatch: pytest.MonkeyPatch):
    docs = _findings(list(CLEAN))
    monkeypatch.setattr(scan_list_mod, "get_findings_for_scan_id", lambda *a, **k: list(docs))
    dash = generate_sbom_sca_dashboard_data([_scan(list(CLEAN))])
    assert dash["card_data"]["total_vulnerabilities"] == 0
    assert dash["card_data"]["total_license_risks"] == 0
    assert dash["card_data"]["average_risk_score"] == 0.0
    assert dash["severity_distribution"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert sum(dash["reachability_distribution"].values()) == 0
    assert dash["vulnerability_trends_over_time"] == {}
    assert dash["top_vulnerabilities_by_risk_score"] == []
    assert dash["remediation_actions_required"]["total_findings"] == 0


# ------------------------------------------------------------------------------------------------ per-scan dashboard
def test_results_dashboard_counts_vulnerabilities_not_inventory(stored):
    dash = generate_scan_dashboard("sbom_sca", scan_object=_scan([VULNERABLE, *CLEAN]))
    card = dash["card_data"]
    assert card["total_vulnerabilities"] == 1
    assert card["total_reachable_issues"] == 1
    assert card["total_license_risks"] == 1
    assert card["total_high_risk_licenses"] == 0
    assert card["average_risk_score"] == 7.5
    assert dash["severity_distribution"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert dash["reachability_distribution"] == {"not_reachable": 0, "potentially_reachable": 0, "reachable": 1,
                                                 "not_assessed": 0}
    assert dash["vulnerability_trends_over_time"] == {"2026-11-16": {"critical": 0, "high": 1, "medium": 0, "low": 0}}
    assert sum(dash["licenses_distribution"].values()) == 1
    assert [t["dependency"] for t in dash["top_vulnerabilities_by_risk_score"]] == ["acme-parser@2.1.0"]
    assert dash["remediation_actions_required"]["total_findings"] == 1
