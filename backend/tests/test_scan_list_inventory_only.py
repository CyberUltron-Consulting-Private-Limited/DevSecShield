"""#46: an SCA + SBOM scan's inventoried packages are its SBOM, not Low vulnerabilities.

The worker stores every package Syft and cdxgen found next to the vulnerability rows (``_finalize_sbom``,
RabbitMQ/worker/scan_worker.py), each as ``impact: Low``, ``reachability: not_reachable``, ``inventory_only: true``
(merge_inventory.inventory_to_finding_rows), and every row also becomes a stored finding (create_findings.py). These
tests run the real list-item builder, the list dashboard, the per-scan dashboard, the results API's findings, the team
dashboard, Jira's ticket candidates and the SBOM PDF on the issue's repro: one vulnerable package and three packages
with no known vulnerability (two of them under copyleft licenses). Mongo is stubbed; nothing else is. The inventory
stays in the bill of materials (the results page's Bill of materials table and the CycloneDX download read
``sbom_json``, which these tests do not touch) and in the PDF's own package list.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlmodel import Session, SQLModel, create_engine

from backend.utilities.dashboard import scan as scan_mod
from backend.utilities.dashboard import scan_list as scan_list_mod
from backend.utilities.dashboard.scan import generate_scan_dashboard
from backend.utilities.dashboard.scan_list import generate_sbom_sca_dashboard_data
from backend.utilities.db import findings as findings_mod
from backend.utilities.db.scan_list_item import return_sbom_sca_list_item

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pdf_export_smoke import _pdf_haystack  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
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
    # review 6028132826 M4: license risk is counted over the SBOM's packages (the weak-copyleft vulnerable one and
    # the clean GPL / AGPL ones), not over the vulnerability rows
    assert card["total_license_risks"] == 3
    assert card["total_high_risk_licenses"] == 2
    assert card["average_risk_score"] == 7.5
    assert dash["severity_distribution"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert dash["reachability_distribution"] == {"not_reachable": 0, "potentially_reachable": 0, "reachable": 1,
                                                 "not_assessed": 0}
    assert dash["vulnerability_trends_over_time"] == {"2026-11-16": {"critical": 0, "high": 1, "medium": 0, "low": 0}}
    assert sum(dash["licenses_distribution"].values()) == 4  # one per package (M4)
    assert dash["licenses_distribution"]["weak_copyleft"] == 1
    assert dash["licenses_distribution"]["strong_copyleft"] == 1
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
    assert dash["card_data"]["total_license_risks"] == 2  # the GPL and AGPL packages (M4: over the packages)
    assert dash["card_data"]["average_risk_score"] is None  # the average of no vulnerability: the card shows "—"
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
    assert card["total_license_risks"] == 3  # over the SBOM's packages (review 6028132826 M4)
    assert card["total_high_risk_licenses"] == 2
    assert card["average_risk_score"] == 7.5
    assert dash["severity_distribution"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert dash["reachability_distribution"] == {"not_reachable": 0, "potentially_reachable": 0, "reachable": 1,
                                                 "not_assessed": 0}
    assert dash["vulnerability_trends_over_time"] == {"2026-11-16": {"critical": 0, "high": 1, "medium": 0, "low": 0}}
    assert sum(dash["licenses_distribution"].values()) == 4
    assert [t["dependency"] for t in dash["top_vulnerabilities_by_risk_score"]] == ["acme-parser@2.1.0"]
    assert dash["remediation_actions_required"]["total_findings"] == 1


def test_results_dashboard_without_a_vulnerability_has_no_average(monkeypatch: pytest.MonkeyPatch):
    docs = _findings(list(CLEAN))
    monkeypatch.setattr(scan_mod, "get_findings_for_scan_id", lambda *a, **k: list(docs))
    card = generate_scan_dashboard("sbom_sca", scan_object=_scan(list(CLEAN)))["card_data"]
    assert card["total_vulnerabilities"] == 0
    assert card["average_risk_score"] is None  # the average of no vulnerability: the card shows "—"


@pytest.mark.parametrize("source", ["frontend/components/SbomResults.tsx", "frontend/app/[team_id]/sbom_sca/page.tsx"])
def test_the_avg_risk_cards_show_a_dash_without_a_vulnerability(source):
    """Both Risk score cards (results page, list dashboard) show the one 0-100 score (risk_posture) through the shared
    util, which writes "—" when the backend sent none. A successful scan without a known vulnerability has a score:
    0 · A (Low risk), as on its row and in its PDF (the 0-10 average_risk_score stays None on the API, #46)."""
    text = (REPO / source).read_text(encoding="utf-8")
    assert re.search(r"\{riskScoreText\(postureOf\(card\)\)\}", text), source
    util = (REPO / "frontend" / "utils" / "riskPosture.ts").read_text(encoding="utf-8")
    assert 'return p ? `${p.score} · ${p.grade}` : "—";' in util


# ------------------------------------------------------------------------------------------------ stored findings
class _FindingsCollection:
    """Mongo's scan_findings collection, as much as get_findings_for_scan_id uses (find by scan_id)."""

    def __init__(self, docs: list[dict]):
        self.docs = docs

    def find(self, query: dict | None = None) -> list[dict]:
        return [d for d in self.docs if all(d.get(k) == v for k, v in (query or {}).items())]


@pytest.fixture
def mongo(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """The repro's stored findings behind the real read path (findings.get_findings_for_scan_id)."""
    docs = [{"_id": f"finding-{i}", **doc} for i, doc in enumerate(_findings([VULNERABLE, *CLEAN]))]
    monkeypatch.setattr(findings_mod, "get_mongo_client_db", lambda: {"scan_findings": _FindingsCollection(docs)})
    return docs


def test_inventory_rows_are_not_findings():
    assert findings_mod.is_ticketable_finding("sbom_sca", VULNERABLE)
    assert not any(findings_mod.is_ticketable_finding("sbom_sca", row) for row in CLEAN)


def test_results_api_lists_the_vulnerability_not_the_inventory(mongo):
    # the results page's Findings table, its count, its Impact and Risk score filters and its Jira row selection
    rows = findings_mod.get_findings_for_scan_type("sbom_sca", 46)
    assert [r["dependency"] for r in rows] == ["acme-parser@2.1.0"]
    # nothing is deleted: the stored rows (and any status set on them) are only not shown
    assert len(findings_mod.get_findings_for_scan_id(46)) == 4


def test_jira_does_not_ticket_packages_with_no_known_vulnerability(mongo):
    from backend.utilities.integrations.jira_ticketing import jira_candidates

    assert [d["finding_data"]["dependency"] for d in jira_candidates("sbom_sca", mongo)] == ["acme-parser@2.1.0"]


def test_team_dashboard_counts_vulnerabilities_not_inventory(mongo, tmp_path):
    from backend.new_models import Scan, Team, User
    from backend.utilities.dashboard.team import generate_team_dashboard_data

    mongo[0].update(finding_status="fixed", fixed_at=CREATED)  # the vulnerability is fixed; nothing else is to fix
    engine = create_engine(f"sqlite:///{tmp_path / 'team.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    repro = _scan([VULNERABLE, *CLEAN])
    with Session(engine) as session:
        session.add(Team(id=1, name="Payments", credit_balance=10.0))
        session.commit()
        session.add(User(id=1, email="o@example.test", password="x", first_name="O", last_name="Wner",
                         profile_photo=None, session_active=True, default_team_id=1))
        session.commit()
        session.add(Scan(id=46, team_id=1, owner_user_id=1, scan_type="sbom_sca", title=repro.title,
                         scan_status="success", created_at=CREATED, last_updated=CREATED,
                         scan_metadata=repro.scan_metadata, scan_data=repro.scan_data))
        session.commit()
    dash = generate_team_dashboard_data(1, engine)
    assert dash["card_data"]["total_findings"] == 1
    assert dash["card_data"]["total_fixed_findings"] == 1
    assert dash["card_data"]["remediation_percentage"] == 100.0  # not 25.0 (1 fixed of 4 rows)
    assert dash["findings_per_day"] == {"2026-11-16": 1}
    assert dash["remediations_status_distribution"]["2026-11-16"]["not_started"] == 0


# ------------------------------------------------------------------------------------------------ SBOM PDF
# an inventory row parser.apply_grype_cves gave Grype's CVE ids: a known vulnerability, so not in the clean list
GRYPE_MATCHED = {**_inventory("minimist", "1.2.5", "MIT", "permissive"), "purl": "pkg:npm/minimist@1.2.5",
                 "cves": {"CVE-2021-44906": "Prototype pollution in minimist"}}


def test_pdf_counts_vulnerabilities_and_lists_the_other_packages(monkeypatch: pytest.MonkeyPatch, tmp_path):
    from backend.utilities.pdf import sbom_sca_pdf

    seen: dict = {}
    summary, catalog = sbom_sca_pdf.append_executive_summary, sbom_sca_pdf.append_findings_catalog

    def spy_summary(story, **kw):
        seen.update(overview=dict(kw["overview_rows"]), severity=dict(kw["severity_counts"]))
        return summary(story, **kw)

    def spy_catalog(story, **kw):
        seen["catalog"] = len(kw["catalog_rows"])
        return catalog(story, **kw)

    monkeypatch.setattr(sbom_sca_pdf, "append_executive_summary", spy_summary)
    monkeypatch.setattr(sbom_sca_pdf, "append_findings_catalog", spy_catalog)
    clean = [{**CLEAN[0], "purl": "pkg:npm/left-pad@1.3.0"}, *CLEAN[1:]]
    out = tmp_path / "sbom.pdf"
    sbom_sca_pdf.generate_pdf({"duration_of_scan": 1.0, "results": [VULNERABLE, *clean, GRYPE_MATCHED]}, str(out))

    assert seen["overview"]["Total vulnerabilities"] == "1"
    assert seen["overview"]["Packages affected"] == "1"
    assert seen["overview"]["Risk score"] == "20 / 100 · grade B · Moderate risk"  # one High (risk_scale.posture)
    assert seen["severity"] == {"High": 1}
    assert seen["catalog"] == 1  # the findings catalog and Detailed Findings: the vulnerability only
    text = _pdf_haystack(str(out))
    assert "Inventory: left-pad" not in text and "No CVE recorded for this component" not in text
    # the PDF stays a complete bill of materials: one line per other package, name, version, ecosystem, licence
    assert "Packages with no known vulnerability" in text
    for needle in ("left-pad", "1.3.0", "npm", "MIT", "gpl-thing", "4.0.0", "GPL-3.0-only", "agpl-thing",
                   "AGPL-3.0-only"):
        assert needle in text, needle
    assert "Inventoried packages with CVE ids from Grype" in text
    assert "minimist" in text and "CVE-2021-44906" in text


def test_results_page_without_stored_findings_skips_inventory_rows():
    """With no stored finding the page lists the scan's own result rows instead: those leave the inventory out too."""
    text = (REPO / "frontend/components/SbomResults.tsx").read_text(encoding="utf-8")
    assert re.search(r"const vulnerabilities = \(Array\.isArray\(data\) \? data : \[\]\)\.filter\(\(row\) => "
                     r"!\(row as \{ inventory_only\?: unknown \} \| null\)\?\.inventory_only\)", text)
