"""One scan, one set of numbers: every CBOM surface counts the same findings.

The fixture is the product run-object the worker stores for the synthetic crypto app (``aibom`` engine at level 4,
regenerate with ``aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield``): 13 rows, of which 7 carry a
finding code and 6 are clean inventory (AES-GCM, SHA-256, a certificate, key material ...).

The same finding count, severity split and quantum readiness must come out of: the scan dashboard, the scan-list
item, the multi-scan dashboard, the scan PDF, the team roll-up, the Mongo findings read path, the Jira candidate
lists (scan and CI), the CI page, the CycloneDX JSON export and its XML form.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_deliverable_common import pdf_full_text  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cbom_consistency_scan.json"
SEVERITIES = ("critical", "high", "medium", "low")
SCAN_ID = 4242


class _Collection:
    def __init__(self) -> None:
        self.docs: list[dict] = []

    def delete_many(self, query: dict) -> SimpleNamespace:
        before = len(self.docs)
        self.docs = [d for d in self.docs if not all(d.get(k) == v for k, v in query.items())]
        return SimpleNamespace(deleted_count=before - len(self.docs))

    def insert_many(self, docs: list[dict]) -> None:
        for doc in docs:
            self.docs.append({**doc, "_id": f"oid{len(self.docs)}"})

    def find(self, query: dict) -> list[dict]:
        return [d for d in self.docs if all(d.get(k) == v for k, v in query.items())]


class FakeMongo(dict):
    def __missing__(self, key: str) -> _Collection:
        self[key] = _Collection()
        return self[key]


@pytest.fixture(scope="module")
def run() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def expected(run) -> dict:
    flagged = [r for r in run["results"] if r["finding_codes"]]
    assert len(run["results"]) == 13 and len(flagged) == 7  # the fixture this file documents
    severity = Counter(str(r["impact"]).lower() for r in flagged)
    return {"findings": len(flagged), "inventory": len(run["results"]) - len(flagged),
            "severity": {s: severity.get(s, 0) for s in SEVERITIES}}


@pytest.fixture()
def mongo(monkeypatch, run) -> FakeMongo:
    from backend.utilities.celery.create_findings import create_findings_in_mongo_db
    from backend.utilities.db import findings as findings_mod

    db = FakeMongo()
    create_findings_in_mongo_db(scan_id=SCAN_ID, scan_results=run, scan_type="cbom", mongo_db=db)
    assert len(db["scan_findings"].docs) == 13  # every row is stored; the filter is on READ
    monkeypatch.setattr(findings_mod, "get_mongo_client_db", lambda: db)
    return db


def _scan(run: dict) -> SimpleNamespace:
    owner = SimpleNamespace(email="a@example.test", first_name="A", last_name="B")
    now = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
    return SimpleNamespace(id=SCAN_ID, scan_data=run, scan_status="success", scan_metadata={"zip_file_used": True},
                           title="t", created_at=now, last_updated=now, credit_consumed=1.0, info=None,
                           owner_user=owner)


def _severity(d: dict) -> dict:
    return {s: int(d.get(s, 0) or 0) for s in SEVERITIES}


def test_dashboard_counts_findings_only(run, expected, mongo):
    from backend.utilities.dashboard.scan import generate_scan_dashboard

    dash = generate_scan_dashboard(scan_type="cbom", scan_object=_scan(run))
    assert dash["card_data"]["total_crypto_vulnerabilities"] == expected["findings"]
    assert dash["card_data"]["total_informational"] == expected["inventory"]
    assert _severity(dash["severity_distribution"]) == expected["severity"]
    assert dash["severity_distribution"]["informational"] == expected["inventory"]
    assert dash["remediation_actions_required"]["total_findings"] == expected["findings"]  # Mongo read path
    assert len(dash["top_risks"]) == expected["findings"]
    assert all(r["risk_score"] > 0 for r in dash["top_risks"])
    # inventory distributions still cover every row (a CBOM lists everything)
    assert sum(dash["algorithm_type_distribution"].values()) == len(run["results"])


def test_list_item_and_multi_scan_dashboard_agree(run, expected, mongo):
    from backend.utilities.dashboard.scan_list import generate_cbom_dashboard_data
    from backend.utilities.db.scan_list_item import return_cbom_list_item

    item = return_cbom_list_item(_scan(run))
    risk = item["risk_data"]
    assert {s: risk[f"total_{s}"] for s in SEVERITIES} == expected["severity"]
    assert risk["total_informational"] == expected["inventory"]
    multi = generate_cbom_dashboard_data([_scan(run)])
    assert multi["card_data"]["total_crypto_vulnerabilities"] == expected["findings"]
    assert _severity(multi["severity_distribution"]) == expected["severity"]
    assert multi["remediation_actions_required"]["total_findings"] == expected["findings"]
    single = __import__("backend.utilities.dashboard.scan", fromlist=["x"]).generate_scan_dashboard(
        scan_type="cbom", scan_object=_scan(run))
    for key in ("average_risk_score", "quantum_readiness_score", "total_weak_algorithms", "total_quantum_vulnerable",
                "total_crypto_assets", "total_crypto_vulnerabilities", "total_informational", "total_certificates",
                "total_keys", "quantum_readiness_judged"):
        assert item.get(key, multi["card_data"][key]) == multi["card_data"][key] == single["card_data"][key], key
    # rev4 M2: "Crypto assets" is the inventory rows on every surface (findings + informational), not the CycloneDX
    # component count (17 here: it also lists the 4 crypto libraries the files import)
    assert len(run["cbom_json"]["components"]) == 17
    assert single["card_data"]["total_crypto_assets"] == len(run["results"]) == expected["findings"] + expected["inventory"]


def test_mongo_read_path_lists_findings_only(run, expected, mongo):
    from backend.utilities.db.findings import get_findings_for_scan_id, get_findings_for_scan_type

    listed = get_findings_for_scan_type("cbom", SCAN_ID)
    assert len(listed) == expected["findings"]
    assert all(f["finding_codes"] for f in listed)
    assert len(get_findings_for_scan_id(SCAN_ID)) == 13  # raw read (no type) still sees every stored row


def test_jira_candidates_are_the_findings(run, expected, mongo):
    from backend.utilities.integrations.jira_ticketing import flatten_scan_result_rows, jira_candidates

    docs = mongo["scan_findings"].find({"scan_id": SCAN_ID})
    assert len(jira_candidates("cbom", docs)) == expected["findings"]
    assert len(flatten_scan_result_rows("cbom", run)) == expected["findings"]  # CI auto-tickets
    assert len(jira_candidates("sast", [{"finding_data": {}}])) == 1  # other scan types are untouched


def test_ci_page_lists_the_same_findings(run, expected, mongo):
    from backend.utilities.cicd.cbom_page import project_cbom_ci_page

    page = project_cbom_ci_page(run)
    assert len(page["findings"]) == expected["findings"]
    assert page["dashboard"]["remediation_actions_required"]["total_findings"] == expected["findings"]
    assert page["dashboard"]["card_data"]["total_crypto_vulnerabilities"] == expected["findings"]


def test_pdf_prints_the_same_numbers(run, expected, tmp_path):
    from backend.utilities.pdf.cbom_pdf import generate_pdf

    out = generate_pdf(run, str(tmp_path / "cbom.pdf"))
    text = re.sub(r"\s+", " ", pdf_full_text(Path(out).read_bytes()))
    assert f"TOTAL FINDINGS {expected['findings']}" in text and f"Total Issues {expected['findings']}" in text
    sev = expected["severity"]
    assert f"{sev['critical']} C · {sev['high']} H · {sev['medium']} M · {sev['low']} L" in text
    assert f"Cryptographic findings {expected['findings']}" in text
    assert f"Informational / Inventory (no finding) {expected['inventory']}" in text
    assert f"Findings Catalog {expected['findings']} issues" in text
    # one detail card per finding (the clean rows have none)
    assert text.count("Where it was found") == expected["findings"]


def test_team_rollup_counts_the_same_issues(run, expected):
    from backend.utilities.dashboard.cbom_team_rollup import ScanHead, fold_scans

    now = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
    head = ScanHead(id=SCAN_ID, team_id=1, scan_type="cbom", title="t", status="success", created_at=now,
                    last_updated=now, scan_metadata={"zip_file_used": False, "repo_url": "https://github.com/o/r",
                                                     "branch": "main"})
    view = fold_scans([head], lambda ids: {i: run for i in ids}, team_id=1, team_name="T", now=now)
    issues = {s: view.issue_by_impact.get(s.capitalize(), 0) for s in SEVERITIES}
    assert issues == expected["severity"]
    assert view.assets_by_impact.get("Info", 0) == expected["inventory"]
    assert "Low" not in view.assets_by_impact or expected["severity"]["low"]
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows

    assert view.readiness_pct == summarize_code_rows(run["results"]).readiness_pct


# rows the pre-reconcile worker stored: no finding_codes, certificates and keys graded quantum_safe False
LEGACY_ROWS = [
    {"algorithm_name": "RSA-2048", "algorithm_type": "pke", "quantum_safe": False, "crypto_strength": "strong",
     "impact": "Medium", "location": "a.py"},
    {"algorithm_name": "server.crt", "algorithm_type": "certificate", "quantum_safe": False, "crypto_strength": "strong",
     "impact": "Medium", "location": "certs/server.crt"},
    {"algorithm_name": "id_rsa", "algorithm_type": "key", "quantum_safe": False, "crypto_strength": "strong",
     "impact": "High", "location": "keys/id_rsa"},
    {"algorithm_name": "AES-256-GCM", "algorithm_type": "block-cipher", "quantum_safe": True,
     "crypto_strength": "quantum_safe", "impact": "Low", "location": "b.py"},
    {"algorithm_name": "DES", "algorithm_type": "block-cipher", "impact": "Severe", "location": "c.py"},
]


def test_team_rollup_agrees_with_the_scan_page_for_legacy_rows():
    """rev4 M3: for a legacy scan the scan page, list and PDF said 4 findings and 25.0 % readiness while the team
    roll-up (and its roadmap / board PDFs) said no issues and 50.0 % (readiness over algorithm rows only, issues only
    with finding codes). The roll-up now reads cbom_metrics.finding_severity / code_row_quantum_vulnerable."""
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows
    from backend.utilities.dashboard.cbom_team_rollup import ScanHead, fold_scans

    now = dt.datetime(2026, 11, 5, tzinfo=dt.timezone.utc)
    head = ScanHead(id=1, team_id=7, scan_type="cbom", title="t", status="success", created_at=now,
                    last_updated=now, scan_metadata={"repo_url": "https://example.com/r.git", "branch": "main"})
    run = {"results": LEGACY_ROWS}
    view = fold_scans([head], lambda ids: {i: run for i in ids}, team_id=7, team_name="T", now=now)
    summary = summarize_code_rows(LEGACY_ROWS)
    assert summary.readiness_pct == 25.0 and summary.findings == 5  # the scan page's numbers
    assert view.readiness_pct == summary.readiness_pct
    assert (view.pqc_vulnerable, view.pqc_safe) == (summary.quantum["quantum_vulnerable"], summary.quantum["quantum_safe"])
    assert {s: view.issue_by_impact.get(s.capitalize(), 0) for s in SEVERITIES} == summary.severity
    assert sum(view.issue_by_impact.values()) == summary.findings
    assert view.pqc_ungraded == 1  # DES: an algorithm with no verdict


def test_cyclonedx_json_and_xml_carry_the_same_findings(run, expected):
    from lxml import etree

    from backend.utilities.cbom_sources.cdx_xml import NS, to_xml, validate_xml

    bom = run["cbom_json"]
    flagged = [c for c in bom["components"]
               if any(p["name"] == "zs:finding_code" for p in c.get("properties") or [])]
    assert len(flagged) == expected["findings"]
    xml = to_xml(bom, strict=True)
    assert validate_xml(xml) == []
    doc = etree.fromstring(xml)
    ns = {"c": NS}
    xml_flagged = [c for c in doc.findall(".//c:components/c:component", ns)
                   if c.find("c:properties/c:property[@name='zs:finding_code']", ns) is not None]
    assert len(xml_flagged) == expected["findings"]
    impacts = Counter(p.text for p in doc.findall(".//c:property[@name='zs:impact']", ns))
    json_impacts = Counter(p["value"] for c in bom["components"] for p in c.get("properties") or []
                           if p["name"] == "zs:impact")
    assert impacts == json_impacts and impacts["Info"] >= expected["inventory"]
    assert sum(n for k, n in impacts.items() if k != "Info") == expected["findings"]


def test_one_quantum_readiness_definition_everywhere(run, mongo):
    from backend.utilities.cbom_sources.cbom_metrics import quantum_readiness_pct, summarize_code_rows
    from backend.utilities.dashboard.scan import generate_scan_dashboard

    summary = summarize_code_rows(run["results"])
    dash = generate_scan_dashboard(scan_type="cbom", scan_object=_scan(run))
    assert dash["card_data"]["quantum_readiness_score"] == (summary.readiness_pct or 0)
    # the definition: share of JUDGED assets that are not quantum-vulnerable; unknown is excluded, none judged = None
    assert quantum_readiness_pct(1, 4) == 75.0 and quantum_readiness_pct(0, 0) is None
    assert quantum_readiness_pct(4, 4) == 0.0 and quantum_readiness_pct(9, 4) == 0.0
