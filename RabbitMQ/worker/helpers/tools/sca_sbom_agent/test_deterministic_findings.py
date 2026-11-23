"""FIX-C1 (SOW D4, audit G-X-2): SBOM vulnerability findings come from Grype, deterministically.

Staging scan #14 failed because the Bedrock token was invalid: the LLM map-reduce was the only source of findings
and any LLM error failed the scan. These tests pin the new contract:
* every Grype match becomes exactly one finding row (one per advisory, package and version), same order every run;
* an LLM failure (any exception) never fails the scan and never drops a row;
* LLM enrichment, when it works, only adds mappings; it never adds, drops or re-rates a finding.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[4]
if str(_REPO_ROOT / "aibom" / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "aibom" / "src"))

FIXTURE = json.loads((_HERE / "fixtures" / "grype-vulnerable-flask-app.json").read_text())
# 8 matches in the fixture; the last repeats the first (grype reports some advisories twice)
EXPECTED_IDS = {
    ("GHSA-xqr8-7jwr-rhp7", "certifi==2017.4.17"),
    ("GHSA-m2qf-hxjv-5gpq", "flask==0.12.2"),
    ("GHSA-68rp-wp8r-4726", "flask==0.12.2"),
    ("GHSA-x7m3-jprg-wc5g", "gevent==1.2.2"),
    ("GHSA-jjg7-2v4v-x38h", "idna==2.5"),
    ("GHSA-462w-v97r-4m45", "jinja2==2.9.6"),
    ("GHSA-q2x7-8rv6-6q7h", "jinja2==2.9.6"),
}


def _inventory(tmp: Path) -> Path:
    comps = [
        {"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}", "bom-ref": f"syft-{i}"}
        for i, (n, v) in enumerate([("certifi", "2017.4.17"), ("flask", "0.12.2"), ("gevent", "1.2.2"),
                                    ("idna", "2.5"), ("jinja2", "2.9.6"), ("click", "8.1.0")])
    ]
    path = tmp / "inv.cdx.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}))
    return path


def _agent():
    from helpers.tools.sca_sbom_agent.main import SCASBOMAgent

    agent = SCASBOMAgent.__new__(SCASBOMAgent)
    agent.directory = tempfile.mkdtemp(prefix="sbom-det-")
    agent.sbom_json_file = None
    agent.state_update_writer = None
    agent.vulnerabilities = None
    agent.inventory_rows = []
    agent.bom_properties = {}
    agent.sbom_json = None
    agent.repo_info = {}
    return agent


def _run(agent, llm_side_effect=None, llm_return=None):
    tmp = Path(tempfile.mkdtemp())
    ctx = MagicMock()
    ctx.results = json.loads(json.dumps(FIXTURE))
    if llm_side_effect is not None:
        ctx.generate_map_reduce_summary.side_effect = llm_side_effect
    else:
        ctx.generate_map_reduce_summary.return_value = llm_return
    with (
        patch("helpers.tools.sca_sbom_agent.main.run_syft", return_value=_inventory(tmp)),
        patch("helpers.tools.sca_sbom_agent.main.run_cdxgen", return_value=None),
        patch("helpers.tools.sca_sbom_agent.main.OpenSourceContext", return_value=ctx),
        # its output model reads the CVE cache from MongoDB (slow connect timeouts without one)
        patch("helpers.tools.sca_sbom_agent.main.SBOMSCASummaryManager", MagicMock()),
    ):
        agent.populate_opensource_context()
    return ctx


def _ids(rows):
    return {(r["vuln_id"], r["dependency"]) for r in rows}


def test_llm_failure_keeps_every_grype_finding(monkeypatch):
    monkeypatch.setenv("SBOM_LLM_ENRICHMENT", "1")
    agent = _agent()
    _run(agent, llm_side_effect=RuntimeError(
        "An error occurred (UnrecognizedClientException) when calling the InvokeModel operation: "
        "The security token included in the request is invalid."))
    rows = agent.vulnerability_rows
    assert _ids(rows) == EXPECTED_IDS
    assert agent.bom_properties["sbom:llm_enrichment"] == "failed"
    assert agent.bom_properties["sbom:vuln_source"] == "grype"


def test_findings_are_deterministic_and_sorted(monkeypatch):
    monkeypatch.setenv("SBOM_LLM_ENRICHMENT", "0")
    first, second = _agent(), _agent()
    ctx = _run(first)
    _run(second)
    assert first.vulnerability_rows == second.vulnerability_rows
    ctx.generate_map_reduce_summary.assert_not_called()
    impacts = [r["impact"] for r in first.vulnerability_rows]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    assert impacts == sorted(impacts, key=order.__getitem__)
    assert first.bom_properties["sbom:llm_enrichment"] == "disabled"


def test_row_fields_come_from_grype():
    from helpers.tools.sca_sbom_agent.grype_findings import finding_rows

    rows = finding_rows(FIXTURE)
    certifi = next(r for r in rows if r["vuln_id"] == "GHSA-xqr8-7jwr-rhp7")
    assert certifi["impact"] == "High"  # grype's own severity for the GHSA, not the related NVD 9.8
    assert certifi["cvss_score"] == 7.5
    assert certifi["purl"] == "pkg:pypi/certifi@2017.4.17"
    assert certifi["fix_versions"] == ["2023.7.22"]
    assert "2023.7.22" in certifi["suggested_fix"]
    assert "CVE-2023-37920" in certifi["cves"] and "GHSA-xqr8-7jwr-rhp7" in certifi["cves"]
    assert certifi["cve_ids"] == ["CVE-2023-37920"]
    assert certifi["reachability"] == "not_assessed"
    assert certifi["owasp_top_10"] == {"VULNERABLE_AND_OUTDATED_COMPONENTS":
                                       "A06:2021 - Vulnerable and Outdated Components"}
    assert len(rows) == len(EXPECTED_IDS)


def test_llm_enrichment_adds_mappings_but_never_findings(monkeypatch):
    monkeypatch.setenv("SBOM_LLM_ENRICHMENT", "1")
    summary = MagicMock()
    hallucinated = MagicMock()
    summary.vulnerabilities = [hallucinated]
    agent = _agent()
    with patch(
        "helpers.tools.sca_sbom_agent.main.SCASBOMAgent.to_dict_list",
        return_value=[
            {"dependency": "flask==0.12.2", "description": "LLM prose", "impact": "Critical",
             "compliance_controls": {"PCI_DSS_6_3_3": "PCI DSS 6.3.3"}, "owasp_top_10": {}},
            {"dependency": "not-in-grype==1.0", "title": "invented", "impact": "Critical"},
        ],
    ):
        _run(agent, llm_return=summary)
    rows = agent.vulnerability_rows
    assert _ids(rows) == EXPECTED_IDS  # the invented package is not added
    flask = [r for r in rows if r["dependency"] == "flask==0.12.2"]
    assert {r["impact"] for r in flask} == {"High", "Low"}  # never re-rated by the LLM
    assert all(r["compliance_controls"] == {"PCI_DSS_6_3_3": "PCI DSS 6.3.3"} for r in flask)
    assert all(r["llm_summary"] == "LLM prose" for r in flask)
    assert agent.bom_properties["sbom:llm_enrichment"] == "applied"


def test_uploaded_sbom_file_is_matched_by_grype_not_the_llm(monkeypatch):
    monkeypatch.setenv("SBOM_LLM_ENRICHMENT", "1")
    from helpers.tools.sca_sbom_agent.main import SCASBOMAgent

    tmp = Path(tempfile.mkdtemp())
    agent = SCASBOMAgent.__new__(SCASBOMAgent)
    agent.directory = None
    agent.sbom_json_file = str(_inventory(tmp))
    agent.state_update_writer = None
    agent.vulnerabilities = None
    agent.inventory_rows = []
    agent.bom_properties = {}
    agent.sbom_json = None
    agent.repo_info = {}
    ctx = MagicMock()
    ctx.generate_map_reduce_summary.side_effect = RuntimeError("bedrock down")
    with (
        patch("helpers.tools.sca_sbom_agent.main.run_sbom_scan", return_value=json.loads(json.dumps(FIXTURE))),
        patch("helpers.tools.sca_sbom_agent.main.OpenSourceContext", return_value=ctx),
        patch("helpers.tools.sca_sbom_agent.main.SBOMSCASummaryManager", MagicMock()),
    ):
        agent.analyze_sbom_file()
    assert _ids(agent.vulnerability_rows) == EXPECTED_IDS
    assert agent.sbom_json["specVersion"] == "1.6"
    assert {c["name"] for c in agent.sbom_json["components"]} >= {"flask", "click"}


def test_finalize_keeps_one_row_per_advisory():
    """scan_worker._finalize_sbom used to key rows by dependency, so flask's second advisory overwrote the first."""
    from helpers.tools.sca_sbom_agent.main import combine_rows
    from helpers.tools.sca_sbom_agent.grype_findings import finding_rows

    vuln = finding_rows(FIXTURE)
    inventory = [{"dependency": "flask==0.12.2", "inventory_only": True},
                 {"dependency": "click==8.1.0", "inventory_only": True}]
    out = combine_rows(inventory, vuln)
    assert len([r for r in out if r.get("vuln_id")]) == len(EXPECTED_IDS)
    assert [r["dependency"] for r in out if r.get("inventory_only")] == ["click==8.1.0"]
