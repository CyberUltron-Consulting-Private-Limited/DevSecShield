"""FIX-C1 (SOW D4): the downloadable SBOM is CycloneDX 1.6 with a complete dependency graph and the Grype findings
as vulnerabilities; the VEX states only vulnerabilities that exist.

Audit evidence (qa/sow/C): SBOM #8 ``/bom`` was specVersion 1.7, ``dependencies`` absent (NTIA dependency
relationship 0/5); its VEX asserted ``not_affected`` for every component under a made-up ``not-affected:<ref>`` id
with no justification (G-D4-2, G-D4-3, G-D4-4). Schema checks use the published CycloneDX 1.6.2 JSON schema
(tests/support/cyclonedx_schema.py, sha256-checked).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from backend.tests.support.cyclonedx_schema import json_errors
from backend.utilities.compliance.cert_in import vex as VEX
from backend.utilities.compliance.sbom_cyclonedx import sanitize_industry_sbom

_REPO = Path(__file__).resolve().parents[2]
_AUDIT_SBOM8 = {
    # the shape of staging SBOM #8 as stored by the worker before FIX-C1 (Syft 1.5x: CycloneDX 1.7, Syft bom-refs)
    "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
    "metadata": {"timestamp": "2026-11-23T10:00:00Z",
                 "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft",
                                           "version": "1.57.0"}]},
                 "component": {"bom-ref": "af63bd4c8601b7f1", "type": "file", "name": "repo_7uv5qtzh"}},
    "components": [
        {"bom-ref": "a1", "type": "library", "name": "actions/checkout", "version": "v4",
         "purl": "pkg:github/actions/checkout@v4"},
        {"bom-ref": "a2", "type": "library", "name": "flask", "version": "0.12.2",
         "purl": "pkg:pypi/flask@0.12.2"},
        {"bom-ref": "a3", "type": "library", "name": "jinja2", "version": "2.9.6",
         "purl": "pkg:pypi/jinja2@2.9.6"},
    ],
    "dependencies": [{"ref": "a2", "dependsOn": ["a3"]}],
}


def _grype_rows() -> list[dict]:
    """What the worker stores for two Grype matches (RabbitMQ/worker/.../grype_findings.py)."""
    base = {"detected_by": "grype", "vuln_assessed": True, "inventory_only": False, "reachability": "not_assessed",
            "license": "BSD-3-Clause", "license_type": "permissive", "owasp_top_10": {}, "compliance_controls": {}}
    return [
        {**base, "vuln_id": "GHSA-m2qf-hxjv-5gpq", "vuln_aliases": ["CVE-2023-30861"], "impact": "High",
         "title": "GHSA-m2qf-hxjv-5gpq in flask 0.12.2", "dependency": "flask==0.12.2",
         "purl": "pkg:pypi/flask@0.12.2", "cvss_score": 7.5, "cvss_version": "3.1",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "cwes": ["CWE-539"],
         "fix_state": "fixed", "fix_versions": ["2.2.5"], "description": "Possible disclosure of a permanent session",
         "suggested_fix": "Upgrade flask from 0.12.2 to 2.2.5 or later.",
         "cves": {"GHSA-m2qf-hxjv-5gpq": "x", "CVE-2023-30861": "x"}},
        {**base, "vuln_id": "GHSA-462w-v97r-4m45", "vuln_aliases": ["CVE-2019-10906"], "impact": "High",
         "dependency": "jinja2==2.9.6", "purl": "pkg:pypi/jinja2@2.9.6", "fix_state": "not-fixed",
         "fix_versions": [], "version_guessed_from": ">=2.9", "suggested_fix": "No fixed release",
         "cves": {"GHSA-462w-v97r-4m45": "x"}},
        {**base, "vuln_id": "GHSA-q2x7-8rv6-6q7h", "impact": "Medium", "dependency": "jinja2==2.9.6",
         "purl": "pkg:pypi/jinja2@2.9.6", "fix_state": "fixed", "fix_versions": ["2.10.1"],
         "cves": {"GHSA-q2x7-8rv6-6q7h": "x"}},
        {"dependency": "actions/checkout==v4", "purl": "pkg:github/actions/checkout@v4", "inventory_only": True,
         "vuln_assessed": True, "cves": {}, "impact": "Low"},
    ]


@pytest.fixture
def bom(monkeypatch):
    monkeypatch.setenv("DSS_BUILD_VERSION", "2026.11.23")
    return sanitize_industry_sbom(json.loads(json.dumps(_AUDIT_SBOM8)), findings=_grype_rows(),
                                  subject_name="peva3/SmarterRouter")


def _reachable(doc: dict) -> set[str]:
    root = doc["metadata"]["component"]["bom-ref"]
    edges = {d["ref"]: d.get("dependsOn") or [] for d in doc.get("dependencies") or []}
    seen, todo = set(), [root]
    while todo:
        for kid in edges.get(todo.pop(), []):
            if kid not in seen:
                seen.add(kid)
                todo.append(kid)
    return seen


# ------------------------------------------------------------------ SBOM --------------------------------------------

def test_stored_17_document_is_downloaded_as_valid_cyclonedx_16(bom):
    assert bom["specVersion"] == "1.6"
    assert bom["$schema"] == "http://cyclonedx.org/schema/bom-1.6.schema.json"
    assert json_errors(bom) == []


def test_tools_name_devsecshield_with_its_version_and_keep_syft(bom):
    tools = {t["name"]: t.get("version") for t in bom["metadata"]["tools"]["components"]}
    assert tools == {"DevSecShield": "2026.11.23", "syft": "1.57.0"}
    assert bom["metadata"]["timestamp"] == "2026-11-23T10:00:00Z"  # the scan's time, kept
    assert bom["metadata"]["component"]["name"] == "peva3/SmarterRouter"  # not the temp dir
    assert bom["metadata"]["component"]["type"] == "application"


def test_every_component_is_reachable_from_the_subject(bom):
    refs = {c["bom-ref"] for c in bom["components"]}
    assert refs == {"pkg:github/actions/checkout@v4", "pkg:pypi/flask@0.12.2", "pkg:pypi/jinja2@2.9.6"}
    assert _reachable(bom) == refs
    deps = {d["ref"]: d.get("dependsOn") for d in bom["dependencies"]}
    # Syft's ref a2 -> a3 survives the purl renaming; jinja2 stays transitive (not a direct child of the subject)
    assert deps["pkg:pypi/flask@0.12.2"] == ["pkg:pypi/jinja2@2.9.6"]
    root = bom["metadata"]["component"]["bom-ref"]
    assert set(deps[root]) == {"pkg:github/actions/checkout@v4", "pkg:pypi/flask@0.12.2"}


def test_grype_rows_become_one_vulnerability_per_advisory(bom):
    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    assert set(vulns) == {"GHSA-m2qf-hxjv-5gpq", "GHSA-462w-v97r-4m45", "GHSA-q2x7-8rv6-6q7h"}
    flask = vulns["GHSA-m2qf-hxjv-5gpq"]
    assert flask["references"] == [{"id": "CVE-2023-30861", "source": {
        "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-30861"}}]
    assert flask["ratings"][0] == {"source": {"name": "GitHub Advisory Database"}, "score": 7.5, "severity": "high",
                                   "method": "CVSSv31",
                                   "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
    assert flask["cwes"] == [539]
    assert flask["affects"] == [{"ref": "pkg:pypi/flask@0.12.2",
                                 "versions": [{"version": "0.12.2", "status": "affected"}]}]
    assert flask["recommendation"].startswith("Upgrade flask")
    # the CVE alias is a reference, not a second vulnerability (the old CVE-only path counted one issue twice)
    assert "CVE-2023-30861" not in vulns


def test_sbom_with_no_matches_still_says_it_was_assessed():
    rows = [{"dependency": "click==8.1.0", "inventory_only": True, "vuln_assessed": True, "cves": {}}]
    doc = sanitize_industry_sbom({"components": [{"name": "click", "version": "8.1.0",
                                                  "purl": "pkg:pypi/click@8.1.0"}]}, findings=rows)
    assert doc["vulnerabilities"] == []
    assert json_errors(doc) == []


def test_a_grype_scan_with_no_match_gets_no_download_time_lookups(monkeypatch):
    """The document must not change between downloads (signature, VEX BOM-Links): no OSV / NVD lookup when Grype
    matched the inventory, even when it found nothing."""
    from backend.utilities.compliance import sbom_advisory

    def boom(*_a, **_k):
        raise AssertionError("no advisory lookup for a Grype-matched SBOM")

    monkeypatch.setattr(sbom_advisory, "attach_advisories", boom)
    stored = {"metadata": {"tools": {"components": [{"name": "grype", "version": "0.121.2"}]}},
              "components": [{"name": "fastapi", "version": "0.109.0", "purl": "pkg:pypi/fastapi@0.109.0"}]}
    rows = [{"dependency": "fastapi==0.109.0", "inventory_only": True, "vuln_assessed": True, "cves": {}}]
    assert sanitize_industry_sbom(stored, findings=rows)["vulnerabilities"] == []


def test_serial_is_stable_across_downloads_when_the_stored_bom_has_none():
    raw = {k: v for k, v in _AUDIT_SBOM8.items() if k != "serialNumber"}
    one = sanitize_industry_sbom(json.loads(json.dumps(raw)), findings=_grype_rows())
    two = sanitize_industry_sbom(json.loads(json.dumps(raw)), findings=_grype_rows())
    assert one["serialNumber"] == two["serialNumber"]
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", one["serialNumber"])


def test_guessed_version_property_survives_the_download():
    comp = {"name": "fastapi", "version": "0.109.0", "purl": "pkg:pypi/fastapi@0.109.0",
            "properties": [{"name": "dss:version_source", "value": "range_lower_bound"},
                           {"name": "dss:version_constraint", "value": ">=0.109.0"},
                           {"name": "syft:package:foundBy", "value": "python-package-cataloger"}]}
    doc = sanitize_industry_sbom({"components": [comp]}, findings=[])
    props = {p["name"]: p["value"] for p in doc["components"][0]["properties"]}
    assert props["dss:version_source"] == "range_lower_bound"
    assert props["dss:version_constraint"] == ">=0.109.0"
    assert "syft:package:foundBy" not in props


# ------------------------------------------------------------------ VEX ---------------------------------------------

def test_vex_has_no_statement_without_a_vulnerability():
    rows = [{"dependency": "urllib3==1.26.0", "impact": "Low", "cves": {}, "inventory_only": True}]
    doc = VEX.build_vex(bom={"components": [{"bom-ref": "pkg:pypi/urllib3@1.26.0", "name": "urllib3"}]},
                        findings=rows, scan_type="sbom_sca")
    assert doc["vulnerabilities"] == []
    ai = VEX.build_vex(bom={"components": [{"bom-ref": "model:gpt-4o", "name": "gpt-4o"}]}, scan_type="ai_bom")
    assert ai["vulnerabilities"] == []
    assert json_errors(doc) == [] and json_errors(ai) == []


def test_vex_statement_per_matched_advisory_with_cisa_minimum_fields(bom):
    doc = VEX.build_vex(bom=bom, findings=_grype_rows(), scan_type="sbom_sca")
    assert json_errors(doc) == []
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert set(by_id) == {"GHSA-m2qf-hxjv-5gpq", "GHSA-462w-v97r-4m45", "GHSA-q2x7-8rv6-6q7h"}
    serial = bom["serialNumber"].split(":")[-1]
    for vid, stmt in by_id.items():
        assert not vid.startswith("not-affected")
        analysis = stmt["analysis"]
        assert analysis["state"] == "in_triage"  # CISA: under investigation (matched, not assessed)
        assert analysis["detail"] and analysis["firstIssued"] == "2026-11-23T10:00:00Z" and analysis["lastUpdated"]
        for aff in stmt["affects"]:
            assert aff["ref"].startswith(f"urn:cdx:{serial}/1#pkg%3Apypi%2F")  # BOM-Link into the SBOM
    flask = by_id["GHSA-m2qf-hxjv-5gpq"]
    assert flask["analysis"]["response"] == ["update"]  # a fixed release exists
    assert flask["affects"][0]["versions"] == [{"version": "0.12.2", "status": "affected"}]
    assert "response" not in by_id["GHSA-462w-v97r-4m45"]["analysis"]  # no fixed release published
    assert "lower bound" in by_id["GHSA-462w-v97r-4m45"]["analysis"]["detail"]
    meta = doc["metadata"]
    assert meta["authors"] == [{"name": "DevSecShield"}]
    assert meta["tools"]["components"][0]["name"] == "DevSecShield"
    assert {"name": "zs:vex_rules", "value": VEX.SBOM_VEX_RULES} in meta["properties"]
    assert meta["component"]["name"] == "peva3/SmarterRouter"


def test_vex_never_uses_states_outside_cyclonedx():
    """'affected' is not a CycloneDX impactAnalysisState; the old rule wrote it for every Low/Medium CVE row."""
    rows = [{"dependency": "requests==2.0.0", "impact": "Medium", "cves": {"CVE-2023-32681": "Proxy-Auth leak"}}]
    doc = VEX.build_vex(findings=rows, scan_type="sbom_sca")
    assert [v["analysis"]["state"] for v in doc["vulnerabilities"]] == ["in_triage"]
    assert json_errors(doc) == []


def test_vex_copies_are_identical():
    backend = (_REPO / "backend/utilities/compliance/cert_in/vex.py").read_text()
    aibom = (_REPO / "aibom/src/aibom/compliance/cert_in/vex.py").read_text()
    assert backend == aibom


def test_stored_vex_from_the_old_rules_is_rebuilt():
    from backend.routers.certin import _vex_is_current

    old = {"metadata": {"properties": [{"name": "zs:vex_rules", "value": "2"}]},
           "vulnerabilities": [{"id": "not-affected:x", "analysis": {"state": "not_affected"}}]}
    assert _vex_is_current("sbom_sca", old) is False
    assert _vex_is_current("ai_bom", {"metadata": {}}) is False
    assert _vex_is_current("sbom_sca", VEX.build_vex(findings=[], scan_type="sbom_sca")) is True
