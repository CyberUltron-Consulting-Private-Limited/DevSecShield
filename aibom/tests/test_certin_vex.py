"""Hermetic tests for CERT-In VEX (default not_affected; CVE → affected)."""

from __future__ import annotations

from aibom.compliance.cert_in.vex import build_vex


def test_empty_inputs_honest_empty() -> None:
    doc = build_vex(bom=None, findings=None, scan_type="sbom_sca")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["vulnerabilities"] == []


def test_sbom_cve_proven_affected() -> None:
    findings = [
        {
            "dependency": "requests==2.31.0",
            "impact": "High",
            "cves": {"CVE-2023-0001": {}},
        }
    ]
    doc = build_vex(findings=findings, scan_type="sbom_sca")
    vulns = doc["vulnerabilities"]
    assert any(v["id"] == "CVE-2023-0001" for v in vulns)
    cve = next(v for v in vulns if v["id"] == "CVE-2023-0001")
    assert cve["analysis"]["state"] == "exploitable"


def test_sbom_no_cve_not_affected() -> None:
    findings = [
        {
            "dependency": "urllib3==1.26.0",
            "impact": "Low",
            "cves": {},
        }
    ]
    doc = build_vex(findings=findings, scan_type="sbom_sca")
    assert len(doc["vulnerabilities"]) == 1
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


def test_cbom_bom_components_default_not_affected() -> None:
    bom = {
        "components": [
            {"bom-ref": "crypto-1", "name": "AES-256"},
            {"bom-ref": "crypto-2", "name": "RSA-2048"},
        ]
    }
    doc = build_vex(bom=bom, scan_type="cbom")
    assert len(doc["vulnerabilities"]) == 2
    assert all(v["analysis"]["state"] == "not_affected" for v in doc["vulnerabilities"])


def test_disclaimer_present() -> None:
    doc = build_vex(bom={"components": [{"name": "x"}]}, scan_type="ai_bom")
    props = doc["metadata"]["properties"]
    assert any("CERT-In" in p.get("value", "") for p in props)


def test_cbom_findings_with_cves_are_never_not_affected() -> None:
    findings = [
        {"bom_ref": "algo-3des", "finding_codes": ["WEAK_ALGORITHM"], "cves": ["CVE-2016-2183"], "impact": "High"},
        {"bom_ref": "algo-md5", "finding_codes": ["WEAK_ALGORITHM"], "cves": ["CVE-2004-2761"], "impact": "High"},
        {"bom_ref": "algo-aes", "finding_codes": [], "cves": [], "impact": "Info"},
    ]
    doc = build_vex(bom={"components": [{"bom-ref": f["bom_ref"]} for f in findings]}, findings=findings, scan_type="cbom")
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-2016-2183"]["analysis"]["state"] == "in_triage"
    assert by_id["ZS-CBOM-WEAK_ALGORITHM"]["affects"] == [{"ref": "algo-3des"}, {"ref": "algo-md5"}]
    not_affected = {v["affects"][0]["ref"] for v in doc["vulnerabilities"] if v["analysis"]["state"] == "not_affected"}
    assert not_affected == {"algo-aes"}
    assert {"name": "zs:vex_rules", "value": "2"} in doc["metadata"]["properties"]
