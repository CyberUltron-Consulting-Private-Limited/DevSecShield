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
