"""Hermetic tests for CERT-In VEX: real vulnerability statements only (audit G-D4-3).

The earlier rules asserted ``not_affected`` for every SBOM / AI BOM / CBOM component
with a made-up id
(``not-affected:<ref>``) and no justification: 103 such statements for SmarterRouter's
AI BOM. A VEX statement is about
a real vulnerability id; ``not_affected`` needs a CycloneDX justification. Every
document is checked against the
official CycloneDX 1.6 JSON schema.
"""

from __future__ import annotations

import pathlib

from aibom.compliance.cert_in.vex import VEX_RULES, build_vex, is_current
from aibom.emit.validate import validate_cyclonedx

_BACKEND_COPY = (
    pathlib.Path(__file__).resolve().parents[2]
    / "backend"
    / "utilities"
    / "compliance"
    / "cert_in"
    / "vex.py"
)


def _valid(doc: dict) -> dict:
    assert validate_cyclonedx(doc) == []
    return doc


def test_empty_inputs_honest_empty() -> None:
    doc = _valid(build_vex(bom=None, findings=None, scan_type="sbom_sca"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["vulnerabilities"] == []


def test_sbom_matched_cve_is_in_triage_against_the_bom_component() -> None:
    bom = {
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@2.31.0",
                "name": "requests",
                "version": "2.31.0",
            }
        ]
    }
    findings = [
        {
            "dependency": "requests==2.31.0",
            "version": "2.31.0",
            "impact": "High",
            "cves": {"CVE-2023-0001": {}},
        }
    ]
    doc = _valid(build_vex(bom=bom, findings=findings, scan_type="sbom_sca"))
    (cve,) = doc["vulnerabilities"]
    assert cve["id"] == "CVE-2023-0001"
    assert (
        cve["analysis"]["state"] == "in_triage"
    )  # a match is not proof of exploitability
    assert cve["affects"] == [{"ref": "pkg:pypi/requests@2.31.0"}]
    assert cve["source"]["url"].endswith("CVE-2023-0001")
    assert cve["ratings"][0]["severity"] == "high"


def test_no_vulnerability_means_no_statement() -> None:
    findings = [{"dependency": "urllib3==1.26.0", "impact": "Low", "cves": {}}]
    bom = {
        "components": [
            {"bom-ref": "c1", "name": "urllib3"},
            {"bom-ref": "c2", "name": "x"},
        ]
    }
    for scan_type in ("sbom_sca", "ai_bom"):
        doc = _valid(build_vex(bom=bom, findings=findings, scan_type=scan_type))
        assert doc["vulnerabilities"] == []
        assert not any(
            str(v.get("id", "")).startswith("not-affected:")
            for v in doc["vulnerabilities"]
        )


def test_not_affected_only_with_a_justification() -> None:
    findings = [
        {
            "dependency": "a",
            "cves": ["CVE-2024-1"],
            "vex_state": "not_affected",
            "vex_justification": "code_not_reachable",
        },
        {
            "dependency": "b",
            "cves": ["CVE-2024-2"],
            "vex_state": "not_affected",
        },  # no justification
    ]
    doc = _valid(build_vex(findings=findings, scan_type="sbom_sca"))
    by_id = {v["id"]: v["analysis"] for v in doc["vulnerabilities"]}
    assert by_id["CVE-2024-1"] == {
        "state": "not_affected",
        "detail": by_id["CVE-2024-1"]["detail"],
        "justification": "code_not_reachable",
    }
    assert by_id["CVE-2024-2"]["state"] == "in_triage"
    assert all(
        a["state"] != "not_affected" or a.get("justification") for a in by_id.values()
    )


def test_ai_bom_restates_the_boms_own_vulnerabilities() -> None:
    bom = {
        "serialNumber": "urn:uuid:0d3c1f0e-0000-4000-8000-000000000001",
        "components": [
            {"bom-ref": "lib-transformers", "name": "transformers", "version": "4.30.0"}
        ],
        "vulnerabilities": [
            {"id": "GHSA-xxxx-yyyy-zzzz", "affects": [{"ref": "lib-transformers"}]}
        ],
    }
    doc = _valid(build_vex(bom=bom, scan_type="ai_bom"))
    (v,) = doc["vulnerabilities"]
    assert v["id"] == "GHSA-xxxx-yyyy-zzzz" and v["affects"] == [
        {"ref": "lib-transformers"}
    ]
    assert v["analysis"]["state"] == "in_triage"
    assert v["source"]["name"] == "GitHub"


def test_metadata_rules_timestamp_and_currency() -> None:
    doc = _valid(
        build_vex(
            bom={"components": [{"name": "x"}]},
            scan_type="ai_bom",
            now="2026-11-23T10:00:00Z",
        )
    )
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["zs:vex_rules"] == VEX_RULES
    assert "CERT-In" in props["certin:disclaimer"]
    assert doc["metadata"]["timestamp"] == "2026-11-23T10:00:00Z"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert is_current("ai_bom", doc) and is_current("sbom_sca", doc)
    stale = {
        "metadata": {
            "properties": [
                {"name": "certin:disclaimer", "value": "default not_affected"}
            ]
        }
    }
    assert not is_current("ai_bom", stale)


def test_cbom_bom_without_findings_states_nothing() -> None:
    bom = {
        "components": [
            {"bom-ref": "crypto-1", "name": "AES-256"},
            {"bom-ref": "crypto-2", "name": "RSA-2048"},
        ]
    }
    doc = _valid(build_vex(bom=bom, scan_type="cbom"))
    assert doc["vulnerabilities"] == []


def test_cbom_findings_with_cves_are_never_not_affected() -> None:
    findings = [
        {
            "bom_ref": "algo-3des",
            "finding_codes": ["WEAK_ALGORITHM"],
            "cves": ["CVE-2016-2183"],
            "impact": "High",
        },
        {
            "bom_ref": "algo-md5",
            "finding_codes": ["WEAK_ALGORITHM"],
            "cves": ["CVE-2004-2761"],
            "impact": "High",
        },
        {"bom_ref": "algo-aes", "finding_codes": [], "cves": [], "impact": "Info"},
    ]
    doc = _valid(
        build_vex(
            bom={"components": [{"bom-ref": f["bom_ref"]} for f in findings]},
            findings=findings,
            scan_type="cbom",
        )
    )
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-2016-2183"]["analysis"]["state"] == "in_triage"
    assert by_id["ZS-CBOM-WEAK_ALGORITHM"]["affects"] == [
        {"ref": "algo-3des"},
        {"ref": "algo-md5"},
    ]
    assert not [
        v for v in doc["vulnerabilities"] if v["analysis"]["state"] == "not_affected"
    ]
    assert {"name": "zs:vex_rules", "value": "2"} in doc["metadata"]["properties"]


def test_backend_copy_is_identical() -> None:
    """The backend image loads its own copy (routers/certin.py): both must carry
    the same rules."""
    here = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src"
        / "aibom"
        / "compliance"
        / "cert_in"
        / "vex.py"
    )
    assert here.read_text(encoding="utf-8") == _BACKEND_COPY.read_text(encoding="utf-8")
