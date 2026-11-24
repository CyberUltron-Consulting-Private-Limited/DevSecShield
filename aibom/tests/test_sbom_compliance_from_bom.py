"""FIX-C1 (SOW D4): NTIA minimum elements and CERT-In SBOM checks read the CycloneDX
document's own fields.

Before: NTIA-5 "dependency relationship" passed for every scan (each finding row got a
synthetic subject edge) while the downloaded SBOM had no ``dependencies`` at all (audit
G-D4-4: 0/5), and author / timestamp were stamped "now" by the checker instead of read
from the document.
"""

from __future__ import annotations

import copy

from aibom.sbom.compliance import run_sbom_compliance

ROOT = "pkg:github/peva3/SmarterRouter@3e705e3"
BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {
        "timestamp": "2026-11-23T10:00:00Z",
        "authors": [{"name": "DevSecShield"}],
        "tools": {
            "components": [
                {"name": "DevSecShield", "version": "1"},
                {"name": "syft"},
                {"name": "grype"},
            ]
        },
        "component": {
            "type": "application",
            "name": "peva3/SmarterRouter",
            "bom-ref": ROOT,
        },
    },
    "components": [
        {
            "bom-ref": "pkg:pypi/fastapi@0.109.0",
            "name": "fastapi",
            "version": "0.109.0",
            "purl": "pkg:pypi/fastapi@0.109.0",
            "supplier": {"name": "PyPI"},
            "licenses": [{"license": {"id": "MIT"}}],
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
        },
        {
            "bom-ref": "pkg:pypi/starlette@0.35.1",
            "name": "starlette",
            "version": "0.35.1",
            "purl": "pkg:pypi/starlette@0.35.1",
        },
    ],
    "dependencies": [
        {"ref": ROOT, "dependsOn": ["pkg:pypi/fastapi@0.109.0"]},
        {"ref": "pkg:pypi/fastapi@0.109.0", "dependsOn": ["pkg:pypi/starlette@0.35.1"]},
    ],
    "vulnerabilities": [],
}
ROWS = [
    {
        "dependency": "fastapi==0.109.0",
        "purl": "pkg:pypi/fastapi@0.109.0",
        "inventory_only": True,
        "vuln_assessed": True,
        "license_type": "permissive",
        "cves": {},
    },
    {
        "dependency": "starlette==0.35.1",
        "purl": "pkg:pypi/starlette@0.35.1",
        "inventory_only": True,
        "vuln_assessed": True,
        "cves": {},
    },
]


def _req(report: dict, fw: str, rid: str) -> dict:
    return next(r for r in report[fw]["requirements"] if r["id"] == rid)


def test_dependency_relationship_passes_only_when_the_graph_reaches_every_component():
    ok = run_sbom_compliance(ROWS, sbom_json=BOM)
    assert _req(ok, "ntia_minimum_elements", "NTIA-5")["verdict"] == "pass"
    assert _req(ok, "cert_in_sbom", "T5-Component-Dependencies")["verdict"] == "pass"

    flat = copy.deepcopy(BOM)
    flat.pop("dependencies")  # the pre-FIX-C1 SBOM: no graph at all
    bad = run_sbom_compliance(ROWS, sbom_json=flat)
    ntia5 = _req(bad, "ntia_minimum_elements", "NTIA-5")
    assert ntia5["verdict"] == "fail" and "2/2" in ntia5["evidence"]
    assert _req(bad, "cert_in_sbom", "T5-Component-Dependencies")["verdict"] != "pass"


def test_hash_licence_and_supplier_are_counted_from_the_document():
    report = run_sbom_compliance(ROWS, sbom_json=BOM)
    hashes = _req(report, "ntia_minimum_elements", "NTIA-8")
    assert hashes["verdict"] == "not_bom_evidenceable" and "1/2" in hashes["evidence"]
    licence = _req(report, "ntia_minimum_elements", "NTIA-9")
    assert licence["verdict"] == "not_bom_evidenceable" and "1/2" in licence["evidence"]
    assert (
        _req(report, "ntia_minimum_elements", "NTIA-1")["verdict"] == "pass"
    )  # supplier or purl on both


def test_author_and_timestamp_come_from_the_metadata_not_the_checker():
    report = run_sbom_compliance(ROWS, sbom_json=BOM)
    assert _req(report, "ntia_minimum_elements", "NTIA-6")["verdict"] == "pass"
    assert _req(report, "ntia_minimum_elements", "NTIA-7")["verdict"] == "pass"
    anonymous = copy.deepcopy(BOM)
    anonymous["metadata"].pop("authors")
    anonymous["metadata"].pop("timestamp")
    report = run_sbom_compliance(ROWS, sbom_json=anonymous)
    assert _req(report, "ntia_minimum_elements", "NTIA-6")["verdict"] == "fail"
    assert _req(report, "ntia_minimum_elements", "NTIA-7")["verdict"] == "fail"


def test_tools_in_the_document_prove_inventory_and_vuln_scanner():
    report = run_sbom_compliance(ROWS, sbom_json=BOM)
    assert _req(report, "cert_in_sbom", "T5-Inventory-Tools")["verdict"] == "pass"
    assert _req(report, "cert_in_sbom", "T5-Vuln-Scanner")["verdict"] == "pass"
