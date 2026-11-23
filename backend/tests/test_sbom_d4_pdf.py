"""FIX-C1 (SOW D4): the SBOM PDF shows the NTIA / CERT-In minimum elements counted in the CycloneDX file and the
framework results computed from them; its package list takes licences from the SBOM and lists no file paths.

Audit evidence: pdf/sbom_sca-8 showed licence "—" for MIT GitHub Actions, file paths (/test_model.gguf) as
packages, and no NTIA result at all (G-D4-6).
"""
from __future__ import annotations

import io

import pypdf

from backend.utilities.compliance.sbom_minimum_elements import minimum_elements
from backend.utilities.pdf.sbom_sca_pdf import generate_pdf

ROOT = "pkg:github/peva3/SmarterRouter@3e705e3"
SBOM = {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e1b6f0e-1111-4c2a-9a55-0d2c1f6b7a10",
    "version": 1,
    "metadata": {"timestamp": "2026-11-23T10:00:00Z", "authors": [{"name": "DevSecShield"}],
                 "tools": {"components": [{"type": "application", "name": "DevSecShield", "version": "2026.11.23"},
                                          {"type": "application", "name": "syft", "version": "1.57.0"},
                                          {"type": "application", "name": "grype", "version": "0.121.2"}]},
                 "component": {"type": "application", "name": "peva3/SmarterRouter", "bom-ref": ROOT}},
    "components": [
        {"bom-ref": "pkg:github/actions/checkout@v4", "type": "library", "name": "actions/checkout",
         "version": "v4", "purl": "pkg:github/actions/checkout@v4"},
        {"bom-ref": "pkg:pypi/flask@0.12.2", "type": "library", "name": "flask", "version": "0.12.2",
         "purl": "pkg:pypi/flask@0.12.2", "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
        {"bom-ref": "pkg:pypi/click@8.1.0", "type": "library", "name": "click", "version": "8.1.0",
         "purl": "pkg:pypi/click@8.1.0", "licenses": [{"license": {"id": "BSD-3-Clause"}}],
         "hashes": [{"alg": "SHA-256", "content": "b" * 64}]},
    ],
    "dependencies": [{"ref": ROOT, "dependsOn": ["pkg:github/actions/checkout@v4", "pkg:pypi/flask@0.12.2"]},
                     {"ref": "pkg:pypi/flask@0.12.2", "dependsOn": ["pkg:pypi/click@8.1.0"]}],
}
ROWS = [
    {"detected_by": "grype", "vuln_id": "GHSA-m2qf-hxjv-5gpq", "vuln_aliases": ["CVE-2023-30861"],
     "title": "GHSA-m2qf-hxjv-5gpq in flask 0.12.2", "description": "Possible disclosure of a permanent session",
     "impact": "High", "dependency": "flask==0.12.2", "purl": "pkg:pypi/flask@0.12.2", "reachability": "not_assessed",
     "license": "BSD-3-Clause", "license_type": "permissive", "cves": {"GHSA-m2qf-hxjv-5gpq": "x"},
     "owasp_top_10": {}, "compliance_controls": {}, "suggested_fix": "Upgrade flask to 2.2.5", "fix_state": "fixed",
     "fix_versions": ["2.2.5"], "vuln_assessed": True, "inventory_only": False},
    {"dependency": "actions/checkout==v4", "purl": "pkg:github/actions/checkout@v4", "title": "Inventory",
     "inventory_only": True, "vuln_assessed": True, "cves": {}, "license": "LicenseRef-not-declared",
     "impact": "Low"},
    {"dependency": "click==8.1.0", "purl": "pkg:pypi/click@8.1.0", "inventory_only": True, "vuln_assessed": True,
     "cves": {}, "license": "LicenseRef-not-declared", "impact": "Low"},
    {"dependency": "/test_model.gguf", "title": "Inventory: /test_model.gguf", "inventory_only": True, "cves": {},
     "impact": "Low"},
]


def _text(tmp_path) -> str:
    out = tmp_path / "sbom.pdf"
    generate_pdf({"results": ROWS, "duration_of_scan": 3.0, "sbom_json": SBOM}, str(out))
    reader = pypdf.PdfReader(io.BytesIO(out.read_bytes()))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def test_minimum_elements_are_counted_from_the_document():
    rows = {r["ntia"] + "|" + r["cert_in"]: r for r in minimum_elements(SBOM)["rows"]}
    assert rows["NTIA-5|T5-Component-Dependencies"]["present"] == 3  # all reachable from the subject
    assert (rows["NTIA-8|T5-Checksums-or-Hashes"]["present"], rows["NTIA-8|T5-Checksums-or-Hashes"]["status"]) \
        == (1, "partial")
    assert rows["NTIA-6|T5-Author-of-SBOM-Data"]["status"] == "pass"
    flat = dict(SBOM, dependencies=[])
    assert {r["ntia"]: r for r in minimum_elements(flat)["rows"]}["NTIA-5"]["status"] == "missing"


def test_pdf_shows_minimum_elements_and_framework_results(tmp_path):
    text = _text(tmp_path)
    assert "SBOM minimum elements (NTIA / CERT-In)" in text
    assert "Dependency relationship" in text and "T5-Component-Dependencies" in text
    assert "CycloneDX 1.6" in text
    assert "SBOM compliance checks" in text
    for label in ("NTIA minimum elements", "CERT-In SBOM", "SEBI CSCRF", "RBI FREE-AI"):
        assert label in text, label


def test_pdf_package_list_takes_licences_from_the_sbom_and_skips_files(tmp_path):
    text = _text(tmp_path)
    package_part = text[text.index("Packages with no known vulnerability"):]
    assert "click" in package_part and "BSD-3-Clause" in package_part
    assert "MIT" in package_part  # actions/* resolve to MIT in the downloaded SBOM
    assert "/test_model.gguf" not in text
