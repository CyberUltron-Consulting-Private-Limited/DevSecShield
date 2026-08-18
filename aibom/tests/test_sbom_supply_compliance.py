"""Hermetic tests for NTIA minimum elements + NIST SSDF on the SBOM lane."""

from __future__ import annotations

import copy

from aibom.compliance.engine import run_framework
from aibom.sbom.compliance import (
    SBOM_FRAMEWORKS,
    findings_to_scan_result,
    run_sbom_compliance,
)


def _row(
    *,
    dependency: str = "requests==2.31.0",
    impact: str = "Low",
    reachability: str = "not_reachable",
    license_type: str = "permissive",
    cves: dict | None = None,
    purl: str | None = "pkg:pypi/requests@2.31.0",
    hash: str | None = None,
    inventory_only: bool = False,
) -> dict:
    row: dict = {
        "dependency": dependency,
        "impact": impact,
        "reachability": reachability,
        "license_type": license_type,
        "cves": cves or {},
        "title": "test",
        "description": "test",
    }
    if purl is not None:
        row["purl"] = purl
    if hash is not None:
        row["hash"] = hash
    if inventory_only:
        row["inventory_only"] = True
    return row


_RICH_BOM = {
    "sbom:author": "DevSecShield",
    "sbom:timestamp": "2026-08-09T12:00:00Z",
    "sbom:vuln_scanner": "grype",
}


def test_sbom_frameworks_order_and_keys() -> None:
    assert SBOM_FRAMEWORKS == [
        "rbi_free_ai_supply",
        "ntia_minimum_elements",
        "nist_ssdf",
        "cert_in_sbom",
        "sebi_cscrf_sbom",
    ]
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    for key in SBOM_FRAMEWORKS:
        assert key in report
        assert isinstance(report[key], dict)
        assert "requirements" in report[key]


def test_ntia_passes_on_rich_inventory() -> None:
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    fw = report["ntia_minimum_elements"]
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    assert by_id["NTIA-1"] == "pass"  # supplier via purl
    assert by_id["NTIA-2"] == "pass"
    assert by_id["NTIA-3"] == "pass"
    assert by_id["NTIA-4"] == "pass"
    assert by_id["NTIA-5"] == "pass"
    assert by_id["NTIA-6"] == "pass"
    assert by_id["NTIA-7"] == "pass"
    assert by_id["NTIA-8"] == "not_bom_evidenceable"  # no hash
    assert by_id["NTIA-9"] == "pass"  # license_type present
    assert by_id["NTIA-10"] == "pass"  # vuln_scanner


def test_ntia_missing_hash_is_nbe() -> None:
    report = run_sbom_compliance([_row(hash=None)], bom_properties=_RICH_BOM)
    by_id = {q["id"]: q["verdict"] for q in report["ntia_minimum_elements"]["requirements"]}
    assert by_id["NTIA-8"] == "not_bom_evidenceable"


def test_ntia_hash_present_passes() -> None:
    report = run_sbom_compliance(
        [_row(hash="sha256:abc")],
        bom_properties=_RICH_BOM,
    )
    by_id = {q["id"]: q["verdict"] for q in report["ntia_minimum_elements"]["requirements"]}
    assert by_id["NTIA-8"] == "pass"


def test_nist_ssdf_manuals_are_nbe() -> None:
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    fw = report["nist_ssdf"]
    by_id = {q["id"]: q["verdict"] for q in fw["requirements"]}
    assert by_id["SSDF-PW-4.4"] == "pass"
    assert by_id["SSDF-RV-1.1"] == "pass"
    assert by_id["SSDF-RV-1.2"] == "pass"
    manuals = [
        "SSDF-PO-1.1",
        "SSDF-PS-1.1",
        "SSDF-PW-1.1",
        "SSDF-RV-3.1",
        "SSDF-PO-3.2",
        "SSDF-PW-7.1",
    ]
    for mid in manuals:
        assert by_id[mid] == "not_bom_evidenceable", mid
    assert fw["not_bom_evidenceable"] == len(manuals)


def test_supply_frameworks_never_read_flags() -> None:
    result = findings_to_scan_result([_row()], bom_properties=_RICH_BOM)
    import aibom.sbom.compliance  # noqa: F401

    for fw in ("ntia_minimum_elements", "nist_ssdf"):
        before = run_framework(result, fw)
        cleared = copy.deepcopy(result)
        cleared.flags.clear()
        after = run_framework(cleared, fw)
        a = {r["id"]: r["verdict"] for r in before["requirements"]}
        b = {r["id"]: r["verdict"] for r in after["requirements"]}
        assert a == b, fw


def test_empty_findings_out_of_scope() -> None:
    report = run_sbom_compliance([])
    assert report["ntia_minimum_elements"]["out_of_scope"] >= 1
    assert report["nist_ssdf"]["out_of_scope"] >= 1
    assert report["ntia_minimum_elements"]["coverage"] is None
    assert report["nist_ssdf"]["coverage"] is None
