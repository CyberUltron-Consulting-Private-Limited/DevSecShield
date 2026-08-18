"""SEBI CSCRF SBOM hermetic compliance tests."""

from __future__ import annotations

import copy

from aibom.compliance.sebi_cscrf.common import manual_ids_for, requirements_for
from aibom.sbom.compliance import SBOM_FRAMEWORKS, run_sbom_compliance


def _row(
    *,
    dependency: str = "requests==2.31.0",
    impact: str = "Low",
    reachability: str = "not_reachable",
    license_type: str = "permissive",
    cves: dict | None = None,
    purl: str | None = "pkg:pypi/requests@2.31.0",
    digest: str | None = None,
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
    if digest is not None:
        row["hash"] = digest
    return row


_RICH_BOM = {
    "sbom:author": "DevSecShield",
    "sbom:timestamp": "2026-08-09T12:00:00Z",
    "sbom:vuln_scanner": "grype",
}


def test_sbom_frameworks_include_sebi() -> None:
    assert SBOM_FRAMEWORKS == [
        "rbi_free_ai_supply",
        "ntia_minimum_elements",
        "nist_ssdf",
        "cert_in_sbom",
        "sebi_cscrf_sbom",
    ]


def test_sebi_cscrf_sbom_present_and_ids() -> None:
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    assert "sebi_cscrf_sbom" in report
    expected = {r.id for r in requirements_for("sebi_cscrf_sbom")}
    got = {q["id"] for q in report["sebi_cscrf_sbom"]["requirements"]}
    assert expected == got


def test_sebi_cscrf_sbom_rich_inventory() -> None:
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    by_id = {q["id"]: q["verdict"] for q in report["sebi_cscrf_sbom"]["requirements"]}
    assert by_id["CSCRF-GV.SC.S5-name"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-ver"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-sup"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-uid"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-lic"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-lic-risk"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-deps"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-hash"] == "not_bom_evidenceable"
    assert by_id["CSCRF-GV.SC.S5-patch"] == "not_bom_evidenceable"
    assert by_id["CSCRF-GV.SC.S5-enc"] == "not_bom_evidenceable"
    assert by_id["CSCRF-GV.SC.S5-known-unknown"] == "not_bom_evidenceable"
    assert by_id["CSCRF-ID.AM-inv"] == "pass"
    assert by_id["CSCRF-ID.RA-vuln-track"] == "pass"
    assert by_id["CSCRF-ID.RA-high"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-author"] == "pass"
    assert by_id["CSCRF-GV.SC.S5-ts"] == "pass"


def test_sebi_cscrf_sbom_high_impact_fails() -> None:
    report = run_sbom_compliance(
        [_row(impact="Critical")],
        bom_properties=_RICH_BOM,
    )
    by_id = {q["id"]: q["verdict"] for q in report["sebi_cscrf_sbom"]["requirements"]}
    assert by_id["CSCRF-ID.RA-high"] == "fail"


def test_sebi_cscrf_sbom_high_risk_license_fails() -> None:
    report = run_sbom_compliance(
        [_row(license_type="strong_copyleft")],
        bom_properties=_RICH_BOM,
    )
    by_id = {q["id"]: q["verdict"] for q in report["sebi_cscrf_sbom"]["requirements"]}
    assert by_id["CSCRF-GV.SC.S5-lic-risk"] == "fail"


def test_sebi_cscrf_sbom_manuals_are_nbe() -> None:
    report = run_sbom_compliance([_row()], bom_properties=_RICH_BOM)
    by_id = {q["id"]: q["verdict"] for q in report["sebi_cscrf_sbom"]["requirements"]}
    for rid in manual_ids_for("sbom"):
        assert by_id[rid] == "not_bom_evidenceable", rid


def test_sebi_cscrf_sbom_empty_is_oos() -> None:
    report = run_sbom_compliance([], bom_properties=_RICH_BOM)
    fw = report["sebi_cscrf_sbom"]
    assert fw["coverage"] is None
    assert fw["out_of_scope"] > 0


def test_sebi_cscrf_sbom_never_reads_flags() -> None:
    from aibom.compliance.engine import run_framework
    from aibom.sbom.compliance import findings_to_scan_result

    result = findings_to_scan_result([_row()], bom_properties=_RICH_BOM)
    before = {
        q["id"]: q["verdict"]
        for q in run_framework(result, "sebi_cscrf_sbom")["requirements"]
    }
    cleared = copy.deepcopy(result)
    cleared.flags = []
    after = {
        q["id"]: q["verdict"]
        for q in run_framework(cleared, "sebi_cscrf_sbom")["requirements"]
    }
    assert before == after
