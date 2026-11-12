"""Tests for deterministic SBOM RBI supply-chain compliance."""

from __future__ import annotations

from aibom.sbom.compliance import run_sbom_compliance


def _row(
    *,
    dependency: str = "requests==2.31.0",
    impact: str = "Low",
    reachability: str = "not_reachable",
    license_type: str = "permissive",
    cves: dict | None = None,
) -> dict:
    return {
        "dependency": dependency,
        "impact": impact,
        "reachability": reachability,
        "license_type": license_type,
        "cves": cves or {},
        "title": "test",
        "description": "test",
    }


def test_clean_sbom_passes_supply_framework() -> None:
    report = run_sbom_compliance([_row()])
    fw = report["rbi_free_ai_supply"]
    assert fw["fail"] == 0
    assert fw["coverage"] == 1.0


def test_critical_finding_fails_supply2() -> None:
    report = run_sbom_compliance([_row(impact="Critical")])
    reqs = {q["id"]: q["verdict"] for q in report["rbi_free_ai_supply"]["requirements"]}
    assert reqs["FREEAI-SUPPLY-2"] == "fail"


def test_high_risk_license_fails_supply4() -> None:
    report = run_sbom_compliance([_row(license_type="strong_copyleft")])
    reqs = {q["id"]: q["verdict"] for q in report["rbi_free_ai_supply"]["requirements"]}
    assert reqs["FREEAI-SUPPLY-4"] == "fail"


def test_empty_findings_out_of_scope() -> None:
    report = run_sbom_compliance([])
    fw = report["rbi_free_ai_supply"]
    assert fw["out_of_scope"] >= 1


def test_cert_in_sbom_peer_present_after_wire() -> None:
    report = run_sbom_compliance([_row()])
    assert "cert_in_sbom" in report
    assert len(report["cert_in_sbom"]["requirements"]) == 41
    # RBI still green on clean row.
    assert report["rbi_free_ai_supply"]["fail"] == 0
