"""CERT-In Phase 3: cert_in_sbom compliance on synthetic SBOM finding rows."""

from __future__ import annotations

import copy
from typing import Any

from aibom.compliance.cert_in.common import requirements_for
from aibom.integrations.sbom_devsecshield import enrich_sbom_scan
from aibom.sbom.compliance import findings_to_scan_result, run_sbom_compliance


def _row(
    *,
    dependency: str = "requests==2.31.0",
    impact: str = "Low",
    reachability: str = "not_reachable",
    license_type: str = "permissive",
    cves: dict | list | None = None,
    purl: str | None = None,
    title: str = "test finding",
    description: str = "test description",
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "dependency": dependency,
        "impact": impact,
        "reachability": reachability,
        "license_type": license_type,
        "cves": cves if cves is not None else {},
        "title": title,
        "description": description,
    }
    if purl is not None:
        out["purl"] = purl
    out.update(extra)
    return out


def test_cert_in_sbom_present() -> None:
    report = run_sbom_compliance([_row()])
    assert "cert_in_sbom" in report
    fw = report["cert_in_sbom"]
    for k in (
        "pass",
        "fail",
        "na",
        "out_of_scope",
        "not_bom_evidenceable",
        "coverage",
        "requirements",
    ):
        assert k in fw
    assert fw["requirements"], "expected non-empty drilldown"
    assert "rbi_free_ai_supply" in report


def test_cert_in_sbom_requirement_ids_complete() -> None:
    report = run_sbom_compliance([_row()])
    expected = {r.id for r in requirements_for("cert_in_sbom")}
    got = {r["id"] for r in report["cert_in_sbom"]["requirements"]}
    assert expected == got, f"only_expected={expected - got} only_got={got - expected}"
    assert len(got) == 41


def test_manuals_are_nbe() -> None:
    by_id = {
        r["id"]: r for r in run_sbom_compliance([_row()])["cert_in_sbom"]["requirements"]
    }
    for n in range(1, 16):
        rid = f"7.1.{n}"
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", rid


def test_core_fail_mode_fields() -> None:
    # Without purl → Supplier fails; with enrichment stamps Author/Timestamp pass.
    thin = run_sbom_compliance([_row()])
    by_id = {r["id"]: r for r in thin["cert_in_sbom"]["requirements"]}
    assert by_id["T5-Component-Name"]["verdict"] == "pass"
    assert by_id["T5-Component-Version"]["verdict"] == "pass"
    assert by_id["T5-Component-License"]["verdict"] == "pass"
    assert by_id["T5-Component-Dependencies"]["verdict"] == "pass"
    assert by_id["T5-Vulnerabilities"]["verdict"] == "pass"
    assert by_id["T5-Unique-Identifier"]["verdict"] == "pass"
    assert by_id["T5-Author-of-SBOM-Data"]["verdict"] == "pass"
    assert by_id["T5-Timestamp"]["verdict"] == "pass"
    assert by_id["T5-Component-Supplier"]["verdict"] == "fail"
    assert by_id["T5-Automation-SPDX"]["verdict"] == "fail"
    assert by_id["T5-Automation-CycloneDX"]["verdict"] == "fail"

    with_purl = run_sbom_compliance(
        [_row(purl="pkg:pypi/requests@2.31.0")]
    )
    by_purl = {r["id"]: r for r in with_purl["cert_in_sbom"]["requirements"]}
    assert by_purl["T5-Component-Supplier"]["verdict"] == "pass"


def test_nbe_fields_when_absent() -> None:
    # description/title present → Description may pass; Origin etc. stay NBE.
    by_id = {
        r["id"]: r
        for r in run_sbom_compliance(
            [_row(description="", title="")]
        )["cert_in_sbom"]["requirements"]
    }
    for rid in (
        "T5-Component-Origin",
        "T5-Patch-Status",
        "T5-Release-Date",
        "T5-EOL-Date",
        "T5-Criticality",
        "T5-Usage-Restrictions",
        "T5-Checksums-or-Hashes",
        "T5-Comments-or-Notes",
        "T5-Executable-Property",
        "T5-Archive-Property",
        "T5-Structured-Property",
        "T5-Inventory-Tools",
        "T5-Vuln-Scanner",
        "T5-Multi-Format-Emit",
    ):
        assert by_id[rid]["verdict"] == "not_bom_evidenceable", (
            rid,
            by_id[rid]["verdict"],
        )


def test_multi_engine_provenance_props_pass() -> None:
    report = run_sbom_compliance(
        [_row(purl="pkg:pypi/requests@2.31.0")],
        bom_properties={
            "sbom:inventory_tools": "syft,cdxgen",
            "sbom:vuln_scanner": "grype",
            "sbom:automation_cyclonedx": "true",
            "sbom:multi_format_emit": "true",
        },
    )
    by_id = {r["id"]: r for r in report["cert_in_sbom"]["requirements"]}
    assert by_id["T5-Inventory-Tools"]["verdict"] == "pass"
    assert by_id["T5-Vuln-Scanner"]["verdict"] == "pass"
    assert by_id["T5-Multi-Format-Emit"]["verdict"] == "pass"
    assert by_id["T5-Automation-CycloneDX"]["verdict"] == "pass"


def test_cert_in_never_reads_flags() -> None:
    result = findings_to_scan_result([_row()])
    from aibom.compliance.engine import run_framework

    # Ensure cert_in_sbom is registered (side-effect of importing sbom.compliance).
    import aibom.sbom.compliance  # noqa: F401

    before = run_framework(result, "cert_in_sbom")
    cleared = copy.deepcopy(result)
    cleared.flags.clear()
    after = run_framework(cleared, "cert_in_sbom")
    a = {r["id"]: r["verdict"] for r in before["requirements"]}
    b = {r["id"]: r["verdict"] for r in after["requirements"]}
    assert a == b


def test_empty_findings_out_of_scope() -> None:
    report = run_sbom_compliance([])
    fw = report["cert_in_sbom"]
    assert fw["out_of_scope"] > 0
    assert fw["coverage"] is None


def test_cert_in_sbom_not_in_cbom_or_aibom_runners() -> None:
    from aibom.cbom.compliance import CBOM_FRAMEWORKS
    from aibom.compliance import engine

    assert "cert_in_sbom" not in CBOM_FRAMEWORKS
    assert "cert_in_sbom" not in engine.FRAMEWORKS


def test_enrich_sbom_scan_carries_cert_in_sbom() -> None:
    out = enrich_sbom_scan([_row(purl="pkg:pypi/requests@2.31.0")], 1.23)
    assert out["duration_of_scan"] == 1.23
    assert "results" in out
    fw = out["sbom_compliance"]["cert_in_sbom"]
    assert len(fw["requirements"]) == 41
    assert "rbi_free_ai_supply" in out["sbom_compliance"]


def test_findings_to_scan_result_uses_package_identity_not_sbom_dep() -> None:
    result = findings_to_scan_result([_row(purl="pkg:pypi/requests@2.31.0")])
    refs = [c.bom_ref for c in result.components]
    assert refs == ["pkg:pypi/requests@2.31.0"]
    assert all("sbom-dep" not in r for r in refs)


def test_enrich_overlays_compliance_on_sbom_json() -> None:
    out = enrich_sbom_scan(
        [_row(purl="pkg:pypi/requests@2.31.0")],
        1.0,
        sbom_json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "type": "library",
                }
            ],
        },
    )
    bom = out["sbom_json"]
    props = (bom.get("metadata") or {}).get("properties") or []
    names = {p.get("name") for p in props if isinstance(p, dict)}
    assert names == {"dss:compliance"}
    values = {p.get("value") for p in props if isinstance(p, dict) and p.get("name") == "dss:compliance"}
    assert values <= {"pass", "fail", "unknown"}
    comp_props = bom["components"][0].get("properties") or []
    assert any(p.get("name") == "dss:compliance" for p in comp_props if isinstance(p, dict))
    assert not any(
        str(p.get("name") or "").startswith("syft:") or str(p.get("name") or "") in {"dss:compliant", "dss:impact"}
        for p in comp_props
        if isinstance(p, dict)
    )
