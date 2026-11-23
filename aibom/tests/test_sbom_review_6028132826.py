"""Review 6028132826 (PR #489) fixes in the aibom SBOM path.

* B2  ``stamp_component_compliance`` / ``overlay_sbom_document`` keep ``dss:version_source`` and
      ``dss:version_constraint`` (and the document-level graph / Grype database properties).
* M1  NTIA-5 and CERT-In T5-Component-Dependencies are partial (not BOM-evidenceable) when the declared graph does
      not reach every component; a declared graph that does reach them passes.
* M3  a file component (``/requirements.txt``) is not counted.
* m3  VEX takes every OSV-style advisory id (GMS, CGA, ALSA, MAL, ...).
"""

from __future__ import annotations

from aibom.compliance.cert_in import vex as VEX
from aibom.sbom.compliance import run_sbom_compliance
from aibom.sbom.cyclonedx_export import overlay_sbom_document, stamp_component_compliance

ROOT = "pkg:github/acme/app@1"


def _bom(graph: str, deps: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-11-24T00:00:00Z",
            "authors": [{"name": "DevSecShield"}],
            "component": {"type": "application", "name": "acme/app", "bom-ref": ROOT},
            "tools": {"components": [{"name": "syft", "version": "1.57.0"}]},
            "properties": [
                {"name": "dss:dependency_graph", "value": graph},
                {"name": "dss:grype_db_built", "value": "2026-11-20T04:12:00Z"},
                {"name": "dss:internal_scratch", "value": "dropped"},
            ],
        },
        "components": [
            {
                "bom-ref": "pkg:pypi/a@1",
                "name": "a",
                "version": "1",
                "purl": "pkg:pypi/a@1",
                "properties": [
                    {"name": "dss:version_source", "value": "range_lower_bound"},
                    {"name": "dss:version_constraint", "value": ">=1"},
                    {"name": "syft:location:0:path", "value": "/requirements.txt"},
                ],
            },
            {"bom-ref": "pkg:pypi/b@2", "name": "b", "version": "2", "purl": "pkg:pypi/b@2"},
            {"bom-ref": "f1", "type": "file", "name": "/requirements.txt"},
        ],
        "dependencies": deps,
    }


ROWS = [
    {"dependency": "a==1", "purl": "pkg:pypi/a@1", "impact": "High", "cves": {"CVE-2024-1": "x"},
     "inventory_only": False, "vuln_assessed": True, "version_guessed_from": ">=1"},
    {"dependency": "b==2", "purl": "pkg:pypi/b@2", "impact": "Low", "inventory_only": True, "vuln_assessed": True},
]


def _props(item: dict) -> dict:
    return {p["name"]: p["value"] for p in item.get("properties") or []}


def test_b2_range_flags_and_document_properties_survive_the_stored_document():
    stored = stamp_component_compliance(overlay_sbom_document(_bom("partial", []), {}), ROWS)
    a = next(c for c in stored["components"] if c["name"] == "a")
    assert _props(a) == {"dss:version_source": "range_lower_bound", "dss:version_constraint": ">=1",
                         "dss:compliance": "fail"}
    meta = _props(stored["metadata"])
    assert meta["dss:dependency_graph"] == "partial"
    assert meta["dss:grype_db_built"] == "2026-11-20T04:12:00Z"
    assert "dss:internal_scratch" not in meta


def _verdict(result: dict, fw: str, rid: str) -> dict:
    return next(r for r in result[fw]["requirements"] if r["id"] == rid)


def test_m1_partial_graph_is_not_a_pass():
    result = run_sbom_compliance(ROWS, sbom_json=_bom("partial", [{"ref": ROOT, "dependsOn": ["pkg:pypi/a@1"]}]))
    ntia5 = _verdict(result, "ntia_minimum_elements", "NTIA-5")
    assert ntia5["verdict"] == "not_bom_evidenceable"
    assert ntia5["evidence"].startswith("partial: 1/2")
    t5 = _verdict(result, "cert_in_sbom", "T5-Component-Dependencies")
    assert t5["verdict"] == "not_bom_evidenceable" and "1/2" in t5["evidence"]


def test_m1_declared_graph_reaching_every_component_passes():
    deps = [{"ref": ROOT, "dependsOn": ["pkg:pypi/a@1"]}, {"ref": "pkg:pypi/a@1", "dependsOn": ["pkg:pypi/b@2"]}]
    result = run_sbom_compliance(ROWS, sbom_json=_bom("declared", deps))
    assert _verdict(result, "ntia_minimum_elements", "NTIA-5")["verdict"] == "pass"
    assert _verdict(result, "cert_in_sbom", "T5-Component-Dependencies")["verdict"] == "pass"


def test_m3_file_components_are_not_counted():
    result = run_sbom_compliance(ROWS, sbom_json=_bom("none", []))
    ntia3 = _verdict(result, "ntia_minimum_elements", "NTIA-3")
    assert ntia3["verdict"] == "pass" and "f1" not in ntia3["refs"]


def test_m3_vex_takes_every_osv_style_advisory_id():
    for raw in ("GMS-2023-1", "CGA-abcd-1234-efgh", "ALSA-2023:1234", "MAL-2024-1234", "DLA-3301-1",
                "SUSE-SU-2023:0001-1", "BIT-golang-2023-1", "RUSTSEC-2021-0001", "PYSEC-2021-1"):
        assert VEX.normalise_advisory_id(raw) == raw, raw
    assert VEX.normalise_advisory_id("cve-2021-1234") == "CVE-2021-1234"
    assert VEX.normalise_advisory_id("GHSA-XQR8-7JWR-RHP7") == "GHSA-xqr8-7jwr-rhp7"
    for bad in ("not an id", "pkg:pypi/x@1", "GHSA-only", ""):
        assert VEX.normalise_advisory_id(bad) is None, bad
