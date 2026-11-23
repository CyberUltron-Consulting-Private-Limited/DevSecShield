"""Review 6028132826 (PR #489) fixes on the API side, on the reviewer's own outputs.

* B1  ``/bom`` for we45/Vulnerable-Flask-App validates as strict CycloneDX 1.6 JSON and XSD with cyclonedx-python-lib
      (the registry gave chardet "LGPL" and mysql-python "GPL", which were written as ``license.id``).
* B2  a version guessed from a range keeps ``dss:version_source`` / ``dss:version_constraint`` through
      ``enrich_sbom_scan`` to ``/bom`` (pcap-hunter: 39 components) and gets no registry hash.
* M1  ``/bom`` never makes up dependency edges: no edges from the tools -> ``compositions`` incomplete and NTIA-5 /
      CERT-In T5 partial (not BOM-evidenceable), not pass.
* M3  the stored compliance equals the compliance of the very ``/bom`` document.
* M4  the dashboard's licence chart and high-risk count are over the SBOM's components.
* M6  an evidence pack leaves out a stored signature whose digest is not the packed ``bom.cdx.json``'s.
* m1  the PDF's minimum-elements page reads the ``/bom`` document (same subject) and prints its SHA-256.

Fixtures (tests/fixtures/sbom_d4/): the reviewer's run A (qa/489/bench/run-A) at PR head 9d3696d3c.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from backend.utilities.compliance import sbom_registry
from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data

FIX = Path(__file__).resolve().parent / "fixtures" / "sbom_d4"
VFA = json.loads((FIX / "vfa-review-run-a.json").read_text())
PCAP = json.loads((FIX / "pcap-hunter-worker-run-a.json").read_text())


def _aibom():
    from backend.utilities.cbom_sources.run_parity import engine

    engine()  # puts aibom/src on the path (checkout) or /opt/aibom/src (image)
    from aibom.integrations.sbom_devsecshield import enrich_sbom_scan
    from aibom.sbom.compliance import run_sbom_compliance

    return enrich_sbom_scan, run_sbom_compliance


@pytest.fixture
def registry(monkeypatch):
    """The answers the reviewer's /bom download got from PyPI / GitHub (keyed by purl), without a network."""
    answers = VFA["registry"]

    def lookup(eco, name, version):
        for purl, meta in answers.items():
            body = purl[4:]
            if body.startswith(f"{eco}/") and body.rsplit("@", 1)[0].split("/", 1)[1].lower() == name.lower():
                out = dict(meta)
                if "hash" in out:
                    out["hash"] = tuple(out["hash"])
                return out
        if eco == "pypi":  # pcap-hunter's packages: a hash for every one (only pinned versions may take it)
            return {"license": "MIT", "author": "someone", "hash": ("SHA-256", "ab" * 32), "depends": []}
        return None

    monkeypatch.setattr(sbom_registry, "lookup_package", lookup)
    return lookup


def _vfa_bom() -> dict:
    return bom_dict_from_scan_data("sbom_sca", copy.deepcopy(VFA["scan_data"]))


def _cyclonedx():
    if os.environ.get("CI"):
        import cyclonedx  # noqa: F401  CI installs cyclonedx-python-lib (ci.yml backend test-command): never skipped
    return pytest.importorskip("cyclonedx")


# ------------------------------------------------------------------------------------------------------------ B1
def test_b1_registry_licence_that_is_not_an_spdx_id_goes_in_license_name(registry):
    bom = _vfa_bom()
    by = {c["name"]: c for c in bom["components"]}
    assert by["chardet"]["licenses"] == [{"license": {"name": "LGPL"}}]
    assert by["mysql-python"]["licenses"] == [{"license": {"name": "GPL"}}]
    assert by["flask"]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
    from backend.utilities.compliance.spdx_license import canonical_id

    for comp in bom["components"]:
        for item in comp.get("licenses") or []:
            if "license" in item and "id" in item["license"]:
                assert canonical_id(item["license"]["id"]) == item["license"]["id"], comp["name"]


def test_b1_vulnerable_flask_app_bom_is_strict_cyclonedx_16_json_and_xsd(registry):
    _cyclonedx()
    from cyclonedx.model.bom import Bom
    from cyclonedx.output import make_outputter
    from cyclonedx.schema import OutputFormat, SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    from cyclonedx.validation.xml import XmlValidator

    text = json.dumps(_vfa_bom())
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    assert error is None, str(getattr(error, "data", error))[:500]
    parsed = Bom.from_json(json.loads(text))  # type: ignore[attr-defined]
    xml = make_outputter(parsed, OutputFormat.XML, SchemaVersion.V1_6).output_as_string()
    error = XmlValidator(SchemaVersion.V1_6).validate_str(xml)
    assert error is None, str(error)[:500]
    assert len(parsed.components) == 32


# ------------------------------------------------------------------------------------------------------------ B2
def test_b2_range_flags_survive_enrich_sbom_scan_to_bom_without_registry_hashes(registry):
    enrich_sbom_scan, _ = _aibom()
    worker = copy.deepcopy(PCAP["worker_sbom"])
    flagged_in = {c["purl"] for c in worker["components"]
                  if any(p.get("name") == "dss:version_source" for p in c.get("properties") or [])}
    assert len(flagged_in) == 39
    stored = enrich_sbom_scan(copy.deepcopy(PCAP["results"]), 1.0, sbom_json=worker)
    # the stored document (what scan_data.sbom_json holds) keeps the flags ...
    kept = {c["purl"] for c in stored["sbom_json"]["components"]
            if any(p.get("name") == "dss:version_source" and p.get("value") == "range_lower_bound"
                   for p in c.get("properties") or [])}
    assert kept == flagged_in
    # ... and so does /bom, with the constraint, and no registry hash on a guessed version
    bom = bom_dict_from_scan_data("sbom_sca", stored)
    flagged = [c for c in bom["components"]
               if any(p.get("name") == "dss:version_source" for p in c.get("properties") or [])]
    assert len(flagged) == 39
    for comp in flagged:
        names = {p["name"] for p in comp["properties"]}
        assert "dss:version_constraint" in names, comp["purl"]
        assert not comp.get("hashes"), comp["purl"]
    pinned = [c for c in bom["components"] if c["purl"].startswith("pkg:pypi/") and c not in flagged]
    assert pinned and all(c.get("hashes") for c in pinned)  # a pinned version still gets its registry hash


# ------------------------------------------------------------------------------------------------------------ M1
def _no_edges(scan_data: dict) -> dict:
    """The tools' own output for a requirements.txt repository: no dependency edges at all."""
    out = copy.deepcopy(scan_data)
    out["sbom_json"].pop("dependencies", None)
    return out


def test_m1_bom_never_makes_up_dependency_edges(registry):
    bom = bom_dict_from_scan_data("sbom_sca", _no_edges(VFA["scan_data"]))
    root = bom["metadata"]["component"]["bom-ref"]
    root_edges = [d for d in bom.get("dependencies") or [] if d["ref"] == root]
    assert not root_edges or not root_edges[0].get("dependsOn")  # the subject does not "depend on" all 32
    comps = {c["aggregate"]: c["dependencies"] for c in bom["compositions"]}
    assert comps["incomplete"] == [root]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["dss:dependency_graph"] in {"partial", "none"}


def test_m1_ntia5_and_certin_t5_are_partial_not_pass_without_declared_edges(registry):
    _, run_sbom_compliance = _aibom()
    data = _no_edges(VFA["scan_data"])
    bom = bom_dict_from_scan_data("sbom_sca", data)
    result = run_sbom_compliance(data["results"], sbom_json=bom)
    ntia = {r["id"]: r for r in result["ntia_minimum_elements"]["requirements"]}
    dep = ntia["NTIA-5"]
    assert dep["verdict"] == "not_bom_evidenceable" and dep["evidence"].startswith("partial"), dep
    t5 = next(r for r in result["cert_in_sbom"]["requirements"] if r["id"] == "T5-Component-Dependencies")
    assert t5["verdict"] == "not_bom_evidenceable" and "partial" in t5["evidence"], t5


# ------------------------------------------------------------------------------------------------------------ M3
def test_m3_stored_compliance_equals_compliance_on_the_downloaded_bom(registry):
    enrich_sbom_scan, run_sbom_compliance = _aibom()
    worker = copy.deepcopy(PCAP["worker_sbom"])
    worker["components"].append({"type": "file", "name": "/requirements.txt", "bom-ref": "f1"})  # Syft 1.57 lists it
    worker["metadata"].setdefault("properties", []).append({"name": "dss:registry", "value": "off: 0/0 resolved"})
    stored = enrich_sbom_scan(copy.deepcopy(PCAP["results"]), 1.0, sbom_json=worker)
    bom = bom_dict_from_scan_data("sbom_sca", stored)
    again = run_sbom_compliance(stored["results"], sbom_json=bom)

    def verdicts(result):
        return {(fw, r["id"]): r["verdict"] for fw, block in result.items() if isinstance(block, dict)
                for r in block.get("requirements") or []}

    assert verdicts(stored["sbom_compliance"]) == verdicts(again)
    assert len(bom["components"]) == len([c for c in stored["sbom_json"]["components"] if c.get("purl")])


# ------------------------------------------------------------------------------------------------------------ M4
def test_m4_licence_chart_and_high_risk_count_are_over_components():
    from backend.utilities.dashboard.sbom_rows import component_licence_categories

    data = {
        "results": [{"dependency": "pillow==10.0", "purl": "pkg:pypi/pillow@10.0", "impact": "Critical",
                     "license": "MIT-CMU", "license_type": "permissive"}],
        "sbom_json": {"components": [
            {"name": "pillow", "purl": "pkg:pypi/pillow@10.0", "licenses": [{"license": {"id": "MIT-CMU"}}]},
            {"name": "scapy", "purl": "pkg:pypi/scapy@2.8.0", "licenses": [{"license": {"id": "GPL-2.0-only"}}]},
            {"name": "chardet", "purl": "pkg:pypi/chardet@3.0.4", "licenses": [{"license": {"name": "LGPL"}}]},
            {"name": "/requirements.txt", "type": "file"},
        ]},
    }
    cats = component_licence_categories(data)
    assert sorted(cats) == ["permissive", "strong_copyleft", "weak_copyleft"]


def test_m2_guessed_version_rows_are_not_counted_in_severity_totals():
    from backend.utilities.dashboard.sbom_rows import severity_rows, unverified_version_rows

    rows = [{"impact": "Critical", "dependency": "pillow==10.0", "version_guessed_from": ">=10.0"},
            {"impact": "High", "dependency": "flask==0.12.2"},
            {"impact": "Low", "dependency": "click==8", "inventory_only": True}]
    assert [r["dependency"] for r in severity_rows(rows)] == ["flask==0.12.2"]
    assert [r["dependency"] for r in unverified_version_rows(rows)] == ["pillow==10.0"]


# ------------------------------------------------------------------------------------------------------------ M6
def test_m6_stale_stored_signature_is_left_out_of_the_pack():
    from backend.routers.certin import _signature_matches
    from backend.utilities.compliance.cert_in.sign import sign_bom

    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "a"}]}
    fresh = sign_bom(bom, secret=b"k")
    stale = sign_bom({**bom, "specVersion": "1.7"}, secret=b"k")
    assert _signature_matches(bom, fresh) is True
    assert _signature_matches(bom, stale) is False
    assert _signature_matches(None, fresh) is False


# ------------------------------------------------------------------------------------------------------------ m1
def test_pdf_minimum_elements_read_the_bom_route_document(registry):
    from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data as route_builder
    from backend.utilities.pdf import sbom_sca_pdf

    data = copy.deepcopy(VFA["scan_data"])
    data["sbom_json"]["metadata"]["component"]["name"] = "repo_ab12cd34"  # an older scan's clone directory name
    data[sbom_sca_pdf.SUBJECT_NAME_KEY] = "we45/Vulnerable-Flask-App"
    pdf_bom = sbom_sca_pdf._downloaded_bom(data)
    route_bom = route_builder("sbom_sca", copy.deepcopy(VFA["scan_data"]) | {
        "sbom_json": data["sbom_json"]}, subject_name="we45/Vulnerable-Flask-App")
    assert pdf_bom == route_bom
    assert pdf_bom["metadata"]["component"]["name"] == "we45/Vulnerable-Flask-App"
    assert len(sbom_sca_pdf.bom_sha256(pdf_bom)) == 64
