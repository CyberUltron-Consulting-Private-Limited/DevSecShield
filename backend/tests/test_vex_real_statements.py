"""SBOM / AI BOM VEX lists real vulnerability statements only, and a stored VEX written by the old rules is rebuilt.

Staging (audit-C G-D4-3): AI BOM #9's VEX had 103 entries ``not-affected:<component>`` (state not_affected, no
vulnerability id, no justification), SBOM #8's 7. The rules are now ``certin-3`` (utilities/compliance/cert_in/vex.py);
the scan page and the evidence pack serve a stored VEX only when it was written by them, so old scans get the honest
document on their next download.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_vex_real_statements.py -q
"""
from __future__ import annotations

import json
import pathlib

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from backend.routers.certin import _load_certin_module, _vex_is_current
from backend.utilities.cbom_sources import vex_semantics
from backend.utilities.dashboard.scan_metadata import _current_vex

_SCHEMAS = pathlib.Path(__file__).resolve().parents[2] / "aibom" / "src" / "aibom" / "schemas"

OLD_AIBOM_VEX = {  # what staging stored for ai_bom #9 (one of its 103 entries)
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"properties": [{"name": "certin:disclaimer", "value": "default not_affected unless proven"}]},
    "vulnerabilities": [{"id": "not-affected:modelref-gpt-4o", "analysis": {"state": "not_affected"},
                         "affects": [{"ref": "modelref-gpt-4o"}]}],
}


def _validator() -> jsonschema.Draft7Validator:
    def load(name: str) -> dict:
        return json.loads((_SCHEMAS / name).read_text(encoding="utf-8"))

    bom = load("bom-1.6.schema.json")
    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s, default_specification=DRAFT7))
        for s in (bom, load("spdx.schema.json"), load("jsf-0.82.schema.json")))
    return jsonschema.Draft7Validator(bom, registry=registry)


def test_aibom_and_sbom_vex_carry_no_per_component_stubs():
    vex = _load_certin_module("vex")
    bom = {"components": [{"bom-ref": f"c{i}", "name": f"n{i}"} for i in range(103)]}
    for scan_type in ("ai_bom", "sbom_sca"):
        doc = vex.build_vex(bom=bom, findings=[{"dependency": "n1", "cves": {}}], scan_type=scan_type)
        assert doc["vulnerabilities"] == []
        assert not list(_validator().iter_errors(doc))


def test_sbom_cve_statement_is_valid_cyclonedx_vex():
    vex = _load_certin_module("vex")
    bom = {"components": [{"bom-ref": "pkg:pypi/flask@0.12", "name": "flask", "version": "0.12"}]}
    doc = vex.build_vex(bom=bom, findings=[{"dependency": "flask", "version": "0.12", "impact": "High",
                                            "cves": ["CVE-2018-1000656"]}], scan_type="sbom_sca")
    (entry,) = doc["vulnerabilities"]
    assert entry["id"] == "CVE-2018-1000656" and entry["analysis"]["state"] == "in_triage"
    assert entry["affects"] == [{"ref": "pkg:pypi/flask@0.12"}]
    assert not list(_validator().iter_errors(doc))


def test_rules_version_is_one_value():
    assert _load_certin_module("vex").VEX_RULES == vex_semantics.CERTIN_VEX_RULES


def test_old_vex_is_rebuilt_not_served():
    new = _load_certin_module("vex").build_vex(bom=None, scan_type="ai_bom")
    for scan_type in ("ai_bom", "sbom_sca"):
        assert not _vex_is_current(scan_type, OLD_AIBOM_VEX)
        assert _vex_is_current(scan_type, new)
        assert _current_vex(scan_type, OLD_AIBOM_VEX) is None
        assert _current_vex(scan_type, new) is new
