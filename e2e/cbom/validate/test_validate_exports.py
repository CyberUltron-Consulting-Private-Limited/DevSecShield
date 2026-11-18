"""The G12 validators accept a valid export and reject broken ones (positive and negative controls).

Needs the pinned validator libraries (requirements.txt); run:
    uv run --no-project --with-requirements e2e/cbom/validate/requirements.txt --with pytest \
        python3 -m pytest -q e2e/cbom/validate/test_validate_exports.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cyclonedx.validation.json")
pytest.importorskip("xmlschema")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_exports as V  # noqa: E402

BOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
       "version": 1, "metadata": {"timestamp": "2026-11-12T10:00:00Z",
                                  "properties": [{"name": "zs:engine_version", "value": "1.0.0+3df26fd8ec02"}]},
       "components": [{"type": "cryptographic-asset", "bom-ref": "zs-asset-1", "name": "z01.lab:443",
                       "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.3"}}}]}
XML = ('<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.6" '
       'serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1"><components>'
       '<component type="cryptographic-asset" bom-ref="zs-asset-1"><name>z01.lab:443</name></component></components></bom>\n')


def _write(tmp: Path, bom: dict, xml: str) -> Path:
    (tmp / "exports").mkdir()
    (tmp / "exports" / "run1.cdx.json").write_text(json.dumps(bom))
    (tmp / "exports" / "run1.cdx.xml").write_text(xml)
    return tmp


def test_valid_bom_passes(tmp_path):
    run = _write(tmp_path, BOM, XML)
    res = {r["name"]: r["ok"] for r in V.cdx_json(run / "exports" / "run1.cdx.json", "3df26fd8ec02") + V.cdx_xml(run / "exports" / "run1.cdx.xml")}
    assert res == {"cdx_json_schema": True, "cdx_json_strict": True, "cdx_engine_version_eq_build": True,
                   "cdx_xml_schema": True, "cdx_xml_lib": True}


def test_broken_boms_fail(tmp_path):
    bad = json.loads(json.dumps(BOM))
    bad["components"][0]["cryptoProperties"]["assetType"] = "quantum-thing"   # not in the 1.6 enum
    bad["metadata"]["timestamp"] = "yesterday"                                 # format checker
    bad["metadata"]["properties"][0]["value"] = "unknown"
    run = _write(tmp_path, bad, XML.replace("<name>", "<nome>").replace("</name>", "</nome>"))
    res = {r["name"]: r for r in V.cdx_json(run / "exports" / "run1.cdx.json", "3df26fd8ec02") + V.cdx_xml(run / "exports" / "run1.cdx.xml")}
    assert not res["cdx_json_schema"]["ok"] and res["cdx_json_schema"]["observed"]["errors"] >= 2
    assert not res["cdx_json_strict"]["ok"]
    assert not res["cdx_engine_version_eq_build"]["ok"]
    assert not res["cdx_xml_schema"]["ok"] and not res["cdx_xml_lib"]["ok"]


def test_oscal_needs_the_model(tmp_path):
    (tmp_path / "exports").mkdir()
    p = tmp_path / "exports" / "run1.oscal.json"
    p.write_text(json.dumps({"assessment-results": {"uuid": "not-a-uuid", "metadata": {}}}))
    [r] = V.oscal(p)
    assert not r["ok"] and r["observed"]["errors"] >= 2
