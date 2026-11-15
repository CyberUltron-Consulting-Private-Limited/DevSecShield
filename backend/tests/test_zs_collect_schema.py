"""zs-collect emits the scan-node inventory format (F1.3, CONTRACT section 4).

The committed JSON Schema (scan_node/zs_scan_node/schemas/zs-collect-1.schema.json) must accept a real zs-collect
document (from the F1.3 parity lab: Debian 12, Tier 2) and every asset in it must be the backend's ``AssetIn``, so the
node and the cloud worker can replay the assets through the existing asset routes unchanged.  Malformed documents
must be refused by the schema and by the node-side ``validate_document`` alike.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import jsonschema
import pytest

from backend.utilities.cbom_sources.schemas import AssetIn

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "scan_node" / "zs_scan_node" / "schemas" / "zs-collect-1.schema.json").read_text())
SAMPLE = json.loads((ROOT / "scan_node" / "tests" / "fixtures" / "zs-collect" / "lab-target.json").read_text())
sys.path.insert(0, str(ROOT / "scan_node"))

from zs_scan_node.zscollect import validate_document  # noqa: E402


def test_schema_is_a_valid_draft_2020_12_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_real_document_matches_the_schema_and_every_asset_is_asset_in():
    jsonschema.Draft202012Validator(SCHEMA).validate(SAMPLE)
    assert SAMPLE["assets"]
    for asset in SAMPLE["assets"]:
        parsed = AssetIn.model_validate(asset)
        assert parsed.location == asset["location"] and parsed.type == asset["type"]
    assert validate_document(SAMPLE, nonce=SAMPLE["run_nonce"], version=SAMPLE["collector_version"]) is None


def _broken(path: tuple, value):
    doc = copy.deepcopy(SAMPLE)
    node = doc
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return doc


@pytest.mark.parametrize("path,value", [
    (("format",), "zs-collect/2"),
    (("run_nonce",), "short"),
    (("tier",), 3),
    (("status",), "ok"),
    (("result",), KeyError),
    (("assets", 0, "location"), ""),
    (("assets", 0, "type"), "x" * 33),
    (("assets", 0, "key_size"), -1),
])
def test_malformed_documents_are_refused_by_both_checks(path, value):
    doc = _broken(path, value)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(doc)
    nonce = doc["run_nonce"] if path != ("run_nonce",) else SAMPLE["run_nonce"]
    assert validate_document(doc, nonce=nonce, version=SAMPLE["collector_version"]) is not None
