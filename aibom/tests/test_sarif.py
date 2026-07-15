"""SARIF 2.1.0 reporter tests: ScanResult.flags -> schema-valid SARIF results."""

from __future__ import annotations

import json
import pathlib

from aibom.emit.sarif import emit_and_validate_sarif, emit_sarif
from aibom.emit.validate import validate_sarif
from aibom.model.component import MetadataComponent
from aibom.model.result import Flag, ScanResult
from aibom.scan.pipeline import scan_repo

_FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)
_GOLDEN = _FIXTURE / "expected" / "chestxr.sarif.json"


def test_sarif_is_schema_valid() -> None:
    doc = emit_and_validate_sarif(scan_repo(_FIXTURE))  # raises if invalid
    assert validate_sarif(doc) == []
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "clinithread-aibom"


def test_sarif_renders_one_result_per_flag() -> None:
    doc = emit_sarif(scan_repo(_FIXTURE))
    results = doc["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert {"MODEL_EU_AI_ACT_HIGH_RISK", "MODEL_PHI_AT_INFERENCE"} <= rule_ids
    for r in results:
        assert r["level"] in {"none", "note", "warning", "error"}
        assert r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
        assert isinstance(r["ruleIndex"], int)


def test_sarif_empty_flags_is_valid() -> None:
    """No flags -> a valid SARIF run with zero results (clean CI gate)."""
    empty = ScanResult(subject=MetadataComponent(name="app"))
    doc = emit_and_validate_sarif(empty)
    assert doc["runs"][0]["results"] == []


def test_sarif_bom_level_flag_has_no_location() -> None:
    r = ScanResult(
        subject=MetadataComponent(name="app"),
        flags=[Flag("BOM_LEVEL", target="", severity="note", message="m")],
    )
    doc = emit_and_validate_sarif(r)
    assert "locations" not in doc["runs"][0]["results"][0]


def test_sarif_matches_golden() -> None:
    assert emit_and_validate_sarif(scan_repo(_FIXTURE)) == json.loads(
        _GOLDEN.read_text()
    )
