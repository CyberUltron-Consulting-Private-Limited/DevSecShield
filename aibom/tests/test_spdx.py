"""SPDX 3.0.1 emitter tests: schema-valid AI + Dataset profiles from one scan."""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.emit.spdx import SpdxValidationError, emit_and_validate_spdx, emit_spdx
from aibom.emit.validate import validate_spdx
from aibom.scan.pipeline import scan_repo

_FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)
_GOLDEN = _FIXTURE / "expected" / "chestxr.spdx.json"


def _graph_by_type(doc: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for el in doc["@graph"]:
        out.setdefault(el.get("type", ""), []).append(el)
    return out


def test_spdx_is_schema_valid() -> None:
    doc = emit_and_validate_spdx(scan_repo(_FIXTURE))  # raises if invalid
    assert validate_spdx(doc) == []
    assert doc["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


def test_spdx_has_ai_and_dataset_profiles() -> None:
    doc = emit_spdx(scan_repo(_FIXTURE))
    by_type = _graph_by_type(doc)

    # AI Profile: one ai_AIPackage carrying architecture, risk, PHI flag, metrics.
    ai = by_type["ai_AIPackage"]
    assert len(ai) == 1
    pkg = ai[0]
    assert pkg["name"] == "chestxr-nodule-detector"
    assert any("ResNet-50" in t for t in pkg["ai_typeOfModel"])
    assert pkg["ai_safetyRiskAssessment"] == "serious"
    assert pkg["ai_useSensitivePersonalInformation"] == "yes"
    assert pkg["ai_informationAboutApplication"]
    assert {m["key"].split(" ")[0] for m in pkg["ai_metric"]} == {
        "AUROC",
        "sensitivity",
    }

    # Dataset Profile: datasetType is MANDATORY and an enum value.
    ds = by_type["dataset_DatasetPackage"]
    assert len(ds) == 1
    d = ds[0]
    assert d["dataset_datasetType"] == ["image"]
    assert d["dataset_datasetSize"] == 412000  # parsed to int
    assert d["dataset_hasSensitivePersonalInformation"] == "no"
    assert d["dataset_dataPreprocessing"]
    assert d["dataset_knownBias"]
    assert d["dataset_intendedUse"]


def test_spdx_exactly_one_concluded_license_per_model() -> None:
    """Every AIPackage must have exactly one hasConcludedLicense relationship."""
    doc = emit_spdx(scan_repo(_FIXTURE))
    by_type = _graph_by_type(doc)
    model_ids = {p["spdxId"] for p in by_type["ai_AIPackage"]}
    concluded = [
        r
        for r in by_type.get("Relationship", [])
        if r["relationshipType"] == "hasConcludedLicense" and r["from"] in model_ids
    ]
    assert len(concluded) == len(model_ids) == 1
    # The relationship points at a license expression element.
    lic_ids = {lic["spdxId"] for lic in by_type["simplelicensing_LicenseExpression"]}
    assert concluded[0]["to"][0] in lic_ids


def test_spdx_relationships_train_and_depend() -> None:
    doc = emit_spdx(scan_repo(_FIXTURE))
    rels = {
        r["relationshipType"]
        for r in _graph_by_type(doc).get("Relationship", [])
    }
    assert {"hasConcludedLicense", "trainedOn", "dependsOn"} <= rels


def test_spdx_matches_golden() -> None:
    regenerated = emit_and_validate_spdx(scan_repo(_FIXTURE))
    assert regenerated == json.loads(_GOLDEN.read_text())


def test_spdx_is_deterministic() -> None:
    a = emit_spdx(scan_repo(_FIXTURE))
    b = emit_spdx(scan_repo(_FIXTURE))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_spdx_raises_on_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    """emit_and_validate_spdx raises when the document is not schema-valid."""
    from aibom.emit import spdx as spdx_mod

    def _broken(_aibom: object) -> dict:
        # datasetType is mandatory; drop it to force a schema error.
        return {"@context": spdx_mod.SPDX_CONTEXT, "@graph": [{"type": "Relationship"}]}

    monkeypatch.setattr(spdx_mod, "emit_spdx", _broken)
    with pytest.raises(SpdxValidationError):
        spdx_mod.emit_and_validate_spdx(scan_repo(_FIXTURE))
