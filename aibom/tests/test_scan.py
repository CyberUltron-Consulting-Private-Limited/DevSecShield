"""Scan-layer tests: the clinical-imaging fixture -> a scored ScanResult with a
schema-valid CycloneDX BOM, the trained_on edge, and at least one flag.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx
from aibom.model.result import REL_DEPENDS_ON, REL_TRAINED_ON
from aibom.scan.pipeline import scan_repo

_FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)
_GOLDEN = _FIXTURE / "expected" / "chestxr.cdx.json"


def test_scan_produces_components_edges_flags_and_score() -> None:
    """One scan yields components, a typed edge graph, flags, and a score."""
    result = scan_repo(_FIXTURE)

    kinds = sorted(c.kind for c in result.components)
    assert kinds.count("model") == 1
    assert kinds.count("dataset") == 1
    assert kinds.count("framework") == 5

    # The trained_on edge (model -> dataset) is present.
    trained = result.out_edges("model-chestxr-cnn", REL_TRAINED_ON)
    assert [e.dst for e in trained] == ["dataset-chestxr-train"]
    # depends_on edges to every framework are present.
    depends = result.out_edges("model-chestxr-cnn", REL_DEPENDS_ON)
    assert {e.dst for e in depends} == {
        "lib-numpy", "lib-pydicom", "lib-safetensors", "lib-torch", "lib-torchvision"
    }

    # At least one flag, and the scorer produced a positive risk score.
    assert result.flags
    assert {f.code for f in result.flags} >= {
        "MODEL_EU_AI_ACT_HIGH_RISK",
        "MODEL_PHI_AT_INFERENCE",
    }
    assert result.scores["risk_total"] > 0
    assert result.scores["by_component"]["model-chestxr-cnn"] > 0


def test_scan_emits_schema_valid_cyclonedx() -> None:
    bom = emit_and_validate(scan_repo(_FIXTURE))  # raises if invalid
    assert validate_cyclonedx(bom) == []
    assert bom["specVersion"] == "1.6"
    by_type = {}
    for c in bom["components"]:
        by_type.setdefault(c["type"], []).append(c)
    model = by_type["machine-learning-model"][0]
    assert model["name"] == "chestxr-nodule-detector"
    assert model["modelCard"]["modelParameters"]["modelArchitecture"] == "ResNet-50"
    assert by_type["data"][0]["bom-ref"] == "dataset-chestxr-train"
    # The trained_on edge surfaces as a CycloneDX dependsOn target.
    dep = next(d for d in bom["dependencies"] if d["ref"] == "model-chestxr-cnn")
    assert "dataset-chestxr-train" in dep["dependsOn"]


def test_scan_matches_committed_golden() -> None:
    regenerated = emit_and_validate(scan_repo(_FIXTURE))
    assert regenerated == json.loads(_GOLDEN.read_text()), (
        "Scan output drifted from the committed golden. If intended, regenerate: "
        "uv run aibom emit -f cyclonedx examples/clinical-imaging "
        "-o examples/clinical-imaging/expected/chestxr.cdx.json"
    )


def test_scan_is_deterministic() -> None:
    a = emit_cyclonedx(scan_repo(_FIXTURE))
    b = emit_cyclonedx(scan_repo(_FIXTURE))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_scan_rejects_non_directory(tmp_path: pathlib.Path) -> None:
    afile = tmp_path / "not-a-dir.txt"
    afile.write_text("x")
    with pytest.raises(NotADirectoryError):
        scan_repo(afile)
