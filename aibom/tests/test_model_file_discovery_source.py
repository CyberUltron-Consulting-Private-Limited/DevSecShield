"""Model-file scanner stamps discovery:source so findings get a real location.

Shadow AI rows for hash-named ``.bin`` / ``.safetensors`` weight files were
landing with empty ``location`` because the scanner only set
``model:weight_file=true``. The adapter maps ``discovery:source`` →
``finding.location`` — this test locks that path end-to-end.
"""

from __future__ import annotations

import pathlib

from aibom.integrations.devsecshield import normalize, run_native_scan
from aibom.scan.pipeline import scan_repo

_CLINICAL = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)


def test_model_file_component_carries_discovery_source() -> None:
    result = scan_repo(_CLINICAL)
    files = [c for c in result.components if c.kind == "model_file"]
    assert files, "clinical-imaging ships model.safetensors"
    for c in files:
        props = c.properties or {}
        assert props.get("model:weight_file") == "true"
        src = props.get("discovery:source")
        assert src, f"{c.name} missing discovery:source"
        assert src.endswith(c.name)
        assert ".." not in src.split("/")


def test_adapter_location_populated_for_model_file() -> None:
    result = run_native_scan(_CLINICAL)
    out = normalize(result, duration_of_scan=0.0)
    named = [f for f in out["results"] if f["component_name"] == "model.safetensors"]
    assert named, "expected model.safetensors finding row"
    assert named[0]["location"] == "model.safetensors"
