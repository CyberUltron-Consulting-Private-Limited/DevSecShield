"""CycloneDX <-> SPDX field-parity: the same model/dataset facts in both formats.

One scan, two serializers — the core facts a reviewer cares about (model
identity/architecture/license/metrics and dataset identity/type) must be present
and consistent across CycloneDX 1.6 and SPDX 3.0.1.
"""

from __future__ import annotations

import pathlib

from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.emit.spdx import emit_spdx
from aibom.scan.pipeline import scan_repo

_FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)


def _cdx_model(bom: dict) -> dict:
    return next(c for c in bom["components"] if c["type"] == "machine-learning-model")


def _cdx_dataset(bom: dict) -> dict:
    return next(c for c in bom["components"] if c["type"] == "data")


def _spdx_first(doc: dict, t: str) -> dict:
    return next(el for el in doc["@graph"] if el.get("type") == t)


def test_cyclonedx_spdx_parity() -> None:
    aibom = scan_repo(_FIXTURE)  # single scan, two emits
    cdx = emit_cyclonedx(aibom)
    spdx = emit_spdx(aibom)

    cdx_model = _cdx_model(cdx)
    ai = _spdx_first(spdx, "ai_AIPackage")

    # (1) Model identity + version.
    assert cdx_model["name"] == ai["name"]
    assert cdx_model["version"] == ai["software_packageVersion"]

    # (2) Architecture: CycloneDX modelArchitecture appears in SPDX ai_typeOfModel.
    arch = cdx_model["modelCard"]["modelParameters"]["modelArchitecture"]
    assert any(arch in t for t in ai["ai_typeOfModel"])

    # (3) License: same SPDX id in CycloneDX licenses and SPDX license expression.
    cdx_lic = cdx_model["licenses"][0]["license"]["id"]
    lic_expr = _spdx_first(spdx, "simplelicensing_LicenseExpression")
    assert lic_expr["simplelicensing_licenseExpression"] == cdx_lic == "Apache-2.0"

    # (4) Metrics: every CycloneDX performance metric type is present in SPDX.
    cdx_metric_types = {
        m["type"] for m in cdx_model["modelCard"]["quantitativeAnalysis"][
            "performanceMetrics"
        ]
    }
    spdx_metric_keys = {m["key"].split(" ")[0] for m in ai["ai_metric"]}
    assert cdx_metric_types <= spdx_metric_keys

    # (5) Dataset identity + type parity.
    cdx_ds = _cdx_dataset(cdx)
    ds = _spdx_first(spdx, "dataset_DatasetPackage")
    assert cdx_ds["name"] == ds["name"]
    cdx_ds_props = {p["name"]: p["value"] for p in cdx_ds["properties"]}
    # CycloneDX free-text "image (DICOM)" <-> SPDX enum "image".
    assert "image" in cdx_ds_props["dataset:type"].lower()
    assert ds["dataset_datasetType"] == ["image"]

    # (6) The model->dataset link exists in both (CycloneDX dependsOn / SPDX trainedOn).
    cdx_dep = next(d for d in cdx["dependencies"] if d["ref"] == cdx_model["bom-ref"])
    assert cdx_ds["bom-ref"] in cdx_dep["dependsOn"]
    trained = next(
        r
        for r in spdx["@graph"]
        if r.get("type") == "Relationship" and r["relationshipType"] == "trainedOn"
    )
    assert ds["spdxId"] in trained["to"]
