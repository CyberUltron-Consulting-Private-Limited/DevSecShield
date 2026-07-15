"""CycloneDX emitter unit tests over an in-code ScanResult.

Exercises the normalize -> emit path on a hand-built :class:`ScanResult`,
independent of the scan layer.

HARD RULES: every emitted BOM schema-validates; healthcare metadata appears only
inside namespaced ``properties[]``; the serializer is PURE (byte-stable); edges
collapse into CycloneDX ``dependencies``.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from pydantic import ValidationError

from aibom.emit.cyclonedx import (
    ADVISORY_DISCLAIMER,
    BomValidationError,
    emit_and_validate,
    emit_cyclonedx,
)
from aibom.emit.validate import validate_cyclonedx
from aibom.model.component import (
    DatasetComponent,
    ExternalReference,
    FrameworkComponent,
    Hash,
    MetadataComponent,
    ModelCard,
    ModelComponent,
    PerformanceMetric,
)
from aibom.model.result import REL_DEPENDS_ON, REL_TRAINED_ON, Edge, Flag, ScanResult

_SCHEMA = (
    pathlib.Path(__file__).resolve().parent.parent
    / "src" / "aibom" / "schemas" / "bom-1.6.schema.json"
)


@pytest.fixture(scope="module")
def allowed_component_keys() -> set[str]:
    """Exact CycloneDX 1.6 component-level keys (additionalProperties:false)."""
    schema = json.loads(_SCHEMA.read_text())
    return set(schema["definitions"]["component"]["properties"].keys())


def _small_result() -> ScanResult:
    """A minimal in-code ScanResult: one model + one dataset + one library."""
    model = ModelComponent(
        bom_ref="model-mini",
        name="mini-lesion-classifier",
        version="0.1.0",
        publisher="Test Clinic AI",
        licenses=[{"license": {"id": "Apache-2.0"}}],
        hashes=[
            Hash(
                alg="SHA-256",
                content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
        ],
        external_references=[
            ExternalReference(
                type="model-card", url="https://example.test/mini.modelcard.json"
            )
        ],
        model_card=ModelCard(
            approach_type="supervised",
            task="classification",
            architecture_family="convolutional neural network",
            model_architecture="ResNet-18",
            datasets=["dataset-mini"],
            inputs=["DICOM image"],
            outputs=["lesion probability"],
            performance_metrics=[
                PerformanceMetric(type="AUROC", value="0.90", slice="overall")
            ],
            intended_use="research-only triage assist",
            modality="MR",
            body_part="brain",
            fda_product_code="QFM",
            device_class="II (SaMD)",
            eu_ai_act_risk_tier="high-risk (Annex I / MDR)",
        ),
    )
    dataset = DatasetComponent(
        bom_ref="dataset-mini",
        name="mini-training-cohort",
        licenses=[{"license": {"name": "internal-restricted"}}],
        dataset_type="image (DICOM)",
        dataset_size="10,000 studies",
        sensitivity="PHI removed; Safe Harbor de-identification",
        known_bias="single-site, single-scanner-vendor",
    )
    lib = FrameworkComponent(
        bom_ref="lib-torch", name="torch", version="2.3.1", purl="pkg:pypi/torch@2.3.1"
    )
    return ScanResult(
        subject=MetadataComponent(
            type="application", name="Mini-SaMD", version="0.1.0"
        ),
        components=[model, dataset, lib],
        edges=[
            Edge("model-mini", REL_TRAINED_ON, "dataset-mini"),
            Edge("model-mini", REL_DEPENDS_ON, "lib-torch"),
        ],
        flags=[Flag("MODEL_EU_AI_ACT_HIGH_RISK", "model-mini", "warning", "high-risk")],
        properties={"clinical:modality": "MR", "regulatory:device_class": "II (SaMD)"},
    )


def test_emit_is_schema_valid() -> None:
    bom = emit_cyclonedx(_small_result())
    types = sorted(c["type"] for c in bom["components"])
    assert types == ["data", "library", "machine-learning-model"]
    assert validate_cyclonedx(bom) == []
    assert emit_and_validate(_small_result()) == bom


def test_edges_become_dependencies() -> None:
    bom = emit_cyclonedx(_small_result())
    dep = next(d for d in bom["dependencies"] if d["ref"] == "model-mini")
    # Both edge types (trained_on, depends_on) collapse into dependsOn.
    assert dep["dependsOn"] == ["dataset-mini", "lib-torch"]


def test_healthcare_props_namespaced(allowed_component_keys: set[str]) -> None:
    bom = emit_cyclonedx(_small_result())
    for comp in bom["components"]:
        leaked = set(comp.keys()) - allowed_component_keys
        assert not leaked, f"{comp.get('bom-ref')!r} leaked non-spec keys: {leaked}"
        for key in comp:
            assert not key.startswith(("clinical:", "regulatory:", "dataset:")), key

    model_comp = next(
        c for c in bom["components"] if c["type"] == "machine-learning-model"
    )
    model_props = {p["name"]: p["value"] for p in model_comp["properties"]}
    assert model_props["clinical:modality"] == "MR"
    assert model_props["regulatory:fda_product_code"] == "QFM"
    assert "intended_use" not in json.dumps(model_comp["modelCard"])

    bom_props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert bom_props["regulatory:disclaimer"] == ADVISORY_DISCLAIMER


def test_deterministic_serial_and_bytes() -> None:
    a = emit_cyclonedx(_small_result())
    b = emit_cyclonedx(_small_result())
    assert a["serialNumber"] == b["serialNumber"]
    assert a["serialNumber"].startswith("urn:uuid:")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_external_reference_without_url_is_unconstructable() -> None:
    with pytest.raises(ValidationError):
        ExternalReference(type="model-card")  # type: ignore[call-arg]


def test_emit_and_validate_raises_on_invalid_bom() -> None:
    valid = emit_cyclonedx(_small_result())
    assert validate_cyclonedx(valid) == []

    corrupted = json.loads(json.dumps(valid))
    del corrupted["bomFormat"]
    assert validate_cyclonedx(corrupted)

    corrupted2 = json.loads(json.dumps(valid))
    corrupted2["components"][0]["intended_use"] = "leaked clinical field"
    assert validate_cyclonedx(corrupted2)

    bad = _small_result()
    bad.subject.name = ""  # schema requires a non-empty component name
    bom = emit_cyclonedx(bad)
    if validate_cyclonedx(bom):
        with pytest.raises(BomValidationError):
            emit_and_validate(bad)


def test_subschema_refs_enforce_through_registry() -> None:
    """The SPDX-license + JSF sub-schema $refs must RESOLVE and ENFORCE through
    the `referencing` Registry — so the RefResolver migration can never silently
    regress to 'passing for the wrong reason' (Hard Rule 1)."""
    valid = emit_cyclonedx(_small_result())
    assert validate_cyclonedx(valid) == []

    # (a) spdx.schema.json $ref: a non-SPDX license id must be rejected.
    bad_license = json.loads(json.dumps(valid))
    model = next(c for c in bad_license["components"] if "licenses" in c)
    model["licenses"] = [{"license": {"id": "NOT-A-REAL-LICENSE-XYZ"}}]
    errs = validate_cyclonedx(bad_license)
    assert errs and any("licenses" in e for e in errs), (
        "non-SPDX license id must fail (spdx $ref not enforcing through registry)"
    )

    # (b) jsf-0.82.schema.json $ref: a malformed signature must be rejected.
    bad_sig = json.loads(json.dumps(valid))
    bad_sig["signature"] = {"completely": "bogus"}
    errs = validate_cyclonedx(bad_sig)
    assert errs and any("signature" in e for e in errs), (
        "malformed signature must fail (jsf $ref not enforcing through registry)"
    )


def test_registry_without_subschemas_is_unresolvable() -> None:
    """Negative control: dropping the sub-schemas makes the $ref unresolvable —
    proving the assertions above can actually detect a registration gap."""
    import jsonschema
    from referencing import Registry, Resource
    from referencing.exceptions import Unresolvable
    from referencing.jsonschema import DRAFT7

    from aibom.emit.validate import _load

    bom_schema = _load("bom-1.6.schema.json")
    resource = Resource.from_contents(bom_schema, default_specification=DRAFT7)
    registry = Registry().with_resources([(bom_schema["$id"], resource)])
    validator = jsonschema.Draft7Validator(bom_schema, registry=registry)
    with pytest.raises(Unresolvable):
        list(validator.iter_errors(emit_cyclonedx(_small_result())))
