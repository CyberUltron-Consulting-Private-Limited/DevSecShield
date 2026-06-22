"""Regression tests for the adversarial-review findings (Phase-1 hardening).

Each test pins a fix so the bug cannot silently return:
  * advisory disclaimer present in CycloneDX, SPDX AND SARIF payloads;
  * de-identification decided from structured fields only (no substring false
    pos/neg), and DATASET_NO_DEIDENT fires on a PHI dataset;
  * case-insensitive card discovery (MODEL_CARD.MD);
  * unresolved declared dataset -> DATASET_DECLARED_NOT_FOUND flag (no silent drop);
  * scanner registry is idempotent (no double registration);
  * Flag severity is constrained to SARIF levels at construction;
  * SARIF emit coerces an out-of-enum level defensively;
  * the EU AI Act risk fact uses one canonical key everywhere.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import pathlib

import pytest

from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.emit.sarif import emit_sarif
from aibom.emit.spdx import emit_spdx
from aibom.model.component import DatasetComponent, MetadataComponent, is_deidentified
from aibom.model.result import Flag, ScanResult
from aibom.scan.pipeline import scan_repo
from aibom.scan.scanners.model_repo import _find_model_card

_is_deidentified = is_deidentified  # canonical predicate moved to model.component

_FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent / "examples" / "clinical-imaging"
)


# --------------------------------------------------------------------------- #
# Advisory disclaimer in every report (CLAUDE.md hard rule)
# --------------------------------------------------------------------------- #


def test_disclaimer_present_in_all_three_formats() -> None:
    r = scan_repo(_FIXTURE)
    cdx = json.dumps(emit_cyclonedx(r))
    spdx = json.dumps(emit_spdx(r))
    sarif = json.dumps(emit_sarif(r))
    needle = "advisory only"
    assert needle in cdx
    assert needle in spdx  # SpdxDocument.comment
    assert needle in sarif  # runs[].properties.advisoryDisclaimer


# --------------------------------------------------------------------------- #
# De-identification: structured fields only (no substring false pos/neg)
# --------------------------------------------------------------------------- #


def test_deident_structured_only() -> None:
    deident = DatasetComponent(
        bom_ref="d", name="d", has_sensitive_personal_information="no"
    )
    assert _is_deidentified(deident) is True

    via_method = DatasetComponent(
        bom_ref="d", name="d", anonymization_method=["HIPAA Safe Harbor"]
    )
    assert _is_deidentified(via_method) is True

    # False NEGATIVE guard: negated prose no longer counts as de-identified.
    negated = DatasetComponent(
        bom_ref="d", name="d", sensitivity="contains PHI; NOT de-identified"
    )
    assert _is_deidentified(negated) is False

    # False POSITIVE guard: unrelated 'anonymized' prose no longer counts.
    unrelated = DatasetComponent(
        bom_ref="d", name="d", provenance="collected from anonymized employee logins"
    )
    assert _is_deidentified(unrelated) is False

    explicit_phi = DatasetComponent(
        bom_ref="d", name="d", has_sensitive_personal_information="yes"
    )
    assert _is_deidentified(explicit_phi) is False


def _write_repo(root: pathlib.Path, model_card: str, dataset_card: str | None) -> None:
    (root / "MODEL_CARD.md").write_text(model_card)
    if dataset_card is not None:
        (root / "DATASET_CARD.md").write_text(dataset_card)


def test_dataset_no_deident_flag_fires(tmp_path: pathlib.Path) -> None:
    _write_repo(
        tmp_path,
        "---\nname: m\nbom_ref: model-m\ndatasets:\n  - dataset-phi\n---\n",
        "---\nname: phi-cohort\nbom_ref: dataset-phi\ndataset_type: image\n"
        "has_sensitive_personal_information: \"yes\"\n---\n",
    )
    result = scan_repo(tmp_path)
    assert "DATASET_NO_DEIDENT" in {f.code for f in result.flags}


# --------------------------------------------------------------------------- #
# Case-insensitive card discovery
# --------------------------------------------------------------------------- #


def test_uppercase_model_card_extension_is_found(tmp_path: pathlib.Path) -> None:
    (tmp_path / "MODEL_CARD.MD").write_text("---\nname: m\nbom_ref: model-m\n---\n")
    assert _find_model_card(tmp_path) is not None
    result = scan_repo(tmp_path)
    assert any(c.kind == "model" for c in result.components)


# --------------------------------------------------------------------------- #
# Declared-but-missing dataset is flagged, not silently dropped
# --------------------------------------------------------------------------- #


def test_declared_missing_dataset_is_flagged(tmp_path: pathlib.Path) -> None:
    _write_repo(
        tmp_path,
        "---\nname: m\nbom_ref: model-m\ndatasets:\n  - dataset-ghost\n---\n",
        None,
    )
    result = scan_repo(tmp_path)
    assert "DATASET_DECLARED_NOT_FOUND" in {f.code for f in result.flags}
    # ... and no phantom trained_on edge to the missing dataset.
    assert result.out_edges("model-m", "trained_on") == []


# --------------------------------------------------------------------------- #
# Scanner registry idempotence
# --------------------------------------------------------------------------- #


def test_register_is_idempotent() -> None:
    import aibom.scan.registry as reg
    import aibom.scan.scanners.requirements as req

    before = len(reg.SCANNERS)
    importlib.reload(req)  # re-runs @register
    assert len(reg.SCANNERS) == before
    names = [s.name for s in reg.ordered_scanners()]
    assert names.count("requirements") == 1


# --------------------------------------------------------------------------- #
# Flag severity invariant + defensive SARIF coercion
# --------------------------------------------------------------------------- #


def test_flag_rejects_non_sarif_severity() -> None:
    with pytest.raises(ValueError):
        Flag("X", "t", severity="critical")
    for ok in ("none", "note", "warning", "error"):
        assert Flag("X", "t", severity=ok).severity == ok


def test_sarif_coerces_out_of_enum_level() -> None:
    flag = Flag("X", "model-x", severity="warning", message="m")
    # Bypass the frozen-dataclass guard to simulate an invariant breach.
    object.__setattr__(flag, "severity", "bogus")
    result = ScanResult(subject=MetadataComponent(name="app"), flags=[flag])
    doc = emit_sarif(result)
    assert doc["runs"][0]["results"][0]["level"] == "warning"


# --------------------------------------------------------------------------- #
# One canonical EU AI Act risk key
# --------------------------------------------------------------------------- #


def test_eu_ai_act_risk_key_is_canonical() -> None:
    bom = emit_cyclonedx(scan_repo(_FIXTURE))
    names = {p["name"] for p in bom["metadata"]["properties"]}
    model = next(c for c in bom["components"] if c["type"] == "machine-learning-model")
    names |= {p["name"] for p in model["properties"]}
    assert "regulatory:eu_ai_act_risk" in names
    assert "regulatory:eu_ai_act_risk_tier" not in names  # old split key is gone


def test_flag_is_frozen_dataclass() -> None:
    assert dataclasses.is_dataclass(Flag)
    f = Flag("X", "t")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.code = "Y"  # type: ignore[misc]
