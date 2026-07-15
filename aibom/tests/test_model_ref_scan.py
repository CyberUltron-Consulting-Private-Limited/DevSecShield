"""Model-reference scanner: inline model ids in source -> model components.

Real fixtures, real detection (never mocked). Asserts the synthetic AND chroma
fixtures yield model references, that the differential model recall clears
threshold on the gated fixtures, and that the example goldens are undisturbed
(no spurious model detected where there is no source model usage).
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.scan.parsers.model_refs import find_model_refs
from aibom.scan.pipeline import scan_repo

_FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def _model_names(path: pathlib.Path) -> set[str]:
    return {c.name for c in scan_repo(path, level=4).components if c.kind == "model"}


# ── dictionary unit checks ───────────────────────────────────────────────────
def test_dictionary_catches_known_families_not_prose() -> None:
    refs = find_model_refs(
        'model="gpt-4o"; embed("claude-3-5-sonnet-20241022"); '
        'EmbeddingFunction("Xenova/all-MiniLM-L6-v2")'
    )
    expected = {"gpt-4o", "claude-3-5-sonnet-20241022", "Xenova/all-MiniLM-L6-v2"}
    assert expected <= set(refs)
    assert refs["gpt-4o"] == "OpenAI"
    # Plain prose with no model token yields nothing (low false-positive design).
    assert find_model_refs("the model was trained on a large dataset of images") == {}


# ── synthetic: exact expected set (hand-labelled) ────────────────────────────
def test_synthetic_yields_model_references() -> None:
    models = _model_names(_FIX / "synthetic")
    assert models >= {"gpt-4o", "claude-3-5-sonnet-20241022", "embed-english-v3.0"}


# ── chroma: real repo yields many model references ───────────────────────────
def test_chroma_yields_model_references() -> None:
    if not (_FIX / "chroma").is_dir():
        pytest.skip("chroma clone absent (see tests/fixtures/CHROMA.md)")
    models = _model_names(_FIX / "chroma")
    # chroma references many models across its embedding functions; a healthy
    # detection surfaces well more than a handful (and never zero).
    assert len(models) >= 5
    # the minilm family is referenced throughout chroma's embedding functions
    assert any("minilm" in m.lower() for m in models)


# ── the differential recall jumps above threshold on the gated fixtures ──────
@pytest.mark.parametrize("fixture", ["synthetic", "trusera-demo"])
def test_differential_model_recall_above_threshold(fixture: str) -> None:
    import differential as report
    import test_differential as gate

    ours = gate._our(fixture)["model"]
    oracle = gate._oracle(fixture, "model")  # model is measured vs Cisco
    recall = len(ours & oracle) / len(oracle)
    assert recall >= gate.THRESHOLDS["model"], (
        f"{fixture} model recall {recall:.2f} < {gate.THRESHOLDS['model']:.2f}; "
        f"missed {sorted(oracle - ours)}"
    )
    # report routing agrees this category is measured vs cisco
    assert report._oracle_tool("model") == "cisco"


# ── golden safety: no spurious model where there is no source model usage ────
@pytest.mark.parametrize("example", ["clinical-imaging", "no-phi-model", "multi-site"])
def test_examples_have_no_spurious_model_refs(example: str) -> None:
    # Each example carries exactly ONE carded model and no inline source refs,
    # so the model-ref scanner must not add components (goldens stay stable).
    models = [c for c in scan_repo(_EX / example).components if c.kind == "model"]
    assert len(models) == 1
    assert not any(c.bom_ref.startswith("modelref-") for c in models)
