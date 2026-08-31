"""Adapter `_provider` matches production ansh policy (never unknown, never purl-only)."""

from __future__ import annotations

from aibom.integrations.devsecshield import _provider


def test_framework_without_purl_is_pypi() -> None:
    assert _provider(None, "torch", "framework") == "pypi"
    assert _provider(None, "langchain", "framework") == "pypi"
    assert _provider(None, "numpy", "framework", location="", props={}) == "pypi"


def test_named_vendor_beats_framework_kind() -> None:
    assert _provider(None, "openai", "framework") == "openai"
    assert _provider(None, "anthropic", "framework") == "anthropic"


def test_model_dataset_prompt_are_local() -> None:
    assert _provider(None, "chestxr-nodule-detector", "model") == "local"
    assert _provider(None, "chestxr-training-cohort", "dataset") == "local"
    assert _provider(None, "system-prompt", "prompt") == "local"
    assert _provider(None, "system-prompt", "prompt_asset") == "local"


def test_fallback_is_local_never_unknown() -> None:
    assert _provider(None, "custom-endpoint", "service") == "local"
    assert _provider(None, "mystery", "external_provider") == "local"
    assert _provider(None, "", "") == "local"
    assert _provider(None, "torch", "framework") != "unknown"
