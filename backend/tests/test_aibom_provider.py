"""Hermetic tests for AIBOM provider resolution (never unknown)."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.aibom_provider import (  # noqa: E402
    KNOWN_PROVIDERS,
    infer_aibom_provider,
    resolve_aibom_provider,
)


def test_openai_path_credential_maps_to_openai() -> None:
    assert (
        resolve_aibom_provider(
            {
                "component_name": "generic_credential",
                "component_type": "external_provider",
                "source": "unknown",
                "location": "src/openai/_client.py",
            }
        )
        == "openai"
    )


def test_bare_credential_maps_to_credential() -> None:
    assert (
        resolve_aibom_provider(
            {
                "component_name": "generic_credential",
                "component_type": "external_provider",
                "source": "unknown",
                "location": "scripts/utils/validate.py",
            }
        )
        == "credential"
    )


def test_ml_framework_maps_to_pypi() -> None:
    assert (
        resolve_aibom_provider(
            {
                "component_name": "httpx",
                "component_type": "ml_framework",
                "source": "unknown",
            }
        )
        == "pypi"
    )


def test_bin_artifact_maps_to_local() -> None:
    assert (
        resolve_aibom_provider(
            {
                "component_name": "abc123.bin",
                "component_type": "external_provider",
                "source": "unknown",
            }
        )
        == "local"
    )


def test_empty_maps_to_local() -> None:
    assert resolve_aibom_provider({}) == "local"


def test_concrete_source_passthrough() -> None:
    assert (
        resolve_aibom_provider(
            {"source": "bedrock", "component_name": "anything"}
        )
        == "bedrock"
    )


def test_azure_and_ollama_needles() -> None:
    assert infer_aibom_provider(name="gpt", location="azure/openai/deploy") == "azure"
    assert infer_aibom_provider(name="llama", location="ollama/pull") == "ollama"


def test_ansh_policy_named_vendors_and_kinds() -> None:
    """Production policy: vendor > framework/pypi > model/dataset/prompt/local."""
    assert infer_aibom_provider(name="openai", kind_or_type="framework") == "openai"
    assert infer_aibom_provider(name="anthropic", kind_or_type="framework") == "anthropic"
    assert infer_aibom_provider(name="torch", kind_or_type="framework") == "pypi"
    assert infer_aibom_provider(name="langchain", kind_or_type="framework") == "pypi"
    assert infer_aibom_provider(name="numpy", kind_or_type="ml_framework") == "pypi"
    assert infer_aibom_provider(name="chestxr-nodule-detector", kind_or_type="model") == "local"
    assert infer_aibom_provider(name="chestxr-training-cohort", kind_or_type="dataset") == "local"
    assert infer_aibom_provider(name="system-prompt", kind_or_type="prompt") == "local"
    assert infer_aibom_provider(name="system-prompt", kind_or_type="prompt_asset") == "local"
    assert infer_aibom_provider(name="custom-endpoint", kind_or_type="service") == "local"

    assert resolve_aibom_provider(
        {"component_name": "torch", "component_type": "ml_framework", "source": "unknown"}
    ) == "pypi"
    assert resolve_aibom_provider(
        {"component_name": "langchain", "component_type": "ml_framework"}
    ) == "pypi"
    assert resolve_aibom_provider(
        {"component_name": "openai", "component_type": "ml_framework", "source": "unknown"}
    ) == "openai"
    assert resolve_aibom_provider({"source": "unknown"}) == "local"


def test_never_returns_unknown() -> None:
    cases = [
        {},
        {"source": "unknown"},
        {"source": ""},
        {"component_name": "x", "component_type": "external_provider"},
        {"component_name": "pydantic", "component_type": "ml_framework"},
    ]
    for asset in cases:
        got = resolve_aibom_provider(asset)
        assert got != "unknown"
        assert got in KNOWN_PROVIDERS


def test_pdf_wrapper_uses_same_resolver() -> None:
    from backend.utilities.pdf.ai_bom_pdf import _provider as pdf_provider

    row = {
        "component_name": "torch",
        "component_type": "ml_framework",
        "source": "unknown",
    }
    assert pdf_provider(row) == resolve_aibom_provider(row) == "pypi"
