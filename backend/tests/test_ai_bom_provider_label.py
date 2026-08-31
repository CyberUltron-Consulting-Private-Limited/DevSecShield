"""AI-BOM Providers chart labels must match production (pypi / local / vendor)."""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.ai_bom_provider import ai_bom_provider_label  # noqa: E402


def test_named_vendor_is_kept():
    assert ai_bom_provider_label({"source": "openai", "component_type": "external_provider"}) == "openai"
    assert ai_bom_provider_label({"source": "anthropic", "component_type": "ml_framework"}) == "anthropic"


def test_framework_without_source_is_pypi_not_unknown():
    assert ai_bom_provider_label({"source": "unknown", "component_type": "ml_framework"}) == "pypi"
    assert ai_bom_provider_label({"component_type": "ml_framework"}) == "pypi"
    assert ai_bom_provider_label({"source": "", "component_type": "ai_framework"}) == "pypi"


def test_local_model_file_is_local():
    assert ai_bom_provider_label({"source": "unknown", "component_type": "local_model_file"}) == "local"


def test_huggingface_model_type():
    assert ai_bom_provider_label({"component_type": "huggingface_model"}) == "huggingface"


def test_stored_pypi_is_kept():
    assert ai_bom_provider_label({"source": "pypi", "component_type": "ml_framework"}) == "pypi"


def test_genuinely_unknown_stays_unknown():
    assert ai_bom_provider_label({"source": "unknown", "component_type": "dataset"}) == "unknown"
    assert ai_bom_provider_label({"source": "unknown", "component_type": "prompt_asset"}) == "unknown"
