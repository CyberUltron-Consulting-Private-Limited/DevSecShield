"""Hermetic tests for AIBOM license resolution (never unknown)."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.aibom_license import (  # noqa: E402
    LICENSE_NOT_APPLICABLE,
    LICENSE_NOT_DECLARED,
    LICENSE_PROPRIETARY,
    resolve_aibom_license,
)


def test_credential_maps_to_not_applicable() -> None:
    assert (
        resolve_aibom_license(
            {
                "component_name": "generic_credential",
                "component_type": "external_provider",
                "license": None,
            }
        )
        == LICENSE_NOT_APPLICABLE
    )


def test_bedrock_api_maps_to_proprietary() -> None:
    assert (
        resolve_aibom_license(
            {
                "component_name": "AWS Bedrock",
                "component_type": "external_provider",
                "source": "bedrock",
            }
        )
        == LICENSE_PROPRIETARY
    )


def test_bin_artifact_maps_to_not_declared() -> None:
    assert (
        resolve_aibom_license(
            {
                "component_name": "abc123.bin",
                "component_type": "external_provider",
            }
        )
        == LICENSE_NOT_DECLARED
    )


def test_distro_framework_maps_to_apache() -> None:
    assert (
        resolve_aibom_license(
            {
                "component_name": "distro",
                "component_type": "ml_framework",
                "license": "unknown",
            }
        )
        == "Apache-2.0"
    )


def test_empty_maps_to_not_declared() -> None:
    assert resolve_aibom_license({}) == LICENSE_NOT_DECLARED


def test_concrete_license_passthrough() -> None:
    assert (
        resolve_aibom_license({"license": "MIT", "component_name": "x"}) == "MIT"
    )


def test_never_returns_unknown() -> None:
    cases = [
        {},
        {"license": "unknown"},
        {"license": ""},
        {"component_name": "generic_credential", "component_type": "external_provider"},
        {"component_name": "jiter", "component_type": "ml_framework"},
        {"component_name": "OpenAI API", "component_type": "external_provider"},
        {"component_name": "x.bin", "component_type": "external_provider"},
    ]
    for asset in cases:
        got = resolve_aibom_license(asset)
        assert got
        assert got.lower() != "unknown"
