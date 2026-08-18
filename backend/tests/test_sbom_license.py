"""Hermetic tests for SBOM license resolution (never unknown)."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.sbom_license import (  # noqa: E402
    LICENSE_NOT_DECLARED,
    LICENSE_REF_NOT_DECLARED,
    resolve_sbom_license_category,
    resolve_sbom_license_fields,
    resolve_sbom_reachability,
    spdx_to_license_category,
)


def test_spdx_mit_is_permissive() -> None:
    assert spdx_to_license_category("MIT") == "permissive"
    assert spdx_to_license_category("Apache-2.0") == "permissive"
    assert spdx_to_license_category("0BSD") == "public_domain"
    assert spdx_to_license_category("GPL-3.0-only") == "strong_copyleft"
    assert spdx_to_license_category("LGPL-2.1-or-later") == "weak_copyleft"
    assert spdx_to_license_category("AGPL-3.0") == "network_copyleft"
    assert spdx_to_license_category("MPL-2.0") == "weak_copyleft"
    assert spdx_to_license_category("SSPL-1.0") == "source_available"
    assert spdx_to_license_category("CC-BY-4.0") == "creative_commons"


def test_unknown_and_empty_map_to_not_declared() -> None:
    assert spdx_to_license_category("unknown") == LICENSE_NOT_DECLARED
    assert spdx_to_license_category("") == LICENSE_NOT_DECLARED
    assert spdx_to_license_category("UNKNOWN") == LICENSE_NOT_DECLARED


def test_legacy_unknown_license_type_enriched_by_package() -> None:
    lic, cat = resolve_sbom_license_fields(
        {"dependency": "click==8.1.0", "license_type": "unknown"}
    )
    assert lic == "BSD-3-Clause"
    assert cat == "permissive"


def test_raw_spdx_in_license_type_remapped() -> None:
    assert (
        resolve_sbom_license_category({"license_type": "MIT", "dependency": "x"})
        == "permissive"
    )


def test_residual_is_not_declared() -> None:
    lic, cat = resolve_sbom_license_fields(
        {"dependency": "totally-obscure-pkg-xyz==1.0", "license_type": "unknown"}
    )
    assert lic == LICENSE_REF_NOT_DECLARED
    assert cat == LICENSE_NOT_DECLARED


def test_concrete_license_passthrough() -> None:
    lic, cat = resolve_sbom_license_fields(
        {"license": "Apache-2.0", "license_type": "unknown", "dependency": "requests"}
    )
    assert lic == "Apache-2.0"
    assert cat == "permissive"


def test_reachability_never_unknown() -> None:
    assert resolve_sbom_reachability({"reachability": "unknown"}) == "not_assessed"
    assert resolve_sbom_reachability({"reachability": None}) == "not_assessed"
    assert (
        resolve_sbom_reachability({"reachability": None, "inventory_only": True})
        == "not_reachable"
    )
    assert resolve_sbom_reachability({"reachability": "reachable"}) == "reachable"


def test_never_emits_literal_unknown() -> None:
    for item in (
        {},
        {"license_type": "unknown"},
        {"license": "unknown"},
        {"dependency": "flask==3.0"},
        {"license_type": "MIT"},
    ):
        lic, cat = resolve_sbom_license_fields(item)
        assert "unknown" not in lic.lower()
        assert cat != "unknown"
        assert resolve_sbom_reachability(item) != "unknown"
