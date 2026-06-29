"""License resolver: real declared-license resolution, never mocked.

Asserts against the deterministic curated manifest (the asserted ground truth —
numpy/torch=BSD, requests=Apache) AND against genuinely-resolved
``importlib.metadata`` for an installed distribution (proving the live path is
real, not stubbed). Also proves the requirements scanner flags only the
genuinely-unknown, and that chroma's unlicensed count drops sharply.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom.scan.parsers.license_resolver import resolve_license
from aibom.scan.pipeline import scan_repo

_CHROMA = pathlib.Path(__file__).resolve().parent / "fixtures" / "chroma"


def test_ground_truth_licenses_resolve() -> None:
    # The hand-labelled GROUND_TRUTH.md values — real, public SPDX ids.
    assert resolve_license("numpy") == "BSD-3-Clause"
    assert resolve_license("torch") == "BSD-3-Clause"
    assert resolve_license("requests") == "Apache-2.0"


def test_pep503_name_normalization() -> None:
    # Extras, case, and underscore/dot variants normalize to the same key.
    assert resolve_license("uvicorn[standard]") == "BSD-3-Clause"
    assert resolve_license("PyYAML") == "MIT"
    assert resolve_license("typing_extensions") == resolve_license("typing-extensions")


def test_genuinely_unknown_is_none_not_guessed() -> None:
    assert resolve_license("totally-not-a-real-package-zzz-9000") is None


def test_importlib_metadata_path_is_real_not_mocked() -> None:
    """A package NOT in the manifest still resolves via real installed metadata.

    ``pytest`` is in the test environment by definition; it is not in the curated
    map, so a map-only lookup misses it and the value can ONLY come from a real
    ``importlib.metadata`` read — no mock involved.
    """
    assert resolve_license("pytest") is None  # map-only: not curated
    assert resolve_license("pytest", allow_metadata=True) == "MIT"  # real metadata


def test_requirements_scanner_flags_only_unresolved() -> None:
    """Resolved deps carry a license + no flag; unknown deps flag, unlicensed."""
    if not _CHROMA.is_dir():
        pytest.skip("chroma clone absent (see tests/fixtures/CHROMA.md)")
    result = scan_repo(_CHROMA, level=1)
    frameworks = [c for c in result.components if c.kind == "framework"]
    licensed = [c for c in frameworks if c.licenses]
    unlicensed = [c for c in frameworks if not c.licenses]
    flagged = {f.target for f in result.flags if f.code == "FRAMEWORK_NO_LICENSE"}

    # Unlicensed count drops sharply: the bulk of chroma's deps resolve. (Now also
    # reads pyproject.toml runtime deps, so a few more unresolved deps surface — the
    # licensed RATIO, not an absolute count, is the stable governance signal.)
    assert len(frameworks) >= 25
    assert len(licensed) >= 0.75 * len(frameworks), "unlicensed count did not drop"
    # A flag is raised for exactly the genuinely-unresolved frameworks.
    assert flagged == {c.bom_ref for c in unlicensed}
    # And every resolved framework is flag-free.
    assert all(c.bom_ref not in flagged for c in licensed)


def test_governance_lifts_off_zero() -> None:
    """has_license() (the FDA §524B / NIST governance signal) is no longer all-false."""
    from aibom.compliance.base import has_license

    if not _CHROMA.is_dir():
        pytest.skip("chroma clone absent (see tests/fixtures/CHROMA.md)")
    frameworks = [
        c for c in scan_repo(_CHROMA, level=1).components if c.kind == "framework"
    ]
    licensed_ratio = sum(has_license(c) for c in frameworks) / len(frameworks)
    # >0.75 (was 0.8): reading pyproject runtime deps surfaces a few more genuinely
    # unresolved licenses — governance is well off zero, which is what this guards.
    assert licensed_ratio > 0.75, f"governance still near zero: {licensed_ratio:.0%}"
