"""Recalibrated scorer — real pipeline (no mocks).

Per-component flags STACK; every finding carries a real severity band; the
synthetic scoring-calibration fixture yields >=1 finding in EACH band
(the planted secret is the critical), and chroma's distribution is no longer
uniformly low.
"""
from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.scan.pipeline import scan_repo
from aibom.score.scorer import component_severity

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def _severity_dist(fixture: str, level: int = 1) -> Counter:
    out = scan_to_devsecshield(_fx(fixture), level=level)
    return Counter((f.get("impact") or "").lower() for f in out["results"])


def test_synthetic_fixture_spans_all_four_bands() -> None:
    dist = _severity_dist("scoring-calibration")
    for band in ("critical", "high", "medium", "low"):
        assert dist.get(band, 0) >= 1, f"missing >=1 {band}: {dict(dist)}"


def test_planted_secret_is_critical() -> None:
    r = scan_repo(_fx("scoring-calibration"), level=1)
    secret = next(c for c in r.components if c.kind == "secret")
    assert r.scores["component_severity"][secret.bom_ref] == "critical"


def test_flags_stack_per_component() -> None:
    # component_severity is a pure function of the STACKED raw weight.
    assert component_severity(14) == "critical"   # a secret
    assert component_severity(8) == "high"        # a no-license model
    assert component_severity(6) == "medium"      # unsanctioned component ALONE
    assert component_severity(5) == "medium"      # unknown-license library
    assert component_severity(2) == "low"         # model-license-unknown
    assert component_severity(0) == "low"         # clean component (vector store)
    # STACKING: unsanctioned (6) + model-license-unknown (2) = 8 -> elevated to high.
    assert component_severity(6 + 2) == "high"


def test_severity_is_not_flat() -> None:
    # The whole point: not every finding is "low".
    dist = _severity_dist("scoring-calibration")
    assert len({b for b, n in dist.items() if n}) >= 3, f"distribution too flat: {dict(dist)}"


def test_chroma_distribution_no_longer_all_low() -> None:
    if not os.path.isdir(_fx("chroma")):
        pytest.skip("chroma clone absent (gitignored)")
    dist = _severity_dist("chroma", level=4)
    non_low = sum(n for band, n in dist.items() if band and band != "low")
    assert non_low >= 1, f"chroma is still uniformly low: {dict(dist)}"
