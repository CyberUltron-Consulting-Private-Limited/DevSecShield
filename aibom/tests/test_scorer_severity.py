"""Recalibrated scorer: per-component flags STACK -> a real severity band.

Before: findings were uniformly Low (flat weights, no stacking, no per-component
severity). Now each component's flag weights stack into a critical/high/medium/low
band, and every finding carries that severity. Real pipeline, no mocks.
"""

from __future__ import annotations

import os
from collections import Counter

import pytest

from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.model.component import FrameworkComponent, MetadataComponent
from aibom.model.result import Flag, ScanResult
from aibom.scan.pipeline import scan_repo
from aibom.score.scorer import component_severity, score_result

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
_BANDS = ("Critical", "High", "Medium", "Low")


def _severities(fixture: str) -> Counter:
    path = os.path.join(_FIX, fixture)
    if not os.path.isdir(path):
        pytest.skip(f"fixture {fixture!r} absent")
    out = scan_to_devsecshield(path, level=4)
    return Counter(f["impact"] for f in out["results"])


# ── the DONE: the synthetic fixture yields >=1 finding per band ──────────────
def test_synthetic_scorer_fixture_one_per_band() -> None:
    dist = _severities("synthetic-scorer")
    for band in _BANDS:
        assert dist.get(band, 0) >= 1, f"no {band} finding (got {dict(dist)})"


def test_planted_secret_is_critical() -> None:
    r = scan_repo(os.path.join(_FIX, "synthetic-scorer"), level=4)
    secret = next(c for c in r.components if c.kind == "secret")
    assert r.scores["component_severity"][secret.bom_ref] == "critical"


# ── per-component flags STACK (the keystone of the recalibration) ────────────
def test_flags_stack_per_component() -> None:
    # Two flags, each BELOW the high band alone, that SUM into high on one component.
    comp = FrameworkComponent(bom_ref="lib-x", name="x")
    r = ScanResult(
        subject=MetadataComponent(name="t"),
        components=[comp],
        flags=[
            Flag(code="UNSANCTIONED_COMPONENT", target="lib-x", severity="warning"),
            Flag(code="MODEL_LICENSE_UNKNOWN", target="lib-x", severity="note"),
        ],
    )
    score_result(r)
    stacked = r.scores["by_component"]["lib-x"]
    assert stacked == 8, f"flags did not stack (6+2): {stacked}"
    assert r.scores["component_severity"]["lib-x"] == "high", "stacked sum not high"
    # Neither flag alone reaches high.
    assert component_severity(6) == "medium"  # UNSANCTIONED_COMPONENT alone
    assert component_severity(2) == "low"  # MODEL_LICENSE_UNKNOWN alone


def test_unflagged_component_is_low_floor() -> None:
    assert component_severity(0) == "low"


# ── chroma is no longer all-low ──────────────────────────────────────────────
def test_chroma_distribution_not_flat() -> None:
    dist = _severities("chroma")
    non_low = sum(v for k, v in dist.items() if k != "Low")
    assert non_low >= 1, f"chroma severity still all-low: {dict(dist)}"
    assert len([b for b in _BANDS if dist.get(b, 0) > 0]) >= 2, "chroma severity flat"
