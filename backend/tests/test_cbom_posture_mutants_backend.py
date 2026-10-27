"""Mutants M19 and M20: previously seen is not current, and absence is not a pass."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.tests.support.airgap import NetworkBlocked, block_network  # noqa: E402
from backend.tests.test_cbom_posture_rollup import blob, fact, fold, head, marker  # noqa: E402


def test_previously_seen_is_not_counted_as_current() -> None:
    older = marker([fact("only-old")])
    newer = marker([])
    view, _seen = fold(
        [
            (head(2, age_days=1), blob(newer)),
            (head(1, age_days=10), blob(older)),
        ]
    )
    assert view.posture.counts.facts == 0
    assert [row.fact_id for row in view.posture.previously_seen] == ["only-old"]
    assert view.posture.previously_seen[0].current is False


def test_a_missing_marker_is_not_assessed_rather_than_zero_findings() -> None:
    view, _seen = fold([(head(1), blob(present=False))])
    assert view.posture.state == "not_assessed"
    assert view.posture.counts.facts == 0
    assert view.posture.sources[0].state == "not_assessed"


def test_blocked_network_catches_a_socket() -> None:
    with block_network():
        with pytest.raises(NetworkBlocked):
            socket.socket()
