"""WP10 degradation matrix: Not_Assessed is never a zero-finding pass."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TESTS = Path(__file__).resolve().parent
for _path in (str(_REPO_ROOT), str(_TESTS)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from backend.utilities.dashboard import cbom_team_rollup as roll  # noqa: E402
from test_cbom_posture_rollup import blob, fact, fold, head, marker  # noqa: E402


def _at_rest(view):
    return view.posture.counts.tri_state["at_rest"]


def test_no_marker_is_not_assessed_and_not_a_pass():
    view, _seen = fold([(head(1), blob(present=False))])
    row = view.posture.sources[0]
    assert view.posture.state == "not_assessed"
    assert row.state == "not_assessed"
    assert row.zero_facts is False
    assert view.posture.counts.facts == 0
    assert _at_rest(view).pass_ == 0
    assert _at_rest(view).fail == 0
    assert _at_rest(view).coverage is None
    assert roll.posture_active(view) is False


def test_zero_facts_with_a_marker_is_assessed_and_not_a_pass():
    view, _seen = fold([(head(1), blob(marker()))])
    row = view.posture.sources[0]
    assert view.posture.state == "assessed"
    assert row.state == "assessed"
    assert row.zero_facts is True
    assert row.reason is None
    assert view.posture.counts.facts == 0
    assert _at_rest(view).coverage is None
    assert _at_rest(view).pass_ == 0
    assert roll.posture_active(view) is False


def test_a_partial_lane_keeps_its_facts():
    block = marker(
        [fact("bucket")],
        failed_lanes=["posture_server"],
    )
    view, _seen = fold([(head(1), blob(block))])
    row = view.posture.sources[0]
    assert row.state == "partial"
    assert row.failed_lanes == ("posture_server",)
    assert row.zero_facts is False
    assert view.posture.state == "assessed"
    assert [agg.fact_id for agg in view.posture.facts] == ["bucket"]
    assert view.posture.counts.facts == 1
    assert _at_rest(view).fail == 1
    assert any("posture_server" in line for line in view.posture.warnings)


def test_assembly_failure_drops_facts_and_is_not_assessed():
    block = marker(
        [fact("should-not-count", verdict="ENCRYPTED_DECLARED", finding_codes=[])],
        lanes=[],
        failed_lanes=["assemble"],
    )
    view, _seen = fold([(head(1), blob(block))])
    row = view.posture.sources[0]
    assert row.state == "not_assessed"
    assert row.reason == "lanes_failed"
    assert row.zero_facts is False
    assert view.posture.facts == ()
    assert view.posture.counts.facts == 0
    assert _at_rest(view).pass_ == 0
    assert _at_rest(view).coverage is None


def test_mixed_sources_count_only_the_assessed_scan():
    assessed = marker([fact("live", verdict="ENCRYPTED_DECLARED", finding_codes=[])])
    view, _seen = fold(
        [
            (head(1, repo="https://github.com/o/live"), blob(assessed)),
            (head(2, repo="https://github.com/o/old"), blob(present=False)),
        ]
    )
    assert view.posture.state == "mixed"
    states = {row.key: row.state for row in view.posture.sources}
    assert "assessed" in states.values()
    assert "not_assessed" in states.values()
    assert view.posture.counts.facts == 1
    assert _at_rest(view).pass_ == 1
    assert _at_rest(view).coverage == 1.0
    assert roll.posture_active(view) is False


def test_a_not_assessed_source_cannot_manufacture_a_pass():
    junk = {
        "schema_version": 1,
        "lanes": [],
        "failed_lanes": [],
        "facts": [fact("ghost", verdict="ENCRYPTED_DECLARED", finding_codes=[])],
        "imports": [],
        "diagnostics": [],
    }
    view, _seen = fold([(head(1), blob(junk))])
    assert view.posture.sources[0].state == "malformed"
    assert view.posture.counts.facts == 0
    assert _at_rest(view).pass_ == 0
    assert _at_rest(view).coverage is None


def test_an_empty_team_has_zero_posture_counts():
    view, _seen = fold([])
    assert view.posture.state == "none"
    assert view.posture.counts.facts == 0
    assert view.posture.sources == ()
    assert _at_rest(view).coverage is None


def test_internal_error_is_not_reported_as_zero_facts():
    block = marker(diagnostic_totals={"internal_error": 1})
    view, _seen = fold([(head(1), blob(block))])
    row = view.posture.sources[0]
    assert row.state == "assessed"
    assert row.zero_facts is False
    assert view.posture.counts.facts == 0


def test_a_newer_engine_is_not_assessed():
    block = marker(schema_version=2)
    view, _seen = fold([(head(1), blob(block))])
    row = view.posture.sources[0]
    assert row.state == "newer_engine"
    assert row.reason == "newer_engine"
    assert row.zero_facts is False
    assert view.posture.state == "not_assessed"
    assert view.posture.counts.facts == 0
    assert _at_rest(view).coverage is None
