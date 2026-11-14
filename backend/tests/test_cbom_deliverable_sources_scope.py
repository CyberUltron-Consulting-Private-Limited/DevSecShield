"""Staging QA 14 Nov 2026: the team deliverables count every CBOM Sources collection as a completed scan and a
source (``merge_collections``, M1x), but the Board report still captioned the count "repositories and uploads
assessed" and "eligible completed scans", and the Basis box of every deliverable said "Scans: 18 included" for a
team with 2 code scans and 16 Sources collections. The words now say what was counted.

Oracle: the counts are literals (2 code scans of 2 code sources, 16 collections); nothing is recomputed with the
product aggregator.
"""

from __future__ import annotations

import dataclasses
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    SOURCE_SOURCES,
    CollectionAgg,
    SourceAgg,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_board_report_pdf as board  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402

NOW = datetime(2026, 11, 14, 11, 55, tzinfo=timezone.utc)


def _source(key: str, kind: str) -> SourceAgg:
    return SourceAgg(key=key, label=key, kind=kind, repo_url=None, branch=None, scan_ids=(1,), scan_count=1,
                     first_scanned=NOW, last_scanned=NOW, current_scan_id=1, current_tier="A", current_fidelity="full",
                     last_attempt_scan_id=1, last_attempt_status="success", last_attempt_at=NOW)


def _view(code_scans: int, code_sources: int, collections: int) -> TeamCbomView:
    view = TeamCbomView(team_id=2, team_name="QA", generated_at=NOW, as_of=NOW.date())
    sources = [_source(f"zip:upload-{i}", "zip") for i in range(code_sources)]
    sources += [_source(f"sources:{i}", SOURCE_SOURCES) for i in range(collections)]
    colls = [CollectionAgg(key=f"sources:{i}", label=f"Sources run #1 · lab-{i}", source_name=f"lab-{i}",
                           source_kind="servers", run_id=1, job_id=i + 1, observed_at=NOW) for i in range(collections)]
    total = code_scans + collections
    return dataclasses.replace(view, scans_total=total, eligible=total, included=total, fidelity_full=total,
                               sources=tuple(sources), collections=tuple(colls))


STAGING = _view(code_scans=2, code_sources=2, collections=16)  # team 2 on staging, 14 Nov
CODE_ONLY = _view(code_scans=3, code_sources=2, collections=0)


def test_board_kpi_captions_split_code_sources_from_cbom_sources_collections():
    sources, scans = board.scope_captions(STAGING)
    assert sources == "2 repositories and uploads, 16 CBOM Sources"
    assert scans == "of 18 eligible: 2 code scans, 16 Sources collections"
    assert "18 repositories" not in sources


def test_board_kpi_captions_unchanged_for_a_team_without_sources_collections():
    assert board.scope_captions(CODE_ONLY) == ("repositories and uploads assessed", "of 3 eligible completed scans")


def test_board_summary_sentence_names_both_kinds():
    assert board.scope_sentence(STAGING) == (
        "Across 18 sources (2 repositories and uploads, 16 CBOM Sources) and 18 completed results "
        "(2 code scans, 16 Sources collections)")
    assert board.scope_sentence(CODE_ONLY) == "Across 2 sources and 3 completed scans"


def test_basis_box_scans_line_says_how_many_are_sources_collections():
    line = common.basis_scans_line(STAGING)
    assert line.startswith("Scans: 18 included of 18 eligible")
    assert line.endswith(" · of which 16 are CBOM Sources collections")
    assert common.basis_scans_line(CODE_ONLY) == (
        "Scans: 3 included of 3 eligible · excluded: 0 failed, 0 not completed, 0 without data")


def test_board_pdf_with_sources_collections_renders():
    pdf = board.build_pdf(STAGING)
    assert pdf[:5] == b"%PDF-"
