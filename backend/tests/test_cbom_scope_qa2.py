"""Staging QA round 2, lane Q1 (D1 / D2 / D14 / S4), the population and history findings:

* Q1-01: the last collection of a DELETED source (``Collection.source_kind == ""``) was counted as current population
  in D1, D12, D14 and the posture documents (7 deleted sources, 374 of 2312 occurrences on staging team 1). Now one
  rule (``collections_view.is_deleted_source``) keeps it out of every total; D1 lists it under "Removed from scope".
* Q1-02: D1's Sources rows for CBOM Sources sources hard-coded scans = 1, first = last scanned and "SUCCESS run #N":
  "Kubernetes lab Tier 1: SUCCESS run #8" although runs #50, #51 and #53 failed with auth_failed. Now they come from
  the source's collect-job history (``collections_view.collection_history``).

Oracles are literals or the fixture's own facts (the fixture ``sources_every_type`` is staging run #50-#52 data);
nothing here recounts with the product aggregator.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support import sources_every_type as FX
from backend.tests.support.pdf_text import pdf_text
from backend.utilities.cbom_sources import collections_view as CV
from backend.utilities.dashboard import cbom_team_rollup as R
from backend.utilities.pdf import cbom_scope_register_pdf as d1

NOW = dt.datetime(2026, 11, 24, 6, 0, tzinfo=dt.timezone.utc)
GONE = "Lab network"  # the fixture's network source, deleted in these tests


def _empty() -> R.TeamCbomView:
    return R.TeamCbomView(team_id=1, team_name="Team", generated_at=NOW, as_of=NOW.date(), fingerprint="f00dfeed")


def _with_deleted(*names: str):
    rows, collections = FX.build()
    collections = [dataclasses.replace(c, source_kind="") if c.source_name in names else c for c in collections]
    by_key = {c.key: c for c in collections}
    for row in rows:
        row.collection = by_key[row.collection.key]
    return rows, collections


def _flat(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", pdf_text(pdf))


# ----------------------------------------------------------------------------- Q1-01: one rule, every count
def test_is_deleted_source_is_the_one_rule():
    rows, collections = _with_deleted(GONE)
    gone = [c for c in collections if CV.is_deleted_source(c)]
    assert [c.source_name for c in gone] == [GONE]
    from backend.utilities.cbom_sources import cert_estate

    assert all(cert_estate.is_deleted(c) == CV.is_deleted_source(c) for c in collections)
    found = CV.current_only(CV.SourcesResult(collections=collections, rows=rows))
    assert GONE not in {c.source_name for c in found.collections}
    assert not [r for r in found.rows if r.collection.source_name == GONE]


def test_merge_counts_nothing_of_a_deleted_source():
    rows, collections = _with_deleted(GONE)
    gone_key = next(c.key for c in collections if c.source_name == GONE)
    gone_assets = sum(1 for r in rows if r.collection.key == gone_key)
    assert gone_assets > 0
    merged = R.merge_collections(_empty(), rows, collections)
    live_rows = [r for r in rows if r.collection.key != gone_key]
    live_colls = [c for c in collections if c.key != gone_key]
    expected = R.merge_collections(_empty(), live_rows, live_colls)
    # the totals are those of the live sources alone
    assert merged.asset_occurrences == expected.asset_occurrences
    assert merged.pqc_vulnerable == expected.pqc_vulnerable
    assert merged.issue_by_impact == expected.issue_by_impact
    assert merged.included == expected.included == len(live_colls)
    assert not [a for a in merged.assets if a.source_key == gone_key]
    assert gone_key not in {s.key for s in merged.sources}
    assert gone_key not in {f.source_key for f in merged.posture.facts}
    # still named, for the record ("Removed from scope", "Left out")
    assert gone_key in {c.key for c in merged.collections}
    assert [c.key for c in R.removed_collections(merged)] == [gone_key]
    assert gone_key not in {c.key for c in R.current_collections(merged)}


def test_d1_lists_a_deleted_source_under_removed_from_scope_outside_every_total():
    rows, collections = _with_deleted(GONE)
    merged = R.merge_collections(_empty(), rows, collections)
    removed = d1.removed_rows(merged)
    gone = next(c for c in collections if c.source_name == GONE)
    assert removed == [["1", GONE, f"#{gone.run_id}", "2026-11-23", str(gone.asset_count), "No"]]
    text = _flat(d1.build_pdf(merged))
    assert "Removed from scope" in text
    assert f"Sources assessed: {len(collections) - 1}." in text
    assert "none of their assets is counted in any total" in text


def test_d1_has_no_removed_table_when_nothing_was_deleted():
    rows, collections = FX.build()
    merged = R.merge_collections(_empty(), rows, collections)
    assert d1.removed_rows(merged) == []
    assert "Removed from scope" not in _flat(d1.build_pdf(merged))


def test_dashboard_counts_no_asset_of_a_deleted_source():
    from backend.utilities.dashboard.scan_list import generate_cbom_dashboard_data

    rows, collections = _with_deleted(GONE)
    both = generate_cbom_dashboard_data([], CV.SourcesResult(collections=collections, rows=rows))
    live = generate_cbom_dashboard_data([], CV.current_only(CV.SourcesResult(collections=collections, rows=rows)))
    assert both["card_data"] == live["card_data"]
    assert both["sources"]["collections"] == len(collections) - 1


# ----------------------------------------------------------------------------- Q1-02: the job history
@pytest.mark.parametrize(("status", "error", "outcome", "expected"), [
    ("failure", "Nothing collected: https://172.24.0.2:6443: auth_failed (the API server refused the credential)",
     "failed", "auth_failed"),
    ("failure", "Nothing collected: 10.232.0.23: identity_unverified (the server's identity cannot be checked)",
     "failed", "identity_unverified"),
    ("failure", "Scan node stopped responding", None, "Scan node stopped responding"),
    ("expired", None, None, "expired"),
    ("pending", None, None, "waiting"),
    ("success", None, "ok", None),
    ("success", None, "partial", "partial"),
])
def test_attempt_reason_reads_the_collector_code(status, error, outcome, expected):
    assert CV.attempt_reason(status, error, outcome) == expected


def _k8s_agg(history: dict) -> R.CollectionAgg:
    return R.CollectionAgg(key="sources:k8s1", label="Kubernetes lab Tier 1", source_name="Kubernetes lab Tier 1",
                           source_kind="kubernetes", run_id=8, job_id=120,
                           observed_at=dt.datetime(2026, 11, 14, 9, 0, tzinfo=dt.timezone.utc), asset_count=40,
                           history=history)


STAGING_K8S = {  # q1/api/before/t1-run50.json: run #8 succeeded, #50, #51 and #53 failed with auth_failed
    "scans": 2, "first_scanned": dt.datetime(2026, 11, 12, 7, 0, tzinfo=dt.timezone.utc),
    "last_attempt_run_id": 53, "last_attempt_job_id": 498, "last_attempt_status": "failure",
    "last_attempt_reason": "auth_failed", "last_attempt_at": dt.datetime(2026, 11, 23, 15, 1, tzinfo=dt.timezone.utc)}


def test_sources_row_reads_scans_first_scanned_and_latest_attempt_from_history():
    row = R._collection_source_row(_k8s_agg(STAGING_K8S), {}, {})
    assert row.scan_count == 2
    assert row.first_scanned == STAGING_K8S["first_scanned"]
    assert row.last_scanned == dt.datetime(2026, 11, 14, 9, 0, tzinfo=dt.timezone.utc)
    assert (row.current_scan_id, row.last_attempt_scan_id) == (8, 53)
    assert row.last_attempt_status == R.STATUS_FAILURE and row.last_attempt_reason == "auth_failed"
    chip, tone, detail = d1._attempt_parts(row)
    assert (chip, tone) == ("FAILED", "critical")
    assert detail.startswith("run #53 (auth_failed), 2026-11-23; figures reflect run #8 of 2026-11-14")


def test_sources_row_is_success_when_the_latest_attempt_is_the_current_collection():
    history = {**STAGING_K8S, "last_attempt_run_id": 8, "last_attempt_status": "success", "last_attempt_reason": None}
    row = R._collection_source_row(_k8s_agg(history), {}, {})
    assert (row.last_attempt_scan_id, row.last_attempt_status, row.last_attempt_reason) == (8, R.STATUS_SUCCESS, None)
    assert d1._attempt_parts(row) == ("SUCCESS", "low", "run #8")


def test_a_waiting_latest_attempt_is_not_completed_never_failed():
    history = {**STAGING_K8S, "last_attempt_run_id": 55, "last_attempt_status": "pending",
               "last_attempt_reason": "waiting"}
    chip, _tone, detail = d1._attempt_parts(R._collection_source_row(_k8s_agg(history), {}, {}))
    assert chip == "NOT COMPLETED" and detail.startswith("run #55 (waiting)")


def test_collection_history_reads_every_collect_job_of_the_source():
    """The DB read: success count, the first success and the newest attempt (whatever its status) per source."""
    from backend.new_models import CbomCollectionJob, CbomCollectionSource
    from sqlalchemy import create_engine
    from sqlmodel import Session

    engine = create_engine("sqlite://")
    for table in (CbomCollectionSource.__table__, CbomCollectionJob.__table__):
        table.create(engine)
    t = lambda day: dt.datetime(2026, 11, day, 9, 0, tzinfo=dt.timezone.utc).replace(tzinfo=None)
    with Session(engine) as s:
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="kubernetes", name="Kubernetes lab Tier 1",
                                   name_lower="kubernetes lab tier 1", source_uid="k8s1")
        s.add(src)
        s.flush()
        for run, day, status, error in ((5, 12, "success", None), (8, 14, "success", None),
                                        (50, 18, "failure", "Nothing collected: https://172.24.0.2:6443: auth_failed"),
                                        (53, 23, "failure", "Nothing collected: https://172.24.0.2:6443: auth_failed")):
            s.add(CbomCollectionJob(team_id=1, run_id=run, source_id=src.id, kind="collect", status=status,
                                    error=error, created_at=t(day), finished_at=t(day), params={"source_uid": "k8s1"}))
        s.add(CbomCollectionJob(team_id=2, run_id=60, source_id=None, kind="collect", status="failure",
                                created_at=t(24), params={"source_uid": "k8s1"}))  # another team: never read
        s.commit()
        history = CV.collection_history(s, 1, {src.id: src})
    h = history["k8s1"]
    assert h["scans"] == 2
    assert h["first_scanned"] == dt.datetime(2026, 11, 12, 9, 0, tzinfo=dt.timezone.utc)
    assert (h["last_attempt_run_id"], h["last_attempt_status"], h["last_attempt_reason"]) == (53, "failure",
                                                                                              "auth_failed")


def test_d14_names_the_deleted_source_and_counts_nothing_of_it():
    from backend.utilities.pdf import cbom_board_report_pdf as d14

    rows, collections = _with_deleted(GONE)
    merged = R.merge_collections(_empty(), rows, collections)
    text = _flat(d14.build_pdf(merged))
    assert f"the last collections of 1 deleted source ({GONE}; listed in D1)" in text
    assert d14.scope_sentence(merged).startswith(f"Across {len(collections) - 1} sources")
