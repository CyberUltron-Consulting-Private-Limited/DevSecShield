"""Issue #159: one Sources run, one asset count, from one function (Rule P, CB-38 PLAN §2.5).

The CBOM Scans table (``GET /{t}/cbom/scans`` ``runs_list_data[].asset_count``), Review & Run
(``GET /{t}/cbom/sources/runs`` ``asset_count``) and the run's assets API (``GET /runs/{id}/assets`` ``total`` and
``all_total``) show the same number for a run, on a fixture that has ``coverage`` rows ("could not read X"). The
number counts every stored row of the run, coverage rows included (#166); the run posture's ``assets`` is the same
rows less the coverage rows (the assets API's ``coverage`` type facet), so each page's figure is derivable from the
other and none is recounted.

Same SQLite + real-router harness as test_cb38_runs_in_results_api.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cb38_runs_in_results_api as _cb38
from test_cb38_runs_in_results_api import MIXED, seed_run

world = _cb38.world
api = _cb38.api
no_mongo = _cb38.no_mongo
_fresh_runs_cache = _cb38._fresh_runs_cache


def _ok(r):
    assert r.status_code == 200, r.text
    return r.json()


def _three_counts(api, run_id: int, **runs_params) -> dict[str, int]:
    table = {r["id"]: r for r in _ok(api("GET", "/1/cbom/scans"))["runs_list_data"]}
    review = {r["id"]: r for r in _ok(api("GET", "/1/cbom/sources/runs", params=runs_params))["runs"]}
    assets = _ok(api("GET", f"/1/cbom/sources/runs/{run_id}/assets"))  # the default page: view=all, no filter
    return {"scans_table": table[run_id]["asset_count"], "review_and_run": review[run_id]["asset_count"],
            "assets_total": assets["total"], "assets_all_total": assets["all_total"],
            "coverage_facet": assets["facets"]["type"].get("coverage", 0)}


def test_159_all_three_endpoints_agree_on_runs_with_coverage_rows(api, world, no_mongo):
    engine, ids = world
    seeded = seed_run(engine, 1, ids["alice"], scan_id=77)                                  # 7 assets + 2 coverage
    no_gaps = seed_run(engine, 1, ids["alice"], source_name="srv-nogaps", rows=MIXED[:3])   # 3 assets, no coverage
    only_gaps = seed_run(engine, 1, ids["alice"], source_name="srv-gaps", rows=MIXED[-2:])  # 2 coverage rows only
    expected = {seeded: (9, 2), no_gaps: (3, 0), only_gaps: (2, 2)}
    for run_id, (rows, coverage) in expected.items():
        counts = _three_counts(api, run_id)
        assert counts == {"scans_table": rows, "review_and_run": rows, "assets_total": rows,
                          "assets_all_total": rows, "coverage_facet": coverage}, (run_id, counts)
        posture = _ok(api("GET", f"/1/cbom/sources/runs/{run_id}/posture"))["posture"]
        assert posture["assets"] == rows - coverage, (run_id, posture["assets"])  # posture: coverage rows left out
    # Review & Run filtered to one linked code scan reports the same number for that run
    assert _three_counts(api, seeded, scan_id=77)["review_and_run"] == 9
    # a second read (the Scans table's finished-run cache) still agrees
    assert _three_counts(api, seeded)["scans_table"] == 9


def test_159_scans_table_and_review_and_run_count_with_one_function(api, world, no_mongo, monkeypatch):
    """Rule P: both run lists take a run's asset count from ``run_list.asset_counts``, not from a count each."""
    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"])
    calls: list[tuple[int, tuple[int, ...]]] = []

    def fake(session, team_id, run_ids):
        ids_ = tuple(sorted({int(i) for i in run_ids}))
        calls.append((team_id, ids_))
        return {i: 4242 for i in ids_}

    monkeypatch.setattr(run_list, "asset_counts", fake)
    table = {r["id"]: r for r in _ok(api("GET", "/1/cbom/scans"))["runs_list_data"]}
    review = {r["id"]: r for r in _ok(api("GET", "/1/cbom/sources/runs"))["runs"]}
    assert table[run_id]["asset_count"] == review[run_id]["asset_count"] == 4242
    assert len(calls) == 2 and all(team == 1 for team, _ in calls)  # one grouped call per list, never per run


def test_159_asset_counts_is_team_scoped_and_counts_every_row(world):
    from sqlmodel import Session

    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    seeded = seed_run(engine, 1, ids["alice"])
    empty = seed_run(engine, 1, ids["alice"], source_name="srv-empty", rows=[])
    with Session(engine) as s:
        assert run_list.asset_counts(s, 1, [seeded, empty, seeded]) == {seeded: len(MIXED), empty: 0}
        assert run_list.asset_counts(s, 2, [seeded]) == {seeded: 0}  # another team's run counts nothing
        assert run_list.asset_counts(s, 1, []) == {}
