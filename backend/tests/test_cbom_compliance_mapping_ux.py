"""#270: the compliance mapping's drill-down and fix data for a Sources run.

C1  /results compliance: every clause carries ``findings`` = [{code, title, fix}] (the KB title and remediation summary
    of each finding code behind it, so the page shows labels and "How to fix" instead of raw codes), and every
    framework ``assets`` = the distinct assets behind any of its clauses (the clause counts overlap, so they cannot be
    added up in the browser). The clauses cited are unchanged (same ids, counts and codes as the posture).
C2  /assets?code=A,B lists exactly the run's collected (non-coverage) assets whose finding codes include A or B, so
    each clause's "N assets" and each framework's assets-affected count equal the filtered table's total.
C3  the code filter is validated like the other filters (400, never echoing input) and combines with them.

Same SQLite + real-router harness as test_cb38_runs_in_results_api.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cb38_runs_in_results_api as RUNS
from backend.new_models import CbomCollectedAsset
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_results as RR
from sqlmodel import Session, select

api = RUNS.api
world = RUNS.world
no_mongo = RUNS.no_mongo
seed_run = RUNS.seed_run

ROWS = [  # (impact, quantum_vulnerable, asset_type, codes)
    ("Medium", True, "ssh_host_key", ["SSH_DH_SHA1", "QUANTUM_VULNERABLE"]),
    ("High", False, "tls_endpoint", ["WEAK_CIPHER"]),
    ("High", True, "tls_endpoint", ["WEAK_CIPHER", "NO_PQ_KEX"]),
    ("Low", True, "ssh_host_key", ["QUANTUM_VULNERABLE"]),
    (None, False, "ssh_host_key", []),
    ("High", None, "coverage", ["COVERAGE_AUTH"]),  # "could not read": never behind a clause
]


@pytest.fixture(autouse=True)
def _fresh_caches():
    RR.clear_cache()
    yield
    RR.clear_cache()


def _get(api, path, **params):
    r = api("GET", path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _assets_with(engine, run_id, codes):
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()
    return {r.id for r in rows if r.asset_type != "coverage" and set(r.finding_codes or []) & set(codes)}


def test_c1_clause_findings_and_framework_assets(api, world, no_mongo):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c1")
    out = _get(api, f"/1/cbom/sources/runs/{run_id}/results")
    frameworks = out["compliance"]["frameworks"]
    with Session(engine) as s:
        p = POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
    # the clauses cited are the posture's, unchanged (lane U3 owns the mapping)
    assert {(f["framework"], c["clause"]): (c["assets"], c["codes"]) for f in frameworks for c in f["clauses"]} == \
        {(RR._framework(f["framework"]), c["id"]): (c["assets"], c["codes"]) for f in p["compliance"]
         for c in f["clauses"]}
    touched = [f for f in frameworks if f["clauses"]]
    assert {f["framework"] for f in touched} >= {"NIST", "CERT-In", "RBI", "SEBI CSCRF"}
    for fw in frameworks:
        codes = {code for c in fw["clauses"] for code in c["codes"]}
        assert fw["assets"] == len(_assets_with(engine, run_id, codes)), fw["framework"]
        for clause in fw["clauses"]:
            assert [f["code"] for f in clause["findings"]] == clause["codes"]
            for f in clause["findings"]:
                kb = crypto_kb.entry("node", f["code"]) or {}
                assert f["title"] == kb["title"] and f["title"] != f["code"]
                assert f["fix"] == (kb.get("remediation") or {}).get("summary") and f["fix"]
    # overlap: WEAK_CIPHER and SSH_DH_SHA1 share the "algorithms" clauses, so a framework's assets are fewer than the
    # sum of its clause counts whenever two clauses name the same asset
    nist = next(f for f in frameworks if f["framework"] == "NIST")
    assert nist["assets"] <= sum(c["assets"] for c in nist["clauses"])
    assert next(f for f in frameworks if f["framework"] == "CNSA 2.0")["assets"] >= 0


def test_c1_posture_framework_assets_are_distinct(world):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c1p")
    with Session(engine) as s:
        p = POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
    for fw in p["compliance"]:
        codes = {code for c in fw["clauses"] for code in c["codes"]}
        assert fw["assets"] == len(_assets_with(engine, run_id, codes)) > 0
        assert fw["assets"] >= max(c["assets"] for c in fw["clauses"])


def test_c2_code_filter_equals_clause_counts(api, world, no_mongo):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c2")
    out = _get(api, f"/1/cbom/sources/runs/{run_id}/results")
    checked = 0
    for fw in out["compliance"]["frameworks"]:
        for clause in fw["clauses"]:
            page = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", code=",".join(clause["codes"]), page_size=200)
            assert page["total"] == clause["assets"] == len(page["items"]), clause["clause"]
            assert {i["id"] for i in page["items"]} == _assets_with(engine, run_id, clause["codes"])
            checked += 1
        if fw["clauses"]:
            codes = sorted({code for c in fw["clauses"] for code in c["codes"]})
            page = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", code=",".join(codes), page_size=200)
            assert page["total"] == fw["assets"]
    assert checked >= 4
    # the run-wide totals and facets do not move with the filter
    plain = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", page_size=200)
    one = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", code="SSH_DH_SHA1", page_size=200)
    assert one["all_total"] == plain["all_total"] and one["facets"] == plain["facets"]
    assert [i["finding_codes"] for i in one["items"]] == [["SSH_DH_SHA1", "QUANTUM_VULNERABLE"]]
    # an underscore is not a LIKE wildcard: SSH_DH_SHA1 never matches SSHxDHxSHA1
    assert _get(api, f"/1/cbom/sources/runs/{run_id}/assets", code="SSH_DH_SHA")["total"] == 0


def test_c3_code_filter_validation_and_combination(api, world, no_mongo):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c3")
    path = f"/1/cbom/sources/runs/{run_id}/assets"
    for bad in ("weak cipher", "WEAK_CIPHER;DROP", "%", ",".join(f"C{i}" for i in range(51)), ""):
        r = api("GET", path, params={"code": bad})
        assert r.status_code == 400, (bad, r.text)
        assert "DROP" not in r.text
    high = _get(api, path, code="WEAK_CIPHER,QUANTUM_VULNERABLE", impact="High", view="findings")
    assert {i["impact"] for i in high["items"]} == {"High"} and high["total"] == 2
    # coverage rows never match, even with their own code
    assert _get(api, path, code="COVERAGE_AUTH")["total"] == 0
    # another team's run: 404 through the caller's own team, 403 through a team they are not in
    assert api("GET", f"/2/cbom/sources/runs/{run_id}/assets", "carol", params={"code": "WEAK_CIPHER"}).status_code == 404
    assert api("GET", path, "carol", params={"code": "WEAK_CIPHER"}).status_code == 403


def test_c4_asset_id_filter(api, world, no_mongo):
    """A tri-state requirement's refs (zs-asset-<id>) drill down by id: only this run's rows, validated like code."""
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c4")
    other = seed_run(engine, 1, ids["alice"], rows=ROWS, source_name="c4-other")
    path = f"/1/cbom/sources/runs/{run_id}/assets"
    mine = [i["id"] for i in _get(api, path, page_size=200)["items"]]
    theirs = [i["id"] for i in _get(api, f"/1/cbom/sources/runs/{other}/assets", page_size=200)["items"]]
    picked = _get(api, path, asset_id=",".join(str(i) for i in [*mine[:2], *theirs[:2]]), page_size=200)
    assert sorted(i["id"] for i in picked["items"]) == sorted(mine[:2]) and picked["total"] == 2
    assert picked["all_total"] == len(mine)  # run-wide totals unchanged
    for bad in ("", "1,x", "-1", "0", ",".join(str(i) for i in range(1, 502)), "99999999999"):
        r = api("GET", path, params={"asset_id": bad})
        assert r.status_code == 400, (bad, r.text)
