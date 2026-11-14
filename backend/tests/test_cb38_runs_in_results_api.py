"""CB-38 PR-1a: every CBOM Sources run is a row of the CBOM Scans -> Table list, and a run's assets carry the unified
results table's fields (PLAN cb-38 §3 PR-1 rows, §5.1, §5.4; tests B1-B5, B7 of §9).

Same SQLite + real-router harness as test_cbom_sources_api.py: real JWTs, real routers, foreign keys enforced.
"""
from __future__ import annotations

import datetime as dt
import sys
import threading
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _api_tests  # noqa: E402
import test_cbom_sources_as_results as _results_tests  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_sources_as_results import CERT, HOST_KEY, TLS  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
)
from backend.utilities.cbom_sources import cbom_metrics as M  # noqa: E402
from backend.utilities.cbom_sources import collections_view as CV  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import waves as WAVES  # noqa: E402

# the shared fixtures (SQLite world, real-JWT client, no Mongo), re-exported so pytest finds them here
world = _api_tests.world
api = _api_tests.api
no_mongo = _results_tests.no_mongo

NOW = dt.datetime.utcnow().replace(microsecond=0)
FAR = (NOW + dt.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------------------------- seeding
def _source(s: Session, team_id: int, owner_id: int, name: str) -> CbomCollectionSource:
    src = CbomCollectionSource(team_id=team_id, owner_user_id=owner_id, kind="linux_servers", name=name,
                               name_lower=name.lower(), config={"targets": ["10.9.0.1"]})
    s.add(src)
    s.flush()
    return src


def _asset(team_id: int, run: CbomCollectionRun, job: CbomCollectionJob, n: int, **kw) -> CbomCollectedAsset:
    base = {"asset_type": "ssh_host_key", "cdx_type": "related-crypto-material", "target": "10.9.0.1",
            "location": f"/etc/ssh/key{n}.pub", "name": f"key {n}", "algorithm": "ssh-rsa", "key_size": 3072,
            "quantum_vulnerable": True, "impact": None, "finding_codes": [], "finding": None, "facts": {},
            "created_at": NOW}
    base.update(kw)
    return CbomCollectedAsset(team_id=team_id, run_id=run.id, job_id=job.id, source_id=job.source_id, attempt=1,
                              asset_key=f"k{n:04d}", **base)


MIXED = [  # (impact, quantum_vulnerable, asset_type, codes): what B3 counts
    ("Critical", True, "ssh_host_key", ["WEAK_KEY", "QUANTUM_VULNERABLE"]),
    ("High", True, "ssh_host_key", ["WEAK_KEY"]),
    ("High", False, "tls_endpoint", ["WEAK_CIPHER"]),
    ("Medium", None, "tls_endpoint", []),
    ("Low", True, "ssh_host_key", ["QUANTUM_VULNERABLE"]),
    (None, True, "ssh_host_key", ["QUANTUM_VULNERABLE"]),  # an RSA host key with no weakness: informational
    (None, False, "ssh_host_key", []),
    (None, None, "coverage", ["COVERAGE_UNREACHABLE"]),  # "could not read": never counted
    ("High", None, "coverage", ["COVERAGE_AUTH"]),       # even with an impact
]


def seed_run(engine, team_id: int, owner_id: int, *, status: str = "done", rows=MIXED, source_name: str = "srv-a",
             charged_c: int = 250, refunded_c: int = 0, scan_id: int | None = None, job_status: str = "success",
             extra_jobs: tuple[str, ...] = ()) -> int:
    with Session(engine) as s:
        src = _source(s, team_id, owner_id, source_name)
        run = CbomCollectionRun(team_id=team_id, owner_user_id=owner_id, client_request_id=f"seed-{source_name}-{status}",
                                status=status, credits_charged_c=charged_c, credits_refunded_c=refunded_c,
                                scan_id=scan_id, created_at=NOW, last_updated=NOW,
                                finished_at=NOW if status in ("done", "partial", "failed", "cancelled") else None)
        s.add(run)
        s.flush()
        job = CbomCollectionJob(team_id=team_id, run_id=run.id, source_id=src.id, kind="collect", status=job_status,
                                attempts=1, finished_at=NOW, params={"source_uid": src.source_uid,
                                                                     "source_name": src.name})
        s.add(job)
        for extra in extra_jobs:
            s.add(CbomCollectionJob(team_id=team_id, run_id=run.id, source_id=src.id, kind="collect", status=extra,
                                    attempts=0, params={"source_uid": src.source_uid, "source_name": src.name}))
        s.flush()
        for n, (impact, qv, a_type, codes) in enumerate(rows):
            s.add(_asset(team_id, run, job, n, impact=impact, quantum_vulnerable=qv, asset_type=a_type,
                         cdx_type="protocol" if a_type == "tls_endpoint" else (
                             "other" if a_type == "coverage" else "related-crypto-material"),
                         location=f"10.9.0.1:{1000 + n}" if a_type == "tls_endpoint" else f"/etc/ssh/key{n}.pub",
                         finding_codes=codes, finding=("finding " + ",".join(codes)) if impact else None))
        s.commit()
        return int(run.id)


@pytest.fixture(autouse=True)
def _fresh_runs_cache():
    try:
        from backend.utilities.cbom_sources import run_list
    except ImportError:  # before CB-38 (the tests then fail on what is missing, not here)
        yield
        return
    run_list.clear_cache()
    yield
    run_list.clear_cache()


@pytest.fixture()
def api_run(api, world):
    """One run through the real node API: the X1 TLS endpoint, its certificate and an SSH host key."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("x1-ssh-lab", node_id=node_id, targets=["10.20.0.1"],
                                                         window="any"))
    run = _run(api, "cb38-run-0001")
    _collect(api, hdr, _claim(api, hdr), [TLS, CERT, HOST_KEY])
    return run["id"]


def _listing(api, team=1, who="alice", **params):
    r = api("GET", f"/{team}/cbom/scans", who, params=params)
    assert r.status_code == 200, r.text
    return r.json()


# ----------------------------------------------------------------------------------------------- B1 list rows
def test_b1_scan_list_includes_runs(api, world, no_mongo, api_run):
    engine, ids = world
    alice = ids["alice"]
    partial = seed_run(engine, 1, alice, status="partial", source_name="srv-partial", charged_c=150, refunded_c=50,
                       scan_id=77, extra_jobs=("failure",))
    cancelled = seed_run(engine, 1, alice, status="cancelled", source_name="srv-cancel", job_status="cancelled")
    active = seed_run(engine, 1, alice, status="running", source_name="srv-active", job_status="claimed",
                      extra_jobs=("pending",))
    queued = seed_run(engine, 1, alice, status="queued", source_name="srv-q", rows=[], job_status="pending")
    failed = seed_run(engine, 1, alice, status="failed", source_name="srv-fail", rows=[], job_status="failure")

    body = _listing(api)
    assert [s["id"] for s in body["scans_list_data"]] == [77]  # the code scans are listed exactly as before
    assert "sources_runs" in body  # deprecated, kept one release
    rows = body["runs_list_data"]
    assert body["runs_total"] == 6 and body["runs_list_error"] is False
    assert [r["id"] for r in rows] == sorted([api_run, partial, cancelled, active, queued, failed], reverse=True)
    by_id = {r["id"]: r for r in rows}
    assert {r["kind"] for r in rows} == {"run"}
    assert {i: by_id[i]["scan_status"] for i in by_id} == {
        api_run: "success", partial: "partial", cancelled: "cancelled", active: "started", queued: "pending",
        failed: "failure"}
    assert by_id[partial]["run_status"] == "partial"

    p = by_id[partial]
    assert p["risk_data"] == {"total_critical": 1, "total_high": 2, "total_medium": 1, "total_low": 1,
                              "total_informational": 2, "total_quantum_vulnerable": 4}
    assert p["average_risk_score"] == M.average_risk({"critical": 1, "high": 2, "medium": 1, "low": 1}) == 6.0
    assert p["asset_count"] == 7 and p["endpoints_probed"] == 2  # coverage rows are not assets
    assert p["title"] == f"Sources run #{partial} · srv-partial"
    assert p["sources"] == [{"id": p["sources"][0]["id"], "name": "srv-partial", "kind": "linux_servers"}]
    assert p["jobs_total"] == 2 and p["jobs_done"] == 2
    assert p["estimated_credits"] == 1.5 and p["credits_refunded"] == 0.5
    assert p["linked_scan_id"] == 77 and p["repo_url"] is None and p["branch"] is None
    assert p["owner_user_email"] == "alice@t1.test" and p["owner_user_full_name"] == "alice t"
    assert p["counts_basis"] == "as_collected"
    assert p["created_at"].endswith("Z") and p["finished_at"].endswith("Z")
    assert by_id[active]["finished_at"] is None and by_id[active]["jobs_total"] == 2 and by_id[active]["jobs_done"] == 0

    q = by_id[queued]  # a run with no assets yet
    assert q["asset_count"] == 0 and q["average_risk_score"] == 0.0 and sum(q["risk_data"].values()) == 0

    real = by_id[api_run]  # judged by the real classifier through the node API
    assert real["asset_count"] == 3 and real["endpoints_probed"] == 1
    assert real["risk_data"]["total_high"] >= 1 and real["sources"][0]["name"] == "x1-ssh-lab"
    expected_keys = {"kind", "id", "title", "created_at", "last_updated", "finished_at", "scan_status", "run_status",
                     "risk_data", "average_risk_score", "sources", "repo_url", "branch", "estimated_credits",
                     "credits_refunded", "owner_user_email", "owner_user_full_name", "asset_count",
                     "endpoints_probed", "jobs_total", "jobs_done", "linked_scan_id", "counts_basis"}
    assert all(set(r) == expected_keys for r in rows)


def test_b1_runs_cursor_and_page_size(api, world, no_mongo, monkeypatch):
    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    made = [seed_run(engine, 1, ids["alice"], source_name=f"s{i}", rows=MIXED[:2]) for i in range(5)]
    monkeypatch.setattr(run_list, "LIST_LIMIT", 2)
    first = _listing(api)
    assert [r["id"] for r in first["runs_list_data"]] == made[::-1][:2] and first["runs_total"] == 5
    second = _listing(api, runs_before=first["runs_list_data"][-1]["id"])
    assert [r["id"] for r in second["runs_list_data"]] == made[::-1][2:4]
    last = _listing(api, runs_before=made[0])
    assert last["runs_list_data"] == [] and last["runs_total"] == 5


def test_list_validation_and_empty_team(api, world, no_mongo):
    for bad in ("0", "-1", "abc", "99999999999"):
        assert api("GET", "/1/cbom/scans", params={"runs_before": bad}).status_code == 422, bad
    empty = _listing(api, team=2, who="carol")
    assert empty["runs_list_data"] == [] and empty["runs_total"] == 0
    # other scan types do not grow the runs fields
    other = api("GET", "/1/sast/scans")
    assert other.status_code == 200 and "runs_list_data" not in other.json()


def test_list_logs_one_line_per_build(api, world, no_mongo, capsys):
    engine, ids = world
    seed_run(engine, 1, ids["alice"])
    capsys.readouterr()
    _listing(api)
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if "cbom runs list team=1 runs=1 ms=" in line]
    assert len(lines) == 1, out


def test_list_survives_a_runs_failure(api, world, no_mongo, monkeypatch):
    from backend.utilities.cbom_sources import run_list

    def boom(*_a, **_k):
        raise RuntimeError("db gone")

    monkeypatch.setattr(run_list, "list_run_rows", boom)
    body = _listing(api)
    assert body["runs_list_data"] == [] and body["runs_list_error"] is True and body["scans_list_data"]


# ----------------------------------------------------------------------------------------------- B2 tenancy
def test_b2_scan_list_runs_tenancy(api, world, no_mongo):
    engine, ids = world
    a_run = seed_run(engine, 1, ids["alice"], source_name="team-a")
    b_run = seed_run(engine, 2, ids["carol"], source_name="team-b")
    team_b = _listing(api, team=2, who="carol")
    assert [r["id"] for r in team_b["runs_list_data"]] == [b_run] and team_b["runs_total"] == 1
    # a cursor naming the other team's run only bounds ids: still team B's runs only
    assert [r["id"] for r in _listing(api, team=2, who="carol", runs_before=a_run + 1)["runs_list_data"]] == \
        ([b_run] if b_run < a_run + 1 else [])
    assert b_run not in [r["id"] for r in _listing(api)["runs_list_data"]]
    assert api("GET", "/1/cbom/scans", "carol").status_code in (401, 403)  # not a member of team A
    # a foreign run's assets: 404 through the caller's own team, 403 through a team they are not in
    assert api("GET", f"/2/cbom/sources/runs/{a_run}/assets", "carol").status_code == 404
    assert api("GET", f"/2/cbom/sources/runs/{a_run}/assets", "carol", params={"view": "findings"}).status_code == 404
    assert api("GET", f"/1/cbom/sources/runs/{a_run}/assets", "carol").status_code == 403
    assert api("GET", "/1/cbom/sources/runs/999999/assets").status_code == 404


# ----------------------------------------------------------------------------------------------- B3 counts rule
def test_b3_run_list_counts_equal_node_row_summary(api, world, no_mongo, api_run):
    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    seeded = seed_run(engine, 1, ids["alice"])
    rows = {r["id"]: r for r in _listing(api)["runs_list_data"]}
    with Session(engine) as s:
        for run_id in (seeded, api_run):
            assets = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()
            jobs = {j.id: j for j in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).all()}
            code_rows = []
            for a in assets:
                if a.asset_type == "coverage":
                    continue
                job = jobs[a.job_id]
                coll = CV.Collection(run_id=run_id, job_id=job.id, source_ref="ref", source_name="n", source_kind="",
                                     observed_at=dt.datetime.now(dt.timezone.utc))
                at_collection = {"impact": a.impact, "finding": a.finding, "finding_codes": a.finding_codes or []}
                code_rows.append(CV.node_row(a, coll, at_collection))
            summary = M.summarize_code_rows(code_rows)
            risk = rows[run_id]["risk_data"]
            assert risk == {"total_critical": summary.severity["critical"], "total_high": summary.severity["high"],
                            "total_medium": summary.severity["medium"], "total_low": summary.severity["low"],
                            "total_informational": summary.informational,
                            "total_quantum_vulnerable": summary.quantum["quantum_vulnerable"]}, run_id
            assert rows[run_id]["average_risk_score"] == summary.average_risk
            assert rows[run_id]["asset_count"] == summary.rows
            assert run_list.grouped_counts(s, 1, [run_id])[run_id]["risk_data"] == risk


def test_counts_cache_finished_runs_only(api, world, no_mongo):
    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    done = seed_run(engine, 1, ids["alice"], source_name="fin", rows=MIXED[:1])
    live = seed_run(engine, 1, ids["alice"], status="running", source_name="live", rows=MIXED[:1], job_status="claimed")
    first = {r["id"]: r["asset_count"] for r in _listing(api)["runs_list_data"]}
    assert first == {done: 1, live: 1}
    assert len(run_list._COUNTS) == 1  # only the finished run's counts are kept
    with Session(engine) as s:  # assets arrive while the run is active; nothing else about either run changes
        for run_id in (done, live):
            run = s.get(CbomCollectionRun, run_id)
            job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).first()
            s.add(_asset(1, run, job, 50, impact="High", finding_codes=["WEAK_KEY"]))
        s.commit()
    second = {r["id"]: r["asset_count"] for r in _listing(api)["runs_list_data"]}
    assert second[live] == 2  # an active run is read live
    assert second[done] == 1  # a finished run's counts are cached by (id, last_updated, status)
    with Session(engine) as s:  # a status change (e.g. the run re-opened and finished again) is a new key
        run = s.get(CbomCollectionRun, done)
        run.last_updated = NOW + dt.timedelta(seconds=5)
        s.add(run)
        s.commit()
    assert {r["id"]: r["asset_count"] for r in _listing(api)["runs_list_data"]}[done] == 2


def test_concurrent_list_builds_agree(world):
    from sqlmodel import Session as S

    from backend.utilities.cbom_sources import run_list

    engine, ids = world
    for i in range(3):
        seed_run(engine, 1, ids["alice"], source_name=f"c{i}")
    results, errors = [], []

    def build():
        try:
            with S(engine) as s:
                results.append(run_list.list_run_rows(s, 1))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=build) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(results) == 6
    assert all(r == results[0] for r in results) and results[0]["runs_total"] == 3


def test_status_buckets_file_matches_backend():
    import json

    from backend.utilities.cbom_sources import run_list

    path = Path(__file__).resolve().parents[2] / "contracts" / "cbom" / "status_buckets.json"
    data = json.loads(path.read_text())
    assert data["run_to_unified"] == run_list.RUN_TO_UNIFIED
    assert data["assignment_to_finding"] == run_list.ASSIGNMENT_TO_FINDING == CV.REMEDIATION_BUCKET
    for raw, unified in data["run_to_unified"].items():
        assert run_list.unified_run_status(raw) == unified
    for raw, unified in data["assignment_to_finding"].items():
        assert run_list.finding_status(raw) == unified
    assert run_list.finding_status(None) == "not_started"
    assert set(WAVES.STATUSES) == set(data["assignment_to_finding"])


# ----------------------------------------------------------------------------------------------- B4 views
def _assets(api, run_id, team=1, who="alice", **params):
    r = api("GET", f"/{team}/cbom/sources/runs/{run_id}/assets", who, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_b4_run_assets_findings_view(api, world, api_run):
    engine, ids = world
    seeded = seed_run(engine, 1, ids["alice"])
    for run_id in (seeded, api_run):
        everything = _assets(api, run_id, page_size=200)
        with Session(engine) as s:  # today's list, called directly (no CB-38 code on this path)
            today = INV.list_assets(s, team_id=1, run_id=run_id, page_size=200)
        assert everything["total"] == today["total"] and everything["all_total"] == today["all_total"]
        assert everything["facets"] == today["facets"] and everything["targets"] == today["targets"]
        assert len(everything["items"]) == len(today["items"])
        for got, before in zip(everything["items"], today["items"]):
            assert list(got)[:len(before)] == list(before)  # same keys, same order, then the new ones
            assert {k: got[k] for k in before} == before

        findings = _assets(api, run_id, view="findings", page_size=200)
        expected = [i["id"] for i in today["items"] if i["type"] != "coverage" and i["impact"]]
        assert [i["id"] for i in findings["items"]] == expected and findings["total"] == len(expected)
        assert findings["findings_total"] == everything["findings_total"] == len(expected)
        assert findings["all_total"] == everything["all_total"]  # the run-wide totals do not move with the view
        assert findings["view"] == "findings" and everything["view"] == "all"
    seeded_all = _assets(api, seeded, page_size=200)
    assert seeded_all["findings_total"] == 5 and seeded_all["all_total"] == 9


def test_run_assets_new_item_fields(api, world, api_run):
    from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

    engine, ids = world
    seeded = seed_run(engine, 1, ids["alice"])
    page = _assets(api, seeded, page_size=200)
    items = {i["id"]: i for i in page["items"]}
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, seeded)
        waves = {w["asset_id"]: w for w in WAVES.node_items(s, 1, run)}
        assets = {a.id: a for a in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == seeded)).all()}
    for aid, item in items.items():
        a = assets[aid]
        if a.asset_type == "coverage":
            assert item["asset_key"] is None and item["wave"] is None and item["type_label"] == "Not collected"
        else:
            assert item["wave"] == waves[aid] and item["asset_key"] == waves[aid]["asset_key"]
        assert item["status"] == "not_started" and item["assignment_status"] is None
        coll = CV.Collection(run_id=seeded, job_id=a.job_id, source_ref="r", source_name="n", source_kind="",
                             observed_at=dt.datetime.now(dt.timezone.utc))
        row = CV.node_row(a, coll, {"impact": item["impact"], "finding": item["finding"],
                                    "finding_codes": item["finding_codes"]})
        assert item["risk_score"] == cbom_finding_risk_score(row)
        assert 0.0 <= item["risk_score"] <= 10.0 and (item["risk_score"] > 0) == bool(item["impact"])
        for key in ("algorithm_name", "algorithm_type", "crypto_strength", "quantum_safe", "description"):
            assert item[key] == row[key], key
    host_keys = [i for i in items.values() if i["type"] == "ssh_host_key"]
    assert {i["type_label"] for i in host_keys} == {"SSH host key"}
    crit = next(i for i in items.values() if i["impact"] == "Critical")
    assert crit["crypto_strength"] == "weak" and crit["quantum_safe"] is False and crit["algorithm_type"] == "key"
    # the real classifier's rows too
    real = _assets(api, api_run)
    assert all(i["asset_key"] and len(i["asset_key"]) == 40 and i["type_label"] for i in real["items"])


def test_run_assets_param_validation(api, world):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"])
    # malformed values are refused exactly like the existing filters (the Sources API answers 400, never echoing input)
    existing = api("GET", f"/1/cbom/sources/runs/{run_id}/assets", params={"impact": "bogus"}).status_code
    assert existing == 400
    for params in ({"view": "bogus"}, {"status": "bogus"}, {"status": "done"}, {"view": ""}, {"view": "ALL"}):
        r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets", params=params)
        assert r.status_code == existing, (params, r.text)
    empty = seed_run(engine, 1, ids["alice"], source_name="nothing", rows=[])
    out = _assets(api, empty, view="findings", status="fixed")
    assert out["items"] == [] and out["total"] == 0 and out["findings_total"] == 0 and out["all_total"] == 0
    # existing filters still combine with the new ones
    crit = _assets(api, run_id, view="findings", impact="Critical")
    assert [i["impact"] for i in crit["items"]] == ["Critical"]


# ----------------------------------------------------------------------------------------------- B5 key and status
def test_b5_run_asset_item_has_stable_key_and_status(api, world):
    engine, ids = world
    run_id = seed_run(engine, 1, ids["alice"])
    before = _assets(api, run_id, view="findings", page_size=200)
    with Session(engine) as s:
        keys = {w["asset_id"]: w["asset_key"] for w in WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))}
    assert all(i["asset_key"] == keys[i["id"]] for i in before["items"])
    target, other = before["items"][0], before["items"][1]
    r = api("PUT", "/1/cbom/remediation", json={"run_id": run_id, "items": [
        {"asset_key": target["asset_key"], "status": "done"},
        {"asset_key": other["asset_key"], "status": "accepted_risk", "wave": 2}]})
    assert r.status_code == 200 and r.json()["updated"] == 2, r.text

    after = {i["id"]: i for i in _assets(api, run_id, page_size=200)["items"]}
    assert after[target["id"]]["status"] == "fixed" and after[target["id"]]["assignment_status"] == "done"
    assert after[other["id"]]["status"] == "ignored" and after[other["id"]]["wave"]["wave"] == 2
    assert after[other["id"]]["wave"]["wave_source"] == "assigned"

    fixed = _assets(api, run_id, status="fixed")
    assert [i["id"] for i in fixed["items"]] == [target["id"]] and fixed["total"] == 1
    assert [i["id"] for i in _assets(api, run_id, status="ignored")["items"]] == [other["id"]]
    assert _assets(api, run_id, status="in_progress")["items"] == []
    open_ids = {i["id"] for i in _assets(api, run_id, status="not_started", page_size=200)["items"]}
    plannable = {i for i, v in after.items() if v["type"] != "coverage"}
    assert open_ids == plannable - {target["id"], other["id"]}
    both = _assets(api, run_id, status="not_started", view="findings", page_size=200)
    assert {i["id"] for i in both["items"]} == {i["id"] for i in before["items"]} - {target["id"], other["id"]}
    # the status follows the stable key, so the same asset in a LATER run of the source says fixed too
    with Session(engine) as s:
        old = s.get(CbomCollectionRun, run_id)
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).one()
        src = s.get(CbomCollectionSource, job.source_id)
        rerun = CbomCollectionRun(team_id=1, owner_user_id=old.owner_user_id, client_request_id="rerun", status="done",
                                  created_at=NOW, last_updated=NOW, finished_at=NOW)
        s.add(rerun)
        s.flush()
        job2 = CbomCollectionJob(team_id=1, run_id=rerun.id, source_id=src.id, kind="collect", status="success",
                                 attempts=1, params={"source_uid": src.source_uid, "source_name": src.name})
        s.add(job2)
        s.flush()
        first = s.get(CbomCollectedAsset, target["id"])
        s.add(CbomCollectedAsset(**{**first.model_dump(exclude={"id"}), "run_id": rerun.id, "job_id": job2.id}))
        s.commit()
        rerun_id = rerun.id
    again = _assets(api, rerun_id)["items"]
    assert len(again) == 1 and again[0]["status"] == "fixed" and again[0]["asset_key"] == target["asset_key"]


# ----------------------------------------------------------------------------------------------- B7 KB memo
def test_b7_library_status_called_once_per_package(api, world, monkeypatch):
    engine, ids = world
    packages = [("openssl", "3.0.2"), ("libssl1.1", "1.1.1f"), ("gnutls", "3.7.3"), ("openssl", "1.0.2k")]
    with Session(engine) as s:
        src = _source(s, 1, ids["alice"], "libs")
        run = CbomCollectionRun(team_id=1, owner_user_id=ids["alice"], client_request_id="libs", status="done",
                                created_at=NOW, last_updated=NOW, finished_at=NOW)
        s.add(run)
        s.flush()
        job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                attempts=1, params={"source_uid": src.source_uid, "source_name": "libs"})
        s.add(job)
        s.flush()
        for n in range(200):
            name, version = packages[n % len(packages)]
            s.add(_asset(1, run, job, n, asset_type="crypto_library", cdx_type="library", location=f"package:{n}",
                         name=name, algorithm=None, key_size=None, quantum_vulnerable=None,
                         facts={"name": name, "version": version, "source": "package"}))
        s.commit()
        run_id = run.id
    cached = getattr(crypto_kb, "_library_status_cached", None)
    if cached is not None:
        cached.cache_clear()
    calls: list[str] = []
    real = crypto_kb.library_for

    def counting(package):
        calls.append(package)
        return real(package)

    monkeypatch.setattr(crypto_kb, "library_for", counting)
    page = _assets(api, run_id, page_size=200)
    assert len(page["items"]) == 200
    days = {NOW.date(), dt.datetime.utcnow().date()}  # as of the run, and today (the same day unless at midnight)
    assert len(calls) <= len(packages) * len(days), f"{len(calls)} uncached library_status calls for 200 rows"
    assert {c for c in calls} == {p for p, _v in packages}
    # every caller gets its own copy: changing one answer never changes the next
    first = crypto_kb.library_status("openssl", "3.0.2")
    first["cves"].append("CVE-0000-0000")
    assert "CVE-0000-0000" not in crypto_kb.library_status("openssl", "3.0.2")["cves"]
