"""CB-14: run concurrency and billing on partial jobs (``cbom-plans/DEVILS-ADVOCATE.md`` CB-14, OA-10b default).

Before this change (dev):
* two Starts that race (two tabs, a tab and a schedule) each planned the same source as not queued, so the source got
  two open collection jobs and the team was charged twice (R3 ``test_f3``: 2 jobs, 0.4 charged);
* a job that read some targets and skipped others at runtime (scan window, Stop all, deadline, never-scan list, a
  refused credential) was charged in full (R2: 2 of 4 skipped by the window, 1.0 charged, 0 refunded; KF-8);
* a refund was guarded only by the job's ``refunded`` flag, read and written by the ORM: two transactions refunding the
  same job (the node's result and the reaper, two cancels) could both give the credits back;
* nothing recorded each charge and refund on its own, so a balance could not be reconciled against the runs;
* a scan node could hold more claimed jobs than any limit (a node older than its own ZS_MAX_JOBS rule, or two claim
  requests at once).

Now: at most one open collection job per source (a partial unique index; the losing Start gets 409 and is charged
nothing), runtime skips refunded pro rata (OA-10b: "charge for what was contacted"), every charge and refund is one row
of ``cbomcreditentry`` with a unique key (a retry, a race or the reaper never moves credits twice), and a per-node cap
on claimed jobs.  Concurrency tests run on SQLite always and on PostgreSQL when ``CBOM_TEST_PG_URL`` is set (CI).

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb14_billing.py
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path

import pytest
import sqlalchemy as sa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import KNOWN_HOSTS, PASSWORD, api, enroll_node, world  # noqa: E402,F401  (fixtures)

from fastapi import HTTPException  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, func, select  # noqa: E402

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun,  # noqa: E402
                                CbomCollectionSource, CbomScanNode, Team)
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import runs as R  # noqa: E402
from backend.utilities.cbom_sources.billing import CbomCreditEntry, runtime_refund_c  # noqa: E402
from backend.utilities.cbom_sources.common import utcnow  # noqa: E402
from backend.utilities.cbom_sources.schemas import Include, RunCreate  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
VERSIONS = REPO / "prod_database_migrations" / "migrations" / "versions"
PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
FOUR = ["10.20.0.1", "10.20.0.2", "10.20.0.3", "10.20.0.4"]


def servers(name="four-hosts", node_id=None, targets=FOUR):
    return {"kind": "linux_servers", "name": name, "node_id": node_id,
            "config": {"targets": list(targets), "credential_type": "password", "login_user": "zs-cbom",
                       "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS, "window": "any"},
            "secrets": {"password": PASSWORD}}


def balance(engine, team_id=1) -> float:
    with Session(engine) as s:
        return round(float(s.get(Team, team_id).credit_balance), 2)


def ledger(engine, **where) -> list[CbomCreditEntry]:
    with Session(engine) as s:
        q = select(CbomCreditEntry)
        for k, v in where.items():
            q = q.where(getattr(CbomCreditEntry, k) == v)
        return list(s.exec(q.order_by(CbomCreditEntry.id)).all())


def started(api, engine, rid="cb14-run-0001", node_targets=FOUR):  # noqa: F811
    """A node, a four-host source and a started run whose one job the node has claimed."""
    node_id, token = enroll_node(api)[:2]
    src = api("POST", "/1/cbom/sources/items", json=servers(node_id=node_id, targets=node_targets)).json()["source"]
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": rid})
    assert run.status_code == 201, run.text
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200, claim.text
    return src, run.json()["run"], claim.json(), hdr


def finish(api, claim, hdr, rows, status="success", post_assets=True):  # noqa: F811
    counts = {"total": len(rows), "ok": sum(1 for r in rows if r["status"] == "ok"),
              "skipped": sum(1 for r in rows if r["status"].startswith("skipped_")),
              "failed": sum(1 for r in rows if r["status"] != "ok" and not r["status"].startswith("skipped_"))}
    job = claim["job"]
    if counts["ok"] and post_assets:  # what the read targets collected
        r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={
            "lease_id": job["lease_id"], "assets": [{"type": "tls_endpoint", "target": x["target"],
                                                     "location": f"{x['target']}:443", "facts": {"protocols": ["TLSv1.2"]}}
                                                    for x in rows if x["status"] == "ok"]})
        assert r.status_code == 200, r.text
    return api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={
        "lease_id": job["lease_id"], "status": status,
        "result": {"counts": counts, "targets": [{**r, "assets": 1 if r["status"] == "ok" else 0} for r in rows]}})


def reconciled(engine) -> None:
    """Every run's charge and refunds are its ledger rows, and the ledger explains the team balance (no double moves)."""
    with Session(engine) as s:
        for run in s.exec(select(CbomCollectionRun)).all():
            rows = s.exec(select(CbomCreditEntry).where(CbomCreditEntry.run_id == run.id)).all()
            assert sum(r.amount_c for r in rows if r.kind == "charge") == run.credits_charged_c, run.id
            assert sum(r.amount_c for r in rows if r.kind == "refund") == run.credits_refunded_c, run.id
            for job in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).all():
                refunds = [r.amount_c for r in rows if r.kind == "refund" and r.job_id == job.id]
                assert len(refunds) <= 1 and sum(refunds) == job.refunded_c <= job.weight_c, job.id


# ============================================================================ one open collection per source
def _race(engine, n: int, *, team_id=1, user_id=1) -> list[object]:
    """``n`` Starts with different client_request_ids that all plan before any of them writes (two tabs)."""
    barrier = threading.Barrier(n, timeout=30)
    real_plan = R.plan_run
    out: list[object] = []
    lock = threading.Lock()

    def planned(*a, **k):
        plan = real_plan(*a, **k)
        barrier.wait()  # every Start has seen "not queued" before the first one commits
        return plan

    def start(i: int) -> None:
        with Session(engine) as s:
            settings = get_or_create_settings(s, team_id)
            s.commit()
            try:
                run, _replayed = R.queue_run(s, team_id, user_id, RunCreate(
                    include=Include(servers=True), client_request_id=f"race-{i:04d}-tab"), settings, utcnow())
                s.commit()
                result: object = "queued"
            except HTTPException as exc:
                s.rollback()
                result = exc.status_code
            except Exception as exc:  # noqa: BLE001  (a leaked IntegrityError is a failure of this test)
                s.rollback()
                result = type(exc).__name__
        with lock:
            out.append(result)

    R.plan_run = planned
    try:
        threads = [threading.Thread(target=start, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
    finally:
        R.plan_run = real_plan
    return out


def test_f3_two_tabs_that_start_together_queue_one_job_and_charge_once(api, world):  # noqa: F811
    engine, ids = world
    node_id = enroll_node(api)[0]
    api("POST", "/1/cbom/sources/items", json=servers(node_id=node_id))
    before = balance(engine)
    out = _race(engine, 2, user_id=ids["alice"])
    assert sorted(map(str, out)) == ["409", "queued"], out
    with Session(engine) as s:
        jobs = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "collect")).all()
    assert len(jobs) == 1  # before the fix: 2 jobs
    assert balance(engine) == round(before - 0.8, 2)  # 4 hosts x 0.2, charged once (before: 1.6)
    assert [e.kind for e in ledger(engine)] == ["charge"]
    reconciled(engine)


def test_a_conflict_refuses_the_whole_start_and_charges_nothing(api, world):  # noqa: F811
    engine, ids = world
    node_id = enroll_node(api)[0]
    api("POST", "/1/cbom/sources/items", json=servers(node_id=node_id))
    api("POST", "/1/cbom/sources/items", json=servers(name="other-hosts", node_id=node_id, targets=["10.30.0.1"]))
    out = _race(engine, 3, user_id=ids["alice"])
    assert sorted(map(str, out)) == ["409", "409", "queued"], out
    with Session(engine) as s:
        per_source = s.exec(select(CbomCollectionJob.source_id, func.count()).where(
            CbomCollectionJob.kind == "collect").group_by(CbomCollectionJob.source_id)).all()
        assert sorted(n for _s, n in per_source) == [1, 1]
        assert len(s.exec(select(CbomCollectionRun)).all()) == 1  # the losing Starts left no run behind
    reconciled(engine)


def test_the_409_says_already_queued_and_a_replay_still_answers_200(api, world):  # noqa: F811
    engine, _ids = world
    node_id = enroll_node(api)[0]
    api("POST", "/1/cbom/sources/items", json=servers(node_id=node_id))
    first = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "tab-one-0001"})
    assert first.status_code == 201
    second = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "tab-two-0001"})
    assert second.status_code == 409 and "already queued" in second.json()["detail"].lower()
    replay = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "tab-one-0001"})
    assert replay.status_code == 200 and replay.json()["replayed"] is True


@needs_pg
def test_s_fifty_concurrent_starts_on_postgresql_give_one_job(monkeypatch):
    from test_cbom_sources_api import USERS  # noqa: F401
    from backend.new_models import TeamMembership, User

    engine = create_engine(PG, pool_size=60, max_overflow=10)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=1000.0))
        s.commit()
        user = User(email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None, default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        node = CbomScanNode(team_id=1, owner_user_id=user.id, name="n1", node_token_hash="0" * 64)
        s.add(node)
        s.commit()
        s.add(CbomCollectionSource(team_id=1, owner_user_id=user.id, kind="linux_servers", name="hosts",
                                   name_lower="hosts", enabled=True, node_id=node.id,
                                   config=servers()["config"]))
        s.commit()
        uid = user.id
    try:
        out = []
        barrier = threading.Barrier(50, timeout=60)
        real_plan = R.plan_run

        def planned(*a, **k):
            plan = real_plan(*a, **k)
            barrier.wait()
            return plan

        monkeypatch.setattr(R, "plan_run", planned)

        def start(i: int) -> None:
            with Session(engine) as s:
                settings = get_or_create_settings(s, 1)
                s.commit()
                try:
                    R.queue_run(s, 1, uid, RunCreate(include=Include(servers=True), client_request_id=f"pg-race-{i:04d}"),
                                settings, utcnow())
                    s.commit()
                    out.append(201)
                except HTTPException as exc:
                    s.rollback()
                    out.append(exc.status_code)

        threads = [threading.Thread(target=start, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        assert sorted(out) == [201] + [409] * 49, out
        with Session(engine) as s:
            assert s.exec(select(func.count()).select_from(CbomCollectionJob)).one() == 1
            assert round(s.get(Team, 1).credit_balance, 2) == 999.2  # four hosts, charged once
        reconciled(engine)
    finally:
        SQLModel.metadata.drop_all(engine)
        engine.dispose()


# ============================================================================ runtime skips (OA-10b)
def test_r2_two_of_four_targets_skipped_by_the_window_refund_half(api, world):  # noqa: F811
    engine, _ids = world
    before = balance(engine)
    _src, run, claim, hdr = started(api, engine)
    assert balance(engine) == round(before - 0.8, 2)
    r = finish(api, claim, hdr, [{"target": "10.20.0.1", "status": "ok"}, {"target": "10.20.0.2", "status": "ok"},
                                 {"target": "10.20.0.3", "status": "skipped_window"},
                                 {"target": "10.20.0.4", "status": "skipped_window"}])
    assert r.status_code == 200, r.text
    assert balance(engine) == round(before - 0.4, 2)  # before the fix: 0.8 charged, 0 refunded
    got = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert got["credits"] == {"charged": 0.8, "refunded": 0.4, "net": 0.4}
    (job,) = got["jobs"]
    assert job["credits_refunded"] == 0.4 and job["outcome"] == "partial"
    (entry,) = ledger(engine, kind="refund")
    assert entry.amount_c == 40 and entry.reason == "runtime_skips" and entry.job_id == claim["job"]["id"]
    reconciled(engine)


def test_contacted_targets_are_charged_and_refused_credentials_are_not(api, world):  # noqa: F811
    """Charge for what was contacted: unreachable and timed-out hosts were contacted; a refused credential, a
    never-scan entry and a stop were not read at all."""
    engine, _ids = world
    before = balance(engine)
    _src, _run, claim, hdr = started(api, engine)
    finish(api, claim, hdr, [{"target": "10.20.0.1", "status": "ok"}, {"target": "10.20.0.2", "status": "unreachable"},
                             {"target": "10.20.0.3", "status": "auth_failed"},
                             {"target": "10.20.0.4", "status": "skipped_never_scan"}])
    assert balance(engine) == round(before - 0.4, 2)  # 2 of 4 refunded: auth_failed + never-scan
    reconciled(engine)


@pytest.mark.parametrize("rows,weight,expected", [
    ([("ok", 2), ("skipped_window", 2)], 80, 40),
    ([("ok", 1), ("skipped_deadline", 2)], 100, 66),  # pro rata, rounded down: never more than due
    ([("ok", 254), ("skipped_stop", 2)], 100, 0),  # network range: 2 of 256 addresses of one /24 block = 0.78 -> 0
    ([("ok", 128), ("skipped_stop", 128)], 100, 50),
    ([("skipped_window", 3)], 60, 60),
    ([("ok", 3)], 60, 0),
    ([("ok", 1), ("timeout", 1), ("refused", 1), ("error", 1)], 80, 0),
    ([("ok", 2), ("skipped_cap", 1), ("skipped_cancelled", 1), ("winrm_denied", 1), ("mfa_required", 1)], 120, 60),
])
def test_runtime_refund_is_pro_rata_over_the_skipped_targets(rows, weight, expected):
    targets = [{"target": f"t{i}-{n}", "status": status} for i, (status, count) in enumerate(rows) for n in range(count)]
    total = len(targets)
    assert runtime_refund_c(weight, {"counts": {"total": total}, "targets": targets}) == expected


def test_runtime_refund_reads_the_rows_a_node_folded_into_its_summary_row():
    targets = [{"target": f"10.0.{i // 256}.{i % 256}", "status": "ok"} for i in range(1000)]
    targets.append({"target": "+1048 more", "status": "summary", "error": '{"skipped_window": 1000, "ok": 48}'})
    assert runtime_refund_c(800, {"counts": {"total": 2048, "ok": 1048, "skipped": 1000}, "targets": targets}) == 390


def test_an_all_skipped_job_is_nothing_read_and_refunded_in_full(api, world):  # noqa: F811
    engine, _ids = world
    before = balance(engine)
    _src, run, claim, hdr = started(api, engine)
    finish(api, claim, hdr, [{"target": t, "status": "skipped_window"} for t in FOUR])
    got = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert got["jobs"][0]["outcome"] == "failed" and got["credits"]["net"] == 0  # "Nothing read"
    assert balance(engine) == before
    assert [e.reason for e in ledger(engine, kind="refund")] == ["nothing_read"]
    reconciled(engine)


# ============================================================================ refunds move credits once
def test_a_retried_result_and_a_second_refund_never_give_credits_back_twice(api, world):  # noqa: F811
    engine, _ids = world
    before = balance(engine)
    _src, _run, claim, hdr = started(api, engine)
    rows = [{"target": "10.20.0.1", "status": "ok"}, {"target": "10.20.0.2", "status": "skipped_stop"},
            {"target": "10.20.0.3", "status": "ok"}, {"target": "10.20.0.4", "status": "ok"}]
    assert finish(api, claim, hdr, rows).status_code == 200
    assert finish(api, claim, hdr, rows, post_assets=False).status_code == 409  # the node retried its POST
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, claim["job"]["id"])
        assert J.refund_job(s, job, J._run_of(s, job)) == 0
        s.commit()
    assert balance(engine) == round(before - 0.6, 2)
    reconciled(engine)


def test_two_transactions_refunding_one_job_at_once_refund_it_once(api, world):  # noqa: F811
    """The node's cancelled result and the reaper (or two cancels) both load the job before either commits."""
    engine, _ids = world
    before = balance(engine)
    node_id = enroll_node(api)[0]
    api("POST", "/1/cbom/sources/items", json=servers(node_id=node_id))
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "twice-0001"})
    run_id = run.json()["run"]["id"]
    with Session(engine) as s:
        job_id = s.exec(select(CbomCollectionJob.id).where(CbomCollectionJob.run_id == run_id)).one()
    barrier = threading.Barrier(2, timeout=30)
    got: list[int] = []

    def refund() -> None:
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, job_id)
            run_row = s.get(CbomCollectionRun, run_id)
            barrier.wait()  # both have read refunded=False
            got.append(J.refund_job(s, job, run_row))
            s.commit()

    threads = [threading.Thread(target=refund) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(got) == [0, 80], got  # before the fix: [80, 80] and 1.6 back for a 0.8 charge
    assert balance(engine) == before
    reconciled(engine)


# ============================================================================ Stop all
def test_stop_all_cancels_a_running_range_refunds_it_in_full_and_keeps_what_it_read(api, world):  # noqa: F811
    engine, _ids = world
    before = balance(engine)
    node_id, token = enroll_node(api)[:2]
    assert api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[True] * 24] * 7}).status_code == 200
    r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "dc-range", "node_id": node_id,
                                                  "config": {"cidr": "10.20.0.0/24", "mode": "full"}})
    assert r.status_code == 201, r.text
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True}, "client_request_id": "stop-all-001",
                                                    "soc_ack": True})
    assert run.status_code == 201, run.text
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200, claim.text
    claim = claim.json()
    read = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/assets", None, headers=hdr, json={
        "lease_id": claim["job"]["lease_id"], "assets": [{"type": "tls_endpoint", "target": "10.20.0.1",
                                                          "location": "10.20.0.1:443", "facts": {"protocols": ["TLSv1.2"]}}]})
    assert read.status_code == 200, read.text
    api("POST", "/1/cbom/sources/settings/stop-all", json={"on": True})
    done = finish(api, claim, hdr, [{"target": "10.20.0.1", "status": "ok"}] +
                  [{"target": f"10.20.0.{i}", "status": "skipped_stop"} for i in range(2, 255)], post_assets=False)
    assert done.status_code == 200 and done.json()["status"] == "cancelled"
    assert balance(engine) == before  # cancelled = refunded in full
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, claim["job"]["id"])
        assert job.refunded_c == job.weight_c and "stop" in (job.error or "").lower()
        assert s.exec(select(func.count()).select_from(CbomCollectedAsset).where(
            CbomCollectedAsset.job_id == job.id)).one() >= 1  # what it read before the stop is kept
    assert [e.reason for e in ledger(engine, kind="refund")] == ["cancelled"]
    reconciled(engine)


# ============================================================================ per-node concurrency
def test_a_node_never_holds_more_claimed_jobs_than_its_cap_even_with_concurrent_claims(api, world, monkeypatch):  # noqa: F811
    engine, _ids = world
    monkeypatch.setenv("CBOM_NODE_MAX_CONCURRENCY", "2")
    node_id, token = enroll_node(api)[:2]
    for i in range(4):
        api("POST", "/1/cbom/sources/items", json=servers(name=f"hosts-{i}", node_id=node_id, targets=[f"10.40.0.{i + 1}"]))
    assert api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                     "client_request_id": "cap-run-0001"}).status_code == 201
    hdr = {"X-ZS-Node-Token": token}
    codes: list[int] = []
    lock = threading.Lock()

    def claim() -> None:
        from fastapi.testclient import TestClient
        from backend.main import app
        r = TestClient(app).post("/cbom/node/jobs/claim", headers=hdr)
        with lock:
            codes.append(r.status_code)

    threads = [threading.Thread(target=claim) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    with Session(engine) as s:
        claimed = s.exec(select(func.count()).select_from(CbomCollectionJob).where(
            CbomCollectionJob.node_id == node_id, CbomCollectionJob.status == "claimed")).one()
    assert claimed == 2 and sorted(codes).count(200) == 2, codes  # before the fix: 4 claimed
    assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 204


def test_the_node_cap_never_blocks_a_connection_test_behind_long_collections(api, world, monkeypatch):  # noqa: F811
    engine, _ids = world
    monkeypatch.setenv("CBOM_NODE_MAX_CONCURRENCY", "1")
    _src, _run, _claim, hdr = started(api, engine)
    src2 = api("POST", "/1/cbom/sources/items", json=servers(name="second", node_id=_src["node_id"],
                                                             targets=["10.50.0.1"])).json()["source"]
    api("POST", f"/1/cbom/sources/items/{src2['id']}/test")
    # the cap counts collections and discoveries; a connection test (minutes, a customer waiting on it) still runs
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200 and claim.json()["job"]["kind"] == "test_connection"


# ============================================================================ migration
def _migration():
    path = next(VERSIONS.glob("cb14credit001_*.py"))
    spec = importlib.util.spec_from_file_location("m_cb14", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_the_migration_is_the_one_head():
    import re
    mod = _migration()
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*(.*)$", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.update(re.findall(r"['\"]([^'\"]+)['\"]", down.group(1)))
    assert mod.down_revision in revisions
    assert len(revisions - parents) == 1 and ("cb14credit001" in parents or revisions - parents == {"cb14credit001"})


def test_the_migration_settles_duplicate_open_jobs_backfills_the_ledger_and_round_trips(tmp_path):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")

    def step(name: str) -> None:
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), name)()

    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE team (id integer PRIMARY KEY, credit_balance float)"))
        conn.execute(sa.text("CREATE TABLE cbomcollectionrun (id integer PRIMARY KEY, team_id integer, "
                             "credits_charged_c integer, credits_refunded_c integer)"))
        conn.execute(sa.text("CREATE TABLE cbomcollectionjob (id integer PRIMARY KEY, team_id integer, run_id integer, "
                             "source_id integer, kind varchar(16), status varchar(16), weight_c integer, "
                             "refunded boolean, finished_at datetime, error varchar(1024), lease_id varchar(32), "
                             "lease_expires_at datetime)"))
        conn.execute(sa.text("INSERT INTO team VALUES (1, 10.0)"))
        conn.execute(sa.text("INSERT INTO cbomcollectionrun VALUES (1, 1, 80, 20), (2, 1, 80, 0)"))
        conn.execute(sa.text(
            "INSERT INTO cbomcollectionjob (id, team_id, run_id, source_id, kind, status, weight_c, refunded) VALUES "
            "(1, 1, 1, 7, 'collect', 'success', 60, 0), (2, 1, 1, 8, 'collect', 'cancelled', 20, 1), "
            "(3, 1, 1, 9, 'collect', 'claimed', 0, 0), "
            "(4, 1, 2, 9, 'collect', 'pending', 80, 0)"))  # job 4 duplicates job 3's open source 9
    step("upgrade")
    with engine.begin() as conn:
        rows = {r[0]: r[1:] for r in conn.execute(sa.text(
            "SELECT id, status, refunded, refunded_c FROM cbomcollectionjob ORDER BY id"))}
        assert rows[3][0] == "claimed" and rows[4][0] == "cancelled" and rows[4][2] == 80  # the newer one settled
        assert rows[2][2] == 20  # an earlier refund backfilled
        assert conn.execute(sa.text("SELECT credit_balance FROM team")).scalar() == pytest.approx(10.8)
        assert conn.execute(sa.text("SELECT credits_refunded_c FROM cbomcollectionrun WHERE id = 2")).scalar() == 80
        entries = conn.execute(sa.text("SELECT run_id, job_id, kind, amount_c FROM cbomcreditentry ORDER BY id")).all()
        key = lambda e: (e[0], e[1] or 0, e[2])  # noqa: E731
        assert sorted(map(tuple, entries), key=key) == sorted([(1, None, "charge", 80), (2, None, "charge", 80),
                                                               (1, 2, "refund", 20), (2, 4, "refund", 80)], key=key)
        with pytest.raises(sa.exc.IntegrityError):  # a second open collection of source 9
            with conn.begin_nested():
                conn.execute(sa.text("INSERT INTO cbomcollectionjob (id, team_id, run_id, source_id, kind, status, "
                                     "weight_c, refunded, refunded_c) VALUES (5, 1, 2, 9, 'collect', 'pending', 0, 0, 0)"))
        conn.execute(sa.text("INSERT INTO cbomcollectionjob (id, team_id, run_id, source_id, kind, status, weight_c, "
                             "refunded, refunded_c) VALUES (6, 1, 2, 9, 'test_connection', 'pending', 0, 0, 0)"))
    step("downgrade")
    assert "cbomcreditentry" not in sa.inspect(engine).get_table_names()
    step("upgrade")
    assert "uq_cbomcollectionjob_open_collect" in {i["name"] for i in sa.inspect(engine).get_indexes("cbomcollectionjob")}
    engine.dispose()


def test_the_alembic_env_sees_the_ledger_table():
    text = (REPO / "prod_database_migrations" / "migrations" / "env.py").read_text()
    assert "backend.utilities.cbom_sources.billing" in text
