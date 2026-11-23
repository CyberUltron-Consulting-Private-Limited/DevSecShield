"""#480 review 6028153035 on PostgreSQL: overlapping reaper passes (m4), the node-offline rule's guards (m1) and the
restart bookkeeping (M1) under real row locks.  Needs ``CBOM_TEST_PG_URL`` (CI sets it); skipped otherwise.  Each
test runs in a schema of its own, dropped afterwards.

m4 is older than #480: on dev, 8 overlapping ``reap`` + ``settle_refunds`` passes over one expiring job deadlocked in
1 to 4 threads per round (the review's R9, same with the queue-TTL rule).  The end state was right; the errors were
not.  One reaper pass at a time (a transaction-scoped advisory lock) ends them.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
import threading
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import func
from sqlmodel import Session, SQLModel, create_engine, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backend.new_models import (  # noqa: E402
    CbomCollectionAuditEvent,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomOpsCounter,
    CbomScanNode,
    Scan,
    Team,
    TeamMembership,
    User,
)
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from test_cbom_sources_api import USERS, api, enroll_node, linux_body  # noqa: E402,F401

PG = os.environ.get("CBOM_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG, reason="CBOM_TEST_PG_URL not set")
THREADS = 8


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


@pytest.fixture()
def world(monkeypatch):
    from backend.routers import auth as auth_router
    from backend.routers import cbom_node, cbom_node_sshca, cbom_vendor_public
    from backend.utilities.cbom_sources import dispatch as _dispatch
    from backend.utilities.cbom_sources import http as cbom_http
    from backend.utilities.cbom_sources import node_auth
    from backend.utilities.db.encryption import _get_fernet

    _get_fernet.cache_clear()
    schema = f"fixb3_{uuid.uuid4().hex[:12]}"
    admin = create_engine(PG)
    with admin.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(PG, connect_args={"options": f"-csearch_path={schema}"}, pool_size=THREADS + 4,
                           max_overflow=4)
    SQLModel.metadata.create_all(engine)
    ids = {}
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=100.0))
        s.add(Team(id=2, name="Bank Two", credit_balance=0.5))
        s.commit()
        for who, (email, team, role) in USERS.items():
            user = User(email=email, password="x", first_name=who, last_name="t", profile_photo=None,
                        session_active=True, default_team_id=team)
            s.add(user)
            s.commit()
            s.refresh(user)
            ids[who] = user.id
            s.add(TeamMembership(team_id=team, user_id=user.id, role=role))
        s.add(Scan(id=77, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="code", scan_status="NOT_STARTED"))
        s.commit()
    for module in (cbom_http, cbom_node, cbom_node_sshca, cbom_vendor_public, node_auth, auth_router):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter,
                    cbom_http.enroll_limiter, cbom_http.vendor_limiter):
        limiter.requests.clear()
    _dispatch.reset(None)
    try:
        yield engine, ids
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


def _queue(api, engine, rid):  # noqa: F811
    node_id, token, _ = enroll_node(api, name="cbom-lab-2-worker")
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, window="any")).json()["source"]
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": rid})
    assert r.status_code == 201, r.text
    run = r.json()["run"]
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run["id"])).one()
    return node_id, token, src, run, job.id


def _age(engine, job_id, node_id, *, queued_ago, seen_ago):
    now = _now()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.created_at = now - queued_ago
        s.add(job)
        node = s.get(CbomScanNode, node_id)
        node.last_heartbeat_at = now - seen_ago
        s.add(node)
        # the reaper has been passing every 30 s for a month: the backend served throughout
        s.merge(CbomOpsCounter(name=J.SERVING_MARK, value=int((now - dt.timedelta(days=30)
                                                                - dt.datetime(1970, 1, 1)).total_seconds()),
                               updated_at=now - dt.timedelta(seconds=30)))
        s.commit()


def _pass(engine) -> int:
    """One reaper pass as ``cbom_cloud_worker.reap_all`` does it: reap + commit, then settle + commit."""
    with Session(engine) as s:
        moved = J.reap(s, _now(), commit_every=J.REAP_COMMIT_EVERY)
        s.commit()
    with Session(engine) as s:
        J.settle_refunds(s)
        s.commit()
    return moved


def _race(fn, n=THREADS) -> list[str]:
    barrier, errors = threading.Barrier(n), []

    def one():
        try:
            barrier.wait()
            fn()
        except Exception as exc:  # pragma: no cover - what the test counts
            errors.append("deadlock" if "deadlock" in str(exc).lower() else f"{type(exc).__name__}: {str(exc)[:120]}")

    threads = [threading.Thread(target=one) for _ in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return errors


@pytest.mark.parametrize("rule", ["queue_ttl", "node_offline"])
@pytest.mark.parametrize("rnd", range(3))
def test_m4_overlapping_reaper_passes_never_deadlock_and_refund_once(api, world, rule, rnd):  # noqa: F811
    engine, _ = world
    node_id, _token, _src, run, job_id = _queue(api, engine, f"fixb3-pg-{rule}-{rnd}"[:24])
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    if rule == "queue_ttl":
        _age(engine, job_id, node_id, queued_ago=dt.timedelta(days=8), seen_ago=dt.timedelta(seconds=5))
    else:
        _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    moved: list[int] = []
    errors = _race(lambda: moved.append(_pass(engine)))
    _pass(engine)  # a later pass settles whatever a skipped settle left
    with Session(engine) as s:
        audits = s.exec(select(func.count()).select_from(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.action == "job.expired", CbomCollectionAuditEvent.object_id == job_id)).one()
        job, run_row, team = s.get(CbomCollectionJob, job_id), s.get(CbomCollectionRun, run["id"]), s.get(Team, 1)
        print(f"m4[{rule}#{rnd}] moved={sorted(moved)} errors={errors} audits={audits} job={job.status} "
              f"run={run_row.status} balance {before} -> {team.credit_balance}")
        assert errors == []
        assert audits == 1 and job.status == "expired" and job.refunded is True
        assert run_row.status == "failed" and run_row.credits_refunded_c == run_row.credits_charged_c
        assert round(team.credit_balance, 2) == round(before + run_row.credits_charged_c / 100, 2)


def test_m4_a_pass_that_finds_the_lock_taken_does_nothing(world):
    engine, _ = world
    with Session(engine) as holder, Session(engine) as other:
        assert J.reaper_lock(holder) is True
        assert J.reaper_lock(other) is False
        assert J.reap(other, _now()) == 0
        assert J.settle_refunds(other) == {"runs": 0, "jobs": 0, "centi": 0}
        other.rollback()
        holder.rollback()  # the end of the transaction releases it
    with Session(engine) as s:
        assert J.reaper_lock(s) is True
        s.rollback()


def test_m1_a_heartbeat_committed_before_the_update_saves_the_job_on_postgres(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    node_id, _token, _src, run, job_id = _queue(api, engine, "fixb3-pg-toctou-001")
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    real = J._expire_open

    def heartbeat_then_expire(*a, **k):
        with Session(engine) as other:
            other.exec(sa.update(CbomScanNode).where(CbomScanNode.id == node_id)  # type: ignore[call-overload]
                       .values(last_heartbeat_at=_now()))
            other.commit()
        return real(*a, **k)

    monkeypatch.setattr(J, "_expire_open", heartbeat_then_expire)
    with Session(engine) as s:
        J.reap(s, _now())
        s.commit()
    with Session(engine) as s:
        assert s.get(CbomCollectionJob, job_id).status == "pending"
        assert s.get(CbomCollectionRun, run["id"]).status == "queued"


def test_m1_concurrent_passes_after_a_long_outage_keep_live_nodes_jobs(api, world):  # noqa: F811
    """M1 under the lock: 8 overlapping first passes after a 6 h 5 min outage expire nothing, and they all agree on
    when the backend started serving again."""
    engine, _ = world
    node_id, _token, _src, _run, job_id = _queue(api, engine, "fixb3-pg-outage-001")
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=6, minutes=10),
         seen_ago=dt.timedelta(hours=6, minutes=5))
    with Session(engine) as s:  # the outage: the last pass was 6 h 5 min ago
        mark = s.get(CbomOpsCounter, J.SERVING_MARK)
        mark.updated_at = _now() - dt.timedelta(hours=6, minutes=5)
        s.add(mark)
        s.commit()
    restart = _now()
    errors = _race(lambda: _pass(engine))
    with Session(engine) as s:
        mark = s.get(CbomOpsCounter, J.SERVING_MARK)
        since = dt.datetime(1970, 1, 1) + dt.timedelta(seconds=int(mark.value))
        assert errors == [] and s.get(CbomCollectionJob, job_id).status == "pending"
        assert restart - dt.timedelta(seconds=1) <= since <= _now()
