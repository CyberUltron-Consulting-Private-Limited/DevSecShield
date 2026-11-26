"""F1 cloud collection at scale: one slice job per AWS account x region on a pool of cloud workers.

Runs on SQLite (file database) and, when CBOM_TEST_PG_URL is set (CI sets it), on PostgreSQL too: claim
exclusivity with 8 concurrent workers, fair share across teams, lease expiry after a SIGKILLed worker, SIGTERM
releasing a lease, idempotent result ingest, cancel, and the organisation walk past 200 accounts (moto) with
throttling backoff.

    cd backend && PYTHONPATH=.. uv run --with pytest --with moto python -m pytest tests/test_cbom_cloud_pool_f1.py -q
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "cbom-cloud-pool-test-secret-0123456789abcdef")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-cloud-pool-test-refresh-0123456789abcdef")

from fastapi import HTTPException  # noqa: E402
from sqlalchemy import event, func  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    Team,
    User,
)
from backend.utilities.cbom_sources import aws_collect as AC  # noqa: E402
from backend.utilities.cbom_sources import aws_org  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import slices as S  # noqa: E402
from backend.utilities.cbom_sources.common import utcnow  # noqa: E402
from backend.utilities.cbom_sources.runs import queue_run  # noqa: E402
from backend.utilities.cbom_sources.schemas import Include, RunCreate  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402
from backend.workers import cbom_cloud_worker as W  # noqa: E402

from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402  (review 6065677758 n1)
PG = cbom_test_pg_url()  # a database named *test* only
BACKENDS = ["sqlite"] + (["pg"] if PG else [])
MGMT = "111122223333"


# ----------------------------------------------------------------------------- world
def _make_engine(kind: str, tmp_path: Path):
    if kind == "pg":
        engine = create_engine(PG, pool_size=40, max_overflow=20)
        SQLModel.metadata.drop_all(engine)
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'pool.db'}", connect_args={"check_same_thread": False,
                                                                                  "timeout": 60})

        @event.listens_for(engine, "connect")
        def _fk(dbapi_conn, _record):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
    SQLModel.metadata.create_all(engine)
    return engine


def _url(engine) -> str:
    return engine.url.render_as_string(hide_password=False)


@pytest.fixture(params=BACKENDS)
def engine(request, tmp_path, monkeypatch):
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", "8")
    monkeypatch.setattr(W, "IDLE_SLEEP_S", 0.05)
    W._stop.clear()
    W._release.clear()
    aws_org.clear_cache()
    eng = _make_engine(request.param, tmp_path)
    eng.kind = request.param  # type: ignore[attr-defined]
    yield eng
    W._stop.clear()
    W._release.clear()
    if request.param == "pg":
        SQLModel.metadata.drop_all(eng)
    eng.dispose()


def _team(engine, team_id: int, credits: float = 100_000.0) -> int:
    with Session(engine) as s:
        s.add(Team(id=team_id, name=f"Team {team_id}", credit_balance=credits))
        s.commit()
        user = User(email=f"owner{team_id}@pool.test", password="x", first_name="o", last_name="t", profile_photo=None,
                    default_team_id=team_id)
        s.add(user)
        s.commit()
        get_or_create_settings(s, team_id)
        s.commit()
        return int(user.id)


def _source(engine, team_id: int, *, accounts: int = 1, regions=("us-east-1",), name="aws") -> int:
    scope = "organization" if accounts > 1 else "account"
    with Session(engine) as s:
        src = CbomCollectionSource(
            team_id=team_id, owner_user_id=1, kind="aws_account", name=name, name_lower=name.lower(),
            config={"scope": scope, "role_arn": f"arn:aws:iam::{MGMT}:role/ZeroShieldCBOMReader",
                    "regions": list(regions)},
            last_test_status="passed", last_test_result={"member_accounts": accounts} if accounts > 1 else {})
        s.add(src)
        s.commit()
        return int(src.id)


def _queue(engine, team_id: int, user_id: int, rid: str) -> int:
    with Session(engine) as s:
        settings = get_or_create_settings(s, team_id)
        run, _ = queue_run(s, team_id, user_id, RunCreate(include=Include(cloud=True), client_request_id=rid),
                           settings, utcnow())
        s.commit()
        return int(run.id)


def _plan(accounts: int):
    """aws_org.plan_slices without AWS: ``accounts`` accounts (the first is the management account)."""
    def plan(team_id, cfg, external_id, emit, should_stop):
        ids = [MGMT] + [f"{200000000000 + i}" for i in range(accounts - 1)]
        role = cfg["role_arn"].split(":role/")[1]
        return {"targets": [], "accounts": accounts,
                "slices": [{"account_id": a, "role_arn": f"arn:aws:iam::{a}:role/{role}", "region": r}
                           for a in ids for r in ["global", *cfg["regions"]]]}
    return plan


def _asset(acct: str, region: str) -> dict:
    arn = f"arn:aws:kms:{region}:{acct}:key/k1"
    return {"type": "kms_key", "target": f"aws:{acct}", "location": arn, "name": "k1", "algorithm": "SYMMETRIC_DEFAULT",
            "key_size": 256, "facts": {"key_spec": "SYMMETRIC_DEFAULT", "identity": arn}}


def _collector(delay: float = 0.0, seen: list | None = None, lock: threading.Lock | None = None):
    """aws_org.collect_slice without AWS: one KMS key per account x region."""
    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop, **_kw):
        acct = role_arn.split(":")[4]
        if seen is not None:
            with lock:  # type: ignore[union-attr]
                seen.append((team_id, acct, region, threading.current_thread().name))
        if delay:
            time.sleep(delay)
        emit(_asset(acct, region))
        return AC.summary([{"target": f"aws:{acct}/{region}", "status": "ok", "assets": 1}], team_id,
                          time.monotonic(), quiet=True)
    return collect


def _drain(engine, worker="t-worker", limit=100_000) -> int:
    n = 0
    while n < limit and W.run_once(engine, worker):
        n += 1
    return n


def _jobs(engine, **where):
    with Session(engine) as s:
        q = select(CbomCollectionJob)
        for key, value in where.items():
            q = q.where(getattr(CbomCollectionJob, key) == value)
        return s.exec(q.order_by(CbomCollectionJob.id)).all()


# ----------------------------------------------------------------------------- fan-out keeps one job per source
def test_aws_source_fans_out_into_account_region_slices_and_the_run_keeps_one_job(engine, monkeypatch, capsys):
    monkeypatch.setattr(aws_org, "plan_slices", _plan(5))
    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    user = _team(engine, 1, credits=100.0)
    _source(engine, 1, accounts=5, regions=("us-east-1", "eu-west-1"))
    run_id = _queue(engine, 1, user, "fanout-run-0001")
    with Session(engine) as s:
        assert s.get(Team, 1).credit_balance == pytest.approx(80.0)  # 5 accounts x 4 credits, charged as before
    assert _drain(engine) == 1 + 15  # the parent (fan-out) then 5 accounts x (global + 2 regions)
    parent = _jobs(engine, kind="collect")
    slices = _jobs(engine, kind="slice")
    assert len(parent) == 1 and len(slices) == 15
    parent = parent[0]
    assert parent.status == "success" and parent.outcome == "ok" and parent.asset_count == 15 and not parent.refunded
    assert all(j.status == "success" and j.run_id is None and j.parent_job_id == parent.id and j.weight_c == 0
               for j in slices)
    assert parent.result["counts"] == {"total": 15, "ok": 15, "partial": 0, "failed": 0, "skipped": 0}
    assert parent.result["slices"] == {"done": 15, "total": 15} and parent.result["fanout"]["by_status"] == {"success": 15}
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        assert run.status == "done" and run.credits_refunded_c == 0
        rows = s.exec(select(CbomCollectedAsset)).all()
        assert {r.job_id for r in rows} == {parent.id} and {r.attempt for r in rows} == {1} and len(rows) == 15
        assert {r.run_id for r in rows} == {run_id}
        assert s.get(Team, 1).credit_balance == pytest.approx(80.0)
    # drift / posture read the run's collect jobs: still exactly one per source
    from backend.utilities.cbom_sources.drift import _run_jobs, job_comparable

    with Session(engine) as s:
        run_jobs = _run_jobs(s, s.get(CbomCollectionRun, run_id))
        assert [j.id for j in run_jobs] == [parent.id] and job_comparable(run_jobs[0]) == (True, None)
    out = capsys.readouterr().out
    assert "cbom sources cloud fan-out" in out and f"job={parent.id} slices=15" in out
    finish = [line for line in out.splitlines() if "cbom sources cloud finish" in line and "job_kind=slice" in line]
    assert len(finish) == 15 and all(k in finish[0] for k in ("team=1", "account=", "region=", "ms=", "outcome=ok"))
    claim = [line for line in out.splitlines() if "cbom sources cloud claim" in line and "job_kind=slice" in line]
    assert len(claim) == 15 and "region=global" in claim[0] and f"account={MGMT}" in claim[0]


def test_serial_walk_stays_available_behind_the_switch(engine, monkeypatch):
    monkeypatch.setenv("CBOM_AWS_SLICES", "0")
    calls = []

    def serial(team_id, cfg, external_id, emit, should_stop):
        calls.append(cfg["scope"])
        emit(_asset(MGMT, "us-east-1"))
        return AC.summary([{"target": f"aws:{MGMT}/us-east-1", "status": "ok"}], team_id, time.monotonic(), quiet=True)

    monkeypatch.setattr(AC, "collect_aws", serial)
    user = _team(engine, 1)
    _source(engine, 1)
    _queue(engine, 1, user, "serial-run-001")
    assert _drain(engine) == 1 and calls == ["account"]
    assert _jobs(engine, kind="slice") == [] and _jobs(engine, kind="collect")[0].status == "success"


# ----------------------------------------------------------------------------- claim exclusivity, 8 workers
def test_eight_concurrent_workers_never_claim_the_same_slice(engine, monkeypatch):
    seen: list = []
    lock = threading.Lock()
    monkeypatch.setattr(aws_org, "plan_slices", lambda team_id, cfg, *a: _plan(100 if team_id == 1 else 20)(team_id, cfg, *a))
    monkeypatch.setattr(aws_org, "collect_slice", _collector(0.002, seen, lock))
    claims: list = []
    real_claim = J.claim_cloud_job

    def recording(session, now, worker, **kw):
        payload = real_claim(session, now, worker, **kw)
        if payload is not None:
            with lock:
                claims.append((payload["job"]["id"], payload["job"]["attempt"], worker))
        return payload

    monkeypatch.setattr(J, "claim_cloud_job", recording)
    for team in (1, 2):
        user = _team(engine, team)
        _source(engine, team, accounts=100 if team == 1 else 20, regions=("us-east-1", "eu-west-1"))
        _queue(engine, team, user, f"excl-run-{team:04d}")
    threads = [threading.Thread(target=W.worker_loop, args=(engine, f"w{i}"), name=f"w{i}") for i in range(8)]
    started = time.monotonic()
    for t in threads:
        t.start()
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if all(j.status in J.TERMINAL for j in _jobs(engine, kind="collect")):
            break
        time.sleep(0.2)
    W._stop.set()
    for t in threads:
        t.join(30)
    elapsed = time.monotonic() - started
    slices = _jobs(engine, kind="slice")
    assert len(slices) == 300 + 60
    ids = [c[0] for c in claims]
    assert len(ids) == len(set(ids)) == 362, "a job was claimed twice"  # 2 parents + 360 slices
    assert len({c[2] for c in claims}) == 8  # every worker took part
    assert all(j.status == "success" and j.attempts == 1 for j in slices)
    assert len(seen) == 360 and len({(t, a, r) for t, a, r, _w in seen}) == 360  # each slice collected exactly once
    parents = _jobs(engine, kind="collect")
    assert [p.status for p in parents] == ["success", "success"] and [p.asset_count for p in parents] == [300, 60]
    print(f"[{engine.kind}] 8 workers, 362 jobs in {elapsed:.1f}s")


# ----------------------------------------------------------------------------- fair share
def test_fair_share_a_thousand_slices_do_not_starve_another_teams_single_job(engine, monkeypatch):
    lease_s = 30
    monkeypatch.setenv("CBOM_CLOUD_LEASE_S", str(lease_s))
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", "3")
    running_peak = {1: 0, 2: 0}
    lock = threading.Lock()
    seen: list = []
    base = _collector(0.01, seen, lock)

    def collect(team_id, *a, **kw):
        with Session(engine) as s:  # how many jobs this team runs right now, every worker counted
            now_running = J._cloud_running(s).get(team_id, 0)
        with lock:
            running_peak[team_id] = max(running_peak[team_id], now_running)
        return base(team_id, *a, **kw)

    monkeypatch.setattr(aws_org, "plan_slices", lambda team_id, cfg, *a: _plan(250 if team_id == 1 else 1)(team_id, cfg, *a))
    monkeypatch.setattr(aws_org, "collect_slice", collect)
    user_a, user_b = _team(engine, 1), _team(engine, 2)
    _source(engine, 1, accounts=250, regions=("us-east-1", "eu-west-1", "ap-south-1"))  # 1,000 slices
    _source(engine, 2, accounts=1, regions=("us-east-1",))
    _queue(engine, 1, user_a, "fair-run-a001")
    threads = [threading.Thread(target=W.worker_loop, args=(engine, f"f{i}")) for i in range(4)]
    for t in threads:
        t.start()
    while len(seen) < 30:  # tenant A's slices are flowing through the pool
        time.sleep(0.05)
    b_run = _queue(engine, 2, user_b, "fair-run-b001")
    queued_at = time.monotonic()
    b_done_at = None
    while time.monotonic() - queued_at < 120:
        with Session(engine) as s:
            if s.get(CbomCollectionRun, b_run).status == "done":
                b_done_at = time.monotonic()
                a_left = s.exec(select(func.count()).select_from(CbomCollectionJob).where(
                    CbomCollectionJob.team_id == 1, CbomCollectionJob.kind == "slice",
                    CbomCollectionJob.status == "pending")).one()
                break
        time.sleep(0.05)
    W._stop.set()
    for t in threads:
        t.join(30)
    assert b_done_at is not None, "tenant B's run never finished"
    waited = b_done_at - queued_at
    assert waited < lease_s, f"tenant B waited {waited:.1f}s, more than one lease interval"
    assert a_left > 500, "B only ran after A drained: no fair share"
    print(f"[{engine.kind}] tenant B's run finished {waited:.2f}s after it was queued; {a_left} of A's 1,000 still pending")


# ----------------------------------------------------------------------------- a killed worker
_CHILD = textwrap.dedent("""
    import os, sys, time
    sys.path.insert(0, {root!r})
    from sqlalchemy import event
    from sqlmodel import create_engine
    from backend.utilities.cbom_sources import aws_org
    from backend.workers import cbom_cloud_worker as W

    url = sys.argv[1]
    mode = sys.argv[2]
    kw = {{"connect_args": {{"check_same_thread": False, "timeout": 60}}}} if url.startswith("sqlite") else {{}}
    engine = create_engine(url, **kw)

    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop, **_kw):
        acct = role_arn.split(":")[4]
        arn = f"arn:aws:kms:{{region}}:{{acct}}:key/k1"
        emit({{"type": "kms_key", "target": f"aws:{{acct}}", "location": arn, "name": "k1",
              "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256, "facts": {{"identity": arn}}}})
        print("CLAIMED", flush=True)
        if mode == "hang":  # one slow AWS call that never returns: only the heartbeat keeps the lease
            should_stop.__self__.flush()
            print("FLUSHED", flush=True)
            time.sleep(3600)
        while not should_stop():  # a collector that checks its stop flag
            time.sleep(0.1)
        return {{"targets": [], "counts": {{}}}}

    aws_org.collect_slice = collect
    if mode == "hang":
        W.run_once(engine, "child")
    else:
        W.get_db = lambda: engine
        sys.argv = ["cbom_cloud_worker", "--workers", "2"]
        W.main()
""")


def _child(engine, tmp_path: Path, mode: str, **env) -> subprocess.Popen:
    script = tmp_path / f"child_{mode}.py"
    script.write_text(_CHILD.format(root=str(_REPO_ROOT)))
    return subprocess.Popen([sys.executable, str(script), _url(engine), mode], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            env={**os.environ, "PYTHONPATH": str(_REPO_ROOT), "CBOM_SCHEDULER": "0",
                                 "INTEGRATION_DISPATCHER": "0", **env})


def _wait_line(proc: subprocess.Popen, text: str, timeout: float = 60) -> list[str]:
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()  # type: ignore[union-attr]
        if not line:
            break
        lines.append(line.rstrip())
        if text in line:
            return lines
    raise AssertionError(f"{text!r} not seen: {lines[-20:]}")


def test_a_killed_worker_s_slice_is_requeued_when_its_lease_expires(engine, monkeypatch, tmp_path):
    lease_s = 6
    monkeypatch.setenv("CBOM_CLOUD_LEASE_S", str(lease_s))
    monkeypatch.setattr(aws_org, "plan_slices", _plan(1))
    user = _team(engine, 1)
    _source(engine, 1)
    _queue(engine, 1, user, "kill-run-0001")
    assert W.run_once(engine, "parent")  # fan-out: 2 slices (global, us-east-1)
    proc = _child(engine, tmp_path, "hang", CBOM_CLOUD_LEASE_S=str(lease_s))
    try:
        _wait_line(proc, "FLUSHED")
        first = next(j for j in _jobs(engine, kind="slice") if j.status == "claimed")
        assert first.lease_expires_at is not None
        # the collector is stuck in one call for longer than the lease: the heartbeat thread keeps the lease alive
        time.sleep(lease_s + 3)
        with Session(engine) as s:
            J.reap(s, utcnow())
            s.commit()
        again = next(j for j in _jobs(engine, kind="slice") if j.id == first.id)
        assert again.status == "claimed" and again.lease_expires_at > first.lease_expires_at
        proc.send_signal(signal.SIGKILL)
        proc.wait(10)
        killed = time.monotonic()
        at_kill = next(j for j in _jobs(engine, kind="slice") if j.id == first.id).lease_expires_at
        assert (at_kill - utcnow()).total_seconds() <= lease_s  # the heartbeat never extends past one lease
        while time.monotonic() - killed < lease_s + 10:
            with Session(engine) as s:
                J.reap(s, utcnow())
                s.commit()
            if next(j for j in _jobs(engine, kind="slice") if j.id == first.id).status == "pending":
                break
            time.sleep(0.25)
        requeued_after = time.monotonic() - killed
    finally:
        if proc.poll() is None:
            proc.kill()
    row = next(j for j in _jobs(engine, kind="slice") if j.id == first.id)
    assert row.status == "pending" and row.attempts == 1 and row.lease_id is None
    assert requeued_after <= lease_s + 1, f"re-queued {requeued_after:.1f}s after the kill (lease {lease_s}s)"
    with Session(engine) as s:  # the dead attempt's batch is already under the parent
        assert s.exec(select(func.count()).select_from(CbomCollectedAsset)).one() == 1
    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    assert _drain(engine) == 2  # the re-queued slice (attempt 2) and the other one
    row = next(j for j in _jobs(engine, kind="slice") if j.id == first.id)
    assert row.status == "success" and row.attempts == 2
    parent = _jobs(engine, kind="collect")[0]
    assert parent.status == "success" and parent.outcome == "ok"
    with Session(engine) as s:  # the re-run stored the same key again: nothing doubled
        rows = s.exec(select(CbomCollectedAsset)).all()
        assert len(rows) == 2 == parent.asset_count and len({r.asset_key for r in rows}) == 2
    print(f"[{engine.kind}] killed worker's slice re-queued {requeued_after:.2f}s after SIGKILL (lease {lease_s}s)")


def test_sigterm_releases_the_running_slice_at_once_after_the_grace_period(engine, monkeypatch, tmp_path):
    monkeypatch.setattr(aws_org, "plan_slices", _plan(1))
    user = _team(engine, 1)
    _source(engine, 1)
    _queue(engine, 1, user, "term-run-0001")
    assert W.run_once(engine, "parent")
    proc = _child(engine, tmp_path, "term", CBOM_CLOUD_SHUTDOWN_GRACE_S="1", CBOM_CLOUD_QUEUE_LOG_S="1")
    try:
        lines = _wait_line(proc, "CLAIMED")
        lines += _wait_line(proc, "CLAIMED")  # both threads hold one slice each
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
    text = "\n".join(lines) + out
    assert proc.returncode == 0, text[-3000:]
    slices = _jobs(engine, kind="slice")
    assert [j.status for j in slices] == ["pending", "pending"] and all(j.lease_id is None for j in slices)
    assert text.count("cbom sources cloud job released") == 2 and "outcome=released" in text
    assert "cbom sources cloud queue" in text and "pending=" in text and "oldest_pending_s=" in text
    assert "cbom sources cloud worker stopped" in text
    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    assert _drain(engine) == 2 and _jobs(engine, kind="collect")[0].status == "success"


# ----------------------------------------------------------------------------- idempotent ingest
def _fanned_out(engine, monkeypatch, accounts=1, regions=("us-east-1",)):
    monkeypatch.setattr(aws_org, "plan_slices", _plan(accounts))
    user = _team(engine, 1)
    _source(engine, 1, accounts=accounts, regions=regions)
    run_id = _queue(engine, 1, user, "idem-run-0001")
    assert W.run_once(engine, "parent")
    return run_id, _jobs(engine, kind="collect")[0]


def test_result_ingest_is_idempotent(engine, monkeypatch):
    run_id, parent = _fanned_out(engine, monkeypatch)
    with Session(engine) as s:
        payload = J.claim_cloud_job(s, utcnow(), "w")
        s.commit()
    job, lease = payload["job"], payload["job"]["lease_id"]
    assert job["kind"] == "slice" and job["slice"]["region"] == "global"
    batch = [_asset(MGMT, "global"), _asset(MGMT, "global")]
    with Session(engine) as s:
        first = J.add_assets(s, None, job["id"], lease, batch, utcnow(), team_id=1)
        s.commit()
    with Session(engine) as s:
        again = J.add_assets(s, None, job["id"], lease, batch, utcnow(), team_id=1)
        s.commit()
    assert (first["accepted"], first["duplicate"]) == (1, 1) and (again["accepted"], again["duplicate"]) == (0, 2)
    result = AC.summary([{"target": f"aws:{MGMT}/global", "status": "ok"}], 1, time.monotonic(), quiet=True)
    with Session(engine) as s:
        J.finish_job(s, None, job["id"], lease, "success", result, None, utcnow(), team_id=1)
        s.commit()
    with Session(engine) as s, pytest.raises(HTTPException) as err:  # the same result again
        J.finish_job(s, None, job["id"], lease, "success", result, None, utcnow(), team_id=1)
    assert err.value.status_code == 409
    with Session(engine) as s, pytest.raises(HTTPException):  # a late batch from the finished slice
        J.add_assets(s, None, job["id"], lease, [_asset(MGMT, "x")], utcnow(), team_id=1)
    with Session(engine) as s:
        assert S.maybe_finalize(s, parent.id, utcnow()) is None  # the region slice is still open
    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    assert _drain(engine) == 1  # the other slice; its worker finalises the parent
    with Session(engine) as s:
        p = s.get(CbomCollectionJob, parent.id)
        assert p.status == "success" and p.asset_count == 2
        assert S.maybe_finalize(s, parent.id, utcnow()) is None and S.finalize(s, p, utcnow()) is None  # once only
        run = s.get(CbomCollectionRun, run_id)
        assert run.status == "done" and run.credits_refunded_c == 0
        assert s.exec(select(func.count()).select_from(CbomCollectedAsset)).one() == 2


def test_cancel_ends_pending_slices_and_refunds_the_parent(engine, monkeypatch):
    run_id, parent = _fanned_out(engine, monkeypatch, accounts=3, regions=("us-east-1", "eu-west-1"))
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        J.cancel_run(s, run, 1, utcnow())
        s.commit()
        J.reap(s, utcnow())
        s.commit()
    with Session(engine) as s:
        p = s.get(CbomCollectionJob, parent.id)
        run = s.get(CbomCollectionRun, run_id)
        assert p.status == "cancelled" and p.refunded and run.status == "cancelled"
        assert run.credits_refunded_c == run.credits_charged_c == 1200
        assert s.get(Team, 1).credit_balance == pytest.approx(100_000.0)
    assert {j.status for j in _jobs(engine, kind="slice")} == {"cancelled"}
    assert not W.run_once(engine, "late")  # nothing left to claim


def test_a_slice_whose_parent_ended_is_never_run(engine, monkeypatch):
    _run, parent = _fanned_out(engine, monkeypatch, accounts=2)
    with Session(engine) as s:  # the parent's fan-out lease is gone (as if the reaper failed it)
        s.get(CbomCollectionJob, parent.id).lease_id = None
        s.commit()
    monkeypatch.setattr(aws_org, "collect_slice", lambda *a: pytest.fail("ran a slice of an ended collection"))
    assert not W.run_once(engine, "w")
    slices = _jobs(engine, kind="slice")
    assert {j.status for j in slices} == {"cancelled"} and "has ended" in slices[0].error


def test_reaper_finalises_a_parent_whose_last_slice_died(engine, monkeypatch):
    monkeypatch.setenv("CBOM_CLOUD_LEASE_S", "10")
    _run, parent = _fanned_out(engine, monkeypatch)
    with Session(engine) as s:
        payload = J.claim_cloud_job(s, utcnow(), "w")
        s.commit()
    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    assert _drain(engine) == 1  # the other slice ends; the claimed one keeps the parent open
    with Session(engine) as s:  # the claimed slice's worker died three times over
        row = s.get(CbomCollectionJob, payload["job"]["id"])
        row.attempts = J.MAX_ATTEMPTS
        s.commit()
        J.reap(s, utcnow() + J.cloud_lease() + J.cloud_lease())
        s.commit()
        p = s.get(CbomCollectionJob, parent.id)
        assert p.status == "success" and p.outcome == "partial" and p.result["counts"]["failed"] == 1


def _run_slices(engine, n: int) -> None:
    for _ in range(n):
        assert W.run_once(engine, "w")


def test_reaper_keeps_a_fanned_out_parent_s_lease_and_progress_and_commits_them(engine, monkeypatch):
    """#140 review M2: reap_parent's writes were rolled back (safe_reap committed only when a job moved)."""
    from backend.utilities.cbom_sources.serialize import public_job

    monkeypatch.setattr(aws_org, "collect_slice", _collector())
    _run, parent = _fanned_out(engine, monkeypatch, accounts=2, regions=("us-east-1", "eu-west-1"))
    _run_slices(engine, 3)
    before = _jobs(engine, kind="collect")[0]
    assert before.result["slices"] == {"done": 0, "total": 6} and before.asset_count == 3  # assets move per batch
    later = utcnow() + J.cloud_lease() - _dt_seconds(5)
    monkeypatch.setattr(W, "utcnow", lambda: later)  # the worker's reap pass, 5 s before the parent's lease ends
    W.reap_all(engine)
    after = _jobs(engine, kind="collect")[0]  # a new session: only what was committed
    assert after.result["slices"] == {"done": 3, "total": 6}
    assert after.lease_expires_at > before.lease_expires_at and after.status == "claimed"
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        out = public_job(after, None, settings, utcnow())
    assert out["progress"] == {"done": 3, "total": 6, "unit": "account-regions"} and out["runner"] == "cloud"


def _dt_seconds(n: int):
    import datetime as dt

    return dt.timedelta(seconds=n)


def test_the_source_asset_cap_is_summed_over_slices_and_the_rest_become_cap_gaps(engine, monkeypatch):
    """#140 review M3: the per-source cap a single job had (CBOM_AWS_MAX_ASSETS_PER_SOURCE, default 50,000) holds
    across every slice; slices after it is reached are not run and end as ``skipped_cap`` coverage rows."""
    monkeypatch.setenv("CBOM_AWS_MAX_ASSETS_PER_SOURCE", "5")

    def two(team_id, cfg, external_id, role_arn, region, emit, should_stop, **_kw):
        acct = role_arn.split(":")[4]
        for i in range(2):
            emit({**_asset(acct, region), "location": f"arn:aws:kms:{region}:{acct}:key/k{i}",
                  "facts": {"identity": f"{acct}-{region}-{i}"}})
        return AC.summary([{"target": f"aws:{acct}/{region}", "status": "ok"}], team_id, time.monotonic(), quiet=True)

    monkeypatch.setattr(aws_org, "collect_slice", two)
    run_id, parent = _fanned_out(engine, monkeypatch, accounts=4)  # 8 slices x 2 assets = 16 > 5
    _drain(engine)
    p = _jobs(engine, kind="collect")[0]
    with Session(engine) as s:
        stored = s.exec(select(func.count()).select_from(CbomCollectedAsset)).one()
        run = s.get(CbomCollectionRun, run_id)
    assert stored == 5 == p.asset_count and p.result.get("truncated") is True
    statuses = [t["status"] for t in p.result["targets"]]
    assert statuses.count("skipped_cap") == 5 and p.result["counts"]["skipped"] == 5
    assert p.status == "success" and p.outcome == "partial" and run.status == "partial"
    # CB-14 (OA-10b): the 5 of 8 account-regions the asset cap left unread are not charged
    assert p.refunded and p.refunded_c == p.weight_c * 5 // 8
    skipped = [j for j in _jobs(engine, kind="slice") if j.status == "cancelled"]
    assert len(skipped) == 5 and all(j.attempts == 0 for j in skipped)  # never run


def _pool_peaks(engine, monkeypatch, teams: dict[int, int], workers: int, cap: int, *, fanned_out: bool = False) -> dict:
    """Run ``workers`` loops over the given {team: accounts} (1 region each) and return each team's peak running
    count, overall and while another team still had queued work, and every claim as the claiming transaction saw it
    right after its UPDATE: (team, the team's running count with this claim, other teams' pending jobs).

    ``fanned_out``: every team's collection is fanned out into its slices before the workers start, so no team's
    pending work grows again while they run (each team only drains). Both measurements are then exact: a team seen
    with queued work at any moment had it at every earlier claim, which the cap had to respect."""
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", str(cap))
    lock = threading.Lock()
    peaks: dict = {t: {"any": 0, "contended": 0} for t in teams}
    peaks["claims"] = []
    base = _collector(0.03)
    real_claim = J.claim_cloud_job

    def claim(session, now, worker, **kw):
        payload = real_claim(session, now, worker, **kw)
        if payload is not None:  # inside the claim's transaction: this claim counted, not yet committed
            team = int(payload["job"]["team_id"])
            others = session.exec(select(func.count()).select_from(CbomCollectionJob).where(
                *J._cloud_queue(), CbomCollectionJob.status == "pending", CbomCollectionJob.team_id != team)).one()
            with lock:
                peaks["claims"].append((team, J._cloud_running(session, team).get(team, 0), int(others)))
        return payload

    def collect(team_id, *a, **kw):
        with Session(engine) as s:
            running = J._cloud_running(s)
            queued = dict(s.exec(select(CbomCollectionJob.team_id, func.count()).where(
                CbomCollectionJob.status == "pending").group_by(CbomCollectionJob.team_id)).all())
        with lock:
            peaks[team_id]["any"] = max(peaks[team_id]["any"], running.get(team_id, 0))
            if any(queued.get(t) for t in teams if t != team_id):
                peaks[team_id]["contended"] = max(peaks[team_id]["contended"], running.get(team_id, 0))
        return base(team_id, *a, **kw)

    monkeypatch.setattr(aws_org, "plan_slices", lambda team_id, cfg, *a: _plan(teams[team_id])(team_id, cfg, *a))
    monkeypatch.setattr(aws_org, "collect_slice", collect)
    for team, accounts in teams.items():
        user = _team(engine, team)
        _source(engine, team, accounts=accounts)
        _queue(engine, team, user, f"peak-run-{team:04d}")
    if fanned_out:  # each collection's parent is the oldest pending job of its team: one run_once fans each out
        for _team_id in teams:
            assert W.run_once(engine, "fan-out")
        assert len(_jobs(engine, kind="slice", status="pending")) == sum(2 * a for a in teams.values())
    monkeypatch.setattr(J, "claim_cloud_job", claim)
    threads = [threading.Thread(target=W.worker_loop, args=(engine, f"p{i}")) for i in range(workers)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and not all(j.status in J.TERMINAL for j in _jobs(engine, kind="collect")):
        time.sleep(0.1)
    W._stop.set()
    for t in threads:
        t.join(30)
    assert all(j.status == "success" for j in _jobs(engine, kind="collect"))
    return peaks


def test_a_lone_tenant_may_use_the_whole_pool(engine, monkeypatch):
    """#140 review M4: the per-team cap is work-conserving; alone in the queue, a team is not held at the cap."""
    peaks = _pool_peaks(engine, monkeypatch, {1: 30}, workers=4, cap=2)
    assert peaks[1]["any"] >= 3, peaks  # before: never more than the cap (2)


def test_the_team_cap_holds_while_another_team_is_waiting(engine, monkeypatch):
    """No claim takes a team past the cap while another team has pending work, checked inside every claiming
    transaction, and the slice-start sample agrees. Both teams are fanned out before the workers start: with a
    work-conserving cap that never preempts, a team legitimately above the cap while alone stays there until its jobs
    finish when another team's work appears later, which a sample taken then would count as a breach (the flake of
    #277 / #280); the race on that path (work appearing during a claim) is test_a_claim_decided_alone_...)."""
    peaks = _pool_peaks(engine, monkeypatch, {1: 30, 2: 30}, workers=4, cap=2, fanned_out=True)
    breaches = [c for c in peaks["claims"] if c[2] > 0 and c[1] > 2]
    assert breaches == [], breaches[:5]
    assert peaks[1]["contended"] <= 2 and peaks[2]["contended"] <= 2, peaks
    contended = [c[1] for c in peaks["claims"] if c[2] > 0]
    assert contended and max(contended) == 2, peaks["claims"][:10]  # and the pool was used up to the cap


def test_a_claim_decided_alone_is_refused_when_another_team_starts_waiting_before_its_update(engine, monkeypatch):
    """The real race behind the flake: the claimer reads the queue (only team 1 waiting, so no cap), another team's
    work appears (its collection fans out), then the claiming UPDATE runs. Before the fix that claim took team 1 past
    its cap while team 2 waited; the UPDATE's guard now re-decides the cap at that moment, on SQLite and PostgreSQL."""
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", "2")
    _run, _parent = _fanned_out(engine, monkeypatch, accounts=5)  # team 1: 10 slices
    for _ in range(2):  # team 1 at its cap
        with Session(engine) as s:
            assert J.claim_cloud_job(s, utcnow(), "w") is not None
            s.commit()
    user2 = _team(engine, 2)
    _source(engine, 2)
    real_check = S.slice_invalid_reason
    fired: list[int] = []

    def team2_arrives(session, job, source):  # called by the claimer after its queue read, before its UPDATE
        if not fired:
            fired.append(_queue(engine, 2, user2, "late-run-0002"))  # committed on its own connection
        return real_check(session, job, source)

    monkeypatch.setattr(S, "slice_invalid_reason", team2_arrives)
    with Session(engine) as s:
        payload = J.claim_cloud_job(s, utcnow(), "w")
        s.commit()
    assert fired, "the claimer never reached its UPDATE"
    assert payload is None  # before the fix: a third team-1 slice while team 2 waited
    with Session(engine) as s:
        assert J._cloud_running(s) == {1: 2}
    # team 2 is served next, and team 1 again once it is back under its cap
    with Session(engine) as s:
        nxt = J.claim_cloud_job(s, utcnow(), "w")
        s.commit()
    assert nxt is not None and nxt["job"]["team_id"] == 2


def test_a_throttled_slice_is_requeued_with_backoff_not_reported_as_auth_failed(engine, monkeypatch):
    """#140 R-qa major: throttling past every retry re-queues the slice (bounded by MAX_ATTEMPTS); on its last try
    it is an ``error`` row, never ``auth_failed``."""
    tries: list[bool] = []

    def throttled(team_id, cfg, external_id, role_arn, region, emit, should_stop, *, raise_throttled=False):
        tries.append(raise_throttled)
        if raise_throttled:
            raise AC.AwsThrottled("Throttling")
        return AC.summary([{"target": f"aws:{MGMT}/{region}", "status": "error", "error": "throttled: Throttling"}],
                          team_id, time.monotonic(), quiet=True)

    waits: list[float] = []
    monkeypatch.setattr(W._stop, "wait", lambda t=None: waits.append(t) or False)
    monkeypatch.setattr(aws_org, "collect_slice", throttled)
    _run, parent = _fanned_out(engine, monkeypatch)  # 2 slices
    _drain(engine)
    slices = _jobs(engine, kind="slice")
    assert [j.attempts for j in slices] == [3, 3] and tries == [True, True, False, True, True, False]
    assert len(waits) == 4 and waits[0] <= waits[1] and waits[2] <= waits[3]  # exponential in the attempt
    p = _jobs(engine, kind="collect")[0]
    assert {t["status"] for t in p.result["targets"]} == {"error"} and p.outcome == "failed" and p.refunded
    # #238 (C2) over the whole source: 0 of N account-regions read is a failure, never "success"
    assert p.status == "failure" and p.error.startswith("No target could be read (0 of 2)")


def test_read_target_reports_a_throttle_as_error_or_raises_for_a_slice():
    from botocore.exceptions import ClientError

    class Acct:  # AssumeRole throttled past every retry
        account = MGMT

        def ensure(self, region):
            raise ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "AssumeRole")

    row = AC.read_target(Acct(), "us-east-1", {}, lambda a: None, lambda: None)
    assert row["status"] == "error" and "Throttling" in row["error"]  # before: auth_failed
    with pytest.raises(AC.AwsThrottled):
        AC.read_target(Acct(), "us-east-1", {}, lambda a: None, lambda: None, raise_throttled=True)


def test_disabling_the_source_ends_every_queued_slice_in_one_reaper_pass(engine, monkeypatch):
    """#140 R-qa minor: queued slices of a disabled / changed source end in one UPDATE, not 25 per claim pass."""
    run_id, parent = _fanned_out(engine, monkeypatch, accounts=50, regions=("us-east-1",))  # 100 slices
    with Session(engine) as s:
        payload = J.claim_cloud_job(s, utcnow(), "w")  # one slice running
        s.commit()
        src = s.exec(select(CbomCollectionSource)).one()
        src.enabled = False
        s.add(src)
        s.commit()
    W.reap_all(engine)
    statuses = [j.status for j in _jobs(engine, kind="slice")]
    assert statuses.count("cancelled") == 99 and statuses.count("claimed") == 1
    # the running slice stops at its next heartbeat; its "ok" read does not count once it is stopped
    with Session(engine) as s:
        assert J.renew_cloud_lease(s, payload["job"]["id"], payload["job"]["lease_id"], utcnow()) == "Source was disabled"
        J.finish_job(s, None, payload["job"]["id"], payload["job"]["lease_id"], "success",
                     AC.summary([{"target": f"aws:{MGMT}/global", "status": "ok"}], 1, time.monotonic(), quiet=True),
                     None, utcnow(), team_id=1)
        s.commit()
    W.reap_all(engine)
    p = _jobs(engine, kind="collect")[0]
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
    assert p.status == "cancelled" and p.refunded and run.status == "cancelled"
    assert p.result["counts"]["ok"] == 0 and p.result["counts"]["skipped"] == 100


def test_a_slice_whose_asset_batch_cannot_be_stored_fails_instead_of_reading_as_auth_failed(engine, monkeypatch):
    """#78's store_failed rule in the slice path: a database error on a batch fails the slice (not auth_failed)."""
    from sqlalchemy.exc import OperationalError

    def boom(*a, **k):
        raise OperationalError("INSERT", {}, Exception("server closed the connection"))

    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop, **_kw):
        try:  # like read_target: every exception becomes a row
            emit(_asset(MGMT, region))
            should_stop.__self__.flush()
        except Exception:
            return AC.summary([{"target": f"aws:{MGMT}/{region}", "status": "auth_failed", "error": "OperationalError"}],
                              team_id, time.monotonic(), quiet=True)
        return AC.summary([{"target": f"aws:{MGMT}/{region}", "status": "ok"}], team_id, time.monotonic(), quiet=True)

    _run, parent = _fanned_out(engine, monkeypatch)
    monkeypatch.setattr(aws_org, "collect_slice", collect)
    monkeypatch.setattr(J, "add_assets", boom)
    _drain(engine)
    slices = _jobs(engine, kind="slice")
    assert {j.status for j in slices} == {"failure"}
    p = _jobs(engine, kind="collect")[0]
    assert {t["status"] for t in p.result["targets"]} == {"error"}  # not the collector's auth_failed row


# ----------------------------------------------------------------------------- organisation walk (moto)
class _Guard:
    """moto does not evaluate trust policies; refuse AssumeRole without the external ID like AWS would."""

    def __init__(self, client):
        self._client = client

    def assume_role(self, **kwargs):
        from botocore.exceptions import ClientError

        if "ExternalId" not in kwargs:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
        return self._client.assume_role(**kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


class _Base:
    def __init__(self):
        import boto3

        self._s = boto3.session.Session(aws_access_key_id="zs", aws_secret_access_key="zs", region_name="us-east-1")

    def client(self, service, **kwargs):
        client = self._s.client(service, **kwargs)
        return _Guard(client) if service == "sts" else client


@pytest.fixture()
def org(monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setattr(AC, "_boto", lambda **kw: (_Base(), None))
    aws_org.clear_cache()
    with moto.mock_aws():
        client = boto3.client("organizations", region_name="us-east-1")
        client.create_organization(FeatureSet="ALL")
        mgmt = client.describe_organization()["Organization"]["MasterAccountId"]
        yield client, mgmt
    aws_org.clear_cache()


def _members(client, n: int) -> None:
    for i in range(n):
        client.create_account(Email=f"m{i}@org.test", AccountName=f"member-{i}")


def test_organisation_walk_reads_every_account_past_200(org):
    client, mgmt = org
    _members(client, 999)  # 1,000 accounts with the management account
    cfg = {"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader",
           "regions": ["us-east-1", "eu-west-1", "ap-south-1"]}
    emitted: list = []
    started = time.monotonic()
    plan = aws_org.plan_slices(1, cfg, "zs-ext-0001", emitted.append, lambda: None)
    took = time.monotonic() - started
    accounts = {s["account_id"] for s in plan["slices"]}
    assert len(accounts) == 1000 and plan["accounts"] == 1000 and plan["org"]["listed"] == 1000
    assert len(plan["slices"]) == 1000 * 4  # global + 3 regions each
    assert plan["targets"] == [] and emitted == []  # no "first 200 were read" gap any more
    assert plan["slices"][0] == {"account_id": mgmt, "role_arn": cfg["role_arn"], "region": "global"}
    print(f"org walk: 1,000 accounts listed and assumed in {took:.1f}s -> {len(plan['slices'])} slices")


def test_a_member_whose_role_cannot_be_assumed_becomes_auth_failed_rows(org, monkeypatch):
    from botocore.exceptions import ClientError

    client, mgmt = org
    _members(client, 249)
    accounts = [a["Id"] for a in client.list_accounts()["Accounts"] if a["Id"] != mgmt]
    broken = accounts[7]
    real = AC._Account.check

    def check(self, region):
        if self.account == broken:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no role"}}, "AssumeRole")
        return real(self, region)

    monkeypatch.setattr(AC._Account, "check", check)
    cfg = {"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader", "regions": ["us-east-1"]}
    plan = aws_org.plan_slices(1, cfg, "zs-ext-0001", lambda a: None, lambda: None)
    assert plan["accounts"] == 250 and plan["org"]["unreachable"] == 1
    assert broken not in {s["account_id"] for s in plan["slices"]} and len(plan["slices"]) == 249 * 2
    assert plan["targets"] == [{"target": f"aws:{broken}/{r}", "status": "auth_failed", "error": "AccessDenied",
                                "assets": 0} for r in ("global", "us-east-1")]


def test_throttling_is_retried_with_backoff(org, monkeypatch):
    from botocore.exceptions import ClientError

    client, mgmt = org
    _members(client, 259)  # 13 pages of 20
    slept: list[float] = []
    monkeypatch.setattr(aws_org, "_sleep", slept.append)
    throttles = {"pages": 0, "assume": 0}
    real_paginator = client.get_paginator

    class Paginator:
        def __init__(self):
            self._p = real_paginator("list_accounts")
            self.calls = 0

        def paginate(self, **kw):
            self.calls += 1
            if self.calls in (4, 5):  # page 4 throttled twice, then answered
                throttles["pages"] += 1
                raise ClientError({"Error": {"Code": "TooManyRequestsException", "Message": "slow"}}, "ListAccounts")
            return self._p.paginate(**kw)

    paginator = Paginator()
    monkeypatch.setattr(client, "get_paginator", lambda name: paginator)
    listed, stopped = aws_org.list_accounts(client, lambda: None)
    assert stopped is None and len(listed) == 260 and len({a["Id"] for a in listed}) == 260
    assert throttles["pages"] == 2 and len(slept) == 2 and 0.25 <= slept[0] <= 0.5 and 0.5 <= slept[1] <= 1.0

    # STS throttled during the parallel member check: retried, the account is still read
    # STS throttled (past botocore's own retries) on the management AssumeRole and in the parallel member check:
    # retried with backoff, every account still read
    real = _Guard.assume_role
    lock = threading.Lock()

    def assume_role(self, **kw):
        with lock:
            if "ExternalId" in kw and throttles["assume"] < 4:
                throttles["assume"] += 1
                raise ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "AssumeRole")
        return real(self, **kw)

    monkeypatch.setattr(_Guard, "assume_role", assume_role)
    monkeypatch.setattr(client, "get_paginator", real_paginator)
    cfg = {"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader", "regions": ["us-east-1"]}
    plan = aws_org.plan_slices(1, cfg, "zs-ext-0001", lambda a: None, lambda: None)
    assert throttles["assume"] == 4 and plan["org"]["unreachable"] == 0 and len(plan["slices"]) == 260 * 2

    # a throttle that never ends gives up after CBOM_AWS_THROTTLE_RETRIES; other errors are never retried
    calls = []

    def always(code):
        def fn():
            calls.append(code)
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "Op")
        return fn

    monkeypatch.setenv("CBOM_AWS_THROTTLE_RETRIES", "4")
    with pytest.raises(ClientError):
        aws_org.with_backoff(always("ThrottlingException"), what="t")
    with pytest.raises(ClientError):
        aws_org.with_backoff(always("AccessDenied"), what="t")
    assert calls.count("ThrottlingException") == 4 and calls.count("AccessDenied") == 1


def test_serial_collect_aws_walks_past_200_accounts_too(org, monkeypatch):
    client, mgmt = org
    _members(client, 249)
    monkeypatch.setattr(AC, "_region_services", lambda acct, region, label, emit, cfg, **kw: [("kms", "ok", None)])
    monkeypatch.setattr(AC, "_global_services", lambda acct, label, emit, **_k: [("iam", "ok", None)])
    cfg = {"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader", "regions": ["us-east-1"]}
    result = AC.collect_aws(1, cfg, "zs-ext-0001", lambda a: None, lambda: None)
    assert result["accounts"] == 250 and result["counts"] == {"total": 500, "ok": 500, "partial": 0, "failed": 0,
                                                              "skipped": 0}


def test_an_assumed_session_for_the_wrong_account_is_never_kept(org, monkeypatch):
    """Before: the session was stored before the identity check, so the next region read with it."""
    _client, mgmt = org
    acct = AC._Account(_Base(), None, "arn:aws:iam::999999999999:role/R", "zs-ext-0001", 1)
    import boto3

    real = boto3.session.Session.client

    def client(self, service, **kw):
        c = real(self, service, **kw)
        if service == "sts" and kw.get("aws_access_key_id") not in (None, "zs"):  # the assumed role's client
            c.get_caller_identity = lambda: {"Account": "123456789012"}
        return c

    monkeypatch.setattr(boto3.session.Session, "client", client)
    for _ in range(2):
        with pytest.raises(AC.AwsCollectError):
            acct.client("kms", "us-east-1")
    assert acct.session is None


def test_migration_chains_on_the_single_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(_REPO_ROOT / "prod_database_migrations" / "alembic.ini"))
    cfg.set_main_option("script_location", str(_REPO_ROOT / "prod_database_migrations" / "migrations"))
    script = ScriptDirectory.from_config(cfg)
    # one head; later revisions (#226 cb226apikey001) chain after this one
    heads = script.get_heads()
    assert len(heads) == 1 and (heads == ["w9cloudpool001"] or
                                any(r.down_revision == "w9cloudpool001" for r in script.walk_revisions()))
    assert script.get_revision("w9cloudpool001").down_revision == "cb25agility001"


def _validate_org(monkeypatch, accounts: int, *, throttle_first: int = 0, page_seconds: float = 0.0):
    import boto3

    sys.path.insert(0, str(Path(__file__).parent))
    import test_cbom_aws_reader_template as R

    from backend.utilities.cbom_sources import aws_validate
    from backend.utilities.cbom_sources.templates import cloudformation_template

    _p, policies = R._resolve_template(cloudformation_template(R.EXT, "organization"))
    base = R._FakeAws(policies)
    calls = {"pages": 0, "throttled": 0}
    clock = [0.0]
    if page_seconds:  # each ListAccounts page takes this long on the validation's clock
        monkeypatch.setattr(aws_validate.time, "monotonic", lambda: clock[0])

    class Org(R._FakeAws):
        def client(self, service, **kw):
            inner = base.client(service, **kw)
            if service != "organizations":
                return inner

            class Accounts:
                def list_accounts(self, NextToken=None):  # noqa: N803 - boto3 names
                    from botocore.exceptions import ClientError

                    if calls["throttled"] < throttle_first:
                        calls["throttled"] += 1
                        raise ClientError({"Error": {"Code": "TooManyRequestsException", "Message": "slow"}}, "ListAccounts")
                    calls["pages"] += 1
                    clock[0] += page_seconds
                    start = int(NextToken or 0)
                    page = [{"Id": f"{300000000000 + i}", "Status": "ACTIVE"} for i in range(start, min(start + 20, accounts))]
                    return {"Accounts": page, **({"NextToken": str(start + 20)} if start + 20 < accounts else {})}
            return Accounts()

    fake = Org(policies)
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")
    monkeypatch.setattr(aws_org, "_sleep", lambda d: None)
    monkeypatch.setattr(aws_validate, "_boto", lambda **_kw: (fake, None))
    monkeypatch.setattr(boto3.session, "Session", fake.session)
    out = aws_validate.validate_aws_role(1, R.ROLE, R.EXT, ["ap-south-1"], "organization")
    row = next(c for c in out["checks"] if c["check"] == "Organization member accounts listed")
    return out, row, calls


def test_validation_counts_every_member_account_and_the_run_is_charged_for_all_of_them(monkeypatch, engine):
    """Owner decision (#140 M5): every account read is billed. Validation counts every page (a throttled page is
    retried); the estimate and a scheduled run charge that count."""
    from backend.utilities.cbom_sources.planning import source_targets

    out, row, calls = _validate_org(monkeypatch, 1000, throttle_first=2)
    assert out["status"] == "passed" and out["member_accounts"] == 1000  # dev: 200
    assert row["detail"] == "Found 1000 member accounts" and calls == {"pages": 50, "throttled": 2}
    _team(engine, 1)
    src_id = _source(engine, 1, accounts=1000)
    with Session(engine) as s:
        assert source_targets(s.get(CbomCollectionSource, src_id), get_or_create_settings(s, 1))["units"] == 1000


def test_a_new_member_count_is_recorded_on_the_source_with_its_change_before_the_next_charge(monkeypatch, engine):
    """The validation stores what each run will be charged and, when the count changed (200 before F1), from what
    and when, on the source the Cloud & Identity tab and a schedule's next run read."""
    from backend.routers import cbom_sources as R
    from backend.utilities.cbom_sources.planning import plan_run

    user = _team(engine, 1)
    src_id = _source(engine, 1, accounts=200)  # validated before F1: the count stopped at 200
    counts = iter([1000, 1000, None, 1200])

    def validate(*a, **k):
        n = next(counts)
        if n is None:  # a failed validation (the role was changed, AWS was down...)
            return {"status": "failed", "checks": [{"check": "Role assumed with external ID", "status": "fail",
                                                    "detail": "AccessDenied"}]}
        return {"status": "passed", "checks": [{"check": "Organization member accounts listed", "status": "pass",
                                                "detail": f"Found {n} member accounts"}], "member_accounts": n}

    monkeypatch.setattr(R, "validate_aws_role", validate)
    monkeypatch.setattr(R, "_save_live_test", lambda engine_, team, user_, source_id, version, action, now, status,
                        summary, result: _store(engine_, source_id, status, result))
    first = R._test_aws(engine, 1, user, src_id)
    est = first["estimate"]
    assert est["accounts"] == 1000 and est["credits_per_account"] == 4.0 and est["credits_per_run"] == 4000.0
    assert est["changed_from"] == {"accounts": 200, "credits_per_run": 800.0} and est["changed_at"].endswith("Z")
    again = R._test_aws(engine, 1, user, src_id)["estimate"]  # unchanged: the last change is kept, not re-dated
    assert again["changed_from"] == est["changed_from"] and again["changed_at"] == est["changed_at"]
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, src_id)
        assert src.last_test_result["estimate"] == again
        plan = plan_run(s, 1, get_or_create_settings(s, 1), utcnow(), include={"cloud": True}, source_ids=None)
        assert plan.total_c == 400_000  # what a schedule's next run would charge: 1,000 x 4 credits
    failed = R._test_aws(engine, 1, user, src_id)
    assert failed["status"] == "failed" and failed["estimate"] == again  # the panel keeps showing the last estimate
    with Session(engine) as s:  # the last estimate and its "changed from" are kept on the source
        assert s.get(CbomCollectionSource, src_id).last_test_result["estimate"] == again
    third = R._test_aws(engine, 1, user, src_id)["estimate"]
    assert third["accounts"] == 1200 and third["changed_from"] == {"accounts": 1000, "credits_per_run": 4000.0}


def test_an_org_validated_before_f1_is_flagged_for_re_validation(engine, capsys):
    from backend.utilities.cbom_sources.planning import org_estimate_stale, plan_run

    user = _team(engine, 1)
    _source(engine, 1, accounts=200, name="old-org")  # validated before F1: no estimate recorded
    with Session(engine) as s:
        src = s.exec(select(CbomCollectionSource)).one()
        assert org_estimate_stale(src)
        plan_run(s, 1, get_or_create_settings(s, 1), utcnow(), include={"cloud": True}, source_ids=None)
        src.last_test_result = {**src.last_test_result, "estimate": {"accounts": 200}}
        assert not org_estimate_stale(src)
    assert f"cbom sources aws org estimate stale: re-validate team=1 source={src.id} accounts=200" in capsys.readouterr().out
    assert user


def _store(engine, source_id, status, result) -> bool:
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, source_id)
        src.last_test_status, src.last_test_result = status, result
        s.add(src)
        s.commit()
    return True


def test_validation_never_reports_a_partial_member_count_as_passed(monkeypatch):
    out, row, calls = _validate_org(monkeypatch, 1000, page_seconds=1.0)  # 20 s budget, 50 pages
    assert 10 < calls["pages"] < 50  # the listing stopped at the time limit
    assert row["status"] == "error" and "before the time limit" in row["detail"] and "member_accounts" not in out
    assert out["status"] != "passed"  # before: "pass", "Found N member accounts" with N the partial count
