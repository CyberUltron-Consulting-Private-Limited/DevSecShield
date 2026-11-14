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

PG = os.environ.get("CBOM_TEST_PG_URL")
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
    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop):
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

    def collect(team_id, *a):
        with Session(engine) as s:  # how many jobs this team runs right now, every worker counted
            now_running = J._cloud_running(s).get(team_id, 0)
        with lock:
            running_peak[team_id] = max(running_peak[team_id], now_running)
        return base(team_id, *a)

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
    assert running_peak[1] <= 3  # the per-team cap held across 4 workers
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

    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop):
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
    real = AC._Account.check
    lock = threading.Lock()

    def check(self, region):
        with lock:
            if throttles["assume"] < 3:
                throttles["assume"] += 1
                raise ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "AssumeRole")
        return real(self, region)

    monkeypatch.setattr(AC._Account, "check", check)
    monkeypatch.setattr(client, "get_paginator", real_paginator)
    cfg = {"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader", "regions": ["us-east-1"]}
    plan = aws_org.plan_slices(1, cfg, "zs-ext-0001", lambda a: None, lambda: None)
    assert throttles["assume"] == 3 and plan["org"]["unreachable"] == 0 and len(plan["slices"]) == 260 * 2

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
    monkeypatch.setattr(AC, "_region_services", lambda acct, region, label, emit, cfg: [("kms", "ok", None)])
    monkeypatch.setattr(AC, "_global_services", lambda acct, label, emit: [("iam", "ok", None)])
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
    assert script.get_heads() == ["w9cloudpool001"]
    assert script.get_revision("w9cloudpool001").down_revision == "r6f14sshca002"


def test_validation_counts_every_member_account_so_the_run_is_charged_for_all_of_them(monkeypatch):
    """The org run is charged per member account counted at validation; the count used to stop at 10 pages (200)."""
    import boto3

    sys.path.insert(0, str(Path(__file__).parent))
    import test_cbom_aws_reader_template as R

    from backend.utilities.cbom_sources import aws_validate
    from backend.utilities.cbom_sources.templates import cloudformation_template

    _p, policies = R._resolve_template(cloudformation_template(R.EXT, "organization"))
    base = R._FakeAws(policies)

    class Org(R._FakeAws):
        def client(self, service, **kw):
            inner = base.client(service, **kw)
            if service != "organizations":
                return inner

            class Accounts:
                def list_accounts(self, NextToken=None):  # noqa: N803 - boto3 names
                    start = int(NextToken or 0)
                    page = [{"Id": f"{300000000000 + i}", "Status": "ACTIVE"} for i in range(start, min(start + 20, 1000))]
                    return {"Accounts": page, **({"NextToken": str(start + 20)} if start + 20 < 1000 else {})}
            return Accounts()

    fake = Org(policies)
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")
    monkeypatch.setattr(aws_validate, "_boto", lambda **_kw: (fake, None))
    monkeypatch.setattr(boto3.session, "Session", fake.session)
    out = aws_validate.validate_aws_role(1, R.ROLE, R.EXT, ["ap-south-1"], "organization")
    assert out.get("member_accounts") == 1000, out["checks"]  # before: 200
    assert next(c for c in out["checks"] if c["check"] == "Organization member accounts listed")["detail"] == \
        "Found 1000 member accounts"
