"""CB-35 W-STATE restart cases (R3 S11): the exact audit actions and timings of the three restart mechanisms.

* A restarted scan node heartbeats ``running: []``.  A claimed job it no longer reports is released back to
  ``pending`` once it is older than ORPHAN_GRACE (120 s): audit ``job.released`` with ``not_reported_by_node``; on
  the last attempt it fails instead (``job.failure``) and is refunded.  This is not lease expiry.
* A node that stays down: the lease (15 min) expires and the reaper moves the job, audit
  ``job.lease_expired.pending`` (``job.lease_expired.failure`` on the last attempt, refunded).
* The cloud worker restarted mid-job (a kill: its SIGTERM handler stops only between jobs): ``--once`` with a seeded
  lease reaps the expired lease first, then claims the same job as attempt 2.

Run nightly by the W-STATE wave (e2e/cbom/waves.yaml), and with the backend suite.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_cloud_pool_f1 import _make_engine, _queue, _source, _team  # noqa: E402
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401

from backend.new_models import CbomCollectionAuditEvent, CbomCollectionJob, CbomScanNode, Team  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.workers import cbom_cloud_worker as W  # noqa: E402


def _audits(engine, job_id: int) -> list[tuple[str, list]]:
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.object_type == "job",
                                                             CbomCollectionAuditEvent.object_id == job_id)
                      .order_by(CbomCollectionAuditEvent.id)).all()
        return [(r.action, list(r.changed_fields or [])) for r in rows if not r.action.startswith("job.claim")]


def _job(engine, job_id: int) -> CbomCollectionJob:
    with Session(engine) as s:
        return s.get(CbomCollectionJob, job_id)


def _heartbeat_empty(engine, job: CbomCollectionJob, at: dt.datetime) -> list[int]:
    with Session(engine) as s:
        released = J.renew_leases(s, s.get(CbomScanNode, job.node_id), at, [])
        s.commit()
        return released


def test_the_timings_are_the_ones_the_plan_budgets():
    assert J.ORPHAN_GRACE == dt.timedelta(seconds=120)
    assert J.LEASE == dt.timedelta(minutes=15)
    assert J.MAX_ATTEMPTS == 3


def test_a_restarted_node_gets_its_job_back_after_120_s_with_job_released(api, world):  # noqa: F811
    engine, _ = world
    _src, _run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    claimed_at = _job(engine, job_id).claimed_at
    job = _job(engine, job_id)
    assert _heartbeat_empty(engine, job, claimed_at + dt.timedelta(seconds=119)) == []  # inside the grace
    assert _job(engine, job_id).status == "claimed"
    assert _heartbeat_empty(engine, job, claimed_at + dt.timedelta(seconds=121)) == [job_id]
    after = _job(engine, job_id)
    assert (after.status, after.lease_id, after.lease_expires_at, after.attempts) == ("pending", None, None, 1)
    assert _audits(engine, job_id)[-1] == ("job.released", ["not_reported_by_node"])


def test_on_the_last_attempt_a_lost_job_fails_with_job_failure_and_is_refunded(api, world):  # noqa: F811
    engine, _ = world
    _src, _run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    with Session(engine) as s:
        balance = s.get(Team, 1).credit_balance
        row = s.get(CbomCollectionJob, job_id)
        row.attempts = J.MAX_ATTEMPTS
        s.add(row)
        s.commit()
    job = _job(engine, job_id)
    _heartbeat_empty(engine, job, job.claimed_at + dt.timedelta(seconds=121))
    after = _job(engine, job_id)
    assert (after.status, after.outcome, after.refunded) == ("failure", "failed", True)
    assert after.error == "The scan node stopped running this job"
    assert _audits(engine, job_id)[-1] == ("job.failure", ["not_reported_by_node"])
    with Session(engine) as s:
        assert s.get(Team, 1).credit_balance > balance


def test_a_node_that_stays_down_loses_the_lease_after_15_min_with_job_lease_expired(api, world):  # noqa: F811
    engine, _ = world
    _src, _run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    expires = _job(engine, job_id).lease_expires_at
    assert expires - _job(engine, job_id).claimed_at == dt.timedelta(minutes=15)
    with Session(engine) as s:
        assert J.reap(s, expires - dt.timedelta(seconds=1)) == 0
        s.commit()
    with Session(engine) as s:
        assert J.reap(s, expires + dt.timedelta(seconds=1)) == 1
        s.commit()
    after = _job(engine, job_id)
    assert (after.status, after.lease_id) == ("pending", None)
    assert _audits(engine, job_id)[-1] == ("job.lease_expired.pending", [])


def test_the_last_attempts_lease_expiry_fails_the_job_and_refunds_it(api, world):  # noqa: F811
    engine, _ = world
    _src, _run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    with Session(engine) as s:
        row = s.get(CbomCollectionJob, job_id)
        row.attempts = J.MAX_ATTEMPTS
        s.add(row)
        s.commit()
    with Session(engine) as s:
        J.reap(s, _job(engine, job_id).lease_expires_at + dt.timedelta(seconds=1))
        s.commit()
    after = _job(engine, job_id)
    assert (after.status, after.error, after.refunded) == ("failure", "Scan node stopped responding", True)
    assert _audits(engine, job_id)[-1] == ("job.lease_expired.failure", [])


def test_cloud_worker_once_with_a_seeded_lease_reaps_then_reclaims_as_attempt_2(tmp_path, monkeypatch):
    """R3 S11: a restart mid-AWS-job is a kill; the next ``--once`` reaps the dead lease and runs attempt 2 (no 17-min
    wait inside the lock hold: the lease is seeded as expired)."""
    engine = _make_engine("sqlite", tmp_path)
    user = _team(engine, 1)
    _source(engine, 1)
    _queue(engine, 1, user, "restart-once-1")
    now = dt.datetime(2026, 12, 1, 3, 0)
    with Session(engine) as s:  # the killed worker's claim: attempt 1, its lease already expired
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "collect")).one()
        job.status, job.attempts, job.lease_id = "claimed", 1, "dead-worker-lease-0001"
        job.claimed_at, job.lease_expires_at = now - dt.timedelta(minutes=20), now - dt.timedelta(minutes=5)
        s.add(job)
        s.commit()
        job_id = job.id
    ran: list[dict] = []
    monkeypatch.setattr(W, "get_db", lambda: engine)
    monkeypatch.setattr(W, "utcnow", lambda: now)
    monkeypatch.setattr(W._Job, "run", lambda self: ran.append(self.job))
    monkeypatch.setattr(W.signal, "signal", lambda *a: None)
    monkeypatch.setattr(sys, "argv", ["cbom_cloud_worker", "--once"])
    W.main()
    assert [(j["id"], j["attempt"]) for j in ran] == [(job_id, 2)]
    after = _job(engine, job_id)
    assert after.status == "claimed" and after.attempts == 2 and after.lease_id != "dead-worker-lease-0001"
    assert [a for a, _f in _audits(engine, job_id)] == ["job.lease_expired.pending"]
