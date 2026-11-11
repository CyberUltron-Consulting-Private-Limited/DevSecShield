"""A cancel racing with the scan's completion, against a real PostgreSQL (C1, rule 4).

Each round starts a running scan charged 2 credits on a team with 10, then lets a cancel and a poll of the finished
worker run at the same moment from two threads (each with its own connection). The round must end in exactly one of:
completed and charged (balance 10), or cancelled and refunded once (balance 12); for a worker that FAILED, refunded
exactly once either way. Several cancels at once refund once.

Needs a throwaway database: CANCEL_RACE_PG_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:55432/c1 (skipped without).
"""
import os
import random
import sys
import threading
import time
import types
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "c1-cancel-race-secret-not-for-production-use")

from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.new_models import Scan, Team, User  # noqa: E402

PG_URL = os.environ.get("CANCEL_RACE_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="CANCEL_RACE_PG_URL not set (throwaway PostgreSQL)")
ROUNDS = 40


class _Result:
    def __init__(self, state, result=None):
        self.state, self.result, self.info, self.traceback = state, result, None, None


@pytest.fixture()
def pg(monkeypatch):
    engine = create_engine(PG_URL, pool_size=10)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=10.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.commit()

    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.team import credits as credits_mod

    worker = {"state": "SUCCESS"}  # what the poll thread sees; the cancel's own sync still sees a running task

    class FakeCelery:
        control = types.SimpleNamespace(revoke=lambda *_a, **_k: None)
        backend = types.SimpleNamespace(database={"scan_cancellations": types.SimpleNamespace(
            update_one=lambda *_a, **_k: None)})

        def AsyncResult(self, _task_id):  # noqa: N802
            if threading.current_thread().name == "poll":
                payload = {"results": [], "duration_of_scan": 1} if worker["state"] == "SUCCESS" else RuntimeError("x")
                return _Result(worker["state"], payload)
            return _Result("STARTED")

    monkeypatch.setattr(cc, "get_celery_app", lambda: FakeCelery())
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: {"scan_findings": types.SimpleNamespace(
        delete_many=lambda *_a, **_k: None)})
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **_k: None)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)  # the failure path's refund
    from backend.utilities.integrations import jira_ticketing

    monkeypatch.setattr(jira_ticketing, "auto_create_tickets_for_successful_scan", lambda *_a: 0)
    yield engine, worker
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def _round(engine, scan_id, *, cancel_delay, poll_delay):
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.scan.cancel_scan import CancelRefused, cancel_scan

    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = 10.0
        s.add(team)
        s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="sast", scan_status="started",
                   task_id=f"t-{scan_id}", credit_consumed=2.0, credit_charged=2.0))
        s.commit()
    gate = threading.Barrier(2)
    outcome = {}

    def do_cancel():
        gate.wait()
        time.sleep(cancel_delay)
        try:
            outcome["cancel"] = cancel_scan(engine, scan_id=scan_id, team_id=1, scan_type="sast", user_id=1)
        except CancelRefused as refused:
            outcome["cancel"] = refused.code

    def do_poll():
        gate.wait()
        time.sleep(poll_delay)
        outcome["poll"] = cc.get_status_and_update_db(scan_id, f"t-{scan_id}", Scan, engine)[0]

    threads = [threading.Thread(target=do_cancel, name="cancel"), threading.Thread(target=do_poll, name="poll")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    with Session(engine) as s:
        return s.get(Scan, scan_id).scan_status, s.get(Team, 1).credit_balance, outcome


def _delays(i):
    """Odd rounds hold the cancel back a little, even rounds the poll (the cancel does more work before its
    compare-and-set, so the poll needs the longer head start for both orders to happen)."""
    rnd = random.Random(i)
    return (rnd.uniform(0, 0.004), 0.0) if i % 2 else (0.0, rnd.uniform(0, 0.04))


def test_cancel_racing_success_ends_completed_or_cancelled_never_both(pg):
    engine, worker = pg
    worker["state"] = "SUCCESS"
    seen = {}
    for i in range(ROUNDS):
        cancel_delay, poll_delay = _delays(i)
        status, balance, outcome = _round(engine, 1000 + i, cancel_delay=cancel_delay, poll_delay=poll_delay)
        assert (status, balance) in {("success", 10.0), ("cancelled", 12.0)}, (i, status, balance, outcome)
        if status == "success":
            assert outcome["cancel"] == "already_completed", outcome
        else:
            assert outcome["cancel"]["refunded_credits"] == 2.0 and outcome["poll"] == "cancelled", outcome
        seen[status] = seen.get(status, 0) + 1
    print(f"\nsuccess-vs-cancel outcomes over {ROUNDS} rounds: {seen}")
    assert set(seen) == {"success", "cancelled"}, seen  # both orders really happened


def test_cancel_racing_failure_refunds_exactly_once(pg):
    engine, worker = pg
    worker["state"] = "FAILURE"
    seen = {}
    for i in range(ROUNDS):
        cancel_delay, poll_delay = _delays(i)
        status, balance, outcome = _round(engine, 2000 + i, cancel_delay=cancel_delay, poll_delay=poll_delay)
        assert status in ("failure", "cancelled") and balance == 12.0, (i, status, balance, outcome)
        seen[status] = seen.get(status, 0) + 1
    print(f"\nfailure-vs-cancel outcomes over {ROUNDS} rounds: {seen}")
    assert set(seen) == {"failure", "cancelled"}, seen


def test_many_cancels_at_once_refund_once(pg):
    from backend.utilities.scan.cancel_scan import CancelRefused, cancel_scan

    engine, _worker = pg
    with Session(engine) as s:
        s.add(Scan(id=3000, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="pending", task_id="t-3000",
                   credit_consumed=2.0, credit_charged=2.0))
        s.commit()
    gate = threading.Barrier(6)
    results = []

    def go():
        gate.wait()
        try:
            results.append(cancel_scan(engine, scan_id=3000, team_id=1, scan_type="cbom", user_id=1)["scan_status"])
        except CancelRefused as refused:
            results.append(refused.code)

    threads = [threading.Thread(target=go, name=f"c{n}") for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == ["already_cancelled"] * 5 + ["cancelled"]
    with Session(engine) as s:
        assert s.get(Team, 1).credit_balance == 12.0 and s.get(Scan, 3000).scan_status == "cancelled"
