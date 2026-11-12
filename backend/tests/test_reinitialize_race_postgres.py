"""Reinitialize races against a real PostgreSQL (#33): threads, each with its own connection, released together.

* Several reinitializes of one scan at once: exactly one is charged the difference, once; the others are refused and
  charge nothing.
* Two scans of one team competing for a balance that covers one difference: one is charged, the other refused, and
  the balance never goes below zero.
* A reinitialize racing a cancel: always ends cancelled with everything the scan paid refunded once.
* A reinitialize racing a poll that sees the REPLACED run succeed: either the old run's result is stored and nothing
  more was charged, or the new run is queued and paid for; never the old result on a scan that paid for the new input.

Needs a throwaway database: CANCEL_RACE_PG_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:55432/c1 (skipped without;
CI sets it, .github/workflows/ci.yml backend job). The schema is dropped and created again by every test.
"""
import asyncio
import io
import json
import os
import random
import sys
import threading
import time
import types
import zipfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "t2-reinitialize-race-secret-not-for-production-use")

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import Scan, Team, User  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scan import credit_estimate  # noqa: E402

PG_URL = os.environ.get("CANCEL_RACE_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="CANCEL_RACE_PG_URL not set (throwaway PostgreSQL)")
ROUNDS = 12
PAYLOAD = json.dumps({"cbom": {"zip_file_used": True}})


def _zip(size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(zipfile.ZipInfo("a.txt", date_time=(2020, 1, 1, 0, 0, 0)), b"a" * size)
    return buf.getvalue()


SMALL, BIG = _zip(50), _zip(750)  # 1 credit (the CBOM minimum) and 7.5 credits


class _Result:
    def __init__(self, state, result=None):
        self.state, self.result, self.info, self.traceback = state, result, None, None


class FakeCelery:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent: list[str] = []
        self.revoked: list[str] = []
        self.poll_sees: dict[str, _Result] = {}  # what the thread named "poll" sees; everyone else sees PENDING
        self.control = types.SimpleNamespace(revoke=self._revoke)
        self.backend = types.SimpleNamespace(database={"scan_cancellations": types.SimpleNamespace(
            update_one=lambda *_a, **_k: None)})

    def _revoke(self, task_id, **_kw):
        with self.lock:
            self.revoked.append(task_id)

    def send_task(self, name, kwargs, queue):
        with self.lock:
            task_id = f"new-{len(self.sent) + 1}"
            self.sent.append(task_id)
        return types.SimpleNamespace(id=task_id)

    def AsyncResult(self, task_id):  # noqa: N802
        if threading.current_thread().name == "poll" and task_id in self.poll_sees:
            return self.poll_sees[task_id]
        return _Result("PENDING")


@pytest.fixture()
def pg(monkeypatch):
    engine = create_engine(PG_URL, pool_size=20, max_overflow=10)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=100.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.commit()

    celery = FakeCelery()
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.db import s3_utils
    from backend.utilities.integrations import jira_ticketing
    from backend.utilities.scan import estimate_scan, format_input
    from backend.utilities.scan import start_scan as start_mod
    from backend.utilities.team import credits as credits_mod

    async def fake_estimate(scan_type, engine, start_scan_payload, uploaded_file=None):
        await asyncio.sleep(random.uniform(0, 0.01))  # spread the requests out a little, differently each round
        await uploaded_file.seek(0)
        with zipfile.ZipFile(io.BytesIO(await uploaded_file.read())) as zf:
            return zf.infolist()[0].file_size / 100

    monkeypatch.setattr(estimate_scan, "estimate_credits", fake_estimate)
    monkeypatch.setattr(format_input, "upload_file", lambda f, extension=".zip": {"bucket": "b", "object_name": "o"})
    monkeypatch.setattr(s3_utils, "delete_file", lambda *_a: True)
    monkeypatch.setattr(cc, "get_celery_app", lambda: celery)
    monkeypatch.setattr(start_mod, "get_celery_app", lambda: celery)
    monkeypatch.setattr(credits_mod, "get_db", lambda: engine)  # the failure path's refund
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: {"scan_findings": types.SimpleNamespace(
        delete_many=lambda *_a, **_k: None)})
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **_k: None)
    monkeypatch.setattr(jira_ticketing, "auto_create_tickets_for_successful_scan", lambda *_a: 0)
    yield engine, celery
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def _new_scan(engine, scan_id, balance):
    section = StartScanPayload.model_validate_json(PAYLOAD).cbom.model_dump(mode="json")
    estimate = {**credit_estimate.input_digest("cbom", section, SMALL), "minimum": 1.0, "credits": 1.0}
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = balance
        s.add(team)
        s.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="pending",
                   task_id=f"t-{scan_id}", credit_consumed=1.0, credit_charged=1.0, credit_estimate=estimate))
        s.commit()


def _reinit(engine, scan_id, data=BIG):
    """One reinitialize, as the route runs it: (200, body) or (status, code)."""
    from fastapi import HTTPException, UploadFile

    from backend.utilities.scan.reinitialize import ReinitializeRefused, reinitialize_scan

    async def run():
        upload = UploadFile(file=io.BytesIO(data), filename="code.zip")
        return await reinitialize_scan(engine, scan_type="cbom", scan_id=scan_id, team_id=1, user_id=1,
                                       start_scan_payload=StartScanPayload.model_validate_json(PAYLOAD),
                                       uploaded_file=upload)

    try:
        return 200, asyncio.run(run())
    except ReinitializeRefused as refused:
        return refused.status_code, refused.code
    except HTTPException as exc:
        return exc.status_code, str(exc.detail)


def _together(*jobs):
    """Run the jobs (name, callable) on their own threads, released by one barrier; their results by name."""
    gate = threading.Barrier(len(jobs))
    out = {}

    def wrap(name, fn):
        gate.wait()
        out[name] = fn()

    threads = [threading.Thread(target=wrap, args=(name, fn), name=name.split(":")[0]) for name, fn in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return out


def _state(engine, scan_id):
    from backend.new_models import CreditLedgerEntry

    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        lines = s.exec(select(CreditLedgerEntry).where(CreditLedgerEntry.scan_id == scan_id)).all()
        return (scan.scan_status, scan.task_id, scan.credit_charged, round(s.get(Team, 1).credit_balance, 4),
                [line.delta for line in lines])


def test_several_reinitializes_of_one_scan_charge_the_difference_once(pg):
    """Six requests released together. Whatever the interleaving: the difference is charged exactly once; a request
    that ran after another had finished sees the input already paid for and is charged 0 (more than one 200 is
    legal); every other request is refused; and only the scan's final run is left to go ahead."""
    engine, celery = pg
    seen = {}
    for i in range(ROUNDS):
        scan_id = 100 + i
        sent_before = len(celery.sent)
        _new_scan(engine, scan_id, balance=100.0)
        out = _together(*[(f"r:{n}", lambda: _reinit(engine, scan_id)) for n in range(6)])
        ok = [v[1]["credits_charged"] for v in out.values() if v[0] == 200]
        refused = [v for v in out.values() if v[0] != 200]
        assert sorted(ok)[-1:] == [6.5] and sorted(ok)[:-1] == [0.0] * (len(ok) - 1), out
        assert all(v[0] == 409 and v[1] in ("reinitialize_conflict", "already_started", "superseded")
                   for v in refused), out
        status, task, charged, balance, deltas = _state(engine, scan_id)
        assert (status, charged, balance, deltas) == ("pending", 7.5, 93.5, [-6.5]), (i, out)
        assert task.startswith("new-")
        # no free duplicate run: every run sent for this scan except the one it now holds was withdrawn, and so
        # was the run it had before
        runs = celery.sent[sent_before:]
        assert set(runs) - {task} <= set(celery.revoked) and f"t-{scan_id}" in celery.revoked, (i, out, task)
        for v in out.values():
            key = f"200 charged {v[1]['credits_charged']}" if v[0] == 200 else f"{v[0]} {v[1]}"
            seen[key] = seen.get(key, 0) + 1
    print(f"\nsix reinitializes at once over {ROUNDS} rounds: {dict(sorted(seen.items()))}")


def test_two_scans_competing_for_one_difference_never_overdraw(pg):
    engine, _celery = pg
    for i in range(ROUNDS):
        a, b = 200 + 2 * i, 201 + 2 * i
        _new_scan(engine, a, balance=10.0)  # covers one difference of 6.5, not two
        _new_scan(engine, b, balance=10.0)
        out = _together(("r:a", lambda: _reinit(engine, a)), ("r:b", lambda: _reinit(engine, b)))
        assert sorted(v[0] for v in out.values()) == [200, 402], out
        assert [v[1] for v in out.values() if v[0] == 402] == ["insufficient_credits"]
        sa, sb = _state(engine, a), _state(engine, b)
        assert sa[3] == sb[3] == 3.5, (i, out)  # one difference taken, the balance never negative
        assert sorted([sa[2], sb[2]]) == [1.0, 7.5] and sorted(sa[4] + sb[4]) == [-6.5]


def test_reinitialize_racing_a_cancel_always_ends_cancelled_and_refunded_once(pg):
    from backend.utilities.scan.cancel_scan import CancelRefused, cancel_scan

    engine, _celery = pg

    def cancel(scan_id, delay):
        time.sleep(delay)
        try:
            return cancel_scan(engine, scan_id=scan_id, team_id=1, scan_type="cbom", user_id=1)["refunded_credits"]
        except CancelRefused as refused:
            return refused.code

    seen = {}
    for i in range(ROUNDS):
        scan_id = 300 + i
        _new_scan(engine, scan_id, balance=100.0)
        delay = random.Random(i).uniform(0, 0.03)
        out = _together(("r:x", lambda: _reinit(engine, scan_id)), ("cancel", lambda: cancel(scan_id, delay)))
        status, _task, _charged, balance, _deltas = _state(engine, scan_id)
        # whatever the order: cancelled, and everything the scan had paid (1, or 1 + 6.5) came back exactly once
        assert (status, balance) == ("cancelled", 101.0), (i, out)
        seen[out["r:x"][0]] = seen.get(out["r:x"][0], 0) + 1
    print(f"\nreinitialize outcomes racing a cancel over {ROUNDS} rounds: {seen}")


def test_reinitialize_racing_a_poll_of_the_replaced_runs_success(pg):
    from backend.utilities.celery import celery_connection as cc

    engine, celery = pg

    def poll(scan_id, delay):
        time.sleep(delay)
        return cc.get_status_and_update_db(scan_id, f"t-{scan_id}", Scan, engine)[0]

    seen = {}
    for i in range(ROUNDS):
        scan_id = 400 + i
        _new_scan(engine, scan_id, balance=100.0)
        celery.poll_sees[f"t-{scan_id}"] = _Result("SUCCESS", {"results": [], "duration_of_scan": 1})
        delay = random.Random(i).uniform(0, 0.03)
        out = _together(("r:x", lambda: _reinit(engine, scan_id)), ("poll", lambda: poll(scan_id, delay)))
        status, task, charged, balance, _deltas = _state(engine, scan_id)
        # the old run's result with nothing more charged, or the new run queued and paid for; never both
        assert (status, charged, balance) in {("success", 1.0, 100.0), ("pending", 7.5, 93.5)}, (i, out, task)
        seen[status] = seen.get(status, 0) + 1
    print(f"\nreinitialize vs a poll of the replaced run over {ROUNDS} rounds: {seen}")
