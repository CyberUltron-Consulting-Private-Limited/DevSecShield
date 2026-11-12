"""A reinitialize whose process dies between its claim and the record of its run (#57 review: security minor on
reinitialize.py:256, QA minor on :228, reproduced out of process in round6/rv-qa57/b/crash_window.py).

A child process runs a real reinitialize against a SQLite file and dies inside ``send_task`` with ``os._exit`` (no
``except``, no ``finally``: what an OOM kill or a container restart does). Before the fix the scan stayed ``pending`` on
a ``reinit-<uuid>`` token forever, charged 7.5 for a run that does not exist, and nothing could withdraw the replaced
run t-1 (its id lived only in the dead request). Now the claim's own UPDATE names both runs and keeps what it
replaced, so:

* the scan list's poll reports the scan as stored and never asks Celery about the claim;
* the sweeper (every minute in the scheduler sidecar) gives a claim older than ``STALE_CLAIM_AFTER`` back: the scan is
  back on t-1 with its price and estimate, the 6.5 difference is refunded with its ledger line, and the run the dead
  process may have sent (its id was chosen before the claim) is withdrawn; t-1 goes ahead;
* or the customer cancels: both runs are withdrawn and everything the scan paid is refunded.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import os
import secrets
import subprocess
import sys
import types
import zipfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))  # generated: no key-shaped literal

PAYLOAD = json.dumps({"cbom": {"zip_file_used": True}})


def _zip(size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(zipfile.ZipInfo("a.txt", date_time=(2020, 1, 1, 0, 0, 0)), b"a" * size)
    return buf.getvalue()


SMALL, BIG = _zip(50), _zip(750)  # 1 credit (the CBOM minimum) and 7.5 credits


class FakeCelery:
    def __init__(self, die_in_send: str | None = None):
        self.die_in_send, self.revoked, self.marks, self.asked = die_in_send, [], {}, []
        self.control = types.SimpleNamespace(revoke=lambda task_id, **_k: self.revoked.append(task_id))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": types.SimpleNamespace(
            update_one=lambda flt, _u, upsert=False: self.marks.setdefault(flt["_id"], True))})

    def send_task(self, name, kwargs, queue, task_id=None):
        if self.die_in_send:
            Path(self.die_in_send).write_text(task_id or "")  # the id the dead process was sending
            os._exit(9)  # like SIGKILL: no except, no finally
        return types.SimpleNamespace(id=task_id)

    def AsyncResult(self, task_id):  # noqa: N802
        self.asked.append(task_id)
        return types.SimpleNamespace(state="PENDING", result=None, info=None, traceback=None)


def _patch_backend(celery):
    """What the route's process would talk to: fake estimator, upload, S3 and Celery (no network)."""
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.db import s3_utils
    from backend.utilities.scan import estimate_scan, format_input
    from backend.utilities.scan import start_scan as start_mod

    async def fake_estimate(scan_type, engine, start_scan_payload, uploaded_file=None):
        await uploaded_file.seek(0)
        with zipfile.ZipFile(io.BytesIO(await uploaded_file.read())) as zf:
            return zf.infolist()[0].file_size / 100

    estimate_scan.estimate_credits = fake_estimate
    format_input.upload_file = lambda f, extension=".zip": {"bucket": "b", "object_name": "o"}
    s3_utils.delete_file = lambda *_a: True
    cc.get_celery_app = lambda: celery
    start_mod.get_celery_app = lambda: celery


def _child(db: str, marker: str) -> None:
    from fastapi import UploadFile
    from sqlmodel import create_engine

    from backend.utilities.db.schemas import StartScanPayload
    from backend.utilities.scan.reinitialize import reinitialize_scan

    _patch_backend(FakeCelery(die_in_send=marker))
    engine = create_engine(f"sqlite:///{db}")
    asyncio.run(reinitialize_scan(engine, scan_type="cbom", scan_id=1, team_id=1, user_id=1,
                                  start_scan_payload=StartScanPayload.model_validate_json(PAYLOAD),
                                  uploaded_file=UploadFile(file=io.BytesIO(BIG), filename="code.zip")))
    raise SystemExit("the child should have died inside send_task")


if __name__ == "__main__" and sys.argv[1:2] == ["--child"]:
    _child(sys.argv[2], sys.argv[3])

import pytest  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import CreditLedgerEntry, Scan, Team, User  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402
from backend.utilities.scan import credit_estimate  # noqa: E402


def _estimate():
    section = StartScanPayload.model_validate_json(PAYLOAD).cbom.model_dump(mode="json")
    return {**credit_estimate.input_digest("cbom", section, SMALL), "minimum": 1.0, "credits": 1.0}


@pytest.fixture()
def crashed(tmp_path, monkeypatch):
    """A scan paid 1 credit and queued as t-1, then a reinitialize with a 7.5-credit input killed inside send_task."""
    db, marker = tmp_path / "crash.db", tmp_path / "sent-id"
    engine = create_engine(f"sqlite:///{db}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=100.0))
        s.add(User(id=1, email="u@example.test", password="x", first_name="u", last_name="t", default_team_id=1))
        s.add(Scan(id=1, team_id=1, owner_user_id=1, scan_type="cbom", scan_status="pending", task_id="t-1",
                   credit_consumed=1.0, credit_charged=1.0, credit_estimate=_estimate()))
        s.commit()
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT)}
    child = subprocess.run([sys.executable, __file__, "--child", str(db), str(marker)], env=env, cwd=str(_REPO_ROOT),
                           capture_output=True, text=True, timeout=120)
    assert child.returncode == 9, child.stdout[-2000:] + child.stderr[-2000:]
    sent_id = marker.read_text()
    assert sent_id, "the child died before it chose the run's id"

    celery = FakeCelery()
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.scan import start_scan as start_mod
    monkeypatch.setattr(cc, "get_celery_app", lambda: celery)
    monkeypatch.setattr(start_mod, "get_celery_app", lambda: celery)
    yield engine, celery, sent_id
    engine.dispose()


def _state(engine):
    with Session(engine) as s:
        scan = s.get(Scan, 1)
        lines = s.exec(select(CreditLedgerEntry).order_by(CreditLedgerEntry.id)).all()
        return (scan.scan_status, scan.task_id, scan.credit_charged, s.get(Team, 1).credit_balance,
                [(x.reason, x.delta) for x in lines], scan.credit_estimate)


def test_a_process_killed_after_its_claim_leaves_everything_needed_to_recover(crashed):
    from backend.utilities.celery import celery_connection as cc

    engine, celery, sent_id = crashed
    status, task, charged, balance, lines, estimate = _state(engine)
    # what the dead process left: the claim names both runs and keeps the replaced state
    assert (status, task, charged, balance) == ("pending", f"reinit-{sent_id}.t-1", 7.5, 93.5)
    assert lines == [("scan_reinitialize_charge", -6.5)]
    assert estimate["reinitialize_claim"] == {"task_id": "t-1", "credit_charged": 1.0, "credit_consumed": 1.0,
                                              "credit_estimate": _estimate()}
    # the scan list keeps polling the scan: it reports the row and never asks Celery about the claim
    assert cc.get_status_and_update_db(1, task, Scan, engine)[0] == "pending" and celery.asked == []


def test_the_sweeper_gives_a_dead_claim_back_and_the_replaced_run_goes_ahead(crashed):
    from backend.utilities.scan.reinitialize import STALE_CLAIM_AFTER, sweep_stale_claims

    engine, celery, sent_id = crashed
    assert sweep_stale_claims(engine) == []  # a fresh claim may still be sending
    later = dt.datetime.now(dt.timezone.utc) + STALE_CLAIM_AFTER + dt.timedelta(seconds=1)
    assert sweep_stale_claims(engine, now=later) == [1]
    status, task, charged, balance, lines, estimate = _state(engine)
    assert (status, task, charged, balance) == ("pending", "t-1", 1.0, 100.0)
    assert estimate == _estimate()
    assert lines == [("scan_reinitialize_charge", -6.5), ("scan_reinitialize_refund", 6.5)]
    assert celery.revoked == [sent_id] and set(celery.marks) == {sent_id}  # t-1 is not withdrawn
    assert sweep_stale_claims(engine, now=later) == []


def test_a_cancel_of_a_dead_claim_withdraws_both_runs_and_refunds_everything(crashed):
    from backend.utilities.scan.cancel_scan import cancel_scan

    engine, celery, sent_id = crashed
    out = cancel_scan(engine, scan_id=1, team_id=1, scan_type="cbom", user_id=1)
    assert out["refunded_credits"] == 7.5
    status, _task, _charged, balance, lines, _estimate = _state(engine)
    assert (status, balance) == ("cancelled", 101.0)
    assert lines == [("scan_reinitialize_charge", -6.5), ("scan_cancel_refund", 7.5)]
    assert set(celery.revoked) == set(celery.marks) == {sent_id, "t-1"}
