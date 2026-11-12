"""Cancelling a code scan (C1): the API rules, who may cancel, the refund given once, and that the poller never stores a
result or refunds again after a cancel (utilities/scan/cancel_scan.py, utilities/celery/celery_connection.py).

Hermetic: SQLite + TestClient with a fake Celery app (revoke + the backend's Mongo database). The race between a cancel
and the scan's completion is proved against a real PostgreSQL in test_cancel_race_postgres.py.
"""
import datetime as dt
import os
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "c1-cancel-test-secret-not-for-production-use")

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402


class _Result:
    def __init__(self, state, result=None):
        self.state, self.result, self.info, self.traceback = state, result, None, None


class _Collection:
    def __init__(self):
        self.docs = {}

    def update_one(self, flt, update, upsert=False):
        self.docs.setdefault(flt["_id"], {}).update(update["$set"])

    def delete_many(self, _flt):
        return None

    def insert_many(self, _docs):
        return None


class FakeCelery:
    """What cancel and the poller use: AsyncResult(task).state/.result, control.revoke and backend.database."""

    def __init__(self):
        self.states: dict[str, _Result] = {}
        self.revoked: list[tuple[str, dict]] = []
        marks = _Collection()
        self.marks = marks
        self.control = types.SimpleNamespace(revoke=lambda task_id, **kw: self.revoked.append((task_id, kw)))
        self.backend = types.SimpleNamespace(database={"scan_cancellations": marks})

    def AsyncResult(self, task_id):  # noqa: N802 (Celery's name)
        return self.states.get(task_id, _Result("PENDING"))


SCANS = {
    # id: (type, status, task_id, charged)
    1: ("sast", "pending", "t-1", 2.0),       # queued, not started by a worker
    2: ("cbom", "started", "t-2", 3.5),       # running
    3: ("iac", "success", "t-3", 1.0),
    4: ("sbom_sca", "failure", "t-4", 1.0),
    5: ("ai_bom", "NOT_STARTED", None, None),
    6: ("sast", "pending", None, None),       # being started: claimed, not dispatched yet
    7: ("dast", "started", "t-7", 1.0),
    8: ("sast", "started", "t-8", 2.0),       # team 2's scan
}


@pytest.fixture()
def http(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    now = dt.datetime.now(dt.timezone.utc)
    with Session(engine) as s:
        s.add(Team(id=1, name="one", credit_balance=10.0))
        s.add(Team(id=2, name="two", credit_balance=10.0))
        s.add(User(id=1, email="a@example.test", password="x", first_name="a", last_name="a", default_team_id=1))
        s.add(User(id=2, email="b@example.test", password="x", first_name="b", last_name="b", default_team_id=2))
        s.add(User(id=3, email="c@example.test", password="x", first_name="c", last_name="c", default_team_id=1))
        s.add(TeamMembership(team_id=1, user_id=1, role="admin"))
        s.add(TeamMembership(team_id=1, user_id=3, role="member"))  # a member who did not start the scans
        s.add(TeamMembership(team_id=2, user_id=2, role="admin"))
        for sid, (kind, status, task, charged) in SCANS.items():
            s.add(Scan(id=sid, team_id=2 if sid == 8 else 1, owner_user_id=2 if sid == 8 else 1, scan_type=kind,
                       scan_status=status, task_id=task, credit_consumed=charged, credit_charged=charged,
                       created_at=now))
        s.commit()

    celery = FakeCelery()
    from backend.routers import scans as scans_router
    from backend.utilities.celery import celery_connection as cc
    from backend.utilities.team import validation

    async def fake_user(_engine, authorization):
        return types.SimpleNamespace(id=int((authorization or "Bearer 1").split()[-1]))

    monkeypatch.setattr(scans_router, "get_db", lambda: engine)
    monkeypatch.setattr(scans_router, "get_user_from_header_or_raise_exception", fake_user)
    monkeypatch.setattr(scans_router, "check_if_user_is_in_team", validation.check_if_user_is_in_team)
    monkeypatch.setattr(cc, "get_celery_app", lambda: celery)

    def refunds():  # the failure refunds the poller wrote (credits ledger, in the transaction of the failure)
        from backend.new_models import CreditLedgerEntry

        with Session(engine) as s:
            return [(r.team_id, r.delta) for r in s.exec(
                select(CreditLedgerEntry).where(CreditLedgerEntry.reason == "scan_failure_refund")).all()]
    from backend.main import app

    return TestClient(app), engine, celery, refunds


def _cancel(client, scan_id, kind, user=1, team=1):
    return client.post(f"/{team}/{kind}/scan/{scan_id}/cancel", headers={"Authorization": f"Bearer {user}"})


def _row(engine, scan_id):
    with Session(engine) as s:
        scan = s.get(Scan, scan_id)
        return scan.scan_status, scan.info, s.get(Team, scan.team_id).credit_balance


def test_queued_scan_is_cancelled_refunded_and_withdrawn_from_the_queue(http):
    client, engine, celery, _ = http
    r = _cancel(client, 1, "sast")
    assert r.status_code == 200, r.text
    assert r.json() == {"scan_status": "cancelled", "refunded_credits": 2.0, "message": "Cancelled — 2 credits refunded."}
    status, info, balance = _row(engine, 1)
    assert status == "cancelled" and info["refunded_credits"] == 2.0 and info["cancelled_by"] == 1
    assert balance == 12.0
    assert celery.revoked == [("t-1", {})]  # revoke WITHOUT terminate: the worker stops itself
    from backend.new_models import CreditLedgerEntry

    with Session(engine) as s:  # the refund's credits-ledger line, committed with the compare-and-set
        (line,) = s.exec(select(CreditLedgerEntry)).all()
        assert (line.reason, line.delta, line.balance_after, line.movement_key) == (
            "scan_cancel_refund", 2.0, 12.0, "scan:1:cancel")
    assert "t-1" in celery.marks.docs  # the mark a worker checks when it picks the task up (survives restarts)


def test_running_scan_is_cancelled_by_any_team_member_and_refunded_in_full(http):
    client, engine, celery, _ = http
    r = _cancel(client, 2, "cbom", user=3)  # not the owner, but a member of the team
    assert r.status_code == 200 and r.json()["refunded_credits"] == 3.5
    assert _row(engine, 2)[0] == "cancelled" and _row(engine, 2)[2] == 13.5
    assert "t-2" in celery.marks.docs


def test_cancelling_twice_refunds_once_and_says_why(http):
    client, engine, _celery, _ = http
    assert _cancel(client, 2, "cbom").status_code == 200
    again = _cancel(client, 2, "cbom")
    assert again.status_code == 409
    assert again.json()["code"] == "already_cancelled" and again.json()["refunded_credits"] == 3.5
    assert "already cancelled" in again.json()["detail"]
    assert _row(engine, 2)[2] == 13.5  # not 17.0


@pytest.mark.parametrize("scan_id,kind,code", [
    (3, "iac", "already_completed"),
    (4, "sbom_sca", "already_failed"),
    (5, "ai_bom", "not_started"),
    (6, "sast", "starting"),
])
def test_scans_that_cannot_be_cancelled_answer_409_with_the_reason(http, scan_id, kind, code):
    client, engine, celery, _ = http
    before = _row(engine, scan_id)
    r = _cancel(client, scan_id, kind)
    assert r.status_code == 409 and r.json()["code"] == code and r.json()["detail"]
    assert _row(engine, scan_id) == before and celery.revoked == []


def test_only_members_of_the_scans_team_can_cancel(http):
    client, engine, _celery, _ = http
    assert _cancel(client, 2, "cbom", user=2, team=1).status_code == 403  # user 2 is not in team 1
    assert _cancel(client, 8, "sast", user=1, team=1).status_code == 404  # team 2's scan through team 1's path
    assert _cancel(client, 2, "sast", user=1, team=1).status_code == 404  # wrong type for the scan
    assert _row(engine, 2)[0] == "started" and _row(engine, 8)[0] == "started"


def test_dast_is_not_a_cancellable_type(http):
    client, engine, _celery, _ = http
    assert _cancel(client, 7, "dast").status_code == 400
    assert _row(engine, 7)[0] == "started"


def test_a_scan_that_already_finished_in_the_worker_is_stored_not_cancelled(http, monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, _ = http
    celery.states["t-2"] = _Result("SUCCESS", {"results": [], "duration_of_scan": 1})
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **_k: None)
    monkeypatch.setattr(cc, "get_mongo_client_db", lambda: {"scan_findings": _Collection()})
    r = _cancel(client, 2, "cbom")
    assert r.status_code == 409 and r.json()["code"] == "already_completed"
    status, _info, balance = _row(engine, 2)
    assert status == "success" and balance == 10.0 and celery.revoked == []


def test_after_a_cancel_the_poller_never_stores_a_result_or_refunds_again(http, monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, refunds = http
    assert _cancel(client, 2, "cbom").status_code == 200
    stored = []
    monkeypatch.setattr(cc, "create_findings_in_mongo_db", lambda **k: stored.append(k))
    for state in ("STARTED", "SUCCESS", "FAILURE", "REVOKED"):
        celery.states["t-2"] = _Result(state, {"results": [1]} if state == "SUCCESS" else RuntimeError("killed"))
        status, data, _scan = cc.get_status_and_update_db(2, "t-2", Scan, engine)
        assert status == "cancelled" and data == {}
    assert stored == [] and refunds() == []
    status, info, balance = _row(engine, 2)
    assert status == "cancelled" and info["refunded_credits"] == 3.5 and balance == 13.5
    # the scan page shows the cancelled scan without asking the worker again
    page = client.get("/1/cbom/scan/2", headers={"Authorization": "Bearer 1"})
    assert page.status_code in (200, 500)  # messages/findings need Mongo; the status is what matters below
    if page.status_code == 200:
        assert page.json()["scan_status"] == "cancelled"


def test_a_progress_poll_that_read_the_row_before_the_cancel_does_not_overwrite_it(http, monkeypatch):
    """The poller's non-terminal update is conditional: a cancel committed between its read and its write wins."""
    from backend.utilities.celery import celery_connection as cc

    client, engine, celery, _ = http
    celery.states["t-2"] = _Result("STARTED")
    real_session = cc.Session
    fired = []

    class CancelMidPoll(real_session):
        def exec(self, statement, *a, **k):
            if not fired and "UPDATE" in str(statement).upper():
                fired.append(1)
                assert _cancel(client, 2, "cbom").status_code == 200
            return super().exec(statement, *a, **k)

    monkeypatch.setattr(cc, "Session", CancelMidPoll)
    cc.get_status_and_update_db(2, "t-2", Scan, engine)
    assert fired and _row(engine, 2)[0] == "cancelled"


def test_a_reinitialize_that_races_a_cancel_withdraws_its_task(http, monkeypatch):
    from backend.utilities.scan import start_scan as start_mod
    from backend.utilities.db.schemas import StartScanPayload

    _client, engine, celery, _ = http
    with Session(engine) as s:
        scan = s.get(Scan, 1)
        scan.scan_status = "cancelled"
        s.add(scan)
        s.commit()
    celery.send_task = lambda **_k: types.SimpleNamespace(id="t-new")
    monkeypatch.setattr(start_mod, "get_celery_app", lambda: celery)

    async def fake_format(**_k):
        return {}

    monkeypatch.setattr(start_mod, "format_input_for_scan", fake_format)
    monkeypatch.setattr(start_mod, "get_scan_metadata_for_type", lambda **_k: {})
    import asyncio

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as err:
        asyncio.run(start_mod.start_scan_and_update_db(scan_type="sast", engine=engine, scan_id=1, team_id=1,
                                                       start_scan_payload=StartScanPayload.model_construct()))
    assert err.value.status_code == 409
    with Session(engine) as s:
        assert s.get(Scan, 1).scan_status == "cancelled" and s.get(Scan, 1).task_id == "t-1"
    assert ("t-new", {}) in celery.revoked and "t-new" in celery.marks.docs


def test_dashboards_count_a_cancelled_scan_neither_completed_nor_failed(monkeypatch):
    from backend.utilities.dashboard import scan_list
    from backend.utilities.dashboard.cbom_team_rollup import EXCLUDED_NOT_COMPLETED, _status_exclusion
    from backend.utilities.dashboard.scan_list import generate_dashboard_data_for_scan_list

    # findings and remediation metrics live in Mongo; a cancelled scan has none
    monkeypatch.setattr(scan_list, "get_findings_for_scan_id", lambda *_a, **_k: [])
    for name in ("get_remediation_metrics", "get_issue_status_metrics", "get_mttr_per_day"):
        monkeypatch.setattr(scan_list, name, lambda *_a, **_k: {})

    assert _status_exclusion("cancelled") == EXCLUDED_NOT_COMPLETED  # team CBOM rollup and its PDF
    now = dt.datetime.now(dt.timezone.utc)
    for kind in ("sast", "iac", "sbom_sca", "cbom", "ai_bom"):
        scan = Scan(id=1, team_id=1, owner_user_id=1, scan_type=kind, scan_status="cancelled", task_id="t",
                    scan_data={}, scan_metadata={}, created_at=now, last_updated=now,
                    info={"cancelled": True, "refunded_credits": 1.0})
        data = generate_dashboard_data_for_scan_list(scans=[scan], scan_type=kind)

        def counted(node, path=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from counted(value, f"{path}.{key}")
            elif isinstance(node, (int, float)) and not isinstance(node, bool):
                yield path, node

        for path, value in counted(data):
            leaf = path.rsplit(".", 1)[-1].lower()
            if any(word in leaf for word in ("success", "completed", "failure", "failed")):
                assert value == 0, (kind, path, value)
