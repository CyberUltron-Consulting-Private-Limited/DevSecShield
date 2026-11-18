"""last_updated moves when the scan changes, not when a page polls or someone chats.

A list load re-polls every pending or started scan. Writing last_updated on a poll that learned
nothing makes "Updated today" true for a scan that did not change. A chat message is not a change
to the scan either.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
import types
from pathlib import Path

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "last-updated-test-secret-not-for-production-use")

from backend.new_models import Scan, Team, User

STAMP = dt.datetime(2026, 11, 1, 8, 0, tzinfo=dt.timezone.utc)


class _Result:
    def __init__(self, state, info=None):
        self.state, self.result, self.info, self.traceback = state, None, info, None


def _engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(Team(id=1, name="t", credit_balance=10.0))
        session.add(User(id=1, email="a@example.test", password="x", first_name="a", last_name="a",
                         default_team_id=1))
        session.commit()
    return engine


def _stamp(engine, scan_id, status, info=None):
    with Session(engine) as session:
        session.add(Scan(id=scan_id, team_id=1, owner_user_id=1, scan_type="cbom", scan_status=status,
                         task_id=f"t-{scan_id}", created_at=STAMP, last_updated=STAMP, info=info,
                         scan_data={"results": []}))
        session.commit()


def _updated(engine, scan_id):
    with Session(engine) as session:
        value = session.get(Scan, scan_id).last_updated
    # SQLite returns the column without a timezone. Compare the UTC clock time.
    if value is not None and value.tzinfo is not None:
        value = value.replace(tzinfo=None)
    return value


def _stamp_time():
    return STAMP.replace(tzinfo=None)


def test_an_unchanged_pending_poll_leaves_last_updated(monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    engine = _engine()
    _stamp(engine, 1, "pending")
    monkeypatch.setattr(cc, "get_celery_app", lambda: types.SimpleNamespace(AsyncResult=lambda _t: _Result("PENDING")))
    cc.get_status_and_update_db(1, "t-1", Scan, engine)
    cc.get_status_and_update_db(1, "t-1", Scan, engine)
    assert _updated(engine, 1) == _stamp_time()


def test_a_status_change_and_new_progress_move_last_updated(monkeypatch):
    from backend.utilities.celery import celery_connection as cc

    engine = _engine()
    _stamp(engine, 2, "pending")
    state = {"info": {"current": 10}}
    monkeypatch.setattr(cc, "get_celery_app",
                        lambda: types.SimpleNamespace(AsyncResult=lambda _t: _Result("STARTED", state["info"])))
    cc.get_status_and_update_db(2, "t-2", Scan, engine)
    moved = _updated(engine, 2)
    assert moved != _stamp_time()
    with Session(engine) as session:
        row = session.get(Scan, 2)
        assert row.scan_status == "started" and row.info == {"current": 10}
    cc.get_status_and_update_db(2, "t-2", Scan, engine)  # same progress
    assert _updated(engine, 2) == moved
    state["info"] = {"current": 40}
    cc.get_status_and_update_db(2, "t-2", Scan, engine)
    assert _updated(engine, 2) != moved

