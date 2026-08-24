"""Hermetic DAST auto-dispatch: sqlite, mocked Celery, no live crawl."""
from __future__ import annotations

import os
import sys
import types
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "dast-auto-test-secret-not-for-prod")

from backend.new_models import DastScanProfile, Scan, Team, User  # noqa: E402
from backend.utilities.dast.auth_crypto import encrypt_auth  # noqa: E402
from backend.utilities.dast.credits import credits_for_auto_dast  # noqa: E402
from backend.utilities.dast.dispatch import DispatchResult, run_dast_from_profile  # noqa: E402


_AUTH = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input",
    "xpath_of_password_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input",
    "username": "jsmith",
    "password": "demo123",
    "xpath_of_submit_button": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input",
}


@pytest.fixture()
def engine(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.team.credits.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.dast.dispatch.get_db", lambda: eng)
    return eng


def _seed(eng, *, inflight_scan_id=None, consent_ok=True, credits=10.0, target="https://demo.testfire.net/index.jsp"):
    with Session(eng) as session:
        team = Team(name="t", credit_balance=credits)
        session.add(team)
        session.commit()
        session.refresh(team)
        user = User(email="u@example.com", password="x", first_name="u", last_name="u", default_team_id=team.id)
        session.add(user)
        session.commit()
        session.refresh(user)
        profile = DastScanProfile(
            team_id=team.id,
            owner_user_id=user.id,
            title="testfire",
            enabled=True,
            target_url=target,
            allowed_hosts=["demo.testfire.net"],
            auth_encrypted=encrypt_auth(_AUTH),
            scan_speed="fast",
            max_urls=1,
            consent_ok=consent_ok,
            inflight_scan_id=inflight_scan_id,
            schedule_kind="off",
        )
        session.add(profile)
        session.commit()
        session.refresh(profile)
        return team.id, user.id, profile.id


def test_credits_for_auto_dast_is_max_urls_times_rate() -> None:
    assert credits_for_auto_dast(1) == 0.08
    assert credits_for_auto_dast(100) == 8.0


def test_dispatch_creates_scan_deducts_credits_and_sends_task(engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "backend.utilities.dast.ssrf._resolve_ips",
        lambda _host: ["23.22.30.252"],
    )
    sent = {}

    class _Task:
        id = "task-abc"

    class _App:
        def send_task(self, name, kwargs=None, queue=None):
            sent["name"] = name
            sent["kwargs"] = kwargs
            sent["queue"] = queue
            return _Task()

        def AsyncResult(self, _id):
            return types.SimpleNamespace(state="PENDING")

    monkeypatch.setattr("backend.utilities.dast.dispatch.get_celery_app", lambda: _App())

    team_id, user_id, profile_id = _seed(engine)
    result = run_dast_from_profile(profile_id, trigger="schedule", engine=engine)

    assert result.status == "started"
    assert result.scan_id is not None
    assert sent["name"] == "dast_worker.dast"
    assert sent["queue"] == "dast_worker_queue"
    assert sent["kwargs"]["dast_dict_context"]["auth"]["password"] == "demo123"

    with Session(engine) as session:
        scan = session.get(Scan, result.scan_id)
        assert scan.scan_type == "dast"
        assert scan.credit_consumed == 0.08
        assert scan.task_id == "task-abc"
        meta = scan.scan_metadata or {}
        assert "password" not in (meta.get("auth") or {})
        assert meta.get("trigger") == "schedule"
        assert meta.get("profile_id") == profile_id
        team = session.get(Team, team_id)
        assert team.credit_balance == pytest.approx(9.92)
        profile = session.get(DastScanProfile, profile_id)
        assert profile.inflight_scan_id == scan.id
        assert profile.last_scan_id == scan.id


def test_dispatch_skips_when_inflight(engine) -> None:
    team_id, user_id, profile_id = _seed(engine)
    with Session(engine) as session:
        scan = Scan(
            team_id=team_id,
            owner_user_id=user_id,
            scan_type="dast",
            title="running",
            scan_status="started",
            task_id="busy",
            credit_consumed=0.08,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        profile = session.get(DastScanProfile, profile_id)
        profile.inflight_scan_id = scan.id
        session.add(profile)
        session.commit()

    result = run_dast_from_profile(profile_id, trigger="schedule", engine=engine)
    assert result.status == "skipped_in_flight"
    assert result.scan_id is None
    with Session(engine) as session:
        scans = session.exec(select(Scan)).all()
        assert len(scans) == 1


def test_dispatch_requires_consent(engine) -> None:
    _tid, _uid, profile_id = _seed(engine, consent_ok=False)
    with pytest.raises(Exception, match="consent"):
        run_dast_from_profile(profile_id, trigger="manual", engine=engine)
