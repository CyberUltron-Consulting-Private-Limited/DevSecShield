"""Hermetic DAST profile CRUD + schedule tick."""
from __future__ import annotations

import os
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "dast-auto-test-secret-not-for-prod")

from backend.main import app  # noqa: E402
from backend.new_models import DastScanProfile, Scan, Team, TeamMembership, User  # noqa: E402
from backend.utilities.dast.beat import tick  # noqa: E402
from backend.utilities.dast.schedule import compute_next_run_at  # noqa: E402


_AUTH = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input",
    "xpath_of_password_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input",
    "username": "jsmith",
    "password": "demo123",
    "xpath_of_submit_button": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input",
}


def test_compute_next_run_daily_rolls_forward() -> None:
    from zoneinfo import ZoneInfo

    now = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    nxt = compute_next_run_at("daily", "09:00", None, now=now)
    expected = datetime(2026, 8, 25, 9, 0, tzinfo=ZoneInfo("Asia/Kolkata")).astimezone(timezone.utc)
    assert nxt == expected


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.team.credits.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.dast.dispatch.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.dast.beat.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.dast_profiles.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.dast_profiles.check_if_user_is_in_team", lambda *_a, **_k: None)
    monkeypatch.setattr("backend.utilities.dast.ssrf._resolve_ips", lambda _host: ["23.22.30.252"])

    class _Task:
        id = "task-profile"

    class _App:
        def send_task(self, name, kwargs=None, queue=None):
            return _Task()

        def AsyncResult(self, _id):
            return types.SimpleNamespace(state="PENDING")

    monkeypatch.setattr("backend.utilities.dast.dispatch.get_celery_app", lambda: _App())

    with Session(eng) as session:
        team = Team(name="t", credit_balance=10.0)
        session.add(team)
        session.commit()
        session.refresh(team)
        user = User(email="u@example.com", password="x", first_name="u", last_name="u", default_team_id=team.id)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        session.commit()
        ids = {"team_id": team.id, "user_id": user.id, "engine": eng}

    async def fake_user(*_a, **_k):
        return types.SimpleNamespace(id=ids["user_id"], email="u@example.com")

    monkeypatch.setattr(
        "backend.routers.dast_profiles.get_user_from_header_or_raise_exception",
        fake_user,
    )
    yield TestClient(app), ids


def test_create_profile_redacts_password_on_get(api) -> None:
    http, ids = api
    created = http.post(
        f"/{ids['team_id']}/dast/profiles",
        json={
            "title": "testfire",
            "target_url": "https://demo.testfire.net/index.jsp",
            "auth": _AUTH,
            "scan_speed": "fast",
            "max_urls": 1,
            "consent_ok": True,
            "schedule_kind": "off",
        },
        headers={"Authorization": "Bearer test"},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert "password" not in (body.get("auth") or {})
    assert "demo123" not in created.text
    assert body["auth"]["username"] == "jsmith"
    profile_id = body["id"]
    fetched = http.get(f"/{ids['team_id']}/dast/profiles/{profile_id}", headers={"Authorization": "Bearer test"})
    assert fetched.status_code == 200
    assert "password" not in (fetched.json().get("auth") or {})
    assert "demo123" not in fetched.text


def test_run_now_dispatches(api) -> None:
    http, ids = api
    created = http.post(
        f"/{ids['team_id']}/dast/profiles",
        json={
            "title": "testfire",
            "target_url": "https://demo.testfire.net/index.jsp",
            "auth": _AUTH,
            "scan_speed": "fast",
            "max_urls": 1,
            "consent_ok": True,
        },
        headers={"Authorization": "Bearer test"},
    )
    profile_id = created.json()["id"]
    ran = http.post(
        f"/{ids['team_id']}/dast/profiles/{profile_id}/run",
        headers={"Authorization": "Bearer test"},
    )
    assert ran.status_code == 200, ran.text
    assert ran.json()["scan_id"]
    second = http.post(
        f"/{ids['team_id']}/dast/profiles/{profile_id}/run",
        headers={"Authorization": "Bearer test"},
    )
    assert second.status_code == 409


def test_beat_tick_dispatches_due_profile(api) -> None:
    http, ids = api
    eng = ids["engine"]
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    with Session(eng) as session:
        profile = DastScanProfile(
            team_id=ids["team_id"],
            owner_user_id=ids["user_id"],
            title="sched",
            enabled=True,
            target_url="https://demo.testfire.net/index.jsp",
            allowed_hosts=["demo.testfire.net"],
            auth_encrypted=__import__("backend.utilities.dast.auth_crypto", fromlist=["encrypt_auth"]).encrypt_auth(_AUTH),
            scan_speed="fast",
            max_urls=1,
            consent_ok=True,
            schedule_kind="daily",
            schedule_time="09:00",
            next_run_at=past,
        )
        session.add(profile)
        session.commit()
        session.refresh(profile)
        pid = profile.id
    results = tick(engine=eng, now=datetime.now(timezone.utc))
    assert any(r.status == "started" for r in results)
    with Session(eng) as session:
        scans = session.exec(select(Scan).where(Scan.scan_type == "dast")).all()
        assert len(scans) == 1
        profile = session.get(DastScanProfile, pid)
        assert profile.next_run_at is not None
        nxt = profile.next_run_at
        if nxt.tzinfo is None:
            nxt = nxt.replace(tzinfo=timezone.utc)
        assert nxt > datetime.now(timezone.utc) - timedelta(hours=1)


def test_create_profile_schedule_config_two_times_ist(api) -> None:
    http, ids = api
    created = http.post(
        f"/{ids['team_id']}/dast/profiles",
        json={
            "title": "two-times",
            "target_url": "https://demo.testfire.net/index.jsp",
            "auth": _AUTH,
            "scan_speed": "fast",
            "max_urls": 1,
            "consent_ok": True,
            "schedule_kind": "daily",
            "schedule_config": {"kind": "daily", "times": ["09:00", "21:00"]},
        },
        headers={"Authorization": "Bearer test"},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["schedule_kind"] == "daily"
    assert body["schedule_config"]["times"] == ["09:00", "21:00"]
    assert body["next_run_at"]
    assert "UTC" not in (body.get("schedule_config") or {})


def test_beat_once_disables_after_fire(api) -> None:
    http, ids = api
    eng = ids["engine"]
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    with Session(eng) as session:
        profile = DastScanProfile(
            team_id=ids["team_id"],
            owner_user_id=ids["user_id"],
            title="once",
            enabled=True,
            target_url="https://demo.testfire.net/index.jsp",
            allowed_hosts=["demo.testfire.net"],
            auth_encrypted=__import__("backend.utilities.dast.auth_crypto", fromlist=["encrypt_auth"]).encrypt_auth(_AUTH),
            scan_speed="fast",
            max_urls=1,
            consent_ok=True,
            schedule_kind="once",
            schedule_config={"kind": "once", "once_at": past.isoformat()},
            next_run_at=past,
        )
        session.add(profile)
        session.commit()
        session.refresh(profile)
        pid = profile.id
    tick(engine=eng, now=datetime.now(timezone.utc))
    with Session(eng) as session:
        profile = session.get(DastScanProfile, pid)
        assert profile.schedule_kind == "off"
        assert profile.next_run_at is None
