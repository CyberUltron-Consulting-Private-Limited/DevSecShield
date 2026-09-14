"""Hermetic Jenkins/CI DAST contract: immediate POST, redacted GET, 403 on team mismatch."""
from __future__ import annotations

import os
import sys
import types

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("JWT_SECRET_KEY", "dast-auto-test-secret-not-for-prod")

from backend.new_models import CicdIntegration, DastScanProfile, Scan, Team, User  # noqa: E402
from backend.utilities.cicd.auth import get_user_and_integration_id  # noqa: E402
from backend.utilities.dast.auth_crypto import encrypt_auth  # noqa: E402
from backend.utilities.dast.severity import dast_severity_counts  # noqa: E402
from backend.main import app  # noqa: E402


_AUTH = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input",
    "xpath_of_password_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input",
    "username": "jsmith",
    "password": "demo123",
    "xpath_of_submit_button": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input",
}


def test_severity_counts_high_and_critical() -> None:
    counts = dast_severity_counts(
        {"results": [{"impact": "High"}, {"impact": "Critical"}, {"severity": "low"}]}
    )
    assert counts["high"] == 1
    assert counts["critical"] == 1
    assert counts["low"] == 1


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.team.credits.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.dast.dispatch.get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.cicd.auth.get_db", lambda: eng)
    monkeypatch.setattr("backend.routers.cicd.get_db", lambda: eng)

    class _Task:
        id = "task-cicd"

    class _App:
        def send_task(self, name, kwargs=None, queue=None):
            return _Task()

        def AsyncResult(self, _id):
            return types.SimpleNamespace(state="PENDING")

    monkeypatch.setattr("backend.utilities.dast.dispatch.get_celery_app", lambda: _App())
    monkeypatch.setattr(
        "backend.utilities.dast.ssrf._resolve_ips",
        lambda _host: ["23.22.30.252"],
    )
    inserted: list = []

    def _insert_one(doc):
        inserted.append(doc)
        return types.SimpleNamespace(inserted_id="log1")

    monkeypatch.setattr(
        "backend.routers.cicd.get_mongo_client_db",
        lambda: {"cicd_logs": types.SimpleNamespace(insert_one=_insert_one)},
    )

    with Session(eng) as session:
        team = Team(name="t", credit_balance=10.0)
        other = Team(name="other", credit_balance=10.0)
        session.add(team)
        session.add(other)
        session.commit()
        session.refresh(team)
        session.refresh(other)
        user = User(email="u@example.com", password="x", first_name="u", last_name="u", default_team_id=team.id)
        session.add(user)
        session.commit()
        session.refresh(user)
        integ = CicdIntegration(
            team_id=team.id,
            owner_user_id=user.id,
            api_key="hashed-dast",
            title="ci-dast",
            scan_type="dast",
        )
        sast_integ = CicdIntegration(
            team_id=team.id,
            owner_user_id=user.id,
            api_key="hashed-sast",
            title="ci-sast",
            scan_type="sast",
        )
        session.add(integ)
        session.add(sast_integ)
        session.commit()
        session.refresh(integ)
        session.refresh(sast_integ)
        profile = DastScanProfile(
            team_id=team.id,
            owner_user_id=user.id,
            title="testfire",
            enabled=True,
            target_url="https://demo.testfire.net/index.jsp",
            allowed_hosts=["demo.testfire.net"],
            auth_encrypted=encrypt_auth(_AUTH),
            scan_speed="fast",
            max_urls=1,
            consent_ok=True,
            schedule_kind="off",
        )
        session.add(profile)
        session.commit()
        session.refresh(profile)
        ids = {
            "team_id": team.id,
            "other_team_id": other.id,
            "user_id": user.id,
            "integration_id": integ.id,
            "sast_integration_id": sast_integ.id,
            "profile_id": profile.id,
            "engine": eng,
            "inserted": inserted,
        }

    def _auth():
        return {
            "user_id": ids["user_id"],
            "integration_id": ids["integration_id"],
            "team_id": ids["team_id"],
            "scan_type": "dast",
        }

    app.dependency_overrides[get_user_and_integration_id] = _auth
    yield TestClient(app), ids
    app.dependency_overrides.clear()


def test_cicd_post_returns_immediately_with_scan_id(client) -> None:
    http, ids = client
    response = http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]})
    assert response.status_code in (200, 202)
    body = response.json()
    assert body.get("scan_id")
    assert body.get("task_id") == "task-cicd"
    assert body.get("status") == "started"


def test_cicd_get_redacts_password(client) -> None:
    http, ids = client
    posted = http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]})
    scan_id = posted.json()["scan_id"]
    with Session(ids["engine"]) as session:
        scan = session.get(Scan, scan_id)
        scan.scan_status = "success"
        scan.scan_data = {"results": [{"impact": "Low"}]}
        session.add(scan)
        session.commit()
    response = http.get(f"/cicd/dast/scan/{scan_id}")
    assert response.status_code == 200
    blob = response.json()
    meta = blob.get("scan_metadata") or {}
    assert "password" not in (meta.get("auth") or {})
    assert "demo123" not in response.text


def test_cicd_log_uses_int_integration_id(client) -> None:
    http, ids = client
    response = http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]})
    assert response.status_code in (200, 202)
    assert ids["inserted"]
    assert ids["inserted"][0]["ci_cd_integration_id"] == ids["integration_id"]
    assert isinstance(ids["inserted"][0]["ci_cd_integration_id"], int)
    assert ids["inserted"][0]["scan_settings_metadata"]["scan_type"] == "dast"


def test_cicd_team_mismatch_is_403(client, monkeypatch: pytest.MonkeyPatch) -> None:
    http, ids = client

    def _other():
        return {
            "user_id": ids["user_id"],
            "integration_id": ids["integration_id"],
            "team_id": ids["other_team_id"],
            "scan_type": "dast",
        }

    app.dependency_overrides[get_user_and_integration_id] = _other
    response = http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]})
    assert response.status_code == 403


def test_sast_key_cannot_start_dast_scan(client) -> None:
    http, ids = client

    def _sast():
        return {
            "user_id": ids["user_id"],
            "integration_id": ids["sast_integration_id"],
            "team_id": ids["team_id"],
            "scan_type": "sast",
        }

    app.dependency_overrides[get_user_and_integration_id] = _sast
    response = http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]})
    assert response.status_code == 403
    assert "not a DAST" in (response.json().get("detail") or "")
    get_resp = http.get("/cicd/dast/scan/1")
    assert get_resp.status_code == 403


def test_dast_key_cannot_start_sast_zip_scan(client) -> None:
    http, _ids = client
    response = http.post(
        "/cicd/sast/scan",
        files={"zip_file": ("proj.zip", b"PK\x03\x04not-a-real-zip", "application/zip")},
    )
    assert response.status_code == 403
    assert "DAST-only" in (response.json().get("detail") or "")
