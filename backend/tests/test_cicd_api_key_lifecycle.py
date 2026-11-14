"""Issue #99: the CI/CD API key a customer needs for a pipeline.

The key is shown exactly once (the create or rotate answer), stored only as its SHA-256 hash, never returned by the
read routes (not even a prefix of the stored hash, which the UI used to show and copy), can be rotated and revoked by
the integration's owner or a team admin, and a rotated or revoked key stops authenticating at once. Another team's
integration answers 404; a caller outside the team answers 403.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("JWT_SECRET_KEY", "issue99-cicd-key-test-secret-not-for-prod")

from backend.main import app
from backend.new_models import CicdIntegration, Team, TeamMembership, User
from backend.utilities.cicd.auth import (
    get_user_integration_team_from_api_key,
)


class _Cursor(list):
    def sort(self, *_a, **_k):
        return self

    def limit(self, *_a, **_k):
        return self

    def skip(self, *_a, **_k):
        return self


class _NoLogs:
    def find(self, *_a, **_k):
        return _Cursor()

    def count_documents(self, *_a, **_k):
        return 0

    def delete_many(self, *_a, **_k):
        return None


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    from backend.routers import cicd as router

    monkeypatch.setattr("backend.get_db.get_db", lambda: eng)
    monkeypatch.setattr(router, "get_db", lambda: eng)
    monkeypatch.setattr("backend.utilities.cicd.auth.get_db", lambda: eng)
    monkeypatch.setattr(router, "get_mongo_client_db", lambda: {"cicd_logs": _NoLogs()})
    monkeypatch.setattr(router, "get_celery_app", lambda: object())
    monkeypatch.setattr(router, "get_cicd_list_dashboard_data", lambda **_k: {})
    monkeypatch.setattr(router, "get_cicd_vuln_chart_data", lambda **_k: {})
    monkeypatch.setattr(router, "project_cbom_ci_page", lambda _run: None)

    people: dict[str, int] = {}
    with Session(eng) as session:
        team_a, team_b = Team(name="a", credit_balance=10.0), Team(name="b", credit_balance=10.0)
        session.add(team_a)
        session.add(team_b)
        session.commit()
        session.refresh(team_a)
        session.refresh(team_b)
        for name, team, role in (("owner", team_a, "member"), ("admin", team_a, "admin"),
                                 ("member", team_a, "member"), ("outsider", team_b, "admin")):
            user = User(email=f"{name}@example.com", password="x", first_name=name, last_name="u",
                        default_team_id=team.id)
            session.add(user)
            session.commit()
            session.refresh(user)
            session.add(TeamMembership(team_id=team.id, user_id=user.id, role=role))
            session.commit()
            people[name] = user.id
        ids = {"a": team_a.id, "b": team_b.id}

    async def _user(_engine, authorization):
        with Session(eng) as session:
            return session.get(User, people[authorization])

    monkeypatch.setattr(router, "get_user_from_header_or_raise_exception", _user)
    http = TestClient(app)

    def call(method: str, path: str, who: str, **kw):
        return http.request(method, path, headers={"Authorization": who}, **kw)

    yield call, eng, ids


def _create(call, ids, who="owner", kind="cbom"):
    res = call("POST", f"/{ids['a']}/cicd/integration", who, json={"title": "pipeline", "scan_type": kind})
    assert res.status_code == 200, res.text
    return res.json()


def _stored(eng, integration_id: int) -> str:
    with Session(eng) as session:
        return session.get(CicdIntegration, integration_id).api_key


def _authenticates(key: str) -> bool:
    try:
        get_user_integration_team_from_api_key(key)
    except HTTPException as exc:
        assert exc.status_code == 401
        return False
    return True


def test_create_answers_the_plaintext_once_and_stores_only_its_hash(env):
    call, eng, ids = env
    body = _create(call, ids)
    key = body["api_key"]
    assert key.startswith(f"cicd{ids['a']}-") and len(key) > 100
    assert "not be shown again" in body["warning"]
    assert body["api_key_state"] == "active" and body["api_key_hint"] == key[-4:]
    assert _stored(eng, body["integration_id"]) == hashlib.sha256(key.encode()).hexdigest()
    assert _authenticates(key)


def test_read_routes_never_return_the_key_or_any_part_of_its_hash(env):
    call, eng, ids = env
    body = _create(call, ids)
    key, digest = body["api_key"], _stored(eng, body["integration_id"])
    listed = call("GET", f"/{ids['a']}/cicd/integrations", "member")
    got = call("GET", f"/{ids['a']}/cicd/integration/{body['integration_id']}", "member")
    for res in (listed, got):
        assert res.status_code == 200, res.text
        text = res.text
        assert key not in text and key[:-4] not in text
        assert digest[:8] not in text and digest[-4:] not in text  # the old UI copied hash[:8]..hash[-4:]
    row = listed.json()["integrations"][0]
    detail = got.json()
    for item in (row, detail):
        assert item["api_key_state"] == "active"
        assert item["api_key_hint"] == key[-4:]
        assert item["api_key_issued_at"]
        assert item["api_key"] == f"cicd{ids['a']}-…{key[-4:]}"  # a label, never something to paste


def test_rotate_shows_a_new_key_once_and_the_old_key_stops_working(env):
    call, eng, ids = env
    body = _create(call, ids)
    old = body["api_key"]
    res = call("POST", f"/{ids['a']}/cicd/integration/{body['integration_id']}/api-key/rotate", "owner")
    assert res.status_code == 200, res.text
    new = res.json()["api_key"]
    assert new != old and new.startswith(f"cicd{ids['a']}-")
    assert res.json()["api_key_state"] == "active" and res.json()["api_key_hint"] == new[-4:]
    assert "not be shown again" in res.json()["warning"]
    assert _stored(eng, body["integration_id"]) == hashlib.sha256(new.encode()).hexdigest()
    assert not _authenticates(old)
    assert _authenticates(new)
    detail = call("GET", f"/{ids['a']}/cicd/integration/{body['integration_id']}", "owner")
    assert new not in detail.text and detail.json()["api_key_hint"] == new[-4:]


def test_revoke_disables_the_key_until_a_new_one_is_issued(env):
    call, eng, ids = env
    body = _create(call, ids)
    iid, key = body["integration_id"], body["api_key"]
    res = call("DELETE", f"/{ids['a']}/cicd/integration/{iid}/api-key", "admin")
    assert res.status_code == 200, res.text
    assert res.json()["api_key_state"] == "revoked" and "api_key" not in res.json()
    assert not _authenticates(key)
    stored = _stored(eng, iid)
    assert stored.startswith("revoked:")
    assert not _authenticates(stored)  # the marker itself never authenticates (legacy plaintext fallback)
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "member").json()
    assert detail["api_key_state"] == "revoked" and detail["api_key"] == "" and detail["api_key_hint"] is None
    listed = call("GET", f"/{ids['a']}/cicd/integrations", "member").json()["integrations"][0]
    assert listed["api_key_state"] == "revoked"
    # revoking again is idempotent; rotating re-issues a working key
    assert call("DELETE", f"/{ids['a']}/cicd/integration/{iid}/api-key", "admin").status_code == 200
    again = call("POST", f"/{ids['a']}/cicd/integration/{iid}/api-key/rotate", "owner").json()
    assert again["api_key_state"] == "active" and _authenticates(again["api_key"])


def test_the_integration_survives_revoke_with_its_settings(env):
    call, _eng, ids = env
    body = _create(call, ids)
    iid = body["integration_id"]
    jira = {"integration_settings": {"jira": {"jira_project_id": "10001", "auto_create_tickets": True}}}
    assert call("PUT", f"/{ids['a']}/cicd/integration/{iid}", "owner", json=jira).status_code == 200
    call("DELETE", f"/{ids['a']}/cicd/integration/{iid}/api-key", "owner")
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "owner").json()
    assert detail["title"] == "pipeline"
    assert detail["integration_settings"]["jira"]["jira_project_id"] == "10001"
    # a Jira settings save after a rotate keeps the key's record
    rotated = call("POST", f"/{ids['a']}/cicd/integration/{iid}/api-key/rotate", "owner").json()
    assert call("PUT", f"/{ids['a']}/cicd/integration/{iid}", "owner", json=jira).status_code == 200
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "owner").json()
    assert detail["api_key_hint"] == rotated["api_key"][-4:]


@pytest.mark.parametrize("who, allowed", [("owner", True), ("admin", True), ("member", False)])
def test_only_the_owner_or_a_team_admin_rotates_or_revokes(env, who, allowed):
    call, eng, ids = env
    body = _create(call, ids, who="owner")
    iid, key = body["integration_id"], body["api_key"]
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", who).json()
    assert detail["can_manage_api_key"] is allowed
    listed = call("GET", f"/{ids['a']}/cicd/integrations", who).json()["integrations"][0]
    assert listed["can_manage_api_key"] is allowed
    rotate = call("POST", f"/{ids['a']}/cicd/integration/{iid}/api-key/rotate", who)
    revoke = call("DELETE", f"/{ids['a']}/cicd/integration/{iid}/api-key", who)
    if allowed:
        assert rotate.status_code == 200 and revoke.status_code == 200
    else:
        assert rotate.status_code == 403 and revoke.status_code == 403
        assert "api_key" not in rotate.json()
        assert _stored(eng, iid) == hashlib.sha256(key.encode()).hexdigest()
        assert _authenticates(key)


def test_another_teams_integration_is_not_found_and_outsiders_are_refused(env):
    call, _eng, ids = env
    body = _create(call, ids)
    iid, key = body["integration_id"], body["api_key"]
    # the outsider is an admin of team B: team B's path does not reach team A's integration
    for method, suffix in (("POST", "/api-key/rotate"), ("DELETE", "/api-key")):
        res = call(method, f"/{ids['b']}/cicd/integration/{iid}{suffix}", "outsider")
        assert res.status_code == 404, res.text
        res = call(method, f"/{ids['a']}/cicd/integration/{iid}{suffix}", "outsider")
        assert res.status_code == 403, res.text
    assert _authenticates(key)
    assert call("GET", f"/{ids['b']}/cicd/integrations", "outsider").json()["integrations"] == []


def test_a_key_issued_before_this_change_still_works_and_shows_no_hint(env):
    """Rows created before the key record existed: hashed key, no metadata. They stay active and show no hint."""
    call, eng, ids = env
    legacy = f"cicd{ids['a']}-" + "ab" * 64
    with Session(eng) as session:
        owner = session.exec(select(User).where(User.email == "owner@example.com")).one()
        integ = CicdIntegration(team_id=ids["a"], owner_user_id=owner.id, title="old", scan_type="sast",
                                api_key=hashlib.sha256(legacy.encode()).hexdigest())
        session.add(integ)
        session.commit()
        session.refresh(integ)
        iid = integ.id
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "owner").json()
    assert detail["api_key_state"] == "active" and detail["api_key_hint"] is None
    assert detail["api_key"] == f"cicd{ids['a']}-…"
    assert _authenticates(legacy)
    assert json.dumps(detail).find(hashlib.sha256(legacy.encode()).hexdigest()[:8]) == -1
