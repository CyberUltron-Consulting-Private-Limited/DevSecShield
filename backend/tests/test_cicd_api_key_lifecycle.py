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

from backend.new_models import CicdIntegration, Team, TeamMembership, User  # noqa: E402
from backend.utilities.cicd.auth import get_user_integration_team_from_api_key  # noqa: E402
from backend.main import app  # noqa: E402


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
    yield from _world(monkeypatch, eng)


def _world(monkeypatch: pytest.MonkeyPatch, eng):
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


def test_a_plaintext_stored_legacy_key_is_never_shown_and_rotates_to_a_hash(env):
    """The oldest rows stored the key itself (the path auth's plaintext fallback and its revoked: guard serve)."""
    call, eng, ids = env
    legacy = f"cicd{ids['a']}-" + "cd" * 64
    with Session(eng) as session:
        owner = session.exec(select(User).where(User.email == "owner@example.com")).one()
        integ = CicdIntegration(team_id=ids["a"], owner_user_id=owner.id, title="oldest", scan_type="cbom",
                                api_key=legacy, integration_settings=None)
        session.add(integ)
        session.commit()
        session.refresh(integ)
        iid = integ.id
    assert _authenticates(legacy)
    listed = call("GET", f"/{ids['a']}/cicd/integrations", "member")
    got = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "member")
    for res in (listed, got):
        assert res.status_code == 200, res.text
        for part in (legacy, legacy[:12], legacy[6:30], legacy[-8:]):
            assert part not in res.text
    assert got.json()["api_key_state"] == "active" and got.json()["api_key_hint"] is None
    rotated = call("POST", f"/{ids['a']}/cicd/integration/{iid}/api-key/rotate", "owner").json()
    assert not _authenticates(legacy)
    assert _authenticates(rotated["api_key"])
    assert _stored(eng, iid) == hashlib.sha256(rotated["api_key"].encode()).hexdigest()


def test_the_settings_log_never_carries_the_key_record(env, monkeypatch):
    call, eng, ids = env
    from backend.routers import cicd as router

    printed: list[str] = []
    monkeypatch.setattr(router.console, "print", lambda *a, **_k: printed.append(" ".join(map(str, a))))
    body = _create(call, ids)
    jira = {"integration_settings": {"jira": {"jira_project_id": "10001"}}}
    assert call("PUT", f"/{ids['a']}/cicd/integration/{body['integration_id']}", "owner", json=jira).status_code == 200
    text = "\n".join(printed)
    assert "10001" in text  # the Jira settings are still logged
    assert "cicd_api_key" not in text and "owner@example.com" not in text and body["api_key"][-4:] not in text


# ---------------------------------------------------------------------------------- PostgreSQL: the row lock
PG = os.environ.get("CBOM_TEST_PG_URL")


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL (as in CI)")
def test_a_rotate_during_a_settings_save_waits_and_the_hint_follows_the_new_key(monkeypatch):
    """R-code minor 1: PUT reads integration_settings, merges Jira into it and writes it back. A rotate that commits in
    between used to be overwritten, so the page showed the old key's last 4. Both now take the row FOR UPDATE: the
    rotate waits for the save, then writes its record on top of it."""
    import threading
    import time

    from backend.routers import cicd as router

    eng = create_engine(PG, pool_size=8, max_overflow=4)
    SQLModel.metadata.drop_all(eng)
    SQLModel.metadata.create_all(eng)
    gen = _world(monkeypatch, eng)
    call, _eng, ids = next(gen)
    body = _create(call, ids)
    iid = body["integration_id"]

    read_done, go = threading.Event(), threading.Event()
    real_print = router.console.print

    def paused_print(*a, **k):
        # the PUT logs the merged settings after reading the row and before its commit: hold it open there
        if a and isinstance(a[0], dict) and "jira" in a[0] and not read_done.is_set():
            read_done.set()
            go.wait(10)
        return real_print(*a, **k)

    monkeypatch.setattr(router.console, "print", paused_print)
    out: dict[str, object] = {}
    jira = {"integration_settings": {"jira": {"jira_project_id": "10001"}}}
    put = threading.Thread(target=lambda: out.update(
        put=call("PUT", f"/{ids['a']}/cicd/integration/{iid}", "owner", json=jira)))
    rot = threading.Thread(target=lambda: out.update(
        rot=call("POST", f"/{ids['a']}/cicd/integration/{iid}/api-key/rotate", "admin")))
    put.start()
    assert read_done.wait(10), "the PUT reached its read"
    rot.start()
    time.sleep(1.0)
    rotate_blocked = rot.is_alive()
    go.set()
    put.join(20)
    rot.join(20)
    assert out["put"].status_code == 200 and out["rot"].status_code == 200
    assert rotate_blocked, "the rotate waited for the settings save (row lock)"
    new_key = out["rot"].json()["api_key"]
    detail = call("GET", f"/{ids['a']}/cicd/integration/{iid}", "owner").json()
    assert detail["api_key_hint"] == new_key[-4:], "the hint is the active key's"
    assert detail["integration_settings"]["jira"]["jira_project_id"] == "10001"
    assert _authenticates(new_key) and not _authenticates(body["api_key"])
    eng.dispose()
