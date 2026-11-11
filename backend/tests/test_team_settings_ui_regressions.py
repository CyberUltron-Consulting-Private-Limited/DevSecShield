"""Team settings, as the customer drives them from /<team>/settings, through the real team router on SQLite.

Found on the local production stack (round 5, L1 walkthrough):
* "Add member by email" with "bad email": the API answered 400 but had already stored a user "bad email" with a
  default team of its own (the admin console listed it); now nothing is stored for an address that is not one, nor
  when the invitation mail cannot be sent.
* Emptying the three Jira fields and saving said "Team updated successfully" but kept the integration (the page
  sends "jira": null, which the API ignored); now it removes it, and a ticket request then says Jira is not set up.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_team_settings_ui_regressions.py -q -p no:cacheprovider
"""
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "team-settings-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "team-settings-test-refresh-secret")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.routers import team as team_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth.auth_utils import create_access_token  # noqa: E402
from backend.new_models import TeamInvitation  # noqa: E402
from backend.utilities.auth import email as invite_mail  # noqa: E402

ADMIN = "alice@acme.test"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'team.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(team_router, "get_db", lambda: engine)
    mailed: list[str] = []

    async def fake_mail(email, team_name, inviter, link, expires_on):
        if email.endswith("@relay-down.test"):
            raise HTTPException(status_code=500, detail="Could not send the email through the configured mail relay")
        mailed.append(email)

    monkeypatch.setattr(invite_mail, "send_team_invitation_email", fake_mail)
    ratelimit.reset_all()
    with Session(engine) as s:
        team = Team(name="Acme Security")
        s.add(team)
        s.commit()
        s.refresh(team)
        user = User(email=ADMIN, password="x", first_name="Alice", last_name="C", session_active=True,
                    default_team_id=team.id)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        s.commit()
        team_id = team.id
    yield engine, team_id, mailed
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app)


def auth():
    return {"Authorization": f"Bearer {create_access_token(ADMIN, version=0)}"}


def users(engine) -> set[str]:
    with Session(engine) as s:
        return {u.email for u in s.exec(select(User)).all()}


def team_names(engine) -> set[str]:
    with Session(engine) as s:
        return {t.name for t in s.exec(select(Team)).all()}


@pytest.mark.parametrize("bad", ["bad email", "nobody", "x@", "@acme.test", "a@b", "a@.test", "two@@at.test x"])
def test_an_address_that_is_not_one_stores_nothing(client, world, bad):
    engine, team_id, mailed = world
    before_users, before_teams = users(engine), team_names(engine)
    r = client.patch(f"/team/{team_id}", headers=auth(), json={"intent": "add", "email_ids": [bad]})
    assert r.status_code == 400, r.text
    assert "valid email" in r.json()["detail"]
    assert users(engine) == before_users
    assert team_names(engine) == before_teams
    assert mailed == []


def test_one_bad_address_refuses_the_whole_request_before_anyone_is_created(client, world):
    engine, team_id, mailed = world
    r = client.patch(f"/team/{team_id}", headers=auth(),
                     json={"intent": "add", "email_ids": ["bob@acme.test", "bad email"]})
    assert r.status_code == 400
    assert "bob@acme.test" not in users(engine) and mailed == []


def test_a_mail_relay_failure_leaves_no_account_behind(client, world):
    engine, team_id, mailed = world
    before_users, before_teams = users(engine), team_names(engine)
    r = client.patch(f"/team/{team_id}", headers=auth(), json={"intent": "add", "email_ids": ["carol@relay-down.test"]})
    assert r.status_code == 500
    assert users(engine) == before_users and team_names(engine) == before_teams
    with Session(engine) as s:
        assert s.exec(select(TeamInvitation)).all() == []  # no invitation whose link never went out


def test_a_valid_new_address_is_invited_not_added(client, world):
    """S2 (round 5): adding an address mails an invitation; no account, no membership until the invitee accepts."""
    engine, team_id, mailed = world
    before_users, before_teams = users(engine), team_names(engine)
    r = client.patch(f"/team/{team_id}", headers=auth(), json={"intent": "add", "email_ids": ["  Bob@Acme.TEST "]})
    assert r.status_code == 200, r.text
    assert mailed == ["bob@acme.test"] and r.json()["invited"] == ["bob@acme.test"]
    members = client.get(f"/team/{team_id}", headers=auth()).json()["team_members"]
    assert all(m["email"] != "bob@acme.test" for m in members)
    assert users(engine) == before_users and team_names(engine) == before_teams


def _put(client, team_id, jira):
    return client.put(f"/team/{team_id}", headers=auth(), json={
        "name": "Acme Security", "description": None, "integration_settings": {"jira": jira}})


def test_emptying_the_jira_fields_removes_the_integration(client, world):
    engine, team_id, _ = world
    jira = {"email": ADMIN, "url": "https://acme.atlassian.net", "api_token": "tok-123"}
    assert _put(client, team_id, jira).status_code == 200
    shown = client.get(f"/team/{team_id}", headers=auth()).json()["team_integration_settings"]["jira"]
    assert shown == {"email": ADMIN, "url": jira["url"], "api_token_set": True}  # never the token

    # the settings page saves {"jira": null} when the three fields are empty
    assert _put(client, team_id, None).status_code == 200
    assert client.get(f"/team/{team_id}", headers=auth()).json()["team_integration_settings"]["jira"] is None
    with Session(engine) as s:
        assert s.get(Team, team_id).integration_settings["jira"] is None


def test_saving_the_name_keeps_jira(client, world):
    """The edit dialog sends the team's (masked) settings back; that must keep the stored token."""
    engine, team_id, _ = world
    _put(client, team_id, {"email": ADMIN, "url": "https://acme.atlassian.net", "api_token": "tok-123"})
    masked = client.get(f"/team/{team_id}", headers=auth()).json()["team_integration_settings"]
    r = client.put(f"/team/{team_id}", headers=auth(),
                   json={"name": "Acme Security Team", "description": "d", "integration_settings": masked})
    assert r.status_code == 200
    with Session(engine) as s:
        stored = s.get(Team, team_id).integration_settings["jira"]
    assert stored["url"] == "https://acme.atlassian.net" and stored["api_token"] not in (None, "", "••••••••")


def test_settings_without_a_jira_key_leave_jira_alone(client, world):
    engine, team_id, _ = world
    _put(client, team_id, {"email": ADMIN, "url": "https://acme.atlassian.net", "api_token": "tok-123"})
    r = client.put(f"/team/{team_id}", headers=auth(),
                   json={"name": "Acme Security", "description": None, "integration_settings": {}})
    assert r.status_code == 200
    with Session(engine) as s:
        assert s.get(Team, team_id).integration_settings["jira"]["url"] == "https://acme.atlassian.net"
