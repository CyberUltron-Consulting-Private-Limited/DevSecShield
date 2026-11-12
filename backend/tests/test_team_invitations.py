"""Team invitations, the forced password change for accounts the old flow made, and write-only Jira secrets.

Found by the round-5 customer walkthrough (X1, Nov 11): adding any address to a team created an account for it and
mailed it a plaintext password ("Credentials for team membership", footer "(c) 2024"); there was no accept step,
no consent and no forced password change.  Now (integrator's decisions, S2):
* adding an address mails a single-use, hashed, 7-day link to /invite/<token> naming the team and the inviter;
* a new address chooses its own password there; an existing account signs in as the address and accepts or
  declines; nobody joins before accepting;
* admins list pending invitations and can resend (old link dies) or revoke; non-admins cannot invite;
* accounts the old flow made must choose a new password at their next sign-in (migration rv6s2invite001);
* the mail footer shows the current year; GET /team never returns the Jira token (only api_token_set).

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_team_invitations.py -q -p no:cacheprovider
"""
import asyncio
import concurrent.futures
import datetime as dt
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "team-invitations-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "team-invitations-test-refresh-secret")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import Team, TeamInvitation, TeamMembership, User  # noqa: E402
from backend.routers import admin as admin_router  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.routers import invitations as invitations_router  # noqa: E402
from backend.routers import team as team_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.auth import email as invite_mail  # noqa: E402
from backend.utilities.auth.auth_utils import create_access_token, get_hashed_password  # noqa: E402
from backend.utilities.auth.html_email import create_verification_email_html  # noqa: E402
from backend.utilities.team import invitations  # noqa: E402

ADMIN = "alice@acme.test"
MEMBER = "mallory@acme.test"
OUTSIDER = "olga@other.test"
BOB = "bob@corp.test"  # has an account, not in the team
PASSWORD = "Correct-Horse-Battery-9"
NEW_PASSWORD = "Brand-New-Choice-42"


class Mailbox:
    def __init__(self):
        self.mails: list[dict] = []

    def last(self, to: str) -> dict:
        return [m for m in self.mails if m["to"] == to][-1]

    def token(self, to: str) -> str:
        return re.search(r"/invite/([0-9a-f]{64})", self.last(to)["html"]).group(1)


def _user(s: Session, email: str, password: str = PASSWORD, **extra) -> User:
    team = Team(name=f"{email} default")
    s.add(team)
    s.commit()
    s.refresh(team)
    user = User(email=email, password=get_hashed_password(password), first_name="F", last_name="L", profile_photo=None,
                session_active=True, default_team_id=team.id, **extra)
    s.add(user)
    s.commit()
    s.refresh(user)
    s.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
    s.commit()
    return user


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'inv.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    for module in (team_router, invitations_router, auth_router, admin_router):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    box = Mailbox()

    async def capture(recipient_email, subject, body=None, html_body=None, custom_domain=None):
        if recipient_email.endswith("@relay-down.test"):
            raise RuntimeError("relay down")
        box.mails.append({"to": recipient_email, "subject": subject, "html": html_body})

    monkeypatch.setattr(invite_mail, "send_outlook_email", capture)  # the real template, a fake relay
    codes: dict[str, str] = {}
    monkeypatch.setattr(auth_router, "send_verification_email", lambda email, code: codes.__setitem__(email, code))
    monkeypatch.setenv("CBOM_PUBLIC_APP_URL", "https://devsec.example.test/")
    ratelimit.reset_all()
    with Session(engine) as s:
        team = Team(name='Acme <b>"Security"</b>')
        s.add(team)
        s.commit()
        s.refresh(team)
        ids = {"team": team.id}
        for email, role in ((ADMIN, "admin"), (MEMBER, "member")):
            u = _user(s, email)
            s.add(TeamMembership(team_id=team.id, user_id=u.id, role=role))
            s.commit()
        other = _user(s, OUTSIDER)
        ids["other_team"] = other.default_team_id
        ids["bob"] = _user(s, BOB).id
    yield engine, ids, box, codes
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app)


def auth(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email, version=0)}"}


def invite(client, team_id, *emails, who=ADMIN):
    return client.patch(f"/team/{team_id}", headers=auth(who), json={"intent": "add", "email_ids": list(emails)})


def members(engine, team_id) -> set[str]:
    with Session(engine) as s:
        rows = s.exec(select(TeamMembership).where(TeamMembership.team_id == team_id)).all()
        return {s.get(User, m.user_id).email for m in rows}


def all_users(engine) -> set[str]:
    with Session(engine) as s:
        return {u.email for u in s.exec(select(User)).all()}


def row(engine, team_id, email) -> TeamInvitation:
    with Session(engine) as s:
        return s.exec(select(TeamInvitation).where(TeamInvitation.team_id == team_id,
                                                   TeamInvitation.email == email)).first()


# ---------------------------------------------------------------------------------------------- create + mail

def test_adding_a_new_address_mails_a_link_and_creates_nothing_else(client, world):
    engine, ids, box, _ = world
    before = all_users(engine)
    r = invite(client, ids["team"], " Newbie@Corp.TEST ")
    assert r.status_code == 200, r.text
    assert r.json()["invited"] == ["newbie@corp.test"]
    assert all_users(engine) == before and "newbie@corp.test" not in members(engine, ids["team"])
    mail = box.last("newbie@corp.test")
    token = box.token("newbie@corp.test")
    assert f"https://devsec.example.test/invite/{token}" in mail["html"]
    stored = row(engine, ids["team"], "newbie@corp.test")
    assert stored.status == "pending" and stored.token_hash == invitations.token_hash(token) and token not in stored.token_hash
    assert dt.timedelta(days=6, hours=23) < stored.expires_at - invitations.utcnow() <= dt.timedelta(days=7)
    assert stored.invited_by_user_id is not None


def test_the_invitation_mail_names_team_and_inviter_and_never_carries_a_password(client, world):
    engine, ids, box, _ = world
    assert invite(client, ids["team"], "newbie@corp.test").status_code == 200
    mail = box.last("newbie@corp.test")
    html = mail["html"]
    assert "password" not in html.lower() and "credential" not in html.lower()
    assert "password" not in mail["subject"].lower() and "Acme" not in mail["subject"]  # team names stay out of headers
    assert ADMIN in html
    assert "Acme &lt;b&gt;&quot;Security&quot;&lt;/b&gt;" in html and "<b>\"Security\"" not in html  # escaped
    assert_this_years_brand(html, box.token("newbie@corp.test"))
    year = dt.datetime.now(dt.timezone.utc).year
    assert f"&copy; {year} Cyberultron Consulting Pvt Ltd" in create_verification_email_html("123456")


def assert_this_years_brand(html: str, token: str) -> None:
    """Same brand, this year, and no trace of the old "(c) 2024" mail. The mail carries a random 64-hex invite token
    (twice), which itself contains "2024" about once in 1,000 mails: look at everything but the token."""
    year = dt.datetime.now(dt.timezone.utc).year
    assert f"&copy; {year} Cyberultron Consulting Pvt Ltd" in html
    assert "2024" not in html.replace(token, "<token>")


def test_the_year_check_ignores_a_random_token_that_contains_2024(client, world, monkeypatch):
    """F-CI-FLAKE-2: CI failed when the random token happened to contain 2024 (run 43267781895, job 131356201412)."""
    engine, ids, box, _ = world
    token = "2024".ljust(64, "a")

    def forced():
        return token, invitations.token_hash(token)

    monkeypatch.setattr(invitations, "new_token", forced)
    assert invite(client, ids["team"], "newbie@corp.test").status_code == 200
    html = box.last("newbie@corp.test")["html"]
    assert box.token("newbie@corp.test") == token and html.count(token) == 2  # the link and its text
    assert_this_years_brand(html, token)


def test_a_relay_failure_keeps_no_invitation(client, world):
    engine, ids, box, _ = world
    r = invite(client, ids["team"], "carol@relay-down.test")
    assert r.status_code == 500
    assert row(engine, ids["team"], "carol@relay-down.test") is None


def test_existing_member_and_live_invitation_are_refused(client, world):
    engine, ids, box, _ = world
    assert invite(client, ids["team"], MEMBER).status_code == 400
    assert invite(client, ids["team"], ADMIN).status_code == 400
    assert invite(client, ids["team"], "newbie@corp.test").status_code == 200
    again = invite(client, ids["team"], "NEWBIE@corp.test")
    assert again.status_code == 409 and "Resend" in again.json()["detail"]
    assert len([m for m in box.mails if m["to"] == "newbie@corp.test"]) == 1


# ---------------------------------------------------------------------------------------------- new address

def test_a_new_address_chooses_its_password_and_joins(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], "newbie@corp.test")
    token = box.token("newbie@corp.test")
    shown = client.get(f"/invitations/{token}").json()
    assert shown["email"] == "newbie@corp.test" and shown["account_exists"] is False
    assert shown["invited_by"] == ADMIN and shown["team_name"] == 'Acme <b>"Security"</b>'
    weak = client.post(f"/invitations/{token}/register", json={"first_name": "N", "last_name": "B", "password": "short"})
    assert weak.status_code == 422 and "short" not in weak.text  # rules as on sign-up; nothing echoed, link kept
    r = client.post(f"/invitations/{token}/register", json={"first_name": "Nia", "last_name": "B", "password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["team_id"] == ids["team"] and body["access_token"] and body["refresh_token"]
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "newbie@corp.test")).one()
        assert user.password.startswith("$argon2id$") and auth_utils.verify_password(NEW_PASSWORD, user.password)
        assert user.must_change_password is False
        role = s.exec(select(TeamMembership).where(TeamMembership.team_id == ids["team"],
                                                   TeamMembership.user_id == user.id)).one().role
    assert role == "member"
    assert client.get(f"/team/{ids['team']}", headers={"Authorization": f"Bearer {body['access_token']}"}).status_code == 200
    # single use
    assert client.get(f"/invitations/{token}").status_code == 404
    assert client.post(f"/invitations/{token}/register",
                       json={"first_name": "X", "last_name": "Y", "password": NEW_PASSWORD}).status_code == 404


def test_register_is_refused_for_an_address_that_has_an_account(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    token = box.token(BOB)
    assert client.get(f"/invitations/{token}").json()["account_exists"] is True
    r = client.post(f"/invitations/{token}/register", json={"first_name": "B", "last_name": "B", "password": NEW_PASSWORD})
    assert r.status_code == 409
    with Session(engine) as s:
        assert auth_utils.verify_password(PASSWORD, s.get(User, ids["bob"]).password)  # never overwritten


def test_two_simultaneous_registrations_with_one_link_make_one_account(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], "racer@corp.test")
    token = box.token("racer@corp.test")

    def go(_):
        return asyncio.run(invitations.register(token, NEW_PASSWORD, "R", "R", engine))

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda i: _safe(go, i), range(2)))
    assert sorted(type(r).__name__ for r in results) == ["HTTPException", "tuple"]
    with Session(engine) as s:
        assert len(s.exec(select(User).where(User.email == "racer@corp.test")).all()) == 1


def _safe(fn, arg):
    try:
        return fn(arg)
    except Exception as e:  # noqa: BLE001
        return e


def test_a_new_address_can_decline_with_the_link(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], "nope@corp.test")
    token = box.token("nope@corp.test")
    assert client.post(f"/invitations/{token}/decline").status_code == 200
    assert row(engine, ids["team"], "nope@corp.test").status == "declined"
    assert client.post(f"/invitations/{token}/register",
                       json={"first_name": "N", "last_name": "B", "password": NEW_PASSWORD}).status_code == 404
    assert "nope@corp.test" not in all_users(engine)


# ---------------------------------------------------------------------------------------------- existing account

def test_an_existing_account_must_sign_in_as_the_address_then_accepts(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    token = box.token(BOB)
    assert BOB not in members(engine, ids["team"])
    assert client.post(f"/invitations/{token}/accept").status_code == 401
    wrong = client.post(f"/invitations/{token}/accept", headers=auth(OUTSIDER))
    assert wrong.status_code == 403 and BOB in wrong.json()["detail"]
    assert client.post(f"/invitations/{token}/decline").status_code == 401  # an account declines signed in
    assert client.post(f"/invitations/{token}/decline", headers=auth(OUTSIDER)).status_code == 403
    assert BOB not in members(engine, ids["team"])
    ok = client.post(f"/invitations/{token}/accept", headers=auth(BOB))
    assert ok.status_code == 200 and ok.json()["team_id"] == ids["team"]
    assert BOB in members(engine, ids["team"])
    assert client.post(f"/invitations/{token}/accept", headers=auth(BOB)).status_code == 404  # works once


def test_an_existing_account_declines_and_does_not_join(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    token = box.token(BOB)
    assert client.post(f"/invitations/{token}/decline", headers=auth(BOB)).status_code == 200
    assert BOB not in members(engine, ids["team"])
    assert client.post(f"/invitations/{token}/accept", headers=auth(BOB)).status_code == 404
    listed = client.get(f"/team/{ids['team']}/invitations", headers=auth(ADMIN)).json()["invitations"]
    assert [(i["email"], i["status"]) for i in listed] == [(BOB, "declined")]


def test_an_expired_link_is_refused(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    token = box.token(BOB)
    with Session(engine) as s:
        inv = s.exec(select(TeamInvitation)).one()
        inv.expires_at = invitations.utcnow() - dt.timedelta(seconds=1)
        s.add(inv)
        s.commit()
    assert client.get(f"/invitations/{token}").status_code == 410
    assert client.post(f"/invitations/{token}/accept", headers=auth(BOB)).status_code == 410
    assert BOB not in members(engine, ids["team"])
    listed = client.get(f"/team/{ids['team']}/invitations", headers=auth(ADMIN)).json()["invitations"]
    assert listed[0]["status"] == "expired"
    assert invite(client, ids["team"], BOB).status_code == 200  # an expired one can be sent again


@pytest.mark.parametrize("bad", ["", "x", "g" * 64, "A" * 64, "0" * 63, "../../etc"])
def test_malformed_tokens_are_404(client, world, bad):
    assert client.get(f"/invitations/{bad}").status_code in (404, 405)
    assert client.post(f"/invitations/{bad}/decline").status_code in (404, 405)


# ---------------------------------------------------------------------------------------------- admin tools

def test_resend_replaces_the_link_and_revoke_kills_it(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    first = box.token(BOB)
    inv_id = client.get(f"/team/{ids['team']}/invitations", headers=auth(ADMIN)).json()["invitations"][0]["id"]
    r = client.post(f"/team/{ids['team']}/invitations/{inv_id}/resend", headers=auth(ADMIN))
    assert r.status_code == 200, r.text
    second = box.token(BOB)
    assert second != first
    assert client.get(f"/invitations/{first}").status_code == 404
    assert client.get(f"/invitations/{second}").status_code == 200
    assert client.delete(f"/team/{ids['team']}/invitations/{inv_id}", headers=auth(ADMIN)).status_code == 200
    assert client.get(f"/invitations/{second}").status_code == 404
    assert client.post(f"/invitations/{second}/accept", headers=auth(BOB)).status_code == 404
    assert client.get(f"/team/{ids['team']}/invitations", headers=auth(ADMIN)).json()["invitations"] == []
    assert BOB not in members(engine, ids["team"])


def test_only_this_teams_admins_manage_invitations(client, world):
    engine, ids, box, _ = world
    invite(client, ids["team"], BOB)
    inv_id = client.get(f"/team/{ids['team']}/invitations", headers=auth(ADMIN)).json()["invitations"][0]["id"]
    # a member who is not an admin
    assert invite(client, ids["team"], "x@corp.test", who=MEMBER).status_code == 403
    assert client.get(f"/team/{ids['team']}/invitations", headers=auth(MEMBER)).status_code == 403
    assert client.post(f"/team/{ids['team']}/invitations/{inv_id}/resend", headers=auth(MEMBER)).status_code == 403
    assert client.delete(f"/team/{ids['team']}/invitations/{inv_id}", headers=auth(MEMBER)).status_code == 403
    # another team's admin: not in this team, and this team's invitation is not found under their team
    assert client.get(f"/team/{ids['team']}/invitations", headers=auth(OUTSIDER)).status_code == 403
    assert client.post(f"/team/{ids['other_team']}/invitations/{inv_id}/resend", headers=auth(OUTSIDER)).status_code == 404
    assert client.delete(f"/team/{ids['other_team']}/invitations/{inv_id}", headers=auth(OUTSIDER)).status_code == 404
    assert row(engine, ids["team"], BOB).status == "pending"
    assert "x@corp.test" not in [m["to"] for m in box.mails]


def test_deleting_the_team_deletes_its_invitations(client, world):
    engine, ids, box, _ = world
    with Session(engine) as s:
        team = Team(name="Temp")
        s.add(team)
        s.commit()
        s.refresh(team)
        admin_id = s.exec(select(User).where(User.email == ADMIN)).one().id
        s.add(TeamMembership(team_id=team.id, user_id=admin_id, role="admin"))
        s.commit()
        temp = team.id
    invite(client, temp, BOB)
    token = box.token(BOB)
    monkey_mongo = {"message_log": _Coll(), "active_context": _Coll(), "cicd_logs": _Coll(), "guardrails_logs": _Coll()}
    team_router.get_mongo_client_db = lambda: monkey_mongo  # restored by module reload in other tests is not needed
    try:
        assert client.delete(f"/team/{temp}", headers=auth(ADMIN)).status_code == 200
    finally:
        from backend.get_db import get_mongo_client_db
        team_router.get_mongo_client_db = get_mongo_client_db
    with Session(engine) as s:
        assert s.exec(select(TeamInvitation).where(TeamInvitation.team_id == temp)).all() == []
    assert client.get(f"/invitations/{token}").status_code == 404


class _Coll:
    def delete_many(self, *_a, **_k):
        return type("R", (), {"deleted_count": 0})()


# ---------------------------------------------------------------------------------------------- forced change

def _login(client, codes, email, password):
    assert client.post("/send_code", json={"email": email}).status_code == 200
    return client.post("/login", json={"email": email, "password": password, "verification_code": codes[email]})


def test_an_account_with_a_mailed_password_must_choose_a_new_one_at_sign_in(client, world):
    engine, ids, box, codes = world
    with Session(engine) as s:
        _user(s, "old@corp.test", must_change_password=True)
    r = _login(client, codes, "old@corp.test", PASSWORD)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["password_change_required"] is True and "access_token" not in body and "refresh_token" not in body
    change = body["change_token"]
    # the change token is not a session
    assert client.get("/get_user", headers={"Authorization": f"Bearer {change}"}).status_code == 401
    same = client.post("/change_password", json={"change_token": change, "password": PASSWORD})
    assert same.status_code == 400 and "different" in same.json()["detail"]
    weak = client.post("/change_password", json={"change_token": change, "password": "short"})
    assert weak.status_code == 422
    ok = client.post("/change_password", json={"change_token": change, "password": NEW_PASSWORD})
    assert ok.status_code == 200, ok.text
    tokens = ok.json()
    assert client.get("/get_user", headers={"Authorization": f"Bearer {tokens['access_token']}"}).status_code == 200
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "old@corp.test")).one()
        assert user.must_change_password is False and user.token_version == 1
    assert client.post("/change_password", json={"change_token": change, "password": "Another-One-77"}).status_code == 400
    assert _login(client, codes, "old@corp.test", PASSWORD).status_code == 400  # the mailed password is gone
    again = _login(client, codes, "old@corp.test", NEW_PASSWORD)
    assert again.status_code == 200 and again.json().get("access_token")


def test_a_reset_also_clears_the_flag(client, world):
    engine, ids, box, codes = world
    with Session(engine) as s:
        _user(s, "old2@corp.test", must_change_password=True)
    assert client.post("/send_code", json={"email": "old2@corp.test"}).status_code == 200
    r = client.post("/reset_password", json={"email": "old2@corp.test", "verification_code": codes["old2@corp.test"],
                                              "password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    assert _login(client, codes, "old2@corp.test", NEW_PASSWORD).json().get("access_token")


def test_a_forged_or_foreign_change_token_is_refused(client, world):
    engine, ids, box, codes = world
    access = create_access_token("old3@corp.test", version=0)
    with Session(engine) as s:
        _user(s, "old3@corp.test", must_change_password=True)
    assert client.post("/change_password", json={"change_token": access, "password": NEW_PASSWORD}).status_code == 400
    plain = auth_utils.create_password_change_token(ADMIN, 0)  # an account without the flag
    assert client.post("/change_password", json={"change_token": plain, "password": NEW_PASSWORD}).status_code == 400


def _migration():
    path = _REPO_ROOT / "prod_database_migrations/migrations/versions/rv6s2invite001_team_invitations.py"
    spec = importlib.util.spec_from_file_location("rv6s2invite001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_migration_flags_exactly_the_accounts_the_old_invite_flow_made(world):
    engine, ids, box, _ = world
    m = _migration()
    assert m.revision.startswith("rv6s2") and m.down_revision == "wp8b0agent001"
    with Session(engine) as s:
        for email, first, last, team_name, desc in (
            ("x1b@agents.dss.test", "x1b", "user", "x1b's Default Team", "Default team for x1b"),  # old flow
            ("Kim@Corp.test", "Kim", "user", "Kim's Default Team", "Default team for Kim"),        # old flow, any case
            ("sam@corp.test", "Sam", "Lee", "Sam's Default Team", "Default team for Sam"),          # sign-up
            ("joe@corp.test", "joe", "Smith", "joe's Default Team", "Default team for joe"),        # sign-up
            ("ann@corp.test", "ann", "user", "Ann's team", "Default team for ann"),                 # renamed team
        ):
            team = Team(name=team_name, description=desc)
            s.add(team)
            s.commit()
            s.refresh(team)
            s.add(User(email=email, password="x", first_name=first, last_name=last, profile_photo=None,
                       default_team_id=team.id))
            s.commit()
    with engine.connect() as conn:
        flagged = m.old_invite_flow_user_ids(conn)
    with Session(engine) as s:
        emails = {s.get(User, i).email for i in flagged}
    assert emails == {"x1b@agents.dss.test", "Kim@Corp.test"}


# ---------------------------------------------------------------------------------------------- secrets

def _set_jira(client, team_id, token="tok-SECRET-123", url="https://acme.atlassian.net", email=ADMIN):
    return client.put(f"/team/{team_id}", headers=auth(ADMIN), json={
        "name": "Acme", "description": None,
        "integration_settings": {"jira": {"email": email, "url": url, "api_token": token}}})


def test_no_member_ever_reads_the_jira_token(client, world):
    engine, ids, box, _ = world
    assert _set_jira(client, ids["team"]).status_code == 200
    with Session(engine) as s:
        ciphertext = s.get(Team, ids["team"]).integration_settings["jira"]["api_token"]
    for who in (MEMBER, ADMIN):
        for path in (f"/team/{ids['team']}", "/teams", f"/team/{ids['team']}/dashboard"):
            r = client.get(path, headers=auth(who))
            if r.status_code != 200:
                continue
            text = json.dumps(r.json())
            assert "tok-SECRET-123" not in text and ciphertext not in text and "api_token\"" not in text, (who, path)
    shown = client.get(f"/team/{ids['team']}", headers=auth(MEMBER)).json()["team_integration_settings"]["jira"]
    assert shown == {"email": ADMIN, "url": "https://acme.atlassian.net", "api_token_set": True}
    r = client.put(f"/team/{ids['team']}", headers=auth(MEMBER), json={"name": "x", "integration_settings": {"jira": None}})
    assert r.status_code == 403


def test_an_empty_token_field_keeps_the_token_only_for_the_same_site(client, world):
    engine, ids, box, _ = world
    _set_jira(client, ids["team"])
    with Session(engine) as s:
        before = s.get(Team, ids["team"]).integration_settings["jira"]["api_token"]
    assert _set_jira(client, ids["team"], token="").status_code == 200  # left empty: kept
    with Session(engine) as s:
        assert s.get(Team, ids["team"]).integration_settings["jira"]["api_token"] == before
    moved = _set_jira(client, ids["team"], token="", url="https://attacker.example")
    assert moved.status_code == 400 and "Re-enter" in moved.json()["detail"]
    assert _set_jira(client, ids["team"], token="", email="other@acme.test").status_code == 400
    with Session(engine) as s:
        assert s.get(Team, ids["team"]).integration_settings["jira"]["url"] == "https://acme.atlassian.net"
    assert _set_jira(client, ids["team"], token="new-token", url="https://acme2.atlassian.net").status_code == 200


# ---------------------------------------------------------------------------------------------- admin-created accounts

ADMIN_TEMP = "Admin-Chosen-Temp-77"


def _superuser(engine) -> dict:
    with Session(engine) as s:
        _user(s, "root@acme.test", is_superuser=True)
    return auth("root@acme.test")


def test_an_admin_created_account_gets_a_link_never_a_password(client, world):
    """Follow-up to S2: POST /admin/create_admin_user mailed "Your password is: <the admin's choice>"."""
    engine, ids, box, codes = world
    r = client.post("/admin/create_admin_user", headers=_superuser(engine),
                    json={"email": " New.Admin@Acme.test ", "password": ADMIN_TEMP, "first_name": "N", "last_name": "A"})
    assert r.status_code == 200, r.text
    mail = box.last("new.admin@acme.test")
    assert ADMIN_TEMP not in mail["html"] and ADMIN_TEMP not in mail["subject"]
    assert "Your password is" not in mail["html"] and "credential" not in mail["html"].lower()
    year = dt.datetime.now(dt.timezone.utc).year
    assert f"&copy; {year} Cyberultron Consulting Pvt Ltd" in mail["html"]
    link = re.search(r'href="(https://devsec\.example\.test/set_password#[^"]+)"', mail["html"]).group(1)
    token = link.split("#", 1)[1]
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "new.admin@acme.test")).one()
        assert user.must_change_password is True
    # the link sets the account's own password once and signs it in
    ok = client.post("/change_password", json={"change_token": token, "password": NEW_PASSWORD})
    assert ok.status_code == 200, ok.text
    assert ok.json()["access_token"] and ok.json()["refresh_token"]
    assert client.post("/change_password", json={"change_token": token, "password": "Another-One-77"}).status_code == 400
    assert _login(client, codes, "new.admin@acme.test", ADMIN_TEMP).status_code == 400  # temporary one is gone
    assert _login(client, codes, "new.admin@acme.test", NEW_PASSWORD).json().get("access_token")


def test_an_admin_created_account_must_change_the_temporary_password_at_first_sign_in(client, world):
    engine, ids, box, codes = world
    client.post("/admin/create_admin_user", headers=_superuser(engine),
                json={"email": "ops2@acme.test", "password": ADMIN_TEMP, "first_name": "O", "last_name": "P"})
    first = _login(client, codes, "ops2@acme.test", ADMIN_TEMP)
    assert first.status_code == 200 and first.json()["password_change_required"] is True
    assert "access_token" not in first.json()
    ok = client.post("/change_password", json={"change_token": first.json()["change_token"], "password": NEW_PASSWORD})
    assert ok.status_code == 200
    mailed = box.last("ops2@acme.test")["html"].split("set_password#", 1)[1].split('"', 1)[0]
    assert client.post("/change_password", json={"change_token": mailed, "password": "Third-Choice-99"}).status_code == 400


def test_a_failed_account_mail_keeps_no_account(client, world):
    engine, ids, box, codes = world
    r = client.post("/admin/create_admin_user", headers=_superuser(engine),
                    json={"email": "x@relay-down.test", "password": ADMIN_TEMP, "first_name": "X", "last_name": "Y"})
    assert r.status_code == 500
    assert "x@relay-down.test" not in all_users(engine)


def test_no_template_left_that_puts_a_password_in_a_mail():
    from backend.utilities.auth import html_email

    assert not hasattr(html_email, "create_user_password_email_html")
    assert not hasattr(html_email, "create_user_password_email_html_for_team_membership")
