"""Team roles end to end (F4 RBAC): owners, admins, members and viewers through the real app.

* creators own their teams; legacy teams (admins only, as the migration leaves them) are claimed by an admin, once;
* invitations carry a role; admins invite members and viewers, owners may invite admins;
* role changes and removals follow the matrix (admins manage members and viewers; owners everybody; a team keeps
  one owner); a change applies to the very next request (roles are never in the token);
* viewers read and are refused every write with 403, while the UI's flags (GET /team) say what they may do;
* IDOR: another team's id, another team's member, a superuser who is not a member: all refused.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_rbac_team_roles.py -q -p no:cacheprovider
"""
import os
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "rbac-roles-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "rbac-roles-test-refresh-secret-0123456789")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import AuditEvent, Team, TeamInvitation, TeamMembership, User  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth import email as invite_mail  # noqa: E402
from backend.utilities.auth.auth_utils import get_hashed_password  # noqa: E402
from backend.utilities.rbac.policy import NOT_IN_TEAM  # noqa: E402
from backend.tests.support.rbac import bearer, join, make_user, patch_all_get_db  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"
OWNER, ADMIN, ADMIN2, MEMBER, VIEWER = "olivia@acme.test", "adam@acme.test", "ada@acme.test", "max@acme.test", "vic@acme.test"
OUTSIDER, ROOT = "eve@evil.test", "root@zeroshield.test"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'roles.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    patch_all_get_db(monkeypatch, engine)
    mails: list[dict] = []

    async def capture(recipient_email, subject, body=None, html_body=None, custom_domain=None):
        mails.append({"to": recipient_email, "subject": subject, "html": html_body})

    monkeypatch.setattr(invite_mail, "send_outlook_email", capture)
    codes: dict[str, str] = {}
    monkeypatch.setattr(auth_router, "send_verification_email", lambda email, code: codes.__setitem__(email, code))
    ratelimit.reset_all()
    ids = {}
    with Session(engine) as s:
        team = Team(name="Acme")
        legacy = Team(name="Legacy (no owner)")
        s.add(team)
        s.add(legacy)
        s.commit()
        s.refresh(team)
        s.refresh(legacy)
        ids["team"], ids["legacy"] = team.id, legacy.id
        for email, role in ((OWNER, "owner"), (ADMIN, "admin"), (ADMIN2, "admin"), (MEMBER, "member"), (VIEWER, "viewer")):
            user = make_user(s, email, password_hash=get_hashed_password(PASSWORD))
            ids[email] = user.id
            join(s, team.id, user.id, role)
        join(s, legacy.id, ids[ADMIN], "admin")
        join(s, legacy.id, ids[ADMIN2], "admin")
        join(s, legacy.id, ids[MEMBER], "member")
        outsider = make_user(s, OUTSIDER)
        ids[OUTSIDER], ids["other_team"] = outsider.id, outsider.default_team_id
        ids[ROOT] = make_user(s, ROOT, superuser=True).id
    yield engine, ids, mails, codes
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app)


def roles(engine, team_id) -> dict:
    with Session(engine) as s:
        rows = s.exec(select(TeamMembership).where(TeamMembership.team_id == team_id)).all()
        return {s.get(User, m.user_id).email: m.role for m in rows}


def set_role(client, team_id, who, email, role):
    ratelimit.reset_all()
    return client.patch(f"/team/{team_id}/members/role", headers=bearer(who), json={"email": email, "role": role})


def remove(client, team_id, who, *emails):
    ratelimit.reset_all()
    return client.patch(f"/team/{team_id}", headers=bearer(who), json={"intent": "remove", "email_ids": list(emails)})


def events(engine, action=None):
    with Session(engine) as s:
        q = select(AuditEvent).order_by(AuditEvent.id)
        if action:
            q = q.where(AuditEvent.action == action)
        return s.exec(q).all()


# ----------------------------------------------------------------------------------------- owners and creators

def test_the_creator_of_a_team_owns_it(world, client):
    engine, ids, _, _ = world
    response = client.post("/team", headers=bearer(MEMBER), json={"name": "Max's lab", "description": "x"})
    assert response.status_code == 200, response.text
    new_team = response.json()["team_id"]
    assert roles(engine, new_team) == {MEMBER: "owner"}
    created = events(engine, "team.create")
    assert created and created[-1].team_id == new_team and created[-1].actor_user_id == ids[MEMBER]


def test_sign_up_owns_its_default_team(world, client):
    engine, _, _, codes = world
    assert client.post("/send_code", json={"email": "new@acme.test"}).status_code == 200
    response = client.post("/signup", json={"email": "new@acme.test", "verification_code": codes["new@acme.test"],
                                            "password": PASSWORD, "first_name": "New", "last_name": "Person"})
    assert response.status_code == 200, response.text
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "new@acme.test")).one()
        assert roles(engine, user.default_team_id) == {"new@acme.test": "owner"}


def test_a_legacy_team_is_claimed_by_one_admin_once(world, client):
    engine, ids, _, _ = world
    legacy = ids["legacy"]
    team = client.get(f"/team/{legacy}", headers=bearer(ADMIN)).json()
    assert team["has_owner"] is False and team["role"] == "admin"
    assert "team.ownership.claim" in team["permissions"]
    assert client.post(f"/team/{legacy}/ownership/claim", headers=bearer(MEMBER)).status_code == 403
    claimed = client.post(f"/team/{legacy}/ownership/claim", headers=bearer(ADMIN))
    assert claimed.status_code == 200, claimed.text
    assert roles(engine, legacy)[ADMIN] == "owner"
    again = client.post(f"/team/{legacy}/ownership/claim", headers=bearer(ADMIN2))
    assert again.status_code == 409 and "already has an owner" in again.json()["detail"]
    assert roles(engine, legacy)[ADMIN2] == "admin"
    claim_events = events(engine, "team.ownership.claim")
    assert [(e.actor_user_id, e.outcome) for e in claim_events] == [(ids[MEMBER], "denied"), (ids[ADMIN], "success")]
    # an owned team cannot be claimed either
    assert client.post(f"/team/{ids['team']}/ownership/claim", headers=bearer(ADMIN)).status_code == 409


# ----------------------------------------------------------------------------------------- invitations with a role

def _token_from(mails, to):
    return re.search(r"/invite/([0-9a-f]{64})", [m for m in mails if m["to"] == to][-1]["html"]).group(1)


def test_invitations_carry_the_role_the_inviter_may_give(world, client):
    engine, ids, mails, _ = world
    team = ids["team"]
    ok = client.patch(f"/team/{team}", headers=bearer(ADMIN), json={"intent": "add", "email_ids": [OUTSIDER], "role": "viewer"})
    assert ok.status_code == 200, ok.text
    with Session(engine) as s:
        assert s.exec(select(TeamInvitation).where(TeamInvitation.email == OUTSIDER)).one().role == "viewer"
    accepted = client.post(f"/invitations/{_token_from(mails, OUTSIDER)}/accept", headers=bearer(OUTSIDER))
    assert accepted.status_code == 200, accepted.text
    assert roles(engine, team)[OUTSIDER] == "viewer"

    ratelimit.reset_all()
    refused = client.patch(f"/team/{team}", headers=bearer(ADMIN), json={"intent": "add", "email_ids": ["a@acme.test"], "role": "admin"})
    assert refused.status_code == 403 and "cannot give the admin role" in refused.json()["detail"]
    ratelimit.reset_all()
    assert client.patch(f"/team/{team}", headers=bearer(OWNER),
                        json={"intent": "add", "email_ids": ["a@acme.test"], "role": "admin"}).status_code == 200
    ratelimit.reset_all()
    owner_invite = client.patch(f"/team/{team}", headers=bearer(OWNER),
                                json={"intent": "add", "email_ids": ["b@acme.test"], "role": "owner"})
    assert owner_invite.status_code == 403
    ratelimit.reset_all()
    bogus = client.patch(f"/team/{team}", headers=bearer(OWNER), json={"intent": "add", "email_ids": ["c@acme.test"], "role": "root"})
    assert bogus.status_code in (400, 422)
    ratelimit.reset_all()
    # no role given: member, as before
    assert client.patch(f"/team/{team}", headers=bearer(ADMIN), json={"intent": "add", "email_ids": ["d@acme.test"]}).status_code == 200
    with Session(engine) as s:
        assert s.exec(select(TeamInvitation).where(TeamInvitation.email == "d@acme.test")).one().role == "member"
    invited = events(engine, "team.members.invite")
    assert {e.details.get("role") for e in invited if e.outcome == "success"} >= {"viewer", "admin", "member"}


def test_an_admin_cannot_resend_an_invitation_for_a_role_above_their_own(world, client):
    engine, ids, _, _ = world
    team = ids["team"]
    assert client.patch(f"/team/{team}", headers=bearer(OWNER),
                        json={"intent": "add", "email_ids": ["boss@acme.test"], "role": "admin"}).status_code == 200
    with Session(engine) as s:
        inv = s.exec(select(TeamInvitation).where(TeamInvitation.email == "boss@acme.test")).one()
    ratelimit.reset_all()
    resend = client.post(f"/team/{team}/invitations/{inv.id}/resend", headers=bearer(ADMIN))
    assert resend.status_code == 403
    ratelimit.reset_all()
    assert client.post(f"/team/{team}/invitations/{inv.id}/resend", headers=bearer(OWNER)).status_code == 200


# ----------------------------------------------------------------------------------------- role changes

def test_admins_move_members_and_viewers_only(world, client):
    engine, ids, _, _ = world
    team = ids["team"]
    assert set_role(client, team, ADMIN, MEMBER, "viewer").status_code == 200
    assert roles(engine, team)[MEMBER] == "viewer"
    assert set_role(client, team, ADMIN, MEMBER, "member").status_code == 200
    for target, new in ((MEMBER, "admin"), (MEMBER, "owner"), (ADMIN2, "member"), (OWNER, "member"), (ADMIN, "member")):
        response = set_role(client, team, ADMIN, target, new)
        assert response.status_code == 403, (target, new, response.text)
    assert roles(engine, team) == {OWNER: "owner", ADMIN: "admin", ADMIN2: "admin", MEMBER: "member", VIEWER: "viewer"}


def test_owners_move_anybody_but_a_team_keeps_one_owner(world, client):
    engine, ids, _, _ = world
    team = ids["team"]
    assert set_role(client, team, OWNER, ADMIN, "member").status_code == 200
    last = set_role(client, team, OWNER, OWNER, "admin")
    assert last.status_code == 409 and "at least one owner" in last.json()["detail"]
    assert set_role(client, team, OWNER, ADMIN2, "owner").status_code == 200
    assert set_role(client, team, OWNER, OWNER, "admin").status_code == 200  # another owner remains
    assert roles(engine, team)[OWNER] == "admin" and roles(engine, team)[ADMIN2] == "owner"
    change = events(engine, "team.members.role")[-1]
    assert change.details == {"email": OWNER, "from": "owner", "to": "admin", "method": "PATCH"}
    assert change.actor_user_id == ids[OWNER]
    assert change.object_type == "member" and change.object_id == str(ids[OWNER]) and change.ip == "testclient"


def test_members_and_viewers_cannot_change_roles(world, client):
    _, ids, _, _ = world
    for who, role in ((MEMBER, "member"), (VIEWER, "viewer")):
        response = set_role(client, ids["team"], who, VIEWER, "member")
        assert response.status_code == 403 and response.json()["detail"].startswith(f"Your role ({role}) cannot")


def test_a_role_change_applies_to_the_next_request_with_the_same_token(world, client):
    engine, ids, _, _ = world
    team = ids["team"]
    token = bearer(MEMBER)
    assert client.post(f"/{team}/cicd/integration", headers=token, json={}).status_code != 403
    assert set_role(client, team, ADMIN, MEMBER, "viewer").status_code == 200
    ratelimit.reset_all()
    refused = client.post(f"/{team}/cicd/integration", headers=token, json={})
    assert refused.status_code == 403 and refused.json()["detail"].startswith("Your role (viewer) cannot")
    assert remove(client, team, ADMIN, MEMBER).status_code == 200
    ratelimit.reset_all()
    gone = client.get(f"/team/{team}", headers=token)
    assert gone.status_code == 403 and gone.json()["detail"] == NOT_IN_TEAM


def test_unknown_members_and_bad_roles(world, client):
    _, ids, _, _ = world
    team = ids["team"]
    assert set_role(client, team, OWNER, OUTSIDER, "member").status_code == 404  # not in this team
    assert set_role(client, team, OWNER, "nobody@acme.test", "member").status_code == 404
    assert set_role(client, team, OWNER, MEMBER, "superuser").status_code in (400, 422)
    assert set_role(client, team, OWNER, MEMBER, "").status_code in (400, 422)
    ratelimit.reset_all()
    assert client.patch(f"/team/{team}/members/role", headers=bearer(OWNER), json={"email": MEMBER}).status_code == 422


def test_emails_match_whatever_their_case(world, client):
    engine, ids, _, _ = world
    assert set_role(client, ids["team"], OWNER, MEMBER.upper(), "viewer").status_code == 200
    assert roles(engine, ids["team"])[MEMBER] == "viewer"


# ----------------------------------------------------------------------------------------- removal

def test_removal_follows_the_matrix(world, client):
    """Before RBAC any admin could remove any admin (and themselves) through the API; the UI only hid it."""
    engine, ids, _, _ = world
    team = ids["team"]
    assert remove(client, team, ADMIN, ADMIN2).status_code == 403
    assert remove(client, team, ADMIN, OWNER).status_code == 403
    assert remove(client, team, ADMIN, ADMIN).status_code == 403
    assert remove(client, team, MEMBER, VIEWER).status_code == 403
    assert remove(client, team, ADMIN, VIEWER).status_code == 200
    assert remove(client, team, OWNER, ADMIN2).status_code == 200
    last = remove(client, team, OWNER, OWNER)
    assert last.status_code == 409 and "at least one owner" in last.json()["detail"]
    assert roles(engine, team) == {OWNER: "owner", ADMIN: "admin", MEMBER: "member"}
    removed = [e for e in events(engine, "team.members.remove") if e.outcome == "success"]
    assert {e.details["email"] for e in removed} == {VIEWER, ADMIN2}


def test_a_mixed_removal_changes_nothing_when_one_address_is_refused(world, client):
    engine, ids, _, _ = world
    team = ids["team"]
    assert remove(client, team, ADMIN, VIEWER, ADMIN2).status_code == 403
    assert roles(engine, team)[VIEWER] == "viewer"


# ----------------------------------------------------------------------------------------- deleting a team

def test_only_an_owner_deletes_a_team_and_its_audit_trail_stays(world, client, monkeypatch):
    engine, ids, _, _ = world
    from backend.routers import team as team_router

    class _NoMongo(dict):
        def __getitem__(self, name):
            class _C:
                def delete_many(self, *_a, **_k):
                    class R:
                        deleted_count = 0
                    return R()
            return _C()

    monkeypatch.setattr(team_router, "get_mongo_client_db", lambda: _NoMongo())
    team = ids["team"]
    refused = client.delete(f"/team/{team}", headers=bearer(ADMIN))
    assert refused.status_code == 403 and refused.json()["detail"].startswith("Your role (admin) cannot delete the team")
    ratelimit.reset_all()
    assert client.delete(f"/team/{team}", headers=bearer(OWNER)).status_code == 200
    with Session(engine) as s:
        assert s.get(Team, team) is None
    trail = [e for e in events(engine) if e.team_id == team]
    assert any(e.action == "team.delete" and e.outcome == "success" for e in trail)
    assert any(e.action == "team.delete" and e.outcome == "denied" and e.actor_user_id == ids[ADMIN] for e in trail)


# ----------------------------------------------------------------------------------------- viewers

def test_get_team_tells_the_ui_what_the_caller_may_do(world, client):
    _, ids, _, _ = world
    viewer = client.get(f"/team/{ids['team']}", headers=bearer(VIEWER)).json()
    assert viewer["role"] == "viewer" and viewer["is_team_admin"] is False
    assert "scan.read" in viewer["permissions"] and "scan.create" not in viewer["permissions"]
    assert viewer["assignable_roles"] == [] and viewer["has_owner"] is True
    owner = client.get(f"/team/{ids['team']}", headers=bearer(OWNER)).json()
    assert owner["role"] == "owner" and owner["is_team_admin"] is True and "team.delete" in owner["permissions"]
    assert owner["assignable_roles"] == ["viewer", "member", "admin", "owner"]
    assert owner["invitable_roles"] == ["viewer", "member", "admin"]
    admin = client.get(f"/team/{ids['team']}", headers=bearer(ADMIN)).json()
    assert admin["assignable_roles"] == ["member", "viewer"] and "team.delete" not in admin["permissions"]
    assert {m["email"]: m["role"] for m in admin["team_members"]}[VIEWER] == "viewer"


VIEWER_WRITES = [
    ("PUT", "/team/{t}", {"name": "x", "description": "y"}),
    ("PATCH", "/team/{t}", {"intent": "add", "email_ids": ["x@acme.test"]}),
    ("POST", "/{t}/sast/scan", {}),
    ("POST", "/{t}/sast/scan/1/start", {}),
    ("DELETE", "/{t}/sast/scan/1", None),
    ("POST", "/{t}/sast/scan/1/finding", {}),
    ("POST", "/{t}/cicd/integration", {}),
    ("POST", "/{t}/dast/profiles", {}),
    ("POST", "/{t}/cbom/sources/nodes", {}),
    ("PATCH", "/{t}/cbom/sources/settings", {}),
    ("PUT", "/{t}/integrations/servicenow", {}),
    ("POST", "/{t}/sast/scan/1/attestations", {}),
    ("POST", "/guardrails/{t}/integration", {}),
]


@pytest.mark.parametrize("method,path,body", VIEWER_WRITES)
def test_a_viewer_is_refused_every_write_with_403(world, client, method, path, body):
    _, ids, _, _ = world
    ratelimit.reset_all()
    response = client.request(method, path.format(t=ids["team"]), headers=bearer(VIEWER), json=body)
    assert response.status_code == 403, response.text
    assert response.json()["detail"].startswith("Your role (viewer) cannot")


def test_a_viewer_reads(world, client):
    _, ids, _, _ = world
    team = ids["team"]
    assert client.get(f"/team/{team}", headers=bearer(VIEWER)).status_code == 200
    assert client.get(f"/{team}/cbom/sources/settings", headers=bearer(VIEWER)).status_code == 200
    assert client.get(f"/{team}/dast/profiles", headers=bearer(VIEWER)).status_code == 200


# ----------------------------------------------------------------------------------------- IDOR

def test_another_teams_id_is_refused_for_every_role(world, client):
    _, ids, _, _ = world
    other = ids["other_team"]
    for who in (OWNER, ADMIN, MEMBER, VIEWER):
        ratelimit.reset_all()
        assert client.get(f"/team/{other}", headers=bearer(who)).json()["detail"] == NOT_IN_TEAM
        assert set_role(client, other, who, OUTSIDER, "viewer").status_code == 403
        assert remove(client, other, who, OUTSIDER).status_code == 403


def test_a_superuser_who_is_not_a_member_gets_no_team_access(world, client):
    _, ids, _, _ = world
    response = client.get(f"/team/{ids['team']}", headers=bearer(ROOT))
    assert response.status_code == 403 and response.json()["detail"] == NOT_IN_TEAM
    assert set_role(client, ids["team"], ROOT, MEMBER, "owner").status_code == 403


def test_the_rbac_matrix_is_served_to_signed_in_people(world, client):
    assert client.get("/rbac/matrix").status_code == 401
    data = client.get("/rbac/matrix", headers=bearer(VIEWER)).json()
    assert data["roles"] == ["viewer", "member", "admin", "owner"]
    assert any(p["name"] == "team.delete" and p["roles"] == ["owner"] for p in data["permissions"])
