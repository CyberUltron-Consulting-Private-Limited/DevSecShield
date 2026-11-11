"""E-mail addresses are one identity whatever their case: sign-up, sign-in, reset and team invitations agree.

Every lookup resolves an address to the account ``auth_utils.user_by_email`` returns (``lower(email)``, lowest user
id). Before this fix a team invitation for an address that two historical accounts share (``Ana@`` and ``ana@``)
added BOTH accounts to the team, so the duplicate that can never sign in through the UI (but may still hold a
token issued before WP1) gained the team's data; and the team page judged "is this user an admin" by comparing
stored e-mails, so a second row with the same address inherited the admin flag.
"""
from __future__ import annotations

import asyncio
import pathlib
import sys
import types

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.utilities.auth.auth_utils import user_by_email  # noqa: E402
from backend.utilities.auth import email as invite_mail  # noqa: E402
from backend.utilities.team import invitations, membership  # noqa: E402


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'emails.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    mails: list[str] = []
    links: dict[str, str] = {}

    async def fake_mail(email, team_name, inviter, link, expires_on):
        mails.append(email)
        links[email] = link.rsplit("/", 1)[1]

    monkeypatch.setattr(invite_mail, "send_team_invitation_email", fake_mail)
    engine.mails = mails  # type: ignore[attr-defined]
    engine.links = links  # type: ignore[attr-defined]
    return engine


def _user(engine, email: str, *, team_id: int | None = None, role: str = "admin") -> int:
    with Session(engine) as s:
        if team_id is None:
            team = Team(name=f"{email} default")
            s.add(team)
            s.commit()
            s.refresh(team)
            team_id = team.id
        user = User(email=email, password="x", first_name="F", last_name="L", profile_photo=None,
                    default_team_id=team_id)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=team_id, user_id=user.id, role=role))
        s.commit()
        return user.id


def _members(engine, team_id: int) -> set[int]:
    with Session(engine) as s:
        return {m.user_id for m in s.exec(select(TeamMembership).where(TeamMembership.team_id == team_id)).all()}


def _team(engine, name: str) -> int:
    with Session(engine) as s:
        team = Team(name=name)
        s.add(team)
        s.commit()
        s.refresh(team)
        return team.id


def test_an_invitation_adds_only_the_account_the_address_signs_in_to(engine):
    winner = _user(engine, "ana@example.com")
    duplicate = _user(engine, "Ana@Example.com")  # stored before addresses were lower-cased
    with Session(engine) as s:
        assert user_by_email(s, "ANA@example.COM").id == winner  # what sign-in, codes and reset resolve to
    team = _team(engine, "finance")
    asyncio.run(membership.add_emails_to_team(["ANA@EXAMPLE.com"], team, engine))
    assert _members(engine, team) == set() and engine.mails == ["ana@example.com"]  # nobody joins before accepting
    token = engine.links["ana@example.com"]
    with Session(engine) as s:
        dup_user = s.get(User, duplicate)
    with pytest.raises(Exception) as refused:
        invitations.accept(token, dup_user, engine)  # the duplicate row is not the account the address signs in to
    assert getattr(refused.value, "status_code", None) == 403
    with Session(engine) as s:
        win_user = s.get(User, winner)
    invitations.accept(token, win_user, engine)
    assert _members(engine, team) == {winner}
    assert duplicate not in _members(engine, team)


def test_an_invitation_in_another_case_never_creates_a_second_account(engine):
    team = _team(engine, "ops")
    asyncio.run(membership.add_emails_to_team([" New.Person@Corp.test "], team, engine))
    other = _team(engine, "audit")
    asyncio.run(membership.add_emails_to_team(["NEW.PERSON@corp.TEST"], other, engine))
    assert engine.mails == ["new.person@corp.test", "new.person@corp.test"]
    with Session(engine) as s:  # inviting creates no account
        assert s.exec(select(User).where(User.email.ilike("new.person@corp.test"))).all() == []  # type: ignore[attr-defined]
    first = engine.links["new.person@corp.test"]  # the second mail replaced the dict entry: re-invite ops for its link
    user, joined = asyncio.run(invitations.register(first, "chosen-pass-1", "New", "Person", engine))
    assert joined == other
    with Session(engine) as s:
        inv = s.exec(select(invitations.TeamInvitation).where(invitations.TeamInvitation.team_id == team)).first()
    assert inv.status == "pending"
    asyncio.run(invitations.resend_invitation(team, inv.id, None, engine))
    assert invitations.describe(engine.links["new.person@corp.test"], engine)["account_exists"] is True
    invitations.accept(engine.links["new.person@corp.test"], user, engine)
    with Session(engine) as s:
        rows = s.exec(select(User).where(User.email.ilike("new.person@corp.test"))).all()  # type: ignore[attr-defined]
    assert [r.email for r in rows] == ["new.person@corp.test"]
    assert _members(engine, team) & _members(engine, other) == {rows[0].id}


def test_removing_an_address_removes_every_account_that_spells_it(engine):
    team = _team(engine, "shared")
    a = _user(engine, "bob@corp.test", team_id=team, role="member")
    b = _user(engine, "BOB@corp.test", team_id=team, role="member")
    keep = _user(engine, "carol@corp.test", team_id=team, role="admin")
    asyncio.run(membership.remove_emails_from_team(["Bob@Corp.Test"], team, engine))
    assert _members(engine, team) == {keep} and {a, b}.isdisjoint(_members(engine, team))


def test_the_team_page_judges_admin_by_account_not_by_address(engine, monkeypatch):
    from backend.main import app
    from backend.routers import team as team_router

    team = _team(engine, "payments")
    _user(engine, "lead@bank.test", team_id=team, role="admin")
    member = _user(engine, "lead@bank.test", team_id=team, role="member")  # a historical second row, same address

    async def as_member(*_a, **_k):
        return types.SimpleNamespace(id=member, email="lead@bank.test")

    monkeypatch.setattr(team_router, "get_db", lambda: engine)
    monkeypatch.setattr(team_router, "get_user_from_header_or_raise_exception", as_member)
    monkeypatch.setattr(team_router, "check_if_user_is_in_team", lambda *_a, **_k: None)
    r = TestClient(app).get(f"/team/{team}", headers={"Authorization": "Bearer t"})
    assert r.status_code == 200, r.text
    assert r.json()["is_team_admin"] is False
