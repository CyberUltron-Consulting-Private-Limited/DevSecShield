"""Changing who is in a team and with which role (F4 RBAC): role changes, removals, ownership claims.

Each operation locks the team row first (``SELECT ... FOR UPDATE`` on PostgreSQL), so two concurrent changes in one
team are applied one after the other: the "a team keeps one owner" and "claim only while there is no owner" rules
are checked against what is really there, never against a snapshot another request is about to change.  The rules
themselves are in utilities/rbac/permissions.py; every change is written to the audit log in the same transaction.
"""
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import Team, TeamMembership, User
from backend.utilities.auth.auth_utils import normalise_email
from backend.utilities.rbac import audit
from backend.utilities.rbac.permissions import removal_problem, role_change_problem
from backend.utilities.rbac.policy import Principal

LAST_OWNER = "at least one owner"


def lock_team(session: Session, team_id: int) -> Team:
    team = session.exec(select(Team).where(Team.id == team_id).with_for_update()).first()
    if team is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
    return team


def owner_count(session: Session, team_id: int) -> int:
    return int(session.exec(select(func.count()).select_from(TeamMembership).where(
        TeamMembership.team_id == team_id, TeamMembership.role == "owner")).one())


def role_of(session: Session, team_id: int, user_id: int) -> str | None:
    return session.exec(select(TeamMembership.role).where(
        TeamMembership.team_id == team_id, TeamMembership.user_id == user_id)).first()


def _members_by_email(session: Session, team_id: int, emails: list[str]) -> list[tuple[User, TeamMembership]]:
    """Every account in the team whose address matches, whatever its case (docs/security/email-case-duplicates.md:
    removing an address removes every account spelled that way)."""
    wanted = {normalise_email(e) for e in emails if (e or "").strip()}
    if not wanted:
        return []
    rows = session.exec(
        select(User, TeamMembership).join(TeamMembership, TeamMembership.user_id == User.id)
        .where(TeamMembership.team_id == team_id, func.lower(User.email).in_(wanted))
        .order_by(User.id)
    ).all()
    return [(user, membership) for user, membership in rows]


def _refuse(problem: str) -> HTTPException:
    code = status.HTTP_409_CONFLICT if LAST_OWNER in problem else status.HTTP_403_FORBIDDEN
    return HTTPException(status_code=code, detail=problem)


def _event(session: Session, actor: Principal, meta: dict, *, action: str, team_id: int, object_id, details: dict):
    audit.record(session, action=action, team_id=team_id, object_type="member", object_id=object_id,
                 ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                 details={**details, "method": meta.get("method")}, **audit.actor_fields(actor))


def change_role(engine: Engine, team_id: int, actor: Principal, email: str, new_role: str, meta: dict) -> dict:
    with Session(engine) as session:
        lock_team(session, team_id)
        actor_role = role_of(session, team_id, actor.user_id)
        targets = _members_by_email(session, team_id, [email])
        if not targets:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{normalise_email(email)} is not in this team")
        owners = owner_count(session, team_id)
        changed = []
        for user, membership in targets:
            old = membership.role
            problem = role_change_problem(actor_role, old, new_role, self_change=(user.id == actor.user_id),
                                          owners=owners)
            if problem:
                session.rollback()
                raise _refuse(problem)
            if old == new_role:
                continue
            membership.role = new_role
            session.add(membership)
            owners += (new_role == "owner") - (old == "owner")
            _event(session, actor, meta, action="team.members.role", team_id=team_id, object_id=user.id,
                   details={"email": normalise_email(user.email), "from": old, "to": new_role})
            changed.append({"email": user.email, "from": old, "to": new_role})
        session.commit()
        return {"email": normalise_email(email), "role": new_role, "changed": changed}


def remove_members(engine: Engine, team_id: int, actor: Principal, emails: list[str], meta: dict) -> list[str]:
    """All or nothing: one address the actor may not remove refuses the whole request.  Addresses that are not in
    the team are skipped (as before)."""
    with Session(engine) as session:
        lock_team(session, team_id)
        actor_role = role_of(session, team_id, actor.user_id)
        targets = _members_by_email(session, team_id, emails)
        owners = owner_count(session, team_id)
        for _user, membership in targets:
            problem = removal_problem(actor_role, membership.role, owners=owners)
            if problem:
                session.rollback()
                raise _refuse(problem)
        if any(m.role == "owner" for _, m in targets) and owners - sum(m.role == "owner" for _, m in targets) < 1:
            session.rollback()
            raise _refuse("A team needs at least one owner: make someone else an owner first")
        removed = []
        for user, membership in targets:
            _event(session, actor, meta, action="team.members.remove", team_id=team_id, object_id=user.id,
                   details={"email": normalise_email(user.email), "role": membership.role})
            session.delete(membership)
            removed.append(user.email)
        session.commit()
        return removed


def claim_ownership(engine: Engine, team_id: int, actor: Principal, meta: dict) -> dict:
    """A team the migration left without an owner (admins only) gets one: the admin who asks first."""
    with Session(engine) as session:
        lock_team(session, team_id)
        if owner_count(session, team_id) > 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="This team already has an owner: ask them to change your role")
        membership = session.exec(select(TeamMembership).where(
            TeamMembership.team_id == team_id, TeamMembership.user_id == actor.user_id)).first()
        if membership is None or membership.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin can claim ownership")
        membership.role = "owner"
        session.add(membership)
        audit.record(session, action="team.ownership.claim", team_id=team_id, object_type="member",
                     object_id=actor.user_id, ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                     details={"email": normalise_email(actor.email), "from": "admin", "to": "owner",
                              "method": meta.get("method")},
                     **audit.actor_fields(actor))
        session.commit()
        return {"role": "owner"}
