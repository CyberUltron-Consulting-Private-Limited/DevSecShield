"""Shared helpers for the F4 RBAC tests: point every router at one SQLite engine, make accounts with roles."""
from __future__ import annotations

import sys

from sqlmodel import Session

from backend.new_models import Team, TeamMembership, User
from backend.utilities.auth.auth_utils import create_access_token


def patch_all_get_db(monkeypatch, engine) -> None:
    """Every router module (and the CBOM Sources HTTP helpers) reaches the database through its own ``get_db``;
    the route policies are bound to the same one."""
    import backend.main  # noqa: F401  (imports every router)

    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        if (name.startswith("backend.routers.") or name == "backend.utilities.cbom_sources.http") \
                and hasattr(module, "get_db"):
            monkeypatch.setattr(module, "get_db", lambda: engine)


def make_user(session: Session, email: str, *, superuser: bool = False, password_hash: str = "x") -> User:
    default = Team(name=f"{email} default", description="default")
    session.add(default)
    session.commit()
    session.refresh(default)
    user = User(email=email, password=password_hash, first_name="F", last_name="L", profile_photo=None,
                session_active=True, is_superuser=superuser, default_team_id=default.id)
    session.add(user)
    session.commit()
    session.refresh(user)
    session.add(TeamMembership(team_id=default.id, user_id=user.id, role="owner"))
    session.commit()
    return user


def join(session: Session, team_id: int, user_id: int, role: str) -> None:
    session.add(TeamMembership(team_id=team_id, user_id=user_id, role=role))
    session.commit()


def bearer(email: str, version: int = 0) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email, version=version)}"}


def stand_in_principal(monkeypatch, *, engine=None, user_for_token=None, role: str = "owner",
                       user_id: int = 1, email: str = "test-user@example.test") -> None:
    """For tests written before F4 that sign requests with a placeholder token ("Bearer t", "Bearer 3") and stub the
    handler's own auth helpers, because auth is not what they test.  The route policy (utilities/rbac) still runs,
    with this stand-in for the token check only:

    * ``engine`` and ``user_for_token(token) -> user id``: the role is that user's real membership of the path's team
      in ``engine`` (no membership: refused as a non-member, exactly like the real policy);
    * otherwise every request is ``user_id`` holding ``role`` in whatever team the path names.

    The role check and the 403s are the real ones; so is the audit trail when ``engine`` is given."""
    from fastapi import HTTPException

    from backend.utilities.rbac import policy

    async def resolve(request, engine_, team_id=None, allow_inactive=False):
        token = policy.bearer_token(request)  # 401 without a header, as before
        if engine is not None and user_for_token is not None:
            try:
                uid = user_for_token(token)
            except (TypeError, ValueError):
                raise HTTPException(status_code=401, detail="Could not validate credentials") from None
            with Session(engine) as session:
                user = session.get(User, uid)
                if user is None:
                    raise HTTPException(status_code=401, detail="Could not validate credentials")
                member = session.get(TeamMembership, (team_id, uid)) if team_id is not None else None
                return policy.Principal(user_id=uid, email=user.email, is_superuser=bool(user.is_superuser),
                                        team_id=team_id, role=member.role if member else None)
        return policy.Principal(user_id=user_id, email=email, is_superuser=False, team_id=team_id,
                                role=role if team_id is not None else None)

    monkeypatch.setattr(policy, "resolve_principal", resolve)
    if engine is None:
        # No database in these tests, so there is nowhere to write the fail-closed "attempted" audit row (with a
        # database, tests keep the real one and its 503 when it cannot be written).
        async def no_audit_attempt(request, ctx, engine_):
            request.state.audit_attempt_id = None

        monkeypatch.setattr(policy, "_audit_attempt", no_audit_attempt)
