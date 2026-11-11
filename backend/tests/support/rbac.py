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
