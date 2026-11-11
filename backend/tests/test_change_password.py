"""X1 (Nov 11): a signed-in customer could not change their password (the user menu had only Logout; the only way was
"forgot password" by email). POST /change_password takes the current password and a new one (sign-up rules), signs
out every other session (token_version is bumped, as at a reset) and returns new tokens for this one. The Account page
(frontend app/[team_id]/account) uses it, and "Sign out everywhere" uses /logout (which already revokes every token)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "auth-hardening-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "auth-hardening-test-refresh-secret")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities.auth.auth_utils import get_hashed_password  # noqa: E402

OLD = "Correct-Horse-Battery-9"
NEW = "Another-Staple-Battery-10"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(auth_router, "get_db", lambda: engine)
    monkeypatch.delenv("DSS_DEV_MODE", raising=False)
    with Session(engine) as s:
        team = Team(name="t")
        s.add(team)
        s.commit()
        s.refresh(team)
        user = User(email="p1@example.test", password=get_hashed_password(OLD), first_name="P", last_name="One",
                    session_active=True, default_team_id=team.id)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        s.commit()
        user_id = user.id
    return engine, user_id


def _tokens(engine, user_id):
    with Session(engine) as s:
        return auth_router._tokens(s.get(User, user_id))


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_change_password_signs_out_other_sessions_and_keeps_this_one(world):
    engine, user_id = world
    client = TestClient(app)
    other = _tokens(engine, user_id)  # another browser
    mine = _tokens(engine, user_id)
    r = client.post("/change_password", json={"current_password": OLD, "new_password": NEW},
                    headers=_auth(mine["access_token"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert "signed out" in body["message"] and OLD not in r.text and NEW not in r.text
    assert client.get("/get_user", headers=_auth(body["access_token"])).status_code == 200  # this session goes on
    assert client.get("/get_user", headers=_auth(other["access_token"])).status_code in (401, 403)  # others end
    assert client.post("/refresh", json={"refresh_token": other["refresh_token"]}).status_code in (401, 403)
    with Session(engine) as s:
        stored = s.get(User, user_id)
        assert stored.token_version == 1
        from backend.utilities.auth.auth_utils import verify_and_update_password
        assert verify_and_update_password(NEW, stored.password)[0]


@pytest.mark.parametrize("body, status, says", [
    ({"current_password": "wrong-password-1", "new_password": NEW}, 400, "current password is not correct"),
    ({"current_password": OLD, "new_password": OLD}, 400, "must be different"),
    ({"current_password": OLD, "new_password": "short"}, 422, "8 to 128"),
])
def test_refusals_change_nothing(world, body, status, says):
    engine, user_id = world
    client = TestClient(app)
    mine = _tokens(engine, user_id)
    r = client.post("/change_password", json=body, headers=_auth(mine["access_token"]))
    assert r.status_code == status and says in r.text, r.text
    assert "short" not in r.text and "wrong-password-1" not in r.text  # never echoed
    assert client.get("/get_user", headers=_auth(mine["access_token"])).status_code == 200
    with Session(engine) as s:
        assert s.get(User, user_id).token_version == 0


def test_needs_a_signed_in_user(world):
    assert TestClient(app).post("/change_password", json={"current_password": OLD, "new_password": NEW}).status_code == 401
