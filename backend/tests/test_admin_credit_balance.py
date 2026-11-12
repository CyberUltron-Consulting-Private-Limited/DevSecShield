"""Admin > Teams > Update Credits sets a team's balance (POST /admin/update).

Credits are fractional: Team.credit_balance is a float, a scan is priced to the cent (utilities/scan/credit_estimate.py
rounds to 2 places), a CBOM sources run charges 0.2 per server, DAST 0.08 per URL, and a scan chat message 0.006. The
endpoint took an int, so the admin console could not set a balance such as 4984.79 (browser QA of PR #30: the console's
parseInt also turned 4984.79 into 4984 without a word). It now takes any finite number of 0 or more, as the console
does (frontend/utils/adminCredits.ts); NaN and Infinity, which Python's JSON parser accepts, are refused.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_admin_credit_balance.py -q -p no:cacheprovider
"""
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "admin-credit-balance-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "admin-credit-balance-test-refresh-secret")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import Team, User  # noqa: E402
from backend.routers import admin as admin_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth.auth_utils import create_access_token, get_hashed_password  # noqa: E402


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'credits.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(admin_router, "get_db", lambda: engine)
    ratelimit.reset_all()
    with Session(engine) as s:
        team = Team(name="Acme", credit_balance=4983.79)
        s.add(team)
        s.commit()
        s.refresh(team)
        for email, superuser in (("root@acme.test", True), ("member@acme.test", False)):
            s.add(User(email=email, password=get_hashed_password("Correct-Horse-Battery-9"), first_name="F",
                       last_name="L", profile_photo=None, session_active=True, is_superuser=superuser,
                       default_team_id=team.id))
        s.commit()
        team_id = team.id
    yield engine, team_id
    ratelimit.reset_all()


def _auth(email: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(email, version=0)}"}


def _balance(engine, team_id: int) -> float:
    with Session(engine) as s:
        return s.get(Team, team_id).credit_balance


@pytest.mark.parametrize("value", [4984.79, 0.2, 0.006, 0, 12, 12.0, 1_000_000.5])
def test_a_superuser_sets_a_fractional_balance(world, value):
    engine, team_id = world
    r = TestClient(app).post("/admin/update", headers=_auth("root@acme.test"),
                             json={"team_id": team_id, "credit_balance": value})
    assert r.status_code == 200, r.text
    assert r.json()["user"]["credit_balance"] == value
    assert _balance(engine, team_id) == value


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_a_balance_that_is_not_a_finite_number_is_refused(world, raw):
    """json.loads accepts NaN and Infinity (and 1e999 overflows to inf); a NaN balance fails every later comparison."""
    engine, team_id = world
    r = TestClient(app).post("/admin/update", headers={**_auth("root@acme.test"), "Content-Type": "application/json"},
                             content=f'{{"team_id": {team_id}, "credit_balance": {raw}}}')
    assert r.status_code == 422, r.text
    assert _balance(engine, team_id) == 4983.79


@pytest.mark.parametrize("value", [-0.01, -1])
def test_a_negative_balance_is_refused(world, value):
    engine, team_id = world
    r = TestClient(app).post("/admin/update", headers=_auth("root@acme.test"),
                             json={"team_id": team_id, "credit_balance": value})
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == "Credit balance cannot be negative"
    assert _balance(engine, team_id) == 4983.79


@pytest.mark.parametrize("value", ["", "abc", None, [1], {"v": 1}])
def test_a_balance_that_is_not_a_number_is_refused(world, value):
    engine, team_id = world
    r = TestClient(app).post("/admin/update", headers=_auth("root@acme.test"),
                             json={"team_id": team_id, "credit_balance": value})
    assert r.status_code == 422, r.text
    assert _balance(engine, team_id) == 4983.79


def test_only_a_superuser_sets_a_balance(world):
    engine, team_id = world
    r = TestClient(app).post("/admin/update", headers=_auth("member@acme.test"),
                             json={"team_id": team_id, "credit_balance": 99999.5})
    assert r.status_code == 403, r.text
    assert _balance(engine, team_id) == 4983.79
