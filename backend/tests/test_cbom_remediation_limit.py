"""Reviewing CBOM findings must never spend the budget that estimates and starts scans.

The CBOM results page asks for a finding's remediation (offline knowledge base: no AI, no credits) every time the
finding opens. It used to share ``scans.start`` (10 a minute) with estimate / start / AI remediation, so a customer
who opened about a dozen findings in a minute saw "Could not load the remediation." and then could not estimate a new
scan ("Too many requests"). Found in the lab UI run (u2, round 5).

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_cbom_remediation_limit.py -q -p no:cacheprovider
"""
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "remediation-limit-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "remediation-limit-test-refresh-secret")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402
from backend.routers import scans  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def client(monkeypatch):
    """The app with authentication refused right after the rate limiters (so no database is needed) and every
    limiter frozen inside one window."""
    async def refused(engine, authorization):
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    monkeypatch.setattr(scans, "get_db", lambda: None)
    monkeypatch.setattr(scans, "get_user_from_header_or_raise_exception", refused)
    from backend.tests.support.rbac import stand_in_principal
    stand_in_principal(monkeypatch)  # the route policy (F4) lets the request through to the handler's refusal
    for limiter in (scans.start_limiter, scans.remediate_limiter):
        monkeypatch.setattr(limiter, "clock", Clock(9_000_000.0 + 3))
    ratelimit.reset_all()
    yield TestClient(app)
    ratelimit.reset_all()


def _auth(email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth_utils.create_access_token(email)}"}


def test_opening_many_cbom_findings_is_never_rate_limited_like_a_scan_start(client):
    headers = _auth("reviewer@example.test")
    statuses = [client.post(f"/1/cbom/scan/5/finding/{i:024x}/remediate", headers=headers).status_code
                for i in range(30)]
    assert statuses == [401] * 30, "30 finding drawers in a minute reach the endpoint (none refused with 429)"
    estimate = client.post("/1/cbom/scan/5/estimate_credits", headers=headers,
                           data={"start_scan_payload_string": "{}"})
    assert estimate.status_code != 429, "estimating a scan right after reviewing findings still works"


def test_ai_remediation_still_spends_the_scan_start_budget(client):
    headers = _auth("ai-user@example.test")
    statuses = [client.post(f"/1/sast/scan/5/finding/{i:024x}/remediate", headers=headers).status_code
                for i in range(11)]
    assert statuses == [401] * 10 + [429]


def test_cbom_review_has_its_own_ceiling(client):
    headers = _auth("scripted@example.test")
    statuses = [client.post(f"/1/cbom/scan/5/finding/{i:024x}/remediate", headers=headers).status_code
                for i in range(scans.remediate_limiter.times + 1)]
    assert statuses[-1] == 429 and set(statuses[:-1]) == {401}
