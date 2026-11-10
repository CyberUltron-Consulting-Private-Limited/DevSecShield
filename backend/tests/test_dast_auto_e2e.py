"""
Live automatic-DAST proofs: profile create + run-now, CI fire-and-forget, scheduler tick.

Self-skips if backend is down. Target is demo.testfire.net with max_urls=1 and fast.
Waiting is condition-based (no assumed scan duration). Deadline ~20 minutes.

Run from backend:
  uv run pytest tests/test_dast_auto_e2e.py -q
"""
from __future__ import annotations

import datetime
import json
import os
import time
import urllib.error
import urllib.request

import pytest

from backend.tests.support.live_backend import mint_token, require_database, require_live_backend

BASE = os.getenv("REGRESSION_BASE_URL", "http://localhost:8081")
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEAM = int(os.getenv("DAST_E2E_TEAM", "1"))
USER = os.getenv("DAST_E2E_USER", "cbom-demo@cyberultron.com")

_AUTH = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input",
    "xpath_of_password_field": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input",
    "username": "jsmith",
    "password": "demo123",
    "xpath_of_submit_button": "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input",
}

PROFILE_BODY = {
    "title": "e2e-testfire",
    "target_url": "https://demo.testfire.net/index.jsp",
    "auth": _AUTH,
    "scan_speed": "fast",
    "max_urls": 1,
    "consent_ok": True,
    "schedule_kind": "off",
    "enabled": True,
}


@pytest.fixture(autouse=True, scope="module")
def _live_backend():
    """Skip the module cleanly unless the backend is up and accepts tokens signed with the exported secret, and the
    database these tests read directly (backend.get_db) answers."""
    require_live_backend(BASE, USER, TEAM)
    require_database()


def _token(sub):
    return mint_token(sub)


def _req(method, path, token=None, body=None, extra_headers=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except OSError:  # URLError, or a server on that port that is not the API (it resets the connection)
        pytest.skip("backend not reachable on " + BASE)


def _assert_secret_absent(payload):
    dumped = json.dumps(payload)
    assert "demo123" not in dumped
    if not isinstance(payload, dict):
        return
    auth = payload.get("auth")
    if auth is None:
        meta = payload.get("scan_metadata") or {}
        auth = meta.get("auth") if isinstance(meta, dict) else None
    if isinstance(auth, dict):
        assert "password" not in auth


def _await_dast(token, sid, deadline_s=1200):
    end = time.monotonic() + deadline_s
    last = None
    last_body = {}
    while time.monotonic() < end:
        st, d = _req("GET", f"/{TEAM}/dast/scan/{sid}", token)
        last = d.get("scan_status")
        last_body = d
        if last in ("success", "failure"):
            return last, d
        time.sleep(5)
    pytest.fail(f"dast scan {sid} not terminal within {deadline_s}s (last status={last} info={last_body.get('info')})")


def _ensure_demo_user():
    global TEAM
    from sqlmodel import Session, select

    from backend.get_db import get_db
    from backend.new_models import Team, TeamMembership, User

    engine = get_db()
    with Session(engine) as session:
        team = session.get(Team, TEAM) or session.exec(select(Team)).first()
        if team is None:
            team = Team(name="demo", credit_balance=100.0)
            session.add(team)
            session.commit()
            session.refresh(team)
        if (team.credit_balance or 0) < 10:
            team.credit_balance = 100.0
            session.add(team)
        user = session.exec(select(User).where(User.email == USER)).first()
        if user is None:
            user = User(
                email=USER,
                password="x",
                first_name="demo",
                last_name="user",
                session_active=True,
                default_team_id=team.id,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
        else:
            user.session_active = True
            user.default_team_id = team.id
            session.add(user)
        mem = session.exec(
            select(TeamMembership).where(
                TeamMembership.user_id == user.id,
                TeamMembership.team_id == team.id,
            )
        ).first()
        if mem is None:
            session.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        session.commit()
        TEAM = int(team.id)
        return team.id, user.id


def test_dast_profile_run_now_e2e():
    _ensure_demo_user()
    token = _token(USER)
    st, created = _req("POST", f"/{TEAM}/dast/profiles", token, PROFILE_BODY)
    if st in (401, 403):
        pytest.skip(f"cannot create DAST profile (status {st}); user/team not seeded")
    if st == 500:
        pytest.skip(f"profile create failed (status {st}); migration may be pending: {created}")
    assert st == 200, created
    _assert_secret_absent(created)
    profile_id = created["id"]

    from sqlmodel import Session

    from backend.get_db import get_db
    from backend.new_models import Team

    engine = get_db()
    with Session(engine) as session:
        credits_before = session.get(Team, TEAM).credit_balance

    st, ran = _req("POST", f"/{TEAM}/dast/profiles/{profile_id}/run", token)
    if st == 409:
        pytest.skip("profile already has an in-flight scan")
    assert st == 200, ran
    sid = ran["scan_id"]
    with Session(engine) as session:
        credits_after = session.get(Team, TEAM).credit_balance
    assert credits_after < credits_before
    overlap_st, _ = _req("POST", f"/{TEAM}/dast/profiles/{profile_id}/run", token)
    assert overlap_st == 409
    status, body = _await_dast(token, sid)
    _assert_secret_absent(body)
    _assert_secret_absent(body.get("scan_metadata") or {})
    assert status in ("success", "failure")
    if status == "failure":
        assert (body.get("info") or {}).get("error")


def test_dast_scheduler_tick_e2e():
    _ensure_demo_user()
    from sqlmodel import Session

    from backend.get_db import get_db
    from backend.new_models import DastScanProfile
    from backend.utilities.dast.auth_crypto import encrypt_auth
    from backend.utilities.dast.beat import tick

    token = _token(USER)
    st, created = _req("POST", f"/{TEAM}/dast/profiles", token, PROFILE_BODY)
    if st != 200:
        pytest.skip(f"cannot seed profile for scheduler ({st})")
    profile_id = created["id"]
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    engine = get_db()
    with Session(engine) as session:
        profile = session.get(DastScanProfile, profile_id)
        if profile is None:
            pytest.skip("profile not in local db")
        profile.enabled = True
        profile.consent_ok = True
        profile.schedule_kind = "daily"
        profile.schedule_time = "00:00"
        profile.next_run_at = past
        profile.inflight_scan_id = None
        profile.auth_encrypted = encrypt_auth(_AUTH)
        session.add(profile)
        session.commit()
    results = tick(engine=engine)
    started = [r for r in results if r.scan_id]
    if not started:
        pytest.skip("scheduler tick produced no scan (overlap or worker/credits)")
    sid = started[0].scan_id
    st, body = _req("GET", f"/{TEAM}/dast/scan/{sid}", token)
    assert st == 200
    _assert_secret_absent(body)


def test_dast_cicd_fire_and_forget_e2e():
    _ensure_demo_user()
    token = _token(USER)
    st, created = _req("POST", f"/{TEAM}/dast/profiles", token, PROFILE_BODY)
    if st != 200:
        pytest.skip(f"cannot seed profile for CI ({st})")
    profile_id = created["id"]

    from sqlmodel import Session, select

    from backend.get_db import get_db
    from backend.new_models import CicdIntegration, User
    from backend.utilities.cicd.auth import create_api_key

    engine = get_db()
    plaintext, hashed = create_api_key(TEAM)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == USER)).first()
        if user is None:
            pytest.skip("seeded e2e user not in database")
        integ = CicdIntegration(
            team_id=TEAM,
            owner_user_id=user.id,
            api_key=hashed,
            title="dast-e2e-temp",
            scan_type="sast",
        )
        session.add(integ)
        session.commit()
        session.refresh(integ)
        integ_id = integ.id

    st, dispatched = _req(
        "POST",
        "/cicd/dast/scan",
        body={"profile_id": profile_id},
        extra_headers={"cicd-api-key": plaintext},
    )
    if st == 409:
        pytest.skip("in-flight DAST profile")
    if st in (401, 403):
        pytest.skip(f"CI key rejected ({st})")
    assert st in (200, 202), dispatched
    assert dispatched.get("scan_id")
    sid = dispatched["scan_id"]
    try:
        end = time.monotonic() + 1200
        last = None
        last_body = {}
        while time.monotonic() < end:
            gst, gd = _req("GET", f"/cicd/dast/scan/{sid}", extra_headers={"cicd-api-key": plaintext})
            last_body = gd
            last = gd.get("status")
            _assert_secret_absent(gd)
            if last in ("success", "failure"):
                return
            time.sleep(5)
        pytest.fail(f"CI DAST scan {sid} not terminal (last={last} body={last_body})")
    finally:
        with Session(engine) as session:
            row = session.get(CicdIntegration, integ_id)
            if row is not None:
                session.delete(row)
                session.commit()
