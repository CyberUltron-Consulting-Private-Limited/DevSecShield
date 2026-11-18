"""API keys act as the person who created them, never beyond that person's current role (F4 RBAC).

Review 5869356370 (cicd.py:66): a CI/CD or guardrails key resolved to its creator and team with no membership or
role check, so a removed or demoted member kept starting scans and reading results through it, and scans started
with keys were not audited.  Now every key route names the permission it needs (``machine(..., permission=...)``);
the key's creator must still be a member whose role holds it, checked on every use; key-driven writes are written to
the audit log with the creator as actor (``actor_type`` ``api_key``).
"""
import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
os.environ.setdefault("JWT_SECRET_KEY", "dast-auto-test-secret-not-for-prod")

from sqlmodel import Session, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import AuditEvent, CicdIntegration, GuardrailsIntegration, Scan, TeamMembership  # noqa: E402
from backend.tests.test_dast_cicd_contract import client  # noqa: E402,F401  (the hermetic CI/CD world)
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.cicd import auth as cicd_auth  # noqa: E402
from backend.utilities.guardrails import auth as gr_auth  # noqa: E402

KEY = "cicd1-" + "k" * 64
GR_KEY = "gr1-" + "g" * 64


@pytest.fixture()
def keyed(client, monkeypatch):  # noqa: F811
    """The contract world with a REAL key (no dependency override) and the creator a member of the team."""
    http, ids = client
    app.dependency_overrides.pop(cicd_auth.get_user_and_integration_id, None)
    engine = ids["engine"]
    monkeypatch.setattr(gr_auth, "get_db", lambda: engine)
    with Session(engine) as s:
        integ = s.get(CicdIntegration, ids["integration_id"])
        integ.api_key = cicd_auth.hash_api_key(KEY)
        s.add(integ)
        s.add(TeamMembership(team_id=ids["team_id"], user_id=ids["user_id"], role="member"))
        gr = GuardrailsIntegration(team_id=ids["team_id"], owner_user_id=ids["user_id"],
                                   api_key=gr_auth.hash_api_key(GR_KEY), title="gr")
        s.add(gr)
        s.commit()
    ratelimit.reset_all()
    yield http, ids
    ratelimit.reset_all()


def _role(ids, role):
    with Session(ids["engine"]) as s:
        m = s.get(TeamMembership, (ids["team_id"], ids["user_id"]))
        if role is None:
            s.delete(m)
        else:
            m.role = role
            s.add(m)
        s.commit()


def _start(http, ids):
    ratelimit.reset_all()
    return http.post("/cicd/dast/scan", json={"profile_id": ids["profile_id"]}, headers={"cicd-api-key": KEY})


def _status(http, scan_id, ids):
    """The status of a finished scan (a running one is polled from the worker queue, which this world has not)."""
    with Session(ids["engine"]) as s:
        scan = s.get(Scan, scan_id)
        scan.scan_status = "success"
        s.add(scan)
        s.commit()
    ratelimit.reset_all()
    return http.get(f"/cicd/dast/scan/{scan_id}", headers={"cicd-api-key": KEY})


def test_a_members_key_starts_a_scan_and_the_start_is_audited_as_the_key(keyed):
    http, ids = keyed
    started = _start(http, ids)
    assert started.status_code in (200, 202), started.text
    with Session(ids["engine"]) as s:
        rows = s.exec(select(AuditEvent).where(AuditEvent.team_id == ids["team_id"])).all()
    created = [r for r in rows if r.action == "scan.create" and r.outcome == "success"]
    assert len(created) == 1, [(r.action, r.outcome, r.actor_type) for r in rows]
    assert created[0].actor_type == "api_key" and created[0].actor_user_id == ids["user_id"]
    assert _status(http, started.json()["scan_id"], ids).status_code == 200


def test_a_removed_members_key_stops_working(keyed):
    http, ids = keyed
    scan_id = _start(http, ids).json()["scan_id"]
    _role(ids, None)
    refused = _start(http, ids)
    assert refused.status_code == 403 and "no longer a member" in refused.json()["detail"]
    assert _status(http, scan_id, ids).status_code == 403  # results are not readable either
    ratelimit.reset_all()
    gr = http.get("/public/guardrails/0123456789abcdef01234567", headers={"gr-api-key": GR_KEY})
    assert gr.status_code == 403 and "no longer a member" in gr.json()["detail"]


def test_a_key_never_does_more_than_its_creators_current_role(keyed):
    http, ids = keyed
    scan_id = _start(http, ids).json()["scan_id"]
    _role(ids, "viewer")
    refused = _start(http, ids)
    assert refused.status_code == 403 and "viewer" in refused.json()["detail"]
    assert _status(http, scan_id, ids).status_code == 200  # a viewer reads scans, in the UI and through the key
    _role(ids, "admin")
    assert _start(http, ids).status_code != 403  # allowed again (409 here: the first scan is still running)
