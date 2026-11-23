"""S1: the CBOM CI/CD gate policy API (team policy, per-integration override), as Settings > CBOM policy gate uses it.

Run (repo root): cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_gate_policy_api.py -q
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.cbom_gate_models import CbomGatePolicy  # noqa: E402
from backend.new_models import CbomCollectionAuditEvent, CicdIntegration  # noqa: E402
from backend.utilities.cicd import gate_policy as GP  # noqa: E402
from backend.utilities.cicd import gate_policy_store as STORE  # noqa: E402

_FIXTURES = (api, world)


@pytest.fixture()
def integrations(world):
    engine, ids = world
    out = {}
    with Session(engine) as s:
        for key, team, scan_type, owner in (("cbom", 1, "cbom", "alice"), ("sast", 1, "sast", "alice"),
                                            ("other", 2, "cbom", "carol")):
            row = CicdIntegration(team_id=team, owner_user_id=ids[owner], api_key=f"h-{key}", title=f"ci-{key}",
                                  scan_type=scan_type, scan_settings={})
            s.add(row)
            s.commit()
            s.refresh(row)
            out[key] = row.id
    return out


def _policy(**over):
    raw = copy.deepcopy(GP.DEFAULT_POLICY)
    raw.update(over)
    return raw


def test_get_shows_the_default_and_the_cbom_integrations(api, integrations):
    r = api("GET", "/1/cbom/gate-policy", who="bob")  # members read
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["team"] is None and body["default"] == GP.DEFAULT_POLICY
    assert set(body["presets"]) == {"sp800-131a", "sp800-131a-2031", "cnsa-2.0"} and body["is_admin"] is False
    assert [i["id"] for i in body["integrations"]] == [integrations["cbom"]]  # SAST and other teams' are not listed
    assert body["rules"] == list(GP.RULES)


def test_admin_saves_the_team_policy_and_the_gate_reads_it(api, world, integrations):
    engine, _ = world
    r = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(name="Team strict", quantum_vulnerable="fail")})
    assert r.status_code == 200, r.text
    assert r.json()["saved"] is True and r.json()["row_version"] == 1
    with Session(engine) as s:
        policy, source, version = STORE.effective_policy(s, 1, integrations["cbom"])
    assert (policy["name"], source, version) == ("Team strict", "team", 1)
    # saving the same policy again changes nothing
    again = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(name="Team strict", quantum_vulnerable="fail"),
                                                    "expected_version": 1})
    assert again.json()["saved"] is False
    # a stale form gets 409
    newer = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(name="v2"), "expected_version": 1})
    assert newer.status_code == 200 and newer.json()["row_version"] == 2
    stale = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(name="v3"), "expected_version": 1})
    assert stale.status_code == 409
    with Session(engine) as s:
        actions = [e.action for e in s.exec(select(CbomCollectionAuditEvent)).all()]
    assert actions.count("cicd.gate_policy.save") == 2


def test_integration_override_wins_and_reset_falls_back(api, world, integrations):
    engine, _ = world
    integ = integrations["cbom"]
    assert api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(name="Team")}).status_code == 200
    r = api("PUT", f"/1/cbom/gate-policy/integrations/{integ}", json={"policy": _policy(name="Legacy app")})
    assert r.status_code == 200, r.text
    with Session(engine) as s:
        assert STORE.effective_policy(s, 1, integ)[:2] == (GP.validate_policy(_policy(name="Legacy app")),
                                                            "integration")
    listed = api("GET", "/1/cbom/gate-policy").json()["integrations"][0]
    assert listed["override"]["policy"]["name"] == "Legacy app"
    assert api("DELETE", f"/1/cbom/gate-policy/integrations/{integ}").json() == {"deleted": True}
    with Session(engine) as s:
        assert STORE.effective_policy(s, 1, integ)[1] == "team"
    assert api("DELETE", "/1/cbom/gate-policy").json() == {"deleted": True}
    with Session(engine) as s:
        assert STORE.effective_policy(s, 1, integ) == (GP.DEFAULT_POLICY, "default", None)


def test_only_admins_change_it_and_only_for_their_own_cbom_integrations(api, integrations):
    assert api("PUT", "/1/cbom/gate-policy", who="bob", json={"policy": _policy()}).status_code in (400, 403)
    assert api("PUT", f"/1/cbom/gate-policy/integrations/{integrations['other']}",
               json={"policy": _policy()}).status_code == 404  # team 2's integration
    sast = api("PUT", f"/1/cbom/gate-policy/integrations/{integrations['sast']}", json={"policy": _policy()})
    assert sast.status_code == 400 and "CBOM" in sast.json()["detail"]
    assert api("GET", "/1/cbom/gate-policy", who="carol").status_code == 403  # not a member of team 1


@pytest.mark.parametrize(("change", "field"), [
    ({"min_key_bits": {"rsa": 512, "dsa": 2048, "dh": 2048, "ec": 256, "symmetric": 128}}, "policy.min_key_bits.rsa"),
    ({"quantum_vulnerable": "sometimes"}, "policy.quantum_vulnerable"),
    ({"exceptions": [{"rule": "min_key_size", "algorithm": "RSA-1024", "location": "vendor/*", "reason": "x",
                       "expires": "2020-01-01"}]}, "policy.exceptions[0].expires"),
    ({"exceptions": [{"rule": "min_key_size", "algorithm": "RSA-1024", "location": "vendor/*", "reason": "x",
                       "expires": "2099-01-01"}]}, "policy.exceptions[0].expires"),
])
def test_invalid_policies_are_a_400_naming_the_field(api, change, field):
    r = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(**change)})
    assert r.status_code == 400 and r.json()["detail"].startswith(field + ":"), r.text
    assert "sometimes" not in r.text  # the submitted value is never echoed


def test_a_wholesale_exception_is_refused_by_the_api(api):
    import datetime as dt

    soon = (dt.date.today() + dt.timedelta(days=300)).isoformat()
    for glob in ("*", "**", "/*"):
        r = api("PUT", "/1/cbom/gate-policy", json={"policy": _policy(
            exceptions=[{"rule": "finding_code", "code": "HARDCODED_KEY", "location": glob, "reason": "temporary",
                         "expires": soon}])})
        assert r.status_code == 400 and r.json()["detail"].startswith("policy.exceptions[0].location:"), r.text


def test_a_stored_policy_that_no_longer_validates_fails_closed(world):
    engine, _ = world
    import datetime as dt

    with Session(engine) as s:
        s.add(CbomGatePolicy(team_id=1, scope="team", policy={"version": 99}, row_version=1,
                             created_at=dt.datetime(2026, 1, 1), updated_at=dt.datetime(2026, 1, 1)))
        s.commit()
        policy, source, _v = STORE.effective_policy(s, 1, None)
    assert source == "unreadable" and policy == GP.PRESETS["cnsa-2.0"]


def test_a_member_is_refused_before_the_policy_is_read(world):
    # review of #483: the admin check runs before validation, so a member never learns which field is wrong
    from fastapi import HTTPException

    from backend.routers import cbom_gate_policy as R

    engine, ids = world
    with pytest.raises(HTTPException) as err:
        R._save(engine, 1, ids["bob"], None, R.PolicyBody(policy={"quantum_vulnerable": "sometimes"}))
    assert err.value.status_code == 400 and "team admin" in err.value.detail
