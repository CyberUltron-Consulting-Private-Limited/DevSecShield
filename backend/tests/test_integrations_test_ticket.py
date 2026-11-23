"""S2 (SOW Table 5, evidence "a test ticket raised successfully"): "Raise test ticket" for Jira and ServiceNow, and
Jira configured in Settings > Integrations next to ServiceNow.

Live, in-process, against the local Jira Cloud REST v3 and ServiceNow Table API receivers (``live_receivers``): the
real API (TestClient, real JWT), the real connectors and the real SSRF guard; nothing leaves this machine. Checked:
the ticket is created in the configured project / table and clearly labelled, its key and link come back, the same
click never raises a second ticket (repeat, concurrent double-click, lost answer), configuration problems are a 400
before anything is sent, only admins act, and no credential appears in any response, request body or log line.

Run (repo root): cd backend && PYTHONPATH=.. python -m pytest tests/test_integrations_test_ticket.py -q
"""
from __future__ import annotations

import logging
import sys
import threading
import uuid
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_receivers import ReceiverLab, local_address  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.cbom_gate_models import IntegrationTestTicket  # noqa: E402
from backend.new_models import Team  # noqa: E402
from backend.utilities.integrations import outbound  # noqa: E402

_FIXTURES = (api, world)
ADDRESS = local_address()
pytestmark = pytest.mark.skipif(ADDRESS is None, reason="this host has no usable non-loopback IPv4 address")


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, f"{ADDRESS}/32")
    monkeypatch.delenv("CBOM_EXTRA_CA_FILE", raising=False)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    with ReceiverLab(tmp_path, ADDRESS) as receivers:
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", receivers.pki["ca"])  # Jira uses requests
        yield receivers


def _click() -> str:
    return str(uuid.uuid4())


def _jira(api, lab, *, project="SEC", token=True, status=200, who="alice"):
    body = {"url": lab.url("jira"), "email": lab.jira_email, "project_key": project, "issue_type": "Task"}
    if token:
        body["api_token"] = lab.jira_token
    r = api("PUT", "/1/integrations/jira", who=who, json=body)
    assert r.status_code == status, r.text
    return r.json()


def _ticket(api, kind, click, status=200, who="alice"):
    r = api("POST", f"/1/integrations/{kind}/test-ticket", who=who, json={"click_id": click})
    assert r.status_code == status, r.text
    return r.json()


def _no_secret(api, lab):
    secrets_ = lab.secret_values()
    for rec in lab.records:
        raw = rec.get("body") or b""
        for value in secrets_:
            assert value.encode() not in raw, (rec["receiver"], rec.get("path"))
    for text in api.seen:
        for value in secrets_:
            assert value not in text


# ------------------------------------------------------------------------------------------------------------ Jira
def test_jira_is_configured_in_integrations_and_the_token_is_write_only(api, world, lab):
    out = _jira(api, lab)["jira"]
    assert out["configured"] and out["api_token_set"] and out["project_key"] == "SEC"
    assert "api_token" not in out and lab.jira_token not in api.seen[-1]
    engine, _ = world
    with Session(engine) as s:  # the same store the code-scan and CBOM Sources tickets read
        stored = s.get(Team, 1).integration_settings["jira"]
    assert stored["url"] == lab.url("jira") and stored["api_token"] != lab.jira_token  # encrypted at rest
    got = api("GET", "/1/integrations/jira", who="bob").json()["jira"]  # members read
    assert got["email"] == lab.jira_email and got["is_admin"] is False
    # blank token keeps the stored one; a changed URL needs it again (never sent to another site)
    assert _jira(api, lab, token=False)["jira"]["api_token_set"]
    r = api("PUT", "/1/integrations/jira", json={"url": "https://other.atlassian.net", "email": lab.jira_email})
    assert r.status_code == 400 and "re-enter" in r.json()["detail"]
    _jira(api, lab, who="bob", status=403)  # admins only (the route policy: team.integrations.manage)


def test_jira_connection_test_reads_and_creates_nothing(api, world, lab):
    _jira(api, lab)
    r = api("POST", "/1/integrations/jira/test")
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert "can see project SEC" in r.json()["message"]
    assert lab.issues == {}
    assert api("GET", "/1/integrations/jira").json()["jira"]["last_test"]["status"] == "ok"
    _jira(api, lab, project="NOPE")
    r = api("POST", "/1/integrations/jira/test").json()
    assert r["ok"] is False and "404" in r["message"]


def test_jira_raise_test_ticket_creates_a_labelled_issue_and_returns_key_and_url(api, world, lab, caplog):
    caplog.set_level(logging.DEBUG)
    _jira(api, lab)
    out = _ticket(api, "jira", _click())
    assert out["ok"] is True and out["status"] == "created" and out["repeated"] is False
    assert out["ticket_key"] == "SEC-1"
    assert out["ticket_url"] == f"{lab.url('jira')}/browse/SEC-1"
    fields = lab.issues["SEC-1"]["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "[ZeroShield] Integration test ticket - safe to close"
    assert "zs-test" in fields["labels"] and any(lb.startswith("zs-test-") for lb in fields["labels"])
    last = api("GET", "/1/integrations/jira").json()["jira"]["last_test_ticket"]
    assert last["ticket_key"] == "SEC-1"
    listed = api("GET", "/1/integrations/test-tickets?kind=jira", who="bob").json()["test_tickets"]
    assert [t["ticket_key"] for t in listed] == ["SEC-1"]
    _no_secret(api, lab)
    assert lab.jira_token not in caplog.text


def test_jira_test_ticket_is_idempotent_per_click(api, world, lab):
    _jira(api, lab)
    click = _click()
    first = _ticket(api, "jira", click)
    again = _ticket(api, "jira", click)
    assert again["ticket_key"] == first["ticket_key"] and again["repeated"] is True
    assert len(lab.issues) == 1
    other = _ticket(api, "jira", _click())  # a new click is a new ticket
    assert other["ticket_key"] == "SEC-2" and len(lab.issues) == 2


def test_jira_concurrent_double_click_raises_one_ticket(api, world, lab):
    _jira(api, lab)
    click = _click()
    lab.fail("jira", ("hang", 1.0))  # hold the first create so the second request arrives while it is in flight
    codes: list[int] = []

    def go():
        codes.append(api("POST", "/1/integrations/jira/test-ticket", json={"click_id": click}).status_code)

    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted(codes) == [200, 409], codes
    engine, _ = world
    with Session(engine) as s:
        rows = s.exec(select(IntegrationTestTicket).where(IntegrationTestTicket.click_id == click)).all()
    assert len(rows) == 1


def test_jira_lost_answer_then_retry_finds_the_issue_instead_of_a_second_one(api, world, lab):
    _jira(api, lab)
    click = _click()
    lab.fail("jira", ("lost", 201))  # Jira creates the issue, the answer never arrives
    first = _ticket(api, "jira", click)
    assert first["ok"] is False and first["status"] in ("failed", "uncertain")
    assert len(lab.issues) == 1
    retry = _ticket(api, "jira", click)
    assert retry["ok"] is True and retry["ticket_key"] == "SEC-1"
    assert len(lab.issues) == 1  # found by its click label, not created again
    assert any(r.get("searched") for r in lab.got("jira"))


def test_jira_test_ticket_needs_a_connection_and_a_project(api, world, lab):
    r = api("POST", "/1/integrations/jira/test-ticket", json={"click_id": _click()})
    assert r.status_code == 400 and "Save the Jira URL" in r.json()["detail"]
    _jira(api, lab, project="")
    r = api("POST", "/1/integrations/jira/test-ticket", json={"click_id": _click()})
    assert r.status_code == 400 and "project" in r.json()["detail"]
    assert lab.got("jira") == []  # nothing was sent
    engine, _ = world
    with Session(engine) as s:  # a refused click leaves no claim behind
        assert s.exec(select(IntegrationTestTicket)).all() == []
    assert api("POST", "/1/integrations/jira/test-ticket", json={"click_id": "not-a-uuid-not-a-uuid-not-a-uuid-xx"}
               ).status_code == 400
    _jira(api, lab)
    _ticket(api, "jira", _click(), who="bob", status=403)  # members cannot raise tickets
    assert api("POST", "/1/integrations/webhook/test-ticket", json={"click_id": _click()}).status_code in (400, 404, 422)


def test_jira_disconnect_removes_the_token(api, world, lab):
    _jira(api, lab)
    assert api("DELETE", "/1/integrations/jira").status_code == 200
    got = api("GET", "/1/integrations/jira").json()["jira"]
    assert got["configured"] is False and got["api_token_set"] is False


# ------------------------------------------------------------------------------------------------------ ServiceNow
def _servicenow(api, lab):
    r = api("PUT", "/1/integrations/servicenow", json={
        "enabled": True, "config": {"instance_url": lab.url("servicenow"), "username": lab.sn_user,
                                    "assignment_group": "Crypto Ops", "ca_pem": lab.ca_pem},
        "secrets": {"password": lab.sn_pass}})
    assert r.status_code == 200, r.text


def test_servicenow_raise_test_ticket_creates_one_labelled_incident(api, world, lab, caplog):
    caplog.set_level(logging.DEBUG)
    _servicenow(api, lab)
    click = _click()
    out = _ticket(api, "servicenow", click)
    assert out["ok"] is True and out["ticket_key"] == "INC0000001"
    (incident,) = lab.incidents.values()
    assert incident["_table"] == "incident"
    assert incident["short_description"] == "[ZeroShield CBOM] Integration test ticket - safe to close"
    assert incident["correlation_id"].startswith("zs-cbom-test-") and incident["assignment_group"] == "Crypto Ops"
    assert (incident["impact"], incident["urgency"]) == ("3", "3")
    assert out["ticket_url"] == (f"{lab.url('servicenow')}/nav_to.do?uri=incident.do%3Fsys_id%3D"
                                 f"{incident['sys_id']}")
    again = _ticket(api, "servicenow", click)
    assert again["repeated"] is True and len(lab.incidents) == 1
    _no_secret(api, lab)
    assert lab.sn_pass not in caplog.text


def test_servicenow_lost_answer_then_retry_finds_the_record(api, world, lab):
    _servicenow(api, lab)
    click = _click()
    lab.fail("servicenow", None, ("lost", None))  # lookup answered; the create is done but its answer is lost
    first = _ticket(api, "servicenow", click)
    assert first["ok"] is False and len(lab.incidents) == 1
    retry = _ticket(api, "servicenow", click)
    assert retry["ok"] is True and retry["ticket_key"] == "INC0000001" and len(lab.incidents) == 1


def test_servicenow_refused_credentials_are_reported_without_a_body(api, world, lab):
    _servicenow(api, lab)
    lab.fail("servicenow", 401)
    out = _ticket(api, "servicenow", _click())
    assert out["ok"] is False and out["status"] == "failed" and "401" in out["message"]
    assert lab.incidents == {}


def test_servicenow_test_ticket_needs_a_saved_integration(api, world, lab):
    r = api("POST", "/1/integrations/servicenow/test-ticket", json={"click_id": _click()})
    assert r.status_code == 400 and "ServiceNow" in r.json()["detail"]


def test_the_in_flight_window_outlasts_the_slowest_jira_retry():
    # review of #483: a retried click makes up to 3 Jira calls (search/jql, /search fallback, create), each bounded by
    # REQUEST_TIMEOUT; a second request of the same click must not run beside it.
    from backend.routers.integrations_ticketing import IN_FLIGHT_S
    from backend.utilities.integrations.jira import REQUEST_TIMEOUT

    assert IN_FLIGHT_S >= 180 and IN_FLIGHT_S > 3 * sum(REQUEST_TIMEOUT)
