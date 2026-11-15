"""Integrations proven live, in-process, against local receivers (``live_receivers.ReceiverLab``): no Docker, no
external service, nothing leaves this machine.

Real product code end to end: the integrations API (TestClient, real JWT), a real collection run (node enrolment,
claimed jobs, uploaded assets: ``two_runs``), drift and "scan finished" recorded by ``drift.record_pending_drift``,
the dispatcher (``dispatch.tick``) and the real transport (``outbound``: SSRF guard, address pinning, TLS
verification, timeouts). Only the clock handed to ``tick`` is chosen by the test (to step over back-off waits); the
socket read timeout is shortened for the timeout cases.

The receivers listen on a non-loopback address of this host, allowed the documented way
(``INTEGRATION_ALLOWED_PRIVATE``); their self-signed CA is trusted the documented ways (``ca_pem`` on the integration,
or ``CBOM_EXTRA_CA_FILE`` server-wide).
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_receivers import ReceiverLab, local_address  # noqa: E402
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs  # noqa: E402,F401

from backend.new_models import CbomDriftEvent, IntegrationDelivery, TeamIntegration  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.integrations import dispatch as D  # noqa: E402
from backend.utilities.integrations import events as EV  # noqa: E402
from backend.utilities.integrations import oscal as OSCAL  # noqa: E402
from backend.utilities.integrations import outbound  # noqa: E402

_FIXTURES = (api, world, two_runs)  # pytest fixtures shared with the CBOM Sources tests (used by name)
ADDRESS = local_address()
pytestmark = pytest.mark.skipif(ADDRESS is None, reason="this host has no usable non-loopback IPv4 address")
T0 = dt.datetime(2030, 1, 1, 12, 0, 0)  # the dispatcher clock (back-off is measured on it, not on the wall clock)


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, f"{ADDRESS}/32")
    monkeypatch.delenv("CBOM_EXTRA_CA_FILE", raising=False)
    monkeypatch.delenv("CBOM_LAB_CA_FILE", raising=False)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)  # a library that reads proxies (requests) must never leave the host
    monkeypatch.setenv("NO_PROXY", "*")
    with ReceiverLab(tmp_path, ADDRESS) as receivers:
        yield receivers


def _put(api, kind, body, status=200):
    r = api("PUT", f"/1/integrations/{kind}", json=body)
    assert r.status_code == status, r.text
    return r.json()


def _test(api, kind):
    r = api("POST", f"/1/integrations/{kind}/test")
    assert r.status_code == 200, r.text
    return r.json()


def _deliveries(engine, kind=None) -> list[IntegrationDelivery]:
    with Session(engine) as s:
        q = select(IntegrationDelivery).order_by(IntegrationDelivery.id)
        if kind:
            q = q.where(IntegrationDelivery.kind == kind)
        return list(s.exec(q).all())


def _integration(engine, kind) -> TeamIntegration:
    with Session(engine) as s:
        return s.exec(select(TeamIntegration).where(TeamIntegration.kind == kind)).one()


def _drift_event(engine, n, *, kind="opened", code="PROTO_TLS10", severity="High", detail=None, key=None, label=None):
    with Session(engine) as s:
        e = CbomDriftEvent(team_id=1, at=T0, scope="node", kind=kind, run_id=None, source_ref="lab", source_name="src-a",
                           asset_key=key or f"tls_endpoint|10.20.0.{n % 250}:443|{n}", asset_label=label or f"10.20.0.{n % 250}:443",
                           code=code if kind in ("opened", "resolved") else None, severity=severity,
                           detail=detail if detail is not None else {"type": "tls_endpoint", "target": "10.20.0.1",
                                                                     "location": "10.20.0.1:443"},
                           dedupe_key=f"lab-{kind}-{n}-{key}")
        s.add(e)
        s.commit()
        return e.id


def _no_secret_left_the_product(api, lab, *, allowed_in_auth=()):
    """No credential in any request body (except the OAuth token request, whose body is the client-credentials
    grant), in any header except the one that carries it, or in any API response."""
    secrets_ = lab.secret_values()
    for rec in lab.records:
        raw = rec.get("body") or rec.get("raw") or b""
        if rec.get("path") == "/oauth_token.do":
            continue
        for value in secrets_:
            assert value.encode() not in raw, (rec["receiver"], rec.get("path"))
        for header, text in (rec.get("headers") or {}).items():
            for value in secrets_:
                if value in text:
                    assert (rec["receiver"], header) in allowed_in_auth, (rec["receiver"], header)
    for text in api.seen:
        for value in secrets_:
            assert value not in text


# ------------------------------------------------------------------------------------------------- webhook
def test_webhook_self_signed_trust_signed_events_after_a_real_run(api, two_runs, lab, tmp_path, monkeypatch):
    engine = two_runs["engine"]
    hook = {"enabled": True, "config": {"url": lab.url("webhook", "/hook")}, "secrets": {"signing_secret": lab.hook_secret}}
    # the self-signed receiver is not trusted until the operator says so
    _put(api, "webhook", hook)
    untrusted = _test(api, "webhook")
    assert not untrusted["ok"] and "not trusted" in untrusted["message"], untrusted
    assert lab.got("webhook") == []  # the TLS handshake failed: nothing was sent
    # documented way 1: the server-wide extra CA file
    monkeypatch.setenv("CBOM_EXTRA_CA_FILE", lab.pki["ca"])
    assert _test(api, "webhook")["ok"]
    monkeypatch.delenv("CBOM_EXTRA_CA_FILE")
    # documented way 2: the destination's own CA (ca_pem). A new trust anchor is a "where" change: the stored secret
    # is cleared and must be entered again (a secret never follows a new destination or CA)
    with_ca = {"enabled": True, "config": {"url": lab.url("webhook", "/hook"), "ca_pem": lab.ca_pem}}
    assert "re-enter it" in _put(api, "webhook", with_ca, status=400)["detail"]
    _put(api, "webhook", {**with_ca, "secrets": {"signing_secret": lab.hook_secret}})
    test = _test(api, "webhook")
    assert test["ok"] and test["confirmed"], test
    tests = lab.got("webhook")
    assert len(tests) == 2 and all(r["verified"] and r["event_type"] == "integration.test" for r in tests)

    # a real run's drift and "scan finished" events, delivered by the dispatcher
    assert DRIFT.record_pending_drift(engine, T0) == 2
    totals = D.tick(engine, T0)
    rows = _deliveries(engine, "webhook")
    assert rows and totals["delivered"] == len(rows) and all(d.status == "delivered" for d in rows), \
        [(d.event_type, d.status, d.last_result) for d in rows]
    got = [r for r in lab.got("webhook") if r["event_type"] != "integration.test"]
    assert len(got) == len(rows)  # exactly once each
    assert all(r["verified"] for r in got)  # the documented receiver snippet accepts every signature
    assert [r["event_id"] for r in got] == [d.event_uid for d in rows]  # in queue order
    for r in got:
        body = r["json"]
        assert r["event_id"] == body["id"] and r["event_type"] == body["type"]
        assert body["schema"] == EV.SCHEMA and body["type"] in EV.TYPES.values() and body["kind"] in EV.EVENT_KINDS
        assert set(body["detail"]) <= set(EV._DETAIL_KEYS), body["detail"]
        assert r["headers"]["content-type"] == "application/json"
    types = {r["event_type"] for r in got}
    assert {"scan.finished", "finding.resolved", "asset.removed", "asset.new"} <= types, types
    finished = {r["json"]["run_id"]: r["json"] for r in got if r["event_type"] == "scan.finished"}
    assert set(finished) == {two_runs["run1"]["id"], two_runs["run2"]["id"]}
    summary = finished[two_runs["run2"]["id"]]["summary"]
    run2 = api("GET", f"/1/cbom/sources/runs/{two_runs['run2']['id']}").json()["run"]
    assert summary["status"] == run2["status"]
    resolved = {(r["json"]["finding"]["code"], r["json"]["asset"]["type"]) for r in got
                if r["event_type"] == "finding.resolved"}
    assert ("PROTO_TLS10", "tls_endpoint") in resolved  # the run comparison's fix reached the receiver
    # a second tick sends nothing again
    before = len(lab.records)
    assert D.tick(engine, T0 + dt.timedelta(minutes=1))["delivered"] == 0 and len(lab.records) == before
    _no_secret_left_the_product(api, lab)


def test_webhook_retry_backoff_timeout_and_dead_letter(api, world, lab, monkeypatch):
    engine, _ = world
    _put(api, "webhook", {"enabled": True, "config": {"url": lab.url("webhook", "/hook"), "ca_pem": lab.ca_pem},
                          "secrets": {"signing_secret": lab.hook_secret}})
    first = _drift_event(engine, 1)
    _drift_event(engine, 2, kind="resolved")
    # 503 with Retry-After: the queue holds, the integration backs off at least Retry-After
    lab.fail("webhook", 503)
    t = D.tick(engine, T0)
    assert t == {**t, "delivered": 0, "retry": 1}
    integ = _integration(engine, "webhook")
    assert integ.failures == 1 and "HTTP 503" in integ.last_error
    assert integ.next_attempt_at >= T0 + dt.timedelta(seconds=120)  # Retry-After: 120 honoured over 30 s back-off
    assert D.tick(engine, T0 + dt.timedelta(seconds=60))["integrations"] == 0  # not due: nothing sent
    assert len(lab.got("webhook")) == 1
    # a receiver that never answers: the read timeout turns it into a retry, not a hung dispatcher
    monkeypatch.setattr(outbound, "READ_TIMEOUT", 1.0)
    lab.fail("webhook", ("hang", 4.0))
    t = D.tick(engine, T0 + dt.timedelta(minutes=5))
    integ = _integration(engine, "webhook")
    assert t["retry"] == 1 and "timed out" in integ.last_error and integ.failures == 2, integ.last_error
    assert integ.next_attempt_at >= T0 + dt.timedelta(minutes=5, seconds=48)  # 60 s doubled back-off (+-20 %)
    # recovery: both delivered in order, the first with the SAME event id on every attempt
    t = D.tick(engine, T0 + dt.timedelta(minutes=30))
    assert t["delivered"] == 2, t
    hooks = lab.got("webhook")
    with Session(engine) as s:
        uid = EV.event_uid("drift", 1, s.get(CbomDriftEvent, first).dedupe_key)
    assert [r["event_id"] for r in hooks[:3]] == [uid] * 3
    assert all(r["verified"] for r in hooks if r.get("status") == 200)
    integ = _integration(engine, "webhook")
    assert integ.failures == 0 and integ.last_error is None and integ.next_attempt_at is None
    # 400 for one event: dead-lettered, the queue moves on; 410: the receiver is gone for that event
    _drift_event(engine, 3)
    _drift_event(engine, 4)
    _drift_event(engine, 5)
    lab.fail("webhook", 400, 410)
    t = D.tick(engine, T0 + dt.timedelta(minutes=31))
    assert (t["delivered"], t["dead"], t["retry"]) == (1, 2, 0), t
    dead = [d for d in _deliveries(engine, "webhook") if d.status == "dead"]
    assert [d.last_result for d in dead] == ["HTTP 400", "HTTP 410: the receiver no longer accepts these events"]
    # dead letters are retried from the API with their event id
    r = api("POST", "/1/integrations/deliveries/retry", json={"ids": [d.id for d in dead]})
    assert r.status_code == 200, r.text
    assert D.tick(engine, T0 + dt.timedelta(minutes=32))["delivered"] == 2
    assert {r["event_id"] for r in lab.got("webhook", status=200)} >= {d.event_uid for d in dead}
    _no_secret_left_the_product(api, lab)


def test_only_allowlisted_detail_keys_leave_the_product(api, world, lab):
    engine, _ = world
    _put(api, "webhook", {"enabled": True, "config": {"url": lab.url("webhook", "/hook"), "ca_pem": lab.ca_pem},
                          "secrets": {"signing_secret": lab.hook_secret}})
    _drift_event(engine, 7, detail={"type": "certificate", "target": "10.20.0.7", "location": "10.20.0.7:443",
                                    "not_after": "2031-01-01T00:00:00Z", "facts": {"subject": "CN=x"},
                                    "credential": "do-not-send", "raw": "-----BEGIN PRIVATE KEY-----"})
    assert D.tick(engine, T0)["delivered"] == 1
    body = lab.got("webhook")[0]
    assert body["verified"]
    assert set(body["json"]["detail"]) == {"type", "target", "location", "not_after"}
    assert b"do-not-send" not in body["body"] and b"PRIVATE KEY" not in body["body"] and b"CN=x" not in body["body"]


# ------------------------------------------------------------------------------------------------- syslog
def _syslog(api, lab, transport, fmt="cef", ca=True):
    name = {"udp": "syslog-udp", "tcp": "syslog-tcp", "tls": "syslog-tls"}[transport]
    cfg = {"host": lab.ip, "port": lab.ports[name], "transport": transport, "format": fmt,
           "sender_name": "zs-mumbai-01"}
    if transport == "tls" and ca:
        cfg["ca_pem"] = lab.ca_pem
    _put(api, "syslog", {"enabled": True, "config": cfg})
    return name


def _frames(lab, name):
    return [r for r in lab.got(name) if "valid" in r]


@pytest.mark.parametrize("transport,fmt", [("tls", "cef"), ("tcp", "json"), ("udp", "cef")])
def test_syslog_rfc5424_framing_batching_after_a_real_run(api, two_runs, lab, transport, fmt):
    engine = two_runs["engine"]
    name = _syslog(api, lab, transport, fmt)
    test = _test(api, "syslog")
    if transport == "udp":
        assert test["ok"] and not test["confirmed"] and test["status"] == "unconfirmed", test  # never "passed"
    else:
        assert test["ok"] and test["confirmed"], test
    assert DRIFT.record_pending_drift(engine, T0) == 2
    for n in range(230):  # with the run's events: more than one dispatcher batch (200 per connection)
        _drift_event(engine, 100 + n, severity=("Critical", "High", "Medium", "Low")[n % 4])
    D.tick(engine, T0)
    rows = _deliveries(engine, "syslog")
    assert len(rows) > 230 and all(d.status == "delivered" for d in rows)
    frames = lab.wait_for(name, len(rows) + 1, timeout=10)
    frames = _frames(lab, name)
    assert len(frames) == len(rows) + 1, (len(frames), len(rows))  # + the test event; none lost, none twice
    assert all(f["valid"] for f in frames), [f["head"] for f in frames if not f["valid"]][:3]
    for f in frames:
        pri = int(f["pri"])
        assert pri // 8 == 16 and f["version"] == "1" and f["hostname"] == "zs-mumbai-01"
        assert f["app"] == "zeroshield-cbom" and f["procid"] == "-" and f["sd"] == "-"
        assert f["timestamp"].endswith("Z") and f["format"] == fmt
    by_id = {f["event_id"]: f for f in frames}
    assert {d.event_uid for d in rows} <= set(by_id)
    for d in rows:  # PRI severity follows the event severity
        sev = {"Critical": 2, "High": 3, "Medium": 4, "Low": 5, "Info": 6}[d.payload["severity"]]
        assert int(by_id[d.event_uid]["pri"]) == 16 * 8 + sev
        assert by_id[d.event_uid]["msgid"] == d.event_type
    if fmt == "cef":
        for f in frames:
            head = f["msg"].split("|")
            assert head[:4] == ["CEF:0", "ZeroShield", "DevSecShield CBOM", "1.0"] and head[6].isdigit()
    else:
        assert all(f["event"]["schema"] == EV.SCHEMA for f in frames if f["event_id"] in {d.event_uid for d in rows})
    if transport != "udp":
        conns = [r for r in lab.got(name) if r.get("closed")]
        # one connection per dispatcher batch (200 events), closed cleanly after the last frame
        assert [c["frames"] for c in conns] == [1, 200, len(rows) - 200], [c["frames"] for c in conns]
        assert all(f["msg_len"] == f["bytes"] for f in frames)  # octet counting matches the message
    else:
        assert all(f["bytes"] <= 2048 for f in frames)


def test_syslog_failures_hold_the_queue(api, world, lab):
    engine, _ = world
    _syslog(api, lab, "tls", ca=False)
    untrusted = _test(api, "syslog")
    assert not untrusted["ok"] and "not trusted" in untrusted["message"], untrusted
    _drift_event(engine, 1)
    t = D.tick(engine, T0)
    assert t["retry"] == 1 and "not trusted" in _integration(engine, "syslog").last_error
    assert _frames(lab, "syslog-tls") == []
    # TCP receiver down: refused, retried later, delivered when it is back (same event, once)
    _syslog(api, lab, "tcp")
    lab.stop_receiver("syslog-tcp")
    t = D.tick(engine, T0 + dt.timedelta(hours=1))
    integ = _integration(engine, "syslog")
    assert t["retry"] == 1 and "refused the connection" in integ.last_error, integ.last_error
    assert _deliveries(engine, "syslog")[0].status == "pending"
    # a long message over UDP is cut at 2048 octets (RFC 5426 3.2) and still parses as RFC 5424
    _syslog(api, lab, "udp")
    _drift_event(engine, 2, label="l" * 1500, detail={"type": "tls_endpoint", "target": "10.20.0.1", "location": "x" * 3000})
    assert D.tick(engine, T0 + dt.timedelta(hours=3))["delivered"] == 2
    grams = lab.wait_for("syslog-udp", 2)
    assert [g["bytes"] for g in grams][-1] == 2048 and all(g["valid"] for g in grams)


# ------------------------------------------------------------------------------------------------- Splunk HEC
def test_splunk_hec_batches_tokens_and_failures(api, world, lab):
    engine, _ = world
    cfg = {"url": lab.url("hec"), "index": "zs_cbom", "sourcetype": "zeroshield:cbom", "ca_pem": lab.ca_pem}
    _put(api, "splunk_hec", {"enabled": True, "config": cfg, "secrets": {"token": "00000000-0000-0000-0000-000000000000"}})
    bad = _test(api, "splunk_hec")
    assert not bad["ok"] and bad["message"] == "HTTP 403: the credentials were refused", bad
    _put(api, "splunk_hec", {"enabled": True, "config": cfg, "secrets": {"token": lab.hec_token}})
    assert _test(api, "splunk_hec")["ok"]
    for n in range(230):
        _drift_event(engine, n)
    # the second HTTP request of the first batch is refused as busy: the first 100 are delivered, the rest wait
    lab.fail("hec", None, 503)
    t = D.tick(engine, T0)
    assert (t["delivered"], t["retry"]) == (100, 1), t
    integ = _integration(engine, "splunk_hec")
    assert "HEC code 9" in integ.last_error and integ.next_attempt_at >= T0 + dt.timedelta(seconds=120)
    t = D.tick(engine, T0 + dt.timedelta(minutes=10))
    assert t["delivered"] == 130, t
    posts = [r for r in lab.got("hec") if r.get("status") == 200]
    sizes = [len(r["events"]) for r in posts]
    assert sizes == [1, 100, 100, 30], sizes  # test event, then at most 100 stacked events per request
    events = [e for r in posts[1:] for e in r["events"]]
    assert [e["event"]["id"] for e in events] == [d.event_uid for d in _deliveries(engine, "splunk_hec")]
    assert all(e["index"] == "zs_cbom" and e["sourcetype"] == "zeroshield:cbom" and isinstance(e["time"], float)
               for e in events)
    # an incorrect index (HTTP 400, code 7) dead-letters that batch; the queue moves on
    _drift_event(engine, 999)
    lab.fail("hec", 400)
    t = D.tick(engine, T0 + dt.timedelta(minutes=20))
    assert t["dead"] == 1
    dead = [d for d in _deliveries(engine, "splunk_hec") if d.status == "dead"]
    assert len(dead) == 1 and "HEC code 7" in dead[0].last_result
    _no_secret_left_the_product(api, lab, allowed_in_auth={("hec", "authorization")})


# ------------------------------------------------------------------------------------------------- ServiceNow
def test_servicenow_incident_create_dedupe_lost_response_and_resolve(api, world, lab):
    engine, _ = world
    _put(api, "servicenow", {"enabled": True, "config": {"instance_url": lab.url("servicenow"), "username": lab.sn_user,
                                                         "category": "Security", "ca_pem": lab.ca_pem},
                             "secrets": {"password": lab.sn_pass}})
    assert _test(api, "servicenow")["ok"]
    assert lab.incidents == {}  # the test reads one record and creates nothing
    key_a, key_b = "tls_endpoint|10.20.0.1:443", "tls_endpoint|10.20.0.2:443"
    _drift_event(engine, 1, key=key_a, severity="High")
    _drift_event(engine, 2, key=key_a, severity="High")  # the same finding opened again (another run): no 2nd record
    _drift_event(engine, 3, key=key_b, severity="Critical")
    # requests: A lookup, A create, A lookup, B lookup, B create: B's create is done but the answer is lost
    lab.fail("servicenow", None, None, None, None, ("lost", None))
    t = D.tick(engine, T0)
    assert (t["delivered"], t["retry"]) == (2, 1), t
    t = D.tick(engine, T0 + dt.timedelta(minutes=10))
    assert t["delivered"] == 1, t
    rows = _deliveries(engine, "servicenow")
    assert [d.last_result for d in rows] == ["created INC0000001", "already open", "already open"], \
        [d.last_result for d in rows]
    assert len(lab.incidents) == 2  # one record per finding, the lost response did not make a duplicate
    inc = {r["number"]: r for r in lab.incidents.values()}
    assert (inc["INC0000001"]["impact"], inc["INC0000001"]["urgency"]) == ("1", "2")  # High -> P2
    assert (inc["INC0000002"]["impact"], inc["INC0000002"]["urgency"]) == ("1", "1")  # Critical -> P1
    assert inc["INC0000001"]["category"] == "Security" and inc["INC0000001"]["correlation_id"].startswith("zs-cbom-")
    assert rows[2].external_ref == "INC0000002"
    # resolved by a later run: the active record is resolved, never a new one
    _drift_event(engine, 4, kind="resolved", key=key_a)
    _drift_event(engine, 5, kind="resolved", key=key_a)  # nothing open any more: nothing changed
    assert D.tick(engine, T0 + dt.timedelta(minutes=20))["delivered"] == 2
    rows = _deliveries(engine, "servicenow")
    assert [d.last_result for d in rows[3:]] == ["resolved INC0000001", "no open record to resolve"]
    assert inc["INC0000001"]["state"] == "6" and inc["INC0000001"]["active"] == "false"
    assert inc["INC0000001"]["close_code"] == "Solution provided" and "no longer finds" in inc["INC0000001"]["close_notes"]
    assert inc["INC0000002"]["active"] == "true"
    # opened again after the fix regressed: a new record (the old one is resolved)
    _drift_event(engine, 6, key=key_a, severity="High")
    assert D.tick(engine, T0 + dt.timedelta(minutes=30))["delivered"] == 1
    assert _deliveries(engine, "servicenow")[-1].last_result == "created INC0000003"
    _no_secret_left_the_product(api, lab, allowed_in_auth={("servicenow", "authorization")})


def test_servicenow_oauth_client_credentials(api, world, lab):
    engine, _ = world
    _put(api, "servicenow", {"enabled": True, "config": {
        "instance_url": lab.url("servicenow"), "auth": "oauth", "client_id": lab.sn_client_id, "ca_pem": lab.ca_pem},
        "secrets": {"client_secret": lab.sn_client_secret}})
    assert _test(api, "servicenow")["ok"]
    _drift_event(engine, 1, severity="Medium")
    assert D.tick(engine, T0)["delivered"] == 1
    assert [r["number"] for r in lab.incidents.values()] == ["INC0000001"]
    assert all(r["headers"].get("authorization", "").startswith("Bearer ") for r in lab.got("servicenow")
               if r["path"].startswith("/api/now/"))
    _no_secret_left_the_product(api, lab)


# ------------------------------------------------------------------------------------------------- OSCAL
def test_oscal_push_after_a_real_run_is_valid_official_oscal(api, two_runs, lab):
    import hashlib

    engine = two_runs["engine"]
    # the vendored schema is byte-identical to the usnistgov/OSCAL v1.2.3 release asset
    # oscal_assessment-results_schema.json (sha256 checked against the download on 14 Nov 2026)
    assert hashlib.sha256(OSCAL.SCHEMA_FILE.read_bytes()).hexdigest() == \
        "4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c"
    _put(api, "oscal", {"enabled": True, "config": {"url": lab.url("webhook", "/oscal"), "ca_pem": lab.ca_pem},
                        "secrets": {"signing_secret": lab.hook_secret}})
    assert _test(api, "oscal")["ok"]
    assert DRIFT.record_pending_drift(engine, T0) == 2
    assert D.tick(engine, T0)["delivered"] == 2
    pushes = lab.got("webhook")
    assert len(pushes) == 3 and all(p["verified"] and p["path"] == "/oscal" for p in pushes)
    validator = _official_validator()
    for p in pushes:
        errors = sorted(validator.iter_errors(p["json"]), key=lambda e: list(e.absolute_path))
        assert errors == [], [e.message for e in errors[:3]]
    docs = {p["json"]["assessment-results"]["metadata"]["version"]: p["json"] for p in pushes[1:]}
    run1, run2 = two_runs["run1"]["id"], two_runs["run2"]["id"]
    assert set(docs) == {f"run-{run1}", f"run-{run2}"}
    # the pushed document is the one the download route serves
    served = api("GET", f"/1/cbom/sources/runs/{run2}/oscal")
    assert served.status_code == 200
    a = json.loads(served.content)["assessment-results"]["results"]
    b = docs[f"run-{run2}"]["assessment-results"]["results"]
    assert [f["uuid"] for f in a[0].get("findings", [])] == [f["uuid"] for f in b[0].get("findings", [])]


def _official_validator():
    """Draft-07 validation of the official schema with Unicode-aware ``pattern`` (the schema uses \\p{L} classes)."""
    import jsonschema
    import regex

    schema = json.loads(OSCAL.SCHEMA_FILE.read_text())

    def pattern(validator, patrn, instance, _schema):
        if validator.is_type(instance, "string") and not regex.search(patrn, instance):
            yield jsonschema.ValidationError(f"{instance[:60]!r} does not match {patrn[:60]!r}")

    return jsonschema.validators.extend(jsonschema.Draft7Validator, {"pattern": pattern})(
        schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)


# ------------------------------------------------------------------------------------------------- Jira (code scans)
class _Findings:
    """The ``scan_findings`` collection (Mongo) the ticketing code reads and updates."""

    def __init__(self, docs):
        self.docs = docs

    def find(self, query):
        return [d for d in self.docs if all(d.get(k) == v for k, v in query.items())]

    def update_one(self, query, change):
        hit = [d for d in self.docs if d["_id"] == query["_id"]]
        for d in hit:
            d.update(change["$set"])
        return type("R", (), {"modified_count": len(hit)})()


def _cbom_row(title, location, codes, *, line=10, impact="High"):
    return {"title": title, "algorithm_name": title, "asset_type": "algorithm", "location": location, "line": line,
            "bom_ref": f"crypto-algo-{title.lower()}-{location}-l{line}", "finding_codes": codes,
            "impact": impact if codes else None, "quantum_safe": not codes}


def test_jira_code_scan_tickets_on_prem_dedupe_across_scans_and_close_on_fixed(world, lab, monkeypatch):
    """Code-scan auto-Jira against a self-hosted Jira on a private address (Jira Server / Data Center in the bank's
    network, opened by the operator in INTEGRATION_ALLOWED_PRIVATE): one ticket per finding, the SAME ticket while a
    re-scan of the repository still has the finding, closed when a later scan no longer has it."""
    import backend.get_db as get_db_module
    from backend.new_models import Scan, Team
    from backend.utilities.integrations import jira_ticketing as JT

    engine, ids = world
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", lab.pki["ca"])  # requests' own trust setting (Jira uses requests)
    docs: list[dict] = []
    monkeypatch.setattr(get_db_module, "get_mongo_client_db", lambda: {"scan_findings": _Findings(docs)})
    des, rsa, aes = (_cbom_row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"]),
                     _cbom_row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low"),
                     _cbom_row("AES-256-GCM", "app.py", []))
    meta = {"repo_url": "https://github.com/acme/pay.git", "branch": "main"}
    jira = {"jira": {"jira_project_id": "10001", "auto_create_tickets": True}}
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.integration_settings = {"jira": {"url": lab.url("jira"), "email": lab.jira_email,
                                              "api_token": lab.jira_token}}
        s.add(team)
        for scan_id, rows, day in ((40, [des, rsa, aes], 1), (41, [{**rsa, "line": 30}, aes], 2), (42, [aes], 3)):
            s.add(Scan(id=scan_id, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay",
                       scan_status="success", scan_metadata=meta, integration_settings=jira,
                       created_at=dt.datetime(2026, 10, day), scan_data={"results": rows}))
        s.commit()

    def store(scan_id, rows):  # what the worker stores per scan: every row, findings and clean inventory
        docs.extend({"_id": f"{scan_id}-{n}", "scan_id": scan_id, "finding_data": r, "finding_status": "not_started"}
                    for n, r in enumerate(rows))

    store(40, [des, rsa, aes])
    assert JT.auto_create_tickets_for_successful_scan(40, engine) == 2  # findings only: 3DES and RSA, not AES-GCM
    assert sorted(lab.issues) == ["SEC-1", "SEC-2"]
    assert JT.auto_create_tickets_for_successful_scan(40, engine) == 0  # once per finding
    created = lab.got("jira", method="POST", path="/rest/api/3/issue")
    assert all(r["status"] == 201 for r in created) and len(created) == 2
    summaries = {lab.issues[k]["fields"]["summary"] for k in lab.issues}
    assert summaries == {"[cbom] 3DES-CBC", "[cbom] RSA-2048"}

    # the next scan of the same repository and branch still has the RSA finding (on another line): no second ticket
    store(41, [{**rsa, "line": 30}, aes])
    assert JT.auto_create_tickets_for_successful_scan(41, engine) == 0
    assert sorted(lab.issues) == ["SEC-1", "SEC-2"]
    rsa41 = next(d for d in docs if d["scan_id"] == 41 and d["finding_data"]["title"] == "RSA-2048")
    assert rsa41["info"]["jira_issue_key"] == "SEC-2"
    # ... and 3DES is gone: its ticket is closed (Done transition)
    assert DRIFT.on_code_scan_success(41, engine, now=dt.datetime(2026, 10, 2, 12))["fixed"] == 1
    assert lab.issues["SEC-1"]["status"] == "Done" and lab.issues["SEC-2"]["status"] == "To Do"
    # the RSA finding is fixed in the third scan: the ticket carried by scan 41 is closed
    store(42, [aes])
    assert JT.auto_create_tickets_for_successful_scan(42, engine) == 0
    assert DRIFT.on_code_scan_success(42, engine, now=dt.datetime(2026, 10, 3, 12))["fixed"] == 1
    assert lab.issues["SEC-2"]["status"] == "Done" and len(lab.issues) == 2
    for rec in lab.got("jira"):
        assert lab.jira_token.encode() not in rec["body"]


def test_jira_private_address_still_needs_the_operator_allowlist(world, lab, monkeypatch):
    from backend.utilities.integrations.jira import validate_jira_url

    url = lab.url("jira")
    assert validate_jira_url(url) is True  # listed in INTEGRATION_ALLOWED_PRIVATE by the lab fixture
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE)
    with pytest.raises(ValueError, match="private"):
        validate_jira_url(url)
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "0.0.0.0/0")
    for never in ("https://127.0.0.1/", "https://169.254.169.254/", "https://[::1]/", "https://localhost/"):
        with pytest.raises(ValueError):
            validate_jira_url(never)
