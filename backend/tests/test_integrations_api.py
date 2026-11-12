"""Integrations API, dispatcher and OSCAL (WP11) on the SQLite + real-router harness of the CBOM Sources tests.

Admin-only changes, write-only secrets (a canary never comes back), a secret cleared when the destination changes,
SSRF refusals through the real guard, at-least-once delivery in order with back-off, dead-letter and retry, one
dispatcher per integration, "scan finished" events, schema-valid OSCAL exports, and team-delete cleanup."""
from __future__ import annotations

import datetime as dt
import json
import sys
import threading
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs, _row, _FakeMongo  # noqa: E402,F401

from backend.new_models import CbomDriftEvent, IntegrationDelivery, Scan, TeamIntegration  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team  # noqa: E402
from backend.utilities.integrations import dispatch as D  # noqa: E402
from backend.utilities.integrations import events as EV  # noqa: E402
from backend.utilities.integrations import oscal as OSCAL  # noqa: E402
from backend.utilities.integrations import outbound, webhook  # noqa: E402

CANARY = "Canary-Webhook-Secret-7f3a91c2"
HOOK = {"enabled": True, "config": {"url": "https://hooks.example/zs"}, "secrets": {"signing_secret": CANARY}}


class Receiver:
    """Stands in for outbound.request in webhook/oscal: verifies the signature like a real receiver would."""

    def __init__(self, statuses=None):
        self.statuses = list(statuses or [])
        self.received: list[dict] = []
        self.lock = threading.Lock()

    def __call__(self, method, url, *, headers=None, body=None, ca_pem=None, total=20.0, max_body=0):
        with self.lock:
            status = self.statuses.pop(0) if self.statuses else 200
            ok = webhook.verify(CANARY, body, headers["X-ZS-Timestamp"], headers["X-ZS-Signature"])
            self.received.append({"status": status, "verified": ok, "id": headers["X-ZS-Event-Id"],
                                  "type": headers["X-ZS-Event-Type"], "body": json.loads(body), "url": url})
        return outbound.Response(status, "", {"retry-after": "1"} if status == 503 else {}, b"{}")


def _drift(engine, n=3, team=1, start=0):
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        for i in range(start, start + n):
            s.add(CbomDriftEvent(team_id=team, at=now, scope="node", kind="opened" if i % 2 == 0 else "resolved",
                                 run_id=5, source_ref="uid", source_name="src", asset_key=f"{i:032x}",
                                 asset_label=f"asset-{i}", code="PROTO_TLS10", severity="High",
                                 detail={"type": "tls_endpoint", "location": f"10.0.0.{i}:443"}, dedupe_key=f"d{i}"))
        s.commit()


# ----------------------------------------------------------------------------- API rules
def test_admin_only_secrets_write_only_and_cleared_when_the_destination_changes(api):
    listed = api("GET", "/1/integrations").json()
    assert [i["kind"] for i in listed["integrations"]] == ["servicenow", "syslog", "splunk_hec", "webhook", "oscal"]
    assert "hmac.new" in listed["webhook_verify_snippet"]
    assert api("PUT", "/1/integrations/webhook", "bob", json=HOOK).status_code == 403  # member: the route policy refuses (F4 RBAC)
    assert api("PUT", "/1/integrations/nope", json=HOOK).status_code == 404
    r = api("PUT", "/1/integrations/webhook", json=HOOK)
    assert r.status_code == 200, r.text
    hook = r.json()["integration"]
    assert hook["enabled"] and hook["secrets_set"] == ["signing_secret"] and hook["row_version"] == 1
    # bad configs are a readable 400 that never echoes the input
    bad = api("PUT", "/1/integrations/webhook", json={**HOOK, "config": {"url": "http://hooks.example/zs?" + CANARY}})
    assert bad.status_code == 400 and "https" in bad.json()["detail"]
    assert api("PUT", "/1/integrations/webhook", json={**HOOK, "secrets": {"signing_secret": "short"}}).status_code == 400
    # a new URL without the secret re-entered: refused, and the stored secret is not carried over
    moved = api("PUT", "/1/integrations/webhook", json={"enabled": True, "config": {"url": "https://evil.example/x"},
                                                        "expected_version": 1})
    assert moved.status_code == 400 and "re-enter" in moved.json()["detail"]
    kept = api("PUT", "/1/integrations/webhook", json={"enabled": True, "config": {"url": "https://hooks.example/zs",
                                                                                     "events": ["opened"]},
                                                       "expected_version": 1})
    assert kept.status_code == 200 and kept.json()["integration"]["secrets_set"] == ["signing_secret"]
    assert api("PUT", "/1/integrations/webhook", json={**HOOK, "expected_version": 1}).status_code == 409
    assert api("GET", "/2/integrations", "carol").json()["integrations"][3]["configured"] is False  # tenancy
    for text in api.seen:
        assert CANARY not in text
    assert api("DELETE", "/1/integrations/webhook", "bob").status_code == 403  # admins only: the route policy refuses a member (F4 RBAC)
    assert api("DELETE", "/1/integrations/webhook").json() == {"deleted": "webhook"}


def test_test_button_goes_through_the_ssrf_guard(api, monkeypatch):
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    for url, words in (("https://127.0.0.1/hook", "never allowed"), ("https://169.254.169.254/latest", "never allowed"),
                       ("https://[::1]:8443/x", "never allowed"), ("https://100.100.100.200/", "never allowed"),
                       ("https://10.20.30.40/hook", "INTEGRATION_ALLOWED_PRIVATE")):
        # Round 5, L1: saving it enabled is refused with Test's own message (it was saved, then every Test failed)
        refused = api("PUT", "/1/integrations/webhook", json={**HOOK, "config": {"url": url}})
        assert refused.status_code == 400 and words in refused.json()["detail"], (url, refused.text)
        assert refused.json()["detail"].startswith("URL: ")
        # saved disabled it is kept (turning an integration off is never blocked), and Test still refuses it
        assert api("PUT", "/1/integrations/webhook",
                   json={**HOOK, "enabled": False, "config": {"url": url}}).status_code == 200
        r = api("POST", "/1/integrations/webhook/test")
        assert r.status_code == 200 and r.json()["ok"] is False and words in r.json()["message"], (url, r.text)
    syslog = api("PUT", "/1/integrations/syslog", json={"enabled": True, "config": {"host": "169.254.169.254",
                                                                                   "transport": "udp"}})
    assert syslog.status_code == 400 and syslog.json()["detail"].startswith("Host: ")
    assert "never allowed" in syslog.json()["detail"]
    syslog = api("PUT", "/1/integrations/syslog", json={"enabled": False, "config": {"host": "169.254.169.254",
                                                                                    "transport": "udp"}})
    assert syslog.status_code == 200
    assert "never allowed" in api("POST", "/1/integrations/syslog/test").json()["message"]
    listed = {i["kind"]: i for i in api("GET", "/1/integrations").json()["integrations"]}
    assert listed["syslog"]["last_test"]["status"] == "failed"
    assert api("POST", "/1/integrations/splunk_hec/test").status_code == 400  # not saved yet
    assert api("POST", "/1/integrations/webhook/test", "bob").status_code == 403  # admins only: the route policy refuses a member (F4 RBAC)


def test_a_udp_syslog_test_is_sent_unconfirmed_never_passed(api, monkeypatch):
    """rev4 M1: UDP has no delivery confirmation (a port with no listener looks the same), yet the test said "Test
    passed". It now reports status "unconfirmed" (ok, confirmed False); TCP / TLS keep "ok"."""
    from backend.utilities.integrations import siem

    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.0.0.0/8")
    sent: list[bytes] = []
    monkeypatch.setattr(siem.outbound, "send_datagrams", lambda host, port, grams: sent.extend(grams) or len(grams))
    monkeypatch.setattr(siem.outbound, "send_stream", lambda host, port, frames, **k: len(frames))
    assert api("PUT", "/1/integrations/syslog", json={"enabled": True, "config": {"host": "10.1.2.3",
                                                                                "transport": "udp"}}).status_code == 200
    r = api("POST", "/1/integrations/syslog/test").json()
    assert (r["ok"], r["confirmed"], r["status"]) == (True, False, "unconfirmed") and "unconfirmed" in r["message"]
    assert len(sent) == 1
    listed = {i["kind"]: i for i in api("GET", "/1/integrations").json()["integrations"]}
    assert listed["syslog"]["last_test"]["status"] == "unconfirmed"
    assert api("PUT", "/1/integrations/syslog", json={"enabled": True, "config": {"host": "10.1.2.3",
                                                                                "transport": "tcp"}}).status_code == 200
    r = api("POST", "/1/integrations/syslog/test").json()
    assert (r["ok"], r["confirmed"], r["status"]) == (True, True, "ok")


def test_a_connection_test_is_audited(api, world, monkeypatch):
    """rev4 L4: a test sends data to an external destination but left no audit row (save / delete / retry did)."""
    from backend.new_models import CbomCollectionAuditEvent

    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    monkeypatch.setattr(webhook.outbound, "request", Receiver([200, 503]))
    assert api("POST", "/1/integrations/webhook/test").json()["ok"] is True
    assert api("POST", "/1/integrations/webhook/test").json()["ok"] is False  # a failed test is audited too
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.action == "integration.test")).all()
        integration = s.exec(select(TeamIntegration).where(TeamIntegration.kind == "webhook")).one()
    assert [(r.team_id, r.actor_type, r.object_type, r.object_id) for r in rows] == \
        [(1, "user", "integration", integration.id)] * 2
    assert all(r.actor_id is not None and r.changed_fields == ["last_test_status"] for r in rows)


# ----------------------------------------------------------------------------- dispatcher
def test_drift_events_are_delivered_once_in_order_with_stable_ids(api, world, monkeypatch):
    engine, _ = world
    _drift(engine, 2)  # before any integration: stamped, never delivered later
    assert D.tick(engine)["queued"] == 0
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver()
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    _drift(engine, 4, start=10)
    _drift(engine, 2, team=2, start=20)  # another team's events never reach team 1's webhook
    out = D.tick(engine)
    assert out["queued"] == 4 and out["delivered"] == 4
    assert all(r["verified"] for r in receiver.received)
    assert [r["body"]["asset"]["label"] for r in receiver.received] == [f"asset-{i}" for i in range(10, 14)]
    assert receiver.received[0]["type"] == "finding.opened" and receiver.received[1]["type"] == "finding.resolved"
    ids = [r["id"] for r in receiver.received]
    assert ids[0] == EV.event_uid("drift", 1, "d10") and len(set(ids)) == 4
    assert D.tick(engine)["delivered"] == 0  # nothing twice
    with Session(engine) as s:
        assert all(e.forwarded_at is not None for e in s.exec(select(CbomDriftEvent)).all())
    log = api("GET", "/1/integrations/deliveries").json()["deliveries"]
    assert len(log) == 4 and {d["status"] for d in log} == {"delivered"} and log[0]["code"] == "PROTO_TLS10"
    assert api("GET", "/2/integrations/deliveries", "carol").json()["deliveries"] == []


def test_a_failing_destination_holds_the_queue_backs_off_then_recovers(api, world, monkeypatch):
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver([503, 503])
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    _drift(engine, 3)
    t0 = dt.datetime.utcnow()
    first = D.tick(engine, t0)
    assert first["retry"] == 1 and first["delivered"] == 0
    with Session(engine) as s:
        row = s.exec(select(TeamIntegration)).one()
        assert row.failures == 1 and row.next_attempt_at > t0 and "HTTP 503" in row.last_error
        assert row.lease_until is None
        head = s.exec(select(IntegrationDelivery).order_by(IntegrationDelivery.id)).first()
        assert head.attempts == 1 and head.status == "pending"
    assert D.tick(engine, t0 + dt.timedelta(seconds=1))["integrations"] == 0  # backing off: not due
    later = t0 + dt.timedelta(minutes=10)
    assert D.tick(engine, later)["retry"] == 1  # second 503
    out = D.tick(engine, later + dt.timedelta(hours=1))
    assert out["delivered"] == 3
    assert [r["status"] for r in receiver.received] == [503, 503, 200, 200, 200]
    assert len({r["id"] for r in receiver.received}) == 3  # the retried event kept its id (receivers de-duplicate)
    with Session(engine) as s:
        row = s.exec(select(TeamIntegration)).one()
        assert row.failures == 0 and row.next_attempt_at is None and row.last_delivery_at is not None


def test_rejected_events_go_to_the_dead_letter_list_and_can_be_retried(api, world, monkeypatch):
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver([400, 200, 200])
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    _drift(engine, 3)
    out = D.tick(engine)
    assert out["dead"] == 1 and out["delivered"] == 2  # the queue moved on past the rejected event
    dead = api("GET", "/1/integrations/deliveries?status=dead").json()["deliveries"]
    assert len(dead) == 1 and dead[0]["result"] == "HTTP 400"
    assert api("POST", "/1/integrations/deliveries/retry", "bob", json={"ids": [dead[0]["id"]]}).status_code == 403  # admins only: the route policy refuses a member (F4 RBAC)
    assert api("POST", "/1/integrations/deliveries/retry", json={}).status_code == 400
    r = api("POST", "/1/integrations/deliveries/retry", json={"kind": "webhook", "all_dead": True})
    assert r.json() == {"requeued": 1}
    assert D.tick(engine)["delivered"] == 1
    assert receiver.received[-1]["id"] == dead[0]["event_id"]


def test_a_batch_whose_every_event_was_refused_is_not_a_delivery(api, world, monkeypatch):
    """rev4 L4: when the destination refused every event of a batch (all dead-lettered), the integration was recorded
    as delivered (last_delivery_at set, last_error cleared) while the dead-letter badge showed the refusals."""
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver([400, 400])
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    _drift(engine, 2)
    out = D.tick(engine)
    assert out["dead"] == 2 and out["delivered"] == 0
    listed = {i["kind"]: i for i in api("GET", "/1/integrations").json()["integrations"]}["webhook"]
    assert listed["last_delivery_at"] is None and listed["queue"].get("dead") == 2
    assert listed["last_error"] == "the destination refused every event of the last batch: HTTP 400"
    assert listed["failures"] == 0 and listed["next_attempt_at"] is None  # it answered: no back-off
    _drift(engine, 1, start=50)
    assert D.tick(engine)["delivered"] == 1  # the next delivery clears the problem
    listed = {i["kind"]: i for i in api("GET", "/1/integrations").json()["integrations"]}["webhook"]
    assert listed["last_delivery_at"] is not None and listed["last_error"] is None


def test_events_older_than_the_max_age_are_dead_lettered_on_failure(api, world, monkeypatch):
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    monkeypatch.setattr(webhook.outbound, "request", Receiver([503] * 10))
    _drift(engine, 2)
    t0 = dt.datetime.utcnow()
    D.tick(engine, t0)
    out = D.tick(engine, t0 + dt.timedelta(hours=25))
    assert out["dead"] == 2
    dead = api("GET", "/1/integrations/deliveries?status=dead").json()["deliveries"]
    assert all("not delivered within 24 h" in d["result"] and "HTTP 503" in d["result"] for d in dead)


def test_refused_destination_is_a_retry_not_a_silent_drop(api, world, monkeypatch):
    engine, _ = world
    # Saving a refused destination is itself refused now; a destination can still become refused later (the
    # operator withdraws INTEGRATION_ALLOWED_PRIVATE): the dispatcher must keep the events, not drop them.
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, "10.20.0.0/16")
    assert api("PUT", "/1/integrations/webhook", json={**HOOK, "config": {"url": "https://10.20.30.40/x"}}).status_code == 200
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE, raising=False)
    _drift(engine, 1)
    assert D.tick(engine)["retry"] == 1
    with Session(engine) as s:
        assert "INTEGRATION_ALLOWED_PRIVATE" in s.exec(select(TeamIntegration)).one().last_error
        assert s.exec(select(IntegrationDelivery)).one().status == "pending"


def test_one_dispatcher_per_integration(api, world, monkeypatch):
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    gate = threading.Event()
    calls = []

    def slow(method, url, **kw):
        calls.append(1)
        gate.wait(5)
        return outbound.Response(200, "", {}, b"")

    monkeypatch.setattr(webhook.outbound, "request", slow)
    _drift(engine, 1)
    EV.enqueue_drift(engine, dt.datetime.utcnow())
    with Session(engine) as s:
        integration_id = s.exec(select(TeamIntegration)).one().id
    results = []
    threads = [threading.Thread(target=lambda: results.append(D.deliver_integration(engine, integration_id)))
               for _ in range(3)]
    for t in threads:
        t.start()
    gate.set()
    for t in threads:
        t.join(10)
    assert len(calls) == 1 and sorted(r["delivered"] for r in results) == [0, 0, 1]


def test_the_time_budget_stops_a_slow_batch_inside_the_lease(api, world, monkeypatch):
    """A slow receiver cannot hold a batch past the lease (another dispatcher would then send out of order)."""
    engine, _ = world
    assert D.LEASE.total_seconds() > D.BUDGET_S + 3 * 20  # one ServiceNow event = up to 3 requests of 20 s
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver()
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    monkeypatch.setattr(D, "BUDGET_S", 0.0)  # already used up: one event per claim, the rest stay queued
    _drift(engine, 3)
    EV.enqueue_drift(engine, dt.datetime.utcnow())
    with Session(engine) as s:
        integration_id = s.exec(select(TeamIntegration)).one().id
    assert D.deliver_integration(engine, integration_id)["delivered"] == 1
    assert D.deliver_integration(engine, integration_id)["delivered"] == 1
    assert [r["body"]["asset"]["label"] for r in receiver.received] == ["asset-0", "asset-1"]  # still in order
    with Session(engine) as s:
        pending = s.exec(select(IntegrationDelivery).where(IntegrationDelivery.status == "pending")).all()
        assert len(pending) == 1 and pending[0].attempts == 0


def test_disabled_integration_and_subscriptions(api, world, monkeypatch):
    engine, _ = world
    receiver = Receiver()
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    assert api("PUT", "/1/integrations/webhook", json={**HOOK, "config": {"url": "https://hooks.example/zs",
                                                                          "events": ["resolved"]}}).status_code == 200
    _drift(engine, 4)
    assert D.tick(engine)["delivered"] == 2 and {r["type"] for r in receiver.received} == {"finding.resolved"}
    assert api("PUT", "/1/integrations/webhook", json={**HOOK, "enabled": False, "expected_version": 1}).status_code == 200
    _drift(engine, 2, start=50)
    assert D.tick(engine)["queued"] == 0  # disabled: not queued


# ----------------------------------------------------------------------------- scan finished + OSCAL
def test_run_finished_queues_scan_finished_and_the_oscal_push_is_schema_valid(api, two_runs, monkeypatch):
    engine = two_runs["engine"]
    assert api("PUT", "/1/integrations/oscal", json={"enabled": True, "config": {"url": "https://grc.example/oscal"},
                                                    "secrets": {"signing_secret": CANARY}}).status_code == 200
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    receiver = Receiver()
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    assert DRIFT.record_pending_drift(engine, dt.datetime.utcnow()) == 2
    out = D.tick(engine)
    grc = [r for r in receiver.received if r["url"] == "https://grc.example/oscal"]
    assert len(grc) == 2 and all(r["verified"] and r["type"] == "scan.finished" for r in grc)
    for r in grc:
        assert OSCAL.validate(r["body"]) == []
    hooks = [r["body"] for r in receiver.received if r["url"] == "https://hooks.example/zs"]
    finished = [b for b in hooks if b["type"] == "scan.finished"]
    assert {b["run_id"] for b in finished} == {two_runs["run1"]["id"], two_runs["run2"]["id"]}
    assert finished[-1]["summary"]["status"] in ("done", "partial") and finished[-1]["summary"]["sources"] == 2
    assert out["delivered"] == len(receiver.received)


def test_oscal_export_of_a_run_maps_findings_to_controls_and_validates(api, two_runs):
    run1 = two_runs["run1"]
    r = api("GET", f"/1/cbom/sources/runs/{run1['id']}/oscal")
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers["content-disposition"]
    doc = r.json()
    assert OSCAL.validate(doc) == []
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.2.3"
    result = ar["results"][0]
    codes = {p["value"] for f in result["findings"] for p in f["props"] if p["name"] == "finding-code"}
    assert {"PROTO_TLS10", "SIG_MD5"} <= codes
    targets = {f["target"]["target-id"] for f in result["findings"]}
    assert "sc-8_obj" in targets and "sc-17_obj" in targets
    assert all(f["target"]["status"]["state"] == "not-satisfied" for f in result["findings"])
    obs = {o["uuid"] for o in result["observations"]}
    assert all(ro["observation-uuid"] in obs for f in result["findings"] for ro in f["related-observations"])
    items = {i["uuid"] for i in result["local-definitions"]["inventory-items"]}
    assert all(s["subject-uuid"] in items for o in result["observations"] for s in o["subjects"])
    tls = next(f for f in result["findings"] if f["title"].startswith("PROTO_TLS10"))
    assert any("cert-in" in link["href"] for link in tls.get("links", []))  # the KB's compliance references
    # deterministic: the same run exports the same uuids
    again = api("GET", f"/1/cbom/sources/runs/{run1['id']}/oscal").json()
    assert again["assessment-results"]["uuid"] == ar["uuid"]
    assert api("GET", f"/2/cbom/sources/runs/{run1['id']}/oscal", "carol").status_code == 404


def test_oscal_schema_validation_is_not_vacuous():
    doc = OSCAL.assessment_results(team_id=1, anchor="x", title="t", namespace="node", start=dt.datetime(2026, 1, 1),
                                   end=None, views=[], kb_version="1", description="d")
    assert OSCAL.validate(doc) == []
    broken = json.loads(json.dumps(doc))
    del broken["assessment-results"]["import-ap"]
    assert any("import-ap" in e for e in OSCAL.validate(broken))
    broken = json.loads(json.dumps(doc))
    broken["assessment-results"]["metadata"]["props"][0]["name"] = "bad name with spaces"
    assert OSCAL.validate(broken)  # the \p{L} token pattern is enforced
    broken = json.loads(json.dumps(doc))
    broken["assessment-results"]["uuid"] = "not-a-uuid"
    assert OSCAL.validate(broken)


def test_every_kb_compliance_area_maps_to_catalog_controls():
    from backend.utilities.cbom_sources.crypto_kb import load

    catalog = OSCAL.catalog()
    kb = load()
    assert set(kb["compliance"]) <= set(OSCAL.COMPLIANCE_TO_CONTROLS)
    for controls in OSCAL.COMPLIANCE_TO_CONTROLS.values():
        assert controls and all(c in catalog and catalog[c]["objective_id"] == f"{c}_obj" for c in controls)
    for ns in ("node", "code"):
        for code in kb["findings"][ns]:
            assert OSCAL.controls_for(ns, code), (ns, code)


def test_code_scan_finished_event_and_oscal_export(api, world, monkeypatch):
    engine, ids = world
    meta = {"repo_url": "https://github.com/acme/pay.git", "branch": "main"}
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"])
    with Session(engine) as s:
        s.add(Scan(id=60, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 1), scan_data={"results": [des]}))
        s.commit()
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    import backend.get_db as get_db_module
    monkeypatch.setattr(get_db_module, "get_mongo_client_db", lambda: _FakeMongo([]))
    DRIFT.on_code_scan_success(60, engine)
    receiver = Receiver()
    monkeypatch.setattr(webhook.outbound, "request", receiver)
    D.tick(engine)
    (event,) = [r["body"] for r in receiver.received]
    assert event["type"] == "scan.finished" and event["scan_id"] == 60 and event["summary"]["findings"] == 1
    assert event["source"]["name"] == "github.com/acme/pay (main)"
    doc = api("GET", "/1/cbom/code-scans/60/oscal").json()
    assert OSCAL.validate(doc) == []
    assert doc["assessment-results"]["results"][0]["findings"][0]["target"]["target-id"] == "sc-13_obj"
    assert api("GET", "/1/cbom/code-scans/78/oscal").status_code == 404  # a SAST scan


def test_team_delete_removes_integrations_and_deliveries(api, world):
    engine, _ = world
    assert api("PUT", "/1/integrations/webhook", json=HOOK).status_code == 200
    _drift(engine, 2)
    EV.enqueue_drift(engine, dt.datetime.utcnow())
    counts = delete_cbom_sources_for_team(engine, 1)
    assert counts["integrationdelivery"] == 2 and counts["teamintegration"] == 1
