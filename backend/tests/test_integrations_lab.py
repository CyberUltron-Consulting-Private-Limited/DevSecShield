"""End-to-end proof against real receivers on a private Docker network (scripts/integrations_lab/run_lab.sh).

Skipped unless INTEGRATION_LAB_IP is set. No monkeypatched transport: the real SSRF guard, TLS with the lab CA,
octet-counted syslog over TLS / TCP and UDP, Splunk HEC (with an injected 503), signed webhooks, OSCAL push and the
ServiceNow Table API mock (incident opened, then resolved by the WP10 "finding resolved" event; CMDB pull)."""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs, _row  # noqa: E402,F401

from backend.new_models import CbomCollectionSource, CbomDriftEvent, IntegrationDelivery  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.integrations import dispatch as D  # noqa: E402
from backend.utilities.integrations import oscal as OSCAL  # noqa: E402
from backend.utilities.integrations import outbound  # noqa: E402

LAB = os.environ.get("INTEGRATION_LAB_IP")
pytestmark = pytest.mark.skipif(not LAB, reason="needs the WP11 lab receivers (scripts/integrations_lab/run_lab.sh)")


def _received(out: Path) -> list[dict]:
    path = out / "received.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _put(api, kind, body):
    r = api("PUT", f"/1/integrations/{kind}", json=body)
    assert r.status_code == 200, r.text
    return r.json()["integration"]


def _test(api, kind):
    r = api("POST", f"/1/integrations/{kind}/test")
    assert r.status_code == 200, r.text
    return r.json()


def test_lab_end_to_end(api, two_runs, monkeypatch):
    engine = two_runs["engine"]
    out = Path(os.environ["INTEGRATION_LAB_OUT"])
    evidence_dir = Path(os.environ["INTEGRATION_LAB_EVIDENCE"])
    ca = Path(os.environ["INTEGRATION_LAB_CA"]).read_text()
    allowed = os.environ[outbound.ENV_ALLOWED_PRIVATE]
    hook_secret, hec_token = os.environ["LAB_HOOK_SECRET"], os.environ["LAB_HEC_TOKEN"]
    sn_user, sn_pass = os.environ["LAB_SN_USER"], os.environ["LAB_SN_PASS"]
    ev: dict = {"lab_ip": LAB, "allowed_private": allowed, "tests": {}, "ssrf": {}}

    # --- SSRF refusals with real sockets -------------------------------------------------------------------------
    hook = {"enabled": True, "config": {"url": f"https://{LAB}:8443/hook", "ca_pem": ca},
            "secrets": {"signing_secret": hook_secret}}
    _put(api, "webhook", hook)
    monkeypatch.delenv(outbound.ENV_ALLOWED_PRIVATE)
    ev["ssrf"]["lab_ip_without_allowlist"] = _test(api, "webhook")
    assert not ev["ssrf"]["lab_ip_without_allowlist"]["ok"]
    assert outbound.ENV_ALLOWED_PRIVATE in ev["ssrf"]["lab_ip_without_allowlist"]["message"]
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, f"{allowed},127.0.0.0/8,169.254.0.0/16")
    for name, url in (("loopback", "https://127.0.0.1:8443/hook"), ("metadata", "https://169.254.169.254/latest/meta-data/"),
                      ("ipv6_loopback", "https://[::1]:8443/hook"), ("cgnat", "https://100.100.100.200/")):
        _put(api, "webhook", {**hook, "config": {"url": url, "ca_pem": ca}, "secrets": {"signing_secret": hook_secret}})
        ev["ssrf"][name] = _test(api, "webhook")
        assert not ev["ssrf"][name]["ok"] and "never allowed" in ev["ssrf"][name]["message"], ev["ssrf"][name]
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, allowed)
    # TLS: the lab certificate is not trusted without its CA
    _put(api, "webhook", {**hook, "config": {"url": f"https://{LAB}:8443/hook"}, "secrets": {"signing_secret": hook_secret}})
    ev["tests"]["webhook_without_ca"] = _test(api, "webhook")
    assert not ev["tests"]["webhook_without_ca"]["ok"] and "not trusted" in ev["tests"]["webhook_without_ca"]["message"]

    # --- configure every integration against the lab and press "Send test" -----------------------------------------
    _put(api, "webhook", hook)
    ev["tests"]["webhook"] = _test(api, "webhook")
    _put(api, "servicenow", {"enabled": True, "config": {"instance_url": f"https://{LAB}:9443", "username": sn_user,
                                                        "ca_pem": ca, "category": "Security"},
                             "secrets": {"password": sn_pass}})
    ev["tests"]["servicenow"] = _test(api, "servicenow")
    for transport, port in (("tcp", 1514), ("udp", 1514), ("tls", 6514)):
        _put(api, "syslog", {"enabled": True, "config": {"host": LAB, "port": port, "transport": transport,
                                                         "format": "cef", "ca_pem": ca if transport == "tls" else None}})
        ev["tests"][f"syslog_{transport}"] = _test(api, "syslog")
    _put(api, "oscal", {"enabled": True, "config": {"url": f"https://{LAB}:8443/oscal", "ca_pem": ca},
                        "secrets": {"signing_secret": hook_secret}})
    ev["tests"]["oscal"] = _test(api, "oscal")
    _put(api, "splunk_hec", {"enabled": True, "config": {"url": f"https://{LAB}:8088", "index": "zs_cbom", "ca_pem": ca},
                             "secrets": {"token": hec_token}})
    assert all(t["ok"] for k, t in ev["tests"].items() if k != "webhook_without_ca"), ev["tests"]

    # --- an opened finding, then the run comparison that resolves it -----------------------------------------------
    diff = api("GET", f"/1/cbom/sources/runs/{two_runs['run2']['id']}/diff").json()
    target = next(x for x in diff["resolved"] if x["code"] == "PROTO_TLS10")
    with Session(engine) as s:
        s.add(CbomDriftEvent(team_id=1, at=dt.datetime.utcnow(), scope="node", kind="opened",
                             run_id=two_runs["run1"]["id"], source_ref="lab", source_name="src-a",
                             asset_key=target["key"], asset_label=target["label"], code="PROTO_TLS10",
                             severity="High", detail={"type": "tls_endpoint", "target": "10.20.0.1",
                                                      "location": "10.20.0.1:443"}, dedupe_key="lab-opened-1"))
        s.commit()
    t0 = dt.datetime.utcnow()
    ev["tick1"] = D.tick(engine, t0)
    assert DRIFT.record_pending_drift(engine, t0) == 2  # both runs: drift + "scan finished"
    ev["tick2"] = D.tick(engine, t0 + dt.timedelta(minutes=10))  # HEC back-off over
    ev["tick3"] = D.tick(engine, t0 + dt.timedelta(minutes=20))
    time.sleep(1.0)  # UDP / last records
    with Session(engine) as s:
        rows = s.exec(select(IntegrationDelivery).order_by(IntegrationDelivery.id)).all()
        by_kind: dict[str, list[IntegrationDelivery]] = {}
        for d in rows:
            by_kind.setdefault(d.kind, []).append(d)
    assert all(d.status == "delivered" for d in rows), [(d.kind, d.status, d.last_result) for d in rows if d.status != "delivered"]
    ev["deliveries"] = {k: {"count": len(v), "event_types": sorted({d.event_type for d in v})} for k, v in by_kind.items()}

    got = _received(out)
    hooks = [r for r in got if r["receiver"] == "webhook" and r["path"] == "/hook"]
    assert all(r["verified"] for r in hooks)
    assert {d.event_uid for d in by_kind["webhook"]} <= {r["event_id"] for r in hooks}
    hec = [r for r in got if r["receiver"] == "splunk-hec"]
    assert hec[0]["status"] == 503 and {d.event_uid for d in by_kind["splunk_hec"]} <= {r.get("event_id") for r in hec}
    tls_frames = [r for r in got if r["receiver"] == "syslog-tls" and r.get("framing")]
    assert {d.event_uid for d in by_kind["syslog"]} <= {r.get("event_id") for r in tls_frames}
    assert all(r["version"] == "1" and r["format"] == "cef" and 0 <= int(r["pri"]) <= 191 for r in tls_frames)
    assert any(r["receiver"] == "syslog-tcp" and r.get("framing") for r in got)
    assert any(r["receiver"] == "syslog-udp" for r in got)
    incidents = {r["number"]: r for r in json.loads((out / "servicenow_incidents.json").read_text())}
    sn = by_kind["servicenow"]
    created = [d for d in sn if (d.last_result or "").startswith("created")]
    assert len(incidents) == len(created)  # one record per opened finding, none twice
    assert sn[0].event_type == "finding.opened" and sn[0].external_ref == "INC0000001"
    first = incidents["INC0000001"]  # the injected TLS 1.0 finding: opened, then resolved by run 2's comparison
    assert first["state"] == "6" and first["active"] is False and first["close_code"] == "Solution provided"
    assert first["correlation_id"].startswith("zs-cbom-")
    assert any(d.last_result == "resolved INC0000001" for d in sn)
    ev["servicenow_incidents"] = [{k: r.get(k) for k in ("number", "state", "active", "short_description", "impact",
                                                         "urgency", "correlation_id")} for r in incidents.values()]
    oscal_docs = sorted(out.glob("oscal-*.json"))
    assert len(oscal_docs) == 3  # the test push + one per run
    ev["oscal_validation"] = {p.name: OSCAL.validate(json.loads(p.read_text())) for p in oscal_docs}
    assert all(v == [] for v in ev["oscal_validation"].values())

    # --- the HEC test button now passes; CMDB pull from the ServiceNow mock -------------------------------------------
    ev["tests"]["splunk_hec"] = _test(api, "splunk_hec")
    assert ev["tests"]["splunk_hec"]["ok"], ev["tests"]["splunk_hec"]
    preview = api("POST", "/1/cbom/sources/cmdb/preview", json={"source": "servicenow", "node_id": two_runs["node_id"]})
    assert preview.status_code == 200, preview.text
    plan = preview.json()["plan"]
    ev["cmdb_plan"] = plan
    applied = api("POST", "/1/cbom/sources/cmdb/apply", json={"source": "servicenow", "node_id": two_runs["node_id"],
                                                             "digest": plan["digest"]})
    assert applied.status_code == 200, applied.text
    ev["cmdb_result"] = applied.json()["result"]
    with Session(engine) as s:
        src_a = s.get(CbomCollectionSource, two_runs["a"]["id"])
        assert src_a.config["owner"] == "Payments Team" and src_a.config["environment"] == "production"
    ev["delivery_log"] = api("GET", "/1/integrations/deliveries?limit=200").json()["deliveries"]
    ev["integrations"] = api("GET", "/1/integrations").json()["integrations"]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "lab-evidence.json").write_text(json.dumps(ev, indent=1, default=str))
    for text in api.seen:
        assert hook_secret not in text and hec_token not in text and sn_pass not in text
