"""Connector formats and outcomes (WP11): syslog RFC 5424 + CEF / JSON, Splunk HEC, signed webhooks, ServiceNow
Table API (de-dup by correlation id, resolve on "finding resolved"), and the config rules."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.utilities.integrations import outbound, servicenow, siem, webhook  # noqa: E402
from backend.utilities.integrations.base import Context  # noqa: E402
from backend.utilities.integrations.registry import SPECS, validate_config  # noqa: E402

EVENT = {"schema": "zeroshield.cbom.event/1", "id": "6f1c2c1e-6a1f-5b8e-9a51-0d1e2f3a4b5c", "type": "finding.opened",
         "kind": "opened", "time": "2026-11-02T10:00:00Z", "team_id": 1, "severity": "High", "scope": "node",
         "run_id": 12, "baseline_run_id": 11, "scan_id": None, "baseline_scan_id": None,
         "source": {"ref": "uid1", "name": "dc|mumbai=1"},
         "asset": {"key": "k" * 32, "label": "pay.bank.local:443 \\ TLS\nendpoint", "type": "tls_endpoint",
                   "target": "10.20.0.1", "location": "10.20.0.1:443"},
         "finding": {"code": "PROTO_TLS10", "title": "TLS 1.0 accepted", "impact": "High"}, "detail": {}}


class FakeHttp:
    """Stands in for ``outbound.request``: records calls and answers from a function."""

    def __init__(self, answer):
        self.calls: list[dict] = []
        self.answer = answer

    def __call__(self, method, url, *, headers=None, body=None, ca_pem=None, total=20.0, max_body=0):
        call = {"method": method, "url": url, "headers": headers or {}, "body": body, "ca_pem": ca_pem}
        self.calls.append(call)
        result = self.answer(call)
        if isinstance(result, Exception):
            raise result
        status, body_out, hdrs = (result + ({},))[:3] if len(result) == 2 else result
        return outbound.Response(status, "", {k.lower(): v for k, v in hdrs.items()}, body_out)


# ----------------------------------------------------------------------------- syslog
def test_syslog_message_follows_rfc5424_with_cef_escaping():
    cfg = validate_config("syslog", {"host": "siem.corp.local", "transport": "tls"})
    assert cfg.port == 6514 and cfg.facility == 16
    msg = siem.syslog_message({**EVENT, "asset": {**EVENT["asset"], "label": "pay é|x=y"}}, cfg).decode("ascii")
    header = re.match(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", msg)
    assert header, msg
    pri, ts, host, app, procid, msgid, sd, body = header.groups()
    assert int(pri) == 16 * 8 + 3  # local0, High -> error (3)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", ts)
    assert (host, app, procid, msgid, sd) == ("zeroshield", "zeroshield-cbom", "-", "finding.opened", "-")
    assert body.startswith("CEF:0|ZeroShield|DevSecShield CBOM|1.0|finding.opened|")
    head = re.split(r"(?<!\\)\|", body, maxsplit=7)  # the extension may contain unescaped pipes
    assert len(head) == 8 and head[6] == "8"  # High -> CEF 8
    assert "pay \\\\u00e9\\|x=y" in head[5]  # header: pipe escaped, non-ASCII as \uXXXX (its backslash escaped)
    ext = head[7]
    assert "externalId=6f1c2c1e-6a1f-5b8e-9a51-0d1e2f3a4b5c" in ext and "cs1Label=finding code cs1=PROTO_TLS10" in ext
    assert "cs2=dc|mumbai\\=1" in ext  # extension: '=' escaped, pipe allowed
    assert msg.isascii() and "\n" not in msg


def test_cef_extension_escapes_backslash_and_newlines():
    text = siem.cef(EVENT)
    assert "pay.bank.local:443 \\\\ TLS\\nendpoint" in text  # backslash doubled, newline as \n
    assert siem.cef({**EVENT, "severity": "Info", "type": "finding.resolved"}).split("|")[6] == "1"


def test_syslog_framing_octet_counting_and_udp_size():
    message = siem.syslog_message(EVENT, validate_config("syslog", {"host": "10.0.0.1", "transport": "tcp"}))
    framed = siem.frame(message)
    length, _, rest = framed.partition(b" ")
    assert int(length) == len(rest) == len(message)
    big = {**EVENT, "detail": {"x": "y" * 5000}}
    cfg = validate_config("syslog", {"host": "10.0.0.1", "transport": "udp", "format": "json"})
    sent = []
    import backend.utilities.integrations.siem as S
    orig = S.outbound.send_datagrams
    S.outbound.send_datagrams = lambda host, port, grams: sent.extend(grams) or len(grams)
    try:
        out = siem.syslog_send(Context(1, cfg, {}), [big])
    finally:
        S.outbound.send_datagrams = orig
    assert out[0].status == "ok" and len(sent[0]) == siem.UDP_MAX and cfg.port == 514


def test_syslog_json_payload_is_the_event(monkeypatch):
    cfg = validate_config("syslog", {"host": "10.0.0.1", "transport": "tls", "format": "json", "facility": 4})
    msg = siem.syslog_message(EVENT, cfg).decode()
    body = msg.split(" - ", 2)[-1]
    assert json.loads(body)["id"] == EVENT["id"] and msg.startswith(f"<{4 * 8 + 3}>1 ")


def test_syslog_failure_holds_the_queue(monkeypatch):
    cfg = validate_config("syslog", {"host": "127.0.0.1", "transport": "tcp"})
    out = siem.syslog_send(Context(1, cfg, {}), [EVENT, EVENT])
    assert len(out) == 1 and out[0].status == "retry" and "never allowed" in out[0].reason


# ----------------------------------------------------------------------------- Splunk HEC
def test_hec_batches_stacked_json_with_the_token_header(monkeypatch):
    fake = FakeHttp(lambda c: (200, b'{"text":"Success","code":0}'))
    monkeypatch.setattr(siem.outbound, "request", fake)
    cfg = validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088", "index": "security"})
    out = siem.hec_send(Context(1, cfg, {"token": "hec-token-123"}), [EVENT] * 150)
    assert [o.status for o in out] == ["ok"] * 150 and len(fake.calls) == 2  # 100 + 50
    call = fake.calls[0]
    assert call["url"] == "https://splunk.corp.local:8088/services/collector/event"
    assert call["headers"]["Authorization"] == "Splunk hec-token-123"
    items = [json.loads(line) for line in call["body"].decode().splitlines()]
    assert len(items) == 100 and items[0]["index"] == "security" and items[0]["sourcetype"] == "zeroshield:cbom"
    assert items[0]["event"]["id"] == EVENT["id"] and items[0]["time"] == 1793613600.0


@pytest.mark.parametrize("status,body,expected", [
    (503, b'{"text":"Server is busy","code":9}', "retry"),
    (429, b'{"text":"HEC queue is at capacity","code":26}', "retry"),
    (403, b'{"text":"Invalid token","code":4}', "retry"),
    (400, b'{"text":"Incorrect index","code":7}', "reject"),
    (200, b'{"text":"weird","code":12}', "retry"),
])
def test_hec_status_codes(monkeypatch, status, body, expected):
    monkeypatch.setattr(siem.outbound, "request", FakeHttp(lambda c: (status, body, {"Retry-After": "7"})))
    cfg = validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088"})
    out = siem.hec_send(Context(1, cfg, {"token": "t"}), [EVENT, EVENT])
    assert out[0].status == expected
    assert "Server is busy" not in out[0].reason or status == 503  # the HEC code label, not the body echoed
    if expected == "retry":
        assert len(out) == 1
    if status == 503:
        assert out[0].retry_after == 7.0 and "HEC code 9" in out[0].reason


# ----------------------------------------------------------------------------- webhook
def test_webhook_signature_round_trip_and_tampering():
    body = b'{"a":1}'
    headers = webhook.signed_headers("s" * 32, "id-1", "finding.opened", body, now=1_800_000_000)
    assert headers["X-ZS-Signature"].startswith("v1=") and headers["X-ZS-Timestamp"] == "1800000000"
    ok = webhook.verify("s" * 32, body, headers["X-ZS-Timestamp"], headers["X-ZS-Signature"], now=1_800_000_010)
    assert ok
    assert not webhook.verify("s" * 32, b'{"a":2}', headers["X-ZS-Timestamp"], headers["X-ZS-Signature"], now=1_800_000_010)
    assert not webhook.verify("t" * 32, body, headers["X-ZS-Timestamp"], headers["X-ZS-Signature"], now=1_800_000_010)
    assert not webhook.verify("s" * 32, body, headers["X-ZS-Timestamp"], headers["X-ZS-Signature"], now=1_800_001_000)
    # the documented snippet is the same check
    scope: dict = {}
    exec(webhook.VERIFY_SNIPPET, scope)  # noqa: S102 - our own constant
    import time as _t
    stamp = str(int(_t.time()))
    sig = webhook.sign("s" * 32, stamp, body)
    assert scope["verify"](b"s" * 32, body, stamp, sig) and not scope["verify"](b"s" * 32, body + b" ", stamp, sig)


@pytest.mark.parametrize("status,expected", [(200, "ok"), (204, "ok"), (500, "retry"), (401, "retry"),
                                             (400, "reject"), (410, "reject"), (302, "retry")])
def test_webhook_outcomes(monkeypatch, status, expected):
    fake = FakeHttp(lambda c: (status, b"<html>internal detail</html>"))
    monkeypatch.setattr(webhook.outbound, "request", fake)
    cfg = validate_config("webhook", {"url": "https://hooks.example/zs"})
    out = webhook.send(Context(1, cfg, {"signing_secret": "x" * 20}), [EVENT, EVENT])
    assert out[0].status == expected and "internal detail" not in out[0].reason
    headers = fake.calls[0]["headers"]
    assert webhook.verify("x" * 20, fake.calls[0]["body"], headers["X-ZS-Timestamp"], headers["X-ZS-Signature"])
    assert headers["X-ZS-Event-Id"] == EVENT["id"] and json.loads(fake.calls[0]["body"])["id"] == EVENT["id"]
    assert len(out) == (1 if expected == "retry" else 2)


# ----------------------------------------------------------------------------- ServiceNow
class FakeServiceNow:
    """In-memory Table API: GET with sysparm_query correlation_id=X^active=true, POST, PATCH, and oauth_token.do."""

    def __init__(self, *, auth="basic"):
        self.records: dict[str, dict] = {}
        self.auth = auth
        self.calls: list[tuple[str, str]] = []
        self.fail_next: int | None = None

    def __call__(self, call):
        parts = urlsplit(call["url"])
        self.calls.append((call["method"], parts.path))
        if self.fail_next:
            code, self.fail_next = self.fail_next, None
            return code, b'{"error":{"message":"secret internal detail"}}', {"Retry-After": "30"}
        if parts.path == "/oauth_token.do":
            form = parse_qs(call["body"].decode())
            if form.get("client_secret") == ["cs-1"] and form.get("grant_type") == ["client_credentials"]:
                return 200, b'{"access_token":"tok-1","expires_in":1800}'
            return 401, b'{"error":"access_denied"}'
        expected = "Bearer tok-1" if self.auth == "oauth" else "Basic " + __import__("base64").b64encode(b"zs:pw").decode()
        if call["headers"].get("Authorization") != expected:
            return 401, b"{}"
        table_path = parts.path.split("/api/now/table/")[1]
        if call["method"] == "GET":
            q = parse_qs(parts.query)
            if "sysparm_query" not in q:
                return 200, json.dumps({"result": [{"sys_id": "a" * 32}]}).encode()
            cid = q["sysparm_query"][0].split("^")[0].split("=", 1)[1]
            hits = [r for r in self.records.values() if r["correlation_id"] == cid and r["active"]]
            return 200, json.dumps({"result": [{"sys_id": r["sys_id"], "number": r["number"]} for r in hits[:1]]}).encode()
        if call["method"] == "POST":
            body = json.loads(call["body"])
            sys_id = f"{len(self.records) + 1:032x}"
            rec = {**body, "sys_id": sys_id, "number": f"INC{len(self.records) + 1:07d}", "active": True, "state": "1"}
            self.records[sys_id] = rec
            return 201, json.dumps({"result": rec}).encode()
        if call["method"] == "PATCH":
            sys_id = table_path.split("/")[1]
            body = json.loads(call["body"])
            rec = self.records[sys_id]
            rec.update(body)
            if body.get("state") == "6":
                rec["active"] = False
            return 200, json.dumps({"result": rec}).encode()
        return 405, b""


def _sn(monkeypatch, auth="basic", **cfg):
    fake = FakeServiceNow(auth=auth)
    monkeypatch.setattr(servicenow.outbound, "request", FakeHttp(fake))
    base = {"instance_url": "https://acme.service-now.com", **({"username": "zs"} if auth == "basic" else
                                                               {"auth": "oauth", "client_id": "zs-client"})}
    config = validate_config("servicenow", {**base, **cfg})
    secrets = {"password": "pw"} if auth == "basic" else {"client_secret": "cs-1"}
    return fake, Context(1, config, secrets)


def test_servicenow_opens_one_record_per_finding_and_resolves_it(monkeypatch):
    fake, ctx = _sn(monkeypatch, category="Security", assignment_group="Crypto Team")
    resolved = {**EVENT, "kind": "resolved", "type": "finding.resolved", "severity": "Info", "id": "e2"}
    out = servicenow.send(ctx, [EVENT, EVENT, resolved, resolved])
    assert [o.status for o in out] == ["ok"] * 4
    assert out[0].reason == "created INC0000001" and out[1].reason == "already open"  # de-dup by correlation id
    assert out[2].reason == "resolved INC0000001" and out[3].reason == "no open record to resolve"
    (rec,) = fake.records.values()
    assert rec["correlation_id"] == servicenow.correlation_id(EVENT) and rec["correlation_id"].startswith("zs-cbom-")
    assert rec["state"] == "6" and rec["close_code"] == "Solution provided" and "no longer finds" in rec["close_notes"]
    assert rec["impact"] == "1" and rec["urgency"] == "2" and rec["category"] == "Security"
    assert rec["short_description"].startswith("[ZeroShield CBOM] PROTO_TLS10")
    # opened again after resolve: a NEW record (only active records de-duplicate)
    assert servicenow.send(ctx, [EVENT])[0].reason == "created INC0000002"


def test_servicenow_oauth_client_credentials_and_failures(monkeypatch):
    fake, ctx = _sn(monkeypatch, auth="oauth", table="sn_vul_vulnerable_item", resolve_state="3", close_code="Fixed")
    assert servicenow.send(ctx, [EVENT])[0].status == "ok"
    assert ("POST", "/oauth_token.do") in fake.calls and ("POST", "/api/now/table/sn_vul_vulnerable_item") in fake.calls
    fake.fail_next = 503
    out = servicenow.send(ctx, [EVENT, EVENT])
    assert len(out) == 1 and out[0].status == "retry"  # the token call got the 503: queue held
    bad = Context(1, ctx.config, {"client_secret": "wrong"})
    out = servicenow.send(bad, [EVENT])
    assert out[0].status == "retry" and "OAuth" in out[0].reason
    fake2, ctx2 = _sn(monkeypatch)
    fake2.fail_next = 429
    out = servicenow.send(ctx2, [EVENT])
    assert out[0].status == "retry" and out[0].retry_after == 30.0 and "secret internal detail" not in out[0].reason


def test_servicenow_test_reads_and_creates_nothing(monkeypatch):
    fake, ctx = _sn(monkeypatch)
    out = servicenow.test(ctx, EVENT)
    assert out.status == "ok" and fake.records == {} and [m for m, _p in fake.calls] == ["GET"]
    out = servicenow.test(Context(1, ctx.config, {"password": "nope"}), EVENT)
    assert out.status == "retry" and "credentials" in out.reason


def test_servicenow_minimum_severity_limits_new_records_but_never_resolving(monkeypatch):
    fake, ctx = _sn(monkeypatch, min_severity="High")
    low = {**EVENT, "severity": "Low", "id": "low", "finding": {**EVENT["finding"], "code": "QUANTUM_VULNERABLE"}}
    out = servicenow.send(ctx, [low, EVENT])
    assert out[0].status == "ok" and "minimum severity" in out[0].reason and len(fake.records) == 1
    resolved = {**EVENT, "kind": "resolved", "type": "finding.resolved", "severity": "Info", "id": "r"}
    assert servicenow.send(ctx, [resolved])[0].reason.startswith("resolved")


def test_servicenow_cert_events_and_ignores_others(monkeypatch):
    fake, ctx = _sn(monkeypatch, events=["opened", "resolved", "cert_expiring", "cert_renewed"])
    expiring = {**EVENT, "kind": "cert_expiring", "type": "certificate.expiring", "finding": None, "id": "c1"}
    renewed = {**expiring, "kind": "cert_renewed", "type": "certificate.renewed", "id": "c2"}
    other = {**EVENT, "kind": "new_asset", "type": "asset.new"}
    out = servicenow.send(ctx, [expiring, other, renewed])
    assert [o.status for o in out] == ["ok", "ok", "ok"] and out[2].reason.startswith("resolved")
    assert len(fake.records) == 1


# ----------------------------------------------------------------------------- config rules
def test_config_rules():
    with pytest.raises(ValidationError):
        validate_config("webhook", {"url": "http://hooks.example/x"})  # https only
    with pytest.raises(ValidationError):
        validate_config("webhook", {"url": "https://u:p@hooks.example/x"})
    with pytest.raises(ValidationError):
        validate_config("webhook", {"url": "https://hooks.example/x", "extra": 1})
    with pytest.raises(ValueError, match="cannot be sent"):
        validate_config("servicenow", {"instance_url": "https://a.service-now.com", "username": "u",
                                       "events": ["new_asset"]})
    with pytest.raises(ValidationError):
        validate_config("servicenow", {"instance_url": "https://a.service-now.com/api/now", "username": "u"})
    with pytest.raises(ValidationError):
        validate_config("servicenow", {"instance_url": "https://a.service-now.com", "auth": "oauth"})  # client_id
    with pytest.raises(ValidationError):
        validate_config("servicenow", {"instance_url": "https://a.service-now.com", "username": "u",
                                       "table": "incident;drop"})
    with pytest.raises(ValidationError):
        validate_config("syslog", {"host": "bad host!"})
    with pytest.raises(ValidationError):
        validate_config("splunk_hec", {"url": "https://splunk:8088/other/path"})
    assert validate_config("syslog", {"host": "10.0.0.1", "transport": "udp"}).port == 514
    assert SPECS["servicenow"].secret_fields(validate_config("servicenow", {
        "instance_url": "https://a.service-now.com", "auth": "oauth", "client_id": "c"})) == {"client_secret"}
    assert validate_config("oscal", {"url": "https://grc.example/oscal"}).events is None
