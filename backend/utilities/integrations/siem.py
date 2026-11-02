"""SIEM / SOAR: syslog (RFC 5424) over TCP, TLS or UDP with a CEF or JSON payload, and Splunk HTTP Event Collector.

Syslog message (RFC 5424 section 6)::

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

* PRI = facility x 8 + severity (default facility 16, local0); severity from the event (Critical 2, High 3,
  Medium 4, Low 5, informational 6). HOSTNAME is the configured sender name, APP-NAME ``zeroshield-cbom``,
  PROCID ``-``, MSGID the event type (at most 32 printable ASCII characters), STRUCTURED-DATA ``-`` (NILVALUE).
* MSG is kept printable ASCII (JSON with \\u escapes; CEF values with non-ASCII characters written as \\uXXXX), so no
  BOM is needed (RFC 5424 6.4 asks for one only before UTF-8 text).
* Framing: TCP and TLS use octet counting, ``MSG-LEN SP SYSLOG-MSG`` (RFC 6587 3.4.1, RFC 5425 4.3; TLS default port
  6514); UDP sends one message per datagram (RFC 5426 3.1), at most 2048 octets (3.2: receivers SHOULD accept 2048).
  UDP has no delivery confirmation; TCP and TLS are confirmed when the whole batch was written and the connection
  closed cleanly.

CEF (ArcSight CEF Implementation Standard)::

    CEF:0|ZeroShield|DevSecShield CBOM|1.0|<event type>|<name>|<severity 0-10>|<extension>

Header fields escape ``\\`` and ``|``; extension values escape ``\\`` and ``=`` and encode newlines as ``\\n`` / ``\\r``.
Severity: Critical 10, High 8, Medium 5, Low 3, informational 1.

Splunk HEC: ``POST <url>/services/collector/event`` with ``Authorization: Splunk <token>`` and stacked JSON event
objects (``time``, ``host``, ``source``, ``sourcetype``, optional ``index``, ``event``), up to 100 per request.
Success is HTTP 200 with code 0; 429 and 503 (codes 9, 18-20, 23, 26, 27: busy or unhealthy) and 401/403 (token)
hold the queue and retry; other 400s (e.g. code 7, incorrect index) reject the batch.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from backend.utilities.integrations import outbound
from backend.utilities.integrations.base import (
    Cfg,
    Context,
    Outcome,
    ca_pem,
    failure,
    host_name,
    http_outcome,
    https_url,
    parse_json,
)

APP_NAME = "zeroshield-cbom"
SYSLOG_SEVERITY = {"Critical": 2, "High": 3, "Medium": 4, "Low": 5, "Info": 6}
CEF_SEVERITY = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3, "Info": 1}
UDP_MAX = 2048
DEFAULT_PORTS = {"udp": 514, "tcp": 514, "tls": 6514}
_PRINTABLE = re.compile(r"[^\x21-\x7e]")
HEC_BATCH = 100


# ----------------------------------------------------------------------------- syslog
class SyslogConfig(Cfg):
    host: str = Field(max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal["udp", "tcp", "tls"] = "tls"
    format: Literal["cef", "json"] = "cef"
    facility: int = Field(default=16, ge=0, le=23)
    sender_name: str = Field(default="zeroshield", max_length=64)
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    events: list[str] | None = None

    _h = field_validator("host")(classmethod(lambda cls, v: host_name(v)))
    _c = field_validator("ca_pem")(classmethod(lambda cls, v: ca_pem(v)))

    @field_validator("sender_name")
    @classmethod
    def _sender(cls, v: str) -> str:
        if not v or _PRINTABLE.search(v):
            raise ValueError("sender_name: printable ASCII without spaces")
        return v

    @model_validator(mode="after")
    def _port(self) -> "SyslogConfig":
        if self.port is None:
            self.port = DEFAULT_PORTS[self.transport]
        return self


def _ascii(text: Any) -> str:
    return "".join(ch if 32 <= ord(ch) < 127 else ("\\u%04x" % ord(ch) if ord(ch) <= 0xFFFF else "?")
                   for ch in str(text))


def _cef_header(value: Any) -> str:
    return _ascii(str(value).replace("\r", " ").replace("\n", " ")).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r\n", "\\n").replace("\n", "\\n")
    return _ascii(text.replace("\r", "\\r"))


def _epoch_ms(iso: str | None) -> int:
    try:
        moment = _dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        moment = _dt.datetime.now(_dt.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return int(moment.timestamp() * 1000)


def _title(event: dict[str, Any]) -> str:
    finding = event.get("finding") or {}
    asset = event.get("asset") or {}
    what = {"finding.opened": "Finding opened", "finding.resolved": "Finding resolved", "asset.new": "New asset",
            "asset.removed": "Asset removed", "certificate.renewed": "Certificate renewed",
            "certificate.expiring": "Certificate expiring", "schedule.skipped": "Scheduled run skipped",
            "scan.finished": "Scan finished", "integration.test": "Integration test"}.get(event["type"], event["type"])
    parts = [what]
    if finding.get("code"):
        parts.append(str(finding["code"]))
    if asset.get("label"):
        parts.append(f"on {asset['label']}")
    return " ".join(parts)[:240]


def cef(event: dict[str, Any]) -> str:
    """One CEF record for an event (no syslog prefix)."""
    finding = event.get("finding") or {}
    asset = event.get("asset") or {}
    source = event.get("source") or {}
    ext: list[tuple[str, Any]] = [("rt", _epoch_ms(event.get("time"))), ("externalId", event["id"]),
                                  ("cat", event["type"]), ("msg", _title(event))]
    if asset.get("target"):
        ext.append(("dhost", asset["target"]))
    custom = [("finding code", finding.get("code")), ("source", source.get("name") or source.get("ref")),
              ("asset key", asset.get("key")), ("asset", asset.get("label")),
              ("location", asset.get("location")), ("finding title", finding.get("title"))]
    for n, (label, value) in enumerate([c for c in custom if c[1]][:6], start=1):
        ext += [(f"cs{n}Label", label), (f"cs{n}", str(value)[:1000])]
    numbers = [("run id", event.get("run_id")), ("scan id", event.get("scan_id")), ("team id", event.get("team_id"))]
    for n, (label, value) in enumerate([c for c in numbers if c[1] is not None][:3], start=1):
        ext += [(f"cn{n}Label", label), (f"cn{n}", int(value))]
    header = ["CEF:0", "ZeroShield", "DevSecShield CBOM", "1.0", event["type"], _title(event),
              str(CEF_SEVERITY.get(event.get("severity") or "Info", 1))]
    return "|".join([header[0]] + [_cef_header(h) for h in header[1:]]) + "|" + " ".join(
        f"{k}={_cef_value(v)}" for k, v in ext)


def _timestamp(iso: str | None) -> str:
    moment = _dt.datetime.fromtimestamp(_epoch_ms(iso) / 1000, _dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def syslog_message(event: dict[str, Any], cfg: SyslogConfig) -> bytes:
    """One RFC 5424 SYSLOG-MSG (no framing)."""
    pri = cfg.facility * 8 + SYSLOG_SEVERITY.get(event.get("severity") or "Info", 6)
    msgid = _PRINTABLE.sub("_", event["type"])[:32] or "-"
    body = cef(event) if cfg.format == "cef" else json.dumps(event, separators=(",", ":"), sort_keys=True,
                                                             ensure_ascii=True)
    header = f"<{pri}>1 {_timestamp(event.get('time'))} {cfg.sender_name[:255]} {APP_NAME} - {msgid} -"
    return f"{header} {body}".encode("ascii", "replace")


def frame(message: bytes) -> bytes:
    """Octet counting (RFC 6587 3.4.1 / RFC 5425 4.3): MSG-LEN SP SYSLOG-MSG."""
    return str(len(message)).encode("ascii") + b" " + message


def syslog_send(ctx: Context, events: list[dict[str, Any]]) -> list[Outcome]:
    cfg: SyslogConfig = ctx.config
    messages = [syslog_message(e, cfg) for e in events]
    try:
        if cfg.transport == "udp":
            outbound.send_datagrams(cfg.host, int(cfg.port or 514), [m[:UDP_MAX] for m in messages])
            return [Outcome("ok", "sent over UDP (no delivery confirmation)") for _ in events]
        outbound.send_stream(cfg.host, int(cfg.port or 514), [frame(m) for m in messages], tls=cfg.transport == "tls",
                             ca_pem=cfg.ca_pem)
    except Exception as exc:
        return [failure(exc)]
    return [Outcome("ok", f"written over {cfg.transport.upper()}") for _ in events]


# ----------------------------------------------------------------------------- Splunk HEC
class SplunkHecConfig(Cfg):
    url: str = Field(max_length=1000)
    index: str | None = Field(default=None, max_length=80)
    sourcetype: str = Field(default="zeroshield:cbom", max_length=80)
    source: str = Field(default="zeroshield", max_length=80)
    host_field: str = Field(default="zeroshield", max_length=80)
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    events: list[str] | None = None

    _c = field_validator("ca_pem")(classmethod(lambda cls, v: ca_pem(v)))

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        text = https_url(v).rstrip("/")
        path = text.split("://", 1)[1].partition("/")[2]
        if path and not ("/" + path).startswith("/services/collector"):
            raise ValueError("url: the HEC base URL (https://splunk:8088) or its /services/collector/event path")
        return text

    @field_validator("index", "sourcetype", "source", "host_field")
    @classmethod
    def _token(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if _PRINTABLE.search(v.replace(" ", "")) or len(v) > 80:
            raise ValueError("use printable ASCII")
        return v


def hec_endpoint(cfg: SplunkHecConfig) -> str:
    return cfg.url if "/services/collector" in cfg.url else cfg.url + "/services/collector/event"


def hec_body(cfg: SplunkHecConfig, events: list[dict[str, Any]]) -> bytes:
    """Stacked JSON event objects, one per event."""
    chunks = []
    for event in events:
        item: dict[str, Any] = {"time": round(_epoch_ms(event.get("time")) / 1000, 3), "host": cfg.host_field or "zeroshield",
                                "source": cfg.source or "zeroshield", "sourcetype": cfg.sourcetype or "zeroshield:cbom",
                                "event": event}
        if cfg.index:
            item["index"] = cfg.index
        chunks.append(json.dumps(item, separators=(",", ":"), sort_keys=True, ensure_ascii=True))
    return "\n".join(chunks).encode("ascii")


_HEC_TEXT = {0: "Success", 4: "Invalid token", 6: "Invalid data format", 7: "Incorrect index", 9: "Server is busy",
             1: "Token disabled", 2: "Token is required", 3: "Invalid authorization", 21: "Invalid token",
             22: "Token disabled", 26: "HEC queue is at capacity"}


def hec_send(ctx: Context, events: list[dict[str, Any]]) -> list[Outcome]:
    cfg: SplunkHecConfig = ctx.config
    out: list[Outcome] = []
    for start in range(0, len(events), HEC_BATCH):
        batch = events[start:start + HEC_BATCH]
        try:
            resp = outbound.request("POST", hec_endpoint(cfg), body=hec_body(cfg, batch), ca_pem=cfg.ca_pem,
                                    headers={"Authorization": f"Splunk {ctx.secrets.get('token') or ''}",
                                             "Content-Type": "application/json"})
        except Exception as exc:
            return out + [failure(exc)]
        parsed = parse_json(resp.body)
        code = parsed.get("code") if isinstance(parsed, dict) and isinstance(parsed.get("code"), int) else None
        what = f"(HEC code {code}: {_HEC_TEXT.get(code, 'see Splunk HEC status codes')})" if code is not None else ""
        outcome = http_outcome(resp, what)
        if outcome.status == "ok" and code not in (None, 0):
            outcome = Outcome("retry", f"HTTP {resp.status} {what}")
        if outcome.status == "retry":
            return out + [outcome]
        out += [Outcome(outcome.status, outcome.reason) for _ in batch]
    return out
