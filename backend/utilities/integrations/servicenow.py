"""ServiceNow: findings as records through the Table API, and the CMDB server pull.

Table API (ServiceNow REST API reference, "Table API"): ``GET /api/now/table/{tableName}`` with ``sysparm_query``,
``sysparm_fields``, ``sysparm_limit``, ``sysparm_offset``, ``sysparm_display_value``,
``sysparm_exclude_reference_link``; ``POST /api/now/table/{tableName}``; ``PATCH /api/now/table/{tableName}/{sys_id}``;
the body is ``{"result": ...}``.

* One record per finding: the correlation id (``correlation_id`` by default, configurable) is a hash of the team, the
  stable asset identity and the finding code. Before creating, the active record with that correlation id is looked
  up, so a retried or repeated "finding opened" never makes a second record (de-duplication lives in ServiceNow, which
  survives a lost response).
* "finding resolved" (WP10 drift) sets the active record to the resolve state (incident: ``6`` Resolved) with a
  resolution code and notes; when no active record exists nothing is changed. Optionally "certificate expiring"
  opens a record and "certificate renewed" resolves it.
* The table is configurable (``incident`` by default; e.g. ``sn_vul_vulnerable_item`` for Vulnerability Response),
  as are the resolve state and resolution code (instances differ: newer releases use codes such as
  "Solution provided").
* Auth: basic (user + password) or OAuth 2.0 client credentials (``POST /oauth_token.do``; the instance must allow
  the client-credentials grant, system property ``glide.oauth.inbound.client.credential.grant_type.enabled``).
* 401/403, 429 and 5xx hold the queue (retry with back-off, honouring Retry-After); a 400 for one record rejects
  that event only.
"""
from __future__ import annotations

import base64
import json
import hashlib
import re
from typing import Any, Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.utilities.integrations import outbound
from backend.utilities.integrations.base import (
    Cfg,
    Context,
    Outcome,
    ca_pem,
    failure,
    http_outcome,
    https_url,
    parse_json,
    retry_after,
)

_TABLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}(\.[a-z][a-z0-9_]{0,79}){0,2}$")
_CMDB_TABLE_RE = re.compile(r"^cmdb_ci[a-z0-9_]{0,72}$")
_PLAIN_RE = re.compile(r"^[\w .,:()/@&'+-]{1,80}$")
OPEN_KINDS = ("opened", "cert_expiring")
CLOSE_KINDS = ("resolved", "cert_renewed")
# impact / urgency (1 high, 2 medium, 3 low): Critical -> P1, High -> P2, Medium -> P3, Low -> P5
_PRIORITY = {"Critical": ("1", "1"), "High": ("1", "2"), "Medium": ("2", "2"), "Low": ("3", "3")}
_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
CMDB_MAX_ROWS = 5000
CMDB_PAGE = 500
CMDB_PAGE_BYTES = 8 * 1024 * 1024


class CmdbMapping(BaseModel):
    """ServiceNow field names for each CMDB import column (dot-walk allowed, e.g. ``owned_by.name``). ``host``
    lists the identity fields tried in order."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    host: list[str] = Field(default_factory=lambda: ["fqdn", "ip_address", "host_name", "name"], max_length=5)
    owner: str | None = "owned_by"
    application: str | None = "u_application"
    environment: str | None = "used_for"
    criticality: str | None = None
    exposure: str | None = None
    data_classification: str | None = None

    @field_validator("host")
    @classmethod
    def _hosts(cls, v: list[str]) -> list[str]:
        clean = [x.strip() for x in v if x and x.strip()]
        if not clean or any(not _FIELD_RE.match(x) for x in clean):
            raise ValueError("cmdb_mapping.host: one or more ServiceNow field names")
        return clean

    @field_validator("owner", "application", "environment", "criticality", "exposure", "data_classification")
    @classmethod
    def _field(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not _FIELD_RE.match(v):
            raise ValueError("a ServiceNow field name such as owned_by or u_application")
        return v


class ServiceNowConfig(Cfg):
    instance_url: str = Field(max_length=500)
    table: str = Field(default="incident", max_length=80)
    auth: Literal["basic", "oauth"] = "basic"
    username: str | None = Field(default=None, max_length=128)
    client_id: str | None = Field(default=None, max_length=128)
    correlation_field: str = Field(default="correlation_id", max_length=80)
    assignment_group: str | None = Field(default=None, max_length=80)
    category: str | None = Field(default=None, max_length=80)
    resolve_state: str = Field(default="6", max_length=20)
    close_code: str = Field(default="Solution provided", max_length=80)
    # records are opened only for findings at or above this severity (resolving always goes through)
    min_severity: Literal["Critical", "High", "Medium", "Low"] = "Low"
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    events: list[str] | None = None
    cmdb_table: str = Field(default="cmdb_ci_server", max_length=80)
    cmdb_query: str | None = Field(default=None, max_length=500)
    cmdb_mapping: CmdbMapping = Field(default_factory=CmdbMapping)

    _c = field_validator("ca_pem")(classmethod(lambda cls, v: ca_pem(v)))

    @field_validator("instance_url")
    @classmethod
    def _url(cls, v: str) -> str:
        text = https_url(v).rstrip("/")
        if text.split("://", 1)[1].partition("/")[2]:
            raise ValueError("instance_url: the instance address only, e.g. https://acme.service-now.com")
        return text

    @field_validator("table", "correlation_field")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _TABLE_RE.match(v):
            raise ValueError("use a ServiceNow table or field name (lower case letters, digits, _)")
        return v

    @field_validator("cmdb_table")
    @classmethod
    def _cmdb(cls, v: str) -> str:
        if not _CMDB_TABLE_RE.match(v):
            raise ValueError("cmdb_table: a CMDB class such as cmdb_ci_server, cmdb_ci_linux_server or cmdb_ci_win_server")
        return v

    @field_validator("assignment_group", "category", "close_code", "resolve_state", "username", "client_id")
    @classmethod
    def _plain(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not _PLAIN_RE.match(v):
            raise ValueError("letters, digits, spaces and . , : ( ) / @ & ' + - only")
        return v

    @field_validator("cmdb_query")
    @classmethod
    def _query(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        if any(ch in v for ch in "\r\n\x00"):
            raise ValueError("cmdb_query: one line")
        return v.strip()

    @model_validator(mode="after")
    def _auth(self) -> "ServiceNowConfig":
        if self.auth == "basic" and not self.username:
            raise ValueError("username: required for basic authentication")
        if self.auth == "oauth" and not self.client_id:
            raise ValueError("client_id: required for OAuth client credentials")
        if not self.resolve_state:
            self.resolve_state = "6"
        return self


def correlation_id(event: dict[str, Any]) -> str:
    asset = (event.get("asset") or {}).get("key") or ""
    code = (event.get("finding") or {}).get("code") or ""
    if event["kind"] in ("cert_expiring", "cert_renewed"):
        code = "CERT_EXPIRING"
    digest = hashlib.sha256(f"{event.get('team_id')}|{asset}|{code}".encode()).hexdigest()[:40]
    return f"zs-cbom-{digest}"


def _api(cfg: ServiceNowConfig, path: str, params: dict[str, Any] | None = None) -> str:
    query = f"?{urlencode(params)}" if params else ""
    return f"{cfg.instance_url}{path}{query}"


def auth_headers(cfg: ServiceNowConfig, secrets: dict[str, str]) -> dict[str, str]:
    """Basic, or a bearer token from the client-credentials grant. Raises outbound errors or PermissionError."""
    if cfg.auth == "basic":
        raw = f"{cfg.username}:{secrets.get('password') or ''}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii"), "Accept": "application/json"}
    form = urlencode({"grant_type": "client_credentials", "client_id": cfg.client_id or "",
                      "client_secret": secrets.get("client_secret") or ""}).encode("ascii")
    resp = outbound.request("POST", _api(cfg, "/oauth_token.do"), body=form, ca_pem=cfg.ca_pem,
                            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    token = (parse_json(resp.body) or {}).get("access_token") if resp.status == 200 else None
    if not isinstance(token, str) or not token:
        raise PermissionError(f"HTTP {resp.status}: the OAuth token request was refused")
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _short(event: dict[str, Any]) -> str:
    finding = event.get("finding") or {}
    asset = event.get("asset") or {}
    what = finding.get("code") or ("CERTIFICATE_EXPIRING" if event["kind"] == "cert_expiring" else event["type"])
    title = finding.get("title")
    text = f"[ZeroShield CBOM] {what}" + (f" - {title}" if title else "") + (f" on {asset.get('label')}" if asset.get("label") else "")
    return text[:160]


def _description(event: dict[str, Any]) -> str:
    finding = event.get("finding") or {}
    asset = event.get("asset") or {}
    source = event.get("source") or {}
    lines = [
        f"ZeroShield CBOM {event['type']} ({event.get('severity')})",
        f"Finding: {finding.get('code') or '-'} {finding.get('title') or ''}".rstrip(),
        f"Asset: {asset.get('label') or '-'}",
        f"Location: {asset.get('location') or '-'}",
        f"Source: {source.get('name') or source.get('ref') or '-'}",
        f"Run: {event.get('run_id') or '-'}  Scan: {event.get('scan_id') or '-'}",
        f"Event id: {event['id']}",
    ]
    return "\n".join(lines)[:4000]


def _find_active(cfg: ServiceNowConfig, headers: dict[str, str], cid: str) -> tuple[outbound.Response, dict | None]:
    url = _api(cfg, f"/api/now/table/{cfg.table}", {
        "sysparm_query": f"{cfg.correlation_field}={cid}^active=true", "sysparm_fields": "sys_id,number",
        "sysparm_limit": "1", "sysparm_exclude_reference_link": "true"})
    resp = outbound.request("GET", url, headers=headers, ca_pem=cfg.ca_pem)
    rows = (parse_json(resp.body) or {}).get("result") if resp.status == 200 else None
    return resp, (rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None)


def _ref(record: dict | None) -> str | None:
    if not record:
        return None
    return str(record.get("number") or record.get("sys_id") or "")[:64] or None


def deliver_one(cfg: ServiceNowConfig, headers: dict[str, str], event: dict[str, Any]) -> Outcome:
    if event["kind"] in OPEN_KINDS and _RANK.get(event.get("severity") or "Low", 3) > _RANK[cfg.min_severity]:
        return Outcome("ok", f"below the minimum severity ({cfg.min_severity}); no record opened")
    cid = correlation_id(event)
    resp, record = _find_active(cfg, headers, cid)
    if resp.status != 200:
        outcome = http_outcome(resp, "looking up the record")
        return outcome if outcome.status != "ok" else Outcome("retry", f"HTTP {resp.status} looking up the record")
    if event["kind"] in OPEN_KINDS:
        if record is not None:
            return Outcome("ok", "already open", ref=_ref(record))
        impact, urgency = _PRIORITY.get(event.get("severity") or "", ("3", "3"))
        body: dict[str, Any] = {"short_description": _short(event), "description": _description(event),
                                cfg.correlation_field: cid, "correlation_display": "ZeroShield CBOM",
                                "impact": impact, "urgency": urgency}
        if cfg.category:
            body["category"] = cfg.category
        if cfg.assignment_group:
            body["assignment_group"] = cfg.assignment_group

        created = outbound.request("POST", _api(cfg, f"/api/now/table/{cfg.table}"), ca_pem=cfg.ca_pem,
                                   body=json.dumps(body).encode("utf-8"),
                                   headers={**headers, "Content-Type": "application/json"})
        outcome = http_outcome(created, "creating the record")
        if outcome.status == "ok":
            outcome.ref = _ref((parse_json(created.body) or {}).get("result"))
            outcome.reason = f"created {outcome.ref or ''}".strip()
        return outcome
    if record is None:
        return Outcome("ok", "no open record to resolve")
    patch = {"state": cfg.resolve_state, "close_code": cfg.close_code,
             "close_notes": f"Resolved: ZeroShield CBOM no longer finds this ({event['type']}, event {event['id']}).",
             "work_notes": _description(event)}

    sys_id = str(record.get("sys_id") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", sys_id):
        return Outcome("reject", "the record has no valid sys_id")
    updated = outbound.request("PATCH", _api(cfg, f"/api/now/table/{cfg.table}/{sys_id}"), ca_pem=cfg.ca_pem,
                               body=json.dumps(patch).encode("utf-8"),
                               headers={**headers, "Content-Type": "application/json"})
    outcome = http_outcome(updated, "resolving the record")
    if outcome.status == "ok":
        outcome.ref, outcome.reason = _ref(record), f"resolved {_ref(record) or ''}".strip()
    return outcome


def send(ctx: Context, events: list[dict[str, Any]]) -> list[Outcome]:
    cfg: ServiceNowConfig = ctx.config
    try:
        headers = auth_headers(cfg, ctx.secrets)
    except PermissionError as exc:
        return [Outcome("retry", str(exc))]
    except Exception as exc:
        return [failure(exc)]
    out: list[Outcome] = []
    for event in events:
        if out and ctx.expired():  # the dispatcher's time budget: the rest stay queued, in order
            break
        if event["kind"] not in OPEN_KINDS + CLOSE_KINDS:
            out.append(Outcome("ok", "not a finding event; nothing to do"))
            continue
        try:
            outcome = deliver_one(cfg, headers, event)
        except Exception as exc:
            outcome = failure(exc)
        out.append(outcome)
        if outcome.status == "retry":
            break
    return out


def test(ctx: Context, _event: dict[str, Any]) -> Outcome:
    """Read one record of the table: proves the address, TLS, credentials and table access; creates nothing."""
    cfg: ServiceNowConfig = ctx.config
    try:
        headers = auth_headers(cfg, ctx.secrets)
        resp = outbound.request("GET", _api(cfg, f"/api/now/table/{cfg.table}", {
            "sysparm_limit": "1", "sysparm_fields": "sys_id"}), headers=headers, ca_pem=cfg.ca_pem)
    except PermissionError as exc:
        return Outcome("retry", str(exc))
    except Exception as exc:
        return failure(exc)
    if resp.status == 200:
        return Outcome("ok", f"HTTP 200: signed in and read the {cfg.table} table")
    if resp.status in (401, 403):
        return Outcome("retry", f"HTTP {resp.status}: the credentials were refused or lack access to {cfg.table}")
    if resp.status == 404:
        return Outcome("retry", f"HTTP 404: table {cfg.table} was not found")
    return http_outcome(resp)


# ----------------------------------------------------------------------------- CMDB pull
def _value(row: dict[str, Any], name: str | None) -> str | None:
    """With ``sysparm_display_value=all`` every field is {display_value, value}: references read by display value."""
    if not name:
        return None
    item = row.get(name)
    if isinstance(item, dict):
        item = item.get("display_value") or item.get("value")
    text = str(item).strip() if item not in (None, "") else ""
    return text or None


def _raw(row: dict[str, Any], name: str) -> str | None:
    item = row.get(name)
    if isinstance(item, dict):
        item = item.get("value") or item.get("display_value")
    text = str(item).strip() if item not in (None, "") else ""
    return text or None


def cmdb_rows(ctx: Context) -> tuple[list[dict[str, Any]], bool]:
    """Read CIs from the configured CMDB table into CMDB import rows. Returns (rows, truncated).
    Raises outbound.Refused / TransportError / PermissionError / RuntimeError (all safe to show)."""
    cfg: ServiceNowConfig = ctx.config
    m = cfg.cmdb_mapping
    columns = {"owner": m.owner, "application": m.application, "environment": m.environment,
               "criticality": m.criticality, "exposure": m.exposure, "data_classification": m.data_classification}
    fields = sorted({*m.host, *(v for v in columns.values() if v), "sys_id", "sys_class_name", "name"})
    headers = auth_headers(cfg, ctx.secrets)
    rows: list[dict[str, Any]] = []
    offset = 0
    while offset < CMDB_MAX_ROWS:
        params = {"sysparm_fields": ",".join(fields), "sysparm_display_value": "all",
                  "sysparm_exclude_reference_link": "true", "sysparm_limit": str(CMDB_PAGE),
                  "sysparm_offset": str(offset)}
        if cfg.cmdb_query:
            params["sysparm_query"] = cfg.cmdb_query
        resp = outbound.request("GET", _api(cfg, f"/api/now/table/{cfg.cmdb_table}", params), headers=headers,
                                ca_pem=cfg.ca_pem, total=30.0, max_body=CMDB_PAGE_BYTES)
        if resp.status != 200:
            hint = retry_after(resp)
            raise RuntimeError(f"HTTP {resp.status} reading {cfg.cmdb_table}" + (f" (retry after {int(hint)} s)" if hint else ""))
        page = (parse_json(resp.body) or {}).get("result")
        if not isinstance(page, list):
            raise RuntimeError(f"{cfg.cmdb_table}: the response was not a Table API result (or larger than 8 MB per page; "
                               "narrow cmdb_query)")
        for item in page:
            if not isinstance(item, dict):
                continue
            hosts = [h for h in (_raw(item, f) for f in m.host) if h]
            cls = (_raw(item, "sys_class_name") or "").lower()
            rows.append({"hosts": hosts, "os": "windows" if "win" in cls else ("linux" if "linux" in cls else None),
                         "ref": _raw(item, "sys_id"), "label": _value(item, "name") or (hosts[0] if hosts else None),
                         **{k: _value(item, v) for k, v in columns.items() if v}})
        if len(page) < CMDB_PAGE:
            return rows, False
        offset += CMDB_PAGE
    return rows[:CMDB_MAX_ROWS], True
