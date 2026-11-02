"""Shared pieces of the integration connectors: delivery outcomes, config validation helpers, HTTP status rules."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from backend.utilities.cbom_sources.kinds import check_http_url, check_pem_certificates
from backend.utilities.integrations import outbound

Status = Literal["ok", "retry", "reject"]
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


@dataclass
class Outcome:
    """``ok``: delivered. ``retry``: the destination failed (down, auth, TLS, throttled): the queue waits and backs
    off. ``reject``: the destination refused THIS event for good (e.g. HTTP 400): it goes to the dead-letter list and
    the queue moves on. ``reason`` is short and safe to show; never a response body."""
    status: Status
    reason: str
    retry_after: float | None = None
    ref: str | None = None


@dataclass
class Context:
    """What a connector gets: validated config, decrypted secrets, the team, and a database engine (OSCAL)."""
    team_id: int
    config: Any
    secrets: dict[str, str]
    engine: Any = None
    integration_id: int | None = None
    deadline: float | None = None  # time.monotonic() after which a per-event connector stops (the rest stay queued)
    extra: dict[str, Any] = field(default_factory=dict)

    def expired(self) -> bool:
        import time

        return self.deadline is not None and time.monotonic() >= self.deadline


class Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def https_url(value: str) -> str:
    text = check_http_url(value, https_only=True)
    if not text:
        raise ValueError("enter an https:// URL")
    return text


def ca_pem(value: str | None) -> str | None:
    return check_pem_certificates(value)


def host_name(value: str) -> str:
    text = (value or "").strip()
    try:
        import ipaddress

        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        pass
    if not _HOST_RE.match(text):
        raise ValueError("enter a host name or IP address")
    return text.lower().rstrip(".")


def retry_after(resp: outbound.Response) -> float | None:
    value = resp.header("retry-after")
    if value and value.strip().isdigit():
        return min(float(value.strip()), 3600.0)
    return None


def http_outcome(resp: outbound.Response, what: str = "") -> Outcome:
    """2xx delivered; 408/425/429/5xx and 401/403 (credentials) hold the queue and retry; other 4xx reject the event."""
    code = resp.status
    label = f"HTTP {code}" + (f" {what}" if what else "")
    if 200 <= code < 300:
        return Outcome("ok", label)
    if 300 <= code < 400:
        return Outcome("retry", f"HTTP {code}: redirects are not followed; check the URL")
    if code in (401, 403):
        return Outcome("retry", f"HTTP {code}: the credentials were refused")
    if code in (408, 425, 429) or code >= 500:
        return Outcome("retry", label, retry_after(resp))
    return Outcome("reject", label)


def failure(exc: BaseException) -> Outcome:
    """A Refused destination or a transport error holds the queue (the configuration or the network must change)."""
    if isinstance(exc, (outbound.Refused, outbound.TransportError)):
        return Outcome("retry", str(exc)[:240])
    return Outcome("retry", f"delivery failed ({type(exc).__name__})")


def json_body(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("ascii")


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body or b"null")
    except (ValueError, UnicodeDecodeError):
        return None
