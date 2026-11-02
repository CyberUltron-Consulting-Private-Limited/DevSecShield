"""Signed webhooks: one HTTPS POST per event, signed with HMAC-SHA256 over the timestamp and the exact body.

Headers on every request::

    Content-Type: application/json
    X-ZS-Event-Id: <event id; the same on every retry, drop duplicates by it>
    X-ZS-Event-Type: finding.opened | finding.resolved | ... | scan.finished
    X-ZS-Timestamp: <unix seconds when this attempt was signed>
    X-ZS-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>." + body)>

Verify on the receiving side (reject when the signature does not match or the timestamp is more than five minutes
old, so a captured request cannot be replayed later)::

    import hashlib, hmac, time

    def verify(secret: bytes, body: bytes, timestamp: str, signature: str, tolerance: int = 300) -> bool:
        if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > tolerance:
            return False
        expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        return any(hmac.compare_digest(expected, part.strip()[3:])
                   for part in signature.split(",") if part.strip().startswith("v1="))

The OSCAL push (``oscal.py``) uses the same signature with ``X-ZS-Event-Type: scan.finished`` and an OSCAL
assessment-results document as the body.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from pydantic import Field, field_validator

from backend.utilities.integrations import outbound
from backend.utilities.integrations.base import Cfg, Context, Outcome, ca_pem, failure, http_outcome, https_url, json_body

SIGNATURE_HEADER = "X-ZS-Signature"
MIN_SECRET = 16
# The receiver-side check, shown in Settings > Integrations next to the signing secret (same as in the docstring).
VERIFY_SNIPPET = '''import hashlib, hmac, time

def verify(secret: bytes, body: bytes, timestamp: str, signature: str, tolerance: int = 300) -> bool:
    """body: the raw request body; timestamp: X-ZS-Timestamp; signature: X-ZS-Signature."""
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > tolerance:
        return False
    expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, part.strip()[3:])
               for part in signature.split(",") if part.strip().startswith("v1="))
'''


def sign(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return f"v1={digest}"


def verify(secret: str, body: bytes, timestamp: str, signature: str, *, tolerance: int = 300,
           now: float | None = None) -> bool:
    """The receiver-side check (used by the tests and the local mock receiver)."""
    if not timestamp.isdigit() or abs((now if now is not None else time.time()) - int(timestamp)) > tolerance:
        return False
    expected = sign(secret, timestamp, body)[3:]
    return any(hmac.compare_digest(expected, part.strip()[3:])
               for part in signature.split(",") if part.strip().startswith("v1="))


def signed_headers(secret: str, event_id: str, event_type: str, body: bytes, *, now: float | None = None
                   ) -> dict[str, str]:
    stamp = str(int(now if now is not None else time.time()))
    return {"Content-Type": "application/json", "X-ZS-Event-Id": event_id, "X-ZS-Event-Type": event_type,
            "X-ZS-Timestamp": stamp, SIGNATURE_HEADER: sign(secret, stamp, body)}


def check_secret(value: str) -> str:
    if len(value) < MIN_SECRET or len(value) > 512:
        raise ValueError(f"signing_secret: use {MIN_SECRET} to 512 characters")
    return value


class WebhookConfig(Cfg):
    url: str = Field(max_length=1000)
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    events: list[str] | None = None

    _u = field_validator("url")(classmethod(lambda cls, v: https_url(v)))
    _c = field_validator("ca_pem")(classmethod(lambda cls, v: ca_pem(v)))


def post_signed(url: str, secret: str, event_id: str, event_type: str, body: bytes, cfg_ca: str | None) -> Outcome:
    try:
        resp = outbound.request("POST", url, headers=signed_headers(secret, event_id, event_type, body), body=body,
                                ca_pem=cfg_ca)
    except Exception as exc:
        return failure(exc)
    if resp.status == 410:
        return Outcome("reject", "HTTP 410: the receiver no longer accepts these events")
    return http_outcome(resp)


def send(ctx: Context, events: list[dict[str, Any]]) -> list[Outcome]:
    secret = ctx.secrets.get("signing_secret") or ""
    out: list[Outcome] = []
    for event in events:
        outcome = post_signed(ctx.config.url, secret, event["id"], event["type"], json_body(event), ctx.config.ca_pem)
        out.append(outcome)
        if outcome.status == "retry":
            break
    return out


def test(ctx: Context, event: dict[str, Any]) -> Outcome:
    return send(ctx, [event])[0]
