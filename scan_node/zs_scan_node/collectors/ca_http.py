"""Shared read-only HTTP for the CLM collectors (Venafi, Keyfactor, DigiCert, Sectigo).

Every request goes through ``netutil.http_client`` (pinned to the address checked against never-scan).
A timeout is a timeout. A 2xx body that is not JSON is reported as not JSON, and only after the response
has arrived. A 401 or 403 is returned to the caller so that target fails; the body is not parsed as a document.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any
from urllib.parse import urlsplit

from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.netutil import Blocked, http_client


def api_base(url: str, suffix: str) -> str:
    """``url`` with ``suffix`` (for example ``/vedsdk``) when the saved address does not already end with it."""
    base = str(url).rstrip("/")
    return base if base.lower().endswith(suffix.lower()) else base + suffix


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


def _stamp(value: Any) -> str | None:
    """An ISO-8601 instant the API returned, trimmed to seconds, or None when it is not a date."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) >= 19 and text[4] == "-" and text[7] == "-" and text[10] == "T":
        return text[:19] + "Z"
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10] + "T00:00:00Z"
    return None


def holds_private_key(raw: bytes) -> bool:
    """True when the body, or its base64 decoding, carries a PEM private key. Those bytes are never stored."""
    if b"PRIVATE KEY" in raw:
        return True
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error):
        return False
    return b"PRIVATE KEY" in decoded


class Api:
    def __init__(self, ctx: Any, url: str, what: str, headers: dict[str, str], ca_pem: str | None) -> None:
        from zs_scan_node.collectors.ca import _ssl, _target

        self.ctx = ctx
        self.what = what
        self.target = _target(ctx, url)
        merged = {"Accept": "application/json", **headers}
        self.client = http_client(url, self.target.ip, ctx.never_scan, verify=_ssl({"ca_pem": ca_pem} if ca_pem else {}),
                                  timeout=20.0, headers=merged)

    def close(self) -> None:
        self.client.close()

    def request(self, method: str, path: str, *, params: dict | None = None, body: dict | None = None,
                headers: dict[str, str] | None = None, json_body: bool = True) -> tuple[int, Any, bytes]:
        """(status, parsed JSON or None, raw body). Transport failures and a 2xx non-JSON body raise ``CaFail``."""
        from zs_scan_node.collectors.ca import CaFail, _http_error

        if self.ctx.should_stop():
            raise CaFail(self.ctx.should_stop() or "skipped_deadline", "stopped")
        kwargs: dict[str, Any] = {}
        if params is not None:
            kwargs["params"] = params
        if body is not None:
            kwargs["json"] = body
        if headers:
            kwargs["headers"] = headers
        try:
            response = self.client.request(method, path, **kwargs)
        except Blocked as exc:
            raise CaFail("skipped_never_scan", str(exc)) from None
        except Exception as exc:  # noqa: BLE001  httpx and TLS errors, mapped by _http_error
            raise _http_error(exc, self.what) from None
        status, content = response.status_code, response.content or b""
        if status in (401, 403) or not json_body:
            return status, None, content
        if not content:
            if 200 <= status < 300:
                raise CaFail("error", f"{self.what} returned an empty body")
            return status, None, content
        try:
            parsed = response.json()
        except ValueError:
            if 200 <= status < 300:
                raise CaFail("error", f"{self.what} answered with something that is not JSON")
            return status, None, content
        return status, parsed, content


def emit_certificate(ctx: Any, target: Any, location: str, raw: bytes, provider: str) -> int:
    """One certificate asset from public certificate bytes, the same shape AD CS and EJBCA emit. 0 when the bytes
    are not a certificate or they carry a private key (those bytes are dropped)."""
    if not raw or holds_private_key(raw):
        return 0
    certs = load_certs(raw)
    if not certs:
        try:
            unpacked = base64.b64decode(raw, validate=True)
        except (ValueError, binascii.Error):
            unpacked = b""
        if unpacked and not holds_private_key(unpacked):
            certs = load_certs(unpacked)
    if not certs:
        return 0
    facts = cert_facts(certs[0], provider)
    facts["provider"] = provider
    ctx.emit("certificate", target.label, location, name=facts.get("subject", ""),
             algorithm=facts.get("key_alg"), key_size=facts.get("key_size"), facts=facts)
    return 1


def rows_of(parsed: Any, what: str) -> list[dict]:
    """A certificate list: a JSON array, or the one array inside an object. Anything else is an error, not an empty estate."""
    from zs_scan_node.collectors.ca import CaFail

    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    if isinstance(parsed, dict):
        arrays = [value for value in parsed.values() if isinstance(value, list)]
        if len(arrays) == 1:
            return [row for row in arrays[0] if isinstance(row, dict)]
    raise CaFail("error", f"{what} answered with something that is not a certificate list")
