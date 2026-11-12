"""Outbound HTTP to a team's identity provider (OIDC discovery, JWKS, token endpoint), without SSRF.

A team owner types the issuer URL, so the server must not let it reach the server's own network:

* by default the URL must be https and every address its name resolves to must be public; the connection goes to
  the checked addresses (``cbom_sources.safe_fetch``: the same resolver, pinning, caps and CA handling as the CBOM
  IdP collector);
* an operator who runs the IdP on a private network (Keycloak on-prem, a lab) lists its origin, exactly, in
  ``SSO_ALLOWED_IDP_ORIGINS`` (comma-separated ``scheme://host[:port]``): only those origins skip the public-address
  rule (http is allowed for them, for labs; it is logged at every use);
* no proxy from the environment, no redirects followed for POST, 1 MB and 15 s caps.
"""
from __future__ import annotations

import json
import logging
import os
import time
from urllib.parse import urlencode, urlsplit

log = logging.getLogger("backend.sso")

MAX_BYTES = 1024 * 1024
TIMEOUT = 15.0


class SsoHttpError(Exception):
    """``str(err)`` is safe to show."""


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}:{port}"


def allowed_origins() -> set[str]:
    out = set()
    for entry in (os.getenv("SSO_ALLOWED_IDP_ORIGINS") or "").split(","):
        entry = entry.strip().rstrip("/")
        if entry and urlsplit(entry).scheme in ("http", "https") and urlsplit(entry).hostname:
            out.add(_origin(entry))
    return out


def is_operator_listed(url: str) -> bool:
    return _origin(url) in allowed_origins()


def check_url(url: str) -> None:
    """Refuse what can never be fetched before anything is stored (the owner sees why at once)."""
    parts = urlsplit(url or "")
    if parts.username or parts.password:
        raise SsoHttpError("The URL must not contain a user name or password")
    if is_operator_listed(url):
        return
    if parts.scheme != "https" or not parts.hostname:
        raise SsoHttpError("Use an https:// URL (an operator can allow a private identity provider: SSO_ALLOWED_IDP_ORIGINS)")


def _listed_request(method: str, url: str, data: dict | None) -> tuple[int, bytes]:
    import httpx

    log.warning("sso: %s %s (operator-listed identity provider origin)", method, _origin(url))
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, trust_env=False) as client:
        response = client.request(method, url, data=data, headers={"Accept": "application/json"})
        body = response.content[:MAX_BYTES + 1]
    if len(body) > MAX_BYTES:
        raise SsoHttpError("The identity provider's answer is too large")
    return response.status_code, body


def _public_get(url: str) -> tuple[int, bytes]:
    from backend.utilities.cbom_sources import safe_fetch

    try:
        fetched = safe_fetch.fetch(url, accept="application/json")
    except safe_fetch.FetchError as exc:
        raise SsoHttpError(str(exc)) from None
    return fetched.status, fetched.body


def _public_post(url: str, data: dict) -> tuple[int, bytes]:
    """POST to a public https endpoint with the same address checks and pinning as ``safe_fetch.fetch``."""
    import http.client
    import ssl

    from backend.utilities.cbom_sources import safe_fetch

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SsoHttpError("only https:// URLs can be used")
    port = parts.port or 443
    try:
        addresses = safe_fetch._resolve(parts.hostname, port, safe_fetch._lab_private_allowed())
    except safe_fetch.FetchError as exc:
        raise SsoHttpError(str(exc)) from None
    conn = safe_fetch._PinnedHTTPS(parts.hostname, addresses, port, safe_fetch._context())
    body = urlencode(data).encode("ascii")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    deadline = time.monotonic() + TIMEOUT
    try:
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
            "Accept-Encoding": "identity", "User-Agent": "ZeroShield-SSO/1.0", "Host": parts.netloc})
        resp = conn.getresponse()
        return resp.status, safe_fetch._read_capped(resp, conn, deadline)
    except ssl.SSLCertVerificationError as exc:
        raise SsoHttpError(f"TLS certificate of {parts.hostname} is not trusted") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise SsoHttpError(f"Could not reach {parts.hostname} ({type(exc).__name__})") from None
    finally:
        conn.close()


def _json(status: int, body: bytes, what: str) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SsoHttpError(f"The identity provider's {what} is not JSON (HTTP {status})") from None
    if not isinstance(data, dict):
        raise SsoHttpError(f"The identity provider's {what} is not a JSON object")
    if status >= 400:
        error = data.get("error") if isinstance(data.get("error"), str) else f"HTTP {status}"
        raise SsoHttpError(f"The identity provider refused the request ({error[:80]})")
    return data


def get_json(url: str) -> dict:
    check_url(url)
    status, body = _listed_request("GET", url, None) if is_operator_listed(url) else _public_get(url)
    return _json(status, body, "document")


def post_form(url: str, data: dict) -> dict:
    check_url(url)
    status, body = _listed_request("POST", url, data) if is_operator_listed(url) else _public_post(url, data)
    return _json(status, body, "token answer")
