"""HTTPS for the Azure and Google Cloud collectors (cloud worker): JSON over a fixed set of provider hosts.

A bearer token is only ever sent to an allow-listed provider host over HTTPS: the fixed ARM, Entra ID and Google API
hosts, and Azure Key Vault data-plane hosts (``<vault>.vault.azure.net``).  Next-page links are followed only when they
stay on the host of the request that returned them.  No redirects, short timeouts, a response size cap, up to four
retries on 429/503 (honouring Retry-After up to 10 s, else a growing back-off); a call still throttled after that fails
with the code ``Throttled``, which the collectors turn into a coverage row.  The TLS context is the one ``safe_fetch`` uses (TLS 1.2+, plus
``CBOM_EXTRA_CA_FILE`` for an inspecting egress proxy); ``HTTPS_PROXY`` is honoured.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from backend.utilities.cbom_sources.safe_fetch import _context as _tls_context

FIXED_HOSTS = frozenset({
    "login.microsoftonline.com", "management.azure.com",
    "oauth2.googleapis.com", "cloudresourcemanager.googleapis.com", "cloudkms.googleapis.com",
    "privateca.googleapis.com", "secretmanager.googleapis.com", "certificatemanager.googleapis.com",
    "compute.googleapis.com", "storage.googleapis.com",
})
_VAULT_HOST = re.compile(r"[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net")  # vault names: 3-24 characters
MAX_BODY = 8 * 1024 * 1024
MAX_PAGES = 200
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
ATTEMPTS = 5  # one call and four retries on 429 / 503 / a timeout
MAX_WAIT_S = 10.0


class CloudHttpError(Exception):
    """``str(err)`` is safe to show: provider error code and a trimmed message, never a token or a request body."""

    def __init__(self, status: int, code: str, message: str = ""):
        self.status, self.code = status, code
        super().__init__(f"{code}{': ' + message[:200] if message else ''}")


def host_allowed(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or (parts.port not in (None, 443)):
        return False
    return host in FIXED_HOSTS or bool(_VAULT_HOST.fullmatch(host))


def _backoff(retry_after: str | None, attempt: int) -> float:
    """Retry-After in seconds when the provider sends one (capped), else 1, 2, 4, 8 s."""
    try:
        wait = float(retry_after) if retry_after is not None else float(2 ** attempt)
    except ValueError:
        wait = float(2 ** attempt)
    return max(min(wait, MAX_WAIT_S), 0.0)


def _error(status: int, raw: bytes) -> CloudHttpError:
    code, message = f"HTTP {status}", ""
    try:
        body = json.loads(raw or b"null")
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):  # ARM, Key Vault and Google APIs
            inner = err.get("innererror") if isinstance(err.get("innererror"), dict) else {}
            reasons = [d.get("reason") for d in err.get("details") or [] if isinstance(d, dict) and d.get("reason")]
            code = str(inner.get("code") or (reasons[0] if reasons else None) or err.get("code") or err.get("status") or code)
            message = str(err.get("message") or "")
        elif isinstance(err, str):  # OAuth token endpoints: {"error": "invalid_client", "error_description": ...}
            code = err
            message = str(body.get("error_description") or "").split("\r\n")[0].split(" Trace ID:")[0]
    return CloudHttpError(status, code[:80], message)


class CloudHttp:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        kwargs: dict[str, Any] = {"timeout": TIMEOUT, "follow_redirects": False, "headers": {"Accept": "application/json"}}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            kwargs["verify"] = _tls_context()
        self._client = httpx.Client(**kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CloudHttp":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def request(self, method: str, url: str, *, token: str | None = None, data: dict[str, str] | None = None,
                params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        if not host_allowed(url):
            raise CloudHttpError(0, "HostNotAllowed", urlsplit(url).hostname or "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        for attempt in range(ATTEMPTS):
            last = attempt == ATTEMPTS - 1
            try:
                with self._client.stream(method, url, headers=headers, data=data, params=params,
                                         json=json_body) as response:
                    if response.status_code in (429, 503):
                        if not last:
                            time.sleep(_backoff(response.headers.get("Retry-After"), attempt))
                            continue
                        response.read()
                        provider = _error(response.status_code, response.content[:4096])
                        raise CloudHttpError(response.status_code, "Throttled", f"{provider.code} after {ATTEMPTS} attempts")
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > MAX_BODY:
                            raise CloudHttpError(response.status_code, "ResponseTooLarge")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    if response.status_code >= 400:
                        raise _error(response.status_code, body)
                    try:
                        parsed = json.loads(body or b"{}")
                    except ValueError as exc:
                        raise CloudHttpError(response.status_code, "NotJson") from exc
                    return parsed if isinstance(parsed, dict) else {"value": parsed}
            except httpx.TimeoutException as exc:
                if last:
                    raise CloudHttpError(0, "Timeout", urlsplit(url).hostname or "") from exc
                time.sleep(_backoff(None, attempt))
            except httpx.TransportError as exc:
                raise CloudHttpError(0, type(exc).__name__, urlsplit(url).hostname or "") from exc
        raise CloudHttpError(429, "Throttled")

    def get(self, url: str, token: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request("GET", url, token=token, params=params)

    def azure_pages(self, url: str, token: str, *, cap: int) -> tuple[list[dict[str, Any]], bool]:
        """Follow Azure ``nextLink`` (same host only).  Returns (items, truncated)."""
        items: list[dict[str, Any]] = []
        host = urlsplit(url).hostname
        for _ in range(MAX_PAGES):
            page = self.get(url, token)
            items.extend(v for v in page.get("value") or [] if isinstance(v, dict))
            if len(items) >= cap:
                return items[:cap], True
            nxt = page.get("nextLink")
            if not nxt:
                return items, False
            if urlsplit(str(nxt)).hostname != host:
                raise CloudHttpError(0, "NextLinkHostChanged", str(urlsplit(str(nxt)).hostname))
            url = str(nxt)
        return items, True

    def google_pages(self, url: str, token: str, key: str, *, cap: int, params: dict[str, Any] | None = None
                     ) -> tuple[list[dict[str, Any]], bool]:
        """Follow Google ``nextPageToken``.  Returns (items, truncated)."""
        items: list[dict[str, Any]] = []
        query = dict(params or {})
        for _ in range(MAX_PAGES):
            page = self.get(url, token, params=query)
            items.extend(v for v in page.get(key) or [] if isinstance(v, dict))
            if len(items) >= cap:
                return items[:cap], True
            token_next = page.get("nextPageToken")
            if not token_next:
                return items, False
            query["pageToken"] = token_next
        return items, True

    def google_aggregated(self, url: str, token: str, key: str, *, cap: int) -> tuple[list[dict[str, Any]], bool, list[str]]:
        """Compute Engine ``aggregatedList``: ``items`` maps a scope (``global``, ``regions/x``) to ``{key: [...]}`` or
        a ``warning``.  Asks for partial success, so a region that cannot be answered is named in ``unreachables``
        instead of failing the call.  Returns (items, truncated, unreachable scopes)."""
        items: list[dict[str, Any]] = []
        unreachable: list[str] = []
        query: dict[str, Any] = {"maxResults": 500, "returnPartialSuccess": "true"}
        for _ in range(MAX_PAGES):
            page = self.get(url, token, params=query)
            scoped = page.get("items")
            for entry in (scoped.values() if isinstance(scoped, dict) else []):
                if isinstance(entry, dict):
                    items.extend(v for v in entry.get(key) or [] if isinstance(v, dict))
            unreachable.extend(str(u) for u in page.get("unreachables") or [] if isinstance(u, str))
            if len(items) >= cap:
                return items[:cap], True, unreachable
            token_next = page.get("nextPageToken")
            if not token_next:
                return items, False, unreachable
            query["pageToken"] = token_next
        return items, True, unreachable
