"""The SCM HTTP client every provider uses, and the repository record they all return.

Rate limits (the reason discovery of thousands of repositories is safe):

* After every response the client reads the remaining budget and its reset time (GitHub ``X-RateLimit-*``, GitLab
  ``RateLimit-*``). When the remaining budget is at or under a reserve, the NEXT request waits for the reset instead of
  spending the last calls (and collecting 403s). The reserve is 5% of the budget, between 1 and 50 calls.
* A 403 / 429 with ``Retry-After`` (secondary limits, Bitbucket's limit) waits that long and retries; a 403 with an
  exhausted budget waits for the reset and retries.
* A wait longer than ``max_wait_s`` is not slept: the client raises ``ScmError(kind="rate_limited", reset_at=...)``
  and the inventory records a partial sync that resumes after the reset.
* 5xx answers and transport errors are retried with exponential backoff (0.5, 1, 2, 4 s), then fail.

Safety: redirects are never followed; a URL (pagination link) is only fetched on the base URL's scheme, host and port;
error messages are fixed sentences plus a status code, never a response body or a header value; the token is only
ever in the Authorization header. The proxy environment is honoured (an enterprise egress proxy is the normal way out).
"""
from __future__ import annotations

import datetime as dt
import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from backend.utilities.scm.hosts import same_origin

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
MAX_BODY = 20 * 1024 * 1024
RETRIES_5XX = 4
RETRIES_LIMIT = 8
DEFAULT_MAX_WAIT_S = 300.0


class ScmError(Exception):
    """A provider call failed. ``str(err)`` is safe to show; ``kind`` is auth | not_found | rate_limited | refused |
    transport | bad_response."""

    def __init__(self, message: str, kind: str, *, status: int | None = None, reset_at: dt.datetime | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.reset_at = reset_at


@dataclass
class DiscoveredRepo:
    external_id: str
    full_name: str
    name: str
    owner: str
    web_url: str
    clone_url: str
    default_branch: str
    visibility: str
    archived: bool
    fork: bool
    language: str | None
    topics: list[str] = field(default_factory=list)
    size_kb: int = 0
    pushed_at: dt.datetime | None = None

    def as_filter_input(self) -> dict[str, Any]:
        return {"full_name": self.full_name, "name": self.name, "archived": self.archived, "fork": self.fork,
                "topics": self.topics, "language": self.language, "visibility": self.visibility,
                "size_kb": self.size_kb}


def parse_time(value: Any) -> dt.datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


def _int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


class HttpClient:
    def __init__(self, base: str, headers: dict[str, str], *, flavour: str, max_wait_s: float | None = None,
                 sleep: Callable[[float], None] = time.sleep, transport: httpx.BaseTransport | None = None):
        self.base = base.rstrip("/")
        self.flavour = flavour  # github | gitlab | bitbucket (which rate-limit headers to read)
        self.headers = {"Accept": "application/json", "User-Agent": "zeroshield-devsecshield-scm/1", **headers}
        self.max_wait_s = DEFAULT_MAX_WAIT_S if max_wait_s is None else float(max_wait_s)
        self.sleep = sleep
        self.client = httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
                                   follow_redirects=False, trust_env=True, transport=transport)
        self.stats: dict[str, Any] = {"api_calls": 0, "pages": 0, "retries": 0, "waits": 0, "waited_s": 0.0,
                                      "rate_limit": None, "rate_remaining": None, "rate_reset": None}
        self._remaining: int | None = None
        self._limit: int | None = None
        self._reset_epoch: float | None = None

    def close(self) -> None:
        self.client.close()

    # ---------------------------------------------------------------- rate limits
    def _reserve(self) -> int:
        if not self._limit:
            return 1
        return max(1, min(50, self._limit // 20))

    def _wait(self, seconds: float) -> None:
        seconds = max(0.0, seconds)
        if seconds > self.max_wait_s:
            reset = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(seconds=seconds)
            raise ScmError(f"Rate limit reached; the provider resets it in {int(seconds)} s", "rate_limited",
                           reset_at=reset.replace(microsecond=0))
        if seconds:
            self.stats["waits"] += 1
            self.stats["waited_s"] = round(self.stats["waited_s"] + seconds, 3)
            self.sleep(seconds)

    def _before_request(self) -> None:
        if self._remaining is not None and self._remaining <= self._reserve() and self._reset_epoch:
            self._wait(self._reset_epoch - time.time() + 0.25)
            self._remaining = None

    def _read_limits(self, headers: httpx.Headers) -> None:
        if self.flavour == "github":
            limit, remaining, reset = (headers.get("x-ratelimit-limit"), headers.get("x-ratelimit-remaining"),
                                       headers.get("x-ratelimit-reset"))
        else:
            limit = headers.get("ratelimit-limit") or headers.get("x-ratelimit-limit")
            remaining = headers.get("ratelimit-remaining") or headers.get("x-ratelimit-remaining")
            reset = headers.get("ratelimit-reset") or headers.get("x-ratelimit-reset")
        if _int(limit) is not None:
            self._limit = _int(limit)
            self.stats["rate_limit"] = self._limit
        if _int(remaining) is not None:
            self._remaining = _int(remaining)
            self.stats["rate_remaining"] = self._remaining
        if _int(reset) is not None:
            value = float(_int(reset))  # epoch seconds (GitHub, GitLab); a small number is "seconds from now"
            self._reset_epoch = value if value > 1_000_000_000 else time.time() + value
            self.stats["rate_reset"] = int(self._reset_epoch)

    def _limited_wait(self, response: httpx.Response) -> float | None:
        """Seconds to wait before retrying a rate-limited answer, or None when the answer is not a rate limit."""
        if response.status_code not in (403, 429):
            return None
        retry_after = _int(response.headers.get("retry-after"))
        if retry_after is not None:
            return float(retry_after) + random.uniform(0, 0.2)
        if response.status_code == 429 or self._remaining == 0:
            if self._reset_epoch:
                return max(1.0, self._reset_epoch - time.time() + 0.25)
            return 60.0
        return None

    # ---------------------------------------------------------------- requests
    def url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base + "/", path_or_url.lstrip("/"))

    def request(self, method: str, path_or_url: str, *, params: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None, json_body: Any = None) -> httpx.Response:
        url = self.url(path_or_url)
        if not same_origin(self.base, url):
            raise ScmError("The provider sent a link to another host; it was not followed", "refused")
        limited_retries = transport_retries = 0
        while True:
            self._before_request()
            try:
                self.stats["api_calls"] += 1
                response = self.client.request(method, url, params=params, json=json_body,
                                               headers={**self.headers, **(headers or {})})
            except httpx.HTTPError as exc:
                transport_retries += 1
                if transport_retries > RETRIES_5XX:
                    raise ScmError(f"The provider could not be reached ({type(exc).__name__})", "transport") from None
                self.stats["retries"] += 1
                self.sleep(0.5 * 2 ** (transport_retries - 1))
                continue
            self._read_limits(response.headers)
            if len(response.content) > MAX_BODY:
                raise ScmError("The provider's answer was too large", "bad_response", status=response.status_code)
            wait = self._limited_wait(response)
            if wait is not None:
                limited_retries += 1
                if limited_retries > RETRIES_LIMIT:
                    raise ScmError("Still rate limited after several retries", "rate_limited",
                                   status=response.status_code)
                self.stats["retries"] += 1
                self._wait(wait)
                continue
            if response.status_code >= 500:
                transport_retries += 1
                if transport_retries > RETRIES_5XX:
                    raise ScmError(f"The provider answered HTTP {response.status_code}", "transport",
                                   status=response.status_code)
                self.stats["retries"] += 1
                self.sleep(0.5 * 2 ** (transport_retries - 1))
                continue
            if response.status_code == 401:
                raise ScmError("The credential was refused (HTTP 401); check the token or the App key", "auth",
                               status=401)
            if response.status_code == 403:
                raise ScmError("The credential cannot read this (HTTP 403); check its permissions", "auth", status=403)
            if response.status_code == 404:
                raise ScmError("Not found (HTTP 404): check the organisation, group or workspace name and that the "
                               "credential can see it", "not_found", status=404)
            if response.status_code >= 400:
                raise ScmError(f"The provider answered HTTP {response.status_code}", "bad_response",
                               status=response.status_code)
            return response

    def get_json(self, path_or_url: str, params: dict[str, Any] | None = None) -> tuple[Any, httpx.Headers]:
        response = self.request("GET", path_or_url, params=params)
        try:
            return response.json(), response.headers
        except ValueError:
            raise ScmError("The provider's answer was not JSON", "bad_response", status=response.status_code) from None

    def paginate_link(self, path: str, params: dict[str, Any], *, items_key: str | None = None) -> Iterator[Any]:
        """Follow ``Link: <...>; rel="next"`` (GitHub, GitLab keyset). Yields the items of each page."""
        url: str | None = path
        first = True
        while url:
            body, headers = self.get_json(url, params if first else None)
            first = False
            self.stats["pages"] += 1
            items = body.get(items_key) if items_key and isinstance(body, dict) else body
            if not isinstance(items, list):
                raise ScmError("The provider's answer had an unexpected shape", "bad_response")
            yield from items
            url = next_link(headers.get("link") or "")


def next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        target = section[0].strip()
        if target.startswith("<") and target.endswith(">") and any(s.strip() == 'rel="next"' for s in section[1:]):
            return target[1:-1]
    return None


__all__ = ["DiscoveredRepo", "HttpClient", "ScmError", "next_link", "parse_time"]
