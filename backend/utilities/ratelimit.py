"""In-process rate limits for the API routes.

Every limiter is a fixed window aligned to the clock (``now // seconds``).  Counts live in this worker's
memory, so with N gunicorn workers a client can get up to N x the configured budget (requests are spread
across workers).  That is acceptable for load shedding; the security-critical counters (one live sign-in
code per email, wrong-code attempts, codes sent per email) are kept in Postgres by ``auth_utils`` instead.

Keys (the budget a request is charged to):

* ``user_key``: the subject of a VERIFIED access token.  A missing, forged, expired or malformed token
  falls back to the client address, so it can never mint a fresh budget of its own.
* ``ip_key``: the client address, IPv6 grouped by /64 and IPv4-mapped IPv6 unwrapped.
* Callers add verified keys of their own (CI/CD integration id, scan-node id) the same way: verify first,
  fall back to ``ip_key``.

Client address = ``request.client.host`` only.  uvicorn's proxy-headers middleware has already replaced the
TCP peer with the ``X-Forwarded-For`` client when, and only when, the peer is listed in
``FORWARDED_ALLOW_IPS`` (gunicorn reads the same variable and hands it to the uvicorn worker).  App code
never parses ``X-Forwarded-For`` itself, so a client cannot choose its own key.

Memory: when a window ends every stored count is stale, so the whole table is dropped (the sweep).  Within
one window at most ``max_keys`` keys are tracked.  A full table never lets a request through uncounted: the
least recently charged key is evicted to make room (a refused request counts as a charge, so a key that keeps
trying stays tracked), and while the table is full a new IPv6 /64 is charged to its /48, so rotating through
the 65,536 /64s of one routed /48 lands in one bucket.  Logged once per window (``rate_limit_table_full``);
verified keys and real client addresses only reach that under a large distributed flood.

A refused request gets 429 with ``Retry-After`` (seconds to the end of the window) and one ``rate_limited``
log line per key per window: limiter name, route, key kind and a short hash of the key, never a token.
"""
# no `from __future__ import annotations`: FastAPI reads the `request: Request` annotation of an instance's
# __call__ at runtime and cannot resolve it from a string there.

import hashlib
import ipaddress
import logging
import math
import threading
import time
from collections import OrderedDict
from typing import Awaitable, Callable

from fastapi import HTTPException, Request

log = logging.getLogger("backend.ratelimit")

Key = tuple[str, str]  # (kind, value): kind is "user", "ip", "ci", "node", "email", ...
KeyFunc = Callable[[Request], Awaitable[Key]]

DEFAULT_MAX_KEYS = 50_000
TOO_MANY = "Too Many Requests"

_REGISTRY: list["RateLimiter"] = []


def normalise_ip(host: str | None) -> str:
    """One bucket per IPv4 address or per IPv6 /64 (a single host usually owns a whole /64)."""
    text = (host or "").strip()
    if "%" in text:  # IPv6 zone id (fe80::1%eth0)
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if ip.version == 6:
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return str(mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def _ipv6_48(value: str) -> str | None:
    """The /48 of an IPv6 /64 key from ``normalise_ip``; None for anything else."""
    if not value.endswith("/64"):
        return None
    try:
        network = ipaddress.ip_network(value)
    except ValueError:
        return None
    return str(network.supernet(new_prefix=48)) if network.version == 6 else None


def client_ip(request: Request) -> str:
    return normalise_ip(request.client.host if request.client else None)


def bearer_token(request: Request) -> str | None:
    """The token of a well-formed ``Authorization: Bearer <token>`` header (scheme in any letter case)."""
    parts = (request.headers.get("authorization") or "").split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1]:
        return parts[1]
    return None


async def ip_key(request: Request) -> Key:
    return ("ip", client_ip(request))


async def user_key(request: Request) -> Key:
    token = bearer_token(request)
    if token:
        # imported here: auth_utils reads the JWT secrets at import time, this module must stay importable alone
        from backend.utilities.auth.auth_utils import access_token_subject

        subject = access_token_subject(token)
        if subject:
            return ("user", subject)
    return await ip_key(request)


def _short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _route(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", None) or request.url.path


class RateLimiter:
    """``times`` requests per key per ``seconds``-long window.  Use it in the route decorator:

        @router.get("/x", dependencies=[Depends(read_limiter)])

    (a ``dependencies=[...]`` *parameter* in the endpoint signature is a query parameter, not a dependency).
    """

    def __init__(
        self,
        name: str,
        times: int,
        seconds: int,
        key_func: KeyFunc = user_key,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if times < 1 or seconds < 1 or max_keys < 1:
            raise ValueError("times, seconds and max_keys must be positive")
        self.name = name
        self.times = times
        self.seconds = seconds
        self.key_func = key_func
        self.max_keys = max_keys
        self.clock: Callable[[], float] = time.time
        # key -> count in the current window, least recently charged first
        self.requests: OrderedDict[str, int] = OrderedDict()
        self._window = -1
        self._full_logged_window = -1
        self._lock = threading.Lock()
        _REGISTRY.append(self)

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()
            self._window = -1
            self._full_logged_window = -1

    def _count(self, kind: str, value: str) -> tuple[int, int, str]:
        """Charge one request.  Returns (count in this window, seconds to the window's end, the value charged:
        ``value``, or its IPv6 /48 while the table is full)."""
        now = self.clock()
        window = int(now // self.seconds)
        retry_after = max(1, math.ceil((window + 1) * self.seconds - now))
        with self._lock:
            if window != self._window:
                self.requests.clear()  # every count of an older window is stale
                self._window = window
            key = f"{kind}:{value}"
            if key not in self.requests and len(self.requests) >= self.max_keys:
                if self._full_logged_window != window:
                    self._full_logged_window = window
                    log.warning("rate_limit_table_full limiter=%s max_keys=%d evicting=least_recent",
                                self.name, self.max_keys)
                coarse = _ipv6_48(value) if kind == "ip" else None
                if coarse is not None:
                    value, key = coarse, f"{kind}:{coarse}"
                if key not in self.requests:
                    self.requests.popitem(last=False)  # the least recently charged key
            count = self.requests.get(key, 0) + 1
            self.requests[key] = count
            self.requests.move_to_end(key)
        return count, retry_after, value

    async def charge(self, request: Request, key: Key) -> None:
        """Charge ``request`` to ``key``; raise 429 with Retry-After when the window's budget is spent."""
        kind, value = key
        count, retry_after, value = self._count(kind, value)
        if count > self.times:
            if count == self.times + 1:  # one line per key per window, not one per refused request
                log.warning(
                    "rate_limited limiter=%s route=%s key_kind=%s key=%s limit=%d window_s=%d retry_after=%d",
                    self.name, _route(request), kind, _short(value), self.times, self.seconds, retry_after,
                )
            raise HTTPException(status_code=429, detail=TOO_MANY, headers={"Retry-After": str(retry_after)})

    async def __call__(self, request: Request) -> None:
        await self.charge(request, await self.key_func(request))


def all_limiters() -> list[RateLimiter]:
    return list(_REGISTRY)


def reset_all() -> None:
    """Forget every count (tests)."""
    for limiter in _REGISTRY:
        limiter.reset()
