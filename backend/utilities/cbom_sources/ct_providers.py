"""Certificate Transparency search providers for CT discovery (cloud worker).

A provider answers "every logged certificate for this domain" as a list of ``Issuance`` (a certificate and its
precertificate are one issuance).  Two providers exist; SPEC section 2 has the evidence for the choice:

* ``certspotter`` (default): SSLMate Cert Spotter API v1 ``/v1/issuances``.  DER of the certificate (the final one
  when known), issuer DN and name, SANs in punycode, public key, revocation.  Unexpired certificates only.  Pages
  of 100 with ``after=<id>``; a short page is the last.  A key (``CBOM_CT_CERTSPOTTER_KEY``) is required for production use by its
  terms; without one the unauthenticated quota is 10 full-domain queries an hour per address (x-ratelimit-limit).
* ``crtsh``: crt.sh JSON.  No key, no paging, 5 requests a minute per address, frequent 502s and multi-second
  answers (recorded on GitHub runners).  Rows carry no public key, signature algorithm or fingerprint, so its
  issuances are ``detail="summary"``.  Used as a fallback only.

RFC 6962 logs themselves are not a provider: a log can only be read by index, never searched by name.

HTTP: httpx to a fixed set of hosts (``api.certspotter.com``, ``crt.sh``), HTTPS only, no redirects, a body cap,
a token bucket per host shared by the process, ``Retry-After`` honoured on 429 (a ``Retry-After`` on a 200 is
Cert Spotter's polling hint and is ignored), exponential backoff with full jitter on 5xx / timeouts / bodies that are
not JSON, and a short in-process cache of whole answers (CT data is public; two teams asking for one domain within
the TTL cost one search).  The clock and sleep are injectable (bench/ct/scale.py runs on a simulated clock).
"""
from __future__ import annotations

import base64
import binascii
import email.utils
import json
import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

import httpx

FIXED_HOSTS = frozenset({"api.certspotter.com", "crt.sh"})
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_EXPAND = ("dns_names", "issuer", "revocation", "cert_der", "pubkey")
MAX_BODY = 16 * 1024 * 1024
MAX_PAGES = 40  # per domain
MAX_RESULTS = 2_000  # per domain; more is listed as a partial answer
MAX_RETRIES = 2  # 5xx, timeouts and non-JSON bodies
MAX_RATE_RETRIES = 4  # 429 / rate_limited
BACKOFF_BASE_S = 2.0
BACKOFF_CAP_S = 60.0
MAX_WAIT_S = 900.0  # a single wait longer than this is not waited for: the provider is "throttled"
TIMEOUT = httpx.Timeout(90.0, connect=15.0)
_AUTH_CODES = frozenset({"bad_credentials", "unauthorized", "payment_required", "disabled_credentials",
                         "not_allowed_by_plan"})
_RETRY_CODES = frozenset({"internal_error", "service_outage", "timeout"})


class CtError(Exception):
    """A provider could not answer for one domain.  ``str(err)`` is safe to show to the customer.

    kind: ``refused`` (the provider rejected the query: no retry, no fallback), ``auth`` (the key was refused),
    ``rate_limited`` (quota spent; ``retry_after`` seconds when known), ``unavailable`` (5xx, timeouts, network),
    ``malformed`` (an answer that is not the documented JSON)."""

    def __init__(self, kind: str, message: str, retry_after: float | None = None):
        self.kind, self.retry_after = kind, retry_after
        super().__init__(message[:300])


@dataclass
class Issuance:
    provider: str
    provider_id: str
    detail: str  # "full" (DER) or "summary" (crt.sh row: no key, signature or fingerprint)
    serial: str | None = None
    issuer_dn: str | None = None
    issuer_name: str | None = None  # the provider's display name (Cert Spotter friendly_name)
    subject_cn: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    dns_names: list[str] = field(default_factory=list)
    der: bytes | None = None
    tbs_sha256: str | None = None
    cert_sha256: str | None = None  # the provider's hash: of the certificate when known, else the precertificate
    pubkey: dict[str, Any] | None = None
    revoked: bool | None = None
    revocation_time: str | None = None
    revocation_reason: Any = None
    precert: bool | None = None  # crt.sh: unknown; Cert Spotter: decided from the DER


@dataclass
class SearchResult:
    domain: str
    provider: str
    issuances: list[Issuance]
    pages: int = 0
    requests: int = 0
    truncated: bool = False
    cached: bool = False


# ----------------------------------------------------------------------------- clock, rate, cache
class Clock:
    """Real time by default; bench/ct/scale.py passes a simulated one."""

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class TokenBucket:
    """At most ``per_second`` and ``per_minute`` requests; ``take`` waits (on the given clock) for a token."""

    def __init__(self, per_second: float, per_minute: float):
        self.per_second, self.per_minute = max(per_second, 0.01), max(per_minute, 0.01)
        self._sec = self._min = None  # type: ignore[assignment]
        self._lock = threading.Lock()

    def wait_time(self, now: float) -> float:
        with self._lock:
            if self._sec is None:
                self._sec, self._min, self._t = self.per_second, self.per_minute, now
            elapsed = max(now - self._t, 0.0)
            self._t = now
            self._sec = min(self.per_second, self._sec + elapsed * self.per_second)
            self._min = min(self.per_minute, self._min + elapsed * self.per_minute / 60.0)
            if self._sec >= 1 and self._min >= 1:
                self._sec -= 1
                self._min -= 1
                return 0.0
            need_sec = 0.0 if self._sec >= 1 else (1 - self._sec) / self.per_second
            need_min = 0.0 if self._min >= 1 else (1 - self._min) * 60.0 / self.per_minute
            return max(need_sec, need_min, 0.001)

    def take(self, clock: Clock) -> float:
        waited = 0.0
        while True:
            wait = self.wait_time(clock.monotonic())
            if wait <= 0:
                return waited
            clock.sleep(wait)
            waited += wait


def _rate(name: str, default: tuple[float, float]) -> tuple[float, float]:
    """``CBOM_CT_RATE_<NAME>="<per second>/<per minute>"``, e.g. "10/500" for a Medium Cert Spotter plan."""
    text = os.environ.get(f"CBOM_CT_RATE_{name.upper()}", "")
    try:
        sec, minute = (float(x) for x in text.split("/", 1))
        if sec > 0 and minute > 0:
            return sec, minute
    except ValueError:
        pass
    return default


_BUCKETS: dict[str, TokenBucket] = {}
_BUCKETS_LOCK = threading.Lock()


def bucket(name: str, default: tuple[float, float]) -> TokenBucket:
    with _BUCKETS_LOCK:
        if name not in _BUCKETS:
            _BUCKETS[name] = TokenBucket(*_rate(name, default))
        return _BUCKETS[name]


class AnswerCache:
    """Whole per-domain answers, keyed (provider, domain, flags), for ``ttl`` seconds; bounded by entries."""

    def __init__(self, ttl: float, max_entries: int = 5_000):
        self.ttl, self.max_entries = ttl, max_entries
        self._data: dict[tuple, tuple[float, SearchResult]] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple, now: float) -> SearchResult | None:
        with self._lock:
            hit = self._data.get(key)
            if hit is None or hit[0] < now:
                self._data.pop(key, None)
                return None
            return hit[1]

    def put(self, key: tuple, value: SearchResult, now: float) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            if len(self._data) >= self.max_entries:
                for old in sorted(self._data, key=lambda k: self._data[k][0])[: self.max_entries // 10 or 1]:
                    self._data.pop(old, None)
            self._data[key] = (now + self.ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


def _cache_ttl() -> float:
    try:
        return max(float(os.environ.get("CBOM_CT_CACHE_TTL_S", "3600")), 0.0)
    except ValueError:
        return 3600.0


CACHE = AnswerCache(_cache_ttl())


# ----------------------------------------------------------------------------- HTTP
@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


def _retry_after(headers: dict[str, str], now_wall: float | None = None) -> float | None:
    value = (headers.get("retry-after") or "").strip()
    if not value:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(when.timestamp() - (now_wall if now_wall is not None else time.time()), 0.0)


def _error_code(body: bytes) -> tuple[str | None, str]:
    try:
        parsed = json.loads(body or b"null")
    except ValueError:
        return None, ""
    if isinstance(parsed, dict):
        return (str(parsed.get("code")) if parsed.get("code") else None), str(parsed.get("message") or "")
    return None, ""


class CtHttp:
    """GET with the retry, backoff and rate rules above.  ``transport``: an httpx transport (tests, the bench)."""

    def __init__(self, transport: httpx.BaseTransport | None = None, clock: Clock | None = None,
                 rng: random.Random | None = None):
        kwargs: dict[str, Any] = {"timeout": TIMEOUT, "follow_redirects": False,
                                  "headers": {"Accept": "application/json", "User-Agent": "ZeroShield-CBOM-CT/1"}}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            from backend.utilities.cbom_sources.safe_fetch import _context as _tls_context

            kwargs["verify"] = _tls_context()
        self._client = httpx.Client(**kwargs)
        self.clock = clock or Clock()
        self.rng = rng or random.Random()
        self.requests = 0
        self.waited_s = 0.0
        self.rate_limited = 0

    def close(self) -> None:
        self._client.close()

    def _backoff(self, attempt: int) -> float:
        return self.rng.uniform(0, min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** attempt)))

    def get(self, url: str, *, bucket_: TokenBucket, headers: dict[str, str] | None = None,
            deadline: float | None = None, what: str = "the provider") -> Response:
        parts = urlsplit(url)
        if parts.scheme != "https" or (parts.hostname or "") not in FIXED_HOSTS or parts.port not in (None, 443):
            raise CtError("refused", f"{parts.hostname or 'that host'} is not a Certificate Transparency provider")
        transient = rated = 0
        while True:
            self.waited_s += bucket_.take(self.clock)
            self.requests += 1
            try:
                with self._client.stream("GET", url, headers=headers or {}) as resp:
                    chunks, size = [], 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > MAX_BODY:
                            raise CtError("malformed", f"{what} answered with more than {MAX_BODY // 2**20} MB")
                        chunks.append(chunk)
                    answer = Response(resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, b"".join(chunks))
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if transient < MAX_RETRIES:
                    self._wait(self._backoff(transient), deadline, what)
                    transient += 1
                    continue
                raise CtError("unavailable", f"{what} did not answer ({type(exc).__name__})") from None
            code, message = _error_code(answer.body)
            if answer.status == 429 or code == "rate_limited":
                self.rate_limited += 1
                wait = _retry_after(answer.headers)
                wait = self._backoff(rated + 2) if wait is None else wait
                if rated >= MAX_RATE_RETRIES or wait > MAX_WAIT_S or not self._fits(wait, deadline):
                    raise CtError("rate_limited", f"{what} rate limit reached; retry after {int(wait)} s", wait)
                self._wait(wait, deadline, what)
                rated += 1
                continue
            if answer.status in (401, 402, 403) or code in _AUTH_CODES:
                raise CtError("auth", f"{what} refused the API key ({code or answer.status})")
            if answer.status >= 500 or code in _RETRY_CODES:
                if transient < MAX_RETRIES:
                    self._wait(self._backoff(transient), deadline, what)
                    transient += 1
                    continue
                raise CtError("unavailable", f"{what} answered HTTP {answer.status}{f' ({code})' if code else ''}")
            if answer.status >= 400:
                raise CtError("refused", f"{what} refused the query: {message or code or f'HTTP {answer.status}'}")
            if answer.status != 200:
                raise CtError("malformed", f"{what} answered HTTP {answer.status}")
            return answer

    def _fits(self, wait: float, deadline: float | None) -> bool:
        return deadline is None or self.clock.monotonic() + wait < deadline

    def _wait(self, seconds: float, deadline: float | None, what: str) -> None:
        if not self._fits(seconds, deadline):
            raise CtError("unavailable", f"{what} kept failing and the run's time ran out")
        self.clock.sleep(seconds)
        self.waited_s += seconds


def json_list(answer: Response, what: str) -> list[Any]:
    try:
        parsed = json.loads(answer.body)
    except ValueError:
        raise CtError("malformed", f"{what} answered with something that is not JSON") from None
    if not isinstance(parsed, list):
        raise CtError("malformed", f"{what} answered with JSON that is not a list")
    return parsed


# ----------------------------------------------------------------------------- providers
def _b64(text: Any) -> bytes | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _str(value: Any, limit: int = 255) -> str | None:
    return str(value)[:limit] if isinstance(value, (str, int)) and str(value) != "" else None


def page_size() -> int:
    """Cert Spotter's page size (100, recorded on google.com: two pages of 100).  A page shorter than this is the last
    one.  ``CBOM_CT_CERTSPOTTER_PAGE_SIZE=0`` follows the documented rule only (page until an empty page)."""
    try:
        value = int(os.environ.get("CBOM_CT_CERTSPOTTER_PAGE_SIZE", "100"))
    except ValueError:
        value = 100
    return value if value > 0 else 0


class CertSpotter:
    name = "certspotter"
    label = "Cert Spotter"

    def __init__(self, http: CtHttp, api_key: str | None = None, rate: TokenBucket | None = None):
        self.http, self.api_key = http, api_key
        self.rate = rate or bucket("certspotter", (5.0, 75.0))

    def _url(self, domain: str, include_subdomains: bool, after: str | None) -> str:
        params: list[tuple[str, str]] = [("domain", domain), ("include_subdomains", "true" if include_subdomains else "false"),
                                         ("match_wildcards", "true")]
        params += [("expand", e) for e in CERTSPOTTER_EXPAND]
        if after:
            params.append(("after", after))
        return CERTSPOTTER_URL + "?" + urlencode(params)

    def search(self, domain: str, include_subdomains: bool, deadline: float | None = None) -> SearchResult:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        out = SearchResult(domain, self.name, [])
        after: str | None = None
        while True:
            if out.pages >= MAX_PAGES or len(out.issuances) >= MAX_RESULTS:
                out.truncated = True
                break
            answer = self.http.get(self._url(domain, include_subdomains, after), bucket_=self.rate, headers=headers,
                                   deadline=deadline, what=self.label)
            out.requests += 1
            rows = json_list(answer, self.label)
            out.pages += 1
            if not rows:
                break
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                    raise CtError("malformed", f"{self.label} answered with an issuance that has no id")
                out.issuances.append(self.issuance(row))
            if 0 < len(rows) < page_size():
                break  # a short page is the last one: saves the empty-page query (each costs quota)
            after = rows[-1]["id"]
        if len(out.issuances) > MAX_RESULTS:
            out.issuances, out.truncated = out.issuances[:MAX_RESULTS], True
        return out

    def issuance(self, row: dict[str, Any]) -> Issuance:
        issuer = row.get("issuer") if isinstance(row.get("issuer"), dict) else {}
        revocation = row.get("revocation") if isinstance(row.get("revocation"), dict) else {}
        names = [str(n)[:253] for n in row.get("dns_names") or [] if isinstance(n, str)]
        return Issuance(
            provider=self.name, provider_id=str(row["id"])[:64], detail="full" if _b64(row.get("cert_der")) else "summary",
            issuer_dn=_str(issuer.get("name")), issuer_name=_str(issuer.get("friendly_name"), 128),
            not_before=_str(row.get("not_before"), 40), not_after=_str(row.get("not_after"), 40), dns_names=names,
            der=_b64(row.get("cert_der")), tbs_sha256=_str(row.get("tbs_sha256"), 64),
            cert_sha256=_str(row.get("cert_sha256"), 64),
            pubkey=row.get("pubkey") if isinstance(row.get("pubkey"), dict) else None,
            revoked=row.get("revoked") if isinstance(row.get("revoked"), bool) else None,
            revocation_time=_str(revocation.get("time"), 40), revocation_reason=revocation.get("reason"),
        )


class CrtSh:
    name = "crtsh"
    label = "crt.sh"

    def __init__(self, http: CtHttp, rate: TokenBucket | None = None):
        self.http = http
        self.rate = rate or bucket("crtsh", (1.0, 5.0))

    def search(self, domain: str, include_subdomains: bool, deadline: float | None = None) -> SearchResult:
        """One request: ``q=<domain>`` is crt.sh's identity search, which also returns subdomains (recorded: the
        same 23 names as ``q=%.<domain>``); rows are kept only when one of their names is the domain or, with
        subdomains, under it, because the search also matches names that merely contain the text."""
        from backend.utilities.cbom_sources.ct_domains import covered_by

        out = SearchResult(domain, self.name, [])
        seen: dict[tuple[str, str], Issuance] = {}
        url = CRTSH_URL + "?" + urlencode({"q": domain, "output": "json", "exclude": "expired", "deduplicate": "Y"})
        answer = self.http.get(url, bucket_=self.rate, deadline=deadline, what=self.label)
        out.requests += 1
        out.pages += 1
        for row in json_list(answer, self.label):
            if not isinstance(row, dict) or row.get("id") is None:
                raise CtError("malformed", f"{self.label} answered with a row that has no id")
            names = [n.strip().lower()[:253] for n in str(row.get("name_value") or "").split("\n") if n.strip()]
            bare = [n[2:] if n.startswith("*.") else n for n in names]
            if not any(n == domain or (include_subdomains and covered_by(n, domain)) for n in bare):
                continue
            serial = str(row.get("serial_number") or "").lower().lstrip("0") or None
            key = (serial or f"id:{row['id']}", str(row.get("issuer_ca_id") or row.get("issuer_name") or ""))
            if key in seen:
                continue  # deduplicate=Y already merges a precertificate with its certificate; this is a guard
            seen[key] = Issuance(
                provider=self.name, provider_id=str(row["id"])[:64], detail="summary", serial=serial,
                issuer_dn=_str(row.get("issuer_name")), subject_cn=_str(row.get("common_name")),
                not_before=_z(row.get("not_before")), not_after=_z(row.get("not_after")), dns_names=names[:200],
            )
            if len(seen) >= MAX_RESULTS:
                out.truncated = True
                break
        out.issuances = list(seen.values())
        return out


def _z(value: Any) -> str | None:
    """crt.sh times have no zone; they are UTC."""
    text = _str(value, 40)
    if not text:
        return None
    return text if text.endswith("Z") else text.split(".")[0] + "Z"


PROVIDERS = {"certspotter": CertSpotter, "crtsh": CrtSh}


def provider_names() -> list[str]:
    """``CBOM_CT_PROVIDER``: provider names in order, comma-separated; default ``certspotter,crtsh``."""
    names = [n.strip().lower() for n in (os.environ.get("CBOM_CT_PROVIDER") or "certspotter,crtsh").split(",")]
    return [n for n in dict.fromkeys(names) if n in PROVIDERS] or ["certspotter"]


def build_chain(http: CtHttp, names: list[str] | None = None) -> list[Any]:
    chain = []
    for name in names or provider_names():
        if name == "certspotter":
            chain.append(CertSpotter(http, api_key=(os.environ.get("CBOM_CT_CERTSPOTTER_KEY") or "").strip() or None))
        elif name == "crtsh":
            chain.append(CrtSh(http))
    return chain


def search_cached(provider: Any, domain: str, include_subdomains: bool, clock: Clock,
                  deadline: float | None = None, cache: AnswerCache | None = None) -> SearchResult:
    cache = CACHE if cache is None else cache
    key = (provider.name, domain, include_subdomains)
    hit = cache.get(key, clock.monotonic())
    if hit is not None:
        return SearchResult(hit.domain, hit.provider, hit.issuances, hit.pages, 0, hit.truncated, cached=True)
    result = provider.search(domain, include_subdomains, deadline=deadline)
    cache.put(key, result, clock.monotonic())
    return result


__all__ = ["AnswerCache", "CACHE", "CertSpotter", "Clock", "CrtSh", "CtError", "CtHttp", "Issuance", "MAX_PAGES",
           "MAX_RESULTS", "PROVIDERS", "SearchResult", "TokenBucket", "build_chain", "bucket", "provider_names",
           "search_cached"]
