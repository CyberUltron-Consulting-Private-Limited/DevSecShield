"""CT discovery providers on recorded answers (fixtures/ct, recorded on GitHub runners; SOURCE.md).

Cert Spotter and crt.sh clients: one page and several pages, an empty answer, an IDN, a wildcard host, provider
errors (400 bad_query, 401 bad_credentials, 502 HTML), the real rate-limit answer (429, Retry-After 348), a timeout,
and malformed JSON (a recorded body cut short).  Domain normalisation (punycode, wildcards, refusals) and the query
set are here too.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_ct_provider.py -q
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.utilities.cbom_sources import ct_domains as D  # noqa: E402
from backend.utilities.cbom_sources import ct_providers as P  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "ct"


# ----------------------------------------------------------------------------- recorded replay (shared by CT tests)
def recorded(case: str) -> tuple[int, dict[str, str], bytes]:
    folder = FIX / case
    body = gzip.decompress((folder / "body.gz").read_bytes()) if (folder / "body.gz").exists() else (folder / "body").read_bytes()
    status = int((folder / "status").read_text().strip())
    headers = json.loads((folder / "headers.json").read_text())
    for drop in ("transfer-encoding", "content-length", "connection", "content-encoding"):
        headers.pop(drop, None)
    return status, headers, body


def oracle(case: str) -> list[dict]:
    return json.loads((FIX / case / "oracle.json").read_text())["rows"]


def _last_id(case: str) -> str:
    return json.loads(recorded(case)[2])[-1]["id"]


# Cert Spotter: (domain, include_subdomains, after) -> recorded case
CS_ROUTES = {
    ("zeroshield.ai", "true", None): "certspotter_zeroshield",
    ("example.com", "true", None): "certspotter_example",
    ("xn--bcher-kva.de", "true", None): "certspotter_idn_buecher",
    ("xn--mnchen-3ya.de", "true", None): "certspotter_idn_muenchen",
    ("ct-proof-host.zeroshield.ai", "false", None): "certspotter_wildcard_host",
    ("zs-ct-empty-proof.example.com", "false", None): "certspotter_empty",
    ("zs-ct-empty-proof.example.com", "true", None): "certspotter_empty",
    ("google.com", "true", None): "certspotter_paging_p1",
}
# crt.sh: q -> recorded case (zeroshield.ai answered by the q=%.zeroshield.ai&exclude=expired recording)
CRT_ROUTES = {"zeroshield.ai": "crtsh_zeroshield_unexpired", "example.com": "crtsh_example",
              "xn--bcher-kva.de": "crtsh_idn_buecher", "zs-ct-empty-proof.example.com": "crtsh_empty"}


class Replay:
    """An httpx transport answering from the recordings; ``override`` maps a key to a case or a callable."""

    def __init__(self, override: dict | None = None):
        self.calls: list[str] = []
        self.override = dict(override or {})
        self.last_id: dict[str, str] = {}  # domain -> the last id of the last Cert Spotter page answered

    def key(self, request: httpx.Request) -> tuple:
        url = urlsplit(str(request.url))
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if url.hostname == "api.certspotter.com":
            return ("certspotter", q.get("domain"), q.get("include_subdomains"), q.get("after"))
        return ("crtsh", q.get("q"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        key = self.key(request)
        target = self.override.get(key)
        paging = (_last_id("certspotter_paging_p1"), _last_id("certspotter_paging_p2"))  # google.com: its own pages
        if (target is None and key[0] == "certspotter" and key[3] is not None and key[3] not in paging
                and key[3] == self.last_id.get(key[1])):
            target = "certspotter_zeroshield_after"  # the page after the last one: the recorded empty array
        target = target or self.override.get(key[:2])
        if callable(target):
            return self._seen(key, target(request))
        if target is None:
            if key[0] == "certspotter":
                if key[3] == _last_id("certspotter_paging_p1"):
                    target = "certspotter_paging_p2"
                elif key[3] == _last_id("certspotter_paging_p2"):
                    target = "certspotter_zeroshield_after"  # a recorded empty page (the end of any listing)
                else:
                    target = CS_ROUTES.get(key[1:4])
            else:
                target = CRT_ROUTES.get(key[1])
        if target is None:
            raise AssertionError(f"no recording for {key}")
        status, headers, body = recorded(target)
        return self._seen(key, httpx.Response(status, headers=headers, content=body))

    def _seen(self, key: tuple, response: httpx.Response) -> httpx.Response:
        if key[0] == "certspotter" and response.status_code == 200:
            try:
                rows = json.loads(response.read())
            except ValueError:
                rows = None
            if isinstance(rows, list) and rows and isinstance(rows[-1], dict) and rows[-1].get("id"):
                self.last_id[key[1]] = rows[-1]["id"]
        return response

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


class FakeClock(P.Clock):
    def __init__(self, start: float = 1000.0):
        self.t = start
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += max(seconds, 0)


def http(replay: Replay, clock: FakeClock | None = None) -> P.CtHttp:
    import random

    return P.CtHttp(transport=replay.transport(), clock=clock or FakeClock(), rng=random.Random(7))


def fast() -> P.TokenBucket:
    return P.TokenBucket(1000, 100000)


# ----------------------------------------------------------------------------- domains
@pytest.mark.parametrize("raw,name,wild", [
    ("Example.COM.", "example.com", False), ("*.zeroshield.ai", "zeroshield.ai", True),
    ("bücher.de", "xn--bcher-kva.de", False), ("München.DE", "xn--mnchen-3ya.de", False),
    ("faß.de", "xn--fa-hia.de", False), ("xn--bcher-kva.de", "xn--bcher-kva.de", False),
])
def test_names_are_stored_as_a_labels(raw, name, wild):
    assert D.normalise(raw) == (name, wild)


@pytest.mark.parametrize("raw", ["10.0.0.1", "[2001:db8::1]", "com", "a..b", "https://x.com", "x‍.com",
                                 "xn--zz.com", "-bad.com", "a" * 64 + ".com", "example.123", "user@example.com", ""])
def test_names_that_are_not_domains_are_refused(raw):
    with pytest.raises(D.DomainError):
        D.normalise(raw)


def test_the_list_limit_and_the_query_set():
    assert D.normalise_list(["a.example", "A.example.", "*.a.example"]) == ["a.example"]
    with pytest.raises(D.DomainError, match="at most 1000"):
        D.normalise_list([f"d{i}.example" for i in range(1001)])
    names = ["www.example.com", "example.com", "a.b.example.com", "example.org", "shop.example.org"]
    assert D.query_set(names, True) == ["example.com", "example.org"]
    assert D.query_set(names, False) == sorted(names)
    assert D.display("xn--bcher-kva.de") == "bücher.de"


# ----------------------------------------------------------------------------- Cert Spotter
def test_certspotter_one_page_matches_the_recording_row_by_row():
    replay = Replay()
    result = P.CertSpotter(http(replay), rate=fast()).search("zeroshield.ai", True)
    rows = json.loads(recorded("certspotter_zeroshield")[2])
    assert [i.provider_id for i in result.issuances] == [r["id"] for r in rows]
    # Cert Spotter's documented rule: page until an empty array, even after a page of 25 (review 5901912537 #1)
    assert result.pages == 2 and result.requests == 2 and len(replay.calls) == 2
    assert parse_qs(urlsplit(replay.calls[1]).query)["after"] == [rows[-1]["id"]]
    query = parse_qs(urlsplit(replay.calls[0]).query)
    assert query["include_subdomains"] == ["true"] and query["match_wildcards"] == ["true"]
    assert sorted(query["expand"]) == sorted(P.CERTSPOTTER_EXPAND)
    first, raw = result.issuances[0], rows[0]
    assert first.tbs_sha256 == raw["tbs_sha256"] and first.cert_sha256 == raw["cert_sha256"]
    assert first.issuer_name == "Let's Encrypt" and first.issuer_dn == raw["issuer"]["name"]
    assert first.dns_names == raw["dns_names"] and first.revoked is False and first.der is not None


def test_certspotter_pages_until_an_empty_page():
    replay = Replay()
    result = P.CertSpotter(http(replay), rate=fast()).search("google.com", True)
    assert result.pages == 3 and len(result.issuances) == 200  # 100 + 100 + the recorded empty page
    afters = [parse_qs(urlsplit(u).query).get("after", [None])[0] for u in replay.calls]
    assert afters == [None, _last_id("certspotter_paging_p1"), _last_id("certspotter_paging_p2")]


def test_certspotter_short_pages_are_never_taken_as_the_last():
    """Review 5901912537 #1: the recorded google.com listing (200 issuances) served in pages of 60, as a keyed plan or a
    size limit could: every issuance is read, ending on the empty page (the old rule stopped at 60, as "ok")."""
    rows = json.loads(recorded("certspotter_paging_p1")[2]) + json.loads(recorded("certspotter_paging_p2")[2])
    afters = []

    def pages_of_60(request):
        after = parse_qs(urlsplit(str(request.url)).query).get("after", [None])[0]
        afters.append(after)
        start = 0 if after is None else next(i for i, r in enumerate(rows) if r["id"] == after) + 1
        return httpx.Response(200, content=json.dumps(rows[start:start + 60]).encode())

    client = P.CtHttp(transport=httpx.MockTransport(pages_of_60), clock=FakeClock())
    result = P.CertSpotter(client, rate=fast()).search("google.com", True)
    assert [i.provider_id for i in result.issuances] == [r["id"] for r in rows] and not result.truncated
    assert result.pages == 5 and afters == [None, rows[59]["id"], rows[119]["id"], rows[179]["id"], rows[199]["id"]]


def test_certspotter_result_cap_marks_the_answer_truncated(monkeypatch):
    monkeypatch.setattr(P, "MAX_RESULTS", 150)
    result = P.CertSpotter(http(Replay()), rate=fast()).search("google.com", True)
    assert result.truncated and len(result.issuances) == 150


def test_certspotter_empty_idn_and_wildcard_host():
    sp = P.CertSpotter(http(Replay()), rate=fast())
    assert sp.search("zs-ct-empty-proof.example.com", False).issuances == []
    idn = sp.search("xn--bcher-kva.de", True)
    assert idn.issuances and all(n.isascii() for i in idn.issuances for n in i.dns_names)
    assert any("xn--bcher-kva.de" in n for i in idn.issuances for n in i.dns_names)
    wild = sp.search("ct-proof-host.zeroshield.ai", False)
    assert wild.issuances and all("*.zeroshield.ai" in i.dns_names for i in wild.issuances)


def test_certspotter_bad_query_is_refused_without_retry():
    replay = Replay({("certspotter", "example.com"): "certspotter_error_bad_value"})
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(http(replay), rate=fast()).search("example.com", True)
    assert err.value.kind == "refused" and "include_subdomains" in str(err.value) and len(replay.calls) == 1


def test_certspotter_bad_key_is_an_auth_error_and_the_key_is_never_shown():
    seen = []

    def answer(request):
        seen.append(request.headers.get("authorization"))
        status, headers, body = recorded("certspotter_error_bad_credentials")
        return httpx.Response(status, headers=headers, content=body)

    replay = Replay({("certspotter", "example.com"): answer})
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(http(replay), api_key="zs-test-key-not-real", rate=fast()).search("example.com", True)
    assert err.value.kind == "auth" and seen == ["Bearer zs-test-key-not-real"] and "zs-test-key" not in str(err.value)


def test_the_recorded_429_is_waited_for_then_retried():
    status, headers, body = recorded("certspotter_fullquota_10")
    assert status == 429 and headers["retry-after"] == "348"
    answers = [httpx.Response(status, headers=headers, content=body)]
    replay = Replay({("certspotter", "zeroshield.ai"): lambda req: answers.pop(0) if answers else
                     httpx.Response(200, content=recorded("certspotter_zeroshield")[2])})
    clock = FakeClock()
    client = http(replay, clock)
    result = P.CertSpotter(client, rate=fast()).search("zeroshield.ai", True)
    assert len(result.issuances) == 25 and sum(clock.slept) == 348.0 and client.rate_limited == 1
    assert max(clock.slept) <= P.HEARTBEAT_S  # waited in slices: the job's lease is renewed between them


def test_a_long_wait_renews_the_lease_and_stops_when_told():
    status, headers, body = recorded("certspotter_fullquota_10")
    replay = Replay({("certspotter", "zeroshield.ai"): lambda req: httpx.Response(status, headers=headers, content=body)})
    clock = FakeClock()
    client = http(replay, clock)
    beats = []
    client.heartbeat = lambda: (beats.append(clock.t), "Stopped at the maximum run time" if len(beats) >= 3 else None)[1]
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(client, rate=fast()).search("zeroshield.ai", True)
    assert err.value.kind == "stopped" and "maximum run time" in str(err.value)
    assert len(beats) == 3 and clock.slept == [P.HEARTBEAT_S] * 3 and len(replay.calls) == 1


def test_a_429_past_the_deadline_or_the_wait_cap_is_not_waited_for():
    status, headers, body = recorded("certspotter_fullquota_10")
    replay = Replay({("certspotter", "zeroshield.ai"): lambda req: httpx.Response(status, headers=headers, content=body)})
    clock = FakeClock()
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(http(replay, clock), rate=fast()).search("zeroshield.ai", True, deadline=clock.t + 100)
    assert err.value.kind == "rate_limited" and err.value.retry_after == 348.0 and clock.slept == []
    long_wait = {**headers, "retry-after": "3600"}
    replay2 = Replay({("certspotter", "zeroshield.ai"): lambda req: httpx.Response(429, headers=long_wait, content=body)})
    with pytest.raises(P.CtError) as err2:
        P.CertSpotter(http(replay2), rate=fast()).search("zeroshield.ai", True)
    assert err2.value.kind == "rate_limited" and err2.value.retry_after == 3600.0


def test_retry_after_on_a_200_is_a_polling_hint_not_a_wait():
    status, headers, _body = recorded("certspotter_empty")
    assert status == 200 and headers.get("retry-after") == "3600"
    clock = FakeClock()
    assert P.CertSpotter(http(Replay(), clock), rate=fast()).search("zs-ct-empty-proof.example.com", False).issuances == []
    assert clock.slept == []


def test_malformed_json_is_retried_then_reported():
    """Derived: the recorded zeroshield.ai body cut at byte 4096 (a body that ends early, as crt.sh's sometimes do)."""
    cut = recorded("certspotter_zeroshield")[2][:4096]
    replay = Replay({("certspotter", "zeroshield.ai"): lambda req: httpx.Response(200, content=cut)})
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(http(replay), rate=fast()).search("zeroshield.ai", True)
    assert err.value.kind == "malformed" and len(replay.calls) == 1


def test_a_json_object_or_a_row_without_id_is_malformed():
    for body in (b'{"code":"x"}', b'[{"tbs_sha256":"ab"}]'):
        replay = Replay({("certspotter", "zeroshield.ai"): lambda req, b=body: httpx.Response(200, content=b)})
        with pytest.raises(P.CtError) as err:
            P.CertSpotter(http(replay), rate=fast()).search("zeroshield.ai", True)
        assert err.value.kind == "malformed"


# ----------------------------------------------------------------------------- crt.sh
def test_crtsh_rows_are_deduplicated_and_filtered_to_the_domain():
    replay = Replay()
    result = P.CrtSh(http(replay), rate=fast()).search("zeroshield.ai", True)
    want = oracle("crtsh_zeroshield_unexpired")  # one row per (serial, issuer CA), read without product code
    assert sorted(i.serial for i in result.issuances) == sorted(r["serial"] for r in want)
    assert len(result.issuances) == 9 and all(i.detail == "summary" and i.der is None for i in result.issuances)
    assert all(i.not_after.endswith("Z") for i in result.issuances)
    query = parse_qs(urlsplit(replay.calls[0]).query)
    assert query == {"q": ["zeroshield.ai"], "output": ["json"], "exclude": ["expired"], "deduplicate": ["Y"]}
    assert len(replay.calls) == 1


def test_crtsh_precertificate_and_certificate_rows_collapse():
    replay = Replay({("crtsh", "zeroshield.ai"): "crtsh_zeroshield_subdomains"})  # 123 rows, no deduplicate
    result = P.CrtSh(http(replay), rate=fast()).search("zeroshield.ai", True)
    assert len(result.issuances) == len(oracle("crtsh_zeroshield_subdomains")) == 68


def test_crtsh_empty_502_and_timeout():
    sh = P.CrtSh(http(Replay()), rate=fast())
    assert sh.search("zs-ct-empty-proof.example.com", True).issuances == []
    replay = Replay({("crtsh", "example.com"): "crtsh_reliability_00"})  # nginx 502 HTML
    clock = FakeClock()
    with pytest.raises(P.CtError) as err:
        P.CrtSh(http(replay, clock), rate=fast()).search("example.com", True)
    assert err.value.kind == "unavailable" and "502" in str(err.value) and len(replay.calls) == 3 and len(clock.slept) == 2

    def timeout(request):
        raise httpx.ReadTimeout("read timed out", request=request)

    replay = Replay({("crtsh", "example.com"): timeout})
    with pytest.raises(P.CtError) as err:
        P.CrtSh(http(replay), rate=fast()).search("example.com", True)
    assert err.value.kind == "unavailable" and "did not answer" in str(err.value) and len(replay.calls) == 3


def test_only_the_fixed_provider_hosts_are_contacted():
    client = http(Replay())
    with pytest.raises(P.CtError, match="not a Certificate Transparency provider"):
        client.get("https://example.com/v1/issuances", bucket_=fast())
    with pytest.raises(P.CtError):
        client.get("http://crt.sh/?q=x", bucket_=fast())


# ----------------------------------------------------------------------------- rate, cache, chain
def test_token_bucket_spaces_requests_per_minute():
    bucket = P.TokenBucket(5, 5)  # crt.sh-like: five a minute
    clock = FakeClock(0)
    waits = [bucket.take(clock) for _ in range(7)]
    assert waits[:5] == [0, 0, 0, 0, 0] and all(w > 0 for w in waits[5:]) and 23 < clock.t < 25


def test_cache_answers_a_second_search_without_a_request():
    replay = Replay()
    cache = P.AnswerCache(3600)
    clock = FakeClock()
    provider = P.CertSpotter(http(replay, clock), rate=fast())
    first = P.search_cached(provider, "zeroshield.ai", True, clock, cache=cache)
    second = P.search_cached(provider, "zeroshield.ai", True, clock, cache=cache)
    assert len(replay.calls) == 2  # the page and the empty page after it, once
    assert second.cached and second.requests == 0 and len(second.issuances) == len(first.issuances)
    clock.t += 3601
    P.search_cached(provider, "zeroshield.ai", True, clock, cache=cache)
    assert len(replay.calls) == 4


def test_provider_chain_from_the_environment(monkeypatch):
    monkeypatch.delenv("CBOM_CT_PROVIDER", raising=False)
    assert P.provider_names() == ["certspotter", "crtsh"]
    monkeypatch.setenv("CBOM_CT_PROVIDER", "crtsh, nonsense")
    assert P.provider_names() == ["crtsh"]
    monkeypatch.setenv("CBOM_CT_CERTSPOTTER_KEY", "zs-test-key-not-real")
    monkeypatch.setenv("CBOM_CT_PROVIDER", "certspotter")
    chain = P.build_chain(http(Replay()))
    assert [p.name for p in chain] == ["certspotter"] and chain[0].api_key == "zs-test-key-not-real"


# ----------------------------------------------------------------------------- review 5901912537
def _google_issuances() -> list:
    rows = json.loads(recorded("certspotter_paging_p1")[2]) + json.loads(recorded("certspotter_paging_p2")[2])
    sp = P.CertSpotter(None, rate=fast())  # type: ignore[arg-type]
    return [sp.issuance(r) for r in rows]


def test_the_answer_size_estimate_is_not_below_what_python_holds():
    """#2: answer_bytes, the cache's measure, against tracemalloc on the recorded google.com pages (200 issuances)."""
    import gc
    import tracemalloc

    raw = [recorded("certspotter_paging_p1")[2], recorded("certspotter_paging_p2")[2]]
    sp = P.CertSpotter(None, rate=fast())  # type: ignore[arg-type]
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    rows = json.loads(raw[0]) + json.loads(raw[1])
    issuances = [sp.issuance(r) for r in rows]
    del rows  # what a cached answer keeps: the issuances, their names and DER, without the parsed JSON
    gc.collect()
    held = sum(s.size_diff for s in tracemalloc.take_snapshot().compare_to(before, "filename"))
    tracemalloc.stop()
    estimate = P.answer_bytes(P.SearchResult("google.com", "certspotter", issuances))
    assert len(issuances) == 200 and held > 200 * 1000 and estimate >= held, (estimate, held)
    assert estimate < 2 * held  # and not so high that the cache holds far less than its budget


def test_the_answer_cache_is_bounded_by_bytes_least_recently_used_first(monkeypatch):
    """#2: SPEC section 2's 64 MB cap is in bytes, not entries; an answer above the per-entry cap is not cached."""
    issuances = _google_issuances()
    one = P.SearchResult("a.example", "certspotter", issuances[:50])
    size = P.answer_bytes(one)
    cache = P.AnswerCache(3600, max_bytes=3 * size + 10, max_entry_bytes=4 * size)
    for name in ("a", "b", "c"):
        cache.put(("certspotter", f"{name}.example", True), one, 0)
    assert len(cache) == 3 and cache.bytes == 3 * size
    assert cache.get(("certspotter", "a.example", True), 1) is one  # a is now the most recently used
    cache.put(("certspotter", "d.example", True), one, 2)
    assert cache.get(("certspotter", "b.example", True), 3) is None  # b was the least recently used: evicted
    assert cache.get(("certspotter", "a.example", True), 3) is one and cache.bytes <= 3 * size + 10
    big = P.SearchResult("big.example", "certspotter", issuances)  # 200 issuances: above max_entry_bytes
    cache.put(("certspotter", "big.example", True), big, 4)
    assert cache.get(("certspotter", "big.example", True), 5) is None and len(cache) == 3
    assert P.CACHE.max_bytes == 64 * 2 ** 20 and P.CACHE.max_entry_bytes == 8 * 2 ** 20
    monkeypatch.setenv("CBOM_CT_CACHE_MAX_BYTES", "1048576")
    assert P._cache_max_bytes() == 2 ** 20


def test_an_answer_that_drips_past_90_seconds_is_cut_and_retried():
    """#3: the httpx timeout is per read; the whole answer gets REQUEST_S (90 s), however slowly it arrives."""
    clock = FakeClock()
    body = recorded("certspotter_zeroshield")[2]

    def drip(_request):
        def chunks():
            for i in range(0, len(body), 4096):
                clock.t += 10.0  # each read well under the 90 s read timeout
                yield body[i:i + 4096]
        return httpx.Response(200, content=chunks())

    calls = []
    client = P.CtHttp(transport=httpx.MockTransport(lambda r: (calls.append(1), drip(r))[1]), clock=clock)
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(client, rate=fast()).search("zeroshield.ai", True)
    assert err.value.kind == "unavailable" and "took more than 90 s" in str(err.value)
    assert len(calls) == 1 + P.MAX_RETRIES  # retried like a timeout


def test_the_wait_budget_holds_inside_a_single_429_wait():
    """#8: a Retry-After the client's wait budget cannot cover is not waited for (it used to wait up to 1 h)."""
    status, headers, body = recorded("certspotter_fullquota_10")
    replay = Replay({("certspotter", "zeroshield.ai"): lambda req: httpx.Response(status, headers=headers, content=body)})
    clock = FakeClock()
    client = http(replay, clock)
    client.wait_budget = 300.0
    with pytest.raises(P.CtError) as err:
        P.CertSpotter(client, rate=fast()).search("zeroshield.ai", True)
    assert err.value.kind == "rate_limited" and clock.slept == [] and len(replay.calls) == 1


def test_crtsh_keeps_a_wildcard_that_covers_the_searched_host():
    """#5: for www-level names crt.sh's rows name *.parent; Cert Spotter (match_wildcards) returns them, so must crt.sh."""
    rows = [{"id": 1, "issuer_ca_id": 7, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "*.zeroshield.ai",
             "name_value": "*.zeroshield.ai\nzeroshield.ai", "not_before": "2026-10-01T00:00:00",
             "not_after": "2026-12-30T00:00:00", "serial_number": "0a1b"},
            {"id": 2, "issuer_ca_id": 7, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "*.other.zeroshield.ai",
             "name_value": "*.other.zeroshield.ai", "not_before": "2026-10-01T00:00:00",
             "not_after": "2026-12-30T00:00:00", "serial_number": "0a1c"},
            {"id": 3, "issuer_ca_id": 7, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "ct-proof-host.zeroshield.ai",
             "name_value": "ct-proof-host.zeroshield.ai", "not_before": "2026-10-01T00:00:00",
             "not_after": "2026-12-30T00:00:00", "serial_number": "0a1d"},
            {"id": 4, "issuer_ca_id": 7, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "*.ai",
             "name_value": "*.ai", "not_before": "2026-10-01T00:00:00", "not_after": "2026-12-30T00:00:00",
             "serial_number": "0a1e"}]
    replay = Replay({("crtsh", "ct-proof-host.zeroshield.ai"): lambda req: httpx.Response(200, content=json.dumps(rows).encode())})
    result = P.CrtSh(http(replay), rate=fast()).search("ct-proof-host.zeroshield.ai", False)
    assert sorted(i.serial for i in result.issuances) == ["a1b", "a1d"]  # *.zeroshield.ai and the host itself
    wildcard_host = {r["serial"] for r in oracle("certspotter_wildcard_host")}
    assert wildcard_host and all(len(r["dns_names"]) and "*.zeroshield.ai" in r["dns_names"]
                                 for r in oracle("certspotter_wildcard_host"))  # what Cert Spotter returns there


def test_rate_buckets_share_the_egress_address(monkeypatch):
    """#4: the providers limit per address; N workers behind one address each get 1/N of the rate."""
    monkeypatch.delenv("CBOM_CT_RATE_CRTSH", raising=False)
    monkeypatch.delenv("CBOM_CT_WORKERS_PER_EGRESS", raising=False)
    assert P._rate("crtsh", (1.0, 5.0)) == (1.0, 5.0)
    monkeypatch.setenv("CBOM_CT_WORKERS_PER_EGRESS", "2")
    assert P._rate("crtsh", (1.0, 5.0)) == (0.5, 2.5)
    monkeypatch.setenv("CBOM_CT_RATE_CERTSPOTTER", "10/500")
    assert P._rate("certspotter", (5.0, 75.0)) == (5.0, 250.0)
    monkeypatch.setenv("CBOM_CT_WORKERS_PER_EGRESS", "nonsense")
    assert P.workers_per_egress() == 1


def test_crtsh_has_one_request_in_flight_per_process():
    import threading
    import time as _time

    active, peak = [0], [0]
    lock = threading.Lock()

    def slow(_request):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        _time.sleep(0.05)
        with lock:
            active[0] -= 1
        return httpx.Response(200, content=b"[]")

    client = P.CtHttp(transport=httpx.MockTransport(slow))
    threads = [threading.Thread(target=P.CrtSh(client, rate=fast()).search, args=(f"d{i}.example", True)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak[0] == 1
