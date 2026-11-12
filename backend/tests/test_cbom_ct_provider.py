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

    def key(self, request: httpx.Request) -> tuple:
        url = urlsplit(str(request.url))
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if url.hostname == "api.certspotter.com":
            return ("certspotter", q.get("domain"), q.get("include_subdomains"), q.get("after"))
        return ("crtsh", q.get("q"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        key = self.key(request)
        target = self.override.get(key) or self.override.get(key[:2])
        if callable(target):
            return target(request)
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
        return httpx.Response(status, headers=headers, content=body)

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
    # 25 rows < the page size of 100: the empty next page is not asked for (one query of quota, not two)
    assert result.pages == 1 and result.requests == 1 and len(replay.calls) == 1
    query = parse_qs(urlsplit(replay.calls[0]).query)
    assert query["include_subdomains"] == ["true"] and query["match_wildcards"] == ["true"]
    assert sorted(query["expand"]) == sorted(P.CERTSPOTTER_EXPAND)
    first, raw = result.issuances[0], rows[0]
    assert first.tbs_sha256 == raw["tbs_sha256"] and first.cert_sha256 == raw["cert_sha256"]
    assert first.issuer_name == "Let's Encrypt" and first.issuer_dn == raw["issuer"]["name"]
    assert first.dns_names == raw["dns_names"] and first.revoked is False and first.der is not None


def test_certspotter_pages_until_a_short_or_empty_page():
    replay = Replay()
    result = P.CertSpotter(http(replay), rate=fast()).search("google.com", True)
    assert result.pages == 3 and len(result.issuances) == 200  # 100 + 100 + the recorded empty page
    afters = [parse_qs(urlsplit(u).query).get("after", [None])[0] for u in replay.calls]
    assert afters == [None, _last_id("certspotter_paging_p1"), _last_id("certspotter_paging_p2")]


def test_certspotter_documented_rule_when_the_page_size_hint_is_off(monkeypatch):
    monkeypatch.setenv("CBOM_CT_CERTSPOTTER_PAGE_SIZE", "0")
    replay = Replay({("certspotter", "zeroshield.ai", "true", _last_id("certspotter_zeroshield")): "certspotter_zeroshield_after"})
    result = P.CertSpotter(http(replay), rate=fast()).search("zeroshield.ai", True)
    assert result.pages == 2 and len(result.issuances) == 25


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
    assert len(result.issuances) == 25 and clock.slept == [348.0] and client.rate_limited == 1


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
    assert len(replay.calls) == 1 and second.cached and second.requests == 0 and len(second.issuances) == len(first.issuances)
    clock.t += 3601
    P.search_cached(provider, "zeroshield.ai", True, clock, cache=cache)
    assert len(replay.calls) == 2


def test_provider_chain_from_the_environment(monkeypatch):
    monkeypatch.delenv("CBOM_CT_PROVIDER", raising=False)
    assert P.provider_names() == ["certspotter", "crtsh"]
    monkeypatch.setenv("CBOM_CT_PROVIDER", "crtsh, nonsense")
    assert P.provider_names() == ["crtsh"]
    monkeypatch.setenv("CBOM_CT_CERTSPOTTER_KEY", "zs-test-key-not-real")
    monkeypatch.setenv("CBOM_CT_PROVIDER", "certspotter")
    chain = P.build_chain(http(Replay()))
    assert [p.name for p in chain] == ["certspotter"] and chain[0].api_key == "zs-test-key-not-real"
