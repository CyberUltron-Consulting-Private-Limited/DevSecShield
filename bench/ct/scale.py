#!/usr/bin/env python3
"""CT discovery at 1,000 domains per team: wall time, provider calls and backoff, on a fake provider.

The product's own code runs (ct_collect.collect_ct -> ct_providers.CertSpotter / CrtSh -> CtHttp, token bucket,
Retry-After handling, lease heartbeat, deadline) against an httpx transport that plays the provider on a SIMULATED
clock, so eight simulated hours take seconds.  The model comes from the recordings (fixtures/ct, capture-results.md):

* latency: the recorded Cert Spotter request durations (fixtures' request.json) plus 6 ms per row returned;
* 100 issuances per page; every page is one "full-domain" query of quota (recorded: x-ratelimit-remaining fell on
  the ``after`` pages too), and the product pages until an empty array (the documented rule), so every domain costs
  one more query than its full pages;
* quota: a token bucket per plan, refilled evenly over the hour (recorded: unauthenticated limit 10, the 11th query
  got 429 with Retry-After 348 s, i.e. one token per 360 s), answered with the recorded 429 body;
* plans (sslmate.com/ct_search_api): unauthenticated 10/h; Medium 100/h, 500/min, 10/s; Large 1,000/h, 2,000/min, 20/s;
* certificates per domain: 70 % 2-40, 25 % 40-150, 5 % 150-600 (seeded);
* crt.sh fallback: 5 requests/min, latency 0.6-25 s, half of the answers 502 (recorded reliability series).

    PYTHONPATH=. python bench/ct/scale.py [--domains 1000] [--out bench/ct/scale-results.json]
"""
from __future__ import annotations

import argparse
import json
import math
import random
import resource
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import httpx  # noqa: E402

from backend.utilities.cbom_sources import ct_collect as C  # noqa: E402
from backend.utilities.cbom_sources import ct_providers as P  # noqa: E402

FIX = REPO / "backend/tests/fixtures/ct"
PLANS = {
    "unauthenticated": {"hour": 10, "minute": 75, "second": 5},
    "medium": {"hour": 100, "minute": 500, "second": 10},
    "large": {"hour": 1000, "minute": 2000, "second": 20},
}
JOB_HOURS = 8.0  # the cloud worker's maximum run time for a collect job (jobs.MAX_RUNTIME)


class SimClock(P.Clock):
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(seconds, 0.0)


def recorded_latencies() -> list[float]:
    out = []
    for path in FIX.glob("certspotter_*/request.json"):
        ms = json.loads(path.read_text()).get("duration_ms")
        if isinstance(ms, int):
            out.append(ms / 1000)
    return sorted(out)


class FakeCertSpotter:
    """Plays api.certspotter.com: quota token bucket, pages of 100, recorded latency and 429 body."""

    def __init__(self, clock: SimClock, plan: dict, sizes: dict[str, int], rng: random.Random):
        self.clock, self.plan, self.sizes, self.rng = clock, plan, sizes, rng
        self.tokens, self.last = float(plan["hour"]), 0.0
        self.latency = recorded_latencies()
        self.status, self.headers, self.body = 429, {"content-type": "application/json"}, (FIX / "certspotter_fullquota_10" / "body").read_bytes()
        self.served = self.refused = 0

    def _refill(self) -> None:
        now = self.clock.t
        self.tokens = min(self.plan["hour"], self.tokens + (now - self.last) * self.plan["hour"] / 3600)
        self.last = now

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self._refill()
        if self.tokens < 1:
            self.refused += 1
            wait = math.ceil((1 - self.tokens) * 3600 / self.plan["hour"])
            self.clock.sleep(self.rng.choice(self.latency) * 0.5)
            return httpx.Response(429, headers={**self.headers, "retry-after": str(wait)}, content=self.body)
        self.tokens -= 1
        q = {k: v[-1] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}
        domain, after = q["domain"], int(q.get("after") or 0)
        total = self.sizes[domain]
        rows = [self._row(domain, i) for i in range(after, min(after + 100, total))]
        self.clock.sleep(self.rng.choice(self.latency) + 0.006 * len(rows))
        self.served += 1
        return httpx.Response(200, headers={"content-type": "application/json"}, content=json.dumps(rows).encode())

    @staticmethod
    def _row(domain: str, i: int) -> dict:
        import hashlib

        tbs = hashlib.sha256(f"{domain}|{i}".encode()).hexdigest()
        return {"id": str(i + 1), "tbs_sha256": tbs, "cert_sha256": tbs[::-1],
                "dns_names": [f"h{i}.{domain}", f"*.{domain}" if i % 25 == 0 else domain],
                "pubkey": {"type": "ecdsa", "curve": "P-256"} if i % 3 else {"type": "rsa", "bit_length": 2048},
                "issuer": {"friendly_name": "Let's Encrypt", "name": f"C=US, O=Let's Encrypt, CN=R{i % 4 + 10}"},
                "not_before": "2026-10-01T00:00:00Z", "not_after": "2026-12-30T00:00:00Z", "revoked": False}


class FakeCrtSh:
    def __init__(self, clock: SimClock, sizes: dict[str, int], rng: random.Random):
        self.clock, self.sizes, self.rng = clock, sizes, rng
        self.served = self.failed = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.clock.sleep(self.rng.uniform(0.6, 25.0))
        if self.rng.random() < 0.5:
            self.failed += 1
            return httpx.Response(502, content=b"<html><head><title>502 Bad Gateway</title></head></html>")
        q = parse_qs(urlsplit(str(request.url)).query)["q"][0]
        rows = [{"id": i, "issuer_ca_id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R10", "common_name": f"h{i}.{q}",
                 "name_value": f"h{i}.{q}", "not_before": "2026-10-01T00:00:00", "not_after": "2026-12-30T00:00:00",
                 "serial_number": f"{abs(hash((q, i))) & ((1 << 128) - 1):032x}"} for i in range(self.sizes[q])]
        self.served += 1
        return httpx.Response(200, content=json.dumps(rows).encode())


class Router:
    def __init__(self, cs: FakeCertSpotter, crt: FakeCrtSh | None):
        self.cs, self.crt, self.calls = cs, crt, 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return self.cs(request) if request.url.host == "api.certspotter.com" else self.crt(request)  # type: ignore[misc]


def sizes_for(n: int, rng: random.Random) -> dict[str, int]:
    out = {}
    for i in range(n):
        r = rng.random()
        out[f"d{i:04d}.example"] = rng.randint(2, 40) if r < 0.70 else rng.randint(40, 150) if r < 0.95 else rng.randint(150, 600)
    return out


def scenario(name: str, plan: str, n: int, *, fallback: bool = False, cache: P.AnswerCache | None = None,
             seed: int = 11) -> dict:
    rng = random.Random(seed)
    sizes = sizes_for(n, rng)
    clock = SimClock()
    cs = FakeCertSpotter(clock, PLANS[plan], sizes, rng)
    crt = FakeCrtSh(clock, sizes, rng) if fallback else None
    router = Router(cs, crt)
    http = P.CtHttp(transport=httpx.MockTransport(router), clock=clock, rng=random.Random(seed))
    p = PLANS[plan]
    chain = [P.CertSpotter(http, rate=P.TokenBucket(p["second"], p["minute"]))]
    if fallback:
        chain.append(P.CrtSh(http, rate=P.TokenBucket(1, 5)))
    beats = [0]

    def should_stop():
        beats[0] += 1
        return None

    emitted = [0, 0]

    def emit(asset):
        emitted[0 if asset["type"] == "certificate" else 1] += 1

    cpu0, real0 = time.process_time(), time.perf_counter()
    result = C.collect_ct({"domains": list(sizes), "include_subdomains": True}, "CT", emit, should_stop,
                          deadline=JOB_HOURS * 3600 - 120, chain=chain, http=http, clock=clock,
                          cache=cache if cache is not None else P.AnswerCache(0))
    cpu, real = time.process_time() - cpu0, time.perf_counter() - real0
    counts = result["counts"]
    return {"scenario": name, "plan": plan, "domains": n, "certificates_listed_by_fake": sum(sizes.values()),
            "simulated_wall_h": round(clock.t / 3600, 2), "domains_ok": counts["ok"] + counts["partial"],
            "domains_not_searched": counts["skipped"], "domains_failed": counts["failed"],
            "certificate_assets": emitted[0], "coverage_rows": emitted[1],
            "provider_requests": router.calls, "certspotter_served": cs.served, "certspotter_429": cs.refused,
            "crtsh_served": crt.served if crt else 0, "crtsh_502": crt.failed if crt else 0,
            "client_waited_h": round(http.waited_s / 3600, 2), "lease_heartbeats": beats[0],
            "process_cpu_s": round(cpu, 2), "process_real_s": round(real, 2)}


def der_parse_cost() -> dict:
    """Real CPU per certificate for the DER read the collector does on full-detail answers (recorded DERs)."""
    import base64

    rows = json.loads((FIX / "certspotter_zeroshield" / "body").read_bytes()) + json.loads((FIX / "certspotter_example" / "body").read_bytes())
    issuances = [P.CertSpotter(None, rate=P.TokenBucket(1, 1)).issuance(r) for r in rows]  # type: ignore[arg-type]
    assert all(i.der for i in issuances) and base64
    t0 = time.process_time()
    rounds = 50
    for _ in range(rounds):
        for iss in issuances:
            C.details(iss)
    per = (time.process_time() - t0) / (rounds * len(issuances))
    return {"certificates": len(issuances) * rounds, "cpu_ms_per_certificate": round(per * 1000, 3)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", type=int, default=1000)
    parser.add_argument("--out", type=Path, default=Path(__file__).with_name("scale-results.json"))
    args = parser.parse_args()
    n = args.domains
    import os

    results = [scenario("large plan", "large", n), scenario("medium plan", "medium", n),
               scenario("unauthenticated", "unauthenticated", n),
               scenario("unauthenticated + crt.sh fallback", "unauthenticated", n, fallback=True)]
    saved = os.environ.get("CBOM_CT_WAIT_BUDGET_S")
    os.environ["CBOM_CT_WAIT_BUDGET_S"] = "1000000"  # no budget: the job waits up to its 8 h maximum
    results.append(scenario("medium plan, no wait budget (8 h job)", "medium", n))
    if saved is None:
        os.environ.pop("CBOM_CT_WAIT_BUDGET_S")
    else:
        os.environ["CBOM_CT_WAIT_BUDGET_S"] = saved
    warm = P.AnswerCache(3600)
    scenario("large plan (fills the cache)", "large", n, cache=warm)
    results.append(scenario("large plan, second team within the cache TTL", "large", n, cache=warm))
    out = {"model": __doc__.split("\n\n")[1], "results": results, "der_parse": der_parse_cost(),
           "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)}
    args.out.write_text(json.dumps(out, indent=1) + "\n")
    cols = ["scenario", "simulated_wall_h", "domains_ok", "domains_not_searched", "certificate_assets",
            "provider_requests", "certspotter_429", "crtsh_502", "client_waited_h", "process_cpu_s"]
    print("| " + " | ".join(cols) + " |")
    print("|" + "---|" * len(cols))
    for r in results:
        print("| " + " | ".join(str(r[c]) for c in cols) + " |")
    print(json.dumps({"der_parse": out["der_parse"], "max_rss_mb": out["max_rss_mb"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
