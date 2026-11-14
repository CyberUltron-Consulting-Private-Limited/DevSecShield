"""CB-03 bench: what the build-identity wrapper (X-ZS-Build + X-ZS-Request-Id, backend/utilities/build_info.py) adds
to a request. Calls a trivial ASGI app directly, with and without the wrapper, so the number is the wrapper's own cost
(no network, no FastAPI routing). Prints p50/p95/p99 in microseconds for both and the p95 difference.

    cd backend && PYTHONPATH=.. .venv/bin/python ../bench/build_identity_header.py [requests]
Acceptance (DEVILS-ADVOCATE CB-03 exit S): the header adds < 1 ms p95.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time

from backend.utilities.build_info import BuildIdentityMiddleware

os.environ.setdefault("DSS_BUILD_SHA", "83b570bed86212e3afed395be942df57b8dc3df5")


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": b"{}"})


async def receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def send(_message):
    return None


def scope(i: int) -> dict:
    headers = [(b"host", b"api.dss.test")]
    if i % 2:  # half the requests bring their own id (echoed), half get a new one
        headers.append((b"x-zs-request-id", f"bench-request-{i:08d}".encode()))
    return {"type": "http", "method": "GET", "path": "/health", "headers": headers}


async def measure(target, n: int) -> list[float]:
    out = []
    for i in range(n):
        s = scope(i)
        t0 = time.perf_counter_ns()
        await target(s, receive, send)
        out.append((time.perf_counter_ns() - t0) / 1000)
    return out


def pct(values: list[float], p: float) -> float:
    return statistics.quantiles(values, n=100)[int(p) - 1]


async def main(n: int) -> None:
    wrapped = BuildIdentityMiddleware(app)
    await measure(app, 2000)  # warm-up
    await measure(wrapped, 2000)
    bare, ident = await measure(app, n), await measure(wrapped, n)
    for name, values in (("bare", bare), ("with identity", ident)):
        print(f"{name:14s} n={n} p50={pct(values, 50):7.2f} us p95={pct(values, 95):7.2f} us p99={pct(values, 99):7.2f} us")
    delta = pct(ident, 95) - pct(bare, 95)
    print(f"p95 added by the wrapper: {delta:.2f} us ({delta / 1000:.4f} ms); limit 1 ms: {'PASS' if delta < 1000 else 'FAIL'}")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 50_000))
