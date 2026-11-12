"""Observability and admission for the scan-node API (F1.1, devil's-advocate review section 4 and D5).

Everything here is in memory, per worker process, and never touches the database on the request path:

* ``serve`` (called by ``node_auth.NodeDeploymentHeader`` for every ``/cbom/node/*`` request):
  ``X-ZS-Deployment``, ``X-ZS-Request-Id`` (echoed when sent, else generated), ``Server-Timing: app;dur=<ASGI entry to
  response start>, tp;dur=<node threadpool wait>, pool;dur=<connection checkout incl. pre-ping>``, per-kind counters
  (count, status class, fixed latency buckets), in-flight maximum, the slow-request line (``CBOM_NODE_SLOW_MS``), and
  tiered admission: a claim or an enrollment arriving while ``CBOM_NODE_MAX_INFLIGHT`` node requests are in flight on
  this worker is answered 429 with a jittered ``Retry-After`` (5-15 s) before its body is read.  Heartbeats, results
  and assets are never shed.
* ``to_node_thread``: the routes' synchronous bodies run on a dedicated thread limiter sized to the connection pool
  (DA E2), not the process-wide anyio limiter the other 56 call sites share; its waiting time is ``tp``.
* ``delivered``: after a route's work, whether the client is still there (``node response undelivered`` line and
  counter; for a claim the caller hands the job straight back, DA D3).
* A sampler task per worker: every second the pool gauges, the thread limiter's queue and the event-loop lag; every
  60 s one ``cbom node stats`` line (see ``_line``).
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import random
import re
import threading
import time
import uuid
from typing import Any

import anyio
import anyio.to_thread

from backend.utilities import request_timing as RT
from backend.utilities.cbom_sources import limits as LIM
from backend.utilities.cbom_sources.common import log

KINDS = ("heartbeat", "claim", "result", "assets", "enroll", "other")
BUCKETS_MS = (25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000)
STATS_EVERY_S = 60.0
SAMPLE_EVERY_S = 1.0
LAG_PROBE_S = 0.25
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
MAX_SAMPLES = 200_000


def kind_of(path: str) -> str:
    if path.endswith("/heartbeat"):
        return "heartbeat"
    if path.endswith("/jobs/claim"):
        return "claim"
    if path.endswith("/result"):
        return "result"
    if path.endswith("/assets"):
        return "assets"
    if path.endswith("/enroll"):
        return "enroll"
    return "other"


class Stats:
    """Per-process counters.  ``window`` resets with every stats line; ``totals`` never reset (tests, the bench)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.inflight = 0
        self.totals: dict[str, int] = {}
        self._reset()

    def _reset(self) -> None:
        self.samples: dict[str, list[float]] = {k: [] for k in KINDS}
        self.classes: dict[str, dict[str, int]] = {k: {} for k in KINDS}
        self.buckets: dict[str, list[int]] = {k: [0] * (len(BUCKETS_MS) + 1) for k in KINDS}
        self.window: dict[str, float] = {}

    def bump(self, name: str, n: int = 1) -> None:
        with self.lock:
            self.totals[name] = self.totals.get(name, 0) + n
            self.window[name] = self.window.get(name, 0) + n

    def peak(self, name: str, value: float) -> None:
        with self.lock:
            if value > self.window.get(name, float("-inf")):
                self.window[name] = value

    def low(self, name: str, value: float) -> None:
        with self.lock:
            if value < self.window.get(name, float("inf")):
                self.window[name] = value

    def record(self, kind: str, status: int, ms: float) -> None:
        cls = f"{status // 100}xx" if status not in (204, 429) else str(status)
        slot = next((i for i, edge in enumerate(BUCKETS_MS) if ms <= edge), len(BUCKETS_MS))
        with self.lock:
            if len(self.samples[kind]) < MAX_SAMPLES:
                self.samples[kind].append(ms)
            self.classes[kind][cls] = self.classes[kind].get(cls, 0) + 1
            self.buckets[kind][slot] += 1
            key = f"{kind}.{cls}"
            self.totals[key] = self.totals.get(key, 0) + 1

    def take(self) -> tuple[dict[str, list[float]], dict[str, dict[str, int]], dict[str, list[int]], dict[str, float]]:
        with self.lock:
            out = (self.samples, self.classes, self.buckets, self.window)
            self._reset()
        return out


STATS = Stats()


# ----------------------------------------------------------------------------- the node threadpool
_LIMITER: list[Any] = [None, 0]  # (limiter, pid): one per worker process, created inside its event loop


def node_thread_tokens() -> int:
    from backend.get_db import pool_settings

    pool = pool_settings()
    return max(4, pool["pool_size"] + pool["max_overflow"])


def node_limiter():
    if _LIMITER[0] is None or _LIMITER[1] != os.getpid():
        _LIMITER[0], _LIMITER[1] = anyio.CapacityLimiter(node_thread_tokens()), os.getpid()
    return _LIMITER[0]


def threads_queued() -> bool:
    """True while node requests of this worker wait for a node thread (the dispatcher then grants no new work)."""
    try:
        return node_limiter().statistics().tasks_waiting > 0
    except Exception:
        return False


async def to_node_thread(fn, *args):
    """Run a node route's synchronous body on the node limiter; the wait for a thread is the request's ``tp``."""
    scheduled = time.perf_counter()
    timing = RT.CURRENT.get()

    def run():
        if timing is not None:
            timing.tp_ms += (time.perf_counter() - scheduled) * 1000.0
        return fn(*args)

    return await anyio.to_thread.run_sync(run, limiter=node_limiter())


# ----------------------------------------------------------------------------- per request
def _header(scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            try:
                return value.decode("latin-1")
            except Exception:
                return None
    return None


def _evict_token(scope) -> None:
    token = _header(scope, b"x-zs-node-token") or ""
    if token.startswith("zsn_") and len(token) <= 128:
        from backend.utilities.cbom_sources import http as H

        H.forget_node_token(hashlib.sha256(token.encode()).hexdigest())


async def serve(app, scope, receive, send, deployment: str | None) -> None:
    _ensure_sampler()
    kind = kind_of(str(scope.get("path") or ""))
    sent_id = _header(scope, b"x-zs-request-id")
    rid = sent_id if sent_id and REQUEST_ID_RE.match(sent_id) else uuid.uuid4().hex[:16]
    timing = RT.Timing(request_id=rid, kind=kind)
    stamp = [(b"x-zs-deployment", deployment.encode())] if deployment else []
    if kind in ("claim", "enroll") and STATS.inflight >= LIM.node_max_inflight():
        retry = random.randint(5, 15)
        ms = (time.perf_counter() - timing.start) * 1000.0
        await send({"type": "http.response.start", "status": 429, "headers": stamp + [
            (b"content-type", b"application/json"), (b"cache-control", b"no-store"),
            (b"retry-after", str(retry).encode()), (b"x-zs-request-id", rid.encode()),
            (b"server-timing", f"app;dur={ms:.1f}, tp;dur=0.0, pool;dur=0.0".encode())]})
        await send({"type": "http.response.body",
                    "body": b'{"detail":"The server is busy; retry after Retry-After seconds"}'})
        STATS.bump("shed_429")
        STATS.record(kind, 429, ms)
        return
    token = RT.CURRENT.set(timing)
    with STATS.lock:
        STATS.inflight += 1
        inflight = STATS.inflight
    STATS.peak("inflight_max", inflight)
    state: dict[str, Any] = {"status": None, "ms": None, "refused": None}
    drop = {b"x-zs-deployment", b"x-zs-request-id", b"server-timing"}

    async def send_timed(message) -> None:
        if message.get("type") == "http.response.start" and state["status"] is None:
            ms = (time.perf_counter() - timing.start) * 1000.0
            state["status"], state["ms"] = int(message.get("status") or 0), ms
            headers = [h for h in message.get("headers") or [] if h[0].lower() not in drop]
            for key, value in headers:
                if key.lower() == b"x-zs-refused":
                    state["refused"] = value.decode("latin-1", "replace")
            headers += stamp + [(b"x-zs-request-id", rid.encode()), (b"server-timing", (
                f"app;dur={ms:.1f}, tp;dur={timing.tp_ms:.1f}, pool;dur={timing.pool_ms:.1f}").encode())]
            message = {**message, "headers": headers}
        await send(message)

    try:
        await app(scope, receive, send_timed)
    finally:
        with STATS.lock:
            STATS.inflight -= 1
        RT.CURRENT.reset(token)
        status = state["status"] if state["status"] is not None else 500
        ms = state["ms"] if state["ms"] is not None else (time.perf_counter() - timing.start) * 1000.0
        STATS.record(kind, status, ms)
        STATS.peak("tp_max_ms", timing.tp_ms)
        STATS.peak("pool_wait_max_ms", timing.pool_ms)
        STATS.bump("pool_checkouts", timing.checkouts)
        STATS.bump("requests")
        if ms >= LIM.node_slow_ms():
            log("node request slow", kind=kind, status=status, ms=int(ms), tp_ms=int(timing.tp_ms),
                pool_ms=int(timing.pool_ms), node=timing.node_id, job=timing.job_id, request_id=rid)
        if status == 401 and state["refused"] == "node_token_revoked":
            _evict_token(scope)


async def delivered(request) -> bool:
    """After the route's work: is the client still there?  A response to a client that left is never delivered
    (``node response undelivered`` line and counter)."""
    try:
        gone = await request.is_disconnected()
    except Exception:  # pragma: no cover - a server without disconnect events
        return True
    if gone:
        timing = RT.CURRENT.get()
        STATS.bump("undelivered")
        log("node response undelivered", kind=timing.kind if timing else None, node=timing.node_id if timing else None,
            job=timing.job_id if timing else None, request_id=timing.request_id if timing else None)
    return not gone


# ----------------------------------------------------------------------------- sampler and the stats line
_SAMPLER = [0]  # pid of the process whose event loop runs the sampler


def _ensure_sampler() -> None:
    if _SAMPLER[0] == os.getpid() or os.environ.get("CBOM_NODE_STATS", "1") == "0":
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _SAMPLER[0] = os.getpid()
    loop.create_task(_sampler())


def sample_once() -> None:
    try:
        from backend.get_db import get_db

        pool = get_db().pool
        STATS.peak("pool_out_max", float(pool.checkedout()))
        STATS.peak("pool_overflow_max", float(max(0, pool.overflow())))
    except Exception:
        pass
    try:
        stats = node_limiter().statistics()
        STATS.peak("tp_waiting_max", float(stats.tasks_waiting))
        STATS.peak("tp_borrowed_max", float(stats.borrowed_tokens))
    except Exception:
        pass
    try:
        from backend.utilities.cbom_sources import dispatch as D

        STATS.low("bucket_min", D.get().level())
    except Exception:
        pass


async def _sampler() -> None:
    loop = asyncio.get_running_loop()
    every = float(os.environ.get("CBOM_NODE_STATS_S") or STATS_EVERY_S)  # the bench uses 10 s
    next_line = time.monotonic() + every
    next_sample = time.monotonic()
    while True:
        t0 = loop.time()
        await asyncio.sleep(LAG_PROBE_S)
        STATS.peak("loop_lag_max_ms", max(0.0, (loop.time() - t0 - LAG_PROBE_S) * 1000.0))
        now = time.monotonic()
        if now >= next_sample:
            next_sample = now + SAMPLE_EVERY_S
            sample_once()
        if now >= next_line:
            next_line = now + every
            try:
                log("cbom node stats", **stats_fields())
            except Exception as exc:  # pragma: no cover - never let the sampler die
                log("cbom node stats FAILED", error=type(exc).__name__)


def _pct(values: list[float], p: float) -> int | None:
    if not values:
        return None
    values = sorted(values)
    return int(round(values[min(len(values) - 1, int(round((len(values) - 1) * p / 100.0)))]))


def stats_fields() -> dict[str, Any]:
    """One stats line's fields (and the window resets)."""
    samples, classes, buckets, window = STATS.take()
    out: dict[str, Any] = {"worker": os.getpid(), "at": int(time.time())}
    for kind, short in (("heartbeat", "hb"), ("claim", "claim"), ("result", "result"), ("assets", "assets"),
                        ("enroll", "enroll")):
        values = samples[kind]
        out[short] = f"{len(values)}/{_pct(values, 50)}/{_pct(values, 99)}"
        if classes[kind]:
            out[f"{short}_codes"] = ",".join(f"{k}:{v}" for k, v in sorted(classes[kind].items()))
    for name in ("inflight_max", "tp_waiting_max", "tp_borrowed_max", "pool_out_max", "pool_overflow_max",
                 "loop_lag_max_ms", "tp_max_ms", "pool_wait_max_ms"):
        out[name] = int(window.get(name, 0))
    for name in ("undelivered", "shed_429", "claims_committed", "results_committed", "limiter_miss",
                 "limiter_lookups", "pool_checkouts", "requests"):
        out[name] = int(window.get(name, 0))
    try:
        from backend.utilities.cbom_sources import dispatch as D

        out.update(D.get().take_counters())
    except Exception:
        pass
    bucket_min = window.get("bucket_min")
    out["bucket_min"] = round(bucket_min, 1) if bucket_min is not None else None
    return out
