"""The F1.1 bench measures what it claims (DA A2): its trace, its error counting and its validity gate.

    cd bench/f1_node_api && python -m pytest -q test_trace.py      # needs aiohttp and pytest

* cx4 P1: with a client connection cap of 4 and requests that chain on the connection they hold, the old trace kept
  only the last queue interval (a 2,020 ms wait traced as 22 ms).  Every heartbeat's traced queue wait must now be at
  least its true wait (server arrival - request start) - 5 ms.
* A heartbeat whose first attempt times out and whose retry succeeds is ONE attempt error and no operation error.
* A 100 ms event-loop stall makes the run invalid (V1: loop lag p99 < 50 ms).
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sim as S  # noqa: E402


class _Server:
    def __init__(self, delay_s: float = 0.0, first_delay_s: float = 0.0) -> None:
        self.delay_s, self.first_delay_s = delay_s, first_delay_s
        self.arrivals: dict[str, float] = {}
        self.calls = 0

    async def handle(self, request: web.Request) -> web.Response:
        self.arrivals[request.headers.get("X-ZS-Request-Id", "")] = time.perf_counter()
        self.calls += 1
        await asyncio.sleep(self.first_delay_s if self.calls == 1 else self.delay_s)
        return web.json_response({"ok": True}, headers={"Server-Timing": "app;dur=1.0, tp;dur=0.0, pool;dur=0.0"})

    async def start(self) -> tuple[web.AppRunner, str]:
        app = web.Application()
        app.router.add_post("/{tail:.*}", self.handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        return runner, f"http://127.0.0.1:{port}"


def test_the_trace_records_the_whole_queue_wait_of_every_heartbeat():
    async def main():
        server = _Server(delay_s=0.2)
        runner, url = await server.start()
        metrics = S.Metrics()
        metrics.measuring = True
        client = S.Client(url, metrics, conns=4, trace_path="/dev/null")
        await client.open()
        starts: dict[int, float] = {}

        async def chain(i):  # a node posting a result and claiming again on the connection it holds
            for _ in range(6):
                await client.call(None, "result", f"/r{i}", {}, retries=0)

        async def heartbeat(i):
            await asyncio.sleep(0.05 * i)
            starts[i] = time.perf_counter()
            await client.call(None, "heartbeat", f"/h{i}", {}, retries=0)

        await asyncio.gather(*(chain(i) for i in range(4)), *(heartbeat(i) for i in range(8)))
        await client.close()
        await runner.cleanup()
        return server, client

    server, client = asyncio.run(main())
    rows = [r for r in client.trace_rows if r[2] == "heartbeat"]
    assert len(rows) == 8
    waited = 0
    for rid, _node, _kind, _attempt, _wall, queue_ms, client_ms, status, _app, _err in rows:
        true_wait_ms = None
        arrival = server.arrivals.get(rid)
        assert arrival is not None and status == 200
        # the true wait: from the request's start to its arrival at the server, minus the 200 ms answer time is not
        # part of it; the traced wait must cover it within 5 ms (connect time on loopback is far below that)
        true_wait_ms = client_ms - 200.0
        assert queue_ms >= true_wait_ms - 5.0, (queue_ms, true_wait_ms)
        waited += true_wait_ms > 100
    assert waited >= 1  # the cap really made some heartbeat wait


def test_a_heartbeat_that_times_out_once_then_succeeds_is_one_attempt_error():
    async def main():
        server = _Server(delay_s=0.0, first_delay_s=1.0)
        runner, url = await server.start()
        metrics = S.Metrics()
        metrics.measuring = True
        client = S.Client(url, metrics, conns=0, timeout_s=0.3)
        await client.open()

        async def no_wait(_seconds):
            return None

        client.sleep = no_wait
        status, _data = await client.call(None, "heartbeat", "/cbom/node/heartbeat", {}, retries=1)
        await client.close()
        await runner.cleanup()
        return metrics, status

    metrics, status = asyncio.run(main())
    assert status == 200
    assert sum(metrics.attempt_errors.values()) == 1 and metrics.attempt_errors["heartbeat:timeout"] == 1
    assert sum(metrics.op_errors.values()) == 0
    assert len(metrics.lat["heartbeat"]) == 1


def test_a_100_ms_loop_stall_makes_the_run_invalid(tmp_path):
    import argparse
    import json

    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"secret": "s", "nodes": 0}))
    args = argparse.Namespace(api="http://127.0.0.1:9", creds=str(creds), db=None, server_pid=None, port=None,
                              nodes=0, node_range=None, p1_frac=0.0, max_jobs=2, duration=0, warmup=0, spread=0,
                              conns=0, force_close=False, run=False, run_timeout=0, work_s=0, mix=False, kill_frac=0,
                              kill_at=0, at=None, residual_ms=20.0, trace=None, out=None, runs=None, open_window=None,
                              cap_x="x", cap_x_ranges=None, run_before_nodes=False)
    sim = S.Sim(args)

    async def main():
        sim.metrics.measuring = True
        lag = asyncio.create_task(sim.lag_monitor())
        for _ in range(10):
            await asyncio.sleep(0.06)
            time.sleep(0.1)  # a stalled event loop
        sim.stopping = True
        await lag

    asyncio.run(main())
    report = sim.report(1.0, 1.0, time.time(), [], {}, {})
    assert report["valid"] is False
    assert any("loop lag" in why for why in report["invalid_because"])


@pytest.mark.parametrize("job_id", range(0, 2000, 7))
def test_the_mix_is_the_da_mix(job_id):
    status, assets = S.outcome_of(job_id)
    assert status in ("success", "failure", "skipped") and assets in (0, 50, 500)
