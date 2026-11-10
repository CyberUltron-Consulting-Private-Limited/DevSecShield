"""A network range reports "addresses done / total" while it runs (round 5 customer testing: the UI showed only a
growing asset count, and a discovery row read "Running on the scan node" until it finished).

The count rides on the asset posts the job already makes (at least every FLUSH_INTERVAL_S); with no assets to carry
it (a sparse range, a discovery sweep) an empty batch carries it.  Other jobs post exactly what they posted before.
"""
from __future__ import annotations

import time

from zs_scan_node import jobctx
from zs_scan_node.api import ApiError
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

from test_network_sweep import TCP16, _fake_tcp


def _ctx(kind: str = "collect") -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 120)


def test_a_sweep_posts_addresses_done_of_total_while_it_runs(monkeypatch):
    tcp, _state = _fake_tcp()
    monkeypatch.setattr(N, "_tcp", tcp)
    monkeypatch.setattr(jobctx, "FLUSH_INTERVAL_S", 0.0)  # post on every address
    posts: list[tuple[int, dict | None]] = []

    def poster(batch, batch_id, progress=None):
        posts.append((len(batch), progress))
        return {"accepted": len(batch)}

    ctx = _ctx("discovery")
    ctx.poster = poster
    scope = {"ranges": [{"cidr": "192.0.2.0/29", "mode": "full"}], "ports": TCP16[:2],
             "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}}
    N.run_network(ctx, scope, discovery_only=True)
    ctx.flush()
    counts = [p for _n, p in posts if p is not None]
    assert counts, posts
    assert all(p["total"] == 6 for p in counts)  # a /29: six usable addresses
    assert counts[-1] == {"done": 6, "total": 6}
    done = [p["done"] for p in counts]
    assert done == sorted(done) and done[0] < 6  # reported while it ran, never backwards
    # a silent discovery sweep has no assets: empty batches carried the count
    assert all(n == 0 for n, _p in posts)


def test_progress_is_posted_at_most_every_interval_and_only_when_it_changed():
    posts: list[dict | None] = []
    ctx = _ctx()
    ctx.poster = lambda batch, batch_id, progress=None: posts.append(progress) or {"accepted": len(batch)}
    ctx.set_progress_total(4)
    ctx.address_done()
    assert posts == []  # the interval has not passed
    ctx._last_flush -= jobctx.FLUSH_INTERVAL_S + 1
    ctx.address_done()
    assert posts == [{"done": 2, "total": 4}]
    ctx.flush()
    assert posts == [{"done": 2, "total": 4}]  # nothing new: no post
    ctx.address_done(2)
    ctx.flush()
    assert posts[-1] == {"done": 4, "total": 4}


def test_jobs_without_progress_post_as_before():
    """A server that does not know ``progress`` never sees it from a job that has none (two-argument poster)."""
    posted: list[int] = []
    ctx = _ctx()
    ctx.poster = lambda batch, batch_id: posted.append(len(batch)) or {"accepted": len(batch)}
    ctx.emit("coverage", "192.0.2.1", "a", facts={"check": "x", "status": "unreachable"})
    ctx.flush()
    ctx.flush()  # no assets, no progress: nothing posted
    assert posted == [1]


def test_a_refused_progress_post_loses_nothing():
    ctx = _ctx()

    def poster(batch, batch_id, progress=None):
        raise ApiError(422, "progress: extra inputs are not permitted")

    ctx.poster = poster
    ctx.set_progress_total(3)
    ctx.address_done()
    ctx.flush()
    assert ctx.lost == 0 and ctx.truncated is False
