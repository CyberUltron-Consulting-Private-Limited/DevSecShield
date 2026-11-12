"""Per-request timing shared by the node-API middleware, the threadpool hop and the database pool (F1.1, DA §4).

The middleware puts a fresh ``Timing`` in ``CURRENT`` for each ``/cbom/node/*`` request.  Context variables are copied
into the worker thread that runs the route's synchronous body, so the thread adds its waits to the same object:

* ``tp_ms``: time from scheduling the body on the node threadpool to the thread starting it;
* ``pool_ms``: time spent getting database connections from the pool (waiting for one, connecting, pre-ping);
* ``checkouts``: how many connections the request took from the pool.

Nothing here touches the database; it is plain arithmetic on ``time.perf_counter()``.
"""
from __future__ import annotations

import contextvars
import time
from dataclasses import dataclass, field


@dataclass
class Timing:
    start: float = field(default_factory=time.perf_counter)
    tp_ms: float = 0.0
    pool_ms: float = 0.0
    checkouts: int = 0
    node_id: int | None = None
    job_id: int | None = None
    request_id: str = ""
    kind: str = ""


CURRENT: "contextvars.ContextVar[Timing | None]" = contextvars.ContextVar("zs_request_timing", default=None)


def add_pool_wait(seconds: float) -> None:
    timing = CURRENT.get()
    if timing is not None:
        timing.pool_ms += seconds * 1000.0
        timing.checkouts += 1


def note(**fields) -> None:
    """Record the node or job a request is about (for the slow-request and undelivered lines)."""
    timing = CURRENT.get()
    if timing is not None:
        for key, value in fields.items():
            setattr(timing, key, value)
