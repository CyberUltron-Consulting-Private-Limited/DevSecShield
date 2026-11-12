"""Configurable fleet limits and node-API timings for CBOM Sources (F1.1).

Each value is read from the environment when it is used (no restart in tests; a deployment sets it once), so an
operator can size a team for its fleet. A missing, non-numeric or out-of-range value falls back to the default and is
logged once. Names and defaults follow the F1 contract (section 3); defaults are sized for an enterprise fleet; the previous hard caps were 50 agentless nodes, 500 sources,
1,000 agent nodes, 50 pool tokens and 1,000 enrollments per pool token.

| Limit / timing                                  | Environment variable          | Default | Range           |
|-------------------------------------------------|-------------------------------|---------|-----------------|
| agentless scan nodes per team                   | CBOM_MAX_AGENTLESS_NODES      | 500     | 1 - 1,000,000   |
| hand-made sources per team (UI, API, CMDB)      | CBOM_MAX_SOURCES              | 5,000   | 1 - 1,000,000   |
| agent-mode nodes per team                       | CBOM_MAX_AGENT_NODES          | 20,000  | 1 - 1,000,000   |
| agent pool tokens per team                      | CBOM_MAX_POOLS                | 200     | 1 - 100,000     |
| enrollments one pool token may allow            | CBOM_MAX_POOL_ENROLLMENTS     | 20,000  | 1 - 1,000,000   |
| idle heartbeat interval (s), +-20% jitter       | CBOM_NODE_HEARTBEAT_S         | 60      | 5 - 3,600       |
| heartbeat while running a non-network job (s)   | CBOM_NODE_BUSY_HEARTBEAT_S    | 30      | 5 - 3,600       |
| heartbeat while running a network job (s)       | CBOM_NODE_NETWORK_BUSY_S      | 5       | 2 - 600         |
| job lease (s): a silent node's job is re-queued | CBOM_JOB_LEASE_S              | 900     | 30 - 86,400 (*) |
| job claims one worker grants per second          | CBOM_DISPATCH_PER_WORKER_S    | 25      | 1 - 10,000      |
| node requests in flight per worker before claims | CBOM_NODE_MAX_INFLIGHT        | 200     | 10 - 100,000    |
| and enrollments are answered 429                |                               |         |                 |
| a node request slower than this is logged (ms)  | CBOM_NODE_SLOW_MS             | 2,000   | 100 - 600,000   |

(*) The effective lease is never shorter than the floor ``lease_seconds()`` derives from the heartbeat intervals nodes
honour (600 s at the defaults), so a live node whose heartbeats time out a few times in a row, or a backend outage of
up to about lease / 2 - 60 s, never has its job re-queued.  The maximum stays 86,400 s.

Dispatch: each worker grants at most ``CBOM_DISPATCH_PER_WORKER_S`` job claims a second (a token bucket with a burst of
one second of rate), so the deployment-wide claim rate is that times the number of workers (100/s on staging's 4).
"""
from __future__ import annotations

import os
import random

from backend.utilities.cbom_sources.common import log

_SPEC: dict[str, tuple[int, int, int]] = {  # name: (default, minimum, maximum)
    "CBOM_MAX_AGENTLESS_NODES": (500, 1, 1_000_000),
    "CBOM_MAX_SOURCES": (5_000, 1, 1_000_000),
    "CBOM_MAX_AGENT_NODES": (20_000, 1, 1_000_000),
    "CBOM_MAX_POOLS": (200, 1, 100_000),
    "CBOM_MAX_POOL_ENROLLMENTS": (20_000, 1, 1_000_000),
    "CBOM_NODE_HEARTBEAT_S": (60, 5, 3_600),
    "CBOM_NODE_BUSY_HEARTBEAT_S": (30, 5, 3_600),
    "CBOM_NODE_NETWORK_BUSY_S": (5, 2, 600),
    "CBOM_JOB_LEASE_S": (900, 30, 86_400),
    "CBOM_DISPATCH_PER_WORKER_S": (25, 1, 10_000),
    "CBOM_NODE_MAX_INFLIGHT": (200, 10, 100_000),
    "CBOM_NODE_SLOW_MS": (2_000, 100, 600_000),
}
# Heartbeat intervals a node actually honours: scan node 1.2+ waits at most 600 s whatever the server says; scan node
# 1.0/1.1 (protocol 1) at most 60 s.  The lease floor is derived from these, never from a value a node would cap.
NODE_MAX_INTERVAL_S = 600
LEASE_FLOOR_S = 600
_warned: set[str] = set()
JITTER = 0.2


def get(name: str) -> int:
    default, low, high = _SPEC[name]
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or not low <= value <= high:
        if raw not in _warned:
            _warned.add(raw)
            log("limit setting ignored", name=name, value=raw[:32], default=default, allowed=f"{low}-{high}")
        return default
    return value


def max_agentless_nodes() -> int:
    return get("CBOM_MAX_AGENTLESS_NODES")


def max_sources() -> int:
    return get("CBOM_MAX_SOURCES")


def max_agent_nodes() -> int:
    return get("CBOM_MAX_AGENT_NODES")


def max_pools() -> int:
    return get("CBOM_MAX_POOLS")


def max_pool_enrollments() -> int:
    return get("CBOM_MAX_POOL_ENROLLMENTS")


_lease_logged: set[tuple[int, int]] = set()


def lease_floor() -> int:
    """The shortest lease that never expires under a live node (DA D4, Nov 12): at least 600 s, at least two busy
    cycles of four timed-out heartbeats (1.2 x jitter, 30 s client timeout plus one 62 s retry each), and at least three
    idle intervals with jitter.  Intervals are the ones nodes honour (at most 600 s)."""
    import math

    idle_h = min(get("CBOM_NODE_HEARTBEAT_S"), NODE_MAX_INTERVAL_S)
    busy_h = min(get("CBOM_NODE_BUSY_HEARTBEAT_S"), idle_h)
    return max(LEASE_FLOOR_S, math.ceil(2 * (4 * 1.2 * busy_h + 30 + 62)), math.ceil(3 * 1.2 * idle_h))


def lease_seconds() -> int:
    """The job lease: ``CBOM_JOB_LEASE_S``, raised to ``lease_floor()`` (logged once per value) and capped at the
    documented maximum.  A backend outage of up to about lease / 2 - 60 s re-queues no live node's job."""
    configured = get("CBOM_JOB_LEASE_S")
    floor = lease_floor()
    effective = min(max(configured, floor), _SPEC["CBOM_JOB_LEASE_S"][2])
    if effective != configured and (configured, effective) not in _lease_logged:
        _lease_logged.add((configured, effective))
        log("job lease raised to the heartbeat floor", configured_s=configured, effective_s=effective,
            tolerated_outage_s=effective // 2 - 60)
    return effective


def dispatch_per_worker() -> int:
    return get("CBOM_DISPATCH_PER_WORKER_S")


def node_max_inflight() -> int:
    return get("CBOM_NODE_MAX_INFLIGHT")


def node_slow_ms() -> int:
    return get("CBOM_NODE_SLOW_MS")


def heartbeat_seconds(*, busy: bool = False, network: bool = False, rnd: random.Random | None = None) -> int:
    """The interval a node is told to wait before its next heartbeat: the idle interval, or the busy one while it runs
    a job (a network job beats fastest, so a team's stop-all reaches it within seconds), each with +-20% jitter so a
    fleet that restarted together spreads out again."""
    if network:
        base = get("CBOM_NODE_NETWORK_BUSY_S")
    elif busy:
        base = min(get("CBOM_NODE_BUSY_HEARTBEAT_S"), get("CBOM_NODE_HEARTBEAT_S"))
    else:
        base = get("CBOM_NODE_HEARTBEAT_S")
    spread = (rnd or random).uniform(-JITTER, JITTER)
    return max(2, int(round(base * (1 + spread))))
