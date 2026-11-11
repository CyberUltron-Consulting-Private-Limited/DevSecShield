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
| job lease (s): a silent node's job is re-queued | CBOM_JOB_LEASE_S              | 900     | 30 - 86,400     |
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
}
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


def lease_seconds() -> int:
    return get("CBOM_JOB_LEASE_S")


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
