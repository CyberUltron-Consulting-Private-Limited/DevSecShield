"""Which scan nodes can run which jobs (F1 contract, section 3).  Created by F1.1; the table is fixed here.

A job whose ``required_capabilities`` are not all in the claiming node's ``capabilities["collectors"]`` (what the node
reports at enrollment and in every heartbeat) is skipped by that node's claim and stays pending for a node that has
them, so an older node is never handed work it cannot do.  Today's kinds need nothing beyond the node itself.
"""
from __future__ import annotations

from typing import Any

_BY_KIND = {
    "awx_hosts": "transport_awx",    # F1.3
    "salt_hosts": "transport_salt",  # F1.3
    "active_directory": "ad_ldaps",  # FIX-B3 (#488 review m3): 1.0.x nodes up to 1.0.6 have no AD collector
}
# Capabilities whose absence the run plan names (the source is skipped with this advice instead of queueing a job no
# node of that version will ever claim): what the node needs, and from which release it has it.  Staging ran nodes
# 1.0.0, 1.0.2 and 1.0.6 when the AD collector was added; the first release that reports ``ad_ldaps`` comes after
# 1.0.6 (scan_node/release.json numbers releases).  The claim still decides by capability, never by version.
UPGRADE_HINTS = {
    "ad_ldaps": ("Active Directory support", "1.0.6"),
}
_BY_CREDENTIAL = {
    "ssh_ca": "ssh_ca",              # F1.4
}


def required_capabilities(kind: str | None, config: dict[str, Any] | None) -> frozenset[str]:
    need = set()
    if kind in _BY_KIND:
        need.add(_BY_KIND[kind])
    credential = (config or {}).get("credential_type")
    if isinstance(credential, str) and credential in _BY_CREDENTIAL:
        need.add(_BY_CREDENTIAL[credential])
    return frozenset(need)


def node_collectors(node) -> frozenset[str]:
    caps = getattr(node, "capabilities", None) or {}
    collectors = caps.get("collectors") if isinstance(caps, dict) else None
    return frozenset(str(c) for c in collectors) if isinstance(collectors, list) else frozenset()


def missing_for(node, kind: str | None, config: dict[str, Any] | None) -> frozenset[str]:
    """The capabilities ``node`` lacks for a job of ``kind`` with ``config`` (empty: it can run it)."""
    need = required_capabilities(kind, config)
    return need - node_collectors(node) if need else frozenset()


def can_run(node, kind: str | None, config: dict[str, Any] | None) -> bool:
    return not missing_for(node, kind, config)


def upgrade_reason(node, kind: str | None, config: dict[str, Any] | None) -> str | None:
    """The plan's skip reason when ``node`` lacks a capability listed in ``UPGRADE_HINTS`` for this source, else
    None (a node that has it, no node, or a capability the plan does not name)."""
    if node is None:
        return None
    for cap in sorted(missing_for(node, kind, config)):
        hint = UPGRADE_HINTS.get(cap)
        if hint:
            running = getattr(node, "node_version", None) or "an older version"
            return (f"Needs a scan node with {hint[0]}: scan node {node.name} runs {running}; update it to a release "
                    f"after {hint[1]} (it reports the {cap} capability)")
    return None


def excluded_for(node) -> tuple[list[str], list[str]]:
    """(source kinds, credential types) whose jobs this node cannot run: the claim's and the hint's runnable
    predicate leaves them out in SQL (DA D1), so such jobs are never locked or counted for this node."""
    have = node_collectors(node)
    kinds = sorted(k for k, cap in _BY_KIND.items() if cap not in have)
    credentials = sorted(c for c, cap in _BY_CREDENTIAL.items() if cap not in have)
    return kinds, credentials
