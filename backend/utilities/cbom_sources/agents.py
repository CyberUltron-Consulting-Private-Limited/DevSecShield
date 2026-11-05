"""Agent-mode scan nodes (``ZS_MODE=agent``, the Helm DaemonSet) and agent pool registration tokens.

An agent node collects only the host it runs on, from read-only mounts.  The server holds it to that:

* the only source that can use an agent node is a ``host_agent`` source, and a ``host_agent`` source can only use
  an agent node (``check_node_for_kind``, applied when a source is saved);
* a claim never hands an agent node another kind of job (``jobs._invalid_reason`` cancels it) and never decrypts a
  secret for it (``jobs.claim_next``); the run plan skips such pairs with a reason;
* each node that enrolls in agent mode gets its own ``host_agent`` source (``ensure_host_source``), so "Run" covers
  every enrolled host without anyone adding them by hand.

Pool tokens (``zsp_``): many pods enroll with one token, each as its own node named after its Kubernetes node.  The
token expires, caps its enrollments (counted with one conditional UPDATE, so concurrent pods cannot overshoot) and
can be revoked; only its SHA-256 is stored.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from fastapi import HTTPException
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource, CbomNodePool, CbomScanNode
from backend.utilities.cbom_sources.common import log

AGENT = "agent"
AGENTLESS = "agentless"
POOL_PREFIX = "zsp_"
MAX_AGENT_NODES = 1000  # per team; separate from the 50 agentless nodes
MAX_POOLS = 50
MAX_POOL_ENROLLMENTS = 1000
MAX_POOL_HOURS = 24 * 90
HOST_KIND = "host_agent"
_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def is_agent(node: CbomScanNode | None) -> bool:
    return bool(node is not None and (node.mode or AGENTLESS) == AGENT)


def kind_problem(node: CbomScanNode | None, kind: str) -> str | None:
    """Why a source of ``kind`` cannot use ``node`` (None when it can)."""
    if node is None:
        return None
    if is_agent(node) and kind != HOST_KIND:
        return (f"Scan node {node.name} runs in agent mode: it collects only its own host and is never given "
                "credentials. Choose an agentless scan node for this source")
    if not is_agent(node) and kind == HOST_KIND:
        return f"Scan node {node.name} is not in agent mode; host agent sources need a node started with ZS_MODE=agent"
    return None


def check_node_for_kind(node: CbomScanNode | None, kind: str) -> None:
    problem = kind_problem(node, kind)
    if problem:
        raise HTTPException(status_code=400, detail=f"node_id: {problem}")


def pool_status(pool: CbomNodePool, now: _dt.datetime) -> str:
    if pool.revoked_at is not None:
        return "revoked"
    if pool.expires_at <= now:
        return "expired"
    if pool.enrollments >= pool.max_enrollments:
        return "full"
    return "active"


def node_name_from(wanted: str | None, fallback: str) -> str:
    """A node name from the Kubernetes node name: letters, digits, dots, dashes, underscores; at most 64 characters;
    starting with a letter or digit (the node-name rule of the API)."""
    name = _NAME_CHARS.sub("-", str(wanted or "")).strip("-._")[:64].rstrip("-._")
    return name or fallback


def unique_node_name(session: Session, team_id: int, base: str) -> str:
    taken = {n.lower() for n in session.exec(select(CbomScanNode.name).where(CbomScanNode.team_id == team_id)).all()}
    if base.lower() not in taken:
        return base
    for i in range(2, 1000):
        candidate = f"{base[: 64 - len(str(i)) - 1]}-{i}"
        if candidate.lower() not in taken:
            return candidate
    raise HTTPException(status_code=409, detail="no free node name")


def ensure_host_source(session: Session, node: CbomScanNode, owner_user_id: int, now: _dt.datetime) -> CbomCollectionSource:
    """The node's own ``host_agent`` source (created once; a name clash gets a numeric suffix)."""
    existing = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.node_id == node.id,
                                                               CbomCollectionSource.kind == HOST_KIND)).first()
    if existing is not None:
        return existing
    taken = {n for n in session.exec(select(CbomCollectionSource.name_lower).where(
        CbomCollectionSource.team_id == node.team_id, CbomCollectionSource.kind == HOST_KIND)).all()}
    name = node.name
    i = 2
    while name.lower() in taken:
        name = f"{node.name[: 64 - len(str(i)) - 1]}-{i}"
        i += 1
    source = CbomCollectionSource(
        team_id=node.team_id, owner_user_id=owner_user_id, updated_by_user_id=owner_user_id, kind=HOST_KIND,
        name=name, name_lower=name.lower(), node_id=node.id, enabled=True, config={}, secret_encrypted=None,
        secret_fields=[], created_at=now, last_updated=now, last_test_status="never",
    )
    session.add(source)
    session.flush()
    log("host agent source created", team=node.team_id, node=node.id, source=source.id)
    return source


def public_pool(pool: CbomNodePool, now: _dt.datetime, nodes: list[CbomScanNode] | None = None) -> dict[str, Any]:
    from backend.utilities.cbom_sources.common import iso_z

    return {
        "id": pool.id, "team_id": pool.team_id, "owner_user_id": pool.owner_user_id, "name": pool.name,
        "segment": pool.segment, "status": pool_status(pool, now), "expires_at": iso_z(pool.expires_at),
        "max_enrollments": pool.max_enrollments, "enrollments": pool.enrollments,
        "revoked_at": iso_z(pool.revoked_at), "last_enrolled_at": iso_z(pool.last_enrolled_at),
        "created_at": iso_z(pool.created_at),
        "nodes": [{"id": n.id, "name": n.name} for n in (nodes or [])][:MAX_POOL_ENROLLMENTS],
    }
