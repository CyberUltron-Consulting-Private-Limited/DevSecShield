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
can be revoked; only its SHA-256 is stored.  A pod whose node was reset in ZeroShield gets a 401, enrolls again with
the same pool token and takes its own node back (``node_to_rebind``: same pool, credential revoked, the node id the
pod kept), which uses no enrollment, while the token is neither expired nor revoked.  A deleted node's pod enrolls
as a new node within the pool's cap.

A node's mode follows what it reports (``reconcile_mode``): a node restarted with ``ZS_MODE=agent`` is an agent node
from its next heartbeat or claim on; the other way round needs a new enrollment.  The per-team caps on agent nodes
and pool tokens are checked under the team's settings-row lock (``lock_team``).
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSettings, CbomCollectionSource, CbomNodePool, CbomScanNode
from backend.utilities.cbom_sources import limits as L
from backend.utilities.cbom_sources.common import audit, log

AGENT = "agent"
AGENTLESS = "agentless"
POOL_PREFIX = "zsp_"
# Per-team caps on agent nodes, pool tokens and enrollments per token: limits.py (CBOM_MAX_AGENT_NODES,
# CBOM_MAX_POOLS, CBOM_MAX_POOL_ENROLLMENTS; F1.1, were 1,000 / 50 / 1,000 fixed here)
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


def lock_team(session: Session, team_id: int) -> None:
    """Serialise a check-then-insert against a per-team cap (agent nodes, agent pool tokens): a no-op UPDATE of the
    team's settings row (which must exist: ``get_or_create_settings`` first), which PostgreSQL row-locks and SQLite
    write-locks until the transaction ends, so two requests cannot both pass the same count."""
    session.exec(update(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)
                 .values(row_version=CbomCollectionSettings.row_version))


def node_to_rebind(session: Session, pool: CbomNodePool, node_id: int | None, node_name: str | None) -> CbomScanNode | None:
    """The agent node of ``pool`` that a pod enrolling again with the pool token takes back: one whose credential was
    revoked (reset), found by the node id the pod kept in its state, or (state lost) by its Kubernetes node name when
    exactly one such node has that name.  A node that still holds a credential is never taken."""
    query = select(CbomScanNode).where(CbomScanNode.team_id == pool.team_id, CbomScanNode.pool_id == pool.id,
                                       CbomScanNode.mode == AGENT,
                                       CbomScanNode.node_token_hash.is_(None))  # type: ignore[union-attr]
    if node_id is not None:
        return session.exec(query.where(CbomScanNode.id == node_id)).first()
    name = node_name_from(node_name, "").lower()
    matches = [n for n in session.exec(query).all() if name and n.name.lower() == name]
    return matches[0] if len(matches) == 1 else None


def reconcile_mode(session: Session, node: CbomScanNode, reported: Any, now: _dt.datetime) -> str | None:
    """Apply the mode a node reports (heartbeat ``capabilities.mode``, claim body).  A node now running in agent mode
    is an agent node from this request on (never given a credential again) with its own host source.  A node enrolled
    in agent mode that reports agentless stays an agent node: taking credentials needs a new enrollment.  Returns the
    note for the node's error field in that case."""
    if reported == AGENT and not is_agent(node):
        node.mode = AGENT
        node.row_version += 1
        node.last_updated = now
        session.add(node)
        ensure_host_source(session, node, node.owner_user_id, now)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.mode",
              object_type="node", object_id=node.id, changed_fields=["mode"])
        log("node now runs in agent mode", team=node.team_id, node=node.id)
        return None
    if reported == AGENTLESS and is_agent(node):
        return ("This node enrolled in agent mode and now runs without ZS_MODE=agent; it is still an agent node (its "
                "own host only, no credentials). Reset it and register it again to use it as an agentless node")
    return None


def public_pool(pool: CbomNodePool, now: _dt.datetime, nodes: list[CbomScanNode] | None = None) -> dict[str, Any]:
    from backend.utilities.cbom_sources.common import iso_z

    return {
        "id": pool.id, "team_id": pool.team_id, "owner_user_id": pool.owner_user_id, "name": pool.name,
        "segment": pool.segment, "status": pool_status(pool, now), "expires_at": iso_z(pool.expires_at),
        "max_enrollments": pool.max_enrollments, "enrollments": pool.enrollments,
        "revoked_at": iso_z(pool.revoked_at), "last_enrolled_at": iso_z(pool.last_enrolled_at),
        "created_at": iso_z(pool.created_at),
        "nodes": [{"id": n.id, "name": n.name} for n in (nodes or [])][:L.max_pool_enrollments()],
    }
