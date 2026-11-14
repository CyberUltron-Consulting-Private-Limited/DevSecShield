"""What a decision needs to know about rows outside the policy table: credentials, scan nodes, and (through the
optional-import seams of contract section 3) F1.3's transports and F1.4's SSH CAs.

The seams are removed in the F1 integration PR; until then a missing module or an off flag makes the policies that
need it ``unmanaged`` with a reason the UI shows, never an error.
"""
from __future__ import annotations

import importlib
from typing import Any, Sequence

from sqlmodel import Session, select

from backend.new_models import CbomScanNode
from backend.utilities.cbom_sources.fleet.flags import env_flag
from backend.utilities.cbom_sources.fleet.models import CbomCredential
from backend.utilities.cbom_sources.fleet.policy import Refs, validate_action, PolicyError


def _seam(module: str):
    try:
        return importlib.import_module(module)
    except ImportError:
        return None


def _actions(policies: Sequence[Any]) -> list[dict[str, Any]]:
    out = []
    for p in policies:
        try:
            out.append(validate_action(p.action or {}))
        except PolicyError:
            continue
    return out


def build_refs(session: Session, team_id: int, policies: Sequence[Any]) -> Refs:
    refs = Refs()
    for cred in session.exec(select(CbomCredential).where(CbomCredential.team_id == team_id)).all():
        refs.credentials[cred.id] = f"credential {cred.name!r} was deleted" if cred.deleted_at else None
        refs.credential_types[cred.id] = cred.credential_type
        ca_id = (cred.config or {}).get("ssh_ca_id")
        refs.credential_cas[cred.id] = ca_id if isinstance(ca_id, int) else None
    for node in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all():
        if (node.mode or "agentless") == "agent":
            refs.nodes[node.id] = f"scan node {node.name!r} is an agent-mode node (it collects only its own host)"
        else:
            refs.nodes[node.id] = None
    actions = _actions(policies)
    transport_ids = sorted({a["transport_id"] for a in actions if a.get("transport_id")})
    if transport_ids:
        registry = _seam("backend.utilities.cbom_sources.transports.registry")
        for tid in transport_ids:
            refs.transports[tid] = _transport_problem(session, team_id, tid, registry)
    ca_ids = sorted({ca for cid, ca in refs.credential_cas.items() if ca and refs.credential_types.get(cid) == "ssh_ca"})
    if ca_ids:
        registry = _seam("backend.utilities.cbom_sources.sshca.registry")
        for ca_id in ca_ids:
            refs.cas[ca_id] = _ca_problem(session, team_id, ca_id, registry)
    return refs


def _transport_problem(session: Session, team_id: int, tid: int, registry: Any) -> str | None:
    if registry is None:
        return "transports are not available in this version"
    if not env_flag("CBOM_FLEET_TRANSPORTS"):
        return "transports are turned off"
    ref = registry.get_transport(session, team_id, tid)
    if ref is None:
        return f"transport #{tid} was deleted or not found"
    if getattr(ref, "enabled", True) is False:
        return f"transport #{tid} is disabled"
    return None


def _ca_problem(session: Session, team_id: int, ca_id: int, registry: Any) -> str | None:
    if registry is None:
        return "the SSH CA is not available in this version"
    if not env_flag("CBOM_SSH_CA"):
        return "the SSH CA is turned off"
    if not registry.usable_ca(session, team_id, ca_id):
        return f"SSH CA #{ca_id} is not usable (missing, retired or revoked)"
    return None
