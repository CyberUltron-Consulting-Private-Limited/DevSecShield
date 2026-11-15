"""#150: accept a legitimately changed host key, or forget a remembered one, under trust on first use.

Scan nodes pin host keys per (address, port) in their own state (``known_hosts.json``).  When a server is rebuilt
every source on that node fails with ``host_key_changed``; until now nothing in the product could clear the pin.

* A team admin decides from a ``host_key_changed`` result (a connection-test sample or a collection's target row):
  ``accept`` the new key the result shows, or ``forget`` the remembered keys.  The decision is bound to that evidence:
  the job must be this source's, the row must say ``host_key_changed`` for that target, and an accepted fingerprint
  must be the one the row reports (never a typed or stale one).
* The node that reported it gets the decision with its next job for the source (``config.host_key_resets``) and
  applies it when it connects to that target.  ``accept`` trusts exactly that key; any other key still fails.
* The node lists the decisions it applied in the job result; they are marked ``applied``.  Until then they are sent
  again (applying one twice changes nothing).  A newer decision for the same target and node supersedes an older one.
* Audit rows (field names only) record the request and its application; the CbomHostKeyReset row keeps who, when,
  the old and the accepted fingerprint.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomHostKeyReset
from backend.utilities.cbom_sources.common import audit, iso_z, log

SSH_KINDS = ("linux_servers", "appliance")  # the sources that log in through linux_ssh.open_session
ACTIONS = ("accept", "forget")
_FP = r"SHA256:[A-Za-z0-9+/]{43}"
_CHANGED = re.compile(rf"pinned ({_FP}), now ({_FP})")
_PINNED = re.compile(rf"pinned ({_FP})")
MAX_SENT = 50  # decisions sent with one job

WARNING_ACCEPT = ("Accept only if you know this server was rebuilt or its host keys were regenerated. A host key "
                  "that changes without a reason can mean someone is intercepting the connection.")
WARNING_FORGET = ("The scan node will trust whatever key the server presents on its next connection and remember it. "
                  "Use this only when the server no longer offers the remembered key type and you have checked the "
                  "change is expected.")


def _evidence(job: CbomCollectionJob, target: str) -> str | None:
    """The text of the ``host_key_changed`` row for ``target`` in the job's result (None: there is none)."""
    result = job.result if isinstance(job.result, dict) else {}
    rows = [r for key in ("samples", "targets") for r in (result.get(key) or []) if isinstance(r, dict)]
    for row in rows:
        if row.get("target") == target and row.get("status") == "host_key_changed":
            return str(row.get("note") or row.get("error") or "")
    return None


def _port(source: CbomCollectionSource) -> int:
    try:
        return int((source.config or {}).get("port") or 22)
    except (TypeError, ValueError):
        return 22


def as_dict(row: CbomHostKeyReset) -> dict[str, Any]:
    return {"id": row.id, "source_id": row.source_id, "node_id": row.node_id, "job_id": row.job_id,
            "target": row.target, "port": row.port, "action": row.action, "fingerprint": row.fingerprint,
            "pinned_fingerprint": row.pinned_fingerprint, "status": row.status,
            "requested_by_user_id": row.requested_by_user_id, "requested_at": iso_z(row.requested_at),
            "applied_at": iso_z(row.applied_at) if row.applied_at else None, "applied_job_id": row.applied_job_id}


def request(session: Session, source: CbomCollectionSource, user_id: int, body: dict[str, Any],
            now: _dt.datetime) -> CbomHostKeyReset:
    """Record an admin's decision (the caller checked that ``user_id`` is a team admin and owns the transaction)."""
    if source.kind not in SSH_KINDS:
        raise HTTPException(status_code=400, detail="Only SSH sources remember host keys")
    if ((source.config or {}).get("host_key_policy") or "tofu") == "pinned":
        raise HTTPException(status_code=400, detail="This source checks host keys against your known_hosts, not "
                                                    "keys remembered on first use: update its known_hosts instead")
    action = body.get("action")
    if action not in ACTIONS:
        raise HTTPException(status_code=422, detail="action must be accept or forget")
    target = body.get("target")
    job_id = body.get("job_id")
    if not isinstance(target, str) or not target or len(target) > 255 or not isinstance(job_id, int) \
            or isinstance(job_id, bool):
        raise HTTPException(status_code=422, detail="job_id (integer) and target are required")
    job = session.get(CbomCollectionJob, job_id)
    if job is None or job.team_id != source.team_id or job.source_id != source.id:
        raise HTTPException(status_code=404, detail="Job not found for this source")
    if job.node_id is None:
        raise HTTPException(status_code=400, detail="That job did not run on a scan node")
    text = _evidence(job, target)
    if text is None:
        raise HTTPException(status_code=400, detail=f"That job did not report a changed host key for {target}")
    changed = _CHANGED.search(text)
    pinned = changed.group(1) if changed else (m.group(1) if (m := _PINNED.search(text)) else None)
    fingerprint = None
    if action == "accept":
        if changed is None:
            raise HTTPException(status_code=400, detail="The result does not show a new key to accept (the server no "
                                                        "longer offers the remembered key type): use Forget instead")
        fingerprint = changed.group(2)
        if body.get("fingerprint") != fingerprint:
            raise HTTPException(status_code=409, detail="The key to accept does not match the one the result shows. "
                                                        "Reload and review the key again.")
    port = _port(source)
    superseded = session.exec(
        update(CbomHostKeyReset)
        .where(CbomHostKeyReset.source_id == source.id, CbomHostKeyReset.node_id == job.node_id,
               CbomHostKeyReset.target == target, CbomHostKeyReset.port == port,
               CbomHostKeyReset.status == "pending")
        .values(status="superseded")
    ).rowcount
    row = CbomHostKeyReset(team_id=source.team_id, source_id=source.id, node_id=job.node_id, job_id=job.id,
                           target=target, port=port, action=action, fingerprint=fingerprint,
                           pinned_fingerprint=pinned, status="pending", requested_by_user_id=user_id,
                           requested_at=now)
    session.add(row)
    session.flush()
    audit(session, team_id=source.team_id, actor_type="user", actor_id=user_id,
          action=f"source.host_key_{action}", object_type="source", object_id=source.id,
          changed_fields=["host_key_pin"])
    log("host key decision", team=source.team_id, source=source.id, node=job.node_id, reset=row.id, decision=action,
        target=target, port=port, superseded=superseded, by=user_id)
    return row


def for_claim(session: Session, source: CbomCollectionSource, node_id: int) -> list[dict[str, Any]]:
    """The pending decisions the claiming node applies during this job (only those addressed to it)."""
    if source.kind not in SSH_KINDS:
        return []
    rows = session.exec(
        select(CbomHostKeyReset)
        .where(CbomHostKeyReset.source_id == source.id, CbomHostKeyReset.node_id == node_id,
               CbomHostKeyReset.status == "pending")
        .order_by(CbomHostKeyReset.id)  # type: ignore[arg-type]
        .limit(MAX_SENT)
    ).all()
    return [{"id": r.id, "target": r.target, "port": r.port, "action": r.action,
             **({"fingerprint": r.fingerprint} if r.action == "accept" else {})} for r in rows]


def applied(session: Session, job: CbomCollectionJob, node_id: int, result: dict[str, Any] | None,
            now: _dt.datetime) -> int:
    """Mark the decisions the node says it applied in ``job``; only its own pending ones for this source count."""
    ids = (result or {}).get("host_key_resets_applied") if isinstance(result, dict) else None
    if not isinstance(ids, list) or job.source_id is None:
        return 0
    ids = [i for i in ids[:200] if isinstance(i, int) and not isinstance(i, bool)]
    if not ids:
        return 0
    rows = session.exec(
        select(CbomHostKeyReset)
        .where(CbomHostKeyReset.id.in_(ids), CbomHostKeyReset.source_id == job.source_id,  # type: ignore[union-attr]
               CbomHostKeyReset.node_id == node_id, CbomHostKeyReset.status == "pending")
    ).all()
    for row in rows:
        row.status, row.applied_at, row.applied_job_id = "applied", now, job.id
        session.add(row)
        audit(session, team_id=job.team_id, actor_type="node", actor_id=node_id,
              action=f"source.host_key_{row.action}_applied", object_type="source", object_id=job.source_id,
              changed_fields=["host_key_pin"])
        log("host key decision applied", team=job.team_id, source=job.source_id, node=node_id, reset=row.id,
            decision=row.action, job=job.id)
    return len(rows)


def recent(session: Session, source: CbomCollectionSource, limit: int = 50) -> list[dict[str, Any]]:
    rows = session.exec(
        select(CbomHostKeyReset).where(CbomHostKeyReset.source_id == source.id, CbomHostKeyReset.team_id == source.team_id)
        .order_by(CbomHostKeyReset.id.desc())  # type: ignore[union-attr]
        .limit(limit)
    ).all()
    return [as_dict(r) for r in rows]
