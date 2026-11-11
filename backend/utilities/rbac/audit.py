"""The audit log: append-only, hash-chained, written for every privileged action.

Three writers, one table (``AuditEvent``):

* ``AuditMiddleware`` records every successful request (status < 400) whose access policy is audited (every team
  write, platform-admin writes), after the response, with the route's path parameters as the object.  A handler
  that already wrote a richer event in its own transaction sets ``request.state.audit_written`` and the middleware
  adds nothing.
* ``policy.TeamPermission`` records refusals (outcome "denied") of team writes before it answers 403.
* Handlers record domain events in the same transaction as the change (``record``): role changes (old -> new),
  removals, ownership claims, invitations, team create / delete, sign-ins.  If the change rolls back, so does
  its audit row.

Append-only: there is no update or delete path; the ORM refuses one (``before_update`` / ``before_delete`` and
bulk UPDATE/DELETE statements on the table); PostgreSQL triggers refuse UPDATE, DELETE and TRUNCATE (migration
r6f4rbac001).  Each row's ``hash`` is SHA-256 over the previous row's hash and the row's own fields; writers take
a PostgreSQL advisory lock for the rest of their transaction so the chain never forks, and ``verify_chain`` finds a
changed, inserted or removed row.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from typing import Any, Iterable, Optional

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from backend.access_models import AuditEvent

log = logging.getLogger("backend.audit")

GENESIS = "0" * 64
AUDIT_CHAIN_LOCK = 0x44535346  # pg_advisory_xact_lock key: "DSSF"
MAX_DETAIL_CHARS = 2000
_HASHED_FIELDS = ("at", "team_id", "actor_user_id", "actor_email", "actor_type", "action", "object_type",
                  "object_id", "outcome", "ip", "user_agent", "details")


class AuditLogIsAppendOnly(RuntimeError):
    pass


# ------------------------------------------------------------------------------------------------ append-only

@event.listens_for(AuditEvent, "before_update")
def _refuse_update(mapper, connection, target):  # noqa: ARG001
    raise AuditLogIsAppendOnly("audit events are never changed")


@event.listens_for(AuditEvent, "before_delete")
def _refuse_delete(mapper, connection, target):  # noqa: ARG001
    raise AuditLogIsAppendOnly("audit events are never deleted")


@event.listens_for(OrmSession, "do_orm_execute")
def _refuse_bulk_changes(orm_execute_state):
    if (orm_execute_state.is_update or orm_execute_state.is_delete) and any(
            m.class_ is AuditEvent for m in orm_execute_state.all_mappers):
        raise AuditLogIsAppendOnly("audit events are never changed or deleted")


# ------------------------------------------------------------------------------------------------ the chain

def _canonical(row: AuditEvent) -> str:
    values: dict[str, Any] = {}
    for name in _HASHED_FIELDS:
        value = getattr(row, name)
        if isinstance(value, dt.datetime):
            value = value.replace(tzinfo=None).isoformat(timespec="microseconds")
        values[name] = value
    return json.dumps(values, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def row_hash(prev_hash: str, row: AuditEvent) -> str:
    return hashlib.sha256((prev_hash + "\n" + _canonical(row)).encode("utf-8")).hexdigest()


def _lock_chain(session: Session) -> None:
    if session.get_bind().dialect.name == "postgresql":
        session.exec(text("SELECT pg_advisory_xact_lock(:k)").bindparams(k=AUDIT_CHAIN_LOCK))  # type: ignore[call-overload]


def _last_hash(session: Session) -> str:
    last = session.exec(select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1)).first()  # type: ignore[union-attr]
    return last or GENESIS


def _clean_details(details: Optional[dict]) -> dict:
    if not details:
        return {}
    try:
        encoded = json.dumps(details, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return {"note": "details not serialisable"}
    if len(encoded) > MAX_DETAIL_CHARS:
        return {"truncated": encoded[:MAX_DETAIL_CHARS]}
    return json.loads(encoded)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def record(session: Session, *, action: str, outcome: str = "success", team_id: Optional[int] = None,
           actor_user_id: Optional[int] = None, actor_email: Optional[str] = None, actor_type: str = "user",
           object_type: Optional[str] = None, object_id: Any = None, ip: Optional[str] = None,
           user_agent: Optional[str] = None, details: Optional[dict] = None) -> AuditEvent:
    """Add one event to ``session`` (the caller commits it together with the change it describes)."""
    _lock_chain(session)
    row = AuditEvent(
        at=utcnow(), team_id=team_id, actor_user_id=actor_user_id,
        actor_email=(actor_email or None) and actor_email[:254], actor_type=actor_type[:16], action=action[:64],
        object_type=(object_type or None) and str(object_type)[:32],
        object_id=None if object_id is None else str(object_id)[:128], outcome=outcome[:16],
        ip=(ip or None) and ip[:64], user_agent=(user_agent or None) and user_agent[:200],
        details=_clean_details(details),
    )
    row.prev_hash = _last_hash(session)
    row.hash = row_hash(row.prev_hash, row)
    session.add(row)
    session.flush()
    return row


def record_now(engine: Engine, **fields: Any) -> None:
    """``record`` in its own transaction."""
    with Session(engine) as session:
        record(session, **fields)
        session.commit()


def actor_fields(principal) -> dict:
    if principal is None:
        return {"actor_type": "anonymous"}
    return {"actor_user_id": principal.user_id, "actor_email": principal.email,
            "actor_type": "superuser" if principal.is_superuser else "user"}


_OBJECT_PARAMS = (  # the most specific path parameter names the object
    ("requirement_id", "attestation"), ("finding_id", "finding"), ("invitation_id", "invitation"),
    ("integration_id", "integration"), ("profile_id", "dast_profile"), ("schedule_id", "schedule"),
    ("vendor_id", "vendor"), ("source_id", "source"), ("node_id", "node"), ("pool_id", "node_pool"),
    ("job_id", "job"), ("asset_id", "asset"), ("run_id", "run"), ("scan_id", "scan"), ("area_key", "evidence_area"),
    ("slug", "deliverable"), ("kind", "integration"), ("name", "template"),
)


def object_from_path(path_params: dict, team_id: Optional[int]) -> tuple[Optional[str], Optional[str]]:
    for param, object_type in _OBJECT_PARAMS:
        if param in path_params:
            return object_type, str(path_params[param])
    if team_id is not None:
        return "team", str(team_id)
    return None, None


def record_from_context(engine: Engine, ctx, meta: dict, *, action: Optional[str] = None, outcome: str = "success",
                        status: Optional[int] = None, extra: Optional[dict] = None, note: Optional[dict] = None) -> None:
    """An event for the request the access context describes (the middleware and refusals)."""
    object_type, object_id = object_from_path(ctx.path_params, ctx.team_id)
    if note:
        object_type, object_id = note.get("object_type") or object_type, note.get("object_id", object_id)
        extra = {**(note.get("details") or {}), **(extra or {})}
    permission = getattr(ctx.policy, "permission", None)
    details = {"method": meta.get("method"), "route": ctx.route_path}
    if ctx.path_params.get("type") is not None:
        details["product"] = str(ctx.path_params["type"])[:32]
    if status is not None:
        details["status"] = status
    if extra:
        details.update(extra)
    record_now(engine, action=action or (permission.name if permission else f"{ctx.policy.kind}.{(meta.get('method') or '').lower()}"),
               outcome=outcome, team_id=ctx.team_id, object_type=object_type, object_id=object_id,
               ip=meta.get("ip"), user_agent=meta.get("user_agent"), details=details, **actor_fields(ctx.principal))


def mark_written(request) -> None:
    """A handler that recorded its own event tells the middleware not to add the generic one."""
    request.state.audit_written = True


def note_object(request, object_type: str, object_id: Any, **details: Any) -> None:
    """A handler names the object the middleware's event is about when the path does not (a body's ``user_id``, a
    created row's id), plus non-secret details (names, old -> new values)."""
    request.state.audit_note = {"object_type": object_type, "object_id": object_id, "details": details}


# ------------------------------------------------------------------------------------------------ middleware

class AuditMiddleware:
    """Pure ASGI: sees the final status of every request; writes the audit event of an audited, successful one
    after the response has gone out (the response is never delayed or changed by the audit log)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        scope.setdefault("state", {})
        sent: dict[str, int] = {}

        async def send_and_note(message):
            if message.get("type") == "http.response.start":
                sent["status"] = int(message.get("status", 0))
            await send(message)

        await self.app(scope, receive, send_and_note)
        state = scope.get("state") or {}
        ctx = state.get("access")
        status = sent.get("status", 0)
        if ctx is None or not getattr(ctx.policy, "audited", False) or ctx.engine_getter is None:
            return
        if status >= 400 or status == 0 or state.get("audit_written"):
            return
        meta = _meta_from_scope(scope)
        try:
            await run_in_threadpool(record_from_context, ctx.engine_getter(), ctx, meta, status=status,
                                    note=state.get("audit_note"))
        except Exception as exc:
            log.error("audit: could not record %s %s (%s)", meta.get("method"), ctx.route_path, type(exc).__name__)


def _meta_from_scope(scope) -> dict:
    client = scope.get("client") or ("", 0)
    user_agent = ""
    for name, value in scope.get("headers") or []:
        if name == b"user-agent":
            user_agent = value.decode("latin-1")
            break
    return {"ip": (client[0] or "")[:64] or None, "user_agent": user_agent[:200] or None, "method": scope.get("method")}


# ------------------------------------------------------------------------------------------------ reading

def public_event(row: AuditEvent) -> dict:
    return {
        "id": row.id, "at": row.at.replace(microsecond=0).isoformat() + "Z" if row.at else None,
        "team_id": row.team_id, "actor_user_id": row.actor_user_id, "actor_email": row.actor_email,
        "actor_type": row.actor_type, "action": row.action, "object_type": row.object_type,
        "object_id": row.object_id, "outcome": row.outcome, "ip": row.ip, "user_agent": row.user_agent,
        "details": row.details or {},
    }


def list_events(engine: Engine, *, team_id: Optional[int], limit: int = 50, before_id: Optional[int] = None,
                action: Optional[str] = None, actor_email: Optional[str] = None, outcome: Optional[str] = None,
                platform: bool = False) -> dict:
    """Newest first.  ``team_id`` scopes to one team (always, for team admins); ``platform`` (superusers) may
    leave it None to read every event."""
    limit = max(1, min(int(limit), 200))
    with Session(engine) as session:
        query = select(AuditEvent)
        if team_id is not None or not platform:
            query = query.where(AuditEvent.team_id == team_id)
        if before_id is not None:
            query = query.where(AuditEvent.id < before_id)  # type: ignore[operator]
        if action:
            query = query.where(AuditEvent.action == action[:64])
        if actor_email:
            query = query.where(AuditEvent.actor_email == actor_email.strip().lower()[:254])
        if outcome:
            query = query.where(AuditEvent.outcome == outcome[:16])
        rows = session.exec(query.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()  # type: ignore[union-attr]
        events = [public_event(r) for r in rows[:limit]]
        return {"events": events, "next_before_id": events[-1]["id"] if len(rows) > limit and events else None}


def verify_chain(engine: Engine, batch: int = 1000) -> dict:
    """Walk the chain from the first row; report the first row whose hash or link does not match."""
    checked, prev, last_id = 0, GENESIS, 0
    with Session(engine) as session:
        while True:
            rows: Iterable[AuditEvent] = session.exec(
                select(AuditEvent).where(AuditEvent.id > last_id).order_by(AuditEvent.id).limit(batch)  # type: ignore[operator]
            ).all()
            rows = list(rows)
            if not rows:
                break
            for row in rows:
                if row.prev_hash != prev:
                    return {"ok": False, "checked": checked, "first_bad_id": row.id,
                            "reason": "the link to the previous event does not match (an event was removed or inserted)"}
                if row.hash != row_hash(prev, row):
                    return {"ok": False, "checked": checked, "first_bad_id": row.id,
                            "reason": "the event's contents do not match its hash (it was changed)"}
                prev, last_id, checked = row.hash, row.id, checked + 1
    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": None}
