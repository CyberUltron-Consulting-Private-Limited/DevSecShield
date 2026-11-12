"""Idempotent upsert of inventory targets, and the decisions stored on them.

``upsert`` writes a batch of normalised ``Target``s for one inventory source:

* a target is keyed on ``(team_id, external_id)``; a new one is inserted with ``ON CONFLICT DO NOTHING`` and one that
  a concurrent import inserted first is updated instead, so two imports never duplicate a target;
* **one owner**: a target belongs to the inventory source that first listed it (``inventory_source_id``).  Another
  source that lists the same ``external_id`` gets an error row ("belongs to inventory source ...") and changes
  nothing, so two feeds of one host never take it from each other on every import.  It takes the target over only
  when the owner no longer has it: a person deleted it, or the owner's last snapshot missed it;
* an existing target whose fingerprint, owner and presence are unchanged gets only ``last_seen_at`` (one bulk UPDATE
  per chunk): a re-import that changes nothing reports ``unchanged`` for every row and changes no data;
* a changed one is updated (``row_version`` + 1) and comes back if it was missing or deleted (its source lists it
  again);
* ``snapshot=True`` (a file import, an AWS sync): targets of the source that were not seen are marked
  ``missing_since`` (an AWS sync passes ``in_scope`` so that a region/service it could not read is never marked).

Every write stores the engine's Decision (``decision`` JSON, plus ``decision_action`` / ``decision_policy_id``, the
indexed columns lists filter and count on).  All statements run in the caller's session and transaction; the caller
commits.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Sequence

from sqlalchemy import Text, bindparam, cast, select, update
from sqlmodel import Session

from backend.utilities.cbom_sources.fleet.inventory_sources import Target
from backend.utilities.cbom_sources.fleet.models import CbomInventorySource, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine

CHUNK = 500
MAX_TARGETS_PER_TEAM = 50_000  # imports refuse past it; an AWS sync adds new targets only up to it (``capped``)
_TABLE = CbomInventoryTarget.__table__  # type: ignore[attr-defined]


@dataclass
class UpsertResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    missing: int = 0
    skipped: int = 0  # rows another inventory source owns
    capped: int = 0  # new rows left out by the team's target cap
    errors: list[dict[str, Any]] = field(default_factory=list)
    digest: str = ""
    ids: dict[str, int] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"created": self.created, "updated": self.updated, "unchanged": self.unchanged,
                "missing": self.missing, "skipped": self.skipped, "capped": self.capped,
                "errors": self.errors[:100], "digest": self.digest}


@dataclass(frozen=True)
class Existing:
    id: int
    fingerprint: str
    source_id: int
    missing_since: _dt.datetime | None
    deleted_at: _dt.datetime | None


def digest(targets: Iterable[Target]) -> str:
    h = hashlib.sha256()
    for external_id, fp in sorted((t.external_id, t.fingerprint()) for t in targets):
        h.update(f"{external_id}\x00{fp}\n".encode())
    return h.hexdigest()


def _chunks(items: Sequence[Any], size: int = CHUNK) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def decision_columns(decision: dict[str, Any]) -> dict[str, Any]:
    """The stored form of a Decision dict: the JSON and its two indexed columns."""
    return {"decision": decision, "decision_action": decision.get("action") if decision else None,
            "decision_policy_id": decision.get("policy_id") if decision else None}


def _row_values(t: Target) -> dict[str, Any]:
    return {"kind": t.kind, "address": t.address, "addresses": list(t.addresses), "hostname": t.hostname,
            "tags": dict(t.tags), "account_id": t.account_id, "region": t.region, "platform": t.platform,
            "handles": dict(t.handles), "attributes": dict(t.attributes)}


def _insert(session: Session, rows: list[dict[str, Any]]) -> None:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as dialect_insert  # type: ignore[assignment]
    else:  # pragma: no cover - the product runs PostgreSQL, the tests SQLite
        raise RuntimeError(f"unsupported database {dialect}")
    for chunk in _chunks(rows):
        stmt = dialect_insert(_TABLE).values(list(chunk)).on_conflict_do_nothing(
            index_elements=["team_id", "external_id"])
        session.exec(stmt)  # type: ignore[call-overload]


def existing(session: Session, team_id: int, external_ids: Sequence[str]) -> dict[str, Existing]:
    """What the team already holds for these external ids (one query per 500)."""
    out: dict[str, Existing] = {}
    t = _TABLE.c
    for chunk in _chunks(list(external_ids)):
        rows = session.exec(select(t.id, t.external_id, t.fingerprint, t.inventory_source_id, t.missing_since,  # type: ignore[call-overload]
                                   t.deleted_at)
                            .where(t.team_id == team_id, t.external_id.in_(list(chunk)))).all()
        for row in rows:
            out[row[1]] = Existing(row[0], row[2], row[3], row[4], row[5])
    return out


def _owner_names(session: Session, source_ids: set[int]) -> dict[int, str]:
    if not source_ids:
        return {}
    s = CbomInventorySource.__table__.c  # type: ignore[attr-defined]
    return {row[0]: row[1] for row in session.exec(select(s.id, s.name).where(s.id.in_(sorted(source_ids)))).all()}  # type: ignore[call-overload]


def upsert(session: Session, team_id: int, source: CbomInventorySource, targets: Sequence[Target],
           now: _dt.datetime, *, engine: PolicyEngine | None, snapshot: bool = False,
           in_scope: Callable[[Any], bool] | None = None, dry_run: bool = False,
           known: dict[str, Existing] | None = None, room: int | None = None) -> UpsertResult:
    """``known``: ``existing(...)`` for these targets when the caller already has it.  ``room``: how many new targets
    the team's cap still allows (the rest are counted in ``capped`` and left out, in external-id order)."""
    result = UpsertResult(digest=digest(targets))
    by_id = {t.external_id: t for t in targets}
    rows = known if known is not None else existing(session, team_id, list(by_id))
    new: list[Target] = []
    changed: list[tuple[int, Target]] = []
    same: list[int] = []
    foreign: list[tuple[str, int]] = []
    for ext, target in by_id.items():
        row = rows.get(ext)
        if row is None:
            new.append(target)
        elif row.source_id != source.id and row.deleted_at is None and row.missing_since is None:
            foreign.append((ext, row.source_id))  # another source owns it and still lists it
        elif (row.fingerprint == target.fingerprint() and row.source_id == source.id and row.missing_since is None
              and row.deleted_at is None):
            same.append(row.id)
        else:
            changed.append((row.id, target))
    if foreign:
        names = _owner_names(session, {sid for _ext, sid in foreign})
        for ext, sid in sorted(foreign):
            if len(result.errors) < 100:
                result.errors.append({"external_id": ext[:255],
                                      "error": f"belongs to inventory source {names.get(sid, '?')!r} (#{sid})"})
        result.skipped = len(foreign)
    if room is not None and len(new) > max(room, 0):
        new.sort(key=lambda t: t.external_id)
        result.capped = len(new) - max(room, 0)
        new = new[:max(room, 0)]
    if dry_run:
        result.created, result.updated, result.unchanged = len(new), len(changed), len(same)
        if snapshot:
            result.missing = len(_gone(session, team_id, source.id, set(by_id), in_scope))
        return result

    def decision(t: Target) -> dict[str, Any]:
        return engine.evaluate(t).to_dict() if engine is not None else {}

    if new:
        _insert(session, [{"team_id": team_id, "inventory_source_id": source.id, "external_id": t.external_id,
                           **_row_values(t), "fingerprint": t.fingerprint(), "first_seen_at": now,
                           "last_seen_at": now, "missing_since": None, "deleted_at": None, "pending_since": None,
                           **decision_columns(decision(t)), "managed_source_id": None, "row_version": 1,
                           "created_at": now, "last_updated": now}
                          for t in new])
        inserted = existing(session, team_id, [t.external_id for t in new])
        for t in new:
            row = inserted[t.external_id]
            if row.fingerprint == t.fingerprint() and row.source_id == source.id and row.missing_since is None:
                result.created += 1  # ours (or an identical concurrent insert: nothing left to change)
            elif row.source_id != source.id:
                result.skipped += 1  # a concurrent import of another source inserted it first: it owns it
            else:
                changed.append((row.id, t))  # a concurrent import of this source inserted it first: update it
    if changed:
        c = _TABLE.c
        stmt = (update(_TABLE).where(c.id == bindparam("_id"))
                .values(inventory_source_id=bindparam("_src"), kind=bindparam("_kind"), address=bindparam("_address"),
                        addresses=bindparam("_addresses"), hostname=bindparam("_hostname"), tags=bindparam("_tags"),
                        account_id=bindparam("_account"), region=bindparam("_region"),
                        platform=bindparam("_platform"), handles=bindparam("_handles"),
                        attributes=bindparam("_attributes"), fingerprint=bindparam("_fp"),
                        decision=bindparam("_decision"), decision_action=bindparam("_action"),
                        decision_policy_id=bindparam("_policy"), last_seen_at=now, missing_since=None,
                        deleted_at=None, last_updated=now, row_version=c.row_version + 1))
        params = []
        for row_id, t in changed:
            v = _row_values(t)
            d = decision_columns(decision(t))
            params.append({"_id": row_id, "_src": source.id, "_kind": v["kind"], "_address": v["address"],
                           "_addresses": v["addresses"], "_hostname": v["hostname"], "_tags": v["tags"],
                           "_account": v["account_id"], "_region": v["region"], "_platform": v["platform"],
                           "_handles": v["handles"], "_attributes": v["attributes"], "_fp": t.fingerprint(),
                           "_decision": d["decision"], "_action": d["decision_action"],
                           "_policy": d["decision_policy_id"]})
        for chunk in _chunks(params):
            session.connection().execute(stmt, list(chunk))
        result.updated = len(changed)
    if same:
        for chunk in _chunks(same):
            session.exec(update(_TABLE).where(_TABLE.c.id.in_(list(chunk))).values(last_seen_at=now)  # type: ignore[call-overload]
                         .execution_options(synchronize_session=False))
        result.unchanged = len(same)
    if snapshot:
        gone = _gone(session, team_id, source.id, set(by_id), in_scope)
        for chunk in _chunks(gone):
            session.exec(update(_TABLE).where(_TABLE.c.id.in_(list(chunk)), _TABLE.c.missing_since.is_(None))  # type: ignore[call-overload]
                         .values(missing_since=now, last_updated=now, row_version=_TABLE.c.row_version + 1)
                         .execution_options(synchronize_session=False))
        result.missing = len(gone)
    return result


def _gone(session: Session, team_id: int, source_id: int | None, seen: set[str],
          in_scope: Callable[[Any], bool] | None) -> list[int]:
    t = _TABLE.c
    rows = session.exec(select(t.id, t.external_id, t.region, t.attributes)  # type: ignore[call-overload]
                        .where(t.team_id == team_id, t.inventory_source_id == source_id, t.missing_since.is_(None))).all()
    out = []
    for row in rows:
        if row[1] in seen:
            continue
        if in_scope is not None and not in_scope(row):
            continue
        out.append(row[0])
    return out


def mark_deleted(session: Session, team_id: int, now: _dt.datetime, *, target_id: int | None = None,
                 source_id: int | None = None) -> int:
    """A person removed one target, or every target of an inventory source, from the inventory: ``deleted_at`` (never
    collected again; the next reconcile takes it out of its managed source) and ``missing_since``.  Returns rows."""
    t = _TABLE.c
    stmt = update(_TABLE).where(t.team_id == team_id, t.deleted_at.is_(None))
    stmt = stmt.where(t.id == target_id) if target_id is not None else stmt.where(t.inventory_source_id == source_id)
    from sqlalchemy import func
    res = session.exec(stmt.values(deleted_at=now, missing_since=func.coalesce(t.missing_since, now),  # type: ignore[call-overload]
                                   last_updated=now, row_version=t.row_version + 1)
                       .execution_options(synchronize_session=False))
    return int(res.rowcount or 0)


VIEW_COLUMNS = ("id", "external_id", "inventory_source_id", "kind", "address", "addresses", "hostname", "tags",
                "account_id", "region", "platform", "handles", "missing_since", "deleted_at", "pending_since",
                "decision", "decision_action", "decision_policy_id", "managed_source_id")


_LIGHT = tuple(c for c in VIEW_COLUMNS if c != "decision")


def iter_views(session: Session, team_id: int, *, present_only: bool = False, light: bool = False,
               decision_text: bool = False) -> Iterable[SimpleNamespace]:
    """Every target of the team as a light read-only view (no ORM objects in the caller's session), in id order.
    ``present_only``: neither missing nor deleted.  ``light``: without the stored decision JSON.  ``decision_text``
    (with ``light``): the stored decision as undecoded JSON text, for a caller that needs it for a few rows only."""
    names = _LIGHT if light else VIEW_COLUMNS
    cols = [getattr(_TABLE.c, name) for name in names]
    if light and decision_text:
        names = (*names, "decision_text")
        cols.append(cast(_TABLE.c.decision, Text))
    last_id = 0
    while True:
        query = select(*cols).where(_TABLE.c.team_id == team_id, _TABLE.c.id > last_id)
        if present_only:
            query = query.where(_TABLE.c.missing_since.is_(None), _TABLE.c.deleted_at.is_(None))
        rows = session.exec(query.order_by(_TABLE.c.id).limit(CHUNK)).all()  # type: ignore[call-overload]
        if not rows:
            return
        for row in rows:
            view = SimpleNamespace(**dict(zip(names, row)))
            last_id = view.id
            yield view


@dataclass
class Refreshed:
    changed: int = 0
    counts: dict[str, list[int]] = field(default_factory=dict)  # policy id -> [matched, won], present targets
    collect: dict[int, Any] = field(default_factory=dict)  # target id -> Decision, for the materializer


def refresh_decisions(session: Session, team_id: int, engine: PolicyEngine, *, keep_collect: bool = False) -> Refreshed:
    """Re-evaluate every target of the team (after a policy, credential, node or settings change).  Only rows whose
    decision changed are written.  Also counts, per policy, the present targets it matches and wins."""
    out = Refreshed()
    changed = []
    counts: dict[int, list[int]] = {}
    for view in iter_views(session, team_id):
        d = engine.evaluate(view)
        fresh = d.to_dict()
        if fresh != (view.decision or {}) or view.decision_action != d.action or view.decision_policy_id != d.policy_id:
            changed.append({"_id": view.id, "_decision": fresh, "_action": d.action, "_policy": d.policy_id})
        if view.missing_since is None and view.deleted_at is None:
            for pid in d.matched_policy_ids:
                counts.setdefault(pid, [0, 0])[0] += 1
            if d.policy_id is not None:
                counts.setdefault(d.policy_id, [0, 0])[1] += 1
        if keep_collect and d.action == "collect":
            out.collect[view.id] = d
    if changed:
        stmt = (update(_TABLE).where(_TABLE.c.id == bindparam("_id"))
                .values(decision=bindparam("_decision"), decision_action=bindparam("_action"),
                        decision_policy_id=bindparam("_policy")))
        for chunk in _chunks(changed):
            session.connection().execute(stmt, list(chunk))
    out.changed = len(changed)
    out.counts = {str(k): v for k, v in sorted(counts.items())}
    return out
