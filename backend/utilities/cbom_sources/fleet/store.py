"""Idempotent upsert of inventory targets, and the cached decisions on them.

``upsert`` writes a batch of normalised ``Target``s for one inventory source:

* a target is keyed on ``(team_id, external_id)``; a new one is inserted with ``ON CONFLICT DO NOTHING`` and one that
  a concurrent import inserted first is updated instead, so two imports never duplicate a target;
* an existing target whose fingerprint, inventory source and presence are unchanged gets only ``last_seen_at`` (one
  bulk UPDATE per chunk): a re-import that changes nothing reports ``unchanged`` for every row and changes no data;
* a changed one is updated (``row_version`` + 1) and comes back if it was missing;
* ``snapshot=True`` (a file import, an AWS sync): targets of the source that were not seen are marked
  ``missing_since`` (an AWS sync passes ``in_scope`` so that a region/service it could not read is never marked).

All statements run in the caller's session and transaction; the caller commits.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Sequence

from sqlalchemy import bindparam, select, update
from sqlmodel import Session

from backend.utilities.cbom_sources.fleet.inventory_sources import Target
from backend.utilities.cbom_sources.fleet.models import CbomInventorySource, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine

CHUNK = 500
_TABLE = CbomInventoryTarget.__table__  # type: ignore[attr-defined]


@dataclass
class UpsertResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    missing: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    digest: str = ""
    ids: dict[str, int] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"created": self.created, "updated": self.updated, "unchanged": self.unchanged,
                "missing": self.missing, "errors": self.errors[:100], "digest": self.digest}


def digest(targets: Iterable[Target]) -> str:
    h = hashlib.sha256()
    for external_id, fp in sorted((t.external_id, t.fingerprint()) for t in targets):
        h.update(f"{external_id}\x00{fp}\n".encode())
    return h.hexdigest()


def _chunks(items: Sequence[Any], size: int = CHUNK) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


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


def _existing(session: Session, team_id: int, external_ids: Sequence[str]) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    t = _TABLE.c
    for chunk in _chunks(list(external_ids)):
        rows = session.exec(select(t.id, t.external_id, t.fingerprint, t.inventory_source_id, t.missing_since)  # type: ignore[call-overload]
                            .where(t.team_id == team_id, t.external_id.in_(list(chunk)))).all()
        for row in rows:
            out[row[1]] = (row[0], row[2], row[3], row[4])
    return out


def upsert(session: Session, team_id: int, source: CbomInventorySource, targets: Sequence[Target],
           now: _dt.datetime, *, engine: PolicyEngine | None, snapshot: bool = False,
           in_scope: Callable[[Any], bool] | None = None, dry_run: bool = False) -> UpsertResult:
    result = UpsertResult(digest=digest(targets))
    by_id = {t.external_id: t for t in targets}
    existing = _existing(session, team_id, list(by_id))
    new: list[Target] = []
    changed: list[tuple[int, Target]] = []
    same: list[int] = []
    for ext, target in by_id.items():
        row = existing.get(ext)
        if row is None:
            new.append(target)
        elif row[1] == target.fingerprint() and row[2] == source.id and row[3] is None:
            same.append(row[0])
        else:
            changed.append((row[0], target))
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
                           "last_seen_at": now, "missing_since": None, "decision": decision(t),
                           "managed_source_id": None, "row_version": 1, "created_at": now, "last_updated": now}
                          for t in new])
        inserted = _existing(session, team_id, [t.external_id for t in new])
        for t in new:
            row = inserted[t.external_id]
            if row[1] == t.fingerprint() and row[2] == source.id and row[3] is None:
                result.created += 1  # ours (or an identical concurrent insert: nothing left to change)
            else:
                changed.append((row[0], t))  # a concurrent import inserted it first: update it
    if changed:
        c = _TABLE.c
        stmt = (update(_TABLE).where(c.id == bindparam("_id"))
                .values(inventory_source_id=bindparam("_src"), kind=bindparam("_kind"), address=bindparam("_address"),
                        addresses=bindparam("_addresses"), hostname=bindparam("_hostname"), tags=bindparam("_tags"),
                        account_id=bindparam("_account"), region=bindparam("_region"),
                        platform=bindparam("_platform"), handles=bindparam("_handles"),
                        attributes=bindparam("_attributes"), fingerprint=bindparam("_fp"),
                        decision=bindparam("_decision"), last_seen_at=now, missing_since=None, last_updated=now,
                        row_version=c.row_version + 1))
        params = []
        for row_id, t in changed:
            v = _row_values(t)
            params.append({"_id": row_id, "_src": source.id, "_kind": v["kind"], "_address": v["address"],
                           "_addresses": v["addresses"], "_hostname": v["hostname"], "_tags": v["tags"],
                           "_account": v["account_id"], "_region": v["region"], "_platform": v["platform"],
                           "_handles": v["handles"], "_attributes": v["attributes"], "_fp": t.fingerprint(),
                           "_decision": decision(t)})
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


_VIEW_COLUMNS = ("id", "external_id", "inventory_source_id", "kind", "address", "addresses", "hostname", "tags",
                 "account_id", "region", "platform", "handles", "missing_since", "decision", "managed_source_id")


def iter_views(session: Session, team_id: int, *, present_only: bool = False) -> Iterable[SimpleNamespace]:
    """Every target of the team as a light read-only view (no ORM objects in the caller's session), in id order."""
    cols = [getattr(_TABLE.c, name) for name in _VIEW_COLUMNS]
    last_id = 0
    while True:
        query = select(*cols).where(_TABLE.c.team_id == team_id, _TABLE.c.id > last_id)
        if present_only:
            query = query.where(_TABLE.c.missing_since.is_(None))
        rows = session.exec(query.order_by(_TABLE.c.id).limit(CHUNK)).all()  # type: ignore[call-overload]
        if not rows:
            return
        for row in rows:
            view = SimpleNamespace(**dict(zip(_VIEW_COLUMNS, row)))
            last_id = view.id
            yield view


def refresh_decisions(session: Session, team_id: int, engine: PolicyEngine) -> int:
    """Re-evaluate every target of the team (after a policy, credential or settings change).  Returns how many
    decisions changed; only those rows are written."""
    changed = []
    for view in list(iter_views(session, team_id)):
        fresh = engine.evaluate(view).to_dict()
        if fresh != (view.decision or {}):
            changed.append({"_id": view.id, "_decision": fresh})
    if changed:
        stmt = update(_TABLE).where(_TABLE.c.id == bindparam("_id")).values(decision=bindparam("_decision"))
        for chunk in _chunks(changed):
            session.connection().execute(stmt, list(chunk))
    return len(changed)
