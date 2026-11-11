"""The repository inventory: an idempotent sync of what a connection can see into ``scmrepository``.

* Rows are keyed on (connection, provider id): a rename or a default-branch change updates the row; nothing is ever
  duplicated, however often a sync runs or whoever runs it.
* Only a COMPLETE listing marks unseen repositories removed (``removed_at``; never deleted, their scan history stays).
  A listing cut short (rate limit, error) is ``partial`` / ``failed`` and removes nothing; a removed repository that is
  seen again is restored.
* ``in_scope`` / ``scope_reason`` are recomputed from the connection's filters and the repository's manual override
  on every sync and every filter change (``filters.in_scope``).
* One runner at a time per connection: ``claim_sync`` is a compare-and-set lease on the connection row (30 minutes,
  so a crashed runner's lease can be taken over).
"""
from __future__ import annotations

import datetime as dt
import time
from typing import Any

from sqlalchemy import or_, update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import ScmConnection, ScmRepository
from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.scm import filters as F
from backend.utilities.scm.common import log
from backend.utilities.scm.providers import DiscoveredRepo, ScmError, provider_for_connection

SYNC_LEASE = dt.timedelta(minutes=30)
_META = ("full_name", "name", "owner", "web_url", "clone_url", "default_branch", "visibility", "archived", "fork",
         "language", "topics", "size_kb", "pushed_at")


def filters_of(connection: ScmConnection) -> F.RepoFilters:
    try:
        return F.parse(connection.filters)
    except ValueError:
        return F.RepoFilters()


def scope_for(row: ScmRepository, filters: F.RepoFilters) -> tuple[bool, str]:
    if row.removed_at is not None:
        return False, "removed"
    return F.in_scope(filter_input(row), filters, row.manual_state)


def filter_input(row: Any) -> dict[str, Any]:
    return {"full_name": row.full_name, "name": row.name, "archived": row.archived, "fork": row.fork,
            "topics": list(row.topics or []), "language": row.language, "visibility": row.visibility,
            "size_kb": row.size_kb}


def _apply_scope(row: ScmRepository, filters: F.RepoFilters) -> bool:
    ok, reason = scope_for(row, filters)
    if (row.in_scope, row.scope_reason) != (ok, reason):
        row.in_scope, row.scope_reason = ok, reason
        return True
    return False


def upsert_repo(session: Session, connection: ScmConnection, found: DiscoveredRepo, now: dt.datetime,
                filters: F.RepoFilters, existing: ScmRepository | None) -> tuple[ScmRepository, str]:
    """Insert or update one repository. Returns (row, "added" | "updated" | "restored" | "same")."""
    if existing is None:
        row = ScmRepository(team_id=connection.team_id, connection_id=connection.id, external_id=found.external_id,
                            first_seen_at=now, last_seen_at=now,
                            **{k: getattr(found, k) for k in _META})
        _apply_scope(row, filters)
        session.add(row)
        return row, "added"
    outcome = "same"
    if existing.removed_at is not None:
        existing.removed_at = None
        outcome = "restored"
    changed = False
    for key in _META:
        value = getattr(found, key)
        if getattr(existing, key) != value:
            setattr(existing, key, value)
            changed = True
    if changed:
        existing.row_version = (existing.row_version or 0) + 1
        outcome = "updated" if outcome == "same" else outcome
    existing.last_seen_at = now
    _apply_scope(existing, filters)
    session.add(existing)
    return existing, outcome


def claim_sync(session: Session, connection_id: int, now: dt.datetime) -> bool:
    won = session.exec(  # type: ignore[call-overload]
        update(ScmConnection)
        .where(ScmConnection.id == connection_id,
               or_(ScmConnection.sync_lease_until.is_(None), ScmConnection.sync_lease_until < now))
        .values(sync_lease_until=now + SYNC_LEASE, sync_status="running")
        .execution_options(synchronize_session=False)
    ).rowcount
    return won == 1


def sync_connection(engine: Engine, connection_id: int, *, provider: Any = None, now: dt.datetime | None = None,
                    max_wait_s: float | None = None, claim: bool = True) -> dict[str, Any]:
    """List every repository the connection can see and reconcile the inventory. Returns the summary it stores."""
    now = now or utcnow()
    started = time.monotonic()
    with Session(engine) as session:
        if claim:
            if not claim_sync(session, connection_id, now):
                return {"status": "busy"}
            session.commit()
        connection = session.get(ScmConnection, connection_id)
        if connection is None:
            return {"status": "missing"}
        built = provider is None
        status, error, reset_at = "ok", None, None
        found: dict[str, DiscoveredRepo] = {}
        prov = None
        try:
            prov = provider or provider_for_connection(connection, max_wait_s=max_wait_s)
            for repo in prov.iter_repos():
                found.setdefault(repo.external_id, repo)
        except ScmError as err:
            status = "partial" if err.kind == "rate_limited" else "failed"
            error, reset_at = str(err), err.reset_at
        except Exception as exc:  # never leave the lease held on an unexpected failure
            status, error = "failed", f"Discovery failed ({type(exc).__name__})"
            log("scm sync FAILED", connection=connection_id, error=type(exc).__name__)
        stats = dict(getattr(prov, "stats", {}) or {})
        if built and prov is not None:
            prov.close()

        filters = filters_of(connection)
        rows = session.exec(select(ScmRepository).where(ScmRepository.connection_id == connection_id)).all()
        existing = {r.external_id: r for r in rows}
        counts = {"added": 0, "updated": 0, "restored": 0, "removed": 0}
        for ext_id, repo in found.items():
            _row, outcome = upsert_repo(session, connection, repo, now, filters, existing.get(ext_id))
            if outcome != "same":
                counts[outcome] += 1
        if status == "ok":
            for ext_id, row in existing.items():
                if ext_id not in found and row.removed_at is None:
                    row.removed_at = now
                    _apply_scope(row, filters)
                    session.add(row)
                    counts["removed"] += 1
        session.flush()
        in_scope = sum(1 for r in session.exec(select(ScmRepository).where(
            ScmRepository.connection_id == connection_id, ScmRepository.in_scope == True)).all())  # noqa: E712
        summary = {"status": status, "discovered": len(found), "in_scope": in_scope, **counts,
                   "api_calls": stats.get("api_calls", 0), "pages": stats.get("pages", 0),
                   "retries": stats.get("retries", 0), "waits": stats.get("waits", 0),
                   "waited_s": stats.get("waited_s", 0.0), "rate_limit": stats.get("rate_limit"),
                   "rate_remaining": stats.get("rate_remaining"),
                   "duration_s": round(time.monotonic() - started, 3), "at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        connection.sync_status = status
        connection.last_sync_at = now
        connection.last_sync_summary = summary
        connection.last_sync_error = (error or None) and error[:500]
        connection.sync_lease_until = None
        connection.sync_requested_at = None
        interval = dt.timedelta(minutes=max(15, int(connection.sync_interval_min or 360)))
        connection.next_sync_at = reset_at + dt.timedelta(seconds=30) if reset_at else now + interval
        session.add(connection)
        session.commit()
    log("scm sync", connection=connection_id, status=status, discovered=len(found), **counts)
    return summary


def apply_filters(session: Session, connection_id: int, filters: F.RepoFilters) -> int:
    """Save a connection's filters and recompute ``in_scope`` for its repositories. Returns how many changed."""
    connection = session.get(ScmConnection, connection_id)
    if connection is None:
        return 0
    connection.filters = filters.model_dump(mode="json")
    session.add(connection)
    changed = 0
    for row in session.exec(select(ScmRepository).where(ScmRepository.connection_id == connection_id)).all():
        if _apply_scope(row, filters):
            session.add(row)
            changed += 1
    return changed


def set_manual_state(session: Session, *, team_id: int, repo_ids: list[int], state: str | None) -> int:
    """Pin repositories in or out of scope (``include`` / ``exclude``), or back to the filters (None)."""
    if state not in (None, "include", "exclude"):
        raise ValueError("state must be include, exclude or reset")
    rows = session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                    ScmRepository.id.in_(repo_ids))).all()  # type: ignore[union-attr]
    cache: dict[int, F.RepoFilters] = {}
    for row in rows:
        if row.connection_id not in cache:
            connection = session.get(ScmConnection, row.connection_id)
            cache[row.connection_id] = filters_of(connection) if connection else F.RepoFilters()
        row.manual_state = state
        _apply_scope(row, cache[row.connection_id])
        session.add(row)
    return len(rows)


__all__ = ["SYNC_LEASE", "apply_filters", "claim_sync", "filter_input", "filters_of", "scope_for", "set_manual_state",
           "sync_connection", "upsert_repo"]
