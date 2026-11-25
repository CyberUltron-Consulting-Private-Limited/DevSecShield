"""Moving the stored remediation plans and tickets onto their resource's group key, once, at deploy
(``q111remgroup001``; PR #499 rounds 3-4, ``remediation_group``).

Before ``remediation_group`` a plan or a Jira ticket of a resource two sources read was stored under the
source-scoped key of whichever row a view showed then (``identity.stable_key("node", <source uid>, ...)``).
``remediation_group.resolve`` finds such a record only through the copies a run reads; once that source is deleted, or
no longer read, the record is unreachable and "Create tickets" would open a second issue.  This backfill writes each
such resource's plan to its group key, so ``resolve`` finds it whatever is read later.

What it does, per team (one savepoint each, like ``identity_migration.migrate_all``):

1. the team's ``node`` assignments not already on a group key are the keys to place;
2. each key is mapped to the stored row it was made from: the team's collected rows are read newest job first (light
   columns; facts only for certificates and TLS endpoints, whose identities read them), its own key computed with the
   source uid the job snapshotted (a deleted source's jobs keep it), and the row's group key
   (``remediation_group.row_group_key``, with the job's scope) noted for every key wanted; the walk stops when every
   key is placed;
3. per group key, ``remediation_group.resolve`` over the copies picks the primary (the copy holding a ticket, else the
   first by key order: the precedence every surface already shows) and the ticket holder;
4. no record on the group key yet: one is INSERTED, a copy of the primary (wave, owner, target date, status, note,
   done time, created time, so time-to-remediate is kept) with the ticket of the ticket holder, and
   ``source_ref = "group-backfill:<the primary's key>"``.  A record already on the group key is the primary
   (``resolve``'s first rule) and is left as it is, except that a ticket a copy holds is filled in when it has none.

Nothing is lost or duplicated: the originals are kept unchanged (an older release still reads them), the group record
is the one every surface shows (it is what they already showed: the same primary), the Jira issue is the same one
(its key copied, its label still found by ``run_tickets``' search over every copy's label).  Idempotent: a group key
that holds a record is never inserted again (``ON CONFLICT DO NOTHING`` on ``(team_id, asset_key)`` too).

Downgrade (``reverse``): every record the backfill inserted (``source_ref`` "group-backfill:...") writes its current
plan and ticket back to the original it was copied from (so a change made after the upgrade is not lost to the older
release) and is deleted.  Records a user created on a group key after the upgrade stay (an older release never reads
them).
"""
from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

MARK = "group-backfill:"  # source_ref prefix of a record this backfill inserted; the rest is the original's key
_PLAN_FIELDS = ("wave", "owner", "target_date", "status", "note", "done_at")
_TICKET_FIELDS = ("ticket_key", "ticket_url", "ticket_state")


def _rows_by_key(session: Any, team_id: int, wanted: set[str]) -> dict[str, str | None]:
    """own key -> group key for every wanted key whose row is still stored (newest job first; stops when all are
    placed).  A key whose row was purged maps to nothing and is left alone."""
    from types import SimpleNamespace

    import sqlalchemy as sa
    from sqlmodel import select

    from backend.new_models import (
        CbomCollectedAsset,
        CbomCollectionJob,
        CbomCollectionSource,
        CbomScanNode,
    )
    from backend.utilities.cbom_sources import identity as ID
    from backend.utilities.cbom_sources import remediation_group as RG
    from backend.utilities.cbom_sources import resource_identity as RI

    out: dict[str, str | None] = {}
    if not wanted:
        return out
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    jobs = session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect")
        .order_by(CbomCollectionJob.id.desc())).all()  # type: ignore[union-attr]
    cols = (CbomCollectedAsset.id, CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type,
            CbomCollectedAsset.cdx_type, CbomCollectedAsset.target, CbomCollectedAsset.location)
    with_facts = sa.or_(CbomCollectedAsset.cdx_type == ID.CERT_CDX, CbomCollectedAsset.asset_type.in_(  # type: ignore
        ("certificate", "k8s_certificate", "tls_endpoint")))
    for job in jobs:
        source = sources.get(job.source_id or 0)
        ref = ID.job_source_ref(job, source)
        network, machine = RI.job_scope(job, nodes.get(job.node_id or 0), ref)
        scope = (CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id == job.id,
                 CbomCollectedAsset.asset_type != "coverage")
        for facts_too in (False, True):
            query = select(*cols, CbomCollectedAsset.facts).where(*scope, with_facts) if facts_too else \
                select(*cols).where(*scope, ~with_facts)
            for rec in session.exec(query).all():
                _aid, asset_key, kind, cdx, target, location = rec[:6]
                facts = (rec[6] if facts_too else None) or {}
                row = SimpleNamespace(asset_key=asset_key, asset_type=kind, cdx_type=cdx, target=target,
                                      location=location, facts=facts)
                own = ID.stable_key("node", ref, ID.node_identity(row))
                if own in wanted and own not in out:
                    out[own] = RG.row_group_key(kind, target, location, facts, network=network, machine=machine,
                                                cluster=ref)
        if len(out) == len(wanted):
            break
    return out


def backfill_team(session: Any, team_id: int) -> dict[str, int]:
    """Upgrade one team (module docstring, steps 1-4).  Returns its counts."""
    from sqlmodel import select

    from backend.new_models import CbomRemediationAssignment as A
    from backend.utilities.cbom_sources import remediation_group as RG

    found = {a.asset_key: a for a in session.exec(select(A).where(A.team_id == team_id, A.scope == "node")).all()}
    wanted = {k for k, a in found.items() if not str(a.source_ref or "").startswith(MARK)}
    placed = _rows_by_key(session, team_id, wanted)
    groups: dict[str, list[str]] = {}
    for own, group in placed.items():
        if group and group != own:
            groups.setdefault(group, []).append(own)
    out = {"groups": len(groups), "inserted": 0, "tickets_filled": 0, "kept": 0}
    for group, members in sorted(groups.items()):
        resolved = RG.resolve(found, [group], members, sorted(members)[0])
        held = found.get(group)
        if held is not None:  # the group key's record is the primary already; fill a missing ticket only
            if not held.ticket_key and resolved.ticket is not None:
                for name in _TICKET_FIELDS:
                    setattr(held, name, getattr(resolved.ticket, name))
                held.row_version = int(held.row_version or 1) + 1
                session.add(held)
                out["tickets_filled"] += 1
            else:
                out["kept"] += 1
            continue
        primary, ticket = resolved.assignment, resolved.ticket
        if primary is None:
            continue
        values = {"team_id": team_id, "asset_key": group, "scope": "node",
                  "source_ref": f"{MARK}{primary.asset_key}"[:255], "label": primary.label,
                  **{name: getattr(primary, name) for name in _PLAN_FIELDS},
                  **{name: getattr(ticket, name) if ticket is not None else None for name in _TICKET_FIELDS},
                  "updated_by_user_id": primary.updated_by_user_id, "row_version": 1,
                  "created_at": primary.created_at, "last_updated": primary.last_updated}
        if _insert(session, values):
            out["inserted"] += 1
    return out


def _insert(session: Any, values: dict[str, Any]) -> bool:
    from sqlalchemy.dialects import postgresql as pg_dialect
    from sqlalchemy.dialects import sqlite as sqlite_dialect

    from backend.new_models import CbomRemediationAssignment as A

    dialect = session.get_bind().dialect.name
    mod = pg_dialect if dialect == "postgresql" else sqlite_dialect
    result = session.exec(mod.insert(A).values(**values)  # type: ignore[call-overload]
                          .on_conflict_do_nothing(index_elements=["team_id", "asset_key"]))
    return bool(result.rowcount)


def reverse_team(session: Any, team_id: int) -> dict[str, int]:
    """Downgrade one team: each inserted record writes its plan and ticket back to its original, then goes."""
    from sqlmodel import select

    from backend.new_models import CbomRemediationAssignment as A

    out = {"restored": 0, "removed": 0}
    rows = session.exec(select(A).where(A.team_id == team_id, A.source_ref.startswith(MARK))).all()  # type: ignore
    for group_row in rows:
        origin_key = str(group_row.source_ref)[len(MARK):]
        origin = session.exec(select(A).where(A.team_id == team_id, A.asset_key == origin_key)).first()
        if origin is not None:
            for name in (*_PLAN_FIELDS, *_TICKET_FIELDS, "last_updated"):
                setattr(origin, name, getattr(group_row, name))
            origin.row_version = int(origin.row_version or 1) + 1
            session.add(origin)
            out["restored"] += 1
        session.delete(group_row)
        out["removed"] += 1
    return out


def backfill_all(connection: Any, *, reverse: bool = False, teams: Iterable[int] | None = None) -> dict[str, int]:
    """The deploy step: every team holding a node assignment, each in its own savepoint on the migration's
    connection; a team that fails is rolled back to its savepoint and logged (``resolve`` still finds its records
    through the copies a run reads, as before), so one team never blocks the deploy.  Re-running is harmless."""
    import sqlalchemy as sa
    from sqlmodel import Session

    from backend.new_models import CbomRemediationAssignment as A
    from backend.utilities.cbom_sources.common import log

    started = time.monotonic()
    found = sorted(t for (t,) in connection.execute(sa.select(A.team_id).where(A.scope == "node").distinct()).all())
    wanted = found if teams is None else [t for t in found if t in set(teams)]
    totals: dict[str, int] = {"teams": 0, "failed": 0}
    for team_id in wanted:
        point = connection.begin_nested()
        try:
            with Session(bind=connection) as session:  # joins the savepoint
                counts = reverse_team(session, team_id) if reverse else backfill_team(session, team_id)
                session.commit()
            point.commit()
        except Exception as exc:  # noqa: BLE001 - one team never blocks the deploy
            point.rollback()
            totals["failed"] += 1
            log("cbom remediation group backfill FAILED", team=team_id, reverse=reverse,
                error=type(exc).__name__)
            continue
        totals["teams"] += 1
        for k, v in counts.items():
            totals[k] = totals.get(k, 0) + v
        log("cbom remediation group backfill team", team=team_id, reverse=reverse, **counts)
    log("cbom remediation group backfill done", reverse=reverse, ms=int((time.monotonic() - started) * 1000),
        **totals)
    return totals


__all__ = ["MARK", "backfill_all", "backfill_team", "reverse_team"]
