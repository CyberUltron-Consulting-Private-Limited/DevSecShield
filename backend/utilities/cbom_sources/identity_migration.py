"""Moving the stored keys when the certificate identity changes (staging QA2 Q1-09, #497 review M1).

The certificate identity no longer reads a cloud certificate's free-text subject, and compares a subject stored as an
attribute map as the DN it denotes. That changes ``identity.stable_key("node", source_ref, ...)`` for those rows
only (``identity.rekeyed_observations``: never a DN-text certificate off the cloud, never a non-certificate row).
Two stores hold that key, and each follows it here, in the estate store's own write (``estate.record_run``), so the
first run after the change re-keys what it reads and nothing is read as removed and added:

* ``cbomestateobservation.observation_key`` (waves and estate links look observations up by it); an observation
  keyed ``obs:<key>`` (a certificate with no cross-source key) MOVES to ``obs:<new key>`` through the store's
  existing re-keying path (``alias_to_key`` -> ``EstateWrite.rekeyed``, never a removal);
* ``cbomremediationassignment.asset_key`` (owner, status, ticket of a finding), unless the new key already has one.

The risk register and its Q0 gaps are keyed by the estate key: an ``obs:`` key that moves is in ``EstateWrite.rekeyed``,
which their hooks already read (``q0register.on_estate_write``: the old item closes as moved, never as fixed).

The estate keys (#497 review M1). The CB-21 cross key of a certificate whose subject or issuer was stored as an
attribute map changed too (``asset_keys`` now reads the DN it denotes), and so did the ``obs:`` key of a certificate
with no cross key. ``migrate_source`` renames those estate rows IN PLACE from the source's STORED latest rows (the
stored spelling decides the old key, so a source last collected before #481 moves too): the asset row (its
``first_seen`` kept; merged into the new row when that exists, the earlier ``first_seen`` winning), its observations
(``asset_key`` and ``observation_key``), the risk register row, the open Q0 item ``asset:<key>`` and the estate links.
Nothing is removed or inserted, so the register and D13 keep their history.

When: ``backfill_due`` (the scheduler, at start, per team until done: every source's latest job, deleted ones too,
before any new run) and ``estate.record_run`` (each written source's stored rows first: a source the backfill has
not reached yet). Each source is locked as the store locks it.

Drift needs no migration: both runs of a comparison are keyed from their stored rows with the current rule.
Idempotent: a key already moved maps to nothing.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

BATCH = 500


def _chunks(items: list[str], size: int = BATCH):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def remap(session: Any, team_id: int, moves: Mapping[str, Mapping[str, str]]) -> dict[str, int]:
    """``moves``: source ref -> {old key: new key}. Updates both stores in the caller's transaction; returns how
    many rows of each moved."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateObservation, CbomRemediationAssignment

    out = {"observations": 0, "assignments": 0}
    pairs = {old: new for by_ref in moves.values() for old, new in by_ref.items() if old != new}
    if not pairs:
        return out
    eo = CbomEstateObservation.__table__
    for ref, by_ref in moves.items():
        stale: list[str] = []
        for chunk in _chunks(sorted(k[:40] for k, v in by_ref.items() if k != v)):  # one read; after the first
            stale += [k for (k,) in session.execute(sa.select(eo.c.observation_key).where(  # run, nothing is left
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key.in_(chunk))).all()]
        for old in sorted(set(stale)):
            out["observations"] += session.execute(sa.update(eo).where(
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key == old)
                .values(observation_key=by_ref[old][:40])).rowcount or 0
    ra = CbomRemediationAssignment.__table__
    olds = sorted(pairs)
    held: set[str] = set()
    for chunk in _chunks(sorted(set(pairs.values()))):
        held.update(k for (k,) in session.execute(sa.select(ra.c.asset_key).where(
            ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all())
    for chunk in _chunks(olds):
        for (key,) in session.execute(sa.select(ra.c.asset_key).where(
                ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all():
            new = pairs[key]
            if new in held:
                continue  # the new key already has its own assignment: the newer record wins, the old one stays put
            out["assignments"] += session.execute(sa.update(ra).where(
                ra.c.team_id == team_id, ra.c.asset_key == key).values(asset_key=new)).rowcount or 0
            held.add(new)
    return out


# ----------------------------------------------------------------------------- the estate keys (#497 review M1)
def _key(cross: Any, okey: str) -> str:
    """The estate key ``estate.record_run`` gives a row: its cross key when it has one, else ``obs:<okey>``."""
    return cross if isinstance(cross, str) and cross else "obs:" + okey


def estate_moves(rows: Any, ref: str) -> dict[str, str]:
    """``{stored estate key: estate key now}`` of one source's stored certificate rows whose key the identity rule
    changed (an attribute-map name; an ``obs:`` key of a cloud certificate)."""
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources import identity as ID

    out: dict[str, str] = {}
    for row in rows:
        if not ID.is_certificate(row):
            continue
        obs = AK.Observation(kind=str(row.asset_type or ""), facts=row.facts if isinstance(row.facts, dict) else {},
                             location=str(row.location or ""), target=str(row.target or ""),
                             cdx_type=str(row.cdx_type or ""), scope=ref)
        old = _key(AK.legacy_asset_key(obs), ID.stable_key("node", ref, ID.legacy_node_identity(row)))
        new = _key(AK.asset_key(obs), ID.stable_key("node", ref, ID.node_identity(row)))
        if old != new:
            out[old] = new
    return out


def _rename_asset(session: Any, team_id: int, ref: str, old: str, new: str) -> int:
    """Move ``ref``'s observation of ``old`` to ``new``; the asset row follows (or merges into ``new``'s); returns the
    observations moved. Keeps the earlier first-seen run and time."""
    import sqlalchemy as sa

    from backend.new_models import (CbomEstateAsset, CbomEstateLink, CbomEstateObservation, CbomQ0Gap,
                                    CbomRiskRegister)

    ea, eo, rr = CbomEstateAsset.__table__, CbomEstateObservation.__table__, CbomRiskRegister.__table__
    el, gq = CbomEstateLink.__table__, CbomQ0Gap.__table__
    mine = session.execute(sa.select(eo.c.id).where(eo.c.team_id == team_id, eo.c.asset_key == old,
                                                    eo.c.source_ref == ref)).first()
    if mine is None:
        return 0
    if session.execute(sa.select(eo.c.id).where(eo.c.team_id == team_id, eo.c.asset_key == new,
                                                eo.c.source_ref == ref)).first() is not None:
        session.execute(sa.delete(eo).where(eo.c.id == mine[0]))  # already observed under the new key
    else:
        session.execute(sa.update(eo).where(eo.c.id == mine[0]).values(asset_key=new))
    left = session.execute(sa.select(sa.func.count()).select_from(eo).where(
        eo.c.team_id == team_id, eo.c.asset_key == old)).scalar_one()
    old_row = session.execute(sa.select(ea).where(ea.c.team_id == team_id, ea.c.asset_key == old)).first()
    new_row = session.execute(sa.select(ea).where(ea.c.team_id == team_id, ea.c.asset_key == new)).first()
    if old_row is None:
        return 1
    if new_row is None and not left:  # the asset itself moves: every row keyed by it follows
        session.execute(sa.update(ea).where(ea.c.id == old_row.id).values(asset_key=new))
        if session.execute(sa.select(rr.c.id).where(rr.c.team_id == team_id, rr.c.item_key == new)).first() is None:
            session.execute(sa.update(rr).where(rr.c.team_id == team_id, rr.c.item_key == old).values(item_key=new))
        if session.execute(sa.select(gq.c.id).where(gq.c.team_id == team_id, gq.c.item_key == f"asset:{new}",
                                                    gq.c.closed_at.is_(None))).first() is None:
            session.execute(sa.update(gq).where(gq.c.team_id == team_id, gq.c.item_key == f"asset:{old}",
                                                gq.c.closed_at.is_(None)).values(item_key=f"asset:{new}"))
        session.execute(sa.update(el).where(el.c.team_id == team_id, el.c.asset_key == old).values(asset_key=new))
        return 1
    if new_row is None:  # another source still holds the old key: the new asset starts as a copy of it
        values = {c.name: getattr(old_row, c.name) for c in ea.columns if c.name != "id"}
        session.execute(sa.insert(ea).values(**{**values, "asset_key": new}))
        return 1
    if old_row.first_seen_at is not None and (new_row.first_seen_at is None
                                              or old_row.first_seen_at < new_row.first_seen_at):
        session.execute(sa.update(ea).where(ea.c.id == new_row.id).values(
            first_seen_at=old_row.first_seen_at, first_seen_run_id=old_row.first_seen_run_id))
    if not left:  # merged: the old asset row, its register row and its links go with it
        session.execute(sa.delete(ea).where(ea.c.id == old_row.id))
        session.execute(sa.delete(rr).where(rr.c.team_id == team_id, rr.c.item_key == old))
        session.execute(sa.update(el).where(el.c.team_id == team_id, el.c.asset_key == old).values(asset_key=new))
    return 1


def migrate_source(session: Any, team_id: int, ref: str, rows: Any) -> dict[str, int]:
    """Move every stored key of one source that the identity rule changed, from its STORED latest rows (#497 review
    M1); the caller holds the source's lock and commits. Idempotent: a moved key maps to nothing."""
    from backend.utilities.cbom_sources import identity as ID

    rows = [r for r in rows if r.asset_type != "coverage"]
    out = {"estate": 0, **remap(session, team_id, {ref: ID.rekeyed_observations(rows, ref)})}
    for old, new in estate_moves(rows, ref).items():
        out["estate"] += _rename_asset(session, team_id, ref, old, new)
    return out


MARK = "identity_migration_qa2:team:"  # cbomopscounter name prefix: a team whose stored keys all moved
_DONE: set[int] = set()  # teams this process saw done (no query per tick once everything moved)


def backfill_team(session: Any, team_id: int) -> dict[str, int]:
    """Every source of the team (deleted ones included), from its latest stored job, under the store's lock."""
    import sqlalchemy as sa

    from backend.new_models import CbomCollectedAsset, CbomEstateSource
    from backend.utilities.cbom_sources import estate as E

    es = CbomEstateSource.__table__
    sql = E._Sql(session)
    out = {"sources": 0, "estate": 0, "observations": 0, "assignments": 0}
    for ref, job_id, attempt in session.execute(sa.select(es.c.source_ref, es.c.latest_job_id, es.c.latest_attempt)
                                                .where(es.c.team_id == team_id).order_by(es.c.source_ref)).all():
        if not job_id:
            continue
        E._lock_source(session, sql, team_id, ref)
        rows = session.execute(sa.select(*E._ROW_COLUMNS).where(
            CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id == job_id,
            CbomCollectedAsset.attempt == (attempt or 1), sa.or_(
                CbomCollectedAsset.asset_type.in_(sorted(E.AK.CERT_TYPES)),  # type: ignore[attr-defined]
                CbomCollectedAsset.cdx_type == "certificate"))).all()
        found = migrate_source(session, team_id, ref, rows)
        out["sources"] += 1
        for k, v in found.items():
            out[k] = out.get(k, 0) + v
    return out


def backfill_due(engine: Any, now: Any = None, *, teams: int = 20) -> dict[str, int]:
    """The scheduler's one-off pass (at start, before any new run): up to ``teams`` teams not marked done, one
    transaction each, then marked done (``cbomopscounter``). Safe to run twice or in two processes: a key already
    moved maps to nothing, and each source is locked as the store locks it."""
    import sqlalchemy as sa
    from sqlmodel import Session

    from backend.new_models import CbomEstateSource, CbomOpsCounter
    from backend.utilities.cbom_sources.common import log, utcnow

    out = {"teams": 0, "estate": 0, "assignments": 0}
    with Session(engine) as session:
        all_teams = sorted(t for (t,) in session.execute(sa.select(CbomEstateSource.team_id).distinct()).all())
        marked = {n for (n,) in session.execute(sa.select(CbomOpsCounter.name).where(
            CbomOpsCounter.name.like(MARK + "%"))).all()}  # type: ignore[attr-defined]
    todo = [t for t in all_teams if t not in _DONE and f"{MARK}{t}" not in marked][:teams]
    _DONE.update(t for t in all_teams if f"{MARK}{t}" in marked)
    for team_id in todo:
        with Session(engine) as session:
            found = backfill_team(session, team_id)
            if session.get(CbomOpsCounter, f"{MARK}{team_id}") is None:
                session.add(CbomOpsCounter(name=f"{MARK}{team_id}", value=1, updated_at=now or utcnow()))
            session.commit()
        _DONE.add(team_id)
        out["teams"] += 1
        out["estate"] += found["estate"]
        out["assignments"] += found["assignments"]
        log("cbom sources identity keys moved", team=team_id, sources=found["sources"], estate=found["estate"],
            observations=found["observations"], assignments=found["assignments"])
    return out


__all__ = ["MARK", "backfill_due", "backfill_team", "estate_moves", "migrate_source", "remap"]
