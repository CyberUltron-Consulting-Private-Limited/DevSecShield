"""Per-team estate store (CB-20): one row per cross-source asset key with its latest observation per source.

Two tables (``new_models``):

* ``cbomestateasset`` (unique ``(team_id, asset_key)``): the asset's key (CB-21 ``asset_keys.asset_key``; an asset
  with no cross-source identity, or whose correlation is missing, is keyed ``obs:<observation key>`` and marked
  ``key_kind`` ``source`` / ``not_correlated``), its presence over all sources, the LATEST stored row id
  (``latest_asset_id``: ``cbomcollectedasset.id``, from which CB-19/CB-23 re-read the grade inputs: type, verdict,
  codes, facts), that row's job (``latest_job_id``: the job's ``params.metadata`` is the metadata snapshot: exposure
  override, segment), first / last seen run.
* ``cbomestateobservation`` (unique ``(team_id, asset_key, source_ref)``): per source, the latest observation
  (``asset_id``, ``job_id``, ``run_id``, ``observed_at``, provenance: target, location, occurrences, source kind) and
  its presence: ``present`` (read in the source's latest collection), ``not_read`` (the latest collection did not
  read it: under one of its coverage gaps, or the collection was incomplete or failed; the reason says which) or
  ``removed`` (a complete collection read the place and it was gone).

Rules:

* Written ONCE per run, by ``record_run``, which ``drift.record_run_drift`` calls after it won the ``drift_at``
  compare-and-set, in the same transaction (the caller commits). Registered hooks (``register_hook``; CB-23's risk
  register) run in that transaction too, exactly once per run; a hook that raises rolls the whole recording back (the
  scheduler retries it), so the register never disagrees with the store.
* Presence follows the drift rules (``drift`` module docstring): only a complete (``job_comparable``) collection
  removes anything; what its coverage gaps cover is ``not_read`` with the gap's reason, never removed; an incomplete
  or failed collection makes the unseen ``not_read``.
* An observation whose asset key changed (a stronger key joined it, CB-21 ``correlate``) MOVES to the new key: the
  old observation row is deleted (and the old asset row when nothing is left), listed in ``EstateWrite.rekeyed``,
  never read as a removal.
* Order-safe: every row carries the run that last changed it (``state_run_id`` / ``updated_run_id``) and a write only
  changes rows last changed by the same or an older run, so two runs finalised concurrently or out of order end in
  the state of the newer one, and re-running a run's write (``backfill``) changes nothing.
* No grading here (CB-19's ``qgrade`` reads ``latest_asset_id``), and no per-row SELECT: one bulk read of the run's
  rows (or the rows drift already loaded), batched upserts, and one read of the source's rows the run did NOT see.
* Retention (``protected_job_ids`` / ``prune_collected_assets``): pruning old collected rows never deletes the latest
  comparable job of any source, nor any row the store points at.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

import sqlalchemy as sa
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomEstateObservation,
)
from backend.utilities.cbom_sources import drift as D
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources.common import log

try:  # CB-21 (#137): the one cross-source identity module
    from backend.utilities.cbom_sources import asset_keys as AK
except ImportError:  # pragma: no cover - until #137 lands (same signatures)
    from backend.utilities.cbom_sources import estate_keys_shim as AK  # type: ignore[no-redef]

PRESENCE = ("present", "not_read", "removed")
KEY_KINDS = ("cross", "source", "not_correlated")
BATCH = 500
_EO = CbomEstateObservation.__table__
_EA = CbomEstateAsset.__table__
_ROW_COLUMNS = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.attempt,
                CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type, CbomCollectedAsset.cdx_type,
                CbomCollectedAsset.target, CbomCollectedAsset.location, CbomCollectedAsset.name,
                CbomCollectedAsset.algorithm, CbomCollectedAsset.facts, CbomCollectedAsset.created_at)
_PREFIX_BASIS = {"cert": "certificate", "ep": "endpoint", "cloud": "cloud"}


# ----------------------------------------------------------------------------- hooks (CB-23 registers here)
@dataclass
class EstateWrite:
    """What one run's write did. Hooks get it with the session, inside the transaction. The assets the run saw are
    the rows with ``updated_run_id == run_id`` (``touched_keys``), so a 1.5M-asset run never builds a key list here;
    ``changed`` lists only the keys NOT seen this run whose presence changed (not_read / removed)."""
    team_id: int
    run_id: int
    at: _dt.datetime
    counts: dict[str, int] = field(default_factory=dict)
    changed: dict[str, str] = field(default_factory=dict)  # asset key -> new presence (keys not seen this run)
    rekeyed: list[tuple[str, str, str]] = field(default_factory=list)  # (old key, new key, source_ref)
    removed_keys: list[str] = field(default_factory=list)  # asset rows deleted (every observation moved away)
    source_refs: list[str] = field(default_factory=list)  # the sources this run wrote


Hook = Callable[[Session, EstateWrite], None]
HOOKS: list[Hook] = []


def register_hook(fn: Hook) -> Hook:
    """Call ``fn(session, write)`` after each run's estate write, in the same transaction (once per run)."""
    if fn not in HOOKS:
        HOOKS.append(fn)
    return fn


def unregister_hook(fn: Hook) -> None:
    if fn in HOOKS:
        HOOKS.remove(fn)


def touched_keys(session: Session, team_id: int, run_id: int, *, batch: int = 5_000) -> Iterable[str]:
    """The asset keys a run's write changed, streamed in key order (keyset pages)."""
    after = ""
    while True:
        keys = list(session.exec(select(CbomEstateAsset.asset_key).where(
            CbomEstateAsset.team_id == team_id, CbomEstateAsset.updated_run_id == run_id,
            CbomEstateAsset.asset_key > after).order_by(CbomEstateAsset.asset_key).limit(batch)).all())
        yield from keys
        if len(keys) < batch:
            return
        after = keys[-1]


# ----------------------------------------------------------------------------- helpers
def _insert(session: Session):
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert


def _chunks(items: Sequence[Any], size: int = BATCH) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _least(a, b):
    return sa.case((a.is_(None), b), (b.is_(None), a), (a <= b, a), else_=b)


def _greatest(a, b):
    return sa.case((a.is_(None), b), (b.is_(None), a), (a >= b, a), else_=b)


def _rows(session: Session, job: CbomCollectionJob) -> list[Any]:
    """One job attempt's stored rows, the columns the store and the keys need (no ORM objects)."""
    return list(session.execute(sa.select(*_ROW_COLUMNS).where(
        CbomCollectedAsset.team_id == job.team_id, CbomCollectedAsset.job_id == job.id,
        CbomCollectedAsset.attempt == job.attempts)).all())


def _view(asset_type: str, target: str | None, location: str | None) -> D.View:
    return D.View(identity="", key="", label="", asset_type=asset_type, codes=frozenset(), impact=None,
                  quantum_vulnerable=None, finding=False, judged=False,
                  extra={"target": target or "", "location": location or ""})


def _key_of(key: Any, row: Any, ref: str, obs_key: str) -> tuple[str, str, str | None]:
    """(estate key, key kind, key basis) of one observation."""
    if isinstance(key, str) and key:
        return key, "cross", _PREFIX_BASIS.get(key.split(":", 1)[0])
    return f"obs:{obs_key}", ("not_correlated" if key is AK.NOT_CORRELATED else "source"), None


@dataclass
class _Seen:
    row: Any
    ref: str
    obs_key: str
    kind: str
    basis: str | None
    job: CbomCollectionJob
    occurrences: int = 1


# ----------------------------------------------------------------------------- the per-run write
def record_run(session: Session, run: CbomCollectionRun, now: _dt.datetime, *,
               loaded: Mapping[int, list[Any]] | None = None, hooks: bool = True) -> EstateWrite:
    """Write ``run`` into the team's estate store (see the module docstring). ``loaded``: job id -> that job
    attempt's rows already read by the caller (drift), so they are not read twice. The caller commits."""
    t0 = time.perf_counter()
    team_id, run_id = run.team_id, int(run.id or 0)
    sources: dict[int, CbomCollectionSource] = D._sources(session, team_id)
    jobs: dict[str, CbomCollectionJob] = {}
    for job in D._run_jobs(session, run):  # one job per source in a run; the newest wins if there are more
        jobs[ID.job_source_ref(job, sources.get(job.source_id or 0))] = job
    write = EstateWrite(team_id=team_id, run_id=run_id, at=now, source_refs=sorted(jobs))

    # 1. what the run read: rows of its successful collections, keyed across sources
    job_rows: dict[str, list[Any]] = {}
    observed: list[Any] = []
    refs: list[str] = []
    for ref, job in jobs.items():
        if job.status != "success":
            continue
        rows = loaded.get(int(job.id or 0)) if loaded else None
        rows = list(rows) if rows is not None else _rows(session, job)
        job_rows[ref] = rows
        for row in rows:
            if row.asset_type != "coverage":
                observed.append(row)
                refs.append(ref)
    corr = AK.correlate_detail(observed)
    alias_to_key: dict[str, str] = {}
    seen_groups: set[int] = set()
    seen: dict[tuple[str, str], _Seen] = {}
    for i, row in enumerate(observed):
        ref = refs[i]
        aliases = corr.aliases[i]
        if aliases and id(aliases) not in seen_groups:
            seen_groups.add(id(aliases))
            for alias in aliases:
                alias_to_key[alias] = corr.keys[i]
        obs_key = ID.stable_key("node", ref, ID.node_identity(row))
        key, kind, basis = _key_of(corr.keys[i], row, ref, obs_key)
        old = seen.get((key, ref))
        if old is None:
            seen[(key, ref)] = _Seen(row, ref, obs_key, kind, basis, jobs[ref])
        else:
            old.occurrences += 1
            if row.id > old.row.id:
                old.row, old.obs_key = row, obs_key

    # 2. upsert the observations seen (sorted: concurrent writers lock rows in one order)
    obs_values = []
    for (key, ref), s in sorted(seen.items()):
        job, src = s.job, sources.get(s.job.source_id or 0)
        obs_values.append({
            "team_id": team_id, "asset_key": key, "source_ref": ref, "source_id": job.source_id,
            "source_name": ID.job_source_name(job, src)[:255], "observation_key": s.obs_key, "asset_id": s.row.id,
            "job_id": job.id, "run_id": run_id, "attempt": s.row.attempt, "observed_at": s.row.created_at,
            "asset_type": s.row.asset_type, "target": s.row.target, "location": (s.row.location or "")[:512],
            "provenance": {"source_kind": src.kind if src is not None else (job.params or {}).get("kind"),
                           "occurrences": s.occurrences, "cdx_type": s.row.cdx_type},
            "presence": "present", "presence_reason": None, "first_seen_run_id": run_id, "last_seen_run_id": run_id,
            "state_run_id": run_id, "updated_at": now})
    insert = _insert(session)
    if obs_values:
        stmt = insert(_EO)
        ex = stmt.excluded
        newer_row = _EO.c.job_id < ex.job_id  # a later observation (also from a run finalised out of order)
        newer_state = _EO.c.state_run_id <= ex.state_run_id  # no later run has decided the presence yet
        stmt = stmt.on_conflict_do_update(
            index_elements=["team_id", "asset_key", "source_ref"],
            set_={**{c: sa.case((newer_row, ex[c]), else_=_EO.c[c])
                     for c in ("source_id", "source_name", "observation_key", "asset_id", "job_id", "run_id",
                               "attempt", "observed_at", "asset_type", "target", "location", "provenance")},
                  **{c: sa.case((newer_state, ex[c]), else_=_EO.c[c])
                     for c in ("presence", "presence_reason", "state_run_id", "updated_at")},
                  "first_seen_run_id": _least(_EO.c.first_seen_run_id, ex.first_seen_run_id),
                  "last_seen_run_id": _greatest(_EO.c.last_seen_run_id, ex.last_seen_run_id)},
            where=sa.or_(newer_row, newer_state))
        for chunk in _chunks(obs_values):
            session.execute(stmt, list(chunk))

    # 3. what each source of the run did NOT see this time: moved, not read (gap / incomplete / failed) or removed
    unseen_changed: set[str] = set()
    moved_ids: list[int] = []
    updates: dict[tuple[str, str | None], list[int]] = {}
    for ref, job in jobs.items():
        if job.status == "success":
            ok, why = D.job_comparable(job)
            gaps = D.job_gaps(job_rows.get(ref, ())) if ok else []
        else:
            ok, why, gaps = False, f"collection {job.status}", []
        candidates = session.execute(sa.select(
            _EO.c.id, _EO.c.asset_key, _EO.c.asset_type, _EO.c.target, _EO.c.location, _EO.c.presence,
            _EO.c.presence_reason).where(
            _EO.c.team_id == team_id, _EO.c.source_ref == ref, _EO.c.state_run_id < run_id,
            _EO.c.presence != "removed")).all()
        for c in candidates:
            new_key = alias_to_key.get(c.asset_key)
            if new_key is not None and new_key != c.asset_key and (new_key, ref) in seen:
                moved_ids.append(c.id)
                write.rekeyed.append((c.asset_key, new_key, ref))
                unseen_changed.add(c.asset_key)
                continue
            if ok:
                gap = next((g for g in gaps if g.covers(_view(c.asset_type, c.target, c.location), listed=False)),
                           None)
                presence, reason = ("not_read", gap.reason) if gap is not None else ("removed", None)
            else:
                presence, reason = "not_read", why
            reason = reason[:300] if reason else reason
            if (presence, reason) != (c.presence, c.presence_reason):
                updates.setdefault((presence, reason), []).append(c.id)
                unseen_changed.add(c.asset_key)
    for chunk in _chunks(moved_ids):
        session.execute(sa.delete(_EO).where(_EO.c.id.in_(chunk), _EO.c.state_run_id < run_id))
    for (presence, reason), ids in updates.items():
        for chunk in _chunks(ids):
            session.execute(sa.update(_EO).where(_EO.c.id.in_(chunk), _EO.c.state_run_id < run_id).values(
                presence=presence, presence_reason=reason, state_run_id=run_id, updated_at=now))

    # 4. the asset rows: every key seen this run (present, latest row), then the unseen keys whose presence changed
    best: dict[str, _Seen] = {}
    for (key, _ref), s in seen.items():
        cur = best.get(key)
        if cur is None or s.row.id > cur.row.id:  # row ids grow with ingest: the newest stored row
            best[key] = s
    asset_values = [{
        "team_id": team_id, "asset_key": key, "key_kind": s.kind, "key_basis": s.basis,
        "asset_type": s.row.asset_type, "label": ID.node_label(s.row)[:255], "presence": "present",
        "presence_reason": None, "latest_asset_id": s.row.id, "latest_job_id": s.job.id, "latest_run_id": run_id,
        "latest_source_ref": s.ref, "observed_at": s.row.created_at, "first_seen_run_id": run_id,
        "last_seen_run_id": run_id, "first_seen_at": s.row.created_at, "last_seen_at": s.row.created_at,
        "updated_run_id": run_id, "updated_at": now} for key, s in sorted(best.items())]
    if asset_values:
        stmt = insert(_EA)
        ex = stmt.excluded
        newer_row = _EA.c.latest_asset_id < ex.latest_asset_id
        newer_state = _EA.c.updated_run_id <= ex.updated_run_id
        stmt = stmt.on_conflict_do_update(
            index_elements=["team_id", "asset_key"],
            set_={**{c: sa.case((newer_row, ex[c]), else_=_EA.c[c])
                     for c in ("key_kind", "key_basis", "asset_type", "label", "latest_asset_id", "latest_job_id",
                               "latest_run_id", "latest_source_ref", "observed_at")},
                  **{c: sa.case((newer_state, ex[c]), else_=_EA.c[c])
                     for c in ("presence", "presence_reason", "updated_run_id", "updated_at")},
                  "first_seen_run_id": _least(_EA.c.first_seen_run_id, ex.first_seen_run_id),
                  "first_seen_at": _least(_EA.c.first_seen_at, ex.first_seen_at),
                  "last_seen_run_id": _greatest(_EA.c.last_seen_run_id, ex.last_seen_run_id),
                  "last_seen_at": _greatest(_EA.c.last_seen_at, ex.last_seen_at)},
            where=sa.or_(newer_row, newer_state))
        for chunk in _chunks(asset_values):
            session.execute(stmt, list(chunk))
    _settle(session, write, sorted(unseen_changed - set(best)), now)

    write.counts = {"observations": len(obs_values), "assets": len(asset_values), "moved": len(moved_ids),
                    "not_read": sum(1 for p in write.changed.values() if p == "not_read"),
                    "removed": sum(1 for p in write.changed.values() if p == "removed"),
                    "deleted": len(write.removed_keys)}
    if hooks:
        for hook in list(HOOKS):
            hook(session, write)
    log("estate recorded", team=team_id, run=run_id, ms=round(1000 * (time.perf_counter() - t0)), **write.counts)
    return write


def _settle(session: Session, write: EstateWrite, keys: list[str], now: _dt.datetime) -> None:
    """Recompute the presence of assets the run did not see but whose observations changed (or moved away)."""
    if not keys:
        return
    team_id, run_id = write.team_id, write.run_id
    by_key: dict[str, list[Any]] = {k: [] for k in keys}
    for chunk in _chunks(keys):
        for obs in session.execute(sa.select(_EO.c.asset_key, _EO.c.presence, _EO.c.presence_reason,
                                             _EO.c.source_name).where(
                _EO.c.team_id == team_id, _EO.c.asset_key.in_(chunk))).all():
            by_key[obs.asset_key].append(obs)
    groups: dict[tuple[str, str | None], list[str]] = {}
    gone: list[str] = []
    for key, observations in by_key.items():
        if not observations:
            gone.append(key)
            continue
        present = [o for o in observations if o.presence == "present"]
        not_read = [o for o in observations if o.presence == "not_read"]
        if present:
            presence, reason = "present", None
        elif not_read:
            o = not_read[0]
            presence, reason = "not_read", (f"{o.source_name}: {o.presence_reason}" if o.source_name and
                                            o.presence_reason else o.presence_reason)
        else:
            presence, reason = "removed", None
        groups.setdefault((presence, reason[:300] if reason else None), []).append(key)
        if presence != "present":
            write.changed[key] = presence
    for (presence, reason), group in groups.items():
        for chunk in _chunks(group):
            session.execute(sa.update(_EA).where(
                _EA.c.team_id == team_id, _EA.c.asset_key.in_(chunk), _EA.c.updated_run_id <= run_id).values(
                presence=presence, presence_reason=reason, updated_run_id=run_id, updated_at=now))
    for chunk in _chunks(gone):
        session.execute(sa.delete(_EA).where(_EA.c.team_id == team_id, _EA.c.asset_key.in_(chunk),
                                             _EA.c.updated_run_id <= run_id))
    write.removed_keys = gone


# ----------------------------------------------------------------------------- backfill
def backfill(engine, now: _dt.datetime, *, team_id: int | None = None, hooks: bool = False) -> dict[str, int]:
    """Write every run whose drift is recorded, oldest first, each in its own transaction. Idempotent: a run already
    written changes nothing (``state_run_id`` / ``updated_run_id`` guards), so it can be re-run or interrupted."""
    with Session(engine) as session:
        query = select(CbomCollectionRun.id).where(CbomCollectionRun.drift_at.is_not(None))  # type: ignore[union-attr]
        if team_id is not None:
            query = query.where(CbomCollectionRun.team_id == team_id)
        ids = list(session.exec(query.order_by(CbomCollectionRun.id)).all())
    out = {"runs": 0, "observations": 0, "assets": 0}
    for run_id in ids:
        with Session(engine) as session:
            run = session.get(CbomCollectionRun, run_id)
            if run is None:
                continue
            write = record_run(session, run, now, hooks=hooks)
            session.commit()
        out["runs"] += 1
        out["observations"] += write.counts.get("observations", 0)
        out["assets"] += write.counts.get("assets", 0)
    log("estate backfill", team=team_id, **out)
    return out


# ----------------------------------------------------------------------------- retention
def protected_job_ids(session: Session, team_id: int) -> set[int]:
    """Jobs whose rows retention must keep: the latest comparable collect job of every source (drift's baseline),
    and every job the store points at (latest observation per source, latest row per asset)."""
    keep: set[int] = set()
    sources = D._sources(session, team_id)
    newest: dict[str, int] = {}
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.status == "success").order_by(CbomCollectionJob.id.desc())).all():  # type: ignore[union-attr]
        ref = ID.job_source_ref(job, sources.get(job.source_id or 0))
        if ref not in newest and D.job_comparable(job)[0]:
            newest[ref] = int(job.id or 0)
    keep.update(newest.values())
    keep.update(j for j in session.execute(sa.select(_EO.c.job_id).where(_EO.c.team_id == team_id).distinct())
                .scalars() if j is not None)
    keep.update(j for j in session.execute(sa.select(_EA.c.latest_job_id).where(_EA.c.team_id == team_id)
                                           .distinct()).scalars() if j is not None)
    return keep


def prune_collected_assets(session: Session, team_id: int, *, keep_runs: int) -> int:
    """Delete the collected rows of collect jobs outside the team's newest ``keep_runs`` runs, except protected jobs
    (``protected_job_ids``). Opt-in (the backfill command's ``prune``); nothing schedules it. The caller commits."""
    if keep_runs < 1:
        raise ValueError("keep_runs must be at least 1")
    recent = list(session.exec(select(CbomCollectionRun.id).where(CbomCollectionRun.team_id == team_id)
                               .order_by(CbomCollectionRun.id.desc()).limit(keep_runs)).all())  # type: ignore[union-attr]
    if len(recent) < keep_runs:
        return 0
    keep = protected_job_ids(session, team_id)
    old_jobs = [j for j in session.exec(select(CbomCollectionJob.id).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
        CbomCollectionJob.run_id < min(recent))).all() if j not in keep]  # type: ignore[operator]
    deleted = 0
    for chunk in _chunks(old_jobs):
        deleted += int(session.execute(sa.delete(CbomCollectedAsset.__table__).where(
            CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id.in_(chunk))).rowcount or 0)  # type: ignore[attr-defined]
    log("estate prune", team=team_id, jobs=len(old_jobs), rows=deleted)
    return deleted


# ----------------------------------------------------------------------------- read side
def public_asset(a: CbomEstateAsset) -> dict[str, Any]:
    from backend.utilities.cbom_sources.common import iso_z

    return {"asset_key": a.asset_key, "key_kind": a.key_kind, "key_basis": a.key_basis, "type": a.asset_type,
            "label": a.label, "presence": a.presence, "presence_reason": a.presence_reason,
            "latest": {"asset_id": a.latest_asset_id, "job_id": a.latest_job_id, "run_id": a.latest_run_id,
                       "source_ref": a.latest_source_ref, "observed_at": iso_z(a.observed_at)},
            "first_seen_run_id": a.first_seen_run_id, "last_seen_run_id": a.last_seen_run_id,
            "first_seen_at": iso_z(a.first_seen_at), "last_seen_at": iso_z(a.last_seen_at),
            "updated_run_id": a.updated_run_id}


def public_observation(o: CbomEstateObservation) -> dict[str, Any]:
    from backend.utilities.cbom_sources.common import iso_z

    return {"source_ref": o.source_ref, "source_id": o.source_id, "source_name": o.source_name,
            "observation_key": o.observation_key, "asset_id": o.asset_id, "job_id": o.job_id, "run_id": o.run_id,
            "attempt": o.attempt, "observed_at": iso_z(o.observed_at), "type": o.asset_type, "target": o.target,
            "location": o.location, "provenance": o.provenance or {}, "presence": o.presence,
            "presence_reason": o.presence_reason, "first_seen_run_id": o.first_seen_run_id,
            "last_seen_run_id": o.last_seen_run_id}


def list_estate(session: Session, team_id: int, *, after: str | None = None, limit: int = 200,
                source: str | None = None, asset_type: str | None = None, presence: str | None = None
                ) -> dict[str, Any]:
    """One keyset page of the team's estate in asset-key order (``next``: pass it as ``after``)."""
    query = select(CbomEstateAsset).where(CbomEstateAsset.team_id == team_id)
    if after:
        query = query.where(CbomEstateAsset.asset_key > after)
    if asset_type:
        query = query.where(CbomEstateAsset.asset_type == asset_type)
    if presence:
        query = query.where(CbomEstateAsset.presence == presence)
    if source:
        query = query.where(CbomEstateAsset.asset_key.in_(  # type: ignore[attr-defined]
            select(CbomEstateObservation.asset_key).where(CbomEstateObservation.team_id == team_id,
                                                          CbomEstateObservation.source_ref == source)))
    rows = list(session.exec(query.order_by(CbomEstateAsset.asset_key).limit(limit + 1)).all())
    more = len(rows) > limit
    rows = rows[:limit]
    return {"items": [public_asset(a) for a in rows], "next": rows[-1].asset_key if more else None, "limit": limit}


def get_estate_asset(session: Session, team_id: int, asset_key: str) -> dict[str, Any] | None:
    asset = session.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == team_id,
                                                       CbomEstateAsset.asset_key == asset_key)).first()
    if asset is None:
        return None
    observations = session.exec(select(CbomEstateObservation).where(
        CbomEstateObservation.team_id == team_id, CbomEstateObservation.asset_key == asset_key)
        .order_by(CbomEstateObservation.source_ref)).all()
    return {**public_asset(asset), "observations": [public_observation(o) for o in observations]}


# ----------------------------------------------------------------------------- command line
def main(argv: Sequence[str] | None = None) -> int:
    """``python -m backend.utilities.cbom_sources.estate backfill [--team N]`` (idempotent), or
    ``prune --team N --keep-runs K`` (deletes old collected rows; never the protected jobs)."""
    from backend.get_db import get_db
    from backend.utilities.cbom_sources.common import utcnow

    parser = argparse.ArgumentParser(prog="estate")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backfill", help="write every recorded run into the estate store (idempotent)")
    b.add_argument("--team", type=int, default=None)
    p = sub.add_parser("prune", help="delete collected rows of old runs, keeping protected jobs")
    p.add_argument("--team", type=int, required=True)
    p.add_argument("--keep-runs", type=int, required=True)
    args = parser.parse_args(argv)
    engine = get_db()
    if args.cmd == "backfill":
        print(backfill(engine, utcnow(), team_id=args.team))
        return 0
    with Session(engine) as session:
        print({"deleted": prune_collected_assets(session, args.team, keep_runs=args.keep_runs)})
        session.commit()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
