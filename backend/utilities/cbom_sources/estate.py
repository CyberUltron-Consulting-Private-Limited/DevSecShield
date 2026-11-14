"""Per-team estate store (CB-20): one row per cross-source asset key with its latest observation per source.

Three tables (``new_models``):

* ``cbomestateasset`` (unique ``(team_id, asset_key)``): the asset's key (CB-21 ``asset_keys.asset_key``; an asset
  with no cross-source identity, or whose correlation is missing, is keyed ``obs:<observation key>`` and marked
  ``key_kind`` ``source`` / ``not_correlated``), its presence over all sources, first seen run.
* ``cbomestateobservation`` (unique ``(team_id, asset_key, source_ref)``): the asset as one source last read it (the
  row's per-job key ``row_key``, target, location, occurrences) and its presence there: ``present`` (read in the
  source's latest collection), ``not_read`` (the latest collection did not read it: under one of its coverage gaps,
  or the collection was incomplete or failed; the reason says which) or ``removed`` (a complete collection read the
  place and it was gone).
* ``cbomestatesource`` (unique ``(team_id, source_ref)``): the newest collect job written per source.

The latest observation of a source is the row ``(job, attempt, row_key)`` of ``cbomcollectedasset`` (unique per job
attempt): for a PRESENT observation the job is the source's latest job, otherwise the observation's ``seen_job_id``.
``latest_rows`` resolves the stored row ids (from which CB-19/CB-23 re-read the grade inputs: type, verdict, codes,
facts; the job's ``params.metadata`` is the metadata snapshot: exposure override, segment) for any set of keys in one
query per 500 keys; the API shows them.

Rules:

* Written ONCE per run, by ``record_run``, which ``drift.record_run_drift`` calls (through ``record_run_safely``)
  after it won the ``drift_at`` compare-and-set, in the same transaction (the caller commits) but inside a SAVEPOINT:
  a store error rolls back only the store's write (and its hooks'), is logged at ERROR, and marks the team's store
  stale (``cbomestateteam``) until ``backfill`` replays its runs; drift itself always commits, so one broken team never
  blocks drift recording, the scheduler's batch or ``/changes``.
* Hooks (``register_hook``; CB-23's risk register) run in that savepoint, exactly once per run. A hook registered
  ``atomic=True`` is all-or-nothing with the store: if it raises, the store's write and every hook's are rolled back
  together and the store is marked stale (so a register and the store never disagree; the backfill, run with hooks,
  repairs both). A plain hook runs in its own nested savepoint: if it raises, only its own writes are undone, it is
  logged at ERROR and the store's write stands.
* Only what changed is written (scale: 1.5M assets per team): a new key, an observation whose row, place or presence
  changed, the assets those touch, and one row per source. An asset re-read unchanged costs its key computation and
  one compare, no write.
* Presence follows the drift rules (``drift`` module docstring): only a complete (``job_comparable``) collection
  removes anything; what its coverage gaps cover is ``not_read`` with the gap's reason, never removed; an incomplete
  or failed collection makes the unseen ``not_read``.
* An observation whose asset key changed (a stronger key joined it, CB-21 ``correlate``) MOVES to the new key: the
  old observation row is deleted (and the old asset row when nothing is left), listed in ``EstateWrite.rekeyed``,
  never read as a removal.
* Per source, newest job wins: a source whose newer job is already written is skipped (a run finalised after a newer
  one changes nothing of that source), and its row is locked first (sources in one order), so concurrent
  finalisations serialise per source and re-running a run's write (``backfill``) changes nothing.
* No grading here, no per-row SELECT: one bulk read of the run's rows (or the rows drift already read), one read of
  the stored observations of each source the run wrote, batched writes of the changes.
* Retention (``protected_job_ids`` / ``prune_collected_assets``): pruning old collected rows never deletes the latest
  comparable job of any source, nor any row the store points at.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import logging
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
    CbomEstateSource,
    CbomEstateTeam,
)
from backend.utilities.cbom_sources import asset_keys as AK  # CB-21: the one cross-source identity module
from backend.utilities.cbom_sources import drift as D
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources.common import iso_z, log

PRESENCE = ("present", "not_read", "removed")
KEY_KINDS = ("cross", "source", "not_correlated")
BATCH = 500
_EO, _EA, _ES = CbomEstateObservation.__table__, CbomEstateAsset.__table__, CbomEstateSource.__table__
_ET = CbomEstateTeam.__table__
SOURCE_DELETED = "source deleted"
_ROW_COLUMNS = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.attempt,
                CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type, CbomCollectedAsset.cdx_type,
                CbomCollectedAsset.target, CbomCollectedAsset.location, CbomCollectedAsset.name,
                CbomCollectedAsset.algorithm, CbomCollectedAsset.facts, CbomCollectedAsset.created_at)
_PREFIX_BASIS = {"cert": "certificate", "ep": "endpoint", "cloud": "cloud"}


# ----------------------------------------------------------------------------- hooks (CB-23 registers here)
@dataclass
class EstateWrite:
    """What one run's write did; hooks get it with the session, inside the transaction.

    * ``source_refs``: the sources this run wrote (a source whose newer job was already written is not listed).
      Every PRESENT observation of these sources was re-read in this run, so its latest row is new
      (``latest_rows``): a consumer that grades rows re-grades the present assets of these sources
      (``present_keys``).
    * ``changed``: asset key -> its presence now, for every asset row this run inserted or whose presence changed.
    * ``rekeyed``: (old key, new key, source_ref) for observations that moved to a stronger key; ``removed_keys``:
      asset rows deleted because every observation moved away."""
    team_id: int
    run_id: int
    at: _dt.datetime
    counts: dict[str, int] = field(default_factory=dict)
    changed: dict[str, str] = field(default_factory=dict)
    rekeyed: list[tuple[str, str, str]] = field(default_factory=list)
    removed_keys: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)


Hook = Callable[[Session, EstateWrite], None]
HOOKS: list[tuple[Hook, bool]] = []  # (hook, atomic)
_LOG = logging.getLogger(__name__)


def register_hook(fn: Hook, *, atomic: bool = False) -> Hook:
    """Call ``fn(session, write)`` after each run's estate write, in the same transaction (once per run). ``atomic``:
    a failure undoes the store's write too and marks the store stale (see the module docstring)."""
    unregister_hook(fn)
    HOOKS.append((fn, atomic))
    return fn


def unregister_hook(fn: Hook) -> None:
    HOOKS[:] = [(h, a) for h, a in HOOKS if h is not fn]


def present_keys(session: Session, team_id: int, source_refs: Sequence[str], *, batch: int = 5_000
                 ) -> Iterable[str]:
    """The keys of the present observations of these sources, streamed in key order per source (keyset pages; a key
    two of the sources see is listed twice)."""
    for ref in source_refs:
        after = ""
        while True:
            keys = list(session.execute(sa.select(_EO.c.asset_key).where(
                _EO.c.team_id == team_id, _EO.c.source_ref == ref, _EO.c.presence == "present",
                _EO.c.asset_key > after).order_by(_EO.c.asset_key).limit(batch)).scalars())
            yield from keys
            if len(keys) < batch:
                break
            after = keys[-1]


# ----------------------------------------------------------------------------- raw batched SQL (no ORM per row)
class _Sql:
    """Batched statements on the session's own connection (same transaction): ``executemany`` on SQLite,
    ``execute_values`` / ``execute_batch`` on PostgreSQL. SQLAlchemy's per-row parameter processing cost more than
    the database work at 50k rows (CB-20 bench), so the store's few statement shapes are written out here."""

    def __init__(self, session: Session):
        self.pg = session.get_bind().dialect.name == "postgresql"
        self.cur = session.connection().connection.dbapi_connection.cursor()

    def ts(self, value: _dt.datetime | None) -> Any:
        if value is None or self.pg:
            return value
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")  # SQLAlchemy's SQLite DATETIME storage format

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def query(self, sql: str, params: Sequence[Any]) -> list[tuple]:
        self.cur.execute(self._q(sql), tuple(params))
        return list(self.cur.fetchall())

    def insert(self, table: str, columns: Sequence[str], rows: list[tuple], tail: str = "") -> None:
        if not rows:
            return
        head = f"INSERT INTO {table} ({', '.join(columns)}) VALUES "
        if self.pg:
            from psycopg2.extras import execute_values

            execute_values(self.cur, head + "%s " + tail, rows, page_size=1000)
        else:
            self.cur.executemany(head + f"({', '.join('?' for _ in columns)}) " + tail, rows)

    def many(self, sql: str, rows: list[tuple]) -> None:
        if not rows:
            return
        if self.pg:
            from psycopg2.extras import execute_batch

            execute_batch(self.cur, self._q(sql), rows, page_size=BATCH)
        else:
            self.cur.executemany(sql, rows)


def _chunks(items: Sequence[Any], size: int = BATCH) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _rows(session: Session, job: CbomCollectionJob) -> list[Any]:
    """One job attempt's stored rows, the columns the store and the keys need (no ORM objects)."""
    return list(session.execute(sa.select(*_ROW_COLUMNS).where(
        CbomCollectedAsset.team_id == job.team_id, CbomCollectedAsset.job_id == job.id,
        CbomCollectedAsset.attempt == job.attempts)).all())


def _observation(row: Any, ref: str) -> Any:
    """What CB-21 keys: the row as an ``Observation`` scoped to its source (a private or loopback endpoint address is
    one asset only within the source that saw it). Built directly: reading an ORM object attribute by attribute
    through ``asset_keys.observation`` cost more than the keys themselves (CB-20 bench)."""
    facts = row.facts if isinstance(row.facts, dict) else {}
    return AK.Observation(kind=str(row.asset_type or ""), facts=facts, location=str(row.location or ""),
                          target=str(row.target or ""), cdx_type=str(row.cdx_type or ""), scope=ref)


def _view(asset_type: str, target: str | None, location: str | None) -> D.View:
    return D.View(identity="", key="", label="", asset_type=asset_type, codes=frozenset(), impact=None,
                  quantum_vulnerable=None, finding=False, judged=False,
                  extra={"target": target or "", "location": location or ""})


@dataclass
class _Seen:
    row: Any  # the representative row (lowest per-job row key: stable from run to run)
    kind: str
    basis: str | None
    occurrences: int = 1


def _key_of(key: Any) -> tuple[str | None, str, str | None]:
    if isinstance(key, str) and key:
        return key, "cross", _PREFIX_BASIS.get(key.split(":", 1)[0])
    return None, ("not_correlated" if key is AK.NOT_CORRELATED else "source"), None


def _lock_source(session: Session, sql: _Sql, team_id: int, ref: str) -> Any:
    """The source's stored row, locked until commit (PostgreSQL; on SQLite the drift compare-and-set already holds
    the database write lock), or None."""
    q = sa.select(_ES.c.latest_job_id, _ES.c.latest_attempt, _ES.c.latest_run_id, _ES.c.latest_at).where(
        _ES.c.team_id == team_id, _ES.c.source_ref == ref)
    if sql.pg:
        q = q.with_for_update()
    return session.execute(q).first()


# ----------------------------------------------------------------------------- the per-run write
def record_run(session: Session, run: CbomCollectionRun, now: _dt.datetime, *,
               loaded: Mapping[int, list[Any]] | None = None, hooks: bool = True) -> EstateWrite:
    """Write ``run`` into the team's estate store (see the module docstring). ``loaded``: job id -> that job
    attempt's rows already read by the caller (drift), so they are not read twice. The caller commits."""
    t0 = time.perf_counter()
    team_id, run_id = run.team_id, int(run.id or 0)
    sql = _Sql(session)
    sources: dict[int, CbomCollectionSource] = D._sources(session, team_id)
    by_ref: dict[str, CbomCollectionJob] = {}
    for job in D._run_jobs(session, run):  # one job per source in a run; the newest wins if there are more
        by_ref[ID.job_source_ref(job, sources.get(job.source_id or 0))] = job
    write = EstateWrite(team_id=team_id, run_id=run_id, at=now)

    # 0. per source, newest job wins: lock the source row (sources in one order), skip one already written newer
    jobs: dict[str, tuple[CbomCollectionJob, Any]] = {}
    for ref in sorted(by_ref):
        job = by_ref[ref]
        prev = _lock_source(session, sql, team_id, ref)
        if prev is not None and prev[0] >= int(job.id or 0):
            continue
        jobs[ref] = (job, prev)
    write.source_refs = sorted(jobs)
    marks = {"sources": time.perf_counter()}

    # 1. what the run read: rows of its successful collections, keyed across sources
    job_rows: dict[str, list[Any]] = {}
    observed: list[Any] = []
    seen_rows: list[tuple[Any, str]] = []
    for ref, (job, _prev) in jobs.items():
        if job.status != "success":
            continue
        rows = loaded.get(int(job.id or 0)) if loaded else None
        rows = list(rows) if rows is not None else _rows(session, job)
        job_rows[ref] = rows
        for row in rows:
            if row.asset_type != "coverage":
                observed.append(_observation(row, ref))
                seen_rows.append((row, ref))
    marks["read"] = time.perf_counter()
    corr = AK.correlate_detail(observed)
    alias_to_key: dict[str, str] = {}
    groups_done: set[int] = set()
    seen: dict[tuple[str, str], _Seen] = {}
    for i, (row, ref) in enumerate(seen_rows):
        aliases = corr.aliases[i]
        if aliases and id(aliases) not in groups_done:
            groups_done.add(id(aliases))
            for alias in aliases:
                alias_to_key[alias] = corr.keys[i]
        key, kind, basis = _key_of(corr.keys[i])
        if key is None:
            key = "obs:" + ID.stable_key("node", ref, ID.node_identity(row))
        s = seen.get((key, ref))
        if s is None:
            seen[(key, ref)] = _Seen(row, kind, basis)
        else:
            s.occurrences += 1
            if row.asset_key < s.row.asset_key:
                s.row = row
    marks["keys"] = time.perf_counter()

    # 2. compare with the stored observations of each source written: insert new, update changed, settle the unseen
    inserts: list[tuple] = []
    updates: list[tuple] = []
    transitions: dict[tuple[str, str | None], list[tuple[int, tuple | None]]] = {}
    moved_ids: list[int] = []
    touched: dict[str, str | None] = {}  # asset key -> "present" (seen again or new), None (settle from its rows)
    stamp = sql.ts(now)
    by_source: dict[str, dict[str, _Seen]] = {}
    for (key, ref), s in seen.items():
        by_source.setdefault(ref, {})[key] = s
    for ref, (job, prev) in jobs.items():
        stored = {r[1]: r for r in sql.query(
            "SELECT id, asset_key, row_key, occurrences, presence, presence_reason, asset_type, target, location "
            "FROM cbomestateobservation WHERE team_id = ? AND source_ref = ?", (team_id, ref))}
        mine = by_source.get(ref, {})
        when = sql.ts(job.finished_at or job.created_at)
        for key, s in mine.items():
            row, old = s.row, stored.get(key)
            if old is None:
                inserts.append((team_id, key, ref, ID.stable_key("node", ref, ID.node_identity(row)), row.asset_key,
                                row.asset_type, row.target or None, (row.location or "")[:512], s.occurrences,
                                "present", None, job.id, row.attempt, run_id, when, run_id, run_id, stamp))
                touched[key] = "present"
            elif (old[2], old[3], old[4]) != (row.asset_key, s.occurrences, "present"):
                updates.append((ID.stable_key("node", ref, ID.node_identity(row)), row.asset_key, row.asset_type,
                                row.target or None, (row.location or "")[:512], s.occurrences, job.id, row.attempt,
                                run_id, when, run_id, stamp, old[0]))
                if old[4] != "present":
                    touched[key] = "present"
        # what the source did not see this time
        if job.status == "success":
            ok, why = D.job_comparable(job)
            gaps = D.job_gaps(job_rows.get(ref, ())) if ok else []
        else:
            ok, why, gaps = False, f"collection {job.status}", []
        for key, old in stored.items():
            if key in mine or old[4] == "removed":
                continue
            new_key = alias_to_key.get(key)
            if new_key is not None and new_key != key and new_key in mine:
                moved_ids.append(old[0])
                write.rekeyed.append((key, new_key, ref))
                touched.setdefault(key, None)
                continue
            if ok:
                gap = next((g for g in gaps if g.covers(_view(old[6], old[7], old[8]), listed=False)), None)
                presence, reason = ("not_read", gap.reason) if gap is not None else ("removed", None)
            else:
                presence, reason = "not_read", why
            reason = reason[:300] if reason else None
            if (presence, reason) == (old[4], old[5]):
                continue
            # leaving "present": it was last read in the source's previous latest job
            last = (prev[0], prev[1], prev[2], sql.ts(prev[3])) if old[4] == "present" and prev is not None else None
            transitions.setdefault((presence, reason), []).append((old[0], last))
            touched.setdefault(key, None)
    # a deleted source reads nothing any more: what it still had is "not read" ("source deleted"), never removed
    deleted_refs: list[str] = []
    for ref, source_id, job_id, attempt, last_run, last_at in session.execute(sa.select(
            _ES.c.source_ref, _ES.c.source_id, _ES.c.latest_job_id, _ES.c.latest_attempt, _ES.c.latest_run_id,
            _ES.c.latest_at).where(_ES.c.team_id == team_id, _ES.c.source_id.is_not(None),
                                   _ES.c.latest_status != "deleted")).all():
        if source_id in sources or ref in by_ref:
            continue
        deleted_refs.append(ref)
        for obs_id, key, presence in sql.query(
                "SELECT id, asset_key, presence FROM cbomestateobservation WHERE team_id = ? AND source_ref = ? "
                "AND presence != 'removed'", (team_id, ref)):
            last = (job_id, attempt, last_run, sql.ts(last_at)) if presence == "present" else None
            transitions.setdefault(("not_read", SOURCE_DELETED), []).append((obs_id, last))
            touched.setdefault(key, None)
    sql.many("UPDATE cbomestatesource SET latest_status = 'deleted', updated_at = ? WHERE team_id = ? AND "
             "source_ref = ?", [(stamp, team_id, ref) for ref in deleted_refs])
    obs_cols = ("team_id", "asset_key", "source_ref", "observation_key", "row_key", "asset_type", "target", "location",
                "occurrences", "presence", "presence_reason", "seen_job_id", "seen_attempt", "seen_run_id", "seen_at",
                "first_seen_run_id", "state_run_id", "updated_at")
    sql.insert("cbomestateobservation", obs_cols, inserts, "ON CONFLICT (team_id, asset_key, source_ref) DO NOTHING")
    sql.many("UPDATE cbomestateobservation SET observation_key = ?, row_key = ?, asset_type = ?, target = ?, "
             "location = ?, occurrences = ?, presence = 'present', presence_reason = NULL, seen_job_id = ?, "
             "seen_attempt = ?, seen_run_id = ?, seen_at = ?, state_run_id = ?, updated_at = ? WHERE id = ?", updates)
    for (presence, reason), items in transitions.items():
        sql.many("UPDATE cbomestateobservation SET presence = ?, presence_reason = ?, state_run_id = ?, updated_at = ? "
                 "WHERE id = ?", [(presence, reason, run_id, stamp, i) for i, last in items if last is None])
        sql.many("UPDATE cbomestateobservation SET presence = ?, presence_reason = ?, seen_job_id = ?, "
                 "seen_attempt = ?, seen_run_id = ?, seen_at = ?, state_run_id = ?, updated_at = ? WHERE id = ?",
                 [(presence, reason, *last, run_id, stamp, i) for i, last in items if last is not None])
    for chunk in _chunks(moved_ids):
        session.execute(sa.delete(_EO).where(_EO.c.id.in_(chunk)))
    marks["observations"] = time.perf_counter()

    # 3. the sources' rows: their newest job
    for ref, (job, prev) in jobs.items():
        src = sources.get(job.source_id or 0)
        kind = src.kind if src is not None else str((job.params or {}).get("kind") or "")
        values = (job.source_id, ID.job_source_name(job, src)[:255], kind[:32] or None, job.id, job.attempts or 1,
                  run_id, sql.ts(job.finished_at or job.created_at), str(job.status)[:16],
                  bool(job.status == "success" and D.job_comparable(job)[0]), stamp)
        if prev is None:
            sql.insert("cbomestatesource", ("team_id", "source_ref", "source_id", "source_name", "source_kind",
                                            "latest_job_id", "latest_attempt", "latest_run_id", "latest_at",
                                            "latest_status", "latest_comparable", "updated_at"),
                       [(team_id, ref, *values)])
        else:
            sql.many("UPDATE cbomestatesource SET source_id = ?, source_name = ?, source_kind = ?, latest_job_id = ?, "
                     "latest_attempt = ?, latest_run_id = ?, latest_at = ?, latest_status = ?, latest_comparable = ?, "
                     "updated_at = ? WHERE team_id = ? AND source_ref = ?", [(*values, team_id, ref)])

    # 4. the asset rows the changes touch: present ones upserted, the others' presence recomputed over every source
    present: list[tuple] = []
    done: set[str] = set()
    for (key, _ref), s in sorted(seen.items()):
        if touched.get(key) == "present" and key not in done:
            done.add(key)
            present.append((team_id, key, s.kind, s.basis, s.row.asset_type, ID.node_label(s.row)[:255], "present",
                            None, run_id, sql.ts(s.row.created_at), run_id, stamp))
    sql.insert("cbomestateasset", ("team_id", "asset_key", "key_kind", "key_basis", "asset_type", "label", "presence",
                                   "presence_reason", "first_seen_run_id", "first_seen_at", "updated_run_id",
                                   "updated_at"), present,
               "ON CONFLICT (team_id, asset_key) DO UPDATE SET presence = 'present', presence_reason = NULL, "
               "key_kind = excluded.key_kind, key_basis = excluded.key_basis, asset_type = excluded.asset_type, "
               "label = excluded.label, updated_run_id = excluded.updated_run_id, updated_at = excluded.updated_at")
    for a in present:
        write.changed[a[1]] = "present"
    seen_keys = {key for key, _ref in seen}
    _settle(session, sql, write, sorted(k for k, v in touched.items() if v is None and k not in seen_keys), now)
    marks["assets"] = time.perf_counter()

    write.counts = {"sources": len(jobs), "deleted_sources": len(deleted_refs), "seen": len(seen), "inserted": len(inserts), "updated": len(updates),
                    "moved": len(moved_ids), "assets_changed": len(write.changed),
                    "not_read": sum(1 for p in write.changed.values() if p == "not_read"),
                    "removed": sum(1 for p in write.changed.values() if p == "removed"),
                    "deleted": len(write.removed_keys)}
    if hooks:
        _run_hooks(session, write)
    phases, last_mark = {}, t0
    for name, at in marks.items():  # where the time went (the scale budget's evidence, CB-20)
        phases[f"{name}_ms"], last_mark = round(1000 * (at - last_mark)), at
    log("estate recorded", team=team_id, run=run_id, ms=round(1000 * (time.perf_counter() - t0)), **write.counts,
        **phases)
    return write


def _run_hooks(session: Session, write: EstateWrite) -> None:
    failed = 0
    for hook, atomic in list(HOOKS):
        if atomic:  # raises out of the store's savepoint: store and register are rolled back together
            hook(session, write)
            continue
        try:
            with session.begin_nested():
                hook(session, write)
        except Exception as exc:
            failed += 1
            _LOG.error("cbom estate hook %s failed for team %s run %s: %s", getattr(hook, "__name__", "hook"),
                       write.team_id, write.run_id, type(exc).__name__)
            log("estate hook FAILED", team=write.team_id, run=write.run_id, error=type(exc).__name__)
    write.counts["hook_errors"] = failed


def record_run_safely(session: Session, run: CbomCollectionRun, now: _dt.datetime, *,
                      loaded: Mapping[int, list[Any]] | None = None) -> EstateWrite | None:
    """``record_run`` inside a savepoint: on any error the store's write (and the hooks') is rolled back, logged at
    ERROR, the team's store is marked stale, and None is returned; the caller's own work (drift) stands."""
    try:
        with session.begin_nested():
            return record_run(session, run, now, loaded=loaded)
    except Exception as exc:
        _LOG.error("cbom estate write failed for team %s run %s: %s; the store is stale until the backfill",
                   run.team_id, run.id, type(exc).__name__)
        log("estate write FAILED", team=run.team_id, run=run.id, error=type(exc).__name__)
        mark_stale(session, run.team_id, int(run.id or 0), f"{type(exc).__name__} writing run #{run.id}", now)
        return None


def mark_stale(session: Session, team_id: int, run_id: int, reason: str, now: _dt.datetime) -> None:
    """Flag the team's store as having missed a run's write (keeps the FIRST missed run)."""
    row = session.exec(select(CbomEstateTeam).where(CbomEstateTeam.team_id == team_id)).first()
    if row is None:
        session.add(CbomEstateTeam(team_id=team_id, stale=True, stale_run_id=run_id, stale_reason=reason[:300],
                                   stale_at=now, updated_at=now))
    elif not row.stale:
        row.stale, row.stale_run_id, row.stale_reason, row.stale_at, row.updated_at = True, run_id, reason[:300], now, now
    session.flush()


def stale_status(session: Session, team_id: int) -> dict[str, Any] | None:
    row = session.exec(select(CbomEstateTeam).where(CbomEstateTeam.team_id == team_id,
                                                    CbomEstateTeam.stale.is_(True))).first()  # type: ignore[attr-defined]
    if row is None:
        return None
    return {"since_run_id": row.stale_run_id, "reason": row.stale_reason, "at": iso_z(row.stale_at)}


def _settle(session: Session, sql: _Sql, write: EstateWrite, keys: list[str], now: _dt.datetime) -> None:
    """Recompute the presence of assets the run did not see but whose observations changed (or moved away)."""
    if not keys:
        return
    team_id, run_id = write.team_id, write.run_id
    by_key: dict[str, list[Any]] = {k: [] for k in keys}
    current: dict[str, tuple] = {}
    for chunk in _chunks(keys):
        for obs in session.execute(sa.select(_EO.c.asset_key, _EO.c.presence, _EO.c.presence_reason,
                                             _ES.c.source_name).select_from(_EO.outerjoin(_ES, sa.and_(
                _ES.c.team_id == _EO.c.team_id, _ES.c.source_ref == _EO.c.source_ref))).where(
                _EO.c.team_id == team_id, _EO.c.asset_key.in_(chunk)).order_by(_EO.c.source_ref)).all():
            by_key[obs.asset_key].append(obs)
        current.update({k: (p, r) for k, p, r in session.execute(sa.select(
            _EA.c.asset_key, _EA.c.presence, _EA.c.presence_reason).where(
            _EA.c.team_id == team_id, _EA.c.asset_key.in_(chunk))).all()})
    changes: list[tuple] = []
    gone: list[str] = []
    for key, observations in by_key.items():
        if not observations:
            gone.append(key)
            continue
        if any(o.presence == "present" for o in observations):
            presence, reason = "present", None
        elif not_read := [o for o in observations if o.presence == "not_read"]:
            o = not_read[0]
            presence, reason = "not_read", (f"{o.source_name}: {o.presence_reason}" if o.source_name and
                                            o.presence_reason else o.presence_reason)
        else:
            presence, reason = "removed", None
        reason = reason[:300] if reason else None
        if current.get(key) != (presence, reason):
            changes.append((presence, reason, run_id, sql.ts(now), team_id, key))
            write.changed[key] = presence
    sql.many("UPDATE cbomestateasset SET presence = ?, presence_reason = ?, updated_run_id = ?, updated_at = ? "
             "WHERE team_id = ? AND asset_key = ?", changes)
    for chunk in _chunks(gone):
        session.execute(sa.delete(_EA).where(_EA.c.team_id == team_id, _EA.c.asset_key.in_(chunk)))
    write.removed_keys = [k for k in gone if k in current]


# ----------------------------------------------------------------------------- the latest stored rows
def latest_rows(session: Session, team_id: int, keys: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Per asset key: ``latest``, its latest observation over all sources (present observations first, then the
    newest job), and ``observations``, the same per source: the stored row id (``asset_id``:
    ``cbomcollectedasset.id``, where the grade inputs are re-read), ``job_id``, ``attempt``, ``run_id``,
    ``source_ref``, ``presence``, ``observed_at``. Two queries per 500 keys."""
    out: dict[str, dict[str, Any]] = {}
    for chunk in _chunks(list(keys)):
        rows = session.execute(sa.select(
            _EO.c.asset_key, _EO.c.source_ref, _EO.c.row_key, _EO.c.presence, _EO.c.seen_job_id, _EO.c.seen_attempt,
            _EO.c.seen_run_id, _EO.c.seen_at, _ES.c.latest_job_id, _ES.c.latest_attempt, _ES.c.latest_run_id,
            _ES.c.latest_at).select_from(_EO.outerjoin(_ES, sa.and_(
                _ES.c.team_id == _EO.c.team_id, _ES.c.source_ref == _EO.c.source_ref))).where(
            _EO.c.team_id == team_id, _EO.c.asset_key.in_(chunk))).all()
        pointers = []
        for r in rows:
            if r.presence == "present" and r.latest_job_id is not None:
                p = (r.latest_job_id, r.latest_attempt, r.latest_run_id, r.latest_at)
            else:
                p = (r.seen_job_id, r.seen_attempt, r.seen_run_id, r.seen_at)
            pointers.append((r, p))
        ids: dict[tuple, int] = {}
        wanted = sorted({(p[0], p[1], r.row_key) for r, p in pointers})
        for part in _chunks(wanted, 300):
            for i, job_id, attempt, row_key in session.execute(sa.select(
                    CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.attempt,
                    CbomCollectedAsset.asset_key).where(
                    CbomCollectedAsset.team_id == team_id,
                    sa.tuple_(CbomCollectedAsset.job_id, CbomCollectedAsset.attempt,
                              CbomCollectedAsset.asset_key).in_(part))).all():
                ids[(job_id, attempt, row_key)] = i
        for r, p in pointers:
            entry = {"source_ref": r.source_ref, "presence": r.presence, "asset_id": ids.get((p[0], p[1], r.row_key)),
                     "job_id": p[0], "attempt": p[1], "run_id": p[2], "observed_at": p[3]}
            item = out.setdefault(r.asset_key, {"observations": {}})
            item["observations"][r.source_ref] = entry
            best = item.get("latest")
            if best is None or (r.presence == "present", p[0] or 0) > (best["presence"] == "present",
                                                                         best["job_id"] or 0):
                item["latest"] = entry
    return out


# ----------------------------------------------------------------------------- backfill
def backfill(engine, now: _dt.datetime, *, team_id: int | None = None, hooks: bool = False) -> dict[str, int]:
    """Write every run whose drift is recorded, oldest first, each in its own transaction. Idempotent: a source whose
    job is already written is skipped, so it can be re-run or interrupted."""
    with Session(engine) as session:
        query = select(CbomCollectionRun.id).where(CbomCollectionRun.drift_at.is_not(None))  # type: ignore[union-attr]
        if team_id is not None:
            query = query.where(CbomCollectionRun.team_id == team_id)
        ids = list(session.exec(query.order_by(CbomCollectionRun.id)).all())
        stale_before = {t for t, in session.execute(sa.select(_ET.c.team_id).where(_ET.c.stale.is_(True))).all()}
    out = {"runs": 0, "sources": 0, "inserted": 0, "repaired_teams": 0}
    for run_id in ids:
        with Session(engine) as session:
            run = session.get(CbomCollectionRun, run_id)
            if run is None:
                continue
            write = record_run(session, run, now, hooks=hooks)
            session.commit()
        out["runs"] += 1
        out["sources"] += write.counts.get("sources", 0)
        out["inserted"] += write.counts.get("inserted", 0)
    with Session(engine) as session:  # every run of these teams is written: the stores are whole again
        query = sa.update(_ET).where(_ET.c.stale.is_(True), _ET.c.team_id.in_(stale_before))
        if team_id is not None:
            query = query.where(_ET.c.team_id == team_id)
        out["repaired_teams"] = int(session.execute(query.values(stale=False, repaired_at=now, updated_at=now))
                                    .rowcount or 0)
        session.commit()
    log("estate backfill", team=team_id, **out)
    return out


# ----------------------------------------------------------------------------- retention
def protected_job_ids(session: Session, team_id: int) -> set[int]:
    """Jobs whose rows retention must keep: the latest comparable collect job of every source (drift's baseline),
    and every job the store points at (each source's latest job, the last reading job of each observation that is
    not present any more)."""
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
    keep.update(session.execute(sa.select(_ES.c.latest_job_id).where(_ES.c.team_id == team_id)).scalars())
    keep.update(session.execute(sa.select(_EO.c.seen_job_id).where(  # a present one was read in its source's latest
        _EO.c.team_id == team_id, _EO.c.presence != "present").distinct()).scalars())
    return keep


def prune_collected_assets(session: Session, team_id: int, *, keep_runs: int) -> int:
    """Delete the collected rows of collect jobs outside the team's newest ``keep_runs`` runs, except protected jobs
    (``protected_job_ids``). Opt-in (``python -m backend.utilities.cbom_sources.estate prune``); nothing schedules
    it. The caller commits."""
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
    purged = purge_removed(session, team_id, before_run_id=min(recent))
    log("estate prune", team=team_id, jobs=len(old_jobs), rows=deleted, **purged)
    return deleted


def purge_removed(session: Session, team_id: int, *, before_run_id: int) -> dict[str, int]:
    """Drop what the store has known as ``removed`` since before ``before_run_id``: those observations, and the asset
    rows that are removed and have no observation left. Part of ``prune``. The caller commits."""
    obs = int(session.execute(sa.delete(_EO).where(_EO.c.team_id == team_id, _EO.c.presence == "removed",
                                                   _EO.c.state_run_id < before_run_id)).rowcount or 0)
    assets = int(session.execute(sa.delete(_EA).where(
        _EA.c.team_id == team_id, _EA.c.presence == "removed", _EA.c.updated_run_id < before_run_id,
        ~sa.exists().where(_EO.c.team_id == team_id, _EO.c.asset_key == _EA.c.asset_key))).rowcount or 0)
    return {"removed_observations": obs, "removed_assets": assets}


# ----------------------------------------------------------------------------- read side
def _public_pointer(entry: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    observed = entry.get("observed_at")
    if isinstance(observed, str):
        observed = _dt.datetime.fromisoformat(observed)
    return {"asset_id": entry["asset_id"], "job_id": entry["job_id"], "attempt": entry["attempt"],
            "run_id": entry["run_id"], "source_ref": entry["source_ref"], "observed_at": iso_z(observed)}


def public_asset(a: CbomEstateAsset, latest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    observations = (latest or {}).get("observations") or {}
    runs = [o["run_id"] for o in observations.values() if o.get("run_id") is not None]
    return {"asset_key": a.asset_key, "key_kind": a.key_kind, "key_basis": a.key_basis, "type": a.asset_type,
            "label": a.label, "presence": a.presence, "presence_reason": a.presence_reason,
            "latest": _public_pointer((latest or {}).get("latest")), "sources": len(observations),
            "first_seen_run_id": a.first_seen_run_id, "first_seen_at": iso_z(a.first_seen_at),
            "last_seen_run_id": max(runs, default=None), "updated_run_id": a.updated_run_id}


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
    latest = latest_rows(session, team_id, [a.asset_key for a in rows])
    return {"items": [public_asset(a, latest.get(a.asset_key)) for a in rows],
            "next": rows[-1].asset_key if more else None, "limit": limit, "stale": stale_status(session, team_id)}


def get_estate_asset(session: Session, team_id: int, asset_key: str) -> dict[str, Any] | None:
    asset = session.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == team_id,
                                                       CbomEstateAsset.asset_key == asset_key)).first()
    if asset is None:
        return None
    latest = latest_rows(session, team_id, [asset_key]).get(asset_key) or {}
    rows = session.execute(sa.select(_EO, _ES.c.source_id, _ES.c.source_name, _ES.c.source_kind).select_from(
        _EO.outerjoin(_ES, sa.and_(_ES.c.team_id == _EO.c.team_id, _ES.c.source_ref == _EO.c.source_ref))).where(
        _EO.c.team_id == team_id, _EO.c.asset_key == asset_key).order_by(_EO.c.source_ref)).all()
    observations = []
    for o in rows:
        ptr = _public_pointer((latest.get("observations") or {}).get(o.source_ref)) or {}
        observations.append({
            "source_ref": o.source_ref, "source_id": o.source_id, "source_name": o.source_name,
            "observation_key": o.observation_key, "asset_id": ptr.get("asset_id"), "job_id": ptr.get("job_id"),
            "attempt": ptr.get("attempt"), "run_id": ptr.get("run_id"), "observed_at": ptr.get("observed_at"),
            "type": o.asset_type, "presence": o.presence, "presence_reason": o.presence_reason,
            "first_seen_run_id": o.first_seen_run_id,
            "provenance": {"source_kind": o.source_kind, "target": o.target, "location": o.location,
                           "occurrences": o.occurrences, "row_key": o.row_key}})
    return {**public_asset(asset, latest), "observations": observations}


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


# CB-25: the crypto-agility classes on the store and the baseline per run are written by an estate hook (registered
# here, on this module's own HOOKS, so every record_run with hooks writes them; agility_store.heal fills the rest)
from backend.utilities.cbom_sources import agility_store as _AGILITY_STORE  # noqa: E402

register_hook(_AGILITY_STORE.on_estate_write)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

