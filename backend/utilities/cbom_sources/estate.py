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
import os
import threading
import time
from collections import OrderedDict
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
    # source_ref -> (job, attempt) it pointed at before this write, None for a new source (#352: a hook that brought
    # the source up to that job compares the new job's rows with it instead of every observation's own row)
    previous: dict[str, tuple[int, int] | None] = field(default_factory=dict)
    # staging QA2 Q1-09: stored per-source keys this write moved to the current identity (``identity_migration``)
    identity_moves: dict[str, int] = field(default_factory=dict)


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


# ----------------------------------------------------------------------------- keys, incrementally (CB-21 #205)
# Memory (CB-32, measured with bench/cb32_store_scale/index_memory.py): only observations that can correlate
# (certificates, endpoints, cloud resources) are kept; a key, library or setting has no link key, its asset key is
# per source by construction, and its observation key is recomputed each run. Kept per observation: CB-21's index
# entry, a 64-bit token hash, a 128-bit row id and a 20-byte observation key.
INDEX_BUDGET_MB = int(os.environ.get("CBOM_ESTATE_INDEX_MB", "512") or 512)  # per process, over all teams
BYTES_PER_INDEXED = 2_000  # RSS per correlating observation kept (index_memory.py: 1,893; tracemalloc ~1,450)


def index_capacity() -> int:
    """Correlating observations this process keeps indexed, over all teams (LRU by team)."""
    return max(0, INDEX_BUDGET_MB) * 2**20 // BYTES_PER_INDEXED


@dataclass
class _TeamIndex:
    """One team's correlation as of the last run this process keyed: CB-21's incremental ``CorrelationIndex`` over
    that run's correlating observations (id = (source_ref, 128-bit row id)), a hash of what decided each one's keys
    (``_token``), and its observation key (20 bytes)."""
    index: Any = field(default_factory=lambda: AK.CorrelationIndex())
    tokens: dict[tuple[str, Any], int] = field(default_factory=dict)
    okeys: dict[tuple[str, Any], bytes] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class _Keyed:
    keys: list[Any]  # asset key per row (str, None or NOT_CORRELATED)
    okeys: list[str]  # observation key per row
    alias_to_key: dict[str, str]  # every link key of a group -> the group's key (a stored key that moved)
    changed: int  # correlating rows whose key or aliases changed since the previous run (all of them when cold)
    mode: str = "index"  # index | full (no index kept: cold in a request, or over the memory budget)


_INDEXES: OrderedDict[int, _TeamIndex] = OrderedDict()
_INDEXES_LOCK = threading.Lock()


def _team_index(team_id: int, linked: int) -> _TeamIndex | None:
    """The team's index, made room for (``linked`` observations), or None when the team alone exceeds the budget
    (then it is keyed with a full correlation each run and nothing is kept)."""
    cap = index_capacity()
    with _INDEXES_LOCK:
        if linked > cap:
            _INDEXES.pop(team_id, None)
            return None
        entry = _INDEXES.pop(team_id, None) or _TeamIndex()
        total = sum(len(e.tokens) for e in _INDEXES.values()) + max(linked, len(entry.tokens))
        while _INDEXES and total > cap:
            _team, old = _INDEXES.popitem(last=False)
            total -= len(old.tokens)
        _INDEXES[team_id] = entry
        return entry


def _drop_index(team_id: int) -> None:
    with _INDEXES_LOCK:
        _INDEXES.pop(team_id, None)


def index_stats() -> dict[str, int]:
    with _INDEXES_LOCK:
        return {"teams": len(_INDEXES), "observations": sum(len(e.tokens) for e in _INDEXES.values()),
                "capacity": index_capacity()}


def _token(row: Any) -> int:
    """A hash of what decides a stored row's asset keys: exactly the inputs ``asset_keys._analyse`` reads (a
    certificate's ``_CERT_FIELDS``; otherwise kind, location, target, port, identity, cloud_resource; the scope is the
    source, part of the row's id). 64 bits: a collision would only delay re-keying that row to its next change."""
    facts = row.facts if isinstance(row.facts, dict) else {}
    kind = row.asset_type or ""
    if kind in AK.CERT_TYPES or row.cdx_type == "certificate":
        values: tuple = (0, *map(facts.get, AK._CERT_FIELDS))
    else:
        values = (1, kind, row.location or "", row.target or "", facts.get("port"), facts.get("identity"),
                  bool(facts.get("cloud_resource")))
    try:
        return hash(values)
    except TypeError:  # an unhashable fact value: its text decides
        return hash(repr(values))


def _linkless(row: Any) -> bool:
    """True when the row can never correlate: ``asset_keys._analyse`` answers ``_NOTHING`` for it (not a
    certificate, not an endpoint, no cloud id in its identity or location). Such a row's asset key is None (a
    per-source asset); ``test_cbom_cb32_index_memory`` pins this to ``_analyse``."""
    kind = row.asset_type or ""
    if kind in AK.CERT_TYPES or kind in AK.ENDPOINT_TYPES or row.cdx_type == "certificate":
        return False
    facts = row.facts if isinstance(row.facts, dict) else {}
    return not (AK._maybe_cloud(facts.get("identity")) or AK._maybe_cloud(row.location))


def _rid(row_key: str) -> Any:
    """128 bits of the row's per-job key (a sha256 hex): what identifies it within its source in the index."""
    try:
        return int(row_key[:32], 16) if len(row_key) >= 32 else row_key
    except ValueError:
        return row_key


def _in_request() -> bool:
    try:
        from backend.utilities.build_info import current_request_id
    except ImportError:  # pragma: no cover
        return False
    return current_request_id() is not None


def _warm(team_id: int) -> bool:
    with _INDEXES_LOCK:
        entry = _INDEXES.get(team_id)
        return entry is not None and bool(entry.tokens)


def _full(linked: Sequence[tuple[Any, str]]) -> tuple[list[Any], dict[str, str]]:
    corr = AK.correlate_detail([_observation(row, ref) for row, ref in linked])
    alias_to_key: dict[str, str] = {}
    for key, aliases in zip(corr.keys, corr.aliases):
        for alias in aliases:
            alias_to_key[alias] = key
    return list(corr.keys), alias_to_key


def _keys_for_run(team_id: int, seen_rows: Sequence[tuple[Any, str]]) -> _Keyed:
    """The asset key and observation key of each row of the run, equal to ``correlate_detail`` over the run's
    observations.

    * A row that can never correlate (``_linkless``) is keyed per source; its observation key is computed once per
      run (``observation_keys``) and nothing about it is kept.
    * Correlating rows go through the team's ``CorrelationIndex`` (CB-21): only rows whose key inputs changed since
      the team's previous run in this process are re-read, and only their components re-correlated; their
      observation keys are reused.
    * A cold index (a restarted process, an evicted team) is built in place; a large run is never keyed cold inside
      an HTTP request (``record_run_safely`` defers it to the scheduler). A team over the memory budget is keyed
      with ``correlate_detail`` every run and nothing is kept."""
    n = len(seen_rows)
    keys: list[Any] = [None] * n
    okeys: list[str] = [""] * n
    linked: list[int] = []
    plain: dict[str, list[int]] = {}
    for i, (row, ref) in enumerate(seen_rows):
        if _linkless(row):
            plain.setdefault(ref, []).append(i)
        else:
            linked.append(i)
    for ref, idx in plain.items():
        for i, okey in zip(idx, AK.observation_keys([seen_rows[i][0] for i in idx], ref)):
            okeys[i] = okey
    rows = [seen_rows[i] for i in linked]
    entry = _team_index(team_id, len(rows))
    if entry is None:
        full, alias_to_key = _full(rows)
        by_ref: dict[str, list[int]] = {}
        for j, i in enumerate(linked):
            keys[i] = full[j]
            by_ref.setdefault(seen_rows[i][1], []).append(i)
        for ref, idx in by_ref.items():
            for i, okey in zip(idx, AK.observation_keys([seen_rows[i][0] for i in idx], ref)):
                okeys[i] = okey
        return _Keyed(keys=keys, okeys=okeys, alias_to_key=alias_to_key, changed=len(rows), mode="full")
    with entry.lock:
        try:
            ids: list[tuple[str, Any]] = []
            changes: dict[tuple[str, Any], Any] = {}
            fresh: dict[str, list[tuple[tuple[str, Any], Any]]] = {}
            tokens, cached = entry.tokens, entry.okeys
            for row, ref in rows:
                oid = (ref, _rid(row.asset_key))
                ids.append(oid)
                token = _token(row)
                if tokens.get(oid) != token:
                    changes[oid] = _observation(row, ref)
                    tokens[oid] = token
                    fresh.setdefault(ref, []).append((oid, row))
                elif oid not in cached:
                    fresh.setdefault(ref, []).append((oid, row))
            current = set(ids)
            if len(current) != len(tokens):
                for oid in [o for o in tokens if o not in current]:
                    changes[oid] = None
                    del tokens[oid]
                    cached.pop(oid, None)
            changed = entry.index.update(changes) if changes else set()
            for ref, items in fresh.items():
                for (oid, _row), okey in zip(items, AK.observation_keys([r for _o, r in items], ref)):
                    cached[oid] = bytes.fromhex(okey)
            index = entry.index
            alias_to_key = {}
            groups: set[int] = set()
            for i, oid in zip(linked, ids):
                key = index.key(oid)
                keys[i] = key
                okeys[i] = cached[oid].hex()
                aliases = index.names(oid)  # as stored: iterated, never kept
                if aliases and id(aliases) not in groups:
                    groups.add(id(aliases))
                    for alias in aliases:
                        alias_to_key[alias] = key
            return _Keyed(keys=keys, okeys=okeys, alias_to_key=alias_to_key, changed=len(changed & current))
        except Exception:
            _drop_index(team_id)  # never reuse a half-updated index
            raise


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
               loaded: Mapping[int, list[Any]] | None = None, hooks: bool = True,
               replay: bool = False) -> EstateWrite:
    """Write ``run`` into the team's estate store (see the module docstring). ``loaded``: job id -> that job
    attempt's rows already read by the caller (drift), so they are not read twice. ``replay`` (``backfill``): a run
    with nothing left to write (every source already written at this job or a newer one) runs no hooks, so a replay
    never closes register gaps in the name of a run whose own write closed its gaps long ago (review 6030475121
    minor B: those closures would count in the run's report). The caller commits."""
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
    write.previous = {ref: (int(prev[0]), int(prev[1] or 1)) if prev is not None else None
                      for ref, (_job, prev) in jobs.items()}
    # 0b. #497 reviews 6038990137 M1 / 6057627810 M1: the keys the certificate identity rule changed move IN PLACE
    # before the store is read, driven by the stored observations' own rows (a source whose latest job failed too).
    # The deploy migration moved every team (``identity_migration.migrate_all``) and marked it with the highest job it
    # covered: only rows of later jobs (an older worker's write during a rolling deploy) are looked at here, one read.
    if write.previous:
        from backend.utilities.cbom_sources import identity_migration

        mark = identity_migration.mark_of(session, team_id)
        for k, v in identity_migration.migrate_team(session, team_id, refs=sorted(write.previous),
                                                    since_job=mark or 0, lock=False).items():
            if k != "sources":
                write.identity_moves[k] = write.identity_moves.get(k, 0) + v
    marks = {"sources": time.perf_counter()}

    # 1. what the run read: rows of its successful collections, keyed across sources
    job_rows: dict[str, list[Any]] = {}
    seen_rows: list[tuple[Any, str]] = []
    for ref, (job, _prev) in jobs.items():
        if job.status != "success":
            continue
        rows = loaded.get(int(job.id or 0)) if loaded else None
        rows = list(rows) if rows is not None else _rows(session, job)
        job_rows[ref] = rows
        for row in rows:
            if row.asset_type != "coverage":
                seen_rows.append((row, ref))
    marks["read"] = time.perf_counter()
    keyed = _keys_for_run(team_id, seen_rows)
    alias_to_key = keyed.alias_to_key
    # staging QA2 Q1-09: a key the current rows' spelling changed (a row first collected after #481 under its old
    # identity); the stored rows' own keys moved before the store was read (``identity_migration``, step 0b)
    moves = {ref: found for ref, rows in job_rows.items()
             if (found := ID.rekeyed_observations((r for r in rows if r.asset_type != "coverage"), ref))}
    if moves:
        from backend.utilities.cbom_sources import identity_migration

        for k, v in identity_migration.remap(session, team_id, moves).items():
            write.identity_moves[k] = write.identity_moves.get(k, 0) + v
    seen: dict[tuple[str, str], _Seen] = {}
    for i, (row, ref) in enumerate(seen_rows):
        key, kind, basis = _key_of(keyed.keys[i])
        if key is None:
            key = "obs:" + keyed.okeys[i]
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
    okey_of = {id(row): keyed.okeys[i] for i, (row, _ref) in enumerate(seen_rows)}
    for ref, (job, prev) in jobs.items():
        stored = {r[1]: r for r in sql.query(
            "SELECT id, asset_key, row_key, occurrences, presence, presence_reason, asset_type, target, location "
            "FROM cbomestateobservation WHERE team_id = ? AND source_ref = ?", (team_id, ref))}
        mine = by_source.get(ref, {})
        when = sql.ts(job.finished_at or job.created_at)
        for key, s in mine.items():
            row, old = s.row, stored.get(key)
            if old is None:
                inserts.append((team_id, key, ref, okey_of[id(row)], row.asset_key,
                                row.asset_type, row.target or None, (row.location or "")[:512], s.occurrences,
                                "present", None, job.id, row.attempt, run_id, when, run_id, run_id, stamp))
                touched[key] = "present"
            elif (old[2], old[3], old[4]) != (row.asset_key, s.occurrences, "present"):
                updates.append((okey_of[id(row)], row.asset_key, row.asset_type,
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

    write.counts = {"sources": len(jobs), "deleted_sources": len(deleted_refs), "seen": len(seen),
                    "rekeyed_rows": keyed.changed, "inserted": len(inserts), "updated": len(updates),
                    "moved": len(moved_ids), "assets_changed": len(write.changed),
                    "not_read": sum(1 for p in write.changed.values() if p == "not_read"),
                    "removed": sum(1 for p in write.changed.values() if p == "removed"),
                    "deleted": len(write.removed_keys)}
    if hooks and (jobs or not replay):
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


DEFER_MIN_ROWS = int(os.environ.get("CBOM_ESTATE_DEFER_ROWS", "5000") or 5000)
DEFERRED = "deferred to the scheduler"


def _defer(session: Session, run: CbomCollectionRun, loaded: Mapping[int, list[Any]] | None) -> bool:
    """A run of at least ``DEFER_MIN_ROWS`` rows recorded inside an HTTP request (``/changes`` records drift lazily)
    while this process has no key index for the team (a restarted API process): keying it cold re-reads every row
    (CB-21 analysis, ~2-4 s per 50k rows), so it is left to the scheduler, whose index is warm (CB-32)."""
    if not _in_request() or _warm(run.team_id):
        return False
    counted = sum(int(j.asset_count or 0) for j in D._run_jobs(session, run))
    return max(counted, sum(len(rows) for rows in (loaded or {}).values())) >= DEFER_MIN_ROWS


def record_run_safely(session: Session, run: CbomCollectionRun, now: _dt.datetime, *,
                      loaded: Mapping[int, list[Any]] | None = None) -> EstateWrite | None:
    """``record_run`` inside a savepoint: on any error the store's write (and the hooks') is rolled back, logged at
    ERROR, the team's store is marked stale, and None is returned; the caller's own work (drift) stands. A large run
    recorded in a request by a process with a cold key index is deferred: the store is marked stale ("deferred to the
    scheduler") and the scheduler's ``repair_due`` writes it, hooks included, within a tick."""
    if _defer(session, run, loaded):
        log("estate write deferred", team=run.team_id, run=run.id, reason="cold key index in a request")
        mark_stale(session, run.team_id, int(run.id or 0), f"run #{run.id} {DEFERRED}", now)
        return None
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
    """Flag the team's store as having missed a run's write (keeps the FIRST missed run). Every call bumps
    ``stale_marks``, so a repair that started before a later miss does not clear it (CB-32)."""
    row = session.exec(select(CbomEstateTeam).where(CbomEstateTeam.team_id == team_id)).first()
    if row is None:
        session.add(CbomEstateTeam(team_id=team_id, stale=True, stale_run_id=run_id, stale_reason=reason[:300],
                                   stale_at=now, updated_at=now, stale_marks=1))
    elif not row.stale:
        row.stale, row.stale_run_id, row.stale_reason, row.stale_at, row.updated_at = True, run_id, reason[:300], now, now
        row.stale_marks = (row.stale_marks or 0) + 1
    else:
        row.stale_run_id = min(row.stale_run_id or run_id, run_id)
        row.updated_at, row.stale_marks = now, (row.stale_marks or 0) + 1
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
        by_job: dict[tuple, set[str]] = {}
        for r, p in pointers:
            if p[0] is not None:
                by_job.setdefault((p[0], p[1]), set()).add(r.row_key)
        # one lookup per (job, attempt) through the unique (job_id, attempt, asset_key) index: an OR of 300
        # (job, attempt, key) triples per query cost more to plan than to run, and with a team_id condition PostgreSQL
        # could read the team's every row for each (#352). The team is checked on the rows instead.
        for (job_id, attempt), row_keys in sorted(by_job.items()):
            for i, team, row_key in session.execute(sa.select(
                    CbomCollectedAsset.id, CbomCollectedAsset.team_id, CbomCollectedAsset.asset_key).where(
                    CbomCollectedAsset.job_id == job_id, CbomCollectedAsset.attempt == attempt,
                    CbomCollectedAsset.asset_key.in_(sorted(row_keys)))).all():  # type: ignore[attr-defined]
                if team == team_id:
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
def backfill(engine, now: _dt.datetime, *, team_id: int | None = None, hooks: bool = False,
             since_run_id: int | None = None) -> dict[str, int]:
    """Write every run whose drift is recorded (from ``since_run_id`` on), oldest first, each in its own transaction.
    Idempotent: a source whose job is already written is skipped, so it can be re-run or interrupted."""
    with Session(engine) as session:
        query = select(CbomCollectionRun.id).where(CbomCollectionRun.drift_at.is_not(None))  # type: ignore[union-attr]
        if team_id is not None:
            query = query.where(CbomCollectionRun.team_id == team_id)
        if since_run_id is not None:
            query = query.where(CbomCollectionRun.id >= since_run_id)
        ids = list(session.exec(query.order_by(CbomCollectionRun.id)).all())
        stale_before = dict(session.execute(sa.select(_ET.c.team_id, _ET.c.stale_marks).where(
            _ET.c.stale.is_(True))).all())
    out = {"runs": 0, "sources": 0, "inserted": 0, "repaired_teams": 0}
    for run_id in ids:
        with Session(engine) as session:
            run = session.get(CbomCollectionRun, run_id)
            if run is None:
                continue
            write = record_run(session, run, now, hooks=hooks, replay=True)
            session.commit()
        out["runs"] += 1
        out["sources"] += write.counts.get("sources", 0)
        out["inserted"] += write.counts.get("inserted", 0)
    with Session(engine) as session:  # every run of these teams is written: the stores are whole again, unless a
        # write was missed again meanwhile (its mark count moved on: the next repair replays it)
        for team, marks in stale_before.items():
            if team_id is not None and team != team_id:
                continue
            out["repaired_teams"] += int(session.execute(sa.update(_ET).where(
                _ET.c.team_id == team, _ET.c.stale.is_(True), _ET.c.stale_marks == marks).values(
                stale=False, repaired_at=now, updated_at=now)).rowcount or 0)
        session.commit()
    log("estate backfill", team=team_id, **out)
    return out


def repair_due(engine, now: _dt.datetime, *, teams: int = 1) -> dict[str, int]:
    """Scheduler tick: write the runs a stale team's store missed (a deferred or failed write), hooks included, from
    its first missed run on; ``teams`` per tick, the team waiting longest since its mark or its last attempt first. A
    team whose repair fails is logged and moved to the back of the queue (its ``updated_at`` is the attempt), so one
    broken team never blocks the others (review 6032466269 major 2)."""
    with Session(engine) as session:
        stale = session.execute(sa.select(_ET.c.team_id, _ET.c.stale_run_id).where(_ET.c.stale.is_(True))
                                .order_by(sa.func.coalesce(_ET.c.updated_at, _ET.c.stale_at), _ET.c.team_id)
                                .limit(teams)).all()
    out = {"teams": 0, "runs": 0, "failed": 0}
    for team_id, since in stale:
        try:
            done = backfill(engine, now, team_id=team_id, hooks=True, since_run_id=since)
        except Exception as exc:  # noqa: BLE001 - the team stays stale; the next tick takes another team first
            out["failed"] += 1
            _LOG.error("cbom estate repair failed for team %s: %s; retried after the other stale teams", team_id,
                       type(exc).__name__)
            log("estate repair FAILED", team=team_id, since_run=since, error=type(exc).__name__)
            with Session(engine) as session:
                session.execute(sa.update(_ET).where(_ET.c.team_id == team_id, _ET.c.stale.is_(True))
                                .values(updated_at=now))
                session.commit()
            continue
        out["teams"] += done["repaired_teams"]
        out["runs"] += done["runs"]
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
    if source:  # a join walked in key order on (team_id, source_ref, asset_key), not a semi-join of the source (CB-32)
        query = query.join(CbomEstateObservation, sa.and_(
            CbomEstateObservation.team_id == CbomEstateAsset.team_id,
            CbomEstateObservation.asset_key == CbomEstateAsset.asset_key,
            CbomEstateObservation.source_ref == source))
        if after:
            query = query.where(CbomEstateObservation.asset_key > after)
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

