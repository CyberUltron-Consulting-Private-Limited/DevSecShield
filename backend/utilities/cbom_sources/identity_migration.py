"""Moving the stored keys when the certificate identity changes (staging QA2 Q1-09, #497 reviews 6038990137 M1 and
6057627810 M1 / M2 / m4).

The certificate identity no longer reads a cloud certificate's free-text subject (a certificate at a cloud resource
id is (target, id)), and compares every other subject and issuer as a normalised DN: an attribute map
(``{"CommonName": ...}``) as the DN it denotes, attribute order and spacing ignored. That changes the per-source
observation key (``identity.stable_key("node", ...)``) of those certificates and, for one with no cross-source key,
its ``obs:`` estate key; and the CB-21 cross key of a certificate whose name was stored as an attribute map
(``asset_keys`` reads the DN it denotes). Nothing else moves.

What drives the move: the store itself. Every estate observation names the collected row it was read from
(``seen_job_id`` / ``seen_attempt`` / ``row_key``), so its stored keys and the row they were computed from are read
together (one join per team), whatever the source's latest job is: a source whose latest collection failed, a
paused or deleted source, an observation now ``not_read`` all move. The source's latest job's rows add the
assignment keys of rows the store never wrote. A key moves only when the stored key IS the one the old rule gives
for that row, so nothing an alias or a later rule decided is touched; a moved key maps to nothing (idempotent).

How: set-based per team (review 6057627810 M2: per-certificate statements took 70 s for 4,000 certificates). The
keys are computed in Python, written to temporary tables, and each store is updated with a constant number of
statements: observation keys, the observations' estate keys (an observation whose new key the source already holds
is merged into it), the estate asset rows (renamed in place with their first seen kept; merged into an existing row,
the earlier first seen winning; copied when another source still holds the old key), risk register rows, open Q0
items, estate links and remediation assignments (owner, status such as ``accepted_risk``, ticket).

When: at deploy, in the database migration (``q109certkey001``, ``migrate_all``), before the release serves a request;
each team in its own savepoint, marked done with the highest job id it covered. Fallbacks, both idempotent:
``backfill_due`` (the scheduler: a team the migration could not move) and ``estate.record_run`` (``migrate_team`` for
the written sources, only for rows newer than the team's mark: an older worker's write during a rolling deploy).
The downgrade moves every key back (``reverse``) and clears the marks.

The identity rule is FROZEN here (``node_identity`` / ``legacy_node_identity``), so the migration computes the same
keys whatever a later release does to ``identity``; ``test_cbom_identity_qa2`` pins it equal to the live rule. It
reuses the DN parser (``asset_keys.norm_dn``), the cloud id reader and the cross key (``asset_keys``), which carry
``KEY_VERSION``: a change to those needs its own key migration anyway.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable, Mapping
from typing import Any

BATCH = 500
MARK = "identity_migration_qa2:team:"  # cbomopscounter name prefix; value: the highest job id the move covered
_DONE: set[int] = set()  # teams this process saw done (no query per tick once everything moved)


def _chunks(items: list[Any], size: int = BATCH):
    for start in range(0, len(items), size):
        yield items[start:start + size]


# ----------------------------------------------------------------------------- the frozen identity rule (m4)
def _norm(value: Any) -> str:
    return " ".join(str(value or "").split()).lower()


def _mapping_dn(value: Any) -> str | None:
    mapping: Any = value if isinstance(value, Mapping) else None
    if mapping is None and isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            mapping = json.loads(value)
        except ValueError:
            mapping = None
    if not isinstance(mapping, Mapping):
        return None
    from backend.utilities.cbom_sources.cert_estate import dn_from_mapping

    return dn_from_mapping(mapping) or None


def canonical_dn(value: Any) -> str:
    """An attribute map as its DN, then the DN order- and spacing-insensitive (``asset_keys.norm_dn``)."""
    from backend.utilities.cbom_sources.asset_keys import norm_dn

    return norm_dn(_mapping_dn(value) or value)


def _is_certificate(row: Any) -> bool:
    return row.cdx_type == "certificate" or row.asset_type in ("certificate", "k8s_certificate")


def legacy_node_identity(row: Any) -> str:
    """Before Q1-09: free-text subject and issuer, also for a cloud certificate."""
    facts = row.facts if isinstance(row.facts, dict) else {}
    if _is_certificate(row) and (facts.get("subject") or facts.get("issuer")):
        return "|".join(("cert", _norm(row.target), _norm(row.location), _norm(facts.get("subject")),
                         _norm(facts.get("issuer"))))
    return "key|" + str(row.asset_key)


def node_identity(row: Any) -> str:
    """Q1-09: a cloud certificate is (target, resource id); any other compares canonical DNs."""
    facts = row.facts if isinstance(row.facts, dict) else {}
    if _is_certificate(row) and (facts.get("subject") or facts.get("issuer")):
        from backend.utilities.cbom_sources.asset_keys import cloud_resource_id

        if cloud_resource_id(row.location):
            return "|".join(("cert", _norm(row.target), _norm(row.location)))
        return "|".join(("cert", _norm(row.target), _norm(row.location), canonical_dn(facts.get("subject")),
                         canonical_dn(facts.get("issuer"))))
    return "key|" + str(row.asset_key)


def _node_key(ref: str, identity: str) -> str:
    return hashlib.sha256(f"node|{ref}|{identity}".encode("utf-8", "replace")).hexdigest()[:40]


def _key(cross: Any, okey: str) -> str:
    """The estate key ``estate.record_run`` gives a row: its cross key when it has one, else ``obs:<okey>``."""
    return cross if isinstance(cross, str) and cross else "obs:" + okey


def keys_of(row: Any, ref: str) -> tuple[str, str, str, str] | None:
    """``(old observation key, new observation key, old estate key, new estate key)`` of one certificate row, or None
    when the rule changed neither."""
    if not _is_certificate(row):
        return None
    from backend.utilities.cbom_sources import asset_keys as AK

    old_o, new_o = _node_key(ref, legacy_node_identity(row)), _node_key(ref, node_identity(row))
    obs = AK.Observation(kind=str(row.asset_type or ""), facts=row.facts if isinstance(row.facts, dict) else {},
                         location=str(row.location or ""), target=str(row.target or ""),
                         cdx_type=str(row.cdx_type or ""), scope=ref)
    old_e, new_e = _key(AK.legacy_asset_key(obs), old_o), _key(AK.asset_key(obs), new_o)
    if old_o == new_o and old_e == new_e:
        return None
    return old_o, new_o, old_e, new_e


# ----------------------------------------------------------------------------- the current rows' spelling
def remap(session: Any, team_id: int, moves: Mapping[str, Mapping[str, str]]) -> dict[str, int]:
    """``moves``: source ref -> {old observation key: new}. A row first collected after #481 under its old identity
    (``estate.record_run`` step 1): the observation keys and the assignments follow. Returns the rows moved."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateObservation

    out = {"observations": 0, "assignments": 0}
    eo = CbomEstateObservation.__table__
    for ref, by_ref in moves.items():
        stale: list[str] = []
        for chunk in _chunks(sorted(k[:40] for k, v in by_ref.items() if k != v)):  # one read; once the stored keys
            stale += [k for (k,) in session.execute(sa.select(eo.c.observation_key).where(  # moved, nothing is left
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key.in_(chunk))).all()]
        for old in sorted(set(stale)):
            out["observations"] += session.execute(sa.update(eo).where(
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key == old)
                .values(observation_key=by_ref[old][:40])).rowcount or 0
    pairs = {old: new for by_ref in moves.values() for old, new in by_ref.items() if old != new}
    out["assignments"] = _move_assignments(session, team_id, pairs)
    return out


def _move_assignments(session: Any, team_id: int, pairs: Mapping[str, str]) -> int:
    """Assignments keyed by an old key move to the new one, unless the new key already has one (the newer record
    wins, the old one stays put). Two reads and one update per 500 keys."""
    import sqlalchemy as sa

    from backend.new_models import CbomRemediationAssignment

    if not pairs:
        return 0
    ra = CbomRemediationAssignment.__table__
    held: set[str] = set()
    for chunk in _chunks(sorted(set(pairs.values()))):
        held.update(k for (k,) in session.execute(sa.select(ra.c.asset_key).where(
            ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all())
    todo: dict[str, str] = {}
    for chunk in _chunks(sorted(pairs)):
        for (key,) in session.execute(sa.select(ra.c.asset_key).where(
                ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all():
            new = pairs[key]
            if new not in held:
                todo[key] = new
                held.add(new)
    moved = 0
    for chunk in _chunks(sorted(todo)):
        moved += session.execute(sa.update(ra).where(ra.c.team_id == team_id, ra.c.asset_key.in_(chunk)).values(
            asset_key=sa.case({k: todo[k] for k in chunk}, value=ra.c.asset_key))).rowcount or 0
    return moved


# ----------------------------------------------------------------------------- one team, set-based
def _stored(session: Any, team_id: int, refs: Iterable[str] | None, since_job: int) -> tuple[list[Any], list[Any]]:
    """(the team's certificate observations joined to the rows they were read from; the certificate rows of each
    source's latest job), restricted to ``refs`` and to jobs after ``since_job``."""
    import sqlalchemy as sa

    from backend.new_models import CbomCollectedAsset, CbomEstateObservation, CbomEstateSource

    eo, ca, es = CbomEstateObservation.__table__, CbomCollectedAsset.__table__, CbomEstateSource.__table__
    certs = sa.or_(ca.c.asset_type.in_(("certificate", "k8s_certificate")), ca.c.cdx_type == "certificate")
    row_cols = (ca.c.asset_type, ca.c.cdx_type, ca.c.target, ca.c.location, ca.c.facts, ca.c.asset_key)
    q = (sa.select(eo.c.id, eo.c.source_ref, eo.c.observation_key, eo.c.asset_key.label("estate_key"), eo.c.presence,
                   *row_cols)
         .select_from(eo.join(ca, sa.and_(ca.c.team_id == eo.c.team_id, ca.c.job_id == eo.c.seen_job_id,
                                          ca.c.attempt == eo.c.seen_attempt, ca.c.asset_key == eo.c.row_key)))
         .where(eo.c.team_id == team_id, certs))
    latest = (sa.select(es.c.source_ref, *row_cols)
              .select_from(es.join(ca, sa.and_(ca.c.team_id == es.c.team_id, ca.c.job_id == es.c.latest_job_id,
                                               ca.c.attempt == sa.func.coalesce(es.c.latest_attempt, 1))))
              .where(es.c.team_id == team_id, certs))
    if since_job:
        q, latest = q.where(eo.c.seen_job_id > since_job), latest.where(es.c.latest_job_id > since_job)
    if refs is not None:
        refs = sorted(refs)
        q, latest = q.where(eo.c.source_ref.in_(refs)), latest.where(es.c.source_ref.in_(refs))
    return session.execute(q).all(), session.execute(latest).all()


def _pg(session: Any) -> bool:
    return session.get_bind().dialect.name == "postgresql"


def _temp(session: Any, name: str, columns: str, rows: list[dict[str, Any]]) -> None:
    """A temporary table holding ``rows`` (a multi-row INSERT, batched by SQLAlchemy), analysed on PostgreSQL so the
    updates below join it by key."""
    import sqlalchemy as sa

    session.execute(sa.text(f"CREATE TEMPORARY TABLE {name} ({columns})"))
    if rows:
        table = sa.table(name, *(sa.column(k) for k in rows[0]))
        for chunk in _chunks(rows, 5000):
            session.execute(sa.insert(table).values(chunk))
    if _pg(session):
        session.execute(sa.text(f"ANALYZE {name}"))


def _set_from(session: Any, target: str, column: str, value: str, temp: str, on: str, where: str,
              params: dict[str, Any] | None = None) -> int:
    """``UPDATE target SET column = <temp row's value>`` for the target rows ``on`` matches: ``UPDATE … FROM`` on
    PostgreSQL (one hash join), a correlated sub-select on SQLite. ``on`` / ``where`` name the target ``x`` and the
    temporary table ``t``."""
    import sqlalchemy as sa

    if _pg(session):
        sql = f"UPDATE {target} x SET {column} = {value} FROM {temp} t WHERE {on} AND {where}"
    else:
        sql = (f"UPDATE {target} AS x SET {column} = (SELECT {value} FROM {temp} t WHERE {on} AND {where}) "
               f"WHERE EXISTS (SELECT 1 FROM {temp} t WHERE {on} AND {where})")
    return session.execute(sa.text(sql), params or {}).rowcount or 0


def migrate_team(session: Any, team_id: int, *, refs: Iterable[str] | None = None, since_job: int = 0,
                 reverse: bool = False, lock: bool = True) -> dict[str, int]:
    """Move every stored key of the team (``refs``: those sources only; ``since_job``: rows of later jobs only) that
    the identity rule changed; set-based. ``lock``: lock the team's stored sources as the store does (the migration;
    ``record_run`` already holds them). The caller commits. Returns what moved."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateSource

    out = {"sources": 0, "estate": 0, "observations": 0, "assignments": 0}
    es = CbomEstateSource.__table__
    if lock:
        q = sa.select(es.c.source_ref).where(es.c.team_id == team_id).order_by(es.c.source_ref)
        if session.get_bind().dialect.name == "postgresql":
            q = q.with_for_update()
        out["sources"] = len(session.execute(q).all())
    observed, latest = _stored(session, team_id, refs, since_job)
    obs_rows: list[dict[str, Any]] = []
    assign: dict[str, str] = {}
    cache: dict[tuple[str, ...], Any] = {}  # an observation's row is often its latest job's row too

    def keys(r: Any) -> Any:  # the row key alone is not enough: two jobs' rows can share it with other facts
        k = (r.source_ref, str(r.asset_key), str(r.asset_type), str(r.target), str(r.location),
             json.dumps(r.facts, sort_keys=True, default=str))
        if k not in cache:
            cache[k] = keys_of(r, r.source_ref)
        return cache[k]

    for r in observed:
        keys_ = keys(r)
        if keys_ is None:
            continue
        old_o, new_o, old_e, new_e = keys_
        if reverse:
            old_o, new_o, old_e, new_e = new_o, old_o, new_e, old_e
        okey = new_o if r.observation_key == old_o and old_o != new_o else None
        ekey = new_e if r.estate_key == old_e and old_e != new_e else None
        if okey:
            assign[old_o] = new_o
        if okey or ekey:
            obs_rows.append({"id": int(r.id), "ref": r.source_ref, "okey": okey, "eold": r.estate_key, "enew": ekey,
                             "rank": _PRESENCE_RANK.get(r.presence, 3)})
    for r in latest:
        keys_ = keys(r)
        if keys_ is not None and keys_[0] != keys_[1]:
            old_o, new_o = (keys_[1], keys_[0]) if reverse else (keys_[0], keys_[1])
            assign.setdefault(old_o, new_o)
    if obs_rows:
        out["observations"], out["estate"] = _move_observations(session, team_id, obs_rows)
    out["assignments"] = _move_assignments(session, team_id, assign)
    return out


_PRESENCE_RANK = {"present": 0, "not_read": 1, "removed": 2}  # which observation (and asset) wins a merge


def _move_observations(session: Any, team_id: int, rows: list[dict[str, Any]]) -> tuple[int, int]:
    """The observation keys, then the observations' estate keys, then the estate asset rows and every row keyed by
    them. A constant number of statements over two temporary tables. Returns (observations, estate assets) moved."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateAsset, CbomEstateObservation

    eo, ea = CbomEstateObservation.__table__, CbomEstateAsset.__table__  # reads only; the writes are set-based SQL
    T, A = "q109_obs", "q109_asset"
    # an observation whose new estate key the source already holds (stored, or an earlier row of this batch) merges
    claimed: set[tuple[str, str]] = set()
    news = [{"ref": ref, "k": key} for ref, key in sorted({(r["ref"], r["enew"]) for r in rows if r["enew"]})]
    if news:
        N = "q109_new"
        _temp(session, N, "ref VARCHAR(255), k VARCHAR(64), PRIMARY KEY (ref, k)", news)
        claimed.update((ref, key) for ref, key in session.execute(sa.text(
            f"SELECT n.ref, n.k FROM {N} n JOIN cbomestateobservation o ON o.team_id = :t AND o.source_ref = n.ref "
            f"AND o.asset_key = n.k"), {"t": team_id}).all())
        session.execute(sa.text(f"DROP TABLE {N}"))
    rows.sort(key=lambda r: (r.pop("rank"), r["id"]))  # a present observation keeps its row, a removed one merges
    for r in rows:
        r["act"] = None
        if r["enew"]:
            r["act"] = "drop" if (r["ref"], r["enew"]) in claimed else "move"
            claimed.add((r["ref"], r["enew"]))
    _temp(session, T, "id INTEGER PRIMARY KEY, ref VARCHAR(255), okey VARCHAR(40), eold VARCHAR(64), "
                      "enew VARCHAR(64), act VARCHAR(8)", rows)
    moved_o = _set_from(session, "cbomestateobservation", "observation_key", "t.okey", T, "t.id = x.id",
                        "t.okey IS NOT NULL")
    session.execute(sa.text(f"DELETE FROM cbomestateobservation WHERE id IN (SELECT id FROM {T} WHERE act = 'drop')"))
    _set_from(session, "cbomestateobservation", "asset_key", "t.enew", T, "t.id = x.id", "t.act = 'move'")
    # the estate asset rows: one decision per (old, new) pair, from three reads
    pairs = list(dict.fromkeys((r["eold"], r["enew"]) for r in rows if r["act"]))  # best observation first
    olds, newk = sorted({o for o, _n in pairs}), sorted({n for _o, n in pairs})
    assets: dict[str, Any] = {}
    for chunk in _chunks(sorted(set(olds) | set(newk))):
        for row in session.execute(sa.select(ea.c.id, ea.c.asset_key, ea.c.first_seen_at, ea.c.first_seen_run_id)
                                   .where(ea.c.team_id == team_id, ea.c.asset_key.in_(chunk))).all():
            assets[row.asset_key] = row
    left: dict[str, int] = {}
    for chunk in _chunks(olds):
        left.update({k: int(n) for k, n in session.execute(sa.select(eo.c.asset_key, sa.func.count()).where(
            eo.c.team_id == team_id, eo.c.asset_key.in_(chunk)).group_by(eo.c.asset_key)).all()})
    acts: list[dict[str, Any]] = []
    first: dict[str, tuple[Any, Any]] = {}  # new key -> the earliest (first_seen_at, run) of the rows it absorbs
    exists = {k for k in newk if k in assets}
    base: dict[str, tuple[Any, Any]] = {k: (r.first_seen_at, r.first_seen_run_id) for k, r in assets.items()}
    decided: set[str] = set()
    led: set[str] = set()  # one old key per new key carries its register row and open Q0 item over (no duplicates)
    for old, new in pairs:
        o = assets.get(old)
        if o is None or old in decided:
            continue
        decided.add(old)
        lead = int(new not in led)
        led.add(new)
        if new not in exists:  # the first row to reach a new key becomes it (renamed, or copied while still observed)
            act = "copy" if left.get(old) else "rename"
            exists.add(new)
            base[new] = (o.first_seen_at, o.first_seen_run_id)
        else:
            act = "merge" if not left.get(old) else "seen"
            best = first.get(new) or base.get(new) or (None, None)
            if o.first_seen_at is not None and (best[0] is None or o.first_seen_at < best[0]):
                best = (o.first_seen_at, o.first_seen_run_id)
            first[new] = best
        acts.append({"old": old, "new": new, "act": act, "lead": lead})
    _temp(session, A, "old VARCHAR(64) PRIMARY KEY, new VARCHAR(64), act VARCHAR(8), lead INTEGER", acts)
    tid = {"t": team_id}
    merged = f"(SELECT old FROM {A} WHERE act = 'merge')"
    # copies first (they read the old row), then renames, then the merges' first seen, links, register, Q0, deletes
    if any(a["act"] == "copy" for a in acts):
        cols = [c["name"] for c in sa.inspect(session.connection()).get_columns("cbomestateasset")
                if c["name"] not in ("id", "asset_key")]
        names = ", ".join(cols)
        session.execute(sa.text(
            f"INSERT INTO cbomestateasset ({names}, asset_key) SELECT {', '.join('e.' + c for c in cols)}, a.new "
            f"FROM cbomestateasset e JOIN {A} a ON a.old = e.asset_key WHERE e.team_id = :t AND a.act = 'copy'"), tid)
    _set_from(session, "cbomestateasset", "asset_key", "t.new", A, "t.old = x.asset_key",
              "x.team_id = :t AND t.act = 'rename'", tid)
    seen = [{"new": k, "at": at, "run": run} for k, (at, run) in first.items() if at is not None]
    if seen:  # a merge keeps the earliest first seen of the rows it joins
        S = "q109_seen"
        _temp(session, S, "new VARCHAR(64) PRIMARY KEY, at TIMESTAMP, run INTEGER", seen)
        for column, value in (("first_seen_at", "t.at"), ("first_seen_run_id", "t.run")):
            _set_from(session, "cbomestateasset", column, value, S, "t.new = x.asset_key", "x.team_id = :t", tid)
        session.execute(sa.text(f"DROP TABLE {S}"))
    _set_from(session, "cbomestatelink", "asset_key", "t.new", A, "t.old = x.asset_key",
              "x.team_id = :t AND t.act IN ('rename', 'merge')", tid)
    _set_from(session, "cbomriskregister", "item_key", "t.new", A, "t.old = x.item_key",
              "x.team_id = :t AND t.lead = 1 AND t.act IN ('rename', 'merge') AND NOT EXISTS (SELECT 1 FROM "
              "cbomriskregister r2 WHERE r2.team_id = :t AND r2.item_key = t.new)", tid)
    _set_from(session, "cbomq0gap", "item_key", "'asset:' || t.new", A, "x.item_key = 'asset:' || t.old",
              "x.team_id = :t AND x.closed_at IS NULL AND t.lead = 1 AND t.act IN ('rename', 'merge') AND NOT EXISTS "
              "(SELECT 1 FROM cbomq0gap g2 WHERE g2.team_id = :t AND g2.item_kind = x.item_kind AND "
              "g2.closed_at IS NULL AND g2.item_key = 'asset:' || t.new)", tid)
    session.execute(sa.text(f"DELETE FROM cbomriskregister WHERE team_id = :t AND item_key IN "
                            f"{merged}"), tid)
    session.execute(sa.text(f"DELETE FROM cbomestateasset WHERE team_id = :t AND asset_key IN "
                            f"{merged}"), tid)
    for name in (T, A):
        session.execute(sa.text(f"DROP TABLE {name}"))
    return moved_o, sum(1 for a in acts if a["act"] != "seen")


# ----------------------------------------------------------------------------- the deploy migration and its fallbacks
def backfill_team(session: Any, team_id: int, *, reverse: bool = False) -> dict[str, int]:
    """Every stored key of the team, under the store's lock (``migrate_team``)."""
    return migrate_team(session, team_id, reverse=reverse, lock=True)


def _high_water(session: Any) -> int:
    import sqlalchemy as sa

    from backend.new_models import CbomCollectionJob

    return int(session.execute(sa.select(sa.func.max(CbomCollectionJob.id))).scalar() or 0)


def mark_of(session: Any, team_id: int) -> int | None:
    """The highest job id the team's move covered, or None when the team was never moved (``record_run``)."""
    from backend.new_models import CbomOpsCounter

    row = session.get(CbomOpsCounter, f"{MARK}{team_id}")
    return None if row is None else int(row.value or 0)


def _fail_text(exc: BaseException) -> str:
    """The exception's class and first line, shortened: SQL errors name tables and constraints, never values (the
    statements bind their parameters)."""
    first = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return f"{type(exc).__name__}: {first[:200]}"


def backfill_due(engine: Any, now: Any = None, *, teams: int = 20) -> dict[str, int]:
    """The scheduler's fallback for the deploy migration (``migrate_all``, which marks every team it moved): at start,
    before any new run, up to ``teams`` teams not marked done (a team whose migration failed), one transaction each,
    then marked. A team that fails again is logged with the reason and skipped; the others still move. Safe to run
    twice or in two processes: a key already moved maps to nothing, and the team's sources are locked."""
    import sqlalchemy as sa
    from sqlmodel import Session

    from backend.new_models import CbomEstateSource, CbomOpsCounter
    from backend.utilities.cbom_sources.common import log, utcnow

    out = {"teams": 0, "failed": 0, "estate": 0, "assignments": 0}
    with Session(engine) as session:
        all_teams = sorted(t for (t,) in session.execute(sa.select(CbomEstateSource.team_id).distinct()).all()
                           if t not in _DONE)
        marked = {n for (n,) in session.execute(sa.select(CbomOpsCounter.name).where(
            CbomOpsCounter.name.like(MARK + "%"))).all()}  # type: ignore[attr-defined]
    _DONE.update(t for t in all_teams if f"{MARK}{t}" in marked)
    for team_id in [t for t in all_teams if f"{MARK}{t}" not in marked][:teams]:
        started = time.monotonic()
        try:
            with Session(engine) as session:
                high = _high_water(session)
                found = migrate_team(session, team_id, lock=True)
                if session.get(CbomOpsCounter, f"{MARK}{team_id}") is None:
                    session.add(CbomOpsCounter(name=f"{MARK}{team_id}", value=high, updated_at=now or utcnow()))
                session.commit()
        except Exception as exc:  # noqa: BLE001 - one team never stops the others; the next start retries it
            out["failed"] += 1
            log("cbom sources identity keys move FAILED", team=team_id, error=_fail_text(exc))
            continue
        _DONE.add(team_id)
        out["teams"] += 1
        out["estate"] += found["estate"]
        out["assignments"] += found["assignments"]
        log("cbom sources identity keys moved", team=team_id, sources=found["sources"], estate=found["estate"],
            observations=found["observations"], assignments=found["assignments"],
            ms=int((time.monotonic() - started) * 1000))
    return out


def migrate_all(connection: Any, now: Any = None, *, reverse: bool = False) -> dict[str, int]:
    """The deploy migration (``q109certkey001``): every team with a stored source, each in its own savepoint on the
    migration's connection. Upgrade: moves the keys and marks the team done with the highest job id it covered.
    Downgrade (``reverse``): moves them back and clears the mark. A team whose move fails (an error, or a lock not
    granted within ``LOCK_TIMEOUT`` on PostgreSQL) is rolled back to its savepoint, logged with the reason and left
    unmarked (the scheduler's ``backfill_due`` retries it), so one bad team never blocks the deploy. Progress is
    logged per team (sources, rows moved, milliseconds)."""
    import sqlalchemy as sa
    from sqlmodel import Session

    from backend.new_models import CbomEstateSource, CbomOpsCounter
    from backend.utilities.cbom_sources.common import log, utcnow

    started = time.monotonic()
    oc = CbomOpsCounter.__table__
    out = {"teams": 0, "failed": 0, "sources": 0, "estate": 0, "observations": 0, "assignments": 0}
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    teams = sorted(t for (t,) in connection.execute(sa.select(CbomEstateSource.team_id).distinct()).all())
    high = int(connection.execute(sa.text("SELECT max(id) FROM cbomcollectionjob")).scalar() or 0)
    log("cbom sources identity key migration started", reverse=reverse, teams=len(teams))
    for i, team_id in enumerate(teams, 1):
        t0 = time.monotonic()
        point = connection.begin_nested()
        try:
            with Session(bind=connection) as session:  # joins the savepoint: its commit releases only its own
                found = migrate_team(session, team_id, reverse=reverse, lock=True)
                session.commit()
            connection.execute(sa.delete(oc).where(oc.c.name == f"{MARK}{team_id}"))
            if not reverse:
                connection.execute(sa.insert(oc).values(name=f"{MARK}{team_id}", value=high,
                                                        updated_at=now or utcnow()))
            point.commit()
        except Exception as exc:  # noqa: BLE001 - one team never blocks the deploy; the scheduler retries it
            point.rollback()
            out["failed"] += 1
            log("cbom sources identity key migration FAILED", team=team_id, reverse=reverse, error=_fail_text(exc))
            continue
        _DONE.discard(team_id)
        out["teams"] += 1
        for k in ("sources", "estate", "observations", "assignments"):
            out[k] += found.get(k, 0)
        log("cbom sources identity key migration team", team=team_id, done=i, of=len(teams), reverse=reverse,
            ms=int((time.monotonic() - t0) * 1000), **found)
    log("cbom sources identity key migration", reverse=reverse, ms=int((time.monotonic() - started) * 1000), **out)
    return out


LOCK_TIMEOUT = "30s"  # a store write still holding a source (an older worker) never stalls the deploy longer

__all__ = ["LOCK_TIMEOUT", "MARK", "backfill_due", "backfill_team", "canonical_dn", "keys_of", "legacy_node_identity",
           "mark_of", "migrate_all", "migrate_team", "node_identity", "remap"]
