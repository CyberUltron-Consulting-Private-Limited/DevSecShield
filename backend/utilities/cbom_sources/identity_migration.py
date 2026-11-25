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
Review 6060766322 m1: that last one only during the rolling-deploy window (``window()``, 24 h by default); then the
scheduler's ``close_due`` makes one last pass per team and writes its ``CLOSED`` row, after which a store write reads
that row and nothing else (``pending_since``). The downgrade moves every key back (``reverse``) and clears the marks
and the CLOSED rows.

A merge (review 6060766322 m2 / nit) closes the open Q0 item of the asset merged away when it is not carried over
(``model_change``, as the estate hook does), and drops a link the new key already holds instead of copying it.

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
CLOSED = "identity_migration_qa2:closed:"  # the team's rolling-deploy window is closed (``close_due``); value: its mark
WINDOW_HOURS = 24.0  # ``window()``: CBOM_IDENTITY_WINDOW_HOURS overrides
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


def _temp(session: Any, name: str, columns: list[Any], rows: list[dict[str, Any]]) -> Any:
    """A temporary table (SQLAlchemy Core, no SQL text) holding ``rows``, inserted in batches; analysed on
    PostgreSQL. The caller drops it (``table.drop``)."""
    import sqlalchemy as sa

    table = sa.Table(name, sa.MetaData(), *columns, prefixes=["TEMPORARY"])
    table.create(session.connection())
    for chunk in _chunks(rows, 5000):
        session.execute(sa.insert(table), chunk)
    if _pg(session):  # statistics, so the updates join it by key; constant statements (no SQL is built from data)
        analyze = {"q109_obs": lambda: sa.text("ANALYZE q109_obs"), "q109_asset": lambda: sa.text("ANALYZE q109_asset"),
                   "q109_new": lambda: sa.text("ANALYZE q109_new"), "q109_seen": lambda: sa.text("ANALYZE q109_seen")}
        session.execute(analyze[name]())
    return table


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
    them. A constant number of SQLAlchemy Core statements over temporary tables (``UPDATE … FROM``). Returns (observations, estate assets) moved."""
    import sqlalchemy as sa

    from backend.new_models import (CbomEstateAsset, CbomEstateLink, CbomEstateObservation, CbomQ0Gap,
                                    CbomRiskRegister)
    from backend.utilities.cbom_sources.common import utcnow

    eo, ea = CbomEstateObservation.__table__, CbomEstateAsset.__table__
    rr, el, gq = CbomRiskRegister.__table__, CbomEstateLink.__table__, CbomQ0Gap.__table__
    s64, s255 = sa.String(64), sa.String(255)
    # an observation whose new estate key the source already holds (stored, or an earlier row of this batch) merges
    claimed: set[tuple[str, str]] = set()
    news = [{"ref": ref, "k": key} for ref, key in sorted({(r["ref"], r["enew"]) for r in rows if r["enew"]})]
    if news:
        n_t = _temp(session, "q109_new", [sa.Column("ref", s255, primary_key=True),
                                          sa.Column("k", s64, primary_key=True)], news)
        claimed.update((ref, key) for ref, key in session.execute(sa.select(n_t.c.ref, n_t.c.k).select_from(n_t.join(
            eo, sa.and_(eo.c.team_id == team_id, eo.c.source_ref == n_t.c.ref, eo.c.asset_key == n_t.c.k)))).all())
        n_t.drop(session.connection())
    rows.sort(key=lambda r: (r.pop("rank"), r["id"]))  # a present observation keeps its row, a removed one merges
    for r in rows:
        r["act"] = None
        if r["enew"]:
            r["act"] = "drop" if (r["ref"], r["enew"]) in claimed else "move"
            claimed.add((r["ref"], r["enew"]))
    o_t = _temp(session, "q109_obs", [sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
                                      sa.Column("ref", s255), sa.Column("okey", sa.String(40)), sa.Column("eold", s64),
                                      sa.Column("enew", s64), sa.Column("act", sa.String(8))], rows)
    moved_o = session.execute(sa.update(eo).values(observation_key=o_t.c.okey).where(
        o_t.c.id == eo.c.id, o_t.c.okey.is_not(None))).rowcount or 0
    session.execute(sa.delete(eo).where(eo.c.id.in_(sa.select(o_t.c.id).where(o_t.c.act == "drop"))))
    session.execute(sa.update(eo).values(asset_key=o_t.c.enew).where(o_t.c.id == eo.c.id, o_t.c.act == "move"))
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
    a_t = _temp(session, "q109_asset", [sa.Column("old", s64, primary_key=True), sa.Column("new", s64),
                                        sa.Column("act", sa.String(8)), sa.Column("lead", sa.Integer)], acts)
    joined = ("rename", "merge")
    # copies first (they read the old row), then renames, then the merges' first seen, links, register, Q0, deletes
    if any(a["act"] == "copy" for a in acts):
        live = sa.Table(ea.name, sa.MetaData(), autoload_with=session.connection())  # the columns at this revision
        cols = [c for c in live.c if c.name not in ("id", "asset_key")]
        session.execute(sa.insert(live).from_select(
            [c.name for c in cols] + ["asset_key"],
            sa.select(*cols, a_t.c.new).select_from(live.join(a_t, a_t.c.old == live.c.asset_key))
            .where(live.c.team_id == team_id, a_t.c.act == "copy")))
    session.execute(sa.update(ea).values(asset_key=a_t.c.new).where(
        a_t.c.old == ea.c.asset_key, ea.c.team_id == team_id, a_t.c.act == "rename"))
    seen = [{"new": k, "at": at, "run": run} for k, (at, run) in first.items() if at is not None]
    if seen:  # a merge keeps the earliest first seen of the rows it joins
        s_t = _temp(session, "q109_seen", [sa.Column("new", s64, primary_key=True), sa.Column("at", sa.DateTime),
                                           sa.Column("run", sa.Integer)], seen)
        session.execute(sa.update(ea).values(first_seen_at=s_t.c.at, first_seen_run_id=s_t.c.run).where(
            s_t.c.new == ea.c.asset_key, ea.c.team_id == team_id))
        s_t.drop(session.connection())
    # links (review 6060766322 nit): a link the new key already holds, or that an earlier old key of the same merge
    # brings, is dropped rather than moved, so a merge never leaves two identical links (uq_cbomestatelink_link)
    el2, a2 = el.alias("el2"), a_t.alias("a2")
    same = sa.and_(el2.c.team_id == team_id, el2.c.kind == el.c.kind, el2.c.scan_id == el.c.scan_id,
                   el2.c.component == el.c.component)
    twin = sa.select(el2.c.id).where(same, sa.or_(
        el2.c.asset_key == a_t.c.new,
        sa.and_(el2.c.id < el.c.id, el2.c.asset_key.in_(sa.select(a2.c.old).where(
            a2.c.new == a_t.c.new, a2.c.act.in_(joined)).correlate(a_t))))).correlate(el, a_t)
    session.execute(sa.delete(el).where(el.c.team_id == team_id, sa.exists(sa.select(a_t.c.old).where(
        a_t.c.old == el.c.asset_key, a_t.c.act.in_(joined), sa.exists(twin)).correlate(el))))
    session.execute(sa.update(el).values(asset_key=a_t.c.new).where(
        a_t.c.old == el.c.asset_key, el.c.team_id == team_id, a_t.c.act.in_(joined)))
    rr2 = rr.alias("rr2")
    session.execute(sa.update(rr).values(item_key=a_t.c.new).where(
        a_t.c.old == rr.c.item_key, rr.c.team_id == team_id, a_t.c.lead == 1, a_t.c.act.in_(joined),
        ~sa.exists(sa.select(rr2.c.id).where(rr2.c.team_id == team_id, rr2.c.item_key == a_t.c.new))))
    g2 = gq.alias("g2")
    prefix = sa.literal("asset:", sa.String)
    session.execute(sa.update(gq).values(item_key=prefix + a_t.c.new).where(
        gq.c.item_key == prefix + a_t.c.old, gq.c.team_id == team_id, gq.c.closed_at.is_(None), a_t.c.lead == 1,
        a_t.c.act.in_(joined), ~sa.exists(sa.select(g2.c.id).where(
            g2.c.team_id == team_id, g2.c.item_kind == gq.c.item_kind, g2.c.closed_at.is_(None),
            g2.c.item_key == prefix + a_t.c.new))))
    merged = sa.select(a_t.c.old).where(a_t.c.act == "merge")
    # review 6060766322 m2: an asset merged away whose open Q0 item was not carried over (the new key already had
    # one, or another old key of the merge carried its own) closes now, as the estate hook closes a moved key's item
    # (``model_change``: a re-identification, recorded, not forwarded), so D12 counts it as closed with no further run
    session.execute(sa.update(gq).values(closed_at=utcnow(), close_cause="model_change", closed_grade=None).where(
        gq.c.team_id == team_id, gq.c.item_kind == "asset", gq.c.closed_at.is_(None),
        gq.c.item_key.in_(sa.select(prefix + a_t.c.old).where(a_t.c.act == "merge"))))
    session.execute(sa.delete(rr).where(rr.c.team_id == team_id, rr.c.item_key.in_(merged)))
    session.execute(sa.delete(ea).where(ea.c.team_id == team_id, ea.c.asset_key.in_(merged)))
    for table in (o_t, a_t):
        table.drop(session.connection())
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


def pending_since(session: Any, team_id: int) -> int | None:
    """What ``estate.record_run`` step 0b still has to look at for the team: the job id after which rows may carry the
    old identity (the team's mark; 0 when the team was never moved), or None once its rolling-deploy window is closed
    (``close_due``: no older-release writer remains and the rows it wrote moved), so a steady-state store write costs
    one primary-key read instead of re-reading every certificate it holds (review 6060766322 m1)."""
    import sqlalchemy as sa

    from backend.new_models import CbomOpsCounter

    oc = CbomOpsCounter.__table__
    held = dict(session.execute(sa.select(oc.c.name, oc.c.value).where(
        oc.c.name.in_((f"{MARK}{team_id}", f"{CLOSED}{team_id}")))).all())
    if f"{CLOSED}{team_id}" in held:
        return None
    return int(held.get(f"{MARK}{team_id}") or 0)


def window() -> Any:
    """How long after a team's move an older-release process may still write rows under the old identity (the rolling
    deploy): ``CBOM_IDENTITY_WINDOW_HOURS``, default 24, clamped to ``WINDOW_MIN_HOURS``..``WINDOW_MAX_HOURS`` (1 h to
    30 days; #504 review 6062542062 minor 2: an unbounded value overflowed ``timedelta`` and failed every tick). A value
    that is not a finite number, or is negative, is refused for the default; each refused or clamped spelling is logged
    once per process, never once per tick."""
    import datetime as _dt
    import math
    import os

    raw = os.environ.get("CBOM_IDENTITY_WINDOW_HOURS", "").strip()
    hours = WINDOW_HOURS
    if raw:
        try:
            hours = float(raw)
        except ValueError:
            hours = math.nan
        if not math.isfinite(hours) or hours < 0:
            _warn_once(raw, f"not a finite number of hours >= 0; using the default {WINDOW_HOURS:g}")
            hours = WINDOW_HOURS
        elif not WINDOW_MIN_HOURS <= hours <= WINDOW_MAX_HOURS:
            bound = WINDOW_MIN_HOURS if hours < WINDOW_MIN_HOURS else WINDOW_MAX_HOURS
            _warn_once(raw, f"outside {WINDOW_MIN_HOURS:g}..{WINDOW_MAX_HOURS:g} hours; using {bound:g}")
            hours = bound
    return _dt.timedelta(hours=hours)


WINDOW_MIN_HOURS = 1.0
WINDOW_MAX_HOURS = 30 * 24.0
_WARNED: set[str] = set()  # CBOM_IDENTITY_WINDOW_HOURS spellings already logged by this process


def _warn_once(raw: str, why: str) -> None:
    if raw in _WARNED:
        return
    _WARNED.add(raw)
    from backend.utilities.cbom_sources.common import log

    log("identity window setting REFUSED", setting="CBOM_IDENTITY_WINDOW_HOURS", value=raw[:40], why=why)


# a team whose closing pass failed is retried after a back-off (1, 2, 4 ... 60 minutes) and the teams after it go
# first meanwhile, so teams that fail every tick never hold back the others (#504 review 6062542062 nit)
_CLOSE_FAILS: dict[int, tuple[int, Any]] = {}  # team -> (consecutive failures, not before)
CLOSE_BACKOFF_MAX_MIN = 60


def close_due(engine: Any, now: Any = None, *, teams: int = 20) -> dict[str, int]:
    """Close the rolling-deploy window of every team moved more than ``window()`` ago (the scheduler, each tick):
    under the team's source locks, re-check that no other scheduler closed it, one last pass over the rows written
    after its mark (an older worker's write to a source nobody wrote since), then the ``CLOSED`` row, in one
    transaction. From then on ``record_run`` skips step 0b. Two schedulers racing: only the one whose ``CLOSED`` row
    is written reports the team (the other finds it under the locks, or loses the insert). A team whose pass fails
    backs off (``_CLOSE_FAILS``) so up to ``teams`` others are tried each tick. Returns what it did."""
    import datetime as _dt

    import sqlalchemy as sa
    from sqlmodel import Session

    from backend.new_models import CbomEstateSource, CbomOpsCounter
    from backend.utilities.cbom_sources.common import log, utcnow

    now = now or utcnow()
    out = {"teams": 0, "failed": 0, "skipped": 0, "estate": 0, "assignments": 0}
    oc, es = CbomOpsCounter.__table__, CbomEstateSource.__table__
    with Session(engine) as session:
        rows = session.execute(sa.select(oc.c.name, oc.c.value, oc.c.updated_at).where(
            oc.c.name.like("identity_migration_qa2:%"))).all()
    closed = {n[len(CLOSED):] for n, _v, _at in rows if n.startswith(CLOSED)}
    limit = now - window()
    due = [(int(n[len(MARK):]), int(v or 0)) for n, v, at in rows
           if n.startswith(MARK) and n[len(MARK):] not in closed and (at is None or at <= limit)]
    for team_id in [t for t in _CLOSE_FAILS if str(t) in closed]:
        _CLOSE_FAILS.pop(team_id, None)
    ready = [(t, m) for t, m in due if t not in _CLOSE_FAILS or _CLOSE_FAILS[t][1] <= now]
    out["skipped"] = len(due) - len(ready)
    ready.sort(key=lambda tm: (_CLOSE_FAILS.get(tm[0], (0, None))[0], tm[0]))  # never-failed first, then by team
    for team_id, mark in ready[:teams]:
        started = time.monotonic()
        try:
            with Session(engine) as session:
                q = sa.select(es.c.source_ref).where(es.c.team_id == team_id).order_by(es.c.source_ref)
                if session.get_bind().dialect.name == "postgresql":
                    q = q.with_for_update()
                session.execute(q).all()  # the store's locks: a racing closer or writer waits here
                if session.get(CbomOpsCounter, f"{CLOSED}{team_id}") is not None:
                    continue  # another scheduler closed it while this one waited: it reports the team
                found = migrate_team(session, team_id, since_job=mark, lock=False)
                session.add(CbomOpsCounter(name=f"{CLOSED}{team_id}", value=mark, updated_at=now))
                try:
                    session.commit()
                except sa.exc.IntegrityError:  # another scheduler wrote CLOSED first (no row lock to wait on)
                    session.rollback()
                    continue
        except Exception as exc:  # noqa: BLE001 - backs off; until then step 0b keeps running for the team
            fails = _CLOSE_FAILS.get(team_id, (0, None))[0] + 1
            _CLOSE_FAILS[team_id] = (fails, now + _dt.timedelta(minutes=min(CLOSE_BACKOFF_MAX_MIN, 2 ** (fails - 1))))
            out["failed"] += 1
            log("identity window close FAILED", team=team_id, failures=fails, error=_fail_text(exc))
            continue
        _CLOSE_FAILS.pop(team_id, None)
        out["teams"] += 1
        out["estate"] += found["estate"]
        out["assignments"] += found["assignments"]
        log("identity window closed", team=team_id, since_job=mark, estate=found["estate"],
            observations=found["observations"], assignments=found["assignments"],
            ms=int((time.monotonic() - started) * 1000))
    return out


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

    from backend.new_models import CbomCollectionJob, CbomEstateSource, CbomOpsCounter
    from backend.utilities.cbom_sources.common import log, utcnow

    started = time.monotonic()
    oc = CbomOpsCounter.__table__
    out = {"teams": 0, "failed": 0, "sources": 0, "estate": 0, "observations": 0, "assignments": 0}
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text("SET LOCAL lock_timeout = '30s'"))  # LOCK_TIMEOUT
    teams = sorted(t for (t,) in connection.execute(sa.select(CbomEstateSource.team_id).distinct()).all())
    high = int(connection.execute(sa.select(sa.func.max(CbomCollectionJob.id))).scalar() or 0)
    log("cbom sources identity key migration started", reverse=reverse, teams=len(teams))
    for i, team_id in enumerate(teams, 1):
        t0 = time.monotonic()
        point = connection.begin_nested()
        try:
            with Session(bind=connection) as session:  # joins the savepoint: its commit releases only its own
                found = migrate_team(session, team_id, reverse=reverse, lock=True)
                session.commit()
            connection.execute(sa.delete(oc).where(oc.c.name.in_((f"{MARK}{team_id}", f"{CLOSED}{team_id}"))))
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

__all__ = ["CLOSED", "LOCK_TIMEOUT", "MARK", "backfill_due", "backfill_team", "canonical_dn", "close_due", "keys_of",
           "legacy_node_identity", "mark_of", "migrate_all", "migrate_team", "node_identity", "pending_since", "remap",
           "window"]
