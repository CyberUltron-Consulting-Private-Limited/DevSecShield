"""Crypto-agility on the estate store (CB-25 PR-B): stored fix classes, GROUP BY roll-ups, one baseline per run.

* **Per observation** (``cbomestateobservation``): the class of the observation's latest stored row, judged with its
  job's context (``agility``: codes judged today, the job's metadata snapshot, R-VENDOR...), the system of that job
  (application, else the source), and the two weak certificate link keys a code-scan certificate can match.
  ``fix_job_id``/``fix_attempt`` say which row it was computed from; ``fix_recheck_on`` when a date-based rule
  (certificate expiry, library end of life, KMS key material) may change it.
* **Per asset** (``cbomestateasset``): the class = the hardest across its non-removed observations. With
  none < configurable < code-fixed < vendor-fixed < unknown < hardware-fixed this is exactly the asset rule over the
  union of their codes (an observation is unknown only when it has an unknown code and no hardware-fixed one), so
  the asset class is a MAX over stored values, never a re-read. Its system is its latest observation's.
* **Roll-up**: ``GROUP BY system_key, fix_class, fix_class_excl_pq, fix_reasons`` over the team's assets (the
  covering partial index ``ix_cbomestateasset_agility_groups``, an index-only scan; CB-32), plus the code scans and evidence items (``agility_rollup``).
* **Written** by an estate hook (``on_estate_write``) in each run's estate write: the observations of the sources the
  run wrote are re-judged, their assets re-aggregated, and the run's baseline row is written. **Healed** when read
  (``heal``): an observation whose row moved on, whose class was never computed, computed by another model version,
  or whose recheck date has come is re-judged first (a failed hook, a deploy with a new knowledge base, a backfill
  without hooks, the calendar), so the roll-up never serves a stale class.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import sqlalchemy as sa

from backend.utilities.cbom_sources import agility as AG

UTC = _dt.timezone.utc
BATCH = 500
ORDER = ("none", "configurable", "code-fixed", "vendor-fixed", "unknown", "hardware-fixed")
_ORD = {v: i for i, v in enumerate(ORDER)}
BASELINE_SYSTEMS_CAP = 2_000
DAILY = _dt.timedelta(days=1)


def _tables():
    from backend.new_models import CbomCollectedAsset, CbomEstateAsset, CbomEstateObservation, CbomEstateSource

    return (CbomEstateObservation.__table__, CbomEstateSource.__table__, CbomEstateAsset.__table__,
            CbomCollectedAsset)


def _chunks(items: Sequence[Any], size: int = BATCH) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _aware(moment: Any) -> _dt.datetime:
    if not isinstance(moment, _dt.datetime):
        return _dt.datetime(1970, 1, 1, tzinfo=UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _naive(moment: _dt.datetime) -> _dt.datetime:
    return _aware(moment).replace(tzinfo=None)


# ---------------------------------------------------------------------------------------------- context per job
class Contexts:
    """Per job: the class rules' memo key and the system (application, else the source uid snapshot)."""

    def __init__(self, session: Any, team_id: int, job_ids: Iterable[int]):
        from sqlmodel import select

        from backend.new_models import CbomCollectionJob, CbomCollectionSource

        ids = sorted({int(j) for j in job_ids if j is not None})
        self.jobs = {j.id: j for chunk in _chunks(ids) for j in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.id.in_(chunk))).all()}  # type: ignore[union-attr]
        self.sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
            CbomCollectionSource.team_id == team_id)).all()}
        self._memo: dict[int, tuple[tuple, tuple[str, str, str]]] = {}

    def of(self, job_id: int, source_ref: str, source_name: str) -> tuple[tuple, tuple[str, str, str]]:
        hit = self._memo.get(job_id)
        if hit is None:
            job = self.jobs.get(job_id)
            source = self.sources.get(getattr(job, "source_id", None) or 0)
            ctx = AG.node_context(job, source)
            (kind, skey), label = AG.system_of(job, source, ctx)
            if kind == "source":  # the source uid every team view uses (job snapshot first)
                skey, label = source_ref, source_name
            hit = self._memo[job_id] = (AG._ctx_key(ctx), (f"{kind}:{skey}"[:300], str(label)[:255], kind))
        return hit


def evaluate_node(kb: str, ctx_key: tuple, a_type: str, codes: Iterable[Any], facts: Any, location: Any) -> tuple:
    """``agility._evaluate`` for one node row (RunAgility's path: the job context's memo key computed once per job)."""
    facts = facts if isinstance(facts, dict) else {}
    return AG._evaluate(kb, "node", a_type, AG._codes(codes), AG._deciding(a_type, facts, location), ctx_key)


def recheck_on(asset_type: str, facts: Any, today: _dt.date) -> _dt.date | None:
    """The first day after ``today`` on which a date-based rule may judge this row differently (classify's
    DATED_TYPES): a certificate 31 days before and on its notAfter; a library or KMS key every day; else never."""
    from backend.utilities.cbom_sources import classify as C

    if asset_type in C.CERT_DATED_TYPES:
        when = C._parse_time((facts or {}).get("not_after")) if isinstance(facts, dict) else None
        if when is None:
            return None
        edge = when - C._EXPIRY_WINDOW  # the day it enters the 30-day window, and the day it expires (each +1 day:
        days = sorted(d for d in (edge.date(), (edge + DAILY).date(), when.date(), (when + DAILY).date())
                      if d > today)  # the rule reads the time of day, so the next day is certain)
        return days[0] if days else None
    if asset_type in C.LIBRARY_DATED_TYPES or asset_type in C.KEY_DATED_TYPES:
        return today + DAILY
    return None


def _join(values: Iterable[str], limit: int) -> str | None:
    text = ",".join(values)
    return text[:limit] if text else None


def _split(text: str | None) -> tuple[str, ...]:
    return tuple(v for v in (text or "").split(",") if v)


# ---------------------------------------------------------------------------------------------- combining
@dataclass
class Part:
    """One observation's (or one merged subject's) stored answer."""

    fix_class: str
    excl_pq: str
    floor: str | None
    reasons: tuple[str, ...]
    codes: tuple[str, ...]
    at: tuple
    system: tuple[str, str, str]


def combine(parts: Sequence[Part]) -> Part:
    """The hardest across the parts (see the module docstring), the floor of an unknown result, its reasons and
    deciding codes, and the latest part's system."""
    cls = max((p.fix_class for p in parts), key=_ORD.__getitem__)
    excl = max((p.excl_pq for p in parts), key=_ORD.__getitem__)
    floor = None
    if cls == "unknown":
        for p in parts:
            floor = AG._max(floor, p.floor if p.fix_class == "unknown" else p.fix_class)
    reasons = tuple(sorted({r for p in parts if p.fix_class == "unknown" for r in p.reasons})) if cls == "unknown" else ()
    codes = tuple(dict.fromkeys(c for p in parts if p.fix_class == cls for c in p.codes)) if cls in AG.RANK else ()
    latest = max(parts, key=lambda p: p.at)
    return Part(cls, excl, floor, reasons, codes, latest.at, latest.system)


def part_of_eval(ev: tuple, at: tuple, system: tuple[str, str, str]) -> Part:
    whole, per, excl, reasons = ev
    cls = whole["fix_class"]
    codes = tuple(dict.fromkeys(p["code"] for p in per if p["class"] == cls)) if cls in AG.RANK else ()
    return Part(cls, excl, whole["floor"], tuple(sorted(reasons)), codes, at, system)


# ---------------------------------------------------------------------------------------------- observations
def judge_observations(session: Any, team_id: int, now: _dt.datetime, where: Any) -> set[str]:
    """Re-judge the non-removed observations matching ``where`` (a SQL condition on ``cbomestateobservation``) from
    their latest stored row; returns their asset keys."""
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources.classify import shown

    eo, es, _ea, row_model = _tables()
    found = session.execute(sa.select(
        eo.c.id, eo.c.asset_key, eo.c.source_ref, eo.c.row_key, eo.c.presence, eo.c.seen_job_id, eo.c.seen_attempt,
        eo.c.seen_at, es.c.latest_job_id, es.c.latest_attempt, es.c.latest_at, es.c.source_name)
        .select_from(eo.join(es, sa.and_(es.c.team_id == eo.c.team_id, es.c.source_ref == eo.c.source_ref)))
        .where(eo.c.team_id == team_id, eo.c.presence != "removed", where)).all()
    if not found:
        return set()
    pointers: dict[tuple[int, int], list[tuple[Any, Any]]] = {}
    for o in found:
        job, attempt, at = ((o.latest_job_id, o.latest_attempt, o.latest_at) if o.presence == "present"
                            else (o.seen_job_id, o.seen_attempt, o.seen_at))
        pointers.setdefault((job, attempt), []).append((o, at))
    columns = (row_model.asset_key, row_model.asset_type, row_model.cdx_type, row_model.target, row_model.location,
               row_model.algorithm, row_model.key_size, row_model.protocol, row_model.facts, row_model.finding_codes,
               row_model.impact, row_model.finding, row_model.created_at)
    contexts = Contexts(session, team_id, (job for job, _a in pointers))
    kb, version = AG.crypto_kb.version(), AG.version()
    today = _naive(now)
    updates: list[dict[str, Any]] = []
    for (job_id, attempt), items in pointers.items():
        rows: dict[str, Any] = {}
        for chunk in _chunks(sorted({o.row_key for o, _at in items})):
            for r in session.execute(sa.select(*columns).where(
                    row_model.team_id == team_id, row_model.job_id == job_id, row_model.attempt == attempt,
                    row_model.asset_key.in_(chunk))).all():  # type: ignore[attr-defined]
                rows[r.asset_key] = r
        for o, at in items:
            row = rows.get(o.row_key)
            name = o.source_name or o.source_ref
            ctx_key, system = contexts.of(job_id, o.source_ref, name)
            if row is None or row.asset_type == "coverage":  # pruned (retention keeps pointed rows) or not an asset
                part, recheck, cnb, cn = Part("none", "none", None, (), (), (_aware(at), job_id), system), None, None, None
            else:
                codes = [c for c in shown(row, today)["finding_codes"] if not c.startswith("COVERAGE_")]
                a_type = str(row.asset_type or "")
                part = part_of_eval(evaluate_node(kb, ctx_key, a_type, codes, row.facts, row.location),
                                    (_aware(at), job_id), system)
                recheck = recheck_on(a_type, row.facts, today.date())
                cnb = cn = None
                if a_type in AK.CERT_TYPES or row.cdx_type == "certificate":
                    facts = row.facts if isinstance(row.facts, dict) else {}
                    links = {k.basis: k.key for k in AK.link_keys(AK.Observation(
                        kind=a_type, facts=facts, location=str(row.location or ""), cdx_type=str(row.cdx_type or ""),
                        scope=o.source_ref))}
                    cnb = links.get("cnb")
                    cn = links.get("cn") if not facts.get("not_before") else None
            updates.append({"b_id": o.id, "fix_class": part.fix_class, "fix_class_excl_pq": part.excl_pq,
                            "fix_floor": part.floor, "fix_reasons": _join(part.reasons, 200),
                            "fix_codes": _join(part.codes, 300), "fix_version": version, "fix_job_id": job_id,
                            "fix_attempt": attempt, "fix_recheck_on": recheck, "fix_at": _naive(_aware(at)),
                            "system_key": system[0], "system_label": system[1], "system_kind": system[2],
                            "cert_cnb_key": cnb, "cert_cn_key": cn})
    stmt = sa.update(eo).where(eo.c.id == sa.bindparam("b_id")).values(
        **{k: sa.bindparam(k) for k in updates[0] if k != "b_id"})
    for chunk in _chunks(updates, 1_000):
        session.execute(stmt, list(chunk))
    return {o.asset_key for o in found}


# ---------------------------------------------------------------------------------------------- assets
def aggregate_assets(session: Any, team_id: int, keys: Iterable[str], moves: list[dict[str, Any]] | None = None
                     ) -> int:
    """Re-aggregate the assets ``keys`` from their observations' stored classes; returns the assets whose stored
    answer changed (only those are written). ``moves``: gets one entry per asset whose class changed under the same
    model version (a new asset, or a class recomputed by another model version, is not a move)."""
    eo, _es, ea, _row = _tables()
    version = AG.version()
    keys = sorted(set(keys))
    fields = ("fix_class", "fix_class_excl_pq", "fix_floor", "fix_reasons", "fix_codes", "fix_version", "fix_at",
              "system_key", "system_label", "system_kind", "fix_observations")
    updates: list[dict[str, Any]] = []
    for chunk in _chunks(keys):
        by_key: dict[str, list[Part]] = {}
        for o in session.execute(sa.select(
                eo.c.asset_key, eo.c.fix_class, eo.c.fix_class_excl_pq, eo.c.fix_floor, eo.c.fix_reasons,
                eo.c.fix_codes, eo.c.fix_at, eo.c.fix_job_id, eo.c.system_key, eo.c.system_label, eo.c.system_kind)
                .where(eo.c.team_id == team_id, eo.c.asset_key.in_(chunk), eo.c.presence != "removed",
                       eo.c.fix_class.is_not(None))).all():
            by_key.setdefault(o.asset_key, []).append(Part(
                o.fix_class, o.fix_class_excl_pq or "none", o.fix_floor, _split(o.fix_reasons), _split(o.fix_codes),
                (_aware(o.fix_at), o.fix_job_id or 0), (o.system_key or "", o.system_label or "", o.system_kind or "")))
        old = {r.asset_key: r for r in session.execute(sa.select(ea.c.asset_key, ea.c.label, *(ea.c[f] for f in fields))
                                                       .where(ea.c.team_id == team_id, ea.c.asset_key.in_(chunk))).all()}
        for key in chunk:
            if key not in old:
                continue  # the asset row is gone (every observation moved to a stronger key)
            parts = by_key.get(key)
            if not parts:  # every observation removed (or none judged): no class
                new = {"fix_class": None, "fix_class_excl_pq": None, "fix_floor": None, "fix_reasons": None,
                       "fix_codes": None, "fix_version": version, "fix_at": None, "system_key": None,
                       "system_label": None, "system_kind": None, "fix_observations": 0}
            else:
                p = combine(parts)
                new = {"fix_class": p.fix_class, "fix_class_excl_pq": p.excl_pq, "fix_floor": p.floor,
                       "fix_reasons": _join(p.reasons, 200), "fix_codes": _join(p.codes, 300), "fix_version": version,
                       "fix_at": _naive(p.at[0]), "system_key": p.system[0], "system_label": p.system[1],
                       "system_kind": p.system[2], "fix_observations": len(parts)}
            was = old[key]
            if all(getattr(was, f) == new[f] for f in fields if f != "fix_at") and \
                    (was.fix_at is None) == (new["fix_at"] is None):
                continue  # nothing the roll-up reads changed (fix_at only orders the observations)
            if moves is not None and was.fix_class and new["fix_class"] and was.fix_class != new["fix_class"] \
                    and was.fix_version == version:
                moves.append({"key": key, "label": was.label, "old_class": was.fix_class, "new_class": new["fix_class"],
                              "system": (new["system_key"], new["system_label"], new["system_kind"])})
            updates.append({"b_key": key, **new})
    if updates:
        stmt = sa.update(ea).where(ea.c.team_id == team_id, ea.c.asset_key == sa.bindparam("b_key")).values(
            **{k: sa.bindparam(k) for k in updates[0] if k != "b_key"})
        for chunk in _chunks(updates, 1_000):
            session.execute(stmt, list(chunk))
    return len(updates)


def _stale_condition(now: _dt.datetime) -> Any:
    eo, es, _ea, _row = _tables()
    pointer_job = sa.case((eo.c.presence == "present", es.c.latest_job_id), else_=eo.c.seen_job_id)
    pointer_attempt = sa.case((eo.c.presence == "present", es.c.latest_attempt), else_=eo.c.seen_attempt)
    return sa.or_(eo.c.fix_version.is_(None), eo.c.fix_version != AG.version(),
                  eo.c.fix_recheck_on <= _naive(now).date(),
                  eo.c.fix_job_id != pointer_job, eo.c.fix_attempt != pointer_attempt)


STALE_IDS_MAX = 50_000  # more stale observations than this (a new model version): one scan instead of id lists


def _other_than(column: Any, value: Any) -> list[Any]:
    """``column IS NULL OR column <> value`` as three conditions, each an index range (run one statement each: an
    OR of ranges is read as a filter over the whole team)."""
    return [column.is_(None), column < value, column > value]


def stale_ids(session: Any, team_id: int, now: _dt.datetime) -> list[int] | None:
    """The ids of the observations ``_stale_condition`` selects, found through indexes (CB-32: the condition joins
    every observation of the team to its source, 1.5M rows on each roll-up). None when there are more than
    ``STALE_IDS_MAX`` (heal then scans with ``_stale_condition``)."""
    eo, es, _ea, _row = _tables()
    live = (eo.c.team_id == team_id, eo.c.presence != "removed")
    probes = [sa.select(eo.c.id).where(*live, cond) for cond in _other_than(eo.c.fix_version, AG.version())]
    probes.append(sa.select(eo.c.id).where(*live, eo.c.fix_recheck_on.is_not(None),
                                           eo.c.fix_recheck_on <= _naive(now).date()))
    # not read any more: its pointer is its own last reading job (ix_cbomestateobs_unread_fix_moved)
    probes.append(sa.select(eo.c.id).where(eo.c.team_id == team_id, eo.c.presence == "not_read", sa.or_(
        eo.c.fix_job_id != eo.c.seen_job_id, eo.c.fix_attempt != eo.c.seen_attempt)))
    for ref, job, attempt in session.execute(sa.select(es.c.source_ref, es.c.latest_job_id, es.c.latest_attempt)
                                             .where(es.c.team_id == team_id)).all():
        # present: computed from another row than the source's latest job's (ix_cbomestateobs_present_fix)
        base = (eo.c.team_id == team_id, eo.c.presence == "present", eo.c.source_ref == ref)
        for cond in (eo.c.fix_job_id < job, eo.c.fix_job_id > job,
                     sa.and_(eo.c.fix_job_id == job, eo.c.fix_attempt < attempt),
                     sa.and_(eo.c.fix_job_id == job, eo.c.fix_attempt > attempt)):
            probes.append(sa.select(eo.c.id).where(*base, cond))
    ids: set[int] = set()
    for probe in probes:
        ids.update(session.execute(probe.limit(STALE_IDS_MAX + 1 - len(ids))).scalars())
        if len(ids) > STALE_IDS_MAX:
            return None
    return sorted(ids)


def heal(session: Any, team_id: int, now: _dt.datetime, *, extra_keys: Iterable[str] = (),
         moves: list[dict[str, Any]] | None = None) -> int:
    """Re-judge every stale observation of the team (see the module docstring) and re-aggregate its assets, plus any
    asset never aggregated or aggregated by another version, plus ``extra_keys``. Returns the assets whose stored
    answer changed (0 in steady state). Steady state costs a few index probes (``stale_ids``, CB-32), not a scan of
    the team. The caller commits."""
    eo, _es, ea, _row = _tables()
    ids = stale_ids(session, team_id, now)
    if ids is None:
        keys = judge_observations(session, team_id, now, _stale_condition(now))
    else:
        keys = set()
        for chunk in _chunks(ids, 5_000):
            keys |= judge_observations(session, team_id, now, eo.c.id.in_(chunk))
    keys |= set(extra_keys)
    for cond in _other_than(ea.c.fix_version, AG.version()):
        keys |= set(session.execute(sa.select(ea.c.asset_key).where(
            ea.c.team_id == team_id, ea.c.presence != "removed", cond)).scalars())
    return aggregate_assets(session, team_id, keys, moves) if keys else 0


def carry_unchanged(session: Any, team_id: int, refs: Sequence[str]) -> tuple[int, int]:
    """The incremental part of a run's write. A source re-read in a new job points its present observations at the
    new job's rows; an observation whose new row is the row it was judged from in everything the class reads (type,
    place, algorithm, key size, protocol, verdict, codes, facts as stored), under the same job context and system,
    keeps its class: only its ``fix_job_id``/``fix_attempt`` move forward, nothing is loaded or judged. The stored
    codes are compared too, so a date-based code the new ingest recorded is a change; the calendar after that is
    ``fix_recheck_on``'s (same facts, same recheck day). Returns (observations carried, (source, old job) pairs
    looked at)."""
    eo, es, _ea, row = _tables()
    version = AG.version()
    moved = sa.or_(eo.c.fix_job_id != es.c.latest_job_id, eo.c.fix_attempt != es.c.latest_attempt)
    base = (eo.c.team_id == team_id, eo.c.source_ref.in_(list(refs)), eo.c.presence == "present",
            eo.c.fix_version == version, moved)
    joined = eo.join(es, sa.and_(es.c.team_id == eo.c.team_id, es.c.source_ref == eo.c.source_ref))
    pairs = session.execute(sa.select(
        eo.c.source_ref, eo.c.fix_job_id, eo.c.system_key, eo.c.system_label, eo.c.system_kind, es.c.latest_job_id,
        es.c.latest_attempt, es.c.source_name).select_from(joined).where(*base).distinct()).all()
    if not pairs:
        return 0, 0
    contexts = Contexts(session, team_id, {p.fix_job_id for p in pairs} | {p.latest_job_id for p in pairs})
    same: set[tuple[str, int]] = set()
    for p in pairs:
        name = p.source_name or p.source_ref
        old_ctx, _old_system = contexts.of(p.fix_job_id, p.source_ref, name)
        new_ctx, new_system = contexts.of(p.latest_job_id, p.source_ref, name)
        if old_ctx == new_ctx and new_system == (p.system_key, p.system_label, p.system_kind):
            same.add((p.source_ref, p.fix_job_id))
    if not same:
        return 0, len(pairs)
    n = row.__table__.alias("n")
    o = row.__table__.alias("o")
    text = lambda c: sa.cast(c, sa.Text)  # noqa: E731 - JSON compared as stored (PostgreSQL json keeps its text)
    same_row = sa.and_(*(sa.not_(n.c[c].is_distinct_from(o.c[c])) for c in (
        "asset_type", "cdx_type", "location", "algorithm", "key_size", "protocol", "impact", "finding")),
        sa.not_(text(n.c.finding_codes).is_distinct_from(text(o.c.finding_codes))),
        sa.not_(text(n.c.facts).is_distinct_from(text(o.c.facts))))
    # One statement for the whole run, all in SQL (#352). The observations of the (source, old job) pairs whose
    # context did not change, each with its source's latest job, are taken first (a MATERIALIZED CTE: one relation
    # that holds both halves of each row's keys), then each is looked up in its new and its old job through the
    # unique (job, attempt, asset_key) index. Written as one join, or as one correlated statement per pair (before),
    # PostgreSQL could scan a whole job's rows for every observation (3M rows read at 5k assets, minutes at 50k).
    c = sa.select(eo.c.id, eo.c.row_key, eo.c.fix_job_id, eo.c.fix_attempt, es.c.latest_job_id.label("new_job"),
                  es.c.latest_attempt.label("new_attempt")).select_from(joined).where(
        eo.c.team_id == team_id, sa.tuple_(eo.c.source_ref, eo.c.fix_job_id).in_(sorted(same)),
        eo.c.presence == "present", eo.c.fix_version == version).cte("carry").prefix_with("MATERIALIZED")
    carried = int(session.execute(sa.update(eo).where(
        eo.c.id == c.c.id,
        n.c.job_id == c.c.new_job, n.c.attempt == c.c.new_attempt, n.c.asset_key == c.c.row_key, n.c.team_id == team_id,
        o.c.job_id == c.c.fix_job_id, o.c.attempt == c.c.fix_attempt, o.c.asset_key == c.c.row_key,
        o.c.team_id == team_id, same_row,
    ).values(fix_job_id=c.c.new_job, fix_attempt=c.c.new_attempt).add_cte(c)).rowcount or 0)
    return carried, len(pairs)


# ---------------------------------------------------------------------------------------------- the estate hook
def on_estate_write(session: Any, write: Any) -> None:
    """After a run's estate write (same transaction, its own savepoint), incrementally: carry the observations whose
    re-read row is unchanged (``carry_unchanged``), re-judge only the rest that is stale, re-aggregate those assets
    and the ones whose observations' presence or key changed in this run, write the run's baseline, and record the
    agility events (an asset that moved class, a system whose class mix changed)."""
    eo, _es, _ea, _row = _tables()
    now = _aware(getattr(write, "at", None) or _dt.datetime.now(UTC))
    team_id, run_id = write.team_id, int(write.run_id)
    if write.source_refs:
        carry_unchanged(session, team_id, list(write.source_refs))
    keys: set[str] = set(write.changed) | {k for old, new, _ref in write.rekeyed for k in (old, new)}
    keys |= {k for k, in session.execute(sa.select(eo.c.asset_key).where(
        eo.c.team_id == team_id, eo.c.state_run_id == run_id)).all()}  # observations this run changed
    moves: list[dict[str, Any]] = []
    heal(session, team_id, now, extra_keys=keys, moves=moves)
    previous, current = write_baseline(session, team_id, run_id, now)
    if current is not None:
        record_events(session, team_id, run_id, now, moves, previous, current)


def write_baseline(session: Any, team_id: int, run_id: int, now: _dt.datetime) -> tuple[Any, Any]:
    """The run's baseline row (once: a replay of the same run by the backfill keeps the first). Returns (the
    previous run's baseline or None, the row written now or None when it already existed)."""
    from sqlmodel import select

    from backend.new_models import CbomAgilityBaseline
    from backend.utilities.cbom_sources import agility_rollup as ROLLUP

    if session.exec(select(CbomAgilityBaseline.id).where(CbomAgilityBaseline.team_id == team_id,
                                                         CbomAgilityBaseline.run_id == run_id)).first():
        return None, None
    previous = session.exec(select(CbomAgilityBaseline).where(
        CbomAgilityBaseline.team_id == team_id, CbomAgilityBaseline.run_id < run_id)
        .order_by(CbomAgilityBaseline.run_id.desc()).limit(1)).first()  # type: ignore[attr-defined]
    summary = ROLLUP.build_store(session, team_id, now=now, healed=True).summary(limit=BASELINE_SYSTEMS_CAP)
    systems = summary["systems"]["items"]
    row = CbomAgilityBaseline(
        team_id=team_id, run_id=run_id, scope="enterprise", agility_version=summary["agility_version"],
        assets=summary["assets"], self_fixable_pct=summary["self_fixable_pct"], counts=summary["counts"],
        counts_excl_pq=summary["counts_excl_pq"], unknown_reasons=summary["unknown_reasons"],
        systems=[{k: s[k] for k in ("key", "label", "kind", "assets", "hardest", "counts", "self_fixable_pct")}
                 for s in systems],
        systems_truncated=summary["systems_total"] > len(systems), created_at=_naive(now))
    session.add(row)
    session.flush()
    return previous, row


# ---------------------------------------------------------------------------------------------- events
EVENT_SCOPE = "agility"
ASSET_MOVED = "agility_asset_moved"
SYSTEM_CHANGED = "agility_system_changed"


def system_changes(previous: Any, current: Any) -> list[dict[str, Any]]:
    """Systems whose class mix differs between two consecutive baselines (a system that appeared or left counts as
    a change from or to nothing). None when either baseline was computed by another model version, or truncated its
    systems (then a missing system proves nothing)."""
    if previous is None or previous.agility_version != current.agility_version or \
            previous.systems_truncated or current.systems_truncated:
        return []
    before = {s["key"]: s for s in previous.systems or []}
    after = {s["key"]: s for s in current.systems or []}
    out = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old and new and old.get("counts") == new.get("counts"):
            continue
        ref = new or old
        out.append({"key": key, "label": ref.get("label"), "kind": ref.get("kind"),
                    "old_counts": old.get("counts") if old else None, "new_counts": new.get("counts") if new else None,
                    "old_hardest": old.get("hardest") if old else None, "new_hardest": new.get("hardest") if new else None,
                    "old_self_fixable_pct": old.get("self_fixable_pct") if old else None,
                    "new_self_fixable_pct": new.get("self_fixable_pct") if new else None})
    return out


def _event(team_id: int, now: _dt.datetime, kind: str, *, asset_key: str | None, label: str | None,
           detail: dict[str, Any], dedupe_parts: tuple) -> dict[str, Any]:
    from backend.utilities.cbom_sources.drift import dedupe

    # the run is in detail.run_id (CB-23's rule): a run's own events stay its estate drift (drift tests, run Changes)
    return {"team_id": team_id, "at": _naive(now), "scope": EVENT_SCOPE, "kind": kind, "run_id": None,
            "baseline_run_id": None, "scan_id": None, "baseline_scan_id": None, "source_ref": "", "source_name": None,
            "asset_key": asset_key[:64] if asset_key else None, "asset_label": (label or "")[:255] or None,
            "code": None, "severity": "Info", "detail": detail, "dedupe_key": dedupe("agility", team_id, *dedupe_parts),
            "forwarded_at": None}


def record_events(session: Any, team_id: int, run_id: int, now: _dt.datetime, moves: list[dict[str, Any]],
                  previous: Any, current: Any) -> int:
    """One ``agility_asset_moved`` per asset that changed class in this run (at most ``drift.EVENT_CAP``) and one
    ``agility_system_changed`` per system whose class mix changed since the previous baseline; forwarded by the
    integrations dispatcher like every drift event. Nothing on a team's first baseline or across a model change."""
    from backend.utilities.cbom_sources.drift import EVENT_CAP, insert_events

    events = []
    if previous is not None:
        for m in sorted(moves, key=lambda m: m["key"])[:EVENT_CAP]:
            events.append(_event(team_id, now, ASSET_MOVED, asset_key=m["key"], label=m["label"], detail={
                "old_class": m["old_class"], "new_class": m["new_class"], "system_key": m["system"][0],
                "system_label": m["system"][1], "run_id": run_id}, dedupe_parts=("asset", m["key"], run_id)))
    for c in system_changes(previous, current):
        events.append(_event(team_id, now, SYSTEM_CHANGED, asset_key=None, label=c["label"], detail={
            "system_key": c["key"], "system_label": c["label"], "system_kind": c["kind"], "old_counts": c["old_counts"],
            "new_counts": c["new_counts"], "old_hardest": c["old_hardest"], "new_hardest": c["new_hardest"],
            "old_self_fixable_pct": c["old_self_fixable_pct"], "new_self_fixable_pct": c["new_self_fixable_pct"],
            "baseline_run_id": previous.run_id, "run_id": run_id}, dedupe_parts=("system", c["key"], run_id)))
    return insert_events(session, events) if events else 0


def history(session: Any, team_id: int, limit: int = 50) -> list[dict[str, Any]]:
    """The team's baselines, newest run first (without the per-system lists)."""
    from sqlmodel import select

    from backend.new_models import CbomAgilityBaseline
    from backend.utilities.cbom_sources.common import iso_z

    rows = session.exec(select(CbomAgilityBaseline).where(CbomAgilityBaseline.team_id == team_id)
                        .order_by(CbomAgilityBaseline.run_id.desc()).limit(limit)).all()  # type: ignore[attr-defined]
    return [{"run_id": r.run_id, "at": iso_z(r.created_at), "agility_version": r.agility_version, "assets": r.assets,
             "counts": r.counts, "counts_excl_pq": r.counts_excl_pq, "self_fixable_pct": r.self_fixable_pct,
             "unknown_reasons": r.unknown_reasons, "systems": len(r.systems or []),
             "systems_truncated": r.systems_truncated} for r in rows]


def register() -> None:
    from backend.utilities.cbom_sources import estate as ESTATE

    ESTATE.register_hook(on_estate_write)


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m backend.utilities.cbom_sources.agility_store heal [--team N]``: compute every missing or stale
    stored class now (after a deploy with a new knowledge base, or an ``estate backfill``), so the first request
    does not pay for it (50k assets: about 11 s on the bench)."""
    import argparse

    from sqlmodel import Session, select

    from backend.get_db import get_db
    from backend.new_models import CbomEstateSource

    parser = argparse.ArgumentParser(prog="agility_store")
    sub = parser.add_subparsers(dest="cmd", required=True)
    heal_cmd = sub.add_parser("heal")
    heal_cmd.add_argument("--team", type=int, default=None)
    args = parser.parse_args(argv)
    engine = get_db()
    now = _dt.datetime.now(UTC)
    with Session(engine) as session:
        teams = [args.team] if args.team is not None else sorted(set(session.exec(select(CbomEstateSource.team_id)).all()))
    for team in teams:
        with Session(engine) as session:
            n = heal(session, team, now)
            session.commit()
        print(f"team {team}: {n} assets re-aggregated")
    return 0


__all__ = ["ASSET_MOVED", "Contexts", "ORDER", "Part", "SYSTEM_CHANGED", "aggregate_assets", "carry_unchanged",
           "combine", "evaluate_node", "heal", "history", "judge_observations", "on_estate_write", "recheck_on",
           "record_events", "register", "system_changes", "write_baseline"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
