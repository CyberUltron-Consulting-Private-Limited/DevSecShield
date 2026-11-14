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
* **Roll-up**: ``GROUP BY system_key, fix_class, fix_class_excl_pq, fix_reasons`` over the team's assets (index
  ``(team_id, system_key, fix_class)``), plus the code scans and evidence items (``agility_rollup``).
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
def aggregate_assets(session: Any, team_id: int, keys: Iterable[str]) -> int:
    """Re-aggregate the assets ``keys`` from their observations' stored classes; returns the assets written."""
    eo, _es, ea, _row = _tables()
    version = AG.version()
    keys = sorted(set(keys))
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
        for key in chunk:
            parts = by_key.get(key)
            if not parts:  # every observation removed (or none judged): no class
                updates.append({"b_key": key, "fix_class": None, "fix_class_excl_pq": None, "fix_floor": None,
                                "fix_reasons": None, "fix_codes": None, "fix_version": version, "fix_at": None,
                                "system_key": None, "system_label": None, "system_kind": None,
                                "fix_observations": 0})
                continue
            p = combine(parts)
            updates.append({"b_key": key, "fix_class": p.fix_class, "fix_class_excl_pq": p.excl_pq,
                            "fix_floor": p.floor, "fix_reasons": _join(p.reasons, 200),
                            "fix_codes": _join(p.codes, 300), "fix_version": version,
                            "fix_at": _naive(p.at[0]), "system_key": p.system[0], "system_label": p.system[1],
                            "system_kind": p.system[2], "fix_observations": len(parts)})
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


def heal(session: Any, team_id: int, now: _dt.datetime) -> int:
    """Re-judge every stale observation of the team (see the module docstring) and re-aggregate its assets, plus any
    asset never aggregated or aggregated by another version. Returns the assets re-aggregated (0 in steady state).
    The caller commits."""
    _eo, _es, ea, _row = _tables()
    keys = judge_observations(session, team_id, now, _stale_condition(now))
    keys |= {k for k, in session.execute(sa.select(ea.c.asset_key).where(
        ea.c.team_id == team_id, ea.c.presence != "removed",
        sa.or_(ea.c.fix_version.is_(None), ea.c.fix_version != AG.version()))).all()}
    return aggregate_assets(session, team_id, keys) if keys else 0


# ---------------------------------------------------------------------------------------------- the estate hook
def on_estate_write(session: Any, write: Any) -> None:
    """After a run's estate write (same transaction, its own savepoint): re-judge the observations of the sources the
    run wrote and those whose asset changed or moved, re-aggregate their assets, heal anything else stale, then write
    the run's baseline."""
    eo, _es, _ea, _row = _tables()
    now = _aware(getattr(write, "at", None) or _dt.datetime.now(UTC))
    keys: set[str] = set(write.changed) | {new for _old, new, _ref in write.rekeyed} | {
        old for old, _new, _ref in write.rekeyed}
    conds = []
    if write.source_refs:
        conds.append(eo.c.source_ref.in_(list(write.source_refs)))
    touched = set()
    if conds:
        touched |= judge_observations(session, write.team_id, now, sa.or_(*conds))
    for chunk in _chunks(sorted(keys)):
        touched |= judge_observations(session, write.team_id, now, sa.and_(
            eo.c.asset_key.in_(list(chunk)), eo.c.fix_version.is_(None)))
    aggregate_assets(session, write.team_id, touched | keys)
    heal(session, write.team_id, now)
    write_baseline(session, write.team_id, int(write.run_id), now)


def write_baseline(session: Any, team_id: int, run_id: int, now: _dt.datetime) -> None:
    """The run's baseline row (once: a replay of the same run by the backfill keeps the first)."""
    from sqlmodel import select

    from backend.new_models import CbomAgilityBaseline
    from backend.utilities.cbom_sources import agility_rollup as ROLLUP

    if session.exec(select(CbomAgilityBaseline.id).where(CbomAgilityBaseline.team_id == team_id,
                                                         CbomAgilityBaseline.run_id == run_id)).first():
        return
    summary = ROLLUP.build_store(session, team_id, now=now, healed=True).summary(limit=BASELINE_SYSTEMS_CAP)
    systems = summary["systems"]["items"]
    session.add(CbomAgilityBaseline(
        team_id=team_id, run_id=run_id, scope="enterprise", agility_version=summary["agility_version"],
        assets=summary["assets"], self_fixable_pct=summary["self_fixable_pct"], counts=summary["counts"],
        counts_excl_pq=summary["counts_excl_pq"], unknown_reasons=summary["unknown_reasons"],
        systems=[{k: s[k] for k in ("key", "label", "kind", "assets", "hardest", "counts", "self_fixable_pct")}
                 for s in systems],
        systems_truncated=summary["systems_total"] > len(systems), created_at=_naive(now)))
    session.flush()


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


__all__ = ["Contexts", "ORDER", "Part", "aggregate_assets", "combine", "evaluate_node", "heal", "history",
           "judge_observations", "on_estate_write", "recheck_on", "register", "write_baseline"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
