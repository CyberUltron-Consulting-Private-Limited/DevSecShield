"""The team's quantum risk register (CB-23 PR-B; CB-19 PLAN §2.3, §2.5 ``cb23register001``, §2.6, §2.10).

One ``CbomRiskRegister`` row per estate asset key (CB-20 store, CB-21 cross-source keys): an asset four collectors
see is one row, so the register's totals are sums of distinct keys (DA-8). The grade is the CURRENT one (team view,
PLAN §2.3): the team's Mosca now, each source's data lifetime, exposure override and node segment now, the current
grade model; graded from the latest stored row of each present observation (``estate.latest_rows``); the worst known
grade over them wins (Q1 before Q4), Q0 only when no observation has a known grade.

Stored grades
* Every row keeps ``grade_digest`` = sha256(team inputs digest, model version, each graded observation's source and
  row content). The estate hook (``apply_write``) re-reads the keys a run touched and grades only those whose digest
  changed: an unchanged estate re-run costs a content hash per key, no class / exposure / grade work and no write.
* An inputs change (Mosca, a source's data lifetime or exposure, a node segment) or a new grade model changes every
  row's digest: the background re-grade (``regrade_due``, from the scheduler tick) re-grades mismatched rows in
  batches, oldest first, and fills keys the register has not seen yet (the first deploy, a backfilled store).

Q0 items: an asset whose grade is Q0 for a reason of the asset (``unknown_verdict``, ``not_correlated``) is an open
``cbomq0gap`` item ``asset:<estate key>``; leaving Q0 closes it with the cause of the re-grade (``observation`` from a
run, ``inputs`` / ``model_change`` from the background re-grade; ``model_change`` is never forwarded). ``mosca_missing``
stays the one team item ``inputs:mosca`` (``q0register.sync_mosca``).
"""
from __future__ import annotations

import base64
import csv
import datetime as _dt
import hashlib
import io
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence

import sqlalchemy as sa
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomRiskRegister,
    CbomScanNode,
)
from backend.utilities.cbom_sources.common import iso_z, log

RANK = {"Q1": 1, "Q2": 2, "Q3": 3, "Q4": 4, "Q0": 5, None: 6}
ASSET_Q0_REASONS = ("unknown_verdict", "not_correlated")
BATCH = 500
REGRADE_BATCH = 2000
LIMIT_MAX = 500
CSV_COLUMNS = ("item_key", "q_grade", "q_label", "q_reason", "label", "asset_type", "family", "exposure",
               "source_name", "application", "presence", "sources", "last_run_id", "last_observed_at",
               "model_version", "owners", "data_classification")
_RT = CbomRiskRegister.__table__


# ----------------------------------------------------------------------------- the team's inputs now
@dataclass
class TeamInputs:
    mosca: dict[str, int | None]
    risk_model: dict[str, Any]
    by_source: dict[int, dict[str, Any]]  # source id -> {x, exposure, segment, application, name, uid}
    digest: str


def team_inputs(session: Session, team_id: int) -> TeamInputs:
    from backend.utilities.cbom_sources import posture as P
    from backend.utilities.cbom_sources import qgrade as QG

    settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    risk_model = (settings.risk_model if settings is not None else None) or {}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    by_source: dict[int, dict[str, Any]] = {}
    for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all():
        meta = P.job_metadata(None, s, nodes.get(s.node_id or 0) if getattr(s, "node_id", None) else None)
        cfg = s.config if isinstance(s.config, dict) else {}
        by_source[int(s.id)] = {  # type: ignore[arg-type]
            "x": QG._mosca_int(meta.get("data_lifetime_years")),
            "exposure": meta.get("exposure") if meta.get("exposure") in P.EXPOSURES else None,
            "segment": meta.get("segment") if isinstance(meta.get("segment"), str) else None,
            "application": (str(cfg.get("application"))[:128] if cfg.get("application") else None),
            "name": s.name, "uid": s.source_uid}
    mosca = QG.mosca_of(risk_model)
    doc = {"mosca": mosca, "sources": sorted([v["uid"] or str(k), v["x"], v["exposure"], v["segment"]]
                                             for k, v in by_source.items())}
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
                            .encode()).hexdigest()[:16]
    return TeamInputs(mosca=mosca, risk_model=risk_model, by_source=by_source, digest=digest)


# ----------------------------------------------------------------------------- grading one key
def _content(row: CbomCollectedAsset) -> str:
    facts = row.facts if isinstance(row.facts, dict) else {}
    doc = [row.asset_type, row.algorithm, row.key_size, row.protocol, row.quantum_vulnerable, row.target,
           row.location, sorted(str(c) for c in (row.finding_codes or [])), facts]
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
                          .encode("utf-8", "replace")).hexdigest()


@dataclass
class _Graded:
    q_grade: str | None
    q_reason: str
    exposure: str | None
    family: str | None


class Grader:
    """Grades stored rows with the team's inputs now; one grade context per run (cached)."""

    def __init__(self, session: Session, team_id: int, inputs: TeamInputs, now: _dt.datetime):
        self.session, self.team_id, self.inputs, self.now = session, team_id, inputs, now
        self._ctx: dict[int | None, Any] = {}
        self.graded = 0

    def _context(self, row: CbomCollectedAsset) -> Any:
        from dataclasses import replace

        from backend.utilities.cbom_sources import qgrade as QG

        key = row.run_id
        if key not in self._ctx:
            ctx = QG.load_context(self.session, team_id=self.team_id, run_id=row.run_id,
                                  job_id=None if row.run_id else row.job_id, risk_model=self.inputs.risk_model,
                                  inputs="current")
            for jid, info in list(ctx.jobs.items()):
                now = self.inputs.by_source.get(info.source_id or 0)
                if now is not None:  # a source that still exists: its settings now (a deleted one keeps its snapshot)
                    ctx.jobs[jid] = replace(info, x=now["x"], exposure=now["exposure"], segment=now["segment"])
            self._ctx[key] = ctx
        return self._ctx[key]

    def grade(self, row: CbomCollectedAsset) -> _Graded:
        from backend.utilities.cbom_sources import heatmap as HEAT
        from backend.utilities.cbom_sources import posture as P
        from backend.utilities.cbom_sources import qgrade as QG
        from backend.utilities.cbom_sources.classify import shown

        self.graded += 1
        ctx = self._context(row)
        codes = [c for c in shown(row, self.now)["finding_codes"] if not c.startswith("COVERAGE_")]
        cls = P.classify_pqc(row, codes, elsewhere=ctx.elsewhere)[0]
        out = ctx.grade_row(row, codes, explain=False, cls=cls)
        job = ctx._job(row.job_id)
        facts = row.facts if isinstance(row.facts, dict) else {}
        exposure = QG.grade_exposure(facts, row.target, row.location, override=job.exposure, segment=job.segment,
                                     memo=ctx.memo)[0]
        return _Graded(out.q_grade, out.q_reason, exposure, HEAT.algorithm_family(row.algorithm, row.asset_type,
                                                                                  facts)[:32])


def not_correlated(g: _Graded, key_kind: str | None) -> _Graded:
    """qg-1 rule 6: an asset whose cross-source correlation is required but absent (CB-21 ``NOT_CORRELATED``, estate
    ``key_kind`` ``not_correlated``) is Q0 ``not_correlated``, after rules 4-5 (an unknown class stays
    ``unknown_verdict``; no public-key cryptography stays "no grade") and before Mosca and the class rules."""
    if key_kind != "not_correlated" or g.q_grade is None or g.q_reason == "unknown_verdict":
        return g
    return _Graded("Q0", "not_correlated", g.exposure, g.family)


def _worst(graded: list[tuple[str, _Graded]]) -> tuple[str, _Graded]:
    """The observation the key's grade comes from: the worst known grade (Q1 first), else Q0, else no grade."""
    return min(graded, key=lambda sg: (RANK.get(sg[1].q_grade, 6), sg[0]))


@dataclass
class Transition:
    key: str
    before: tuple[str | None, str | None] | None  # (grade, reason) stored before, None = no row
    after: tuple[str | None, str | None] | None  # None = row deleted
    label: str | None = None
    source_ref: str | None = None
    source_name: str | None = None
    asset_type: str | None = None


@dataclass
class Refresh:
    keys: int = 0
    graded: int = 0
    skipped: int = 0
    written: int = 0
    deleted: int = 0
    transitions: list[Transition] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {"keys": self.keys, "graded": self.graded, "skipped": self.skipped, "written": self.written,
                "deleted": self.deleted}


def _chunks(items: Sequence[Any], size: int = BATCH) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _upsert(session: Session, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    cols = [c for c in rows[0] if c not in ("team_id", "item_key")]
    for part in _chunks(rows):
        stmt = dialect_insert(_RT).values(list(part))
        session.execute(stmt.on_conflict_do_update(index_elements=["team_id", "item_key"],
                                                   set_={c: getattr(stmt.excluded, c) for c in cols}))


def refresh(session: Session, team_id: int, keys: Iterable[str], now: _dt.datetime, *, run_id: int | None = None,
            inputs: TeamInputs | None = None, force: bool = False) -> Refresh:
    """Bring the register rows of ``keys`` in line with the estate store: grade a key only when its digest changed
    (or ``force``), delete keys the store no longer has or whose every observation is removed. The caller commits."""
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources import qgrade as QG

    out = Refresh()
    keys = sorted(set(keys))
    out.keys = len(keys)
    if not keys:
        return out
    inputs = inputs or team_inputs(session, team_id)
    grader = Grader(session, team_id, inputs, now)
    model = QG.GRADE_MODEL_VERSION
    for part in _chunks(keys):
        stored = {r.item_key: r for r in session.execute(sa.select(
            _RT.c.item_key, _RT.c.q_grade, _RT.c.q_reason, _RT.c.grade_digest).where(
            _RT.c.team_id == team_id, _RT.c.item_key.in_(list(part)))).all()}
        assets = {a.asset_key: a for a in session.exec(select(CbomEstateAsset).where(
            CbomEstateAsset.team_id == team_id, CbomEstateAsset.asset_key.in_(list(part)))).all()}  # type: ignore[attr-defined]
        latest = E.latest_rows(session, team_id, [k for k in part if k in assets])
        chosen: dict[str, list[dict[str, Any]]] = {}
        for key in part:
            asset, item = assets.get(key), latest.get(key)
            if asset is None or item is None or asset.presence == "removed":
                continue
            obs = [o for o in item["observations"].values() if o["presence"] == "present" and o["asset_id"]]
            if not obs and item.get("latest", {}).get("asset_id"):
                obs = [item["latest"]]  # not read now: graded from what was read last
            if obs:
                chosen[key] = obs
        ids = sorted({o["asset_id"] for obs in chosen.values() for o in obs})
        rows: dict[int, CbomCollectedAsset] = {}
        for ids_part in _chunks(ids):
            rows.update({r.id: r for r in session.exec(select(CbomCollectedAsset).where(
                CbomCollectedAsset.id.in_(list(ids_part)))).all()})  # type: ignore[union-attr]
        writes: list[dict[str, Any]] = []
        gone: list[str] = []
        for key in part:
            before = stored.get(key)
            obs = [o for o in chosen.get(key, []) if o["asset_id"] in rows]
            if not obs:
                if before is not None:
                    gone.append(key)
                    out.transitions.append(Transition(key, (before.q_grade, before.q_reason), None))
                continue
            asset = assets[key]
            digest = hashlib.sha256(json.dumps([inputs.digest, model, sorted(
                [o["source_ref"], o["presence"], _content(rows[o["asset_id"]])] for o in obs)],
                separators=(",", ":")).encode()).hexdigest()[:16]
            if before is not None and before.grade_digest == digest and not force:
                out.skipped += 1
                continue
            graded = [(o["source_ref"], grader.grade(rows[o["asset_id"]])) for o in obs]
            ref, g = _worst(graded)
            g = not_correlated(g, asset.key_kind)
            row = next(rows[o["asset_id"]] for o in obs if o["source_ref"] == ref)
            src = inputs.by_source.get(row.source_id or 0) or {}
            pointer = next(o for o in obs if o["source_ref"] == ref)
            writes.append({
                "team_id": team_id, "item_key": key, "item_kind": "asset", "q_grade": g.q_grade,
                "q_rank": RANK.get(g.q_grade, 6), "q_reason": g.q_reason[:32], "label": (asset.label or None),
                "asset_type": asset.asset_type, "family": g.family, "source_ref": ref[:255],
                "source_name": (src.get("name") or None), "application": src.get("application"),
                "exposure": g.exposure, "presence": asset.presence, "sources": len(latest[key]["observations"]),
                "last_run_id": pointer.get("run_id") if run_id is None else run_id,
                "last_observed_at": pointer.get("observed_at"), "model_version": model[:32],
                "inputs_digest": inputs.digest, "grade_digest": digest, "updated_at": now})
            if before is None or (before.q_grade, before.q_reason) != (g.q_grade, g.q_reason):
                out.transitions.append(Transition(
                    key, (before.q_grade, before.q_reason) if before is not None else None, (g.q_grade, g.q_reason),
                    label=asset.label, source_ref=ref, source_name=src.get("name"), asset_type=asset.asset_type))
        _upsert(session, writes)
        if gone:
            session.execute(sa.delete(_RT).where(_RT.c.team_id == team_id, _RT.c.item_key.in_(gone)))
        out.written += len(writes)
        out.deleted += len(gone)
    out.graded = grader.graded
    return out


# ----------------------------------------------------------------------------- the estate hook and the re-grade
def apply_write(session: Session, write: Any) -> Refresh:
    """The run's keys (present observations of the sources it wrote, assets whose presence changed, keys that moved)
    graded where their digest changed, rows of keys that left the store deleted."""
    from backend.utilities.cbom_sources import estate as E

    keys = set(E.present_keys(session, write.team_id, write.source_refs)) | set(write.changed)
    keys |= {new for _old, new, _ref in write.rekeyed} | {old for old, _new, _ref in write.rekeyed}
    keys |= set(write.removed_keys)
    out = refresh(session, write.team_id, keys, write.at, run_id=write.run_id)
    if out.written or out.deleted:
        log("risk register written", team=write.team_id, run=write.run_id, **out.counts())
    return out


def _ordered_keys(session: Session, conds: list[Any], limit: int) -> list[str]:
    """Keys matching any of ``conds`` (each one simple enough for an index range), oldest grade first, at most
    ``limit``. One statement per condition: an OR of ranges is read as a filter over the whole team (CB-32)."""
    found: list[tuple[Any, str]] = []
    for cond in conds:
        found += session.execute(sa.select(_RT.c.updated_at, _RT.c.item_key).where(cond).order_by(
            _RT.c.updated_at, _RT.c.item_key).limit(limit)).all()
    found.sort(key=lambda r: (r[0] is not None, r[0] or _dt.datetime.min, r[1]))
    return [k for _at, k in found[:limit]]


def _other_model(team_id: int, model: str) -> list[Any]:
    """``model_version <> model`` as two index ranges (ix_cbomriskregister_team_model_inputs)."""
    return [sa.and_(_RT.c.team_id == team_id, _RT.c.model_version < model),
            sa.and_(_RT.c.team_id == team_id, _RT.c.model_version > model)]


def _other_inputs(team_id: int, model: str, digest: str) -> list[Any]:
    """``model_version = model AND inputs_digest <> digest`` as two index ranges."""
    return [sa.and_(_RT.c.team_id == team_id, _RT.c.model_version == model, _RT.c.inputs_digest < digest),
            sa.and_(_RT.c.team_id == team_id, _RT.c.model_version == model, _RT.c.inputs_digest > digest)]


def missing_count(session: Session, team_id: int, *, graded_live: int | None = None) -> int:
    """Live estate assets the register has no row for, as a difference of two index-only counts (live assets minus
    live register rows). Exact while the register follows the store (its hook runs in the store's write; a failed
    write marks the store stale and the backfill, with hooks, repairs both). An anti-join of 1.5M keys took ~1 s per
    call and ran on every summary and every scheduler tick (CB-32)."""
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

    live = SUMMARY.count(session, team_id, "assets_live")  # CB-32: trigger-kept counters, not two 1.5M counts
    graded = graded_live if graded_live is not None else sum(
        n for _g, _r, _f, presence, n in SUMMARY.register_groups(session, team_id) if presence != "removed")
    return max(0, live - graded)


def _mismatched(session: Session, team_id: int, inputs: TeamInputs, model: str, limit: int
                ) -> tuple[list[str], list[str], list[str]]:
    """(keys graded with another model, keys graded with other inputs, estate keys the register has not seen)."""
    by_model = _ordered_keys(session, _other_model(team_id, model), limit)
    by_inputs = _ordered_keys(session, _other_inputs(team_id, model, inputs.digest), max(0, limit - len(by_model)))
    room = max(0, limit - len(by_model) - len(by_inputs))
    _EA = CbomEstateAsset.__table__
    missing = list(session.execute(sa.select(_EA.c.asset_key).select_from(_EA.outerjoin(_RT, sa.and_(
        _RT.c.team_id == _EA.c.team_id, _RT.c.item_key == _EA.c.asset_key))).where(
        _EA.c.team_id == team_id, _EA.c.presence != "removed", _RT.c.id.is_(None))
        .order_by(_EA.c.asset_key).limit(room)).scalars()) if room and missing_count(session, team_id) else []
    return by_model, by_inputs, missing


def regrade_team(session: Session, team_id: int, now: _dt.datetime, *, limit: int = REGRADE_BATCH) -> dict[str, int]:
    """One batch of the background re-grade of a team: model change first, then inputs change, then keys never
    graded. Their Q0 asset items open / close with the matching cause. The caller commits."""
    from backend.utilities.cbom_sources import q0register as Q0
    from backend.utilities.cbom_sources import qgrade as QG

    inputs = team_inputs(session, team_id)
    by_model, by_inputs, missing = _mismatched(session, team_id, inputs, QG.GRADE_MODEL_VERSION, limit)
    out = {"model": len(by_model), "inputs": len(by_inputs), "missing": len(missing), "graded": 0}
    for keys, cause in ((by_model, "model_change"), (by_inputs, "inputs"), (missing, "observation")):
        if not keys:
            continue
        res = refresh(session, team_id, keys, now, inputs=inputs, force=True)
        out["graded"] += res.graded
        Q0.sync_assets(session, team_id, res.transitions, now, cause=cause)
    if any((by_model, by_inputs, missing)):
        Q0.sync_mosca(session, team_id, now)
        log("risk register re-graded", team=team_id, **out)
    return out


def _teams(session: Session) -> list[int]:
    return sorted(set(session.exec(select(CbomEstateAsset.team_id).distinct()).all()))  # type: ignore[attr-defined]


def regrade_due(engine, now: _dt.datetime, *, limit: int = REGRADE_BATCH) -> dict[str, int]:
    """Scheduler tick: one re-grade batch per team, each team in its own transaction."""
    total = {"teams": 0, "graded": 0}
    with Session(engine) as session:
        teams = _teams(session)
    for team_id in teams:
        with Session(engine) as session:
            try:
                res = regrade_team(session, team_id, now, limit=limit)
                session.commit()
                total["teams"] += 1
                total["graded"] += res["graded"]
            except Exception as exc:
                session.rollback()
                log("risk register re-grade FAILED", team=team_id, error=type(exc).__name__)
    return total


def pending(session: Session, team_id: int, *, graded_live: int | None = None) -> int:
    """Register rows still to re-grade after an inputs or model change, plus estate keys not graded yet."""
    from backend.utilities.cbom_sources import qgrade as QG

    inputs = team_inputs(session, team_id)
    model = QG.GRADE_MODEL_VERSION
    stale = sum(int(session.execute(sa.select(sa.func.count()).select_from(_RT).where(cond)).scalar_one())
                for cond in (*_other_model(team_id, model), *_other_inputs(team_id, model, inputs.digest)))
    return stale + missing_count(session, team_id, graded_live=graded_live)


# ----------------------------------------------------------------------------- the API
FILTERS = ("grade", "reason", "kind", "source", "application", "family", "exposure", "type", "presence")


def encode_after(rank: int, key: str) -> str:
    return base64.urlsafe_b64encode(f"{rank}|{key}".encode()).decode().rstrip("=")


def decode_after(value: str) -> tuple[int, str]:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    rank, _sep, key = raw.partition("|")
    if not key:
        raise ValueError("cursor")
    return int(rank), key


def _where(team_id: int, f: dict[str, Any]) -> list[Any]:
    cond = [_RT.c.team_id == team_id]
    if f.get("grade"):
        cond.append(_RT.c.q_grade.is_(None) if f["grade"] == "none" else _RT.c.q_grade == f["grade"])
    for name, col in (("reason", _RT.c.q_reason), ("kind", _RT.c.item_kind), ("source", _RT.c.source_ref),
                      ("application", _RT.c.application), ("family", _RT.c.family), ("exposure", _RT.c.exposure),
                      ("type", _RT.c.asset_type), ("presence", _RT.c.presence)):
        if f.get(name):
            cond.append(col == f[name])
    return cond


def _add_business(session: Session, team_id: int, items: list[dict[str, Any]]) -> None:
    """Engine step 3: each row's owners and the data classification of the systems its asset sits in (its sources'
    current metadata, ``estate_links.business``; no scan is read)."""
    from backend.utilities.cbom_sources import estate_links as LINKS

    biz = LINKS.business(session, team_id, [i["item_key"] for i in items])
    for item in items:
        b = biz.get(item["item_key"]) or {}
        item["owners"] = b.get("owners", [])
        item["data_classification"] = b.get("data_classification")


def public_row(r: Any) -> dict[str, Any]:
    from backend.utilities.cbom_sources.qgrade import LABELS

    return {"item_key": r.item_key, "item_kind": r.item_kind, "q_grade": r.q_grade,
            "q_label": LABELS.get(r.q_grade or ""), "q_reason": r.q_reason, "label": r.label,
            "asset_type": r.asset_type, "family": r.family, "source_ref": r.source_ref, "source_name": r.source_name,
            "application": r.application, "exposure": r.exposure, "presence": r.presence, "sources": r.sources,
            "last_run_id": r.last_run_id, "last_observed_at": iso_z(r.last_observed_at),
            "model_version": r.model_version, "updated_at": iso_z(r.updated_at)}


_SUMMARY_FILTERS = {"grade", "reason", "family", "presence"}


def _total(session: Session, team_id: int, filters: dict[str, Any]) -> int:
    """The filtered row count: from cbomregistersummary when every filter is one of its dimensions (CB-32), else a
    count over the filter's index."""
    active = {k: v for k, v in filters.items() if v}
    if set(active) <= _SUMMARY_FILTERS:
        from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

        want_grade = active.get("grade")
        return sum(n for grade, reason, fam, presence, n in SUMMARY.register_groups(session, team_id)
                   if (not want_grade or (grade is None if want_grade == "none" else grade == want_grade))
                   and (not active.get("reason") or reason == active["reason"])
                   and (not active.get("family") or fam == active["family"])
                   and (not active.get("presence") or presence == active["presence"]))
    return int(session.execute(sa.select(sa.func.count()).select_from(_RT).where(*_where(team_id, filters))).scalar_one())


def list_register(session: Session, team_id: int, filters: dict[str, Any], *, after: tuple[int, str] | None,
                  limit: int) -> dict[str, Any]:
    """One keyset page in (q_rank, item_key) order. ``total`` is counted on the first page only (``None`` on the
    next ones; the UI reads the first page's): at 1.5M rows a count per page cost more than the page (CB-32)."""
    q = sa.select(_RT).where(*_where(team_id, filters))
    if after is not None:  # a row-value range, so the (…, q_rank, item_key) index seeks to it (CB-32)
        q = q.where(sa.tuple_(_RT.c.q_rank, _RT.c.item_key) > sa.tuple_(after[0], after[1]))
    rows = list(session.execute(q.order_by(_RT.c.q_rank, _RT.c.item_key).limit(limit + 1)).all())
    more = len(rows) > limit
    rows = rows[:limit]
    total = None if after is not None else _total(session, team_id, filters)
    items = [public_row(r) for r in rows]
    _add_business(session, team_id, items)
    return {"items": items, "total": total,
            "next_after": encode_after(rows[-1].q_rank, rows[-1].item_key) if more and rows else None}


def summary(session: Session, team_id: int, now: _dt.datetime, *, weeks: int = 12) -> dict[str, Any]:
    from backend.new_models import CbomQ0Gap
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources import qgrade as QG

    # the tallies and the live rows "pending" needs come from cbomregistersummary, kept by triggers (CB-32)
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

    grades: dict[str | None, int] = {}
    q0_reasons: dict[str, int] = {}
    families: dict[str, dict[str, int]] = {}
    live = 0
    for grade, reason, fam, presence, n in SUMMARY.register_groups(session, team_id):
        live += int(n) if presence != "removed" else 0
        grades[grade] = grades.get(grade, 0) + int(n)
        if grade == "Q0":
            q0_reasons[reason] = q0_reasons.get(reason, 0) + int(n)
        bucket = families.setdefault(fam or "Other", {})
        bucket[grade or "none"] = bucket.get(grade or "none", 0) + int(n)
    gaps_open = dict(session.exec(select(CbomQ0Gap.reason, sa.func.count()).where(  # type: ignore[call-overload]
        CbomQ0Gap.team_id == team_id, CbomQ0Gap.closed_at.is_(None)).group_by(CbomQ0Gap.reason)).all())  # type: ignore[union-attr]
    start = (now - _dt.timedelta(days=now.weekday(), weeks=weeks - 1)).replace(hour=0, minute=0, second=0,
                                                                                microsecond=0)
    weekly: dict[str, dict[str, int]] = {}
    for i in range(weeks):
        monday = start + _dt.timedelta(weeks=i)
        weekly[monday.date().isoformat()] = {}
    end = start + _dt.timedelta(weeks=weeks)
    for closed_at, cause in session.exec(select(CbomQ0Gap.closed_at, CbomQ0Gap.close_cause).where(
            CbomQ0Gap.team_id == team_id, CbomQ0Gap.closed_at >= start,  # type: ignore[operator]
            CbomQ0Gap.closed_at < end)).all():  # type: ignore[operator]
        monday = (closed_at - _dt.timedelta(days=closed_at.weekday())).date().isoformat()
        bucket = weekly[monday]
        bucket[cause or "unknown"] = bucket.get(cause or "unknown", 0) + 1
    total = sum(int(v) for v in grades.values())
    return {
        "total": total, "q_grades": {g or "none": int(grades.get(g, 0)) for g in (*QG.GRADES, None)},
        "q0_reasons": {k: int(v) for k, v in sorted(q0_reasons.items())},
        "q0_gaps_open": {k: int(v) for k, v in sorted(gaps_open.items())},
        "families": dict(sorted(families.items())),
        "closures_by_week": [{"week": w, "total": sum(c.values()), "by_cause": dict(sorted(c.items()))}
                             for w, c in sorted(weekly.items())],
        "pending_regrade": pending(session, team_id, graded_live=live), "estate": E.stale_status(session, team_id),
        "model_version": QG.GRADE_MODEL_VERSION, "server_time": iso_z(now),
    }


HEATMAP_ROWS = 15
HEATMAP_COLUMNS = 10


def heatmap(session: Session, team_id: int, *, rows: int = HEATMAP_ROWS, columns: int = HEATMAP_COLUMNS
            ) -> dict[str, Any]:
    """Algorithm family x source: per cell the count per grade and its worst KNOWN grade (Q1 before Q4; Q0 is counted
    apart and never hides a known grade). Families and sources are ranked by worst grade then size; the rest fold into
    one "other" row / column (``other: true``, no drill-down). A cell drills down to the register list filtered by
    ``family`` and ``source`` (the cell's ``filter``). One GROUP BY on ``(team_id, family, source_ref, q_grade)``."""
    raw = session.execute(sa.select(_RT.c.family, _RT.c.source_ref, sa.func.max(_RT.c.source_name), _RT.c.q_grade,
                                    sa.func.count()).where(_RT.c.team_id == team_id)
                          .group_by(_RT.c.family, _RT.c.source_ref, _RT.c.q_grade)).all()
    names: dict[str, str | None] = {}
    fam_n: dict[str, int] = {}
    src_n: dict[str, int] = {}
    fam_worst: dict[str, int] = {}
    src_worst: dict[str, int] = {}
    for fam, ref, name, grade, n in raw:
        fam, ref = fam or "Other", ref or ""
        names[ref] = names.get(ref) or name
        fam_n[fam] = fam_n.get(fam, 0) + int(n)
        src_n[ref] = src_n.get(ref, 0) + int(n)
        if grade in ("Q1", "Q2", "Q3", "Q4"):
            fam_worst[fam] = min(fam_worst.get(fam, 9), RANK[grade])
            src_worst[ref] = min(src_worst.get(ref, 9), RANK[grade])
    fams = sorted(fam_n, key=lambda f: (fam_worst.get(f, 9), -fam_n[f], f))
    srcs = sorted(src_n, key=lambda r: (src_worst.get(r, 9), -src_n[r], r))
    keep_f, keep_s = set(fams[:rows]), set(srcs[:columns])
    cells: dict[tuple[str, str], dict[str, int]] = {}
    for fam, ref, _name, grade, n in raw:
        fam, ref = fam or "Other", ref or ""
        row_key = fam if fam in keep_f else "__other__"
        col_key = ref if ref in keep_s else "__other__"
        counts = cells.setdefault((row_key, col_key), {})
        counts[grade or "none"] = counts.get(grade or "none", 0) + int(n)
    out_cells = []
    for (fam, ref), counts in sorted(cells.items()):
        known = [g for g in ("Q1", "Q2", "Q3", "Q4") if counts.get(g)]
        other = fam == "__other__" or ref == "__other__"
        out_cells.append({"family": None if fam == "__other__" else fam, "source_ref": None if ref == "__other__" else ref,
                          "counts": dict(sorted(counts.items())), "total": sum(counts.values()),
                          "worst": known[0] if known else None, "q0": counts.get("Q0", 0), "other": other,
                          "filter": None if other else {"family": fam, "source": ref}})
    columns_out = [{"source_ref": r, "source_name": names.get(r), "total": src_n[r], "other": False}
                   for r in srcs[:columns]]
    if len(srcs) > columns:
        columns_out.append({"source_ref": None, "source_name": f"{len(srcs) - columns} more sources",
                            "total": sum(src_n[r] for r in srcs[columns:]), "other": True})
    rows_out = [{"family": f, "total": fam_n[f], "other": False} for f in fams[:rows]]
    if len(fams) > rows:
        rows_out.append({"family": None, "label": f"{len(fams) - rows} more families",
                         "total": sum(fam_n[f] for f in fams[rows:]), "other": True})
    return {"rows": rows_out, "columns": columns_out, "cells": out_cells, "total": sum(fam_n.values())}


REPORT_TOP = 100
REPORT_Q0 = 200


def report(session: Session, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    """What the register PDF prints (deliverable #2): the summary, the heat-map, the top Q1 Critical items and the
    open Q0 gaps by reason, read in one place so the PDF and the API cannot disagree."""
    from backend.new_models import CbomQ0Gap
    from backend.utilities.cbom_sources.q0register import public_gap

    top = list_register(session, team_id, {"grade": "Q1"}, after=None, limit=REPORT_TOP)
    gaps = session.exec(select(CbomQ0Gap).where(CbomQ0Gap.team_id == team_id, CbomQ0Gap.closed_at.is_(None))  # type: ignore[union-attr]
                        .order_by(CbomQ0Gap.reason, CbomQ0Gap.opened_at, CbomQ0Gap.id).limit(REPORT_Q0)).all()
    return {"summary": summary(session, team_id, now), "heatmap": heatmap(session, team_id),
            "top_q1": top["items"], "top_q1_total": top["total"],
            "q0_gaps": [public_gap(g, now) for g in gaps]}


def get_item(session: Session, team_id: int, key: str) -> dict[str, Any] | None:
    from backend.new_models import CbomQ0Gap
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources.q0register import public_gap

    row = session.execute(sa.select(_RT).where(_RT.c.team_id == team_id, _RT.c.item_key == key)).first()
    if row is None:
        return None
    latest = E.latest_rows(session, team_id, [key]).get(key) or {"observations": {}}
    observations = [{**o, "observed_at": iso_z(o.get("observed_at"))} for o in latest["observations"].values()]
    gaps = session.exec(select(CbomQ0Gap).where(CbomQ0Gap.team_id == team_id,
                                                CbomQ0Gap.item_key == f"asset:{key}")
                        .order_by(CbomQ0Gap.opened_at.desc())).all()  # type: ignore[union-attr,attr-defined]
    item = public_row(row)
    _add_business(session, team_id, [item])
    return {"item": item, "observations": sorted(observations, key=lambda o: o["source_ref"]),
            "q0_gaps": [public_gap(g, _dt.datetime.utcnow()) for g in gaps]}


def _csv_cell(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value  # a spreadsheet never runs a cell as a formula
    return value


def csv_rows(engine, team_id: int, filters: dict[str, Any], *, batch: int = 1000) -> Iterator[bytes]:
    """The register as CSV, streamed in keyset batches (constant memory), one short session per batch."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    yield buf.getvalue().encode()
    after: tuple[int, str] | None = None
    while True:
        with Session(engine) as session:
            page = list_register(session, team_id, filters, after=after, limit=batch)
        buf.seek(0)
        buf.truncate()
        for item in page["items"]:
            writer.writerow([_csv_cell("; ".join(v) if isinstance(v := item.get(c), list) else v)
                             for c in CSV_COLUMNS])
        yield buf.getvalue().encode()
        if not page["next_after"]:
            return
        after = decode_after(page["next_after"])


__all__ = ["TeamInputs", "team_inputs", "refresh", "apply_write", "regrade_team", "regrade_due", "pending",
           "list_register", "summary", "heatmap", "report", "not_correlated", "get_item", "csv_rows", "encode_after", "decode_after", "RANK",
           "ASSET_Q0_REASONS", "CSV_COLUMNS", "FILTERS", "LIMIT_MAX"]
