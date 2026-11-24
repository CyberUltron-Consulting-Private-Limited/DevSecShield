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
from backend.utilities.cbom_sources.common import iso_z, log, utcnow

RANK = {"Q1": 1, "Q2": 2, "Q3": 3, "Q4": 4, "Q0": 5, None: 6}
ASSET_Q0_REASONS = ("unknown_verdict", "not_correlated")
BATCH = 500
REGRADE_BATCH = 2000
LIMIT_MAX = 500
CSV_COLUMNS = ("item_key", "q_grade", "q_label", "q_reason", "label", "asset_type", "family", "exposure",
               "source_name", "application", "presence", "sources", "last_run_id", "last_observed_at",
               "model_version", "owners", "data_classification",
               # SOW D12 (audit A-15): what the grade read and how to fix it, per asset (``add_detail``)
               *("pqc_class", "algorithm", "key_size", "fips_203_204_205", "cnsa_2_0", "sp800_131a", "fix_class",
                 "nist_pq_target", "nist_pq_reference", "data_lifetime_years", "data_lifetime_basis",
                 "migration_years", "crqc_years", "grade_inputs", "criticality", "owner"))
DETAIL_FIELDS = CSV_COLUMNS[CSV_COLUMNS.index("pqc_class"):]
_RT = CbomRiskRegister.__table__
USE_DIGESTS = True  # #352: narrow a write's keys with the content digests (False: every key, the reference path)


# ----------------------------------------------------------------------------- the team's inputs now
@dataclass
class TeamInputs:
    mosca: dict[str, int | None]
    risk_model: dict[str, Any]
    by_source: dict[int, dict[str, Any]]  # source id -> {x, exposure, segment, application, name, uid}
    digest: str
    year: int = 0  # the UTC year the default Z counts from (qgrade.default_z); 0: this year


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
            # the default Mosca X reads the source's business criticality (C5) when no X is set (qgrade.default_x)
            "criticality": meta.get("criticality") if meta.get("criticality") in ("low", "medium", "high", "critical")
            else None,
            "application": (str(cfg.get("application"))[:128] if cfg.get("application") else None),
            "name": s.name, "uid": s.source_uid}
    mosca = QG.mosca_of(risk_model)
    year = utcnow().year
    # the default Z is in the digest: on 1 January the years left until 2035 drop by one and the register re-grades
    doc = {"mosca": mosca, "sources": sorted([v["uid"] or str(k), v["x"], v["exposure"], v["segment"],
                                              v["criticality"]] for k, v in by_source.items()),
           "z_default": QG.default_z(year)}
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
                            .encode()).hexdigest()[:16]
    return TeamInputs(mosca=mosca, risk_model=risk_model, by_source=by_source, digest=digest, year=year)


# ----------------------------------------------------------------------------- grading one key
_CA = CbomCollectedAsset.__table__  # type: ignore[attr-defined]
_CONTENT = ("asset_type", "algorithm", "key_size", "protocol", "quantum_vulnerable", "target", "location",
            "finding_codes", "facts")  # the columns _content reads


def _content(row: Any) -> str:
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
                    ctx.jobs[jid] = replace(info, x=now["x"], exposure=now["exposure"], segment=now["segment"],
                                            criticality=now["criticality"])
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
        ea = CbomEstateAsset.__table__  # type: ignore[attr-defined]
        assets = {a.asset_key: a for a in session.execute(sa.select(  # plain columns: no ORM object per key
            ea.c.asset_key, ea.c.presence, ea.c.key_kind, ea.c.label, ea.c.asset_type).where(
            ea.c.team_id == team_id, ea.c.asset_key.in_(list(part)))).all()}
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
        content: dict[int, str] = {}  # the digest's inputs, read as plain columns (#352); ORM rows are loaded only
        for ids_part in _chunks(ids):  # for the keys whose digest changed, the few a run re-grades
            content.update({r.id: _content(r) for r in session.execute(sa.select(
                _CA.c.id, *(_CA.c[c] for c in _CONTENT)).where(_CA.c.id.in_(list(ids_part)))).all()})
        writes: list[dict[str, Any]] = []
        gone: list[str] = []
        first = len(out.transitions)
        due: list[tuple[str, list[dict[str, Any]], str]] = []
        for key in part:
            before = stored.get(key)
            obs = [o for o in chosen.get(key, []) if o["asset_id"] in content]
            if not obs:
                if before is not None:
                    gone.append(key)
                    out.transitions.append(Transition(key, (before.q_grade, before.q_reason), None))
                continue
            digest = hashlib.sha256(json.dumps([inputs.digest, model, sorted(
                [o["source_ref"], o["presence"], content[o["asset_id"]]] for o in obs)],
                separators=(",", ":")).encode()).hexdigest()[:16]
            if before is not None and before.grade_digest == digest and not force:
                out.skipped += 1
                continue
            due.append((key, obs, digest))
        rows: dict[int, CbomCollectedAsset] = {}
        for ids_part in _chunks(sorted({o["asset_id"] for _k, obs, _d in due for o in obs})):
            rows.update({r.id: r for r in session.exec(select(CbomCollectedAsset).where(
                CbomCollectedAsset.id.in_(list(ids_part)))).all()})  # type: ignore[union-attr]
        for key, obs, digest in due:
            before = stored.get(key)
            asset = assets[key]
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
        out.transitions[first:] = sorted(out.transitions[first:], key=lambda t: t.key)  # key order, as before
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
    graded where their digest changed, rows of keys that left the store deleted. Only the keys whose grade inputs
    may have changed are read (``write_keys``, #352); every other one would compute the digest it has."""
    inputs = team_inputs(session, write.team_id)
    keys = write_keys(session, write, inputs)
    out = refresh(session, write.team_id, keys, write.at, run_id=write.run_id, inputs=inputs)
    mark_through(session, write)
    if out.written or out.deleted:
        log("risk register written", team=write.team_id, run=write.run_id, **out.counts())
    return out


def all_write_keys(session: Session, write: Any) -> set[str]:
    """Every key ``apply_write`` would grade without the content digests (the path before #352; the tests' reference)."""
    from backend.utilities.cbom_sources import estate as E

    keys = set(E.present_keys(session, write.team_id, write.source_refs)) | set(write.changed)
    keys |= {new for _old, new, _ref in write.rekeyed} | {old for old, _new, _ref in write.rekeyed}
    return keys | set(write.removed_keys)


def write_keys(session: Session, write: Any, inputs: TeamInputs) -> set[str]:
    """The keys of ``all_write_keys`` whose grade digest may have changed (#352). A key is left out only when none of
    its observations changed: the store did not touch them in this write (``state_run_id``), and each one of a source
    this write re-read has the same content digest in the new job as in the job the register last graded that source
    from (``register_through``, which must be the job the source pointed at before this write). Every key is kept
    (the path before #352) while any register row was graded with another model or other inputs, or a live asset has
    no register row: the write grades those keys, as it did."""
    from backend.utilities.cbom_sources import agility_store as AS
    from backend.utilities.cbom_sources import estate as E

    team_id, run_id = write.team_id, int(write.run_id)
    model = _grade_model()
    if not USE_DIGESTS or any(session.execute(sa.select(_RT.c.id).where(cond).limit(1)).first() is not None
           for cond in _other_model(team_id, model) + _other_inputs(team_id, model, inputs.digest)) \
            or missing_count(session, team_id) > 0:
        return all_write_keys(session, write)
    _EO, _ES = E._EO, E._ES
    keys = set(write.changed) | {k for _o, new, _r in write.rekeyed for k in (_o, new)} | set(write.removed_keys)
    refs = list(write.source_refs or ())
    touched = set(session.execute(sa.select(_EO.c.asset_key).where(
        _EO.c.team_id == team_id, _EO.c.state_run_id == run_id).distinct()).scalars())
    for chunk in _chunks(sorted(touched - keys)):  # touched keys among the ones the write grades
        keys |= set(session.execute(sa.select(_EO.c.asset_key).where(
            _EO.c.team_id == team_id, _EO.c.asset_key.in_(list(chunk)), _EO.c.presence == "present",
            _EO.c.source_ref.in_(refs)).distinct()).scalars()) if refs else set()
    previous = getattr(write, "previous", None) or {}
    for r in session.execute(sa.select(_ES.c.source_ref, _ES.c.latest_job_id, _ES.c.latest_attempt,
                                       _ES.c.register_through_job_id, _ES.c.register_through_attempt).where(
            _ES.c.team_id == team_id, _ES.c.source_ref.in_(refs))).all() if refs else []:
        latest = (int(r.latest_job_id), int(r.latest_attempt or 1))
        through = (int(r.register_through_job_id), int(r.register_through_attempt)) \
            if r.register_through_job_id is not None and r.register_through_attempt is not None else None
        present = (_EO.c.team_id == team_id, _EO.c.source_ref == r.source_ref, _EO.c.presence == "present")
        if through == latest:
            continue
        changed = AS.changed_condition(session, write, latest, through) \
            if through is not None and through == previous.get(r.source_ref) else None
        if changed is None:  # not known (or most of the job changed): every key, as before
            keys |= set(E.present_keys(session, team_id, [r.source_ref]))
        else:
            keys |= set(session.execute(sa.select(_EO.c.asset_key).where(*present, changed)).scalars())
    return keys


def mark_through(session: Session, write: Any) -> None:
    """The register's grades of the sources ``write`` re-read now follow their latest job (#352)."""
    from backend.utilities.cbom_sources import estate as E

    if write.source_refs:
        session.execute(sa.update(E._ES).where(E._ES.c.team_id == write.team_id,
                                               E._ES.c.source_ref.in_(list(write.source_refs))).values(
            register_through_job_id=E._ES.c.latest_job_id, register_through_attempt=E._ES.c.latest_attempt))


def _grade_model() -> str:
    from backend.utilities.cbom_sources import qgrade as QG

    return QG.GRADE_MODEL_VERSION


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
        # a batch that re-graded rows of another grade model closes the Mosca item as a model change (recorded, not
        # forwarded, not a gap the team closed); otherwise the cause follows the team's inputs (q0register.mosca_cause)
        Q0.sync_mosca(session, team_id, now, cause="model_change" if by_model else None)
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
        item["business_criticality"] = b.get("criticality", [])


# grades whose rule decides before Mosca is read (qg-1 rules 1-6, the deprecated rules): why no input was used
_NOT_READ = {"not_correlated": "not used (Q0 before Mosca: not correlated across sources)",
             "unknown_verdict": "not used (Q0 before Mosca: PQC class unknown)",
             "deprecated": "not used (SP 800-131A disallowed: graded on exposure)",
             "deprecated_internet": "not used (SP 800-131A disallowed: graded on exposure)"}


def _inputs_text(assumed: tuple[str, ...] | list[str], reads_mosca: bool, reason: str | None = None) -> str:
    if not reads_mosca:
        return _NOT_READ.get(str(reason or ""), "not used (the class needs no Mosca inputs)")
    if assumed:
        return "default assumptions: " + ", ".join(k.upper() for k in assumed)
    return "team / source inputs"


def add_detail(session: Session, team_id: int, items: list[dict[str, Any]], now: _dt.datetime,
               inputs: TeamInputs | None = None) -> None:
    """SOW D12: per register row, what the grade read and what fixing it means, from the stored row the grade was
    taken from (the observation of the row's ``source_ref``): PQC class (with SP 800-131A ``deprecated``),
    algorithm and key size, the FIPS 203/204/205, CNSA 2.0 and SP 800-131A verdicts, the fix class, the NIST PQ
    target of its function, the Mosca inputs used (X with its basis, Y, Z, and whether a default filled one),
    business criticality and owner. Every surface (the list with ``detail``, the CSV, the PDF) calls this one
    function, so their values cannot differ. Needs ``_add_business`` first (owners, criticality)."""
    from backend.new_models import CbomCollectionJob
    from backend.utilities.cbom_sources import agility as AG
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources import posture as P
    from backend.utilities.cbom_sources import pqc_targets as PQT
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources import standards as STD
    from backend.utilities.cbom_sources.classify import shown, standards_of

    if not items:
        return
    inputs = inputs or team_inputs(session, team_id)
    latest = E.latest_rows(session, team_id, [i["item_key"] for i in items])
    pick: dict[str, int] = {}
    for item in items:
        entry = latest.get(item["item_key"]) or {}
        obs = (entry.get("observations") or {}).get(item.get("source_ref") or "") or entry.get("latest") or {}
        if obs.get("asset_id"):
            pick[item["item_key"]] = int(obs["asset_id"])
    rows: dict[int, CbomCollectedAsset] = {}
    for part in _chunks(sorted(set(pick.values()))):
        rows.update({r.id: r for r in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.id.in_(list(part)))).all()})  # type: ignore[union-attr]
    job_ids = sorted({r.job_id for r in rows.values()})
    jobs = {j.id: j for part in _chunks(job_ids) for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.id.in_(list(part)))).all()}  # type: ignore[union-attr]
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    contexts: dict[tuple, dict[str, Any]] = {}
    m = inputs.mosca
    grader = Grader(session, team_id, inputs, now)  # the grade's own context per run: its read-elsewhere rule (m1)
    for item in items:
        row = rows.get(pick.get(item["item_key"], -1))
        out: dict[str, Any] = {k: None for k in DETAIL_FIELDS}
        crit = item.get("business_criticality") or []
        out["criticality"] = "; ".join(crit) if isinstance(crit, list) else crit
        out["owner"] = "; ".join(item.get("owners") or []) or PQT.UNASSIGNED_OWNER
        if row is not None:
            facts = row.facts if isinstance(row.facts, dict) else {}
            codes = [c for c in shown(row, now)["finding_codes"] if not c.startswith("COVERAGE_")]
            # the class the grade read: the same JudgedElsewhere as ``Grader.grade`` (a row another job of the run read
            # with a verdict is not "unknown"), so the CSV never prints a class the grade did not use
            cls = QG.graded_pqc_class(P.classify_pqc(row, codes, elsewhere=grader._context(row).elsewhere)[0], row)
            graded = standards_of(row.asset_type, row.algorithm, row.key_size, facts)
            if not graded and row.algorithm:
                try:
                    graded = STD.grade([("key", row.algorithm, row.key_size)])
                except (ValueError, TypeError, KeyError, AttributeError):  # never costs the row its other columns
                    graded = None
            job = jobs.get(row.job_id)
            src = sources.get(row.source_id or 0)
            key = (row.job_id, row.source_id)
            if key not in contexts:
                contexts[key] = AG.node_context(job, src)
            fix = AG.evaluate("node", row.asset_type, codes, facts, contexts[key], row.location)
            target = PQT.asset_target(row.asset_type, row.algorithm, facts)
            src_in = inputs.by_source.get(row.source_id or 0) or {}
            x, y, z, basis, assumed = QG.effective_mosca(src_in.get("x"), m["x"], m["y"], m["z"],
                                                         src_in.get("criticality"), inputs.year)
            reads = str(item.get("q_reason") or "").startswith("qv_")
            out.update({
                "pqc_class": cls, "algorithm": row.algorithm, "key_size": row.key_size,
                **{k: (STD.export_value(graded[k]) if graded and k in graded else None)
                   for k in ("fips_203_204_205", "cnsa_2_0", "sp800_131a")},
                "fix_class": fix.get("fix_class"),
                "nist_pq_target": target["target_text"] if target else None,
                "nist_pq_reference": target["reference"] if target else None,
                "data_lifetime_years": x, "data_lifetime_basis": basis, "migration_years": y, "crqc_years": z,
                "grade_inputs": _inputs_text(assumed, reads, item.get("q_reason")),
            })
            if not out["criticality"] and src_in.get("criticality"):
                out["criticality"] = src_in["criticality"]
        item.update(out)


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
                  limit: int, detail: bool = False, now: _dt.datetime | None = None) -> dict[str, Any]:
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
    if detail:  # SOW D12: the CSV's per-asset columns (``add_detail``), on request (they read the stored rows)
        add_detail(session, team_id, items, now or utcnow())
    return {"items": items, "total": total,
            "next_after": encode_after(rows[-1].q_rank, rows[-1].item_key) if more and rows else None}


REMOVED_ITEMS_MAX = 200  # rows of the D12 "Removed from scope" table (the counts are always complete)


def _removed_condition(team_id: int) -> Any:
    """Register rows whose estate asset only deleted sources still hold: every observation not ``removed`` is
    ``not_read`` with reason "source deleted" (``estate.SOURCE_DELETED``), and there is at least one. Staging QA2
    Q1-01 / #497 review M2: they are history, never current population (the roll-up's ``is_deleted_source`` rule)."""
    from backend.new_models import CbomEstateObservation
    from backend.utilities.cbom_sources.estate import SOURCE_DELETED

    eo = CbomEstateObservation.__table__
    own = sa.and_(eo.c.team_id == _RT.c.team_id, eo.c.asset_key == _RT.c.item_key)
    deleted = sa.and_(eo.c.presence == "not_read", eo.c.presence_reason == SOURCE_DELETED)
    return sa.and_(_RT.c.team_id == team_id, _RT.c.presence != "removed",
                   sa.exists(sa.select(eo.c.id).where(own, deleted)),
                   ~sa.exists(sa.select(eo.c.id).where(own, eo.c.presence != "removed", ~deleted)))


def removed_from_scope(session: Session, team_id: int, *, items: int = 0) -> dict[str, Any]:
    """``{"total", "q_grades", "items"}``: the register rows of assets only deleted sources read (``items``: up to
    that many rows, worst first). ``summary`` leaves them out of ``total`` and ``q_grades``."""
    from backend.utilities.cbom_sources import qgrade as QG

    grades = dict(session.execute(sa.select(_RT.c.q_grade, sa.func.count()).where(_removed_condition(team_id))
                                  .group_by(_RT.c.q_grade)).all())
    out: dict[str, Any] = {"total": int(sum(grades.values())),
                           "q_grades": {g or "none": int(grades.get(g, 0)) for g in (*QG.GRADES, None)}, "items": []}
    if items and out["total"]:
        out["items"] = [public_row(r) for r in session.execute(sa.select(_RT).where(_removed_condition(team_id))
                                                               .order_by(_RT.c.q_rank, _RT.c.item_key)
                                                               .limit(items)).all()]
    return out


def summary(session: Session, team_id: int, now: _dt.datetime, *, weeks: int = 12) -> dict[str, Any]:
    from backend.new_models import CbomQ0Gap
    from backend.utilities.cbom_sources import estate as E

    # the tallies and the live rows "pending" needs come from cbomregistersummary, kept by triggers (CB-32)
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY
    from backend.utilities.cbom_sources import qgrade as QG

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
    # a closure the grade model made (``model_change``: a re-grade under a new model, a re-keyed item) is not a gap the
    # team closed: it is never forwarded (q0register.NOT_FORWARDED), so it is not counted here either (drift_report.
    # weekly_drift never sees it); the week is marked ``model_changes`` instead
    from backend.utilities.cbom_sources.q0register import NOT_FORWARDED

    model_weeks: dict[str, int] = {}
    for closed_at, cause in session.exec(select(CbomQ0Gap.closed_at, CbomQ0Gap.close_cause).where(
            CbomQ0Gap.team_id == team_id, CbomQ0Gap.closed_at >= start,  # type: ignore[operator]
            CbomQ0Gap.closed_at < end)).all():  # type: ignore[operator]
        monday = (closed_at - _dt.timedelta(days=closed_at.weekday())).date().isoformat()
        if cause in NOT_FORWARDED:
            model_weeks[monday] = model_weeks.get(monday, 0) + 1
            continue
        bucket = weekly[monday]
        bucket[cause or "unknown"] = bucket.get(cause or "unknown", 0) + 1
    # SOW D12 Table 7 "gaps closed by week": with each week's openings and the gaps still open at its end, from the
    # gap lifecycle the runs wrote (opened_at / closed_at), so the series reads as a burn-down
    opened = {w: 0 for w in weekly}
    open_end = {w: 0 for w in weekly}
    mondays = sorted(weekly)
    for opened_at, closed_at in session.exec(select(CbomQ0Gap.opened_at, CbomQ0Gap.closed_at).where(
            CbomQ0Gap.team_id == team_id, CbomQ0Gap.opened_at < end,  # type: ignore[operator]
            sa.or_(CbomQ0Gap.closed_at.is_(None), CbomQ0Gap.closed_at >= start))).all():  # type: ignore[union-attr]
        if opened_at >= start:
            opened[(opened_at - _dt.timedelta(days=opened_at.weekday())).date().isoformat()] += 1
        for monday in mondays:
            week_end = _dt.datetime.fromisoformat(monday) + _dt.timedelta(weeks=1)
            if opened_at < week_end and (closed_at is None or closed_at >= week_end):
                open_end[monday] += 1
    # #497 review M2 (Rule P): the assets only deleted sources read are not current population; D1, D12 and D14 print
    # this total, so they are left out here and returned apart (D12's "Removed from scope" table)
    removed = removed_from_scope(session, team_id)
    for grade, n in removed["q_grades"].items():
        key = None if grade == "none" else grade
        if n:
            grades[key] = max(int(grades.get(key, 0)) - n, 0)
    total = sum(int(v) for v in grades.values())
    return {
        "total": total, "q_grades": {g or "none": int(grades.get(g, 0)) for g in (*QG.GRADES, None)},
        "removed_from_scope": {"total": removed["total"], "q_grades": removed["q_grades"]},
        "q0_reasons": {k: int(v) for k, v in sorted(q0_reasons.items())},
        "q0_gaps_open": {k: int(v) for k, v in sorted(gaps_open.items())},
        "families": dict(sorted(families.items())),
        # Q0 GAP lifecycle per week (not drift events: drift_report.weekly_drift() counts findings opened / closed by
        # run comparison, a different series): total = Q0 gaps closed, q0_gaps_opened, q0_gaps_open_at_week_end
        "closures_by_week": [{"week": w, "total": sum(c.values()), "by_cause": dict(sorted(c.items())),
                              "q0_gaps_opened": opened[w], "q0_gaps_open_at_week_end": open_end[w],
                              "model_changes": model_weeks.get(w, 0)}
                             for w, c in sorted(weekly.items())],
        "default_assumptions": default_assumptions(session, team_id),
        "pending_regrade": pending(session, team_id, graded_live=live), "estate": E.stale_status(session, team_id),
        "model_version": QG.GRADE_MODEL_VERSION, "server_time": iso_z(now),
    }


def default_assumptions(session: Session, team_id: int, inputs: TeamInputs | None = None) -> dict[str, Any]:
    """SOW D12: how many register rows were graded on a default Mosca input (X, Y or Z the team / source has not
    set; ``qgrade.effective_mosca``), which inputs, and the defaults' text. A row reads Mosca only when its reason is
    a ``qv_*`` one (quantum-vulnerable, or a classical fallback)."""
    from backend.utilities.cbom_sources import qgrade as QG

    inputs = inputs or team_inputs(session, team_id)
    m = inputs.mosca
    by_ref = {(v.get("uid") or ""): v for v in inputs.by_source.values()}
    counts: dict[str, int] = {}
    count = 0
    for ref, n in session.execute(sa.select(_RT.c.source_ref, sa.func.count()).where(
            _RT.c.team_id == team_id, _RT.c.q_reason.like("qv\\_%", escape="\\"), _RT.c.presence != "removed")
            .group_by(_RT.c.source_ref)).all():
        src = by_ref.get(ref or "") or {}
        assumed = QG.effective_mosca(src.get("x"), m["x"], m["y"], m["z"], src.get("criticality"), inputs.year)[4]
        if assumed:
            count += int(n)
            for k in assumed:
                counts[k] = counts.get(k, 0) + int(n)
    return {"count": count, "inputs": {k: counts[k] for k in "xyz" if k in counts},
            "team_mosca": m, "defaults": QG.DEFAULTS_TEXT}


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
REPORT_ALL = 2000  # the PDF's per-asset appendix; the CSV always holds every row


def report(session: Session, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    """What the register PDF prints (SOW deliverable D12): the summary, the heat-map, the top Q1 Critical items and the
    open Q0 gaps by reason, read in one place so the PDF and the API cannot disagree."""
    from backend.new_models import CbomQ0Gap
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources.q0register import public_gap

    top = list_register(session, team_id, {"grade": "Q1"}, after=None, limit=REPORT_TOP, detail=True, now=now)
    gaps = session.exec(select(CbomQ0Gap).where(CbomQ0Gap.team_id == team_id, CbomQ0Gap.closed_at.is_(None))  # type: ignore[union-attr]
                        .order_by(CbomQ0Gap.reason, CbomQ0Gap.opened_at, CbomQ0Gap.id).limit(REPORT_Q0)).all()
    every = list_register(session, team_id, {}, after=None, limit=REPORT_ALL, detail=True, now=now)
    # #497 review M2: an asset only deleted sources read is listed under "Removed from scope", outside every table
    # and total of the document (the summary leaves it out of ``total`` / ``q_grades``)
    removed = removed_from_scope(session, team_id, items=REMOVED_ITEMS_MAX)
    gone = {r["item_key"] for r in removed["items"]}
    for page, less in ((top, removed["q_grades"].get("Q1", 0)), (every, removed["total"])):
        page["items"] = [r for r in page["items"] if r["item_key"] not in gone]
        if page["total"] is not None:
            page["total"] = max(int(page["total"]) - int(less), 0)
    return {"summary": summary(session, team_id, now), "heatmap": heatmap(session, team_id),
            "removed_from_scope": removed,
            "top_q1": top["items"], "top_q1_total": top["total"],
            "q0_gaps": [public_gap(g, now) for g in gaps],
            # SOW D12 "every asset with its grade": worst first, the same rows and columns as the CSV
            "assets": every["items"], "assets_total": every["total"],
            # what X, Y and Z mean, the defaults' sources, and each reason in words (the PDF prints these, never codes)
            "mosca_definition": QG.MOSCA_DEFINITION,
            "reason_text": {code: meta["text"] for code, meta in QG.REASONS.items()}}


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


CSV_BOM = "\ufeff"  # UTF-8 byte order mark: Excel on Windows reads the file as UTF-8 (labels carry "\u00b7")


def csv_rows(engine, team_id: int, filters: dict[str, Any], *, batch: int = 1000,
             now: _dt.datetime | None = None) -> Iterator[bytes]:
    """The register as CSV (RFC 4180: CRLF, minimal quoting; UTF-8 with a byte order mark; no cell a spreadsheet
    runs as a formula), streamed in keyset batches (constant memory), one short session per batch. Each row carries
    the per-asset detail columns (``add_detail``), the same values as ``GET …/register?detail=true``."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    yield (CSV_BOM + buf.getvalue()).encode("utf-8")
    after: tuple[int, str] | None = None
    now = now or utcnow()
    while True:
        with Session(engine) as session:
            page = list_register(session, team_id, filters, after=after, limit=batch, detail=True, now=now)
        buf.seek(0)
        buf.truncate()
        for item in page["items"]:
            writer.writerow([_csv_cell("; ".join(v) if isinstance(v := item.get(c), list) else v)
                             for c in CSV_COLUMNS])
        yield buf.getvalue().encode("utf-8")
        if not page["next_after"]:
            return
        after = decode_after(page["next_after"])


__all__ = ["DETAIL_FIELDS", "add_detail", "TeamInputs", "team_inputs", "refresh", "apply_write", "regrade_team", "regrade_due", "pending",
           "list_register", "summary", "heatmap", "report", "not_correlated", "get_item", "csv_rows", "encode_after", "decode_after", "RANK",
           "ASSET_Q0_REASONS", "CSV_COLUMNS", "FILTERS", "LIMIT_MAX"]
