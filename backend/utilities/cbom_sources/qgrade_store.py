"""CB-19 PR-3: the record grade stored on each collected asset at ingest, and what reads it.

* ``ingest_grades`` grades the rows of one batch before they are inserted (``jobs.store_rows``, which both the node's
  own jobs and cloud-pool slices use), with ``qgrade``'s one context loader and ``GradeContext.grade_row``, so a stored
  grade is the grade every view computes. Rows are insert-only: nothing is UPDATEd later (PLAN §3, rejected (b)).
* A grade is stored only when it is the record grade the run's views compute: the run has its grade-input snapshot
  (PR-2), the run was started under the grade model version this code grades with, and the job carries its metadata
  snapshot (per-source X, exposure override, node segment). Otherwise both columns stay NULL ("graded at view").
* The one input a batch cannot know is CB-18 EC-3 (``posture.JudgedElsewhere``): an ``unknown`` row that another job of
  the same run read with a verdict is not an unknown verdict. That job may store its rows later, so the stored grade is
  the grade without that rule, and the reads below apply it in SQL (``_read_elsewhere``), exactly as the list does.
* ``status`` says whether a run's stored grades can serve the filter and facet: every row stored, the run's model
  version is the current one. Otherwise the run list hides the grade filter and says why (PLAN §2.5: old rows are
  never backfilled).

This module is outside ``GRADE_MODEL_VERSION`` on purpose: it computes no grade (``qgrade`` does), so adding or
changing it does not re-judge every run.
"""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

from sqlalchemy import and_, exists, func, not_, or_
from sqlalchemy.orm import aliased
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun
from backend.utilities.cbom_sources import posture as P
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.cbom_sources.common import log

GRADE_FILTERS = (*QG.GRADES, "none")
UNKNOWN = "unknown_verdict"


class Unavailable(ValueError):
    """The run's grades were not stored, so they cannot be filtered in SQL (409 on the API)."""


# ----------------------------------------------------------------------------- at ingest
def _context(session: Session, owner: CbomCollectionJob) -> QG.GradeContext | None:
    """The run's record context, or None when a grade stored now would not be the record grade."""
    if owner.run_id is None or not isinstance((owner.params or {}).get("metadata"), dict):
        return None
    run = session.get(CbomCollectionRun, owner.run_id)
    if run is None or run.grade_model_version != QG.GRADE_MODEL_VERSION:
        return None
    ctx = QG.load_context(session, team_id=owner.team_id, run_id=run.id)
    if ctx.inputs_source != "snapshot" or owner.id not in ctx.jobs:
        return None
    return replace(ctx, elsewhere=None)  # EC-3 is applied when the grades are read (module doc)


def ingest_grades(session: Session, owner: CbomCollectionJob, rows: list[dict[str, Any]]) -> int:
    """Set ``q_grade`` / ``q_reason`` on rows about to be inserted for ``owner`` (every row gets both keys: a
    multi-row INSERT needs one column set). Returns the rows graded."""
    for row in rows:
        row["q_grade"] = row["q_reason"] = None
    if not rows:
        return 0
    ctx = _context(session, owner)
    if ctx is None:
        return 0
    graded = 0
    for row in rows:
        view = SimpleNamespace(id=None, **row)
        codes = list(row.get("finding_codes") or [])
        try:
            cls = None if row["asset_type"] == "coverage" else P.classify_pqc(view, codes)[0]
            out = ctx.grade_row(view, codes, explain=False, cls=cls)  # type: ignore[arg-type]
        except Exception as exc:  # a row the grade cannot read stays "graded at view"; the batch is stored
            log("grade at ingest FAILED; asset stored without a stored grade", job=owner.id,
                asset_type=row.get("asset_type"), error=type(exc).__name__)
            continue
        row["q_grade"], row["q_reason"] = out.q_grade, out.q_reason
        graded += 1
    return graded


# ----------------------------------------------------------------------------- reads
def _read_elsewhere():
    """CB-18 EC-3 in SQL, as ``posture.JudgedElsewhere`` reads it: a stored ``unknown_verdict`` row with a row of the
    same run, asset type, target and location that another job read with a verdict."""
    other = aliased(CbomCollectedAsset)
    sibling = exists().where(
        other.team_id == CbomCollectedAsset.team_id, other.run_id == CbomCollectedAsset.run_id,
        other.asset_type == CbomCollectedAsset.asset_type, other.location == CbomCollectedAsset.location,
        func.coalesce(other.target, "") == func.coalesce(CbomCollectedAsset.target, ""),
        other.quantum_vulnerable.is_not(None), other.job_id != CbomCollectedAsset.job_id)  # type: ignore[union-attr]
    return and_(CbomCollectedAsset.q_reason == UNKNOWN, sibling)


def grade_clause(grade: str):
    """The rows whose list grade is ``grade`` ("Q0".."Q4" or "none")."""
    if grade not in GRADE_FILTERS:
        raise ValueError(f"q_grade: {grade}")
    if grade == "none":
        return or_(CbomCollectedAsset.q_grade.is_(None), _read_elsewhere())  # type: ignore[union-attr]
    if grade == "Q0":
        return and_(CbomCollectedAsset.q_grade == "Q0", not_(_read_elsewhere()))
    return CbomCollectedAsset.q_grade == grade


def status(session: Session, team_id: int, run: CbomCollectionRun) -> dict[str, Any]:
    """Whether the run's stored grades serve the grade filter and facet (``available``), and why not (``reason``)."""
    snap = run.grade_inputs if isinstance(run.grade_inputs, dict) else None
    if run.grade_model_version is None or not (snap and isinstance(snap.get("mosca"), dict)):
        return {"available": False, "reason": "graded at view: the run was started before grade inputs were "
                                              "recorded", "missing": None}
    if run.grade_model_version != QG.GRADE_MODEL_VERSION:
        return {"available": False, "reason": f"graded at view: the run was started under grade model "
                                              f"{run.grade_model_version}; the product now grades with "
                                              f"{QG.GRADE_MODEL_VERSION}", "missing": None}
    missing = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id,
        CbomCollectedAsset.q_reason.is_(None))).one())  # type: ignore[union-attr]
    if missing:
        return {"available": False, "reason": f"graded at view: {missing} of the run's assets were stored without "
                                              "a grade (collected before grades were stored, or by a job without "
                                              "its metadata snapshot)", "missing": missing}
    return {"available": True, "reason": None, "missing": 0}


def facet(session: Session, team_id: int, run_id: int, exclude: list[int] | None = None) -> dict[str, int]:
    """Rows per list grade over the whole run (coverage rows included, as the list shows them), from the stored
    column: one GROUP BY on the (run_id, q_grade) index, then EC-3's rows moved from Q0 to "none".  ``exclude``: rows
    the list leaves out because another job of the run read the same resource (``resource_identity.run_fold``)."""
    base = (CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)
    if exclude:
        base = (*base, CbomCollectedAsset.id.notin_(list(exclude)))  # type: ignore[union-attr]
    counts = {g: 0 for g in GRADE_FILTERS}
    for grade, n in session.exec(select(CbomCollectedAsset.q_grade, func.count()).where(*base)
                                 .group_by(CbomCollectedAsset.q_grade)).all():
        counts[grade or "none"] = counts.get(grade or "none", 0) + int(n)
    moved = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        *base, _read_elsewhere())).one())
    counts["Q0"] -= moved
    counts["none"] += moved
    return counts


__all__ = ["GRADE_FILTERS", "Unavailable", "facet", "grade_clause", "ingest_grades", "status"]
