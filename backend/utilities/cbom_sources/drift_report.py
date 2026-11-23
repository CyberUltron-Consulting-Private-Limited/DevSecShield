"""Drift in the delivered files (SOW S4: "drift results included in the final re-scan").

The customer receives files, not a platform login (SOW Section 2), so the change between a run and the previous
comparable run must be in the run's report PDF and evidence pack, not only on the results page. Rule P: every
number here is read from ``drift.run_diff``, the comparison ``GET /runs/{id}/diff`` and the run page's "Changes"
answer; nothing is recounted, except the Q0 transitions, which are read off that diff's own lists.

* ``run_drift(session, run)``: the run against ``drift.previous_comparable_run`` (or ``None`` baseline with the
  reason), as the compact ``zeroshield-cbom-run-drift/1`` document the PDF section and ``drift.json`` share.
* ``drift_bytes(doc)``: ``drift.json`` of the evidence pack (sorted keys, stable for a finished run).
* ``weekly_drift(session, team_id, now, weeks)``: the team's recorded drift events per ISO week and kind (opened,
  resolved, new / removed asset, Q0 gaps closed), the per-week source D12's "gaps closed by week" may also show.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import CbomCollectionRun, CbomDriftEvent
from backend.utilities.cbom_sources import drift as DRIFT
from backend.utilities.cbom_sources.common import iso_z

FORMAT = "zeroshield-cbom-run-drift/1"
TOP = 25  # items per list in the PDF and in drift.json (the counts are always complete)
LISTS = ("added", "removed", "changed", "opened", "resolved", "not_read")
COUNTS = ("added", "removed", "changed", "opened", "resolved", "not_read", "excluded", "entered_scope",
          "collector_changes", "rule_changes", "compared_sources", "not_compared_sources")
_ITEM_FIELDS = ("key", "label", "type", "source_name", "code", "impact", "q_grade", "location", "reason")
Q0_EVENT_SCAN = 5_000  # q0_closed events read to find this run's register closures


def _item(entry: dict[str, Any]) -> dict[str, Any]:
    out = {k: entry.get(k) for k in _ITEM_FIELDS if entry.get(k) not in (None, "", [])}
    changes = entry.get("changes")
    if isinstance(changes, dict) and changes:
        out["changes"] = {k: v for k, v in sorted(changes.items())}
    return out


def q0_transitions(diff: dict[str, Any]) -> dict[str, int]:
    """Assets graded Q0 Unknown on one side and not the other, read off the diff's lists: ``closed`` (Q0 before,
    Q1-Q4 now), ``opened`` (graded before, Q0 now, or a new asset at Q0), ``removed`` (a Q0 asset no longer
    collected)."""
    closed = opened = 0
    for entry in diff.get("changed") or []:
        grade = (entry.get("changes") or {}).get("q_grade")
        if isinstance(grade, list) and len(grade) == 2 and (grade[0] == "Q0") != (grade[1] == "Q0"):
            if grade[0] == "Q0":
                closed += 1
            else:
                opened += 1
    opened += sum(1 for entry in diff.get("added") or [] if entry.get("q_grade") == "Q0")
    removed = sum(1 for entry in diff.get("removed") or [] if entry.get("q_grade") == "Q0")
    return {"closed": closed, "opened": opened, "removed": removed}


def register_closures(session: Session, run: CbomCollectionRun) -> dict[str, int]:
    """Quantum-risk-register Q0 gaps this run closed (``q0_closed`` events whose detail names the run), by cause."""
    rows = session.exec(select(CbomDriftEvent.detail).where(
        CbomDriftEvent.team_id == run.team_id, CbomDriftEvent.kind == "q0_closed",
        CbomDriftEvent.at >= run.created_at)  # type: ignore[operator]
        .order_by(CbomDriftEvent.id).limit(Q0_EVENT_SCAN)).all()
    out: dict[str, int] = {}
    for detail in rows:
        detail = detail if isinstance(detail, dict) else {}
        if detail.get("run_id") == run.id:
            cause = str(detail.get("cause") or "unknown")
            out[cause] = out.get(cause, 0) + 1
    return dict(sorted(out.items()))


def summarise(run: CbomCollectionRun, base: CbomCollectionRun | None, diff: dict[str, Any] | None,
              register: dict[str, int] | None = None, message: str | None = None) -> dict[str, Any]:
    """The drift document for ``run`` (``diff`` is ``drift.run_diff(session, run, base)``, or None without a base)."""
    doc: dict[str, Any] = {
        "format": FORMAT,
        "run": {"id": run.id, "status": run.status, "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "trigger": _trigger(run), "schedule_id": run.schedule_id},
        "baseline": None,
        "source": "GET /{team}/cbom/sources/runs/{run}/diff (drift.run_diff), the run page's Changes",
    }
    if base is None or diff is None:
        doc["message"] = message or ("No earlier run collected any of these sources completely; nothing to compare "
                                     "yet")
        return doc
    counts = diff.get("counts") or {}
    doc.update({
        "baseline": {"id": base.id, "status": base.status, "created_at": iso_z(base.created_at),
                     "finished_at": iso_z(base.finished_at), "trigger": _trigger(base)},
        "counts": {k: int(counts.get(k, 0) or 0) for k in COUNTS},
        "readiness": dict(diff.get("readiness") or {}),
        "q0": {**q0_transitions(diff), "register_closed": register or {},
               "register_closed_total": sum((register or {}).values())},
        "rules": {k: (diff.get("versions") or {}).get(k) for k in ("rules_changed", "reclassified",
                                                                     "grade_model_changed", "grade_inputs_changed")},
        "sources": [{"name": s.get("name"), "status": s.get("status"), "reason": s.get("reason"),
                     "counts": s.get("counts")} for s in diff.get("sources") or []],
        "truncated": bool(diff.get("truncated")),
        "top": TOP,
    })
    for name in LISTS:
        doc[name] = [_item(e) for e in (diff.get(name) or [])[:TOP]]
    return doc


def _trigger(run: CbomCollectionRun) -> str:
    from backend.utilities.cbom_sources.serialize import run_trigger

    return run_trigger(run)


def run_drift(session: Session, run: CbomCollectionRun) -> dict[str, Any]:
    """``run`` against its previous comparable run (the same baseline ``/diff`` picks without ``against``)."""
    if run.status not in DRIFT.FINISHED:
        return summarise(run, None, None, message="The run is still collecting: drift is computed when it ends")
    base = DRIFT.previous_comparable_run(session, run)
    if base is None:
        return summarise(run, None, None)
    return summarise(run, base, DRIFT.run_diff(session, run, base), register_closures(session, run))


def drift_bytes(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")


WEEKLY_KINDS = ("opened", "resolved", "new_asset", "removed_asset", "q0_closed")


def weekly_drift(session: Session, team_id: int, now: _dt.datetime, *, weeks: int = 12) -> list[dict[str, Any]]:
    """Recorded drift events of the team per ISO week (Monday, UTC), oldest first, ``weeks`` weeks ending with the
    current one: ``{"week": "YYYY-MM-DD", "opened": n, "resolved": n, "new_asset": n, "removed_asset": n,
    "q0_closed": n}``. Read-only; the D12 "gaps closed by week" table can show it beside the register's closures."""
    now = now.replace(tzinfo=None)
    start = (now - _dt.timedelta(days=now.weekday(), weeks=max(1, weeks) - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0)
    series = {(start + _dt.timedelta(weeks=i)).date().isoformat(): dict.fromkeys(WEEKLY_KINDS, 0)
              for i in range(max(1, weeks))}
    rows = session.exec(select(CbomDriftEvent.at, CbomDriftEvent.kind, func.count()).where(
        CbomDriftEvent.team_id == team_id, CbomDriftEvent.at >= start,  # type: ignore[operator]
        CbomDriftEvent.kind.in_(WEEKLY_KINDS))  # type: ignore[union-attr]
        .group_by(CbomDriftEvent.at, CbomDriftEvent.kind)).all()
    for at, kind, n in rows:
        if at is None:
            continue
        monday = (at - _dt.timedelta(days=at.weekday())).date().isoformat()
        if monday in series:
            series[monday][kind] += int(n)
    return [{"week": week, **counts} for week, counts in series.items()]


__all__ = ["FORMAT", "LISTS", "TOP", "WEEKLY_KINDS", "drift_bytes", "q0_transitions", "register_closures",
           "run_drift", "summarise", "weekly_drift"]
