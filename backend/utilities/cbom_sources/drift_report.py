"""Drift in the delivered files (SOW S4: "drift results included in the final re-scan").

The customer receives files, not a platform login (SOW Section 2), so the change between a run and the previous
comparable run must be in the run's report PDF and evidence pack, not only on the results page. Rule P: every
number here is read from ``drift.run_diff``, the comparison ``GET /runs/{id}/diff`` and the run page's "Changes"
answer, including the Q0 transitions (its uncapped ``q0_*`` counts). A recorded run's document is taken once, after its
drift is recorded, and stored on the run (``drift_summary``): the report and the pack serve it, so a finished run's
files keep their bytes and no download re-runs the comparison.

* ``run_drift(session, run, store=False)``: the run against ``drift.previous_comparable_run`` (or ``None`` baseline
  with the reason), as the compact ``zeroshield-cbom-run-drift/1`` document the PDF section and ``drift.json`` share.
* ``drift_bytes(doc)``: ``drift.json`` of the evidence pack (sorted keys, stable for a finished run).
* ``weekly_drift(session, team_id, now, weeks)``: the team's recorded drift events per ISO week and kind (opened,
  resolved, new / removed asset, Q0 gaps closed), the per-week source D12's "gaps closed by week" may also show.
"""
from __future__ import annotations

import copy
import datetime as _dt
import json
import threading
from collections import OrderedDict
from typing import Any

from sqlalchemy import func, update
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
    """Assets graded Q0 Unknown on one side and not the other: ``closed`` (Q0 before, Q1-Q4 now), ``opened`` (graded
    before, Q0 now, or a new asset at Q0), ``removed`` (a Q0 asset no longer collected). From the diff's uncapped
    ``counts`` (``q0_closed`` / ``q0_opened`` / ``q0_removed``: its lists stop at LIST_CAP, review #486 minor 1); a
    diff without them is read off its lists."""
    counts = diff.get("counts") or {}
    if all(f"q0_{k}" in counts for k in ("closed", "opened", "removed")):
        return {k: int(counts[f"q0_{k}"] or 0) for k in ("closed", "opened", "removed")}
    return DRIFT.q0_counts(diff.get("changed") or [], diff.get("added") or [], diff.get("removed") or [])


def _closed_by(detail: dict[str, Any], at: _dt.datetime | None, run: CbomCollectionRun) -> bool:
    """Did ``run`` cause this ``q0_closed`` event? ``closed_by_run_id`` says so (None: a settings save, an evidence
    answer or a source removal closed it, review #486 M1). An event stored before that key existed has only
    ``run_id``, which falls back to the run that last saw the gap: it counts only when stamped with the run's own
    ``drift_at`` (the run's estate write and its register hook share that moment; a later closure never does)."""
    if "closed_by_run_id" in detail:
        return detail.get("closed_by_run_id") == run.id
    return detail.get("run_id") == run.id and run.drift_at is not None and at == run.drift_at


def register_closures(session: Session, run: CbomCollectionRun) -> dict[str, int]:
    """Quantum-risk-register Q0 gaps this run closed, by cause: ``q0_closed`` events the run caused, recorded by the
    time its drift was (``drift_at``; ``finished_at`` before that). A closure made later by something else, or by an
    estate replay of the run, never changes a finished run's number (its report.pdf is REPRODUCIBLE)."""
    end = run.drift_at or run.finished_at
    query = select(CbomDriftEvent.at, CbomDriftEvent.detail).where(
        CbomDriftEvent.team_id == run.team_id, CbomDriftEvent.kind == "q0_closed",
        CbomDriftEvent.at >= run.created_at)  # type: ignore[operator]
    if end is not None:
        query = query.where(CbomDriftEvent.at <= end)  # type: ignore[operator]
    out: dict[str, int] = {}
    for at, detail in session.exec(query.order_by(CbomDriftEvent.id).limit(Q0_EVENT_SCAN)).all():
        detail = detail if isinstance(detail, dict) else {}
        if _closed_by(detail, at, run):
            cause = str(detail.get("cause") or "unknown")
            out[cause] = out.get(cause, 0) + 1
    return dict(sorted(out.items()))


def summarise(run: CbomCollectionRun, base: CbomCollectionRun | None, diff: dict[str, Any] | None,
              register: dict[str, int] | None = None, message: str | None = None,
              schedules: dict[int, str] | None = None) -> dict[str, Any]:
    """The drift document for ``run`` (``diff`` is ``drift.run_diff(session, run, base)``, or None without a base).
    ``schedules``: names of the live schedules that started the runs (``serialize.schedule_names``)."""
    names = schedules or {}
    doc: dict[str, Any] = {
        "format": FORMAT,
        "run": {"id": run.id, "status": run.status, "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "trigger": _trigger(run), "schedule_id": run.schedule_id,
                "schedule_name": names.get(run.schedule_id or 0)},
        "baseline": None,
        # when the comparison was taken: the run's drift recording (null while it is not recorded yet)
        "recorded_at": iso_z(run.drift_at),
        "source": "GET /{team}/cbom/sources/runs/{run}/diff (drift.run_diff), the run page's Changes",
    }
    if base is None or diff is None:
        doc["message"] = message or ("No earlier run collected any of these sources completely; nothing to compare "
                                     "yet")
        return doc
    counts = diff.get("counts") or {}
    doc.update({
        "baseline": {"id": base.id, "status": base.status, "created_at": iso_z(base.created_at),
                     "finished_at": iso_z(base.finished_at), "trigger": _trigger(base),
                     "schedule_id": base.schedule_id, "schedule_name": names.get(base.schedule_id or 0)},
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


STORED_VERSION = 1  # of ``CbomCollectionRun.drift_summary``: another version is recomputed, never served
CACHE_SIZE = 32  # recorded runs without a stored document (finished before rsched1trig001): computed once per process
_CACHE: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
_CACHE_LOCK = threading.Lock()


def _stored(run: CbomCollectionRun, base_id: int | None) -> dict[str, Any] | None:
    """The document stored on the run, if it was taken against this baseline (keyed by run and baseline)."""
    held = getattr(run, "drift_summary", None)
    if (isinstance(held, dict) and held.get("v") == STORED_VERSION and held.get("baseline_id") == base_id
            and isinstance(held.get("doc"), dict) and held["doc"].get("format") == FORMAT):
        return held["doc"]
    return None


def _compute(session: Session, run: CbomCollectionRun, base: CbomCollectionRun | None) -> dict[str, Any]:
    from backend.utilities.cbom_sources.serialize import schedule_names

    names = schedule_names(session, run.team_id, [run.schedule_id, base.schedule_id if base is not None else None])
    if base is None:
        doc = summarise(run, None, None, schedules=names)
    else:
        doc = summarise(run, base, DRIFT.run_diff(session, run, base), register_closures(session, run), schedules=names)
    return json.loads(drift_bytes(doc))  # plain JSON: the same values whether served now or read back from the run


def run_drift(session: Session, run: CbomCollectionRun, *, store: bool = False) -> dict[str, Any]:
    """``run`` against its previous comparable run (the same baseline ``/diff`` picks without ``against``).

    A run whose drift is recorded (``drift_at``) gets its document once (review #486 minor 8): ``store=True`` (the
    scheduler's ``drift.store_pending_summaries``, after the recording) computes it and writes it to ``drift_summary``
    keyed by the baseline (the caller commits); a download serves that document as long as the baseline is the same,
    so report.pdf and drift.json neither run the full comparison again nor change afterwards. A recorded run without
    one (not reached yet, or recorded before the column existed) is computed once per process (LRU of CACHE_SIZE). A
    run not recorded yet is computed on every call, as before."""
    if run.status not in DRIFT.FINISHED:
        return summarise(run, None, None, message="The run is still collecting: drift is computed when it ends")
    base = DRIFT.previous_comparable_run(session, run)
    base_id = base.id if base is not None else None
    held = None if store else _stored(run, base_id)
    if held is not None:
        return held
    key = ((str(session.get_bind().url), run.team_id, run.id, run.client_request_id, iso_z(run.created_at), base_id,
            iso_z(run.drift_at), STORED_VERSION) if run.drift_at is not None else None)
    if key is not None and not store:
        with _CACHE_LOCK:
            if key in _CACHE:
                _CACHE.move_to_end(key)
                return copy.deepcopy(_CACHE[key])
    doc = _compute(session, run, base)
    if store and run.drift_at is not None:
        session.exec(update(CbomCollectionRun).where(CbomCollectionRun.id == run.id)  # type: ignore[call-overload]
                     .values(drift_summary={"v": STORED_VERSION, "baseline_id": base_id, "doc": doc}))
    elif key is not None:
        with _CACHE_LOCK:
            _CACHE[key] = copy.deepcopy(doc)
            while len(_CACHE) > CACHE_SIZE:
                _CACHE.popitem(last=False)
    return doc


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


__all__ = ["CACHE_SIZE", "FORMAT", "LISTS", "STORED_VERSION", "TOP", "WEEKLY_KINDS", "drift_bytes", "q0_transitions",
           "register_closures", "run_drift", "summarise", "weekly_drift"]
