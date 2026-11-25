"""CBOM Sources runs as rows of the CBOM Scans -> Table list (CB-38 PR-1a): ``GET /{team}/cbom/scans``
``runs_list_data`` / ``runs_total``.

One row per run of the team (newest first, ``LIST_LIMIT`` per page, ``runs_before=<run id>`` for the next page), in the
same column vocabulary as a code-scan row (``scan_status``, ``risk_data``, ``average_risk_score``, credits, owner), so
the browser renders both kinds in one table.

Counts are the run's verdict AS COLLECTED (``counts_basis``): severity = the stored ``impact`` of every asset that is
not a ``coverage`` row ("could not read X"), informational = the other assets, quantum-vulnerable = assets stored with
``quantum_vulnerable`` true. That is exactly what ``cbom_metrics.summarize_code_rows`` counts over
``collections_view.node_row`` rows judged at collection (``node_row`` makes an asset a finding iff it has an impact),
so a run row and a code-scan row use one rule (test B3). ``asset_count`` is every stored row of the run, coverage rows
included: the number Review & Run (``GET /runs``) and the run's assets API (``total`` / ``all_total``) show (issue #159).
Both run lists take it from ``asset_counts`` (Rule P: one function; test_cbom_159_run_asset_count_single_source.py).

Database work per list request (independent of the number of runs listed): one query for the page of runs, one count,
one grouped count over ``cbomcollectedasset (run_id, impact, quantum_vulnerable)`` and one over ``(run_id)``
(``asset_counts``) for the runs not in the cache, one
query for their jobs (plus one for deleted sources' names, only when such jobs exist), one for the team's sources and
one for the owners. Counts of finished runs are cached in-process by ``(run_id, last_updated, status)``; an active
run's counts are read live (its assets arrive without a status change).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Iterable

from sqlalchemy import case, func
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource, User
from backend.utilities.cbom_sources.run_status import status_reason
from backend.utilities.cbom_sources.cbom_metrics import (
    RUN_SCORED_STATUSES,
    average_risk,
    risk_fields,
    risk_posture,
)
from backend.utilities.cbom_sources.collections_view import NETWORK_TYPES, REMEDIATION_BUCKET
from backend.utilities.build_info import utc_timestamp
from backend.utilities.cbom_sources.common import console, iso_z, utcnow
from backend.utilities.cbom_sources.serialize import run_trigger, schedule_names

LIST_LIMIT = 200
CACHE_SIZE = 4_096
COUNTS_BASIS = "as_collected"
COVERAGE = "coverage"
FINISHED = frozenset({"done", "partial", "failed", "cancelled"})
JOB_DONE = frozenset({"success", "failure", "cancelled", "expired"})  # jobs.TERMINAL
_IMPACTS = {"Critical": "total_critical", "High": "total_high", "Medium": "total_medium", "Low": "total_low"}

# Run status -> the unified status the results table shows (contracts/cbom/status_buckets.json "run_to_unified",
# checked by test_status_buckets_file_matches_backend in tests/test_cb38_runs_in_results_api.py; the browser reads
# the same file).
RUN_TO_UNIFIED = {"queued": "pending", "running": "started", "done": "success", "partial": "partial",
                  "failed": "failure", "cancelled": "cancelled"}
# Remediation assignment status -> finding status ("assignment_to_finding"): collections_view's one table.
ASSIGNMENT_TO_FINDING = dict(REMEDIATION_BUCKET)


def unified_run_status(status: str | None) -> str:
    """The results table's status of a run (``not_started`` for a status this build does not know)."""
    return RUN_TO_UNIFIED.get(str(status or ""), "not_started")


def finding_status(assignment_status: str | None) -> str:
    """The finding status of an asset from its remediation assignment (no assignment = ``not_started``)."""
    return ASSIGNMENT_TO_FINDING.get(str(assignment_status or "open"), "not_started")


# ----------------------------------------------------------------------------- counts (cached for finished runs)
class _Lru:
    """A small thread-safe LRU (two list requests may build at once; each computes what it misses)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self._data: OrderedDict[tuple, dict[str, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple) -> dict[str, Any] | None:
        with self._lock:
            hit = self._data.get(key)
            if hit is not None:
                self._data.move_to_end(key)
            return hit

    def put(self, key: tuple, value: dict[str, Any]) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self.size:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


_COUNTS = _Lru(CACHE_SIZE)


def _cache_key(run: CbomCollectionRun) -> tuple:
    return (run.id, iso_z(run.last_updated), run.status)


def _empty_counts() -> dict[str, Any]:
    return {"risk_data": {"total_critical": 0, "total_high": 0, "total_medium": 0, "total_low": 0,
                          "total_informational": 0, "total_quantum_vulnerable": 0},
            "asset_count": 0, "endpoints_probed": 0}


def asset_counts(session: Session, team_id: int, run_ids: Iterable[int]) -> dict[int, int]:
    """THE asset count of each run (issue #159, Rule P): every stored row of the run, ``coverage`` rows included, the
    number the CBOM Scans table, Review & Run (``GET /runs``) and the run's assets API (``total`` / ``all_total`` of
    the unfiltered list) show. One grouped query; a run of another team (or with no rows) counts 0."""
    ids = sorted({int(i) for i in run_ids})
    out = {i: 0 for i in ids}
    if not ids:
        return out
    query = (select(CbomCollectedAsset.run_id, func.count())
             .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id.in_(ids))  # type: ignore[union-attr]
             .group_by(CbomCollectedAsset.run_id))
    for run_id, count in session.exec(query).all():
        out[int(run_id)] = int(count or 0)
    return out


def grouped_counts(session: Session, team_id: int, run_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
    """Severity, informational, quantum-vulnerable and probed-endpoint counts per run, as collected, in ONE grouped
    query, and ``asset_count`` from ``asset_counts`` (issue #159). ``coverage`` rows count only in ``asset_count``,
    never as a severity, informational, quantum-vulnerable or probed endpoint."""
    ids = sorted({int(i) for i in run_ids})
    out: dict[int, dict[str, Any]] = {i: _empty_counts() for i in ids}
    if not ids:
        return out
    for run_id, count in asset_counts(session, team_id, ids).items():
        out[run_id]["asset_count"] = count
    net = case((CbomCollectedAsset.asset_type.in_(sorted(NETWORK_TYPES)), 1), else_=0)  # type: ignore[union-attr]
    cov = case((CbomCollectedAsset.asset_type == COVERAGE, 1), else_=0)
    query = (select(CbomCollectedAsset.run_id, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable, net,
                    cov, func.count())
             .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id.in_(ids))  # type: ignore[union-attr]
             .group_by(CbomCollectedAsset.run_id, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable, net,
                       cov))
    for run_id, impact, qv, is_net, is_cov, count in session.exec(query).all():
        counts = out[int(run_id)]
        risk = counts["risk_data"]
        count = int(count or 0)
        if is_cov:
            continue  # "could not read X": a row of the run, never a finding or an endpoint (B3)
        if is_net:
            counts["endpoints_probed"] += count
        field = _IMPACTS.get(str(impact or ""))
        if field:
            risk[field] += count
        else:
            risk["total_informational"] += count
        if qv is True:
            risk["total_quantum_vulnerable"] += count
    # the verdict every other surface counts (``posture.stored_verdict``: a symmetric key is never quantum-vulnerable,
    # review 6057476173 M1): the stored column, corrected row by row where the class rule overrules it
    # (``posture.scope_corrections``: classified once per run and cached, review 6061787002)
    from backend.utilities.cbom_sources.posture import scope_corrections

    for run in ids:
        for _run_id, old, new in scope_corrections(session, team_id, run_id=run).values():
            if old is True and new is not True:
                out[run]["risk_data"]["total_quantum_vulnerable"] -= 1
            elif new is True and old is not True:
                out[run]["risk_data"]["total_quantum_vulnerable"] += 1
    return out


def _counts_for(session: Session, team_id: int, runs: list[CbomCollectionRun]) -> dict[int, dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    missing: list[CbomCollectionRun] = []
    for run in runs:
        hit = _COUNTS.get(_cache_key(run)) if run.status in FINISHED else None
        if hit is not None:
            found[int(run.id)] = hit
        else:
            missing.append(run)
    fresh = grouped_counts(session, team_id, (r.id for r in missing))
    for run in missing:
        counts = fresh[int(run.id)]
        if run.status in FINISHED:
            _COUNTS.put(_cache_key(run), counts)
        found[int(run.id)] = counts
    return found


# ----------------------------------------------------------------------------- jobs, sources, owners (live)
def _jobs_by_run(session: Session, team_id: int, run_ids: list[int]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {i: {"jobs_total": 0, "jobs_done": 0, "sources": {}, "rows": []} for i in run_ids}
    if not run_ids:
        return out
    sources = {s_id: (name, kind) for s_id, name, kind in session.exec(
        select(CbomCollectionSource.id, CbomCollectionSource.name, CbomCollectionSource.kind)
        .where(CbomCollectionSource.team_id == team_id)).all()}
    orphans: list[int] = []
    rows = session.exec(select(CbomCollectionJob.id, CbomCollectionJob.run_id, CbomCollectionJob.status,
                               CbomCollectionJob.source_id, CbomCollectionJob.outcome, CbomCollectionJob.error,
                               CbomCollectionJob.node_id, CbomCollectionJob.node_segment)
                        .where(CbomCollectionJob.team_id == team_id,
                               CbomCollectionJob.run_id.in_(run_ids))  # type: ignore[union-attr]
                        .order_by(CbomCollectionJob.id)).all()
    by_id: dict[int, dict[str, Any]] = {}
    partly_read: list[int] = []
    waiting: list[int] = []
    for job_id, run_id, job_status, source_id, outcome, error, node_id, segment in rows:
        entry = out[int(run_id)]
        entry["jobs_total"] += 1
        # FIX-B3: what the run's status_reason is built from (the run detail's job fields, #480 review m3)
        row = {"id": job_id, "status": job_status, "outcome": outcome, "error": error,
               "source_name": sources.get(source_id, (None, None))[0] if source_id else None}
        entry["rows"].append(row)
        by_id[int(job_id)] = row
        if job_status == "success" and outcome in ("partial", "failed"):
            partly_read.append(int(job_id))
        elif job_status == "pending" and node_id is not None and not segment:
            waiting.append(int(job_id))
        if job_status in JOB_DONE:
            entry["jobs_done"] += 1
        if source_id is not None and source_id in sources:
            name, kind = sources[source_id]
            entry["sources"].setdefault(("id", source_id), {"id": source_id, "name": name, "kind": kind})
        else:
            orphans.append(job_id)
    _reason_details(session, team_id, by_id, partly_read, waiting)
    if orphans:  # a deleted source keeps its name (and, on newer jobs, its kind) on the job's params
        for job_id, run_id, source_id, params in session.exec(
                select(CbomCollectionJob.id, CbomCollectionJob.run_id, CbomCollectionJob.source_id,
                       CbomCollectionJob.params).where(CbomCollectionJob.id.in_(orphans))).all():  # type: ignore[union-attr]
            params = params if isinstance(params, dict) else {}
            name = params.get("source_name")
            if not name and source_id is None:
                continue  # not a source's job (nothing to name)
            key = ("id", source_id) if source_id is not None else ("name", str(name))
            out[int(run_id)]["sources"].setdefault(key, {
                "id": source_id, "name": str(name or "Deleted source"), "kind": str(params.get("source_kind") or "")})
    return out


def _reason_details(session: Session, team_id: int, by_id: dict[int, dict[str, Any]], partly_read: list[int],
                    waiting: list[int]) -> None:
    """The two job fields ``status_reason`` reads beyond the job row, as the run detail has them (#480 review m3):
    the ``summary`` of a job that read its targets with gaps (its result is read only for those jobs), and the
    ``waiting_reason`` of a pending job pinned to an offline scan node (one query for those jobs, one for their
    nodes)."""
    if partly_read:
        for job_id, result in session.exec(select(CbomCollectionJob.id, CbomCollectionJob.result)
                                           .where(CbomCollectionJob.id.in_(partly_read))).all():  # type: ignore[union-attr]
            by_id[int(job_id)]["summary"] = (result or {}).get("summary") if isinstance(result, dict) else None
    if not waiting:
        return
    from backend.new_models import CbomCollectionSettings, CbomScanNode
    from backend.utilities.cbom_sources.jobs import (
        job_waiting_reason,
        offline_wait_reason,
    )
    from backend.utilities.cbom_sources.planning import node_status
    from backend.utilities.cbom_sources.run_status import WINDOW_WAIT

    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.id.in_(waiting))).all()  # type: ignore[union-attr]
    node_ids = sorted({int(j.node_id) for j in jobs if j.node_id is not None})
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(
        CbomScanNode.team_id == team_id, CbomScanNode.id.in_(node_ids))).all()}  # type: ignore[union-attr]
    settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    now = utcnow()
    for job in jobs:
        node = nodes.get(job.node_id)
        if node is not None and node_status(node, now) == "offline":
            by_id[int(job.id)]["waiting_reason"] = offline_wait_reason(job, node, now)
        elif node is not None and settings is not None:  # QA2 Q1-12: held by the scan window, as the run detail says
            source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
            if job_waiting_reason(job, node, settings, now, source) == WINDOW_WAIT:
                by_id[int(job.id)]["waiting_reason"] = WINDOW_WAIT


def _owners(session: Session, user_ids: Iterable[int]) -> dict[int, tuple[str | None, str | None]]:
    ids = sorted({int(i) for i in user_ids if i is not None})
    if not ids:
        return {}
    # a missing part is left out ("alice", never "alice None"); None when the user has neither
    return {uid: (email, " ".join(p for p in (first, last) if p) or None) for uid, email, first, last in session.exec(
        select(User.id, User.email, User.first_name, User.last_name).where(User.id.in_(ids))).all()}  # type: ignore[union-attr]


def _credits(centi: int | None) -> float:
    return round((centi or 0) / 100, 2)


def run_row(run: CbomCollectionRun, counts: dict[str, Any], jobs: dict[str, Any],
            owner: tuple[str | None, str | None] | None, schedule_name: str | None = None) -> dict[str, Any]:
    sources = sorted(jobs["sources"].values(), key=lambda s: (str(s["name"]).casefold(), s["id"] or 0))
    names = ", ".join(str(s["name"]) for s in sources)
    risk = dict(counts["risk_data"])
    severity = {"critical": risk["total_critical"], "high": risk["total_high"], "medium": risk["total_medium"],
                "low": risk["total_low"]}
    return {
        "kind": "run",
        "id": run.id,
        "title": f"Sources run #{run.id}" + (f" · {names}" if names else ""),
        "created_at": iso_z(run.created_at),
        "last_updated": iso_z(run.last_updated),
        "finished_at": iso_z(run.finished_at),
        "scan_status": unified_run_status(run.status),
        "run_status": run.status,
        # FIX-B3: why the run is partial / failed / cancelled, or what an open run waits for (as GET /runs/{id})
        "status_reason": status_reason(run.status, jobs.get("rows") or [])["status_reason"],
        "risk_data": risk,
        "average_risk_score": average_risk(severity),
        # the one risk score (posture function), as a code scan's list row (PR #500 takeover)
        # a run that has not finished (queued, running) or failed / was cancelled has no score (re-review 6064703319)
        **risk_fields(risk_posture(severity), judged=str(run.status or "") in RUN_SCORED_STATUSES),
        "sources": [{"id": s["id"], "name": s["name"], "kind": s["kind"]} for s in sources],
        "repo_url": None,
        "branch": None,
        "estimated_credits": _credits(run.credits_charged_c),
        "credits_refunded": _credits(run.credits_refunded_c),
        "owner_user_email": owner[0] if owner else None,
        "owner_user_full_name": owner[1] if owner else None,
        "asset_count": counts["asset_count"],
        "endpoints_probed": counts["endpoints_probed"],
        "jobs_total": jobs["jobs_total"],
        "jobs_done": jobs["jobs_done"],
        "linked_scan_id": run.scan_id,
        "counts_basis": COUNTS_BASIS,
        # S4: "scheduled" (with the schedule's id and, while it exists, its name) or "manual"
        "trigger": run_trigger(run),
        "schedule_id": run.schedule_id,
        "schedule_name": schedule_name,
    }


def list_run_rows(session: Session, team_id: int, *, before_id: int | None = None,
                  limit: int | None = None) -> dict[str, Any]:
    """``{"runs_list_data": [...], "runs_total": n}`` for the team (newest first; ``before_id``: only runs with a
    smaller id, the cursor of the next page). A ``before_id`` of another team's run, or of no run, only bounds the
    ids: the result is still this team's runs and nothing else."""
    started = time.perf_counter()
    total = int(session.exec(select(func.count()).select_from(CbomCollectionRun)
                             .where(CbomCollectionRun.team_id == team_id)).one())
    query = select(CbomCollectionRun).where(CbomCollectionRun.team_id == team_id)
    if before_id is not None:
        query = query.where(CbomCollectionRun.id < before_id)  # type: ignore[operator]
    runs = list(session.exec(query.order_by(CbomCollectionRun.id.desc()).limit(limit or LIST_LIMIT)).all())  # type: ignore[union-attr]
    ids = [int(r.id) for r in runs]
    counts = _counts_for(session, team_id, runs)
    jobs = _jobs_by_run(session, team_id, ids)
    owners = _owners(session, (r.owner_user_id for r in runs))
    schedules = schedule_names(session, team_id, (r.schedule_id for r in runs))
    rows = [run_row(r, counts[int(r.id)], jobs[int(r.id)], owners.get(r.owner_user_id),
                    schedules.get(r.schedule_id or 0)) for r in runs]
    ms = int((time.perf_counter() - started) * 1000)
    _log_line(team_id, len(rows), ms)
    return {"runs_list_data": rows, "runs_total": total}


def list_runs_for_scan_list(session: Session, team_id: int, *, before_id: int | None = None) -> dict[str, Any]:
    """What ``GET /{team}/cbom/scans`` adds. The code scans are listed even if the runs cannot be: a failure here is
    logged and answered as ``runs_list_error: true`` with no rows, never as a failed scan list."""
    try:
        return {**list_run_rows(session, team_id, before_id=before_id), "runs_list_error": False}
    except Exception as exc:  # noqa: BLE001 - the scan list must survive a runs failure
        session.rollback()
        log_line(f"cbom runs list failed team={team_id} error={type(exc).__name__}")
        return {"runs_list_data": [], "runs_total": 0, "runs_list_error": True}


def runs_for_scan_list(engine: Any, team_id: int, before_id: int | None = None) -> dict[str, Any]:
    """``list_runs_for_scan_list`` in its own session: the async scan-list handler runs it in a worker thread
    (``run_in_threadpool``), so building the runs never blocks the event loop."""
    with Session(engine) as session:
        return list_runs_for_scan_list(session, team_id, before_id=before_id)


def _log_line(team_id: int, runs: int, ms: int) -> None:
    """``cbom runs list team=<t> runs=<n> ms=<ms>``: one line per list build (compare UI, API and logs)."""
    log_line(f"cbom runs list team={team_id} runs={runs} ms={ms}")


def log_line(text: str) -> None:
    """One greppable line, prefixed with the ISO UTC time (logging must never fail a request)."""
    try:
        console.print(f"{utc_timestamp()} {text}", markup=False, highlight=False, soft_wrap=True)
    except Exception:  # noqa: BLE001, S110
        pass


def clear_cache() -> None:
    _COUNTS.clear()


__all__ = ["ASSIGNMENT_TO_FINDING", "COUNTS_BASIS", "LIST_LIMIT", "RUN_TO_UNIFIED", "asset_counts", "clear_cache",
           "finding_status",
           "grouped_counts", "list_run_rows", "list_runs_for_scan_list", "log_line", "runs_for_scan_list", "run_row", "unified_run_status"]

