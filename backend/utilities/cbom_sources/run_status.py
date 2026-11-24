"""Why a Sources run has the status it has (FIX-B3), for the run API and the UI.

A finished run is ``partial`` when some job failed, expired or was cancelled while others succeeded, and also when
every job succeeded but one of them read only part of its targets (job ``outcome`` ``partial``/``failed``:
``jobs._final_status``).  Staging run #52 was the second case: 19 of 19 jobs ``success``, the run ``partial``, and
nothing on the run said that the Google Cloud job had read its project with gaps.  ``status_reason`` says it.

Pure: works on the job dicts ``serialize.public_job`` returns, or on the lighter rows the run lists build (keys
``id``, ``status``, ``outcome``, ``source_name``, ``error``, optional ``summary`` and ``waiting_reason``).
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

MAX_NAMED = 3  # jobs named in the sentence; every one is in ``status_reason_jobs``
MAX_JOBS = 50
_CATEGORY_WORDS = (
    ("partial", "collected only part of its targets", "collected only part of their targets"),
    ("failed", "failed", "failed"),
    ("expired", "expired", "expired"),
    ("cancelled", "was cancelled", "were cancelled"),
)


def _clip(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def job_problem(job: dict[str, Any]) -> tuple[str, str] | None:
    """(category, one line) for a job that did not read everything, else None."""
    status, outcome = job.get("status"), job.get("outcome")
    name = job.get("source_name") or f"job #{job.get('id')}"
    error = _clip(job.get("error") or "")
    summary = _clip(job.get("summary") or "")
    if status == "success" and outcome in ("partial", "failed"):
        detail = summary or error
        return "partial", f"{name}: collected only part of its targets" + (f" ({detail})" if detail else "")
    if status == "failure":
        return "failed", f"{name}: {error or 'failed'}"
    if status == "expired":
        return "expired", f"{name}: {error or 'expired before a scan node picked it up'}"
    if status == "cancelled":
        return "cancelled", f"{name}: {error or 'cancelled'}"
    return None


WINDOW_WAIT = "Outside the scan window"  # jobs.job_waiting_reason


def _offline_waits(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [j for j in jobs if j.get("status") == "pending" and "offline" in str(j.get("waiting_reason") or "")]


def _window_waits(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [j for j in jobs if j.get("status") == "pending" and str(j.get("waiting_reason") or "") == WINDOW_WAIT]


def status_reason(run_status: str | None, jobs: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """``{"status_reason": str | None, "status_reason_jobs": [...]}`` for a run and its jobs.

    done: no reason.  partial / failed / cancelled: how many jobs fell short and why, naming up to three.  running or
    queued: only when jobs wait for offline scan nodes (each says when it expires)."""
    jobs = list(jobs)
    problems: list[dict[str, Any]] = []
    by_category: dict[str, int] = {}
    for job in jobs:
        found = job_problem(job)
        if found is None:
            continue
        category, line = found
        by_category[category] = by_category.get(category, 0) + 1
        problems.append({"job_id": job.get("id"), "source_name": job.get("source_name"), "status": job.get("status"),
                         "outcome": job.get("outcome"), "category": category, "reason": line})
    total = len(jobs)
    if run_status in ("queued", "running"):
        waits, window = _offline_waits(jobs), _window_waits(jobs)
        if not waits and not window:
            return {"status_reason": None, "status_reason_jobs": []}
        parts = []
        if waits:
            first = _clip(str(waits[0].get("waiting_reason")), 240)
            parts.append(f"{len(waits)} of {total} jobs wait for an offline scan node; a job expires (and is "
                         f"refunded) when its node stays offline past the deadline. First: {first}")
        if window:  # staging QA2 Q1-12: a run held by the scan window said nothing
            parts.append(f"{len(window)} of {total} jobs wait for the scan window: "
                         f"{'it starts' if len(window) == 1 else 'they start'} when the window opens (Settings, "
                         "scan window)")
        return {"status_reason": _clip(". ".join(parts), 900), "status_reason_jobs": [
            {"job_id": j.get("id"), "source_name": j.get("source_name"), "status": "pending", "outcome": None,
             "category": "waiting", "reason": _clip(str(j.get("waiting_reason")), 240)}
            for j in [*waits, *window][:MAX_JOBS]]}
    if run_status not in ("partial", "failed", "cancelled") or not problems:
        return {"status_reason": None, "status_reason_jobs": []}
    parts = []
    for category, one, many in _CATEGORY_WORDS:
        n = by_category.get(category, 0)
        if n:
            parts.append(f"{n} {one if n == 1 else many}")
    full = total - len(problems)
    lead = {"partial": f"{full} of {total} jobs read everything; ",
            "failed": "No job read anything: ",
            "cancelled": ""}.get(str(run_status), "")
    named = "; ".join(p["reason"] for p in problems[:MAX_NAMED])
    more = len(problems) - MAX_NAMED
    text = f"{lead}{', '.join(parts)}. {named}" + (f"; and {more} more" if more > 0 else "")
    return {"status_reason": _clip(text, 900), "status_reason_jobs": problems[:MAX_JOBS]}
