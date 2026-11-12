"""
Never start a DAST run the backend withdrew while it was queued.

The backend withdraws a run (backend/utilities/scan/cancel_scan.py ``tell_workers``) when a reinitialize replaces the
queued run of a scan (backend/utilities/scan/reinitialize.py), or a reinitialize's claim is given back. It sends a
Celery ``revoke`` AND writes a mark in the Celery result backend's Mongo database: collection ``scan_cancellations``,
``_id`` = the task id (the same mark the scan worker reads, RabbitMQ/worker/helpers/context/cancellation.py). A revoke
lives only in the memory of a worker that is up: it is lost when no worker is running (the "stuck in the queue" case a
reinitialize is for), when the worker restarts, and after 3 hours (Celery's REVOKE_EXPIRES). The mark is not.

``skip_if_withdrawn`` wraps the DAST task (``bind=True``): before the scan starts it reads the mark through the task's
own result backend; a marked task is recorded as REVOKED and never run (Celery ``Ignore``). A Mongo error lets the scan
run (the backend never stores a withdrawn run's results: its poller only acts for the scan's current task). A DAST
scan is not cancelled by the customer once it runs, so the mark is not polled during the scan.
"""
from __future__ import annotations

import functools
from typing import Any, Callable

CANCEL_COLLECTION = "scan_cancellations"


def withdrawn(task: Any) -> bool:
    """True when the backend has withdrawn this task (its mark exists)."""
    task_id = getattr(getattr(task, "request", None), "id", None)
    if not task_id:
        return False
    try:
        return task.backend.database[CANCEL_COLLECTION].find_one({"_id": task_id}, {"_id": 1}) is not None
    except Exception:  # Mongo unreachable: run the scan (see the module docstring)
        return False


def skip_if_withdrawn(func: Callable) -> Callable:
    """Decorator for the bound DAST task: a withdrawn task is never started (module docstring)."""

    @functools.wraps(func)
    def run(self, *args, **kwargs):
        if withdrawn(self):
            from celery.exceptions import Ignore

            try:
                self.backend.mark_as_revoked(self.request.id, "withdrawn by the backend", request=self.request)
            except Exception:
                pass  # the scan row already moved on; this only tidies Celery's own record
            raise Ignore()
        return func(self, *args, **kwargs)

    return run


__all__ = ["CANCEL_COLLECTION", "skip_if_withdrawn", "withdrawn"]
