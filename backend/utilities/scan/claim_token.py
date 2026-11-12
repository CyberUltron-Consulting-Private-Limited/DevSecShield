"""The claim a reinitialize holds on a scan while it sends the new run (utilities/scan/reinitialize.py).

The claim is written into ``scan.task_id`` by the compare-and-set that also charges the difference, so it must carry
what anyone needs if the request dies before it records the new run: ``reinit-<new run's task id>.<replaced task id>``.
The new run's Celery task id is chosen before the claim (``send_task(task_id=...)``), so the run can be withdrawn even if
it was sent and never recorded; the replaced task is the run the scan goes back to when the claim is given back.

No imports from the rest of the backend: the poller, cancel and the worker withdrawal read tokens without cycles.
"""
from __future__ import annotations

import uuid

CLAIM_PREFIX = "reinit-"


def new_task_id() -> str:
    """The Celery task id of the run a reinitialize is about to send (Celery's own format)."""
    return str(uuid.uuid4())


def make(new_task: str, replaced_task: str) -> str:
    if "." in new_task or not replaced_task:
        raise ValueError("a claim needs a dot-free new task id and the replaced task id")
    return f"{CLAIM_PREFIX}{new_task}.{replaced_task}"


def is_claim(task_id: str | None) -> bool:
    return bool(task_id) and task_id.startswith(CLAIM_PREFIX)


def parse(task_id: str | None) -> tuple[str, str] | None:
    """(new run's task id, replaced task id) of a claim; None for anything else (a real task id, None)."""
    if not is_claim(task_id):
        return None
    new_task, sep, replaced = task_id[len(CLAIM_PREFIX):].partition(".")
    if not sep or not new_task or not replaced:
        return None
    return new_task, replaced


def task_ids(task_id: str | None) -> list[str]:
    """Every Celery task a scan's ``task_id`` stands for: a claim stands for the run being sent and the run it
    replaces (both must be withdrawn when the scan is cancelled while on the claim)."""
    if not task_id:
        return []
    parsed = parse(task_id)
    return list(parsed) if parsed else [task_id]


__all__ = ["CLAIM_PREFIX", "is_claim", "make", "new_task_id", "parse", "task_ids"]
