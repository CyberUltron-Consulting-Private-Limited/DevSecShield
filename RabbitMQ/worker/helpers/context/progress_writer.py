from celery import Task

from helpers.context.cancellation import check_cancelled


class StateUpdateWriter:
    """Writes a scan's progress to Celery. Every write is also a safe point: a scan the customer cancelled stops
    here (ScanCancelled, helpers/context/cancellation.py)."""

    def __init__(self, task : Task):
        self.task : Task = task


    def write_progress_percentage(self, progress : float):
        check_cancelled()
        self.task.update_state(state="STARTED", meta={"current": progress})


    def write_progress_out_of_total(self, current : int, total : int):
        check_cancelled()
        self.task.update_state(state="STARTED", meta={"current": current, "total": total})


    def update_state_with_meta(self, meta : dict):
        check_cancelled()
        self.task.update_state(state="STARTED", meta=meta)
