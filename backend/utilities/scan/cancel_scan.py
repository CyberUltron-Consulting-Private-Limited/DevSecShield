"""
Cancelling a code scan (SAST, IaC, SCA + SBOM, CBOM, AI BOM).

The scan row in Postgres decides the outcome. Cancel is ONE compare-and-set that flips a dispatched, unfinished scan to
"cancelled" and gives the charge back in the same transaction; the poller's transitions into "success" and "failure"
(utilities/celery/celery_connection.py) never touch a cancelled row, and its own refund only follows its own
transition. So a cancel racing with completion ends in exactly one state: completed and charged, or cancelled and
refunded once.

The worker learns about the cancel from a mark in the Celery result backend's Mongo database (the only store the
scan worker can reach, RabbitMQ/worker/helpers/context/cancellation.py): a queued task that a worker picks up is never
run, and a running one stops at its next progress point and kills the tool processes it started. ``revoke`` (without
terminate) is also sent so a worker that is up discards the queued message at once; the mark covers worker restarts.
"""
from __future__ import annotations

import datetime
from datetime import timezone

from fastapi import HTTPException, status
from rich.console import Console
from sqlalchemy import or_, update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import Scan, Team

console = Console()

CANCELLABLE_TYPES = ("sast", "iac", "sbom_sca", "cbom", "ai_bom")
# The Mongo collection (in the Celery result backend's database) the scan worker reads.
CANCEL_COLLECTION = "scan_cancellations"
_RUNNING = ("pending", "started", "retry")


class CancelRefused(Exception):
    """The scan cannot be cancelled: ``code`` and ``detail`` go to the client with a 409."""

    def __init__(self, code: str, detail: str, refunded: float | None = None):
        super().__init__(detail)
        self.code, self.detail, self.refunded = code, detail, refunded


def _credits_text(amount: float) -> str:
    value = round(float(amount or 0), 2)
    return f"{value:g} credit" + ("" if value == 1 else "s")


def refunded_credits(scan: Scan) -> float:
    """What a cancel gives back: what /start charged (the estimate for scans from before credit_charged existed)."""
    amount = scan.credit_charged if scan.credit_charged is not None else scan.credit_consumed
    return float(amount) if amount and amount > 0 else 0.0


def _refusal(scan: Scan) -> CancelRefused:
    if scan.scan_status == "cancelled":
        refunded = (scan.info or {}).get("refunded_credits") if isinstance(scan.info, dict) else None
        return CancelRefused("already_cancelled", "This scan was already cancelled"
                             + (f"; {_credits_text(refunded)} were refunded." if refunded else "."), refunded)
    if scan.scan_status == "success":
        return CancelRefused("already_completed", "This scan has already completed and cannot be cancelled.")
    if scan.scan_status == "failure":
        return CancelRefused("already_failed", "This scan has already failed and cannot be cancelled. "
                                               "Its credits were refunded when it failed.")
    if scan.scan_status == "pending" and not scan.task_id:
        return CancelRefused("starting", "This scan is still being started. Try again in a moment.")
    return CancelRefused("not_started", "This scan has not been started, so there is nothing to cancel.")


def tell_workers(task_id: str) -> None:
    """Revoke the queued message and leave the mark the worker checks (both best effort: the scan is already
    cancelled and refunded, and the poller never ingests a cancelled scan's results)."""
    from backend.utilities.celery.celery_connection import get_celery_app

    try:
        app = get_celery_app()
    except Exception as err:  # the broker is down: the mark below is the one that matters
        console.print(f"Cancel: no Celery app for task {task_id}: {err}", style="bold red")
        return
    try:
        app.control.revoke(task_id)  # no terminate: a running scan stops itself at its next safe point
    except Exception as err:
        console.print(f"Cancel: revoke failed for task {task_id}: {type(err).__name__}", style="bold yellow")
    try:
        app.backend.database[CANCEL_COLLECTION].update_one(
            {"_id": task_id},
            {"$set": {"cancelled_at": datetime.datetime.now(timezone.utc)}},
            upsert=True,
        )
    except Exception as err:
        console.print(f"Cancel: could not mark task {task_id} for the worker: {type(err).__name__}", style="bold red")


def _sync_with_worker(engine: Engine, scan: Scan) -> None:
    """Store the worker's result first when it has already finished, so a finished scan is reported as finished
    instead of being thrown away (the compare-and-set below is what keeps the race safe either way)."""
    from backend.utilities.celery import celery_connection

    try:
        celery_connection.get_status_and_update_db(scan_id=scan.id, task_id=scan.task_id, table=Scan, engine=engine)
    except Exception as err:
        console.print(f"Cancel: status sync skipped for scan {scan.id}: {err}", style="dim yellow")


def cancel_scan(engine: Engine, *, scan_id: int, team_id: int, scan_type: str, user_id: int) -> dict:
    """Cancel a pending or running code scan and refund its charge once. Raises 404 (no such scan in this team and
    type), 400 (a scan type that cannot be cancelled) or ``CancelRefused`` (finished, failed, already cancelled, not
    started)."""
    if scan_type not in CANCELLABLE_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only code scans can be cancelled.")

    def load(session: Session) -> Scan:
        scan = session.exec(select(Scan).where(Scan.id == scan_id, Scan.team_id == team_id,
                                               Scan.scan_type == scan_type)).first()
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return scan

    with Session(engine) as session:
        scan = load(session)
        if scan.scan_status not in _RUNNING or not scan.task_id:
            raise _refusal(scan)
        session.expunge(scan)

    _sync_with_worker(engine, scan)

    with Session(engine) as session:
        scan = load(session)
        if scan.scan_status not in _RUNNING or not scan.task_id:
            raise _refusal(scan)
        refund = refunded_credits(scan)
        task_id = scan.task_id
        now = datetime.datetime.now(timezone.utc)
        info = {
            "cancelled": True,
            "refunded_credits": round(refund, 4),
            "cancelled_by": user_id,
            "cancelled_at": now.isoformat(),
        }
        # The compare-and-set and the refund commit together: exactly one request flips the row, and only it refunds.
        won = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.team_id == team_id, Scan.task_id == task_id,
                   or_(*(Scan.scan_status == s for s in _RUNNING)))
            .values(scan_status="cancelled", info=info, last_updated=now)
        ).rowcount == 1
        if won and refund > 0:
            session.exec(update(Team).where(Team.id == team_id).values(credit_balance=Team.credit_balance + refund))
        session.commit()
        if not won:
            raise _refusal(load(session))

    console.print(f"Scan {scan_id} cancelled by user {user_id}; {refund} credits refunded to team {team_id}",
                  style="bold yellow")
    tell_workers(task_id)
    return {"scan_status": "cancelled", "refunded_credits": round(refund, 4),
            "message": f"Cancelled — {_credits_text(refund)} refunded."}
