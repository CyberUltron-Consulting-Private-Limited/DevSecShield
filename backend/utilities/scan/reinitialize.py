"""
Reinitializing a dispatched scan with a new input (#33).

``POST /{team}/{type}/scan/{id}/reinitialize`` replaces the queued run of a scan that was estimated, charged and
dispatched but that the worker has not picked up yet (a run stuck in the queue), with a run of the input sent now
(the frontend sends what its form holds, which may differ from what was paid for). Before #33 it charged nothing for
the new input: pay for a tiny archive or URL list, reinitialize with a huge one for free.

The rules:

1. Only a dispatched scan (``pending`` with a task) whose run the worker still reports as PENDING. A scan /start is
   still starting (no task yet) or that the worker already picked up is refused with 409: reinitializing it would
   send a second run.
2. The new input is priced like a new scan's: the same estimator and minimum (``credit_estimate.priced``). The same
   input as the stored estimate (same digest) is not estimated again and costs nothing, whatever the formula now.
3. The scan pays the positive difference against what it has paid (``refunded_credits``: what a cancel or a failure
   gives back). A cheaper input is never refunded: the scan keeps what it paid.
4. A balance too small for the difference: 402, before anything is uploaded, charged or sent.
5. The target checks of a new scan run before any credit moves: the payload's validators (git host allow-list) when
   the route parses it, and ``format_input_for_scan`` (DAST address rule, 50 MB limit, archive and BOM checks) on
   every reinitialize, also when the estimate is skipped. Its output is the run's input (no second upload).
6. ONE transaction claims the scan and charges the difference: a compare-and-set of the scan (still ``pending`` with
   the task it had) to a claim token, the conditional debit (``balance >= difference``) and the ledger line. Only one
   of several concurrent reinitializes can win the claim; a debit the balance no longer covers rolls the claim back.
7. The run is recorded only while the claim is still ours (``start_scan_and_update_db(expected_task_id=...)``). If it
   cannot be sent, the claim is given back with the difference (and a ledger line), in one transaction, only while
   it is still ours: a cancel that won meanwhile has already refunded everything the scan paid.
8. The replaced run is withdrawn (revoke + the cancel mark, as a cancel does) unless the scan got it back, and the
   poller ignores it (``get_status_and_update_db`` only acts for the scan's current task).

A cancel or a failure afterwards refunds ``credit_charged``, which includes every difference paid, once.
"""
from __future__ import annotations

import datetime
import uuid
from datetime import timezone
from typing import Any

from fastapi import HTTPException, UploadFile, status
from rich.console import Console
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import Scan, Team
from backend.utilities.celery import celery_connection
from backend.utilities.db.schemas import StartScanPayload
from backend.utilities.scan import credit_estimate, estimate_scan, format_input
from backend.utilities.scan.cancel_scan import refunded_credits, tell_workers
from backend.utilities.scan.start_scan import start_scan_and_update_db
from backend.utilities.team import credit_ledger

console = Console()

CLAIM_PREFIX = "reinit-"


class ReinitializeRefused(Exception):
    """The reinitialize cannot go ahead; nothing was charged or sent. Goes to the client as ``status_code`` with
    ``{"detail", "code", **extra}``."""

    def __init__(self, status_code: int, code: str, detail: str, **extra: Any):
        super().__init__(detail)
        self.status_code, self.code, self.detail, self.extra = status_code, code, detail, extra

    def body(self) -> dict[str, Any]:
        return {"detail": self.detail, "code": self.code, **self.extra}


def _credits(amount: float) -> str:
    value = round(float(amount or 0), 2)
    return f"{value:g} credit" + ("" if value == 1 else "s")


def _insufficient(price: float, paid: float, difference: float, balance: float | None) -> ReinitializeRefused:
    have = round(float(balance or 0), 2)
    return ReinitializeRefused(
        status.HTTP_402_PAYMENT_REQUIRED, "insufficient_credits",
        f"Reinitializing with this input costs {_credits(price)}. The scan has paid {_credits(paid)}, so "
        f"{difference:g} more credit{'' if difference == 1 else 's'} are needed and the team has {_credits(have)}. "
        "Nothing was charged.",
        credits_required=price, credits_paid=paid, credits_difference=difference, credit_balance=have)


def _conflict() -> ReinitializeRefused:
    return ReinitializeRefused(
        status.HTTP_409_CONFLICT, "reinitialize_conflict",
        "This scan changed while it was being reinitialized (it started, finished, was cancelled or was "
        "reinitialized by another request). Nothing was charged. Reload the scan and try again.")


def _load(session: Session, scan_id: int, team_id: int, scan_type: str) -> Scan | None:
    return session.exec(select(Scan).where(Scan.id == scan_id, Scan.team_id == team_id,
                                           Scan.scan_type == scan_type)).first()


def _uploaded_object(scan_kwargs: dict[str, Any]) -> tuple[str, str] | None:
    for key in ("zip_dict_context", "file_dict_context"):
        ctx = scan_kwargs.get(key)
        if isinstance(ctx, dict) and ctx.get("bucket_name") and ctx.get("object_name"):
            return ctx["bucket_name"], ctx["object_name"]
    return None


def _remove_upload(scan_kwargs: dict[str, Any] | None) -> None:
    """The run's input was uploaded but no run will read it: delete it (best effort, the scan is already safe)."""
    obj = _uploaded_object(scan_kwargs or {})
    if obj is None:
        return
    try:
        from backend.utilities.db import s3_utils

        s3_utils.delete_file(*obj)
    except Exception as err:
        console.print(f"Reinitialize: could not delete an unused upload: {type(err).__name__}", style="bold yellow")


async def _read(uploaded_file: UploadFile | None) -> bytes | None:
    if uploaded_file is None:
        return None
    data = await uploaded_file.read()
    await uploaded_file.seek(0)
    return data


def _give_back(engine: Engine, *, scan_id: int, team_id: int, user_id: int, token: str, previous: dict[str, Any],
               difference: float, detail: dict[str, Any]) -> bool:
    """The run could not be sent: the scan gets its old task and price back and the team the difference, in ONE
    transaction, only while the claim is still ours. False when it is not (a cancel won and refunded everything)."""
    with Session(engine) as session:
        won = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.team_id == team_id, Scan.task_id == token, Scan.scan_status == "pending")
            .values(**previous)
        ).rowcount == 1
        if won and difference > 0:
            session.exec(update(Team).where(Team.id == team_id)
                         .values(credit_balance=Team.credit_balance + difference))
            credit_ledger.record(session, team_id=team_id, scan_id=scan_id, user_id=user_id, delta=difference,
                                 reason="scan_reinitialize_refund", detail=detail)
        session.commit()
    return won


async def reinitialize_scan(engine: Engine, *, scan_type: str, scan_id: int, team_id: int, user_id: int,
                            start_scan_payload: StartScanPayload, uploaded_file: UploadFile | None = None
                            ) -> dict[str, Any]:
    """Replace the queued run of a dispatched scan with a run of this input, charging the difference (module doc).
    Raises HTTPException (400/404/413/422/500 as a new scan does) or ReinitializeRefused (402/409)."""
    # ---- 1. the scan: this team's, this type, the caller's, dispatched and not started
    with Session(engine) as session:
        scan = _load(session, scan_id, team_id, scan_type)
        if scan is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Scan not found or User not allowed to start this scan")
        if scan.owner_user_id != user_id:  # only the user who created the scan can reinitialize it
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="You do not have permission to reinitialize this scan")
        if scan.scan_status != "pending":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan is not pending, cannot reinitialize")
        if not scan.task_id:
            raise ReinitializeRefused(status.HTTP_409_CONFLICT, "starting",
                                      "This scan is still being started. Try again in a moment.")
        old_task = scan.task_id

    # ---- 2. the worker must not have picked the queued run up (the database may not know yet)
    worker_state, _data, _obj = celery_connection.get_status_and_update_db(
        scan_id=scan_id, task_id=old_task, table=Scan, engine=engine)
    with Session(engine) as session:
        scan = _load(session, scan_id, team_id, scan_type)
        if worker_state != "pending" or scan is None or scan.scan_status != "pending":
            raise ReinitializeRefused(
                status.HTTP_409_CONFLICT, "already_started",
                "The worker has already picked this scan up (or it finished or was cancelled), so it cannot be "
                "reinitialized. Nothing was charged.")
        if scan.task_id != old_task:
            raise _conflict()
        paid = round(refunded_credits(scan), 4)
        stored = dict(scan.credit_estimate) if isinstance(scan.credit_estimate, dict) else None
        previous = {"task_id": old_task, "credit_charged": scan.credit_charged,
                    "credit_consumed": scan.credit_consumed, "credit_estimate": scan.credit_estimate}

    # ---- 3. the price of the new input
    section = credit_estimate.payload_section(start_scan_payload, scan_type)
    measured = credit_estimate.input_digest(scan_type, section, await _read(uploaded_file))
    same_input = stored is not None and stored.get("digest") == measured["digest"]
    new_estimate = None
    if same_input:
        price = round(float(stored.get("credits") if stored.get("credits") is not None else paid), 2)
        difference = 0.0
    else:
        raw = await estimate_scan.estimate_credits(scan_type=scan_type, engine=engine,
                                                   start_scan_payload=start_scan_payload, uploaded_file=uploaded_file)
        if uploaded_file is not None:
            await uploaded_file.seek(0)
        price = credit_estimate.priced(scan_type, section, raw)
        new_estimate = {**measured, "minimum": credit_estimate.minimum_credits(scan_type, section), "credits": price}
        difference = round(max(0.0, price - paid), 2)
    total = round(paid + difference, 4)
    detail = {"scan_type": scan_type, "previous_charged": paid, "price": price, "difference": difference,
              "total": total, "input_digest": measured["digest"], "formula": measured["formula"]}

    # ---- 4. a balance that cannot cover the difference: refused before anything is uploaded for the run
    if difference > 0:
        with Session(engine) as session:
            balance = session.exec(select(Team.credit_balance).where(Team.id == team_id)).first()
        if balance is None or balance < difference:
            raise _insufficient(price, paid, difference, balance)

    # ---- 5. the target checks and the run's input, exactly as a new scan's dispatch formats them
    scan_kwargs = await format_input.format_input_for_scan(scan_type=scan_type, start_scan_payload=start_scan_payload,
                                                           uploaded_file=uploaded_file)

    # ---- 6. claim + charge + ledger line: one transaction
    token = f"{CLAIM_PREFIX}{uuid.uuid4().hex}"
    values: dict[str, Any] = {"task_id": token, "credit_charged": total, "credit_consumed": total,
                              "last_updated": datetime.datetime.now(timezone.utc)}
    if new_estimate is not None:
        values["credit_estimate"] = new_estimate
    with Session(engine) as session:
        claimed = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.team_id == team_id, Scan.scan_type == scan_type,
                   Scan.scan_status == "pending", Scan.task_id == old_task)
            .values(**values)
        ).rowcount == 1
        if not claimed:
            session.rollback()
            _remove_upload(scan_kwargs)
            raise _conflict()
        if difference > 0:
            debited = session.exec(
                update(Team).where(Team.id == team_id, Team.credit_balance >= difference)
                .values(credit_balance=Team.credit_balance - difference)
            ).rowcount == 1
            if not debited:
                balance = session.exec(select(Team.credit_balance).where(Team.id == team_id)).first()
                session.rollback()
                _remove_upload(scan_kwargs)
                raise _insufficient(price, paid, difference, balance)
            credit_ledger.record(session, team_id=team_id, scan_id=scan_id, user_id=user_id, delta=-difference,
                                 reason="scan_reinitialize_charge", detail=detail)
        session.commit()
    console.print(f"Scan {scan_id}: reinitialize claimed; price {price}, paid {paid}, charged {difference} credits "
                  f"to team {team_id}", style="bold yellow")

    # ---- 7. send the new run; record it only while the claim is ours
    try:
        new_task = await start_scan_and_update_db(scan_type=scan_type, engine=engine, scan_id=scan_id, team_id=team_id,
                                                  start_scan_payload=start_scan_payload, uploaded_file=uploaded_file,
                                                  scan_kwargs=scan_kwargs, expected_task_id=token)
    except BaseException:
        try:
            restored = _give_back(engine, scan_id=scan_id, team_id=team_id, user_id=user_id, token=token,
                                  previous=previous, difference=difference, detail=detail)
        except Exception as err:  # the claim stays: the scan keeps what it paid and can be cancelled or reinitialized
            console.print(f"CRITICAL: scan {scan_id}: reinitialize could not give its claim back: {err}",
                          style="bold red")
            restored = False
        console.print(f"Scan {scan_id}: reinitialize failed to send the run; claim "
                      f"{'given back with ' + str(difference) + ' credits' if restored else 'lost to another request'}",
                      style="bold yellow")
        if not restored:
            tell_workers(old_task)  # our claim replaced it and nothing gave it back to the scan
        _remove_upload(scan_kwargs)
        raise

    # ---- 8. the replaced run never runs
    tell_workers(old_task)
    console.print(f"Scan {scan_id}: reinitialized as task {new_task}; replaced task withdrawn", style="bold green")
    return {"message": "Scan reinitialized successfully", "credits_charged": difference, "credits_total": total,
            "credits_required": price}


__all__ = ["CLAIM_PREFIX", "ReinitializeRefused", "reinitialize_scan"]
