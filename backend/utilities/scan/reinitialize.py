"""
Reinitializing a dispatched scan with a new input (#33).

``POST /{team}/{type}/scan/{id}/reinitialize`` replaces the queued run of a scan that was estimated, charged and
dispatched but that the worker has not picked up yet (a run stuck in the queue), with a run of the input sent now
(the frontend sends what its form holds, which may differ from what was paid for). Before #33 it charged nothing for
the new input: pay for a tiny archive or URL list, reinitialize with a huge one for free.

The rules:

1. Only a scan type whose worker task honours the withdrawal mark (``start_scan.SCAN_TASKS``), and only a dispatched
   scan (``pending`` with a task) whose run the worker still reports as PENDING. Anything else is refused with 409:
   ``not_pending`` (not started yet, already picked up, finished, failed or cancelled), ``starting`` (/start or another
   reinitialize is still sending its run).
2. The new input is priced like a new scan's: the same estimator and minimum (``credit_estimate.priced``). The same
   input as the stored estimate (same digest) is not estimated again and costs nothing, whatever the formula now.
3. The scan pays the positive difference against what it has paid (``refunded_credits``: what a cancel or a failure
   gives back). A cheaper input is never refunded: the scan keeps what it paid.
4. A balance too small for the difference: 402, before anything is uploaded, charged or sent.
5. The target checks of a new scan run before any credit moves: the payload's validators (git host allow-list) when
   the route parses it, and ``format_input_for_scan`` (DAST address rule, 50 MB limit, archive and BOM checks) on
   every reinitialize, also when the estimate is skipped. Its output is the run's input (no second upload).
6. ONE transaction claims the scan and charges the difference: a compare-and-set of the scan (still ``pending`` with
   the task it had) to a claim, the conditional debit (``balance >= difference``) and its credits-ledger line
   (``credit_ledger.move``, key ``scan:{id}:reinit:{new task}``). Only one of several concurrent reinitializes can win
   the claim; a debit the balance no longer covers rolls the claim back. The claim persists everything a give-back
   needs, in the same UPDATE: ``task_id = reinit-<new run's task id>.<replaced task id>`` (claim_token.py; the new
   run's id is chosen before it is sent) and the replaced state (task, charge, estimate) in
   ``credit_estimate["reinitialize_claim"]``.
7. The run is recorded only while the claim is still ours (``start_scan_and_update_db(expected_task_id=...)``). If it
   cannot be sent or recorded, ``give_back_claim`` restores the replaced state and refunds the difference (with its
   line) in one transaction, only while the claim is still ours, and withdraws the new run. A claim taken meanwhile (a
   cancel, which refunds everything and withdraws both runs, or a give-back of a claim that went stale) answers 409
   ``superseded``.
8. The replaced run is withdrawn (revoke + the mark its task checks, ``tell_workers``), and the poller ignores it
   (``get_status_and_update_db`` only acts for the scan's current task, and never asks Celery about a claim).
9. A process that dies between the claim and the record (OOM kill, container restart) leaves the scan on its claim:
   ``sweep_stale_claims`` (run every minute by the scheduler sidecar, backend/utilities/dast/beat.py) gives back
   claims older than ``STALE_CLAIM_AFTER``; a reinitialize of a scan on a stale claim gives it back first; a cancel
   withdraws both runs of a claim and refunds everything.

A cancel or a failure afterwards refunds ``credit_charged``, which includes every difference paid, once.
"""
from __future__ import annotations

import datetime
from datetime import timezone
from typing import Any

from fastapi import HTTPException, UploadFile, status
from rich.console import Console
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import CreditLedgerEntry, Scan, Team
from backend.utilities.celery import celery_connection
from backend.utilities.db.schemas import StartScanPayload
from backend.utilities.scan import claim_token, credit_estimate, estimate_scan, format_input
from backend.utilities.scan.cancel_scan import refunded_credits, tell_workers
from backend.utilities.scan.start_scan import SCAN_TASKS, start_scan_and_update_db
from backend.utilities.team import credit_ledger

console = Console()

CLAIM_PREFIX = claim_token.CLAIM_PREFIX
CLAIM_KEY = "reinitialize_claim"  # in credit_estimate: the state a claim replaced (task, charge, estimate)
# A live claim lasts one send_task and one UPDATE (seconds, ~20 s with a broker that is down). Older: the request died.
STALE_CLAIM_AFTER = datetime.timedelta(minutes=10)


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
        f"{difference:g} more credit{'' if difference == 1 else 's'} {'is' if difference == 1 else 'are'} needed and "
        f"the team has {_credits(have)}. Nothing was charged.",
        credits_required=price, credits_paid=paid, credits_difference=difference, credit_balance=have)


_NOT_PENDING = {
    "NOT_STARTED": "This scan has not been started yet: Start estimates and charges it.",
    "started": "The worker has already picked this scan up, so it can no longer be reinitialized.",
    "retry": "The worker has already picked this scan up, so it can no longer be reinitialized.",
    "success": "This scan has already finished. Use Run again for a new run.",
    "failure": "This scan has failed (its credits were refunded). Use Run again for a new run.",
    "cancelled": "This scan was cancelled (its credits were refunded). Use Run again for a new run.",
}


def _not_pending(scan_status: str | None) -> ReinitializeRefused:
    """One stable code for "the scan is not waiting in the queue", whenever it is seen (before or after asking the
    worker); the detail says which state it is in."""
    reason = _NOT_PENDING.get(scan_status or "", "The worker has already picked this scan up, so it can no longer "
                                                 "be reinitialized.")
    return ReinitializeRefused(status.HTTP_409_CONFLICT, "not_pending", f"{reason} Nothing was charged.",
                               scan_status=scan_status)


def _starting() -> ReinitializeRefused:
    return ReinitializeRefused(status.HTTP_409_CONFLICT, "starting",
                               "This scan is still being started or reinitialized by another request. Try again in "
                               "a moment. Nothing was charged.")


def _conflict() -> ReinitializeRefused:
    return ReinitializeRefused(
        status.HTTP_409_CONFLICT, "reinitialize_conflict",
        "This scan changed while it was being reinitialized (it started, finished, was cancelled or was "
        "reinitialized by another request). Nothing was charged. Reload the scan and try again.")


def _superseded() -> ReinitializeRefused:
    """Our claim was taken while the run was being sent: by a cancel (which refunded everything the scan paid and
    withdrew both runs), or by a give-back of the claim as stale (which refunded this request's difference)."""
    return ReinitializeRefused(
        status.HTTP_409_CONFLICT, "superseded",
        "This scan was cancelled, or this reinitialize took too long and was rolled back, while its run was being "
        "sent, so the run was withdrawn. A cancel refunds everything the scan paid; a rollback gives this request's "
        "charge back. Reload the scan.")


def _load(session: Session, scan_id: int, team_id: int, scan_type: str) -> Scan | None:
    return session.exec(select(Scan).where(Scan.id == scan_id, Scan.team_id == team_id,
                                           Scan.scan_type == scan_type)).first()


def _charge_key(scan_id: int, new_task: str) -> str:
    return f"scan:{scan_id}:reinit:{new_task}"


def _refund_key(scan_id: int, new_task: str) -> str:
    return f"scan:{scan_id}:reinit-refund:{new_task}"


def _naive_utc(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _is_stale(last_updated: datetime.datetime | None, now: datetime.datetime | None = None,
              older_than: datetime.timedelta = STALE_CLAIM_AFTER) -> bool:
    now = _naive_utc(now or datetime.datetime.now(timezone.utc))
    seen = _naive_utc(last_updated)
    return seen is None or now - seen >= older_than


def _without_claim(estimate: Any) -> dict[str, Any] | None:
    if not isinstance(estimate, dict):
        return None
    return {k: v for k, v in estimate.items() if k != CLAIM_KEY}


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


def give_back_claim(engine: Engine, *, scan_id: int, token: str, by: str, user_id: int | None = None) -> bool:
    """A claim whose run was never recorded: in ONE transaction, only while the scan is still ``pending`` on this
    claim, restore what the claim replaced (task, charge, estimate: ``credit_estimate[CLAIM_KEY]``) and refund what
    the claim charged (its ledger line, if any) with a ``scan_reinitialize_refund`` line; then withdraw the new run,
    which may have been sent. False when the claim is not the scan's any more (recorded, cancelled, given back).
    ``by``: who gives it back (``dispatch_failure``, ``sweeper``, ``reinitialize``), kept in the line's detail."""
    parsed = claim_token.parse(token)
    if parsed is None:
        return False
    new_task, replaced = parsed
    with Session(engine) as session:
        scan = session.exec(select(Scan).where(Scan.id == scan_id)).first()
        if scan is None or scan.task_id != token or scan.scan_status != "pending":
            return False
        charged = session.exec(select(CreditLedgerEntry.delta_mc)
                               .where(CreditLedgerEntry.movement_key == _charge_key(scan_id, new_task))).first()
        charged_mc = -int(charged) if charged is not None and charged < 0 else 0
        difference = credit_ledger.from_mc(charged_mc) or 0.0
        snapshot = scan.credit_estimate.get(CLAIM_KEY) if isinstance(scan.credit_estimate, dict) else None
        if isinstance(snapshot, dict) and snapshot.get("task_id") == replaced:
            values: dict[str, Any] = {key: snapshot.get(key) for key in ("credit_charged", "credit_consumed",
                                                                         "credit_estimate")}
        else:  # no snapshot (never written by this code): the price before the claim is the price minus its charge
            values = {"credit_charged": round(float(scan.credit_charged or 0) - difference, 4),
                      "credit_consumed": round(float(scan.credit_consumed or 0) - difference, 4),
                      "credit_estimate": _without_claim(scan.credit_estimate)}
        values.update(task_id=replaced, last_updated=datetime.datetime.now(timezone.utc))
        won = session.exec(
            update(Scan).where(Scan.id == scan_id, Scan.task_id == token, Scan.scan_status == "pending")
            .values(**values)
        ).rowcount == 1
        if won and charged_mc > 0:
            credit_ledger.move(session, team_id=scan.team_id, delta_mc=charged_mc, reason="scan_reinitialize_refund",
                               movement_key=_refund_key(scan_id, new_task), ref_type="scan", ref_id=scan_id,
                               scan_id=scan_id, user_id=user_id, detail={"by": by, "refunded": difference})
        session.commit()
    if won:
        tell_workers(new_task)  # sent or not, the claim's run never runs; the replaced run goes ahead
        console.print(f"Scan {scan_id}: reinitialize claim given back ({by}); {difference} credits refunded",
                      style="bold yellow")
    return won


def sweep_stale_claims(engine: Engine, *, now: datetime.datetime | None = None,
                       older_than: datetime.timedelta = STALE_CLAIM_AFTER) -> list[int]:
    """Give back every reinitialize claim older than ``older_than`` (its request died between the claim and the
    record); returns the scans given back."""
    with Session(engine) as session:
        rows = session.exec(select(Scan.id, Scan.task_id, Scan.last_updated)
                            .where(Scan.scan_status == "pending", Scan.task_id.startswith(CLAIM_PREFIX))).all()
    given_back = []
    for scan_id, token, last_updated in rows:
        if not _is_stale(last_updated, now, older_than):
            continue
        try:
            if give_back_claim(engine, scan_id=scan_id, token=token, by="sweeper"):
                given_back.append(scan_id)
        except Exception as err:  # the next tick tries again
            console.print(f"Reinitialize sweep: scan {scan_id} not given back: {type(err).__name__}", style="bold red")
    return given_back


async def reinitialize_scan(engine: Engine, *, scan_type: str, scan_id: int, team_id: int, user_id: int,
                            start_scan_payload: StartScanPayload, uploaded_file: UploadFile | None = None
                            ) -> dict[str, Any]:
    """Replace the queued run of a dispatched scan with a run of this input, charging the difference (module doc).
    Raises HTTPException (400/404/413/422/500 as a new scan does) or ReinitializeRefused (402/409)."""
    if scan_type not in SCAN_TASKS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This scan type cannot be reinitialized")

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
            raise _not_pending(scan.scan_status)
        if not scan.task_id:
            raise _starting()
        current, claimed_at = scan.task_id, scan.last_updated

    if claim_token.is_claim(current):  # another reinitialize is sending its run, or died doing it
        if not _is_stale(claimed_at):
            raise _starting()
        give_back_claim(engine, scan_id=scan_id, token=current, by="reinitialize", user_id=user_id)
        with Session(engine) as session:
            scan = _load(session, scan_id, team_id, scan_type)
            if scan is None or scan.scan_status != "pending":
                raise _not_pending(scan.scan_status if scan else None)
            if not scan.task_id or claim_token.is_claim(scan.task_id):
                raise _conflict()
            current = scan.task_id
    old_task = current

    # ---- 2. the worker must not have picked the queued run up (the database may not know yet)
    worker_state, _data, _obj = celery_connection.get_status_and_update_db(
        scan_id=scan_id, task_id=old_task, table=Scan, engine=engine)
    with Session(engine) as session:
        scan = _load(session, scan_id, team_id, scan_type)
        if scan is None or scan.scan_status != "pending":
            raise _not_pending(scan.scan_status if scan else None)
        if worker_state != "pending":
            raise _not_pending(worker_state)
        if scan.task_id != old_task:
            raise _conflict()
        paid = round(refunded_credits(scan), 4)
        stored = _without_claim(scan.credit_estimate)
        snapshot = {"task_id": old_task, "credit_charged": scan.credit_charged,
                    "credit_consumed": scan.credit_consumed, "credit_estimate": stored}

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
    difference_mc = credit_ledger.to_mc(difference)
    total = round(paid + difference, 4)
    detail = {"scan_type": scan_type, "previous_charged": paid, "price": price, "difference": difference,
              "total": total, "input_digest": measured["digest"], "formula": measured["formula"]}

    # ---- 4. a balance that cannot cover the difference: refused before anything is uploaded for the run
    if difference_mc > 0:
        with Session(engine) as session:
            balance = session.exec(select(Team.credit_balance).where(Team.id == team_id)).first()
        if balance is None or balance < difference:
            raise _insufficient(price, paid, difference, balance)

    # ---- 5. the target checks and the run's input, exactly as a new scan's dispatch formats them
    scan_kwargs = await format_input.format_input_for_scan(scan_type=scan_type, start_scan_payload=start_scan_payload,
                                                           uploaded_file=uploaded_file)

    # ---- 6. claim (with what a give-back needs) + charge + its ledger line: one transaction
    new_task = claim_token.new_task_id()
    token = claim_token.make(new_task, old_task)
    values: dict[str, Any] = {"task_id": token, "credit_charged": total, "credit_consumed": total,
                              "credit_estimate": {**(new_estimate or stored or {}), CLAIM_KEY: snapshot},
                              "last_updated": datetime.datetime.now(timezone.utc)}
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
        if difference_mc > 0:
            after = credit_ledger.move(session, team_id=team_id, delta_mc=-difference_mc,
                                       reason="scan_reinitialize_charge", movement_key=_charge_key(scan_id, new_task),
                                       ref_type="scan", ref_id=scan_id, scan_id=scan_id, user_id=user_id,
                                       detail=detail, require_cover=True)
            if after is None:  # the balance was spent elsewhere after the check: the claim is rolled back with it
                session.rollback()
                balance = session.exec(select(Team.credit_balance).where(Team.id == team_id)).first()
                _remove_upload(scan_kwargs)
                raise _insufficient(price, paid, difference, balance)
        session.commit()
    console.print(f"Scan {scan_id}: reinitialize claimed; price {price}, paid {paid}, charged {difference} credits "
                  f"to team {team_id}", style="bold yellow")

    # ---- 7. send the new run (with the id the claim names); record it only while the claim is ours
    try:
        await start_scan_and_update_db(scan_type=scan_type, engine=engine, scan_id=scan_id, team_id=team_id,
                                       start_scan_payload=start_scan_payload, uploaded_file=uploaded_file,
                                       scan_kwargs=scan_kwargs, expected_task_id=token, task_id=new_task)
    except BaseException as failure:
        try:
            restored = give_back_claim(engine, scan_id=scan_id, token=token, by="dispatch_failure", user_id=user_id)
        except Exception as err:  # the claim stays; sweep_stale_claims gives it back
            console.print(f"CRITICAL: scan {scan_id}: reinitialize could not give its claim back now: "
                          f"{type(err).__name__}", style="bold red")
            restored = False
        console.print(f"Scan {scan_id}: reinitialize failed to send or record the run; claim "
                      f"{'given back with ' + str(difference) + ' credits' if restored else 'not given back here'}",
                      style="bold yellow")
        _remove_upload(scan_kwargs)
        # start_scan_and_update_db answers 409 when the claim was no longer ours at the moment it recorded the run
        if isinstance(failure, HTTPException) and failure.status_code == status.HTTP_409_CONFLICT and not restored:
            raise _superseded() from failure
        raise

    # ---- 8. the replaced run never runs
    tell_workers(old_task)
    console.print(f"Scan {scan_id}: reinitialized as task {new_task}; replaced task withdrawn", style="bold green")
    return {"message": "Scan reinitialized successfully", "credits_charged": difference, "credits_total": total,
            "credits_required": price}


__all__ = ["CLAIM_KEY", "CLAIM_PREFIX", "STALE_CLAIM_AFTER", "ReinitializeRefused", "give_back_claim",
           "reinitialize_scan", "sweep_stale_claims"]
