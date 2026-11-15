"""AI remediation of a finding, paid before it is generated (issue #87; hardened after reviews 5909551771, 5909721853).

Every claim lineage carries one **debit id** (the token of the claim that started it; a takeover keeps it, never clears
it), and every credit movement of that debit is a row of the credit ledger with a unique key, written in the same
transaction as the balance change (``cbomcreditentry``, the only ledger table on dev until the general credits ledger
of #52 / PR #57 lands; ``airem:<debit>:charge`` / ``airem:<debit>:refund``, run and job empty):

1. **Claim** the finding with one conditional Mongo update (``remediation_claim``): only a finding with no completed
   remediation and no live claim can be claimed, so at most one request per finding generates at a time; the others
   get ``RemediationBusy`` (HTTP 409). A claim untouched for ``CLAIM_TTL_S`` (its worker died or hangs) may be taken
   over: compare-and-set on that exact claim (token, time, state, debit), keeping its debit id.
2. **Charge** the debit id: insert its charge row ``ON CONFLICT DO NOTHING`` and, only if this call inserted it, the
   conditional ``UPDATE team SET credit_balance = credit_balance - cost WHERE credit_balance >= cost``, one
   transaction. So a debit is charged at most once whoever tries (the stalled request, its takeover, a retry), and
   whether it was charged is a fact in the database, not a guess: a worker that died after the commit leaves a claim
   whose retry finds the row and reuses the charge; one that died before it leaves no row, and the retry charges once.
   A team that cannot pay gets ``InsufficientCredits`` (HTTP 402) and the claim is dropped. A charge that raised
   without committing (no row) drops the claim too, so the finding can be retried at once; if even that cannot be
   told, the claim stays and expires.
3. **Generate**, then **store**: one conditional update on "the claim carrying this debit" that also drops the claim,
   so the store consumes the debit; a request whose claim was taken over can still store under its debit.
4. **Refund**: the request whose conditional update dropped the claim carrying the debit without storing a completed
   remediation refunds it: the refund row is inserted ``ON CONFLICT DO NOTHING`` together with the balance change,
   and only when the debit's charge row exists. So a refund happens at most once and only for a charge that
   committed, and the claim is gone the moment it is refunded (no 600 s block).

The claim lives next to ``remediation``, never in it, so finding lists never see it.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

from fastapi.concurrency import run_in_threadpool
from sqlalchemy import update as sa_update
from sqlmodel import Session, select

from backend.new_models import Team
from backend.utilities.cbom_sources import billing as LEDGER
from backend.utilities.team import credits as CREDITS

log = logging.getLogger("backend.ai.remediation")

COST = 0.05
COST_C = 5  # the ledger counts centi-credits
CLAIM_TTL_S = 600.0  # longer than two model calls; a claim untouched this long belongs to a worker that died
CLAIM = "remediation_claim"
REASON = "ai_remediation"


class RemediationBusy(Exception):
    """Another request is generating this finding's remediation right now (or took it over from this one)."""


class InsufficientCredits(Exception):
    """The team's balance does not cover the remediation; nothing was generated or stored."""


# ------------------------------------------------------------------------------------------------ the ledger
def ledger_key(debit: str, kind: str) -> str:
    return f"airem:{debit}:{kind}"


def _row(session: Session, key: str) -> Any:
    return session.exec(select(LEDGER.CbomCreditEntry).where(LEDGER.CbomCreditEntry.idem_key == key)).first()


def is_charged(debit: str) -> bool:
    with Session(CREDITS.get_db()) as session:
        return _row(session, ledger_key(debit, "charge")) is not None


def charge(team_id: int, debit: str) -> bool:
    """Charge ``debit`` once. True when this call charged it, False when it was charged before. Raises
    InsufficientCredits (nothing written)."""
    with Session(CREDITS.get_db()) as session:
        if _row(session, ledger_key(debit, "charge")) is not None:
            return False
        if not LEDGER.record(session, team_id=team_id, run_id=None, job_id=None, kind="charge", reason=REASON,
                             amount_c=COST_C, idem_key=ledger_key(debit, "charge")):
            session.rollback()
            return False  # a concurrent charge of the same debit won
        moved = session.exec(sa_update(Team).where(Team.id == team_id, Team.credit_balance >= COST)  # type: ignore[call-overload]
                             .values(credit_balance=Team.credit_balance - COST))
        if not moved.rowcount:
            session.rollback()
            raise InsufficientCredits()
        session.commit()
    log.info("ai remediation charged team=%s debit=%s", team_id, debit)
    return True


def refund(team_id: int, debit: str) -> bool:
    """Refund ``debit`` once, and only if its charge committed. True when this call refunded it."""
    with Session(CREDITS.get_db()) as session:
        if _row(session, ledger_key(debit, "charge")) is None:
            return False  # never charged: nothing to give back
        if not LEDGER.record(session, team_id=team_id, run_id=None, job_id=None, kind="refund", reason=REASON,
                             amount_c=COST_C, idem_key=ledger_key(debit, "refund")):
            session.rollback()
            return False  # refunded before
        session.exec(sa_update(Team).where(Team.id == team_id)  # type: ignore[call-overload]
                     .values(credit_balance=Team.credit_balance + COST))
        session.commit()
    log.info("ai remediation refunded team=%s debit=%s", team_id, debit)
    return True


# ------------------------------------------------------------------------------------------------ the claim
def _completed(doc: dict | None) -> dict | None:
    remediation = (doc or {}).get("remediation")
    return remediation if isinstance(remediation, dict) and remediation.get("status") == "completed" else None


def _take(collection: Any, finding_id: Any, scan_id: int, token: str) -> dict | None:
    """The new claim (keeping the debit id of the claim it takes over), or None when the finding is complete or
    claimed live."""
    doc = collection.find_one({"_id": finding_id, "scan_id": scan_id})
    if doc is None or _completed(doc) is not None:
        return None
    now = time.time()
    old = doc.get(CLAIM)
    flt: dict[str, Any] = {"_id": finding_id, "scan_id": scan_id, "remediation.status": {"$ne": "completed"}}
    claim = {"token": token, "at": now, "debit": token, "state": "claimed"}
    if isinstance(old, dict):
        at = old.get("at")
        if not isinstance(at, (int, float)) or at >= now - CLAIM_TTL_S:
            return None
        # compare-and-set on that exact claim: a stalled holder that moved on (charged, refreshed) makes this miss
        flt.update({f"{CLAIM}.token": old.get("token"), f"{CLAIM}.at": at, f"{CLAIM}.state": old.get("state"),
                    f"{CLAIM}.debit": old.get("debit")})
        if old.get("debit"):
            claim.update(debit=old["debit"], state=old.get("state") or "claimed")  # never cleared, never replaced
    else:
        flt[CLAIM] = {"$exists": False}
    return claim if collection.update_one(flt, {"$set": {CLAIM: claim}}).modified_count == 1 else None


def _drop_and_refund(collection: Any, finding_id: Any, team_id: int, debit: str, why: str,
                     failed: dict | None = None) -> bool:
    """Drop the claim carrying ``debit`` (storing a failed result with it) and, only if this call dropped it, refund
    the debit (once, and only if it was charged). False when another request already consumed or refunded it."""
    update: dict[str, Any] = {"$unset": {CLAIM: ""}}
    if failed is not None:
        update["$set"] = {"remediation": failed}
    dropped = collection.update_one({"_id": finding_id, f"{CLAIM}.debit": debit,
                                     "remediation.status": {"$ne": "completed"}}, update).modified_count == 1
    if not dropped:
        return False
    try:
        refund(team_id, debit)
    except Exception as exc:  # the ledger row says whether it happened; a later refund() of this debit is safe
        log.error("ai remediation refund FAILED team=%s finding=%s debit=%s reason=%s error=%s", team_id, finding_id,
                  debit, why, type(exc).__name__)
        raise
    return True


async def remediate(collection: Any, *, finding_id: Any, scan_id: int, team_id: int, finding_data: dict,
                    scan_type: str, generate: Callable[[dict, str], dict]) -> dict:
    """The finding's remediation: the stored one when it is complete, else a newly paid-for one (module docstring).
    Raises RemediationBusy, InsufficientCredits, or the error of a failed charge or generation."""
    token = uuid.uuid4().hex
    claim = _take(collection, finding_id, scan_id, token)
    if claim is None:
        stored = _completed(collection.find_one({"_id": finding_id}))
        if stored is not None:
            return stored  # finished (and charged) by the request that held the claim
        raise RemediationBusy()
    mine = {"_id": finding_id, f"{CLAIM}.token": token}
    debit = claim["debit"]
    try:
        charge(team_id, debit)  # a no-op when this debit was charged before (a takeover after a crash)
    except InsufficientCredits:
        collection.update_one(mine, {"$unset": {CLAIM: ""}})
        raise
    except Exception:
        try:
            committed = is_charged(debit)
        except Exception:
            raise  # cannot tell: the claim stays (and expires), so a retry never charges twice
        if not committed:
            collection.update_one(mine, {"$unset": {CLAIM: ""}})  # provably nothing charged: retry at once
            raise
        log.warning("ai remediation charge raised after its commit team=%s debit=%s", team_id, debit)
    if not collection.update_one(mine, {"$set": {CLAIM: {**claim, "state": "charged", "at": time.time()}}}
                                 ).modified_count:
        # taken over meanwhile: the new holder carries this debit and will consume or refund it
        raise RemediationBusy()
    try:
        result = await run_in_threadpool(generate, finding_data, scan_type)
        if not isinstance(result, dict):
            raise TypeError("remediation generator returned no result")
    except BaseException:
        _drop_and_refund(collection, finding_id, team_id, debit, "error")
        raise
    if result.get("status") == "completed":
        if collection.update_one({"_id": finding_id, f"{CLAIM}.debit": debit,
                                  "remediation.status": {"$ne": "completed"}},
                                 {"$set": {"remediation": result}, "$unset": {CLAIM: ""}}).modified_count:
            return result  # stored: the charge stands
        # the debit was consumed (a takeover stored first) or refunded (a takeover failed): not ours to give away
        stored = _completed(collection.find_one({"_id": finding_id}))
        if stored is not None:
            return stored
        raise RemediationBusy()
    # not completed: shown to the customer (its error), refunded, retried as a new attempt next time
    _drop_and_refund(collection, finding_id, team_id, debit, "generation_failed", failed=result)
    return result


__all__ = ["COST", "CLAIM_TTL_S", "RemediationBusy", "InsufficientCredits", "remediate", "charge", "refund",
           "is_charged", "ledger_key"]
