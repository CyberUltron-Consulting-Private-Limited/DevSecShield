"""AI remediation of a finding, paid before it is generated (issue #87; hardened after review 5909551771).

Order, per finding:

1. **Claim** the finding with one conditional Mongo update (``remediation_claim``): only a finding with no completed
   remediation and no live claim can be claimed, so at most one request per finding generates at a time; the others
   get ``RemediationBusy`` (HTTP 409). A claim older than ``CLAIM_TTL_S`` (its worker died or hangs) may be taken
   over, compare-and-set on the old claim, and the new claim **inherits the old claim's debit**.
2. **Debit**, unless the claim inherited one: first the claim records the debit it is about to make (``debit`` = this
   claim's token, ``state`` = ``debiting``), then the atomic conditional UPDATE of ``deduct_credits_from_team``
   (``credit_balance >= cost``, one statement), then ``state`` = ``charged``. A team that cannot pay gets
   ``InsufficientCredits`` (HTTP 402), the claim is dropped and nothing is generated or stored. A worker that dies
   after the debit leaves a claim that names it, so the retry reuses that charge (or refunds it), never charges again.
   (A crash between recording ``debiting`` and the UPDATE's commit is treated as paid: the customer is never charged
   twice, at worst one remediation is not charged.)
3. **Generate**, then **store**: the store is one conditional update on "the claim carrying this debit" that also drops
   the claim, so it consumes the debit; a request whose claim was taken over can still store under the debit it made.
4. **Refund**: dropping the claim carrying a debit without storing a completed remediation (a failed or raising
   generation) is what entitles a refund, and only the request whose conditional update dropped it refunds. So each
   debit is consumed or refunded exactly once, the claim is gone the moment it is refunded (no 600 s block), and a
   refund whose bookkeeping raises after its commit is never repeated.

Every charge and refund is logged with its debit id (the claim token) for reconciliation until the credits ledger
(#52 / PR #57) is on dev. The claim lives next to ``remediation``, never in it, so finding lists never see it.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

from fastapi.concurrency import run_in_threadpool

from backend.utilities.team import credits as CREDITS

log = logging.getLogger("backend.ai.remediation")

COST = 0.05
CLAIM_TTL_S = 600.0  # longer than two model calls; a claim this old belongs to a worker that died
CLAIM = "remediation_claim"
PAID_STATES = ("debiting", "charged")


class RemediationBusy(Exception):
    """Another request is generating this finding's remediation right now (or took it over from this one)."""


class InsufficientCredits(Exception):
    """The team's balance does not cover the remediation; nothing was generated or stored."""


def _completed(doc: dict | None) -> dict | None:
    remediation = (doc or {}).get("remediation")
    return remediation if isinstance(remediation, dict) and remediation.get("status") == "completed" else None


def _take(collection: Any, finding_id: Any, scan_id: int, token: str) -> dict | None:
    """The new claim (with the debit it inherits, if any), or None when the finding is complete or claimed live."""
    doc = collection.find_one({"_id": finding_id, "scan_id": scan_id})
    if doc is None or _completed(doc) is not None:
        return None
    now = time.time()
    old = doc.get(CLAIM)
    flt: dict[str, Any] = {"_id": finding_id, "scan_id": scan_id, "remediation.status": {"$ne": "completed"}}
    claim = {"token": token, "at": now, "debit": None, "state": "claimed"}
    if isinstance(old, dict):
        at = old.get("at")
        if not isinstance(at, (int, float)) or at >= now - CLAIM_TTL_S:
            return None
        flt.update({f"{CLAIM}.token": old.get("token"), f"{CLAIM}.at": at})  # compare-and-set on that claim
        if old.get("debit") and old.get("state") in PAID_STATES:
            claim.update(debit=old["debit"], state=old["state"])
    else:
        flt[CLAIM] = {"$exists": False}
    return claim if collection.update_one(flt, {"$set": {CLAIM: claim}}).modified_count == 1 else None


def _refund_dropped(collection: Any, finding_id: Any, team_id: int, debit: str, why: str,
                    failed: dict | None = None) -> bool:
    """Drop the claim carrying ``debit`` (storing a failed result with it) and, only if this call dropped it, refund
    the debit once. False when another request already consumed or refunded it."""
    update: dict[str, Any] = {"$unset": {CLAIM: ""}}
    if failed is not None:
        update["$set"] = {"remediation": failed}
    dropped = collection.update_one({"_id": finding_id, f"{CLAIM}.debit": debit,
                                     "remediation.status": {"$ne": "completed"}}, update).modified_count == 1
    if not dropped:
        return False
    try:
        CREDITS.refund_credits_to_team(team_id, COST)
        log.info("ai remediation refunded team=%s finding=%s debit=%s reason=%s", team_id, finding_id, debit, why)
    except Exception as exc:  # never retried: the refund may have committed before the error
        log.error("ai remediation refund FAILED team=%s finding=%s debit=%s reason=%s error=%s", team_id, finding_id,
                  debit, why, type(exc).__name__)
        raise
    return True


async def remediate(collection: Any, *, finding_id: Any, scan_id: int, team_id: int, finding_data: dict,
                    scan_type: str, generate: Callable[[dict, str], dict]) -> dict:
    """The finding's remediation: the stored one when it is complete, else a newly paid-for one (module docstring).
    Raises RemediationBusy, InsufficientCredits, or the HTTPException of a credit helper."""
    token = uuid.uuid4().hex
    claim = _take(collection, finding_id, scan_id, token)
    if claim is None:
        stored = _completed(collection.find_one({"_id": finding_id}))
        if stored is not None:
            return stored  # finished (and charged) by the request that held the claim
        raise RemediationBusy()
    mine = {"_id": finding_id, f"{CLAIM}.token": token}
    debit = claim["debit"]
    if debit is None:
        debit = token
        if not collection.update_one(mine, {"$set": {CLAIM: {**claim, "debit": debit, "state": "debiting"}}}
                                     ).modified_count:
            raise RemediationBusy()  # taken over before this request paid anything
        try:
            CREDITS.deduct_credits_from_team(team_id, COST)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 400:  # the conditional UPDATE matched no row: not enough
                collection.update_one(mine, {"$unset": {CLAIM: ""}})
                raise InsufficientCredits() from None
            raise  # unknown whether it committed: the claim stays "debiting", so a retry never charges again
        collection.update_one(mine, {"$set": {CLAIM: {**claim, "debit": debit, "state": "charged"}}})
        log.info("ai remediation charged team=%s finding=%s debit=%s", team_id, finding_id, debit)
    else:
        log.info("ai remediation reuses the charge of a stale claim team=%s finding=%s debit=%s", team_id,
                 finding_id, debit)
    try:
        result = await run_in_threadpool(generate, finding_data, scan_type)
        if not isinstance(result, dict):
            raise TypeError("remediation generator returned no result")
    except BaseException:
        _refund_dropped(collection, finding_id, team_id, debit, "error")
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
    _refund_dropped(collection, finding_id, team_id, debit, "generation_failed", failed=result)
    return result


__all__ = ["COST", "CLAIM_TTL_S", "RemediationBusy", "InsufficientCredits", "remediate"]
