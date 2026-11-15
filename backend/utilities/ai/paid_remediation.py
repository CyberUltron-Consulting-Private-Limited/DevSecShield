"""AI remediation of a finding, paid before it is generated (issue #87).

Order, per finding:

1. **Claim** the finding with one conditional Mongo update (``remediation_claim``): only a finding with no completed
   remediation and no live claim can be claimed, so at most one request per finding generates at a time; the others
   get ``RemediationBusy`` (HTTP 409) and the finished remediation on their next try. A claim older than
   ``CLAIM_TTL_S`` (its worker died) may be taken over.
2. **Debit** with the atomic conditional UPDATE of ``deduct_credits_from_team`` (``credit_balance >= cost``, one
   statement): a team that cannot pay gets ``InsufficientCredits`` (HTTP 402) and nothing is generated or stored.
3. **Generate**, then **store** the completed remediation only while the claim is still ours (one conditional update
   that also drops the claim). A completed remediation in Mongo has therefore always been paid for, and the route's
   cache serves only such remediations.
4. **Refund** (``refund_credits_to_team``) when generation fails or raises, or when the result cannot be stored; a
   failed result is stored (for the panel's message) without a charge, and the next attempt is a normal one.

The credit movements are the same atomic helpers ``/start`` uses; a ledger line per movement comes with the credits
ledger (#52 / PR #57), which is not on dev yet. The claim lives next to ``remediation`` (``remediation_claim``), never in
it, so finding lists and the panel never see it.
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


class RemediationBusy(Exception):
    """Another request is generating this finding's remediation right now."""


class InsufficientCredits(Exception):
    """The team's balance does not cover the remediation; nothing was generated or stored."""


def _completed(doc: dict | None) -> dict | None:
    remediation = (doc or {}).get("remediation")
    return remediation if isinstance(remediation, dict) and remediation.get("status") == "completed" else None


def _claim(collection: Any, finding_id: Any, scan_id: int, token: str) -> bool:
    now = time.time()
    result = collection.update_one(
        {"_id": finding_id, "scan_id": scan_id, "remediation.status": {"$ne": "completed"},
         "$or": [{CLAIM: {"$exists": False}}, {f"{CLAIM}.at": {"$lt": now - CLAIM_TTL_S}}]},
        {"$set": {CLAIM: {"token": token, "at": now}}})
    return result.modified_count == 1


def _refund(team_id: int, finding_id: Any, why: str) -> None:
    CREDITS.refund_credits_to_team(team_id, COST)
    log.info("ai remediation refunded team=%s finding=%s reason=%s", team_id, finding_id, why)


async def remediate(collection: Any, *, finding_id: Any, scan_id: int, team_id: int, finding_data: dict,
                    scan_type: str, generate: Callable[[dict, str], dict]) -> dict:
    """The finding's remediation: the stored one when it is complete, else a newly paid-for one (module docstring).
    Raises RemediationBusy, InsufficientCredits, or the HTTPException of a credit helper."""
    token = uuid.uuid4().hex
    if not _claim(collection, finding_id, scan_id, token):
        stored = _completed(collection.find_one({"_id": finding_id}))
        if stored is not None:
            return stored  # finished (and charged) by the request that held the claim
        raise RemediationBusy()
    mine = {"_id": finding_id, f"{CLAIM}.token": token}
    charged = False
    try:
        try:
            CREDITS.deduct_credits_from_team(team_id, COST)
        except Exception as exc:
            if getattr(exc, "status_code", None) == 400:  # the conditional UPDATE matched no row: not enough
                raise InsufficientCredits() from None
            raise
        charged = True
        result = await run_in_threadpool(generate, finding_data, scan_type)
        if not isinstance(result, dict):
            raise TypeError("remediation generator returned no result")
        if result.get("status") == "completed":
            if collection.update_one(mine, {"$set": {"remediation": result}, "$unset": {CLAIM: ""}}).modified_count:
                charged = False  # stored: the charge stands
                return result
            # our claim expired and another request took the finding over: store ours only if it has none
            if collection.update_one({"_id": finding_id, "remediation.status": {"$ne": "completed"}},
                                     {"$set": {"remediation": result}}).modified_count:
                charged = False
                return result
            _refund(team_id, finding_id, "superseded")
            charged = False
            return _completed(collection.find_one({"_id": finding_id})) or result
        # not completed: shown to the customer (its error), never charged, retried as a new attempt next time
        _refund(team_id, finding_id, "generation_failed")
        charged = False
        collection.update_one(mine, {"$set": {"remediation": result}, "$unset": {CLAIM: ""}})
        return result
    finally:
        if charged:
            # generation raised (or the store did): give the credits back before the error reaches the customer
            try:
                _refund(team_id, finding_id, "error")
            except Exception as exc:  # the balance is left debited: say so, with ids only
                log.error("ai remediation refund FAILED team=%s finding=%s error=%s", team_id, finding_id,
                          type(exc).__name__)
        collection.update_one(mine, {"$unset": {CLAIM: ""}})


__all__ = ["COST", "CLAIM_TTL_S", "RemediationBusy", "InsufficientCredits", "remediate"]
