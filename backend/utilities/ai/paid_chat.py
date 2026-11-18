"""Scan chat messages, paid for before the model is called (issue #86).

``POST /{team_id}/{type}/scan/{scan_id}/message`` used to check the balance, store the message, call the model and only
then debit. Concurrent messages from a team whose balance covered one all passed the check and all got an answer; the
debits that no longer fit were refused after the answers had been stored. Now each message is:

1. **Charged** before anything is stored or the model is called. The message's credit ledger row
   (``chat:<message id>:charge``) is inserted ``ON CONFLICT DO NOTHING`` and, only if this call inserted it, the
   conditional ``UPDATE team SET credit_balance = credit_balance - COST WHERE credit_balance >= COST`` runs, in one
   transaction. A balance that does not cover the message refuses it (``InsufficientCredits``) and nothing is written,
   so however many messages arrive at once, the model answers only as many as the balance pays for.
2. **Refunded** when no answer comes back (the message could not be stored, the model failed or raised, the request was
   cancelled). The refund row (``chat:<message id>:refund``) is inserted ``ON CONFLICT DO NOTHING`` together with the
   balance change, and only when the message's charge row exists. So a message is refunded at most once, and only for a
   charge that committed.

The ledger is ``cbomcreditentry`` (``backend/utilities/cbom_sources/billing.py``), the one ledger table on dev until the
milli-credit ledger of #52 / PR #57 lands, used as AI remediation uses it (#87, ``paid_remediation.py``): run and job
empty, one fixed reason (``chat_message``). That table counts whole centi-credits, and a message costs 0.6 of one, so
its rows carry 1 (the nearest whole unit) and the reason names the exact price, ``COST``.

``create_response`` stores the answer as its last step, in ``message_log`` and then in ``active_context``. If the second
write fails, the request fails and is refunded, although the first write already stored the answer: a request that
failed is never charged.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import update as sa_update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.new_models import Team
from backend.utilities.cbom_sources import billing as LEDGER

log = logging.getLogger("backend.ai.chat")

COST = 0.006  # credits per message (backend/Notes.md)
COST_C = 1  # in the ledger's whole centi-credits (module docstring)
REASON = "chat_message"


class InsufficientCredits(Exception):
    """The team's balance does not cover the message: nothing was charged, stored or sent to the model."""


def ledger_key(message_id: str, kind: str) -> str:
    return f"chat:{message_id}:{kind}"


def _row(session: Session, key: str) -> Any:
    return session.exec(select(LEDGER.CbomCreditEntry).where(LEDGER.CbomCreditEntry.idem_key == key)).first()


def charge(engine: Engine, team_id: int, message_id: str) -> bool:
    """Charge the message once. True when this call charged it, False when it was charged before. Raises
    InsufficientCredits (nothing written) when the balance does not cover it."""
    with Session(engine) as session:
        if not LEDGER.record(session, team_id=team_id, run_id=None, job_id=None, kind="charge", reason=REASON,
                             amount_c=COST_C, idem_key=ledger_key(message_id, "charge")):
            session.rollback()
            return False  # this message was charged before
        moved = session.exec(sa_update(Team).where(Team.id == team_id, Team.credit_balance >= COST)  # type: ignore[call-overload]
                             .values(credit_balance=Team.credit_balance - COST))
        if not moved.rowcount:
            session.rollback()
            raise InsufficientCredits()
        session.commit()
    log.info("chat message charged team=%s message=%s", team_id, message_id)
    return True


def refund(engine: Engine, team_id: int, message_id: str) -> bool:
    """Give the message's charge back once, and only if it committed. True when this call refunded it."""
    with Session(engine) as session:
        if _row(session, ledger_key(message_id, "charge")) is None:
            return False  # never charged: nothing to give back
        if not LEDGER.record(session, team_id=team_id, run_id=None, job_id=None, kind="refund", reason=REASON,
                             amount_c=COST_C, idem_key=ledger_key(message_id, "refund")):
            session.rollback()
            return False  # refunded before
        session.exec(sa_update(Team).where(Team.id == team_id)  # type: ignore[call-overload]
                     .values(credit_balance=Team.credit_balance + COST))
        session.commit()
    log.info("chat message refunded team=%s message=%s", team_id, message_id)
    return True


def refund_unanswered(engine: Engine, team_id: int, message_id: str, failure: BaseException) -> None:
    """Refund a message that got no answer; the caller then re-raises ``failure``. Never raises: a refund that fails is
    logged with the message id (its charge row stays, so it can be given back by hand) and the customer still gets the
    error of the failure."""
    try:
        refund(engine, team_id, message_id)
    except Exception as exc:
        log.error("chat message refund FAILED team=%s message=%s reason=%s error=%s", team_id, message_id,
                  type(failure).__name__, type(exc).__name__)


__all__ = ["COST", "InsufficientCredits", "charge", "ledger_key", "refund", "refund_unanswered"]
