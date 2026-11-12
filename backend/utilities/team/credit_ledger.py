"""The credits ledger (#33): one append-only line per movement of a team's credits, with its reason.

``record`` is called inside the transaction that moves ``team.credit_balance``, after the UPDATE, and commits with it:
the balance never moves without its line and a line never exists for a movement that was rolled back. Nothing here
updates or deletes a line.

Reasons (a fixed list, so reports can group by them):

* ``scan_reinitialize_charge``: a reinitialize with a costlier input took the difference against what the scan had
  already paid (utilities/scan/reinitialize.py);
* ``scan_reinitialize_refund``: that difference given back because the new run could not be sent.

The other movements (/start, refunds on failure and cancel, automatic DAST, CI/CD, CBOM Sources runs, scan chat,
the admin's balance edit) do not write lines yet; that is a follow-up.
"""
from __future__ import annotations

from typing import Any

from sqlmodel import Session, select

from backend.new_models import CreditLedgerEntry, Team

REASONS: dict[str, str] = {
    "scan_reinitialize_charge": "Reinitialized with a costlier input: the difference against what the scan had paid",
    "scan_reinitialize_refund": "The reinitialized run could not be sent: the difference was given back",
}


def record(session: Session, *, team_id: int, delta: float, reason: str, scan_id: int | None = None,
           user_id: int | None = None, detail: dict[str, Any] | None = None) -> CreditLedgerEntry:
    """Add the line for a movement the caller has just made in ``session`` (the caller commits both together)."""
    if reason not in REASONS:
        raise ValueError(f"unknown credit ledger reason: {reason}")
    balance = session.exec(select(Team.credit_balance).where(Team.id == team_id)).first()
    entry = CreditLedgerEntry(team_id=team_id, scan_id=scan_id, user_id=user_id, delta=round(float(delta), 4),
                              balance_after=None if balance is None else round(float(balance), 4), reason=reason,
                              detail=detail or {})
    session.add(entry)
    return entry


__all__ = ["REASONS", "record"]
