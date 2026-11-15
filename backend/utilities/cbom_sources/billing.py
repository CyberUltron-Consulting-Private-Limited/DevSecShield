"""CBOM Sources credits (CB-14): the ledger of every charge and refund, and the runtime-skip refund rule.

* **Ledger.**  Each credit movement is one ``cbomcreditentry`` row with a unique ``idem_key``: ``run:<id>:charge`` for a
  run's charge at Start, ``job:<id>:refund`` for a job's one refund.  The row is inserted ``ON CONFLICT DO NOTHING``
  *before* any balance moves, in the same transaction: a retried result, a cancel racing the node's result, or the
  reaper racing a cancel can each try, but only the transaction whose row went in moves credits (on PostgreSQL the
  second insert waits for the first to commit, then does nothing).  Every run reconciles: its charge rows sum to
  ``credits_charged_c`` and its refund rows to ``credits_refunded_c`` (``tests/test_cbom_cb14_billing.py``).
* **Runtime skips (OA-10b default: "charge for what was contacted").**  A collection that ends ``success`` but did
  not read some of its targets because of the run itself (the scan window closed, Stop all, the deadline, a run cap,
  a cancel) or because the target refused the credential is refunded that share of its weight, pro rata over the
  targets in scope (a network range reports one target per address, so it is pro rata by addresses), rounded down.
  Targets that were contacted (unreachable, timed out, refused the port, errors) are charged.  Never-scan targets
  are CB-11's (``jobs.refund_policy_excluded`` adds their per-unit refund to the same ledger row).

Alembic sees ``cbomcreditentry`` because ``prod_database_migrations/migrations/env.py`` imports this module
(migration ``cb14credit001``).
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from sqlalchemy import Index
from sqlmodel import DateTime, Field, Session, SQLModel

from backend.new_models import _cbom_utcnow

# a target that was never read because the run said so, or whose credential was refused: not charged
CREDENTIAL_REFUSED = frozenset({"auth_failed", "mfa_required"})
REASONS = ("start", "runtime_skips", "never_scan", "nothing_read", "failed", "cancelled", "expired", "refund", "backfill",
           "migration_duplicate")


class CbomCreditEntry(SQLModel, table=True):
    """One credit movement of a team's CBOM Sources runs (centi-credits, always positive; ``kind`` says which way)."""
    __tablename__ = "cbomcreditentry"
    __table_args__ = (Index("ix_cbomcreditentry_team_created", "team_id", "created_at"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    run_id: int | None = Field(default=None, foreign_key="cbomcollectionrun.id", index=True)
    job_id: int | None = Field(default=None)  # a plain int: the ledger outlives nothing, but never blocks a delete
    kind: str = Field(max_length=8)  # charge | refund
    reason: str = Field(max_length=32)
    amount_c: int = Field(default=0)
    idem_key: str = Field(max_length=64, unique=True)
    created_at: _dt.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


def record(session: Session, *, team_id: int, run_id: int | None, job_id: int | None, kind: str, reason: str,
           amount_c: int, idem_key: str) -> bool:
    """Insert one ledger row unless its key exists.  True when this call inserted it (and so may move credits)."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    stmt = dialect_insert(CbomCreditEntry.__table__).values(
        team_id=team_id, run_id=run_id, job_id=job_id, kind=kind, reason=reason[:32], amount_c=int(amount_c),
        idem_key=idem_key[:64], created_at=_cbom_utcnow(),
    ).on_conflict_do_nothing(index_elements=["idem_key"])
    return int(session.exec(stmt).rowcount or 0) == 1  # type: ignore[call-overload]


def charge_key(run_id: int) -> str:
    return f"run:{run_id}:charge"


def refund_key(job_id: int) -> str:
    return f"job:{job_id}:refund"


def _tally(result: dict[str, Any]) -> dict[str, int]:
    """Targets by status: the node's rows, plus the statuses it folded into its summary row past its row cap."""
    out: dict[str, int] = {}
    for row in result.get("targets") or []:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        if status == "summary":
            try:
                folded = json.loads(str(row.get("error") or "{}"))
            except ValueError:
                folded = {}
            for name, n in (folded.items() if isinstance(folded, dict) else ()):
                if isinstance(n, int) and not isinstance(n, bool) and n > 0:
                    out[str(name)] = out.get(str(name), 0) + n
            continue
        if status:
            out[status] = out.get(status, 0) + 1
    return out


NEVER_SCAN = "skipped_never_scan"


def refundable(status: str) -> bool:
    """Not read at runtime, so not charged.  Never-scan targets are left to CB-11 (``jobs.policy_refund_units``): most
    were never charged (the estimate subtracts them), and the few it could not subtract are refunded per unit."""
    return (status.startswith("skipped_") and status != NEVER_SCAN) or status in CREDENTIAL_REFUSED


def runtime_refund_c(weight_c: int, result: dict[str, Any] | None) -> int:
    """The share of ``weight_c`` a ``success`` collection gives back for the targets it did not read at runtime
    (module docstring), rounded down; 0 when the result names no targets."""
    if weight_c <= 0 or not isinstance(result, dict):
        return 0
    tally = _tally(result)
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    total = counts.get("total")
    listed = sum(tally.values())
    if not isinstance(total, int) or isinstance(total, bool) or total < listed:
        total = listed
    total -= tally.get(NEVER_SCAN, 0)  # the targets in scope: never-scan ones are excluded by policy (CB-11)
    if total <= 0:
        return 0
    skipped = min(sum(n for status, n in tally.items() if refundable(status)), total)
    return weight_c * skipped // total


__all__ = ["CbomCreditEntry", "record", "runtime_refund_c", "charge_key", "refund_key", "CREDENTIAL_REFUSED"]
