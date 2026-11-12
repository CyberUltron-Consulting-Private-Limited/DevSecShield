"""The credits ledger (#33, #52): one line per movement of a team's credits, with its reason and a unique key.

Amounts are integer milli-credits (``delta_mc``, ``balance_after_mc``): ``sum(delta_mc)`` reconciles exactly, where
float credits drift. Callers speak credits; ``to_mc`` / ``from_mc`` convert at the edge (0.006 credits = 6 mc).

Every line carries a ``movement_key`` (unique, at most 96 characters) naming the movement, e.g.
``scan:{id}:reinit:{task}``: a movement written twice is refused by the database, not by the caller's care. And a
generic reference ``ref_type`` + ``ref_id`` (a scan, a CBOM run, a CI/CD run...), so lines that belong to no scan can be
found and settled per run.

Two ways to write a line:

* ``move`` -- the balance moves and its line is written by ONE statement on PostgreSQL::

      WITH u AS (UPDATE team SET credit_balance = credit_balance + :d WHERE id = :team [AND credit_balance >= :need]
                 RETURNING credit_balance)
      INSERT INTO creditledger (...) SELECT ..., round(u.credit_balance * 1000) FROM u RETURNING balance_after_mc

  so the line holds the change actually applied and the balance after it, with no second round trip under the
  team-row lock. A debit the balance does not cover moves nothing and writes nothing (``None``). A movement key used
  before is a unique violation that undoes the WHOLE statement, the balance change included (``IntegrityError``):
  ``ON CONFLICT DO NOTHING`` is deliberately not used here, because a data-modifying WITH always runs to completion,
  so the balance would move without its line (proof: round6/t2/r7/scratch/cte_probe.out). Call it inside the
  transaction that makes the money move legitimate (the scan's compare-and-set), and commit them together.
  SQLite (tests) has no data-modifying WITH: ``UPDATE ... RETURNING`` then the INSERT, in the same transaction.

* ``record`` -- insert-only, ``INSERT ... ON CONFLICT (movement_key) DO NOTHING``; True when the line is new. It never
  touches the team row, so it can be written outside any team lock.

Per-job movements (a CBOM Sources job ending, thousands per run) never write a line inside the job-end transaction:
that would put every job end on the team-row lock (architecture review 5871780828 measured 29-35 job ends/s against
524/s without it). They are settled per run: the settlement that moves the money writes one ``move`` line per run per
pass (``ref_type="cbom_run"``), or jobs write insert-only ``record`` lines with ``balance_after_mc`` NULL that a
settlement moves later. #52 routes every other movement through this module.

Append-only: the database refuses UPDATE, DELETE and TRUNCATE of the table by a trigger (``zs_append_only()``,
migration r6t2ledger001). That is not a control against the database role itself: a role that owns the table (or a
superuser) can disable or drop the trigger. A least-privilege role (a NOLOGIN owner, the application granted INSERT and
SELECT only) is a follow-up. Corrections are compensating lines.
"""
from __future__ import annotations

import datetime
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

from sqlalchemy import BigInteger, Numeric, cast, func, literal, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlmodel import Session

from backend.new_models import CreditLedgerEntry, Team

MC_PER_CREDIT = 1000
MOVEMENT_KEY_MAX = 96

REASONS: dict[str, str] = {
    "scan_reinitialize_charge": "Reinitialized with a costlier input: the difference against what the scan had paid",
    "scan_reinitialize_refund": "The reinitialized run was never recorded (it could not be sent, or the request died): "
                                "the difference was given back",
    "scan_cancel_refund": "The scan was cancelled: everything it had paid was given back",
    "scan_failure_refund": "The scan failed: everything it had paid was given back",
}

_TEAM = Team.__table__
_LEDGER = CreditLedgerEntry.__table__


def to_mc(credits: float | int | Decimal | None) -> int:
    """Credits to milli-credits, rounded half-even on the decimal value (0.006 -> 6, 6.5 -> 6500)."""
    if credits is None:
        return 0
    value = Decimal(str(credits)) * MC_PER_CREDIT
    return int(value.quantize(Decimal(1), rounding=ROUND_HALF_EVEN))


def from_mc(mc: int | None) -> float | None:
    return None if mc is None else mc / MC_PER_CREDIT


def _line_values(*, team_id: int, delta_mc: int, reason: str, movement_key: str, ref_type: str, ref_id: Any,
                 scan_id: int | None, user_id: int | None, detail: dict[str, Any] | None) -> dict[str, Any]:
    if reason not in REASONS:
        raise ValueError(f"unknown credit ledger reason: {reason}")
    if not movement_key or len(movement_key) > MOVEMENT_KEY_MAX:
        raise ValueError(f"a movement key is 1-{MOVEMENT_KEY_MAX} characters: {movement_key!r}")
    if not isinstance(delta_mc, int) or isinstance(delta_mc, bool):
        raise TypeError("delta_mc is an int (milli-credits): convert with to_mc")
    return {"movement_key": movement_key, "team_id": team_id, "ref_type": str(ref_type), "ref_id": str(ref_id),
            "scan_id": scan_id, "user_id": user_id, "delta_mc": delta_mc, "reason": reason, "detail": detail or {},
            "created_at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)}


def _dialect(session: Session) -> str:
    return session.get_bind().dialect.name


def record(session: Session, *, team_id: int, delta_mc: int, reason: str, movement_key: str, ref_type: str,
           ref_id: Any, scan_id: int | None = None, user_id: int | None = None, detail: dict[str, Any] | None = None,
           balance_after_mc: int | None = None) -> bool:
    """Insert-only line (the caller moves no balance here, or settles it later). True when the line is new, False when
    a line with this movement key already exists (nothing written)."""
    values = _line_values(team_id=team_id, delta_mc=delta_mc, reason=reason, movement_key=movement_key,
                          ref_type=ref_type, ref_id=ref_id, scan_id=scan_id, user_id=user_id, detail=detail)
    values["balance_after_mc"] = balance_after_mc
    insert = postgresql.insert if _dialect(session) == "postgresql" else sqlite.insert
    stmt = (insert(_LEDGER).values(**values).on_conflict_do_nothing(index_elements=["movement_key"])
            .returning(_LEDGER.c.id))
    return session.execute(stmt).first() is not None


def move(session: Session, *, team_id: int, delta_mc: int, reason: str, movement_key: str, ref_type: str, ref_id: Any,
         scan_id: int | None = None, user_id: int | None = None, detail: dict[str, Any] | None = None,
         require_cover: bool = False) -> int | None:
    """Move the team's balance by ``delta_mc`` and write its line (module doc). ``require_cover``: a debit only while
    the balance covers it. Returns the balance after the movement in milli-credits, or None when nothing moved (no such
    team, or a debit not covered). Raises IntegrityError (everything undone) for a movement key used before."""
    values = _line_values(team_id=team_id, delta_mc=delta_mc, reason=reason, movement_key=movement_key,
                          ref_type=ref_type, ref_id=ref_id, scan_id=scan_id, user_id=user_id, detail=detail)
    delta = delta_mc / MC_PER_CREDIT
    conditions = [_TEAM.c.id == team_id]
    if require_cover and delta_mc < 0:
        conditions.append(_TEAM.c.credit_balance >= -delta)
    moved = (update(_TEAM).where(*conditions).values(credit_balance=_TEAM.c.credit_balance + delta)
             .returning(_TEAM.c.credit_balance))

    if _dialect(session) == "postgresql":
        u = moved.cte("u")
        columns = list(values)
        after = cast(func.round(cast(u.c.credit_balance, Numeric) * MC_PER_CREDIT), BigInteger)
        rows = select(*(literal(values[c], type_=_LEDGER.c[c].type) for c in columns), after).select_from(u)
        stmt = (postgresql.insert(_LEDGER).from_select([*columns, "balance_after_mc"], rows)
                .returning(_LEDGER.c.balance_after_mc).add_cte(u))
        row = session.execute(stmt).first()
        return None if row is None else int(row[0])

    balance = session.execute(moved).scalar()  # SQLite: two statements, one transaction (one writer at a time)
    if balance is None:
        return None
    after_mc = to_mc(balance)
    session.execute(sqlite.insert(_LEDGER).values(**values, balance_after_mc=after_mc))
    return after_mc


__all__ = ["MC_PER_CREDIT", "MOVEMENT_KEY_MAX", "REASONS", "from_mc", "move", "record", "to_mc"]
