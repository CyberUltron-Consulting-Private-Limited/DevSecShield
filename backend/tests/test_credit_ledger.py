"""The credits ledger's API (backend/utilities/team/credit_ledger.py; #57 architecture review 5871780828).

* Amounts are integer milli-credits, converted at the edge: sums reconcile exactly where floats drift.
* ``record`` is insert-only with ``ON CONFLICT (movement_key) DO NOTHING``: True for a new line, False for a key seen
  before (nothing written), and it never touches the team row.
* ``move`` moves the balance and writes its line; on PostgreSQL in ONE statement (``WITH u AS (UPDATE team ...
  RETURNING) INSERT ... SELECT``). A debit the balance does not cover moves and writes nothing; a movement key used
  before undoes the whole statement, the balance change included (never a balance moved without its line).

SQLite always; the same checks on PostgreSQL with CANCEL_RACE_PG_URL (a throwaway database; CI sets it).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlalchemy import event  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import CreditLedgerEntry, Team  # noqa: E402
from backend.utilities.team import credit_ledger  # noqa: E402
from backend.utilities.team.credit_ledger import from_mc, move, record, to_mc  # noqa: E402

PG_URL = os.environ.get("CANCEL_RACE_PG_URL")


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request):
    if request.param == "postgresql":
        if not PG_URL:
            pytest.skip("CANCEL_RACE_PG_URL not set (throwaway PostgreSQL)")
        eng = create_engine(PG_URL)
    else:
        eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.drop_all(eng)  # the whole schema, in dependency order (the PostgreSQL database is shared)
    SQLModel.metadata.create_all(eng, tables=[Team.__table__, CreditLedgerEntry.__table__])
    with Session(eng) as s:
        s.add(Team(id=1, name="t", credit_balance=10.0))
        s.commit()
    yield eng
    SQLModel.metadata.drop_all(eng)
    eng.dispose()


def _line(**over):
    base = {"team_id": 1, "reason": "scan_cancel_refund", "ref_type": "scan", "ref_id": 7, "scan_id": 7,
            "detail": {"refunded": 2.0}}
    return {**base, **over}


def _state(eng):
    with Session(eng) as s:
        lines = s.exec(select(CreditLedgerEntry).order_by(CreditLedgerEntry.id)).all()
        return round(s.get(Team, 1).credit_balance, 6), [(x.movement_key, x.delta_mc, x.balance_after_mc) for x in lines]


def test_milli_credits_are_exact_at_the_edge():
    assert [to_mc(v) for v in (0.006, 6.5, 0.2, 0.0333, 1, None)] == [6, 6500, 200, 33, 1000, 0]
    assert from_mc(6) == 0.006 and from_mc(None) is None
    deltas = [0.006, 0.2, 0.03] * 10000  # chat, cent-priced charges: float credits drift, milli-credits do not
    assert sum(to_mc(d) for d in deltas) == 2_360_000
    balance = 1_000_000.0
    for d in deltas:
        balance -= d
    assert balance != 1_000_000.0 - 2360.0  # what a float ledger would have to reconcile against


def test_reasons_keys_and_amounts_are_checked_before_anything_is_written(engine):
    with Session(engine) as s:
        with pytest.raises(ValueError, match="unknown credit ledger reason"):
            record(s, **_line(reason="free_credits"), delta_mc=1, movement_key="k")
        with pytest.raises(ValueError, match="movement key"):
            record(s, **_line(), delta_mc=1, movement_key="k" * 97)
        with pytest.raises(TypeError, match="milli-credits"):
            move(s, **_line(), delta_mc=2.0, movement_key="k")
    assert _state(engine) == (10.0, [])


def test_record_is_insert_only_and_reports_whether_the_line_is_new(engine):
    with Session(engine) as s:
        assert record(s, **_line(), delta_mc=2000, movement_key="scan:7:cancel") is True
        assert record(s, **_line(), delta_mc=9999, movement_key="scan:7:cancel") is False  # nothing written
        assert record(s, **_line(ref_type="cbom_run", ref_id="run-3", scan_id=None), delta_mc=-50,
                      movement_key="cbom_run:3:settle:1") is True
        s.commit()
    assert _state(engine) == (10.0, [("scan:7:cancel", 2000, None), ("cbom_run:3:settle:1", -50, None)])


def test_move_writes_the_applied_change_and_the_balance_after_it(engine):
    with Session(engine) as s:
        assert move(s, **_line(reason="scan_reinitialize_charge"), delta_mc=-6500, movement_key="scan:7:reinit:a",
                    require_cover=True) == 3500
        assert move(s, **_line(), delta_mc=7500, movement_key="scan:7:cancel") == 11000
        s.commit()
    assert _state(engine) == (11.0, [("scan:7:reinit:a", -6500, 3500), ("scan:7:cancel", 7500, 11000)])


def test_a_debit_the_balance_does_not_cover_moves_and_writes_nothing(engine):
    with Session(engine) as s:
        assert move(s, **_line(reason="scan_reinitialize_charge"), delta_mc=-10001, movement_key="k1",
                    require_cover=True) is None
        assert move(s, **_line(reason="scan_reinitialize_charge"), delta_mc=-10000, movement_key="k2",
                    require_cover=True) == 0  # exactly the balance: covered
        s.commit()
    assert _state(engine) == (0.0, [("k2", -10000, 0)])


def test_a_movement_key_used_twice_undoes_the_whole_movement(engine):
    with Session(engine) as s:
        move(s, **_line(), delta_mc=2000, movement_key="scan:7:cancel")
        s.commit()
    with Session(engine) as s:
        with pytest.raises(IntegrityError):
            move(s, **_line(), delta_mc=2000, movement_key="scan:7:cancel")
        s.rollback()
    assert _state(engine) == (12.0, [("scan:7:cancel", 2000, 12000)])  # the balance moved once


def test_on_postgresql_a_movement_is_one_statement(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite has no data-modifying WITH: two statements in one transaction there")
    seen = []
    listener = lambda _c, _cur, statement, *_a: seen.append(statement)  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        with Session(engine) as s:
            move(s, **_line(), delta_mc=2000, movement_key="scan:7:cancel")
            s.commit()
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    writes = [q for q in seen if "creditledger" in q or "UPDATE team" in q]
    assert len(writes) == 1 and writes[0].lstrip().startswith("WITH u AS"), seen
    assert "ON CONFLICT" not in writes[0]  # see credit_ledger.py: DO NOTHING would keep the UPDATE without a line


def test_the_reasons_are_a_fixed_list():
    assert set(credit_ledger.REASONS) == {"scan_reinitialize_charge", "scan_reinitialize_refund", "scan_cancel_refund",
                                          "scan_failure_refund"}
