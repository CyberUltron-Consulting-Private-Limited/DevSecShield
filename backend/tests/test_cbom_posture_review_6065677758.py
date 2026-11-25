"""Review 6065677758 of PR #499 (round 6): the reviewer's P10, P10b and R4 as tests.

M1  A blank leftover record (status "open", no wave, owner, due date or note) counted as a plan: being newest, it hid
    an older real plan on every surface (P10), and q111 wrote it to the group key (R4).  A blank record is not a plan
    (``remediation_group.has_plan``), in ``resolve`` and in the backfill; a released ticket claim deletes the record it
    inserted (P10b) instead of leaving it behind; a user's reset to blank applies to the whole resource, so an older
    plan on another key never comes back.
m1  q110's last cleanup drop of an INVALID index is ``DROP INDEX CONCURRENTLY`` under a short ``lock_timeout``: it never
    queues an ACCESS EXCLUSIVE lock in front of the table's readers (PostgreSQL only, scaled timeouts).
n1  Every test that drops tables in ``CBOM_TEST_PG_URL``'s database reads the URL through the shared guard
    (``support.pg_test_db``).
n3  The Jira label's salt and its fallback to the labels of older issues are documented next to ``resource_label``.

SQLite always; PostgreSQL too with ``CBOM_TEST_PG_URL`` set (as in CI).
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import threading
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionRun,
    CbomCollectionSettings,
)
from backend.new_models import CbomRemediationAssignment as A  # noqa: E402
from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402
from backend.tests.test_cbom_posture_review_6058574998 import _two_runs  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

PG = cbom_test_pg_url()
NOW = dt.datetime(2026, 11, 24, 6, 0, tzinfo=dt.timezone.utc)
OLDER, NEWER = dt.datetime(2026, 11, 1), dt.datetime(2026, 11, 20)


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=pytest.mark.skipif(
    not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL"))])
def engine(request, tmp_path):
    RI.clear_cache()
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path / 'r6065677758.db'}", connect_args={"check_same_thread": False})
    else:
        engine = create_engine(PG)
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    RI.clear_cache()
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


def _own(row, ref: str) -> str:
    return ID.stable_key("node", ref, ID.node_identity(row))


def _row(s, run_id, source_id, kind="kms_key"):
    return s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id,
                                                   CbomCollectedAsset.source_id == source_id,
                                                   CbomCollectedAsset.asset_type == kind)
                  .order_by(CbomCollectedAsset.id)).first()


def _item(s, run_id, label, kind="kms_key"):
    from backend.utilities.cbom_sources import waves as WAVES

    return next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
                if i["type"] == kind and i["label"] == label)


def _surfaces(engine, run_id: int, label: str, kind: str = "kms_key") -> dict:
    """The resource's status on every surface: waves, the run list's status filter, the team view and /results."""
    from backend.utilities.cbom_sources import collections_view as CV
    from backend.utilities.cbom_sources import run_assets as RA
    from backend.utilities.cbom_sources import run_results as RR

    RR._STATUS_CACHE.clear()
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        item = _item(s, run_id, label, kind)
        row = s.get(CbomCollectedAsset, item["asset_id"])
        bucket = next(b for b in RA.FINDING_STATUSES
                      if row.id in {i["id"] for i in RA.list_run_assets(
                          s, team_id=1, run=run, params={"page_size": 1000}, status=b)["items"]})
        kept = CV.resolve([], CV.load_sources_result(s, 1, now=NOW).rows).sources_rows
        team = next(r for r in kept if r.node_type == kind and r.row.get("location") == row.location)
        actions, _m = RR._remediation(s, 1, {bytes.fromhex(item["own_key"]): (1 << 2) | 1}, run)
        results = next(k for k in ("total_fixed", "total_in_progress", "total_not_started", "total_ignored")
                       if actions[k])
    a = item["assignment"] or {}
    return {"waves": (a.get("status"), a.get("owner"), a.get("wave")), "list": bucket,
            "team": team.row["remediation_status"], "results": results}


DAVE_DONE = {"waves": ("done", "dave", 1), "list": "fixed", "team": "done", "results": "total_fixed"}


def _p10(engine, *, blank_ticket: str | None = None):
    """A holds dave's older ``done`` plan (wave 1); B holds the newer blank record a released ticket claim left."""
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id), _row(s, first, b_id)
        s.add(A(team_id=1, asset_key=_own(a_row, "srcA"), source_ref="srcA", status="done", wave=1, owner="dave",
                done_at=OLDER, last_updated=OLDER))
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="open", ticket_key=blank_ticket,
                last_updated=NEWER, row_version=3))
        s.commit()
        return first, ID.node_label(a_row), _own(a_row, "srcA"), _own(b_row, "srcB")


# ------------------------------------------------------------------------------------------------ M1 P10
def test_p10_a_blank_newer_record_never_hides_an_older_plan(engine):
    first, label, a_key, _b_key = _p10(engine)
    assert _surfaces(engine, first, label) == DAVE_DONE  # 348d032f: open / None / not_started everywhere
    with Session(engine) as s:
        assert _item(s, first, label)["asset_key"] == a_key  # a change edits dave's plan


def test_has_plan_rule():
    from types import SimpleNamespace as N

    from backend.utilities.cbom_sources import remediation_group as RG

    blank = dict(status="open", wave=None, owner=None, target_date=None, note=None, ticket_key=None)
    assert not RG.has_plan(N(**blank))
    assert not RG.has_plan(N(**{**blank, "ticket_key": "SEC-1"}))  # ticket-only
    assert not RG.has_plan(N(**{**blank, "owner": ""}))
    for field, value in (("status", "done"), ("status", "in_progress"), ("wave", 2), ("owner", "dave"),
                         ("target_date", "2026-12-01"), ("note", "x")):
        assert RG.has_plan(N(**{**blank, field: value})), field


# ------------------------------------------------------------------------------------------------ M1 P10b
def _jira_fails(monkeypatch, kind: str = "http_4xx"):
    from backend.utilities.cbom_sources import run_tickets as RT

    def create(**_kw):
        raise RT.JIRA.JiraError(kind, "Jira refused the request")

    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", create)
    monkeypatch.setattr(RT.JIRA, "find_issue_by_label", lambda *a, **k: None)
    monkeypatch.setattr(RT, "_jira_creds", lambda team: ("qa@example.com", "token", "https://jira.example"))


def _settings(engine):
    with Session(engine) as s:
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="ext-1-" + "x" * 28, jira_project_key="SEC"))
        s.commit()


def test_p10b_a_failed_jira_call_leaves_no_record_behind(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT

    first, _second, _a, _b = _two_runs(engine)
    _settings(engine)
    _jira_fails(monkeypatch)
    with Session(engine) as s:
        from backend.utilities.cbom_sources import waves as WAVES

        item = next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, first)) if RT.is_ticketable(i))
    out = RT.create_tickets(engine, 1, 1, first, RT.TicketBody(asset_ids=[item["asset_id"]]))
    assert len(out["failed"]) == 1
    with Session(engine) as s:
        assert s.exec(select(A)).all() == []  # 348d032f: ('<group key>', 'open', None, None, None, None)


def test_p10b_dave_s_plan_still_shows_after_a_failed_jira_call(engine, monkeypatch):
    """A failed call on the resource keeps dave's record as it was (no newer blank record, no time bump), and the
    blank record an older release left stays out of the way."""
    from backend.utilities.cbom_sources import run_tickets as RT

    first, label, a_key, b_key = _p10(engine)
    _settings(engine)
    _jira_fails(monkeypatch)
    with Session(engine) as s:
        item = _item(s, first, label)
    out = RT.create_tickets(engine, 1, 1, first, RT.TicketBody(asset_ids=[item["asset_id"]]))
    assert len(out["failed"]) == 1
    with Session(engine) as s:
        rows = {r.asset_key: r for r in s.exec(select(A)).all()}
    assert set(rows) == {a_key, b_key}
    assert (rows[a_key].status, rows[a_key].owner, rows[a_key].last_updated, rows[a_key].ticket_state) == (
        "done", "dave", OLDER, None)
    assert _surfaces(engine, first, label) == DAVE_DONE


def test_a_released_claim_keeps_a_plan_written_while_jira_was_called(engine, monkeypatch):
    """The claim inserted the record, but a user planned the resource while Jira answered: the plan stays."""
    from backend.utilities.cbom_sources import run_tickets as RT

    first, _second, _a, _b = _two_runs(engine)
    _settings(engine)
    with Session(engine) as s:
        from backend.utilities.cbom_sources import waves as WAVES

        item = next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, first)) if RT.is_ticketable(i))

    def create(**_kw):
        with Session(engine) as s:
            row = s.exec(select(A)).one()
            row.owner, row.status = "erin", "in_progress"
            s.add(row)
            s.commit()
        raise RT.JIRA.JiraError("http_4xx", "Jira refused the request")

    _jira_fails(monkeypatch)
    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", create)
    RT.create_tickets(engine, 1, 1, first, RT.TicketBody(asset_ids=[item["asset_id"]]))
    with Session(engine) as s:
        row = s.exec(select(A)).one()
    assert (row.owner, row.status, row.ticket_state, row.ticket_claim) == ("erin", "in_progress", None, None)


# ------------------------------------------------------------------------------------------------ M1 R4 (q111)
def _backfill(engine, reverse: bool = False) -> dict:
    from backend.utilities.cbom_sources import remediation_backfill as RB

    with engine.begin() as conn:
        return RB.backfill_all(conn, reverse=reverse)


def test_r4_the_backfill_writes_dave_s_plan_not_the_blank_record(engine):
    first, label, a_key, b_key = _p10(engine)
    totals = _backfill(engine)
    with Session(engine) as s:
        group_key = _item(s, first, label)["group_key"]
        group = s.exec(select(A).where(A.asset_key == group_key)).one()
    # 348d032f: group-backfill | open | - | - | -
    assert (group.status, group.wave, group.owner, group.source_ref) == ("done", 1, "dave", f"group-backfill:{a_key}")
    assert totals["inserted"] == 1
    assert _surfaces(engine, first, label) == DAVE_DONE
    _backfill(engine, reverse=True)
    with Session(engine) as s:
        rows = {r.asset_key: r for r in s.exec(select(A)).all()}
    assert set(rows) == {a_key, b_key} and (rows[a_key].status, rows[a_key].owner) == ("done", "dave")


def test_r4_blank_records_are_never_written_to_a_group_key(engine):
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id), _row(s, first, b_id)
        for row, ref in ((a_row, "srcA"), (b_row, "srcB")):
            s.add(A(team_id=1, asset_key=_own(row, ref), source_ref=ref, status="open", last_updated=NEWER))
        s.commit()
        label = ID.node_label(a_row)
    totals = _backfill(engine)
    with Session(engine) as s:
        assert not [r for r in s.exec(select(A)).all() if r.source_ref.startswith("group-backfill:")]
        assert _item(s, first, label)["assignment"]["status"] == "open"
    assert totals["inserted"] == 0 and totals["blank"] == 1


def test_r4_a_ticket_only_copy_still_moves_its_ticket(engine):
    """A blank plan is skipped, a ticket is not: the group record carries the ticket (and no plan)."""
    first, label, _a_key, b_key = _p10(engine, blank_ticket="SEC-9")
    with Session(engine) as s:  # dave's plan goes: only the ticket-only copy and nothing else
        s.delete(s.exec(select(A).where(A.owner == "dave")).one())
        s.commit()
    _backfill(engine)
    with Session(engine) as s:
        group = s.exec(select(A).where(A.source_ref.startswith("group-backfill:"))).one()
    assert (group.status, group.owner, group.ticket_key, group.source_ref) == ("open", None, "SEC-9",
                                                                              f"group-backfill:{b_key}")


def test_r4_a_blank_group_record_takes_the_copy_s_plan(engine):
    """A blank record already on the group key (a claim this branch's earlier code left) gets the copy's plan."""
    first, label, a_key, _b_key = _p10(engine)
    with Session(engine) as s:
        group_key = _item(s, first, label)["group_key"]
        s.add(A(team_id=1, asset_key=group_key, source_ref="srcB", status="open", last_updated=NEWER))
        s.commit()
    totals = _backfill(engine)
    with Session(engine) as s:
        group = s.exec(select(A).where(A.asset_key == group_key)).one()
    assert (group.status, group.wave, group.owner) == ("done", 1, "dave") and totals["plans_filled"] == 1
    assert _surfaces(engine, first, label) == DAVE_DONE


# ------------------------------------------------------------------------------------------------ M1 a reset
def test_a_user_reset_to_blank_applies_to_the_resource(engine):
    """After q111 the group record holds a copy of dave's plan and the original stays: clearing the plan (the UI's
    reset: status open, no wave or owner) must not bring the original back."""
    from backend.utilities.cbom_sources import waves as WAVES

    first, label, a_key, _b_key = _p10(engine)
    _backfill(engine)
    with Session(engine) as s:
        item = _item(s, first, label)
        assert item["asset_key"] == item["group_key"]
        body = WAVES.AssignmentBulk(run_id=first, items=[WAVES.AssignmentItem(
            asset_key=item["asset_key"], status="open", wave=None, owner=None)])
        WAVES.upsert(s, 1, 7, body, dt.datetime(2026, 11, 25))
        s.commit()
    shown = _surfaces(engine, first, label)
    assert shown == {"waves": ("open", None, None), "list": "not_started", "team": "open",
                     "results": "total_not_started"}
    with Session(engine) as s:
        original = s.exec(select(A).where(A.asset_key == a_key)).one()
    assert (original.status, original.owner, original.wave) == ("open", None, None)


def test_an_explicit_reopen_keeps_the_plan_fields_and_wins(engine):
    from backend.utilities.cbom_sources import waves as WAVES

    first, label, a_key, _b_key = _p10(engine)
    with Session(engine) as s:
        body = WAVES.AssignmentBulk(run_id=first, items=[WAVES.AssignmentItem(asset_key=a_key, status="open")])
        WAVES.upsert(s, 1, 7, body, dt.datetime(2026, 11, 25))
        s.commit()
    shown = _surfaces(engine, first, label)
    assert shown["waves"] == ("open", "dave", 1) and shown["team"] == "open"


# ------------------------------------------------------------------------------------------------ m1 q110 cleanup
@pytest.fixture()
def pg():
    if not PG:
        pytest.skip("set CBOM_TEST_PG_URL to run against PostgreSQL")
    engine = create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def test_q110_cleanup_drop_never_stalls_the_table_s_readers(pg, caplog):
    """A transaction holds the table for the whole migration: every build attempt fails, and so does the cleanup
    drop.  A reader of ``cbomestatelink`` must never wait meanwhile (348d032f: the plain DROP INDEX queued an ACCESS
    EXCLUSIVE lock for ``LOCK_TIMEOUT`` and every SELECT waited behind it), and the cleanup gives up after its own
    short timeout, logged, leaving the index to the next run."""
    from test_cbom_posture_review_6064356833 import _hold, _q110
    from test_cbom_q109_followups import Q110, _step_tx

    with pg.begin() as conn:
        conn.execute(sa.text("DROP INDEX IF EXISTS uq_cbomestatelink_link"))
    module = _q110("2s", 0.2)
    module.CLEANUP_LOCK_TIMEOUT = "300ms"
    holder = _hold(pg)
    waits: list[float] = []
    stop = threading.Event()

    def read():
        with pg.connect() as conn:
            while not stop.is_set():
                started = time.monotonic()
                conn.execute(sa.text("SELECT count(*) FROM cbomestatelink")).scalar()
                waits.append(time.monotonic() - started)
                conn.rollback()
                time.sleep(0.05)

    reader = threading.Thread(target=read)
    caplog.set_level("WARNING")
    try:
        reader.start()
        with pytest.raises(sa.exc.OperationalError):
            _step_tx(pg, Q110, "upgrade", module=module)
    finally:
        stop.set()
        reader.join()
        holder.rollback()
        holder.close()
    assert waits and max(waits) < 1.0, max(waits)  # 348d032f: ~2 s behind the plain drop
    assert any("cleanup" in r.getMessage() and "uq_cbomestatelink_link" in r.getMessage() for r in caplog.records)
    assert _index_valid(pg) is False  # left for the next run, which drops it first
    _step_tx(pg, Q110, "upgrade", module=_q110("2s", 0.2))  # nothing holds the table now
    assert _index_valid(pg) is True


def test_q110_cleanup_drop_still_removes_an_invalid_index_when_only_a_snapshot_blocks(pg):
    from test_cbom_posture_review_6064356833 import _q110
    from test_cbom_q109_followups import Q110, _step_tx

    with pg.begin() as conn:
        conn.execute(sa.text("DROP INDEX IF EXISTS uq_cbomestatelink_link"))
    holder = pg.connect()  # an old snapshot on another table: blocks a CONCURRENTLY build, holds no table lock
    holder.execute(sa.text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
    holder.execute(sa.text("SELECT count(*) FROM team")).scalar()
    try:
        with pytest.raises(sa.exc.OperationalError):
            _step_tx(pg, Q110, "upgrade", module=_q110("1s", 0.2))
    finally:
        holder.rollback()
        holder.close()
    assert _index_valid(pg) is None  # no INVALID index left behind


def _index_valid(engine):
    with engine.connect() as conn:
        return conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar()


# ------------------------------------------------------------------------------------------------ n1, n3
_DIRECT = re.compile(r"""os\.environ(?:\.get)?\s*[\[(]\s*["']CBOM_TEST_PG_URL["']""")


def test_every_pg_test_reads_the_url_through_the_guard():
    here = Path(__file__).resolve().parent
    offenders = sorted(p.name for p in here.glob("test_*.py") if _DIRECT.search(p.read_text(encoding="utf-8")))
    assert offenders == []  # 348d032f: 24 files, test_cbom_identity_qa2 and test_scm_queue among them


def test_the_guard_never_names_a_database_without_test(monkeypatch):
    from backend.tests.support import pg_test_db as G

    monkeypatch.setattr(G, "_STARTED", False)
    monkeypatch.setattr(G, "_TO_CREATE", {})
    assert G.safe_database_name("cbom") == "cbom_cbom_test" and G.safe_database_name("ci_cbom_test") == "ci_cbom_test"
    assert G.guarded(None) is None
    url = G.guarded("postgresql+psycopg2://ci:pw@127.0.0.1:5432/cbom")
    assert sa.engine.make_url(url).database == "cbom_cbom_test" and G._TO_CREATE[url].endswith("/cbom")
    assert G.guarded("postgresql+psycopg2://ci:pw@127.0.0.1:5432/x_test").endswith("/x_test")
    if PG:
        assert "test" in (sa.engine.make_url(PG).database or "")


def test_the_label_salt_and_its_fallback_are_documented():
    import inspect

    from backend.utilities.cbom_sources import run_tickets as RT

    text = inspect.getsource(RT.resource_label)
    assert "aws_external_id" in text and "previous-salt" in text and "ticket_key" in text and "rotates" in text
