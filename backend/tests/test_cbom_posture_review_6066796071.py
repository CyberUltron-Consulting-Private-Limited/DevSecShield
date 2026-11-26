"""Review 6066796071 of PR #499 (round 7): the group record is the final word whenever it exists.

M1  A reset cleared only the copies of the run it was made in (``waves._reset_other_keys``), so q111's kept original on
    a copy that run did not read (a scheduled single-source run, a deleted source, an older run) was the newest plan
    again: the team view and other runs showed it.  Now ``remediation_group.resolve`` reads the group record's plan as
    the resource's once it exists (a reset to blank included), every write goes to the group key, and the first write
    starts the group record from what the copies show.  No cascade: the copies, and their ``done_at``, stay as they
    were.
m1  Every plan edit writes one ``remediation.assign`` audit row per resource: the key written (the group key), the
    asset and the previous values.
n1  q111 logs, per team, the resources whose copies hold a blank record newer than the plan it copied
    (``test_cbom_posture_review_6065677758``).

SQLite always; PostgreSQL too with ``CBOM_TEST_PG_URL`` set (as in CI).
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionAuditEvent,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
)
from backend.new_models import CbomRemediationAssignment as A  # noqa: E402
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402
from backend.tests.test_cbom_posture_review_6058574998 import T0, _asset, _job, _two_runs  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

PG = cbom_test_pg_url()
OLDER = dt.datetime(2026, 11, 1)
RESET_AT = dt.datetime(2026, 11, 25)
OPEN = {"waves": ("open", None, None), "list": "not_started", "team": "open", "results": "total_not_started"}
BOB_DONE = {"waves": ("done", "bob", 1), "list": "fixed", "team": "done", "results": "total_fixed"}


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=pytest.mark.skipif(
    not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL"))])
def engine(request, tmp_path):
    RI.clear_cache()
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path / 'r6066796071.db'}", connect_args={"check_same_thread": False})
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


def _kms(s, run_id, source_id):
    return s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id,
                                                   CbomCollectedAsset.source_id == source_id,
                                                   CbomCollectedAsset.asset_type == "kms_key")
                  .order_by(CbomCollectedAsset.id)).first()


def _single_run(engine, source_id: int, at: dt.datetime) -> int:
    """A scheduled run of ONE source (nothing to fold: its own copy only)."""
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, source_id)
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"single-{source_id}-{at:%H%M%S}",
                                status="done")
        s.add(run)
        s.commit()
        job = _job(s, run, src, at)
        fixture_job = 520 if src.source_uid == "srcA" else 521
        for item in AWS2.items():
            if item["job_id"] == fixture_job:
                _asset(s, run, job, src, item)
        s.commit()
        return int(run.id)


def _item(s, run_id, label):
    from backend.utilities.cbom_sources import waves as WAVES

    return next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
                if i["type"] == "kms_key" and i["label"] == label)


def _surfaces(engine, run_id: int, label: str) -> dict:
    from test_cbom_posture_review_6065677758 import _surfaces as surfaces

    return surfaces(engine, run_id, label)


def _bob_backfilled(engine):
    """The reviewer's repro: B's own key holds ``done / bob / wave 1``; q111 copies it to the group record G."""
    from backend.utilities.cbom_sources import remediation_backfill as RB

    first, second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        b_row = _kms(s, first, b_id)
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="done", wave=1, owner="bob",
                done_at=OLDER, last_updated=OLDER))
        s.commit()
        label, b_key = ID.node_label(b_row), _own(b_row, "srcB")
    with engine.begin() as conn:
        assert RB.backfill_all(conn)["inserted"] == 1
    return first, second, a_id, b_id, label, b_key


def _reset(engine, run_id: int, label: str) -> dict:
    from backend.utilities.cbom_sources import waves as WAVES

    with Session(engine) as s:
        key = _item(s, run_id, label)["asset_key"]
        out = WAVES.upsert(s, 1, 7, WAVES.AssignmentBulk(run_id=run_id, items=[WAVES.AssignmentItem(
            asset_key=key, status="open", wave=None, owner=None, target_date=None, note=None)]), RESET_AT)
        s.commit()
    return out


def _team_status(engine, label: str) -> str:
    from backend.utilities.cbom_sources import collections_view as CV

    with Session(engine) as s:
        kept = CV.resolve([], CV.load_sources_result(s, 1, now=RESET_AT).rows).sources_rows
    return next(r.row["remediation_status"] for r in kept
                if r.node_type == "kms_key" and r.row.get("location") in label)


# ------------------------------------------------------------------------------------------------ M1 the repro
def test_a_reset_in_a_run_of_a_only_holds_on_every_surface_and_every_run(engine):
    first, second, a_id, _b_id, label, b_key = _bob_backfilled(engine)
    assert _surfaces(engine, first, label) == BOB_DONE
    only_a = _single_run(engine, a_id, T0 + dt.timedelta(days=2))
    with Session(engine) as s:
        item = _item(s, only_a, label)
        assert item["asset_key"] == item["group_key"] and b_key not in item["alias_keys"]
    assert _reset(engine, only_a, label)["updated"] == 1
    for run_id in (only_a, first, second):  # aeedcafc: the team view and the A+B runs showed bob's "done" again
        assert _surfaces(engine, run_id, label) == OPEN, run_id
    with Session(engine) as s:  # no cascade: bob's original and its time-to-remediate history stay
        original = s.exec(select(A).where(A.asset_key == b_key)).one()
    assert (original.status, original.owner, original.done_at) == ("done", "bob", OLDER)


def test_a_reset_holds_after_either_source_is_deleted(engine):
    from test_cbom_remediation_backfill import _delete_source

    first, _second, a_id, b_id, label, _b_key = _bob_backfilled(engine)
    _reset(engine, _single_run(engine, a_id, T0 + dt.timedelta(days=2)), label)  # B's original is not in that run
    for source_id in (a_id, b_id):
        with Session(engine) as s:
            _delete_source(s, source_id)
        RI.clear_cache()
        assert _surfaces(engine, first, label) == OPEN


def test_a_reset_holds_in_a_later_scheduled_single_source_run(engine):
    first, _second, a_id, b_id, label, _b_key = _bob_backfilled(engine)
    _reset(engine, _single_run(engine, a_id, T0 + dt.timedelta(days=2)), label)
    only_b = _single_run(engine, b_id, T0 + dt.timedelta(days=3))  # the source whose copy holds bob's original
    assert _surfaces(engine, only_b, label) == OPEN
    assert _team_status(engine, label) == "open"


def test_a_plan_edit_after_the_reset_is_what_every_run_shows(engine):
    from backend.utilities.cbom_sources import waves as WAVES

    first, second, a_id, _b_id, label, _b_key = _bob_backfilled(engine)
    only_a = _single_run(engine, a_id, T0 + dt.timedelta(days=2))
    _reset(engine, only_a, label)
    with Session(engine) as s:
        key = _item(s, second, label)["asset_key"]
        WAVES.upsert(s, 1, 7, WAVES.AssignmentBulk(run_id=second, items=[WAVES.AssignmentItem(
            asset_key=key, status="in_progress", owner="carol")]), RESET_AT)
        s.commit()
    for run_id in (only_a, first, second):
        shown = _surfaces(engine, run_id, label)
        assert shown["waves"] == ("in_progress", "carol", None) and shown["team"] == "in_progress"


# ------------------------------------------------------------------------------------------------ the first write
def test_the_first_write_starts_the_group_record_from_the_copies(engine):
    """No q111 record (a legacy plan on B's copy): editing the owner writes the group record with bob's status, wave
    and done_at kept, so the edit changes only the owner and time-to-remediate keeps its start."""
    from backend.utilities.cbom_sources import waves as WAVES

    first, _second, _a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        b_row = _kms(s, first, b_id)
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="done", wave=1, owner="bob",
                done_at=OLDER, created_at=OLDER, last_updated=OLDER))
        s.commit()
        label = ID.node_label(b_row)
        item = _item(s, first, label)
        assert item["asset_key"] == item["group_key"]  # the write key, though only a copy holds a record
        WAVES.upsert(s, 1, 7, WAVES.AssignmentBulk(run_id=first, items=[WAVES.AssignmentItem(
            asset_key=item["asset_key"], owner="carol")]), RESET_AT)
        s.commit()
        group = s.exec(select(A).where(A.asset_key == item["group_key"])).one()
    assert (group.status, group.wave, group.owner, group.done_at, group.created_at) == (
        "done", 1, "carol", OLDER, OLDER)
    assert _surfaces(engine, first, label)["waves"] == ("done", "carol", 1)


def test_a_ticket_claim_starts_the_group_record_from_the_copies_and_keeps_it(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT

    first, _second, _a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="ext-1-" + "x" * 28, jira_project_key="SEC"))
        b_row = _kms(s, first, b_id)
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="in_progress", owner="bob",
                last_updated=OLDER))
        s.commit()
        label = ID.node_label(b_row)
        item = _item(s, first, label)
    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", lambda **kw: {"key": "SEC-11"})
    monkeypatch.setattr(RT, "_jira_creds", lambda team: ("qa@example.com", "token", "https://jira.example"))
    out = RT.create_tickets(engine, 1, 1, first, RT.TicketBody(asset_ids=[item["asset_id"]]))
    assert [c["ticket_key"] for c in out["created"]] == ["SEC-11"]
    with Session(engine) as s:
        group = s.exec(select(A).where(A.asset_key == item["group_key"])).one()
    assert (group.status, group.owner, group.ticket_key) == ("in_progress", "bob", "SEC-11")
    shown = _surfaces(engine, first, label)
    assert shown["waves"] == ("in_progress", "bob", None) and shown["team"] == "in_progress"


# ------------------------------------------------------------------------------------------------ m1 audit
def test_each_resource_written_has_an_audit_row_with_its_previous_values(engine):
    from backend.routers import cbom_ops as OPS
    from backend.utilities.cbom_sources import waves as WAVES

    first, _second, _a_id, _b_id, label, _b_key = _bob_backfilled(engine)
    with Session(engine) as s:
        item = _item(s, first, label)
    body = WAVES.AssignmentBulk(run_id=first, items=[WAVES.AssignmentItem(
        asset_key=item["asset_key"], status="open", wave=None, owner=None)])
    out = OPS._put_remediation(engine, 1, 7, body)
    assert out == {"updated": 1}
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.action == "remediation.assign")).all()
    assert sorted(r.object_type for r in rows) == ["resource", "run"]
    fields = set(next(r for r in rows if r.object_type == "resource").changed_fields)
    assert {f"key={item['group_key']}", f"group={item['group_key']}", f"asset={item['own_key']}", "set=status",
            "prev.status=done", "prev.wave=1", f"prev.done_at={OLDER.isoformat()}", "prev.owner=set:3",
            "prev.note=empty"} <= fields
    assert not any("bob" in f for f in fields)  # a person's name is not copied into the audit trail


def test_no_cascade_is_left():
    from backend.utilities.cbom_sources import waves as WAVES

    assert not hasattr(WAVES, "_reset_other_keys")

