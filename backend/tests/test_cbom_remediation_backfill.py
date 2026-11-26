"""The deploy backfill ``q111remgroup001`` (``remediation_backfill``): plans and tickets stored on one source's own key
move to their resource's group key, so they survive that source being deleted.

Run against SQLite always and against PostgreSQL when ``CBOM_TEST_PG_URL`` is set (as ``test_cbom_identity_qa2``).
Fixture: ``fixtures/cbom_sources_two_aws_roles.json`` via ``test_cbom_posture_review_6058574998._two_runs``.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402  (review 6065677758 n1)
from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomRemediationAssignment,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.test_cbom_posture_review_6058574998 import T0, _asset, _job, _two_runs  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

VERSIONS = _REPO_ROOT / "prod_database_migrations/migrations/versions"
MIGRATION = "q111remgroup001_remediation_group_keys"


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=pytest.mark.skipif(
    not cbom_test_pg_url(), reason="set CBOM_TEST_PG_URL to run against PostgreSQL"))])
def engine(request, tmp_path):
    from backend.tests.test_cbom_posture_review_6064356833 import pg_test_url

    RI.clear_cache()
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path / 'backfill.db'}", connect_args={"check_same_thread": False})
    else:  # it drops every table: only a database whose name says "test" (review 6064356833 note)
        engine = create_engine(pg_test_url())
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    RI.clear_cache()
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


def _step(engine, direction: str) -> None:
    """Run the migration's own upgrade / downgrade on a connection, as alembic does."""
    import importlib.util

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    spec = importlib.util.spec_from_file_location("q111", VERSIONS / f"{MIGRATION}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(module, direction)()


def _row(s, run_id: int, source_id: int | None, kind: str = "kms_key") -> CbomCollectedAsset:
    return s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id,
                                                   CbomCollectedAsset.source_id == source_id,
                                                   CbomCollectedAsset.asset_type == kind)
                  .order_by(CbomCollectedAsset.id)).first()


def _own(row: CbomCollectedAsset, ref: str) -> str:
    return ID.stable_key("node", ref, ID.node_identity(row))


def _item(s, run_id: int, label: str, kind: str = "kms_key") -> dict:
    from backend.utilities.cbom_sources import waves as WAVES

    return next(i for i in WAVES.node_items(s, 1, s.get(CbomCollectionRun, run_id))
                if i["type"] == kind and i["label"] == label)


def _delete_source(s, source_id: int) -> None:
    """As ``removal.remove_source`` leaves it: jobs and rows without a source, the job's snapshot kept."""
    for job in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == source_id)).all():
        job.source_id = None
        s.add(job)
    for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.source_id == source_id)).all():
        row.source_id = None
        s.add(row)
    s.delete(s.get(CbomCollectionSource, source_id))
    s.commit()


def _run_with_only(s, source_id: int, at: dt.datetime) -> int:
    run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"only-{source_id}-{at:%j}", status="done")
    s.add(run)
    s.commit()
    src = s.get(CbomCollectionSource, source_id)
    job = _job(s, run, src, at)
    for item in AWS2.items():
        if item["job_id"] == 520:
            _asset(s, run, job, src, item)
    s.commit()
    return int(run.id)


def test_a_plan_on_a_deleted_sources_own_key_is_shown_after_the_backfill(engine):
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        b_row = _row(s, first, b_id)
        label = ID.node_label(b_row)
        b_key = _own(b_row, "srcB")
        s.add(CbomRemediationAssignment(team_id=1, asset_key=b_key, source_ref="srcB", status="in_progress", wave=1,
                                        owner="ops", ticket_key="SEC-7",
                                        ticket_url="https://jira.example/browse/SEC-7", ticket_state="created"))
        s.commit()
        _delete_source(s, b_id)
        later = _run_with_only(s, a_id, T0 + dt.timedelta(days=3))
        before = _item(s, later, label)
    assert before["assignment"] is None  # the limit: nothing in this run reads B's copy any more
    _step(engine, "upgrade")
    with Session(engine) as s:
        after = _item(s, later, label)
        assert after["assignment"]["status"] == "in_progress" and after["assignment"]["owner"] == "ops"
        assert after["assignment"]["ticket_key"] == "SEC-7" and after["asset_key"] == after["group_key"]
        original = s.exec(select(CbomRemediationAssignment).where(CbomRemediationAssignment.asset_key == b_key)).one()
        assert original.status == "in_progress"  # kept for an older release
        count = len(s.exec(select(CbomRemediationAssignment)).all())
    _step(engine, "upgrade")  # idempotent: nothing more
    with Session(engine) as s:
        assert len(s.exec(select(CbomRemediationAssignment)).all()) == count == 2


def test_conflicts_follow_resolve_and_the_ticket_holding_copy_wins(engine):
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id, "cdn_tls"), _row(s, first, b_id, "cdn_tls")
        label = ID.node_label(a_row)
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own(a_row, "srcA"), source_ref="srcA", status="open",
                                        wave=2, owner="plan-only"))
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB",
                                        status="in_progress", ticket_key="SEC-9", ticket_state="created"))
        s.commit()
        shown = _item(s, first, label, "cdn_tls")["assignment"]
    _step(engine, "upgrade")
    with Session(engine) as s:
        item = _item(s, first, label, "cdn_tls")
        group = s.exec(select(CbomRemediationAssignment).where(
            CbomRemediationAssignment.asset_key == item["group_key"])).one()
    assert (group.status, group.ticket_key, group.source_ref) == ("in_progress", "SEC-9", f"group-backfill:"
                                                                  f"{_own(b_row, 'srcB')}")
    assert item["assignment"]["status"] == shown["status"] and item["assignment"]["ticket_key"] == "SEC-9"


def test_the_downgrade_writes_changes_back_and_removes_only_its_records(engine):
    first, _second, _a, b_id = _two_runs(engine)
    with Session(engine) as s:
        b_row = _row(s, first, b_id)
        b_key = _own(b_row, "srcB")
        s.add(CbomRemediationAssignment(team_id=1, asset_key=b_key, source_ref="srcB", status="open", wave=3))
        s.commit()
        label = ID.node_label(b_row)
    _step(engine, "upgrade")
    with Session(engine) as s:
        group_key = _item(s, first, label)["group_key"]
        group = s.exec(select(CbomRemediationAssignment).where(
            CbomRemediationAssignment.asset_key == group_key)).one()
        group.status, group.ticket_key = "done", "SEC-11"  # a change made after the upgrade
        s.add(group)
        s.commit()
    _step(engine, "downgrade")
    with Session(engine) as s:
        rows = s.exec(select(CbomRemediationAssignment)).all()
    assert [(r.asset_key, r.status, r.ticket_key, r.wave) for r in rows] == [(b_key, "done", "SEC-11", 3)]
    _step(engine, "upgrade")  # up again: the same group record, once
    with Session(engine) as s:
        assert len(s.exec(select(CbomRemediationAssignment)).all()) == 2


def test_results_statuses_are_cached_per_finished_run_and_follow_a_change(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_results as RR
    from backend.utilities.cbom_sources import waves as WAVES

    first, _second, a_id, _b = _two_runs(engine)
    calls = []
    real = WAVES.resolve_run
    monkeypatch.setattr(WAVES, "resolve_run", lambda *a, **k: calls.append(1) or real(*a, **k))
    RR._STATUS_CACHE.clear()
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, first)
        one = RR._resolved_statuses(s, 1, run)
        assert RR._resolved_statuses(s, 1, run) == one and len(calls) == 1
        row = _row(s, first, a_id)
        s.add(CbomRemediationAssignment(team_id=1, asset_key=_item(s, first, ID.node_label(row))["asset_key"],
                                        source_ref="srcA", status="done"))
        s.commit()
        changed = RR._resolved_statuses(s, 1, run)
    assert len(calls) == 3 and "done" in changed.values()  # node_items above resolved once more, then the change
