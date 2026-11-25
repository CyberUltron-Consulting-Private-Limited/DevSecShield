"""Review 6064356833 of PR #499 (round 5): the reviewer's seeds R0-R3 and probe P8 as tests.

M1  The group key and Jira label were the same in every team (and environment): team 2's "Create tickets" found team
    1's issue by label across the whole Jira site.  The group key is team-scoped, the label also carries the team's
    own random salt, and the label search is restricted to the team's configured project.
M2  A ticket-only copy replaced a real plan (R1): the plan and the ticket are merged field by field, at run time
    (``remediation_group.resolve``) and in the backfill.
M3  The /results status cache answered for the old kept row after a source was deleted (P8).
m1  The backfill now counts and logs ``unplaced`` (R3) and ``ticket_conflicts`` (R0).
m2  q110: every attempt counts (a lock timeout on the drop fails that attempt), no INVALID index when the table is
    free (PostgreSQL only, scaled timeouts).
n1  Key moves bump ``row_version``.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
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
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomRemediationAssignment as A,
    Team,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.test_cbom_posture_review_6058574998 import T0, _two_runs  # noqa: E402
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import resource_identity as RI  # noqa: E402

VERSIONS = _REPO_ROOT / "prod_database_migrations/migrations/versions"


def _test_database_name(name: str) -> str:
    """The database these tests may drop tables in: ``name`` itself when it says "test", else ``<name>_cbom_test``."""
    return name if "test" in name.lower() else f"{name}_cbom_test"


def pg_test_url() -> str | None:
    """A URL for ``CBOM_TEST_PG_URL``'s server whose database name contains "test" (these tests drop every table):
    the configured database when its name says so, else a database of its own, created once on that server (review
    6064356833 note: never the configured database itself)."""
    url = os.environ.get("CBOM_TEST_PG_URL")
    if not url:
        return None
    parsed = sa.engine.make_url(url)
    target = _test_database_name(parsed.database or "postgres")
    if target == parsed.database:
        return url
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            if not conn.execute(sa.text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": target}).scalar():
                conn.execute(sa.text(f'CREATE DATABASE "{target}"'))
    finally:
        admin.dispose()
    return parsed.set(database=target).render_as_string(hide_password=False)


@pytest.fixture()
def engine(tmp_path):
    RI.clear_cache()
    engine = create_engine(f"sqlite:///{tmp_path / 'r6064356833.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    yield engine
    RI.clear_cache()


def _backfill(engine, reverse: bool = False) -> dict:
    from backend.utilities.cbom_sources import remediation_backfill as RB

    with engine.begin() as conn:
        return RB.backfill_all(conn, reverse=reverse)


def _own(row, ref: str) -> str:
    return ID.stable_key("node", ref, ID.node_identity(row))


def _row(s, run_id, source_id, kind="kms_key"):
    return s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id,
                                                   CbomCollectedAsset.source_id == source_id,
                                                   CbomCollectedAsset.asset_type == kind)
                  .order_by(CbomCollectedAsset.id)).first()


def _item(s, team_id, run_id, label, kind="kms_key"):
    from backend.utilities.cbom_sources import waves as WAVES

    return next(i for i in WAVES.node_items(s, team_id, s.get(CbomCollectionRun, run_id))
                if i["type"] == kind and i["label"] == label)


# ------------------------------------------------------------------------------------------------ M1 two teams
def _team_run(s, team: int) -> int:
    """Team ``team``: one AWS role reading staging run #57's account (the same ARNs in every team)."""
    s.add(Team(id=team, name=f"T{team}", credit_balance=0.0))
    s.add(CbomCollectionSettings(team_id=team, aws_external_id=f"ext-{team}-" + "x" * 28, jira_project_key="SEC"))
    s.commit()
    src = CbomCollectionSource(team_id=team, owner_user_id=1, kind="aws_account", name=f"role{team}",
                               name_lower=f"role{team}", source_uid=f"t{team}role")
    s.add(src)
    s.commit()
    run = CbomCollectionRun(team_id=team, owner_user_id=1, client_request_id=f"t{team}", status="done")
    s.add(run)
    s.commit()
    job = CbomCollectionJob(team_id=team, run_id=run.id, source_id=src.id, kind="collect", status="success",
                            outcome="ok", attempts=1, finished_at=T0,
                            params={"source_uid": src.source_uid, "source_name": src.name})
    s.add(job)
    s.commit()
    for item in AWS2.items():
        if item["job_id"] != 520 or item["type"] != "cdn_tls":
            continue
        j = C.classify(item["type"], item.get("algorithm"), item.get("key_size"), item.get("protocol"),
                       item["facts"], T0)
        s.add(CbomCollectedAsset(
            team_id=team, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
            asset_key=hashlib.sha256(f"{src.source_uid}|{item['location']}".encode()).hexdigest(),
            asset_type=item["type"], cdx_type=j["cdx_type"], target=item.get("target"), location=item["location"],
            name=item.get("name"), algorithm=item.get("algorithm"), key_size=item.get("key_size"),
            protocol=item.get("protocol"), quantum_vulnerable=j["quantum_vulnerable"], impact=j["impact"],
            finding=j["finding"], finding_codes=j["finding_codes"], facts=item["facts"], created_at=T0))
    s.commit()
    return int(run.id)


def test_two_teams_reading_one_arn_get_two_jira_issues_on_one_site(engine, monkeypatch):
    from backend.utilities.cbom_sources import run_tickets as RT
    from backend.utilities.cbom_sources import waves as WAVES

    issues: dict[tuple[str, str], str] = {}  # (project, label) -> key: one Jira site for both teams

    def create(**kw):
        key = f"SEC-{len(issues) + 1}"
        issues[(kw.get("project_key") or kw.get("project_id"), kw["labels"][0])] = key
        return {"key": key}

    def find(url, token, label, jira_email=None, project=None):
        hits = [k for (p, lab), k in issues.items() if lab == label and (project is None or p == project)]
        return hits[-1] if hits else None

    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", create)
    monkeypatch.setattr(RT.JIRA, "find_issue_by_label", find)
    monkeypatch.setattr(RT, "_jira_creds", lambda team: ("qa@example.com", "token", "https://jira.example"))
    with Session(engine) as s:
        runs = {team: _team_run(s, team) for team in (1, 2)}
        items = {team: next(i for i in WAVES.node_items(s, team, s.get(CbomCollectionRun, runs[team]))
                            if RT.is_ticketable(i)) for team in (1, 2)}
    assert items[1]["label"] == items[2]["label"] and items[1]["group_key"] != items[2]["group_key"]
    keys = []
    for team in (1, 2):
        out = RT.create_tickets(engine, team, 1, runs[team], RT.TicketBody(asset_ids=[items[team]["asset_id"]]))
        keys.append([c["ticket_key"] for c in out["created"]])
        # a retry after a lost claim searches by label: it must find this team's issue, never the other's
        found = RT._jira_issue("https://jira.example", "t", "e", "SEC", "Task", items[team], {}, runs[team],
                               search_first=True, salt=f"ext-{team}-" + "x" * 28)
        assert found == (keys[-1][0], True)
    assert keys == [["SEC-1"], ["SEC-2"]]  # 3f3107f4: team 2 got team 1's SEC-1 as "existing"
    assert len({label for _p, label in issues}) == 2


def test_the_label_search_is_restricted_to_the_configured_project(monkeypatch):
    from backend.utilities.integrations import jira as J

    sent = {}

    class Response:
        status_code = 200

        def json(self):
            return {"issues": [{"key": "SEC-4"}]}

        def raise_for_status(self):
            return None

    def request(method, url, data=None, **kw):
        sent["jql"] = __import__("json").loads(data)["jql"]
        return Response()

    monkeypatch.setattr(J, "validate_jira_url", lambda url: None)
    monkeypatch.setattr(J.requests, "request", request)
    assert J.find_issue_by_label("https://bank.atlassian.net", "t", "zs-asset-ab", project="SEC") == "SEC-4"
    assert sent["jql"] == 'project = "SEC" AND labels = "zs-asset-ab" ORDER BY created DESC'
    with pytest.raises(ValueError):
        J.find_issue_by_label("https://bank.atlassian.net", "t", "zs-asset-ab", project='SEC" OR project = "X')


def test_the_backfill_writes_the_team_scoped_group_key():
    from backend.utilities.cbom_sources import remediation_group as RG

    arn = "arn:aws:kms:ap-south-1:444455556666:key/1"
    one = RG.row_group_key("kms_key", "aws:1", arn, {}, team_id=1)
    two = RG.row_group_key("kms_key", "aws:1", arn, {}, team_id=2)
    assert one != two and one == RG.group_key(f"res|kms_key|{arn}", 1)


# ------------------------------------------------------------------------------------------------ M2 (R1)
def _r1(engine):
    """R1: A holds the plan (in_progress, wave 2, owner alice, note), B only the ticket "Create tickets" made."""
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id, "cdn_tls"), _row(s, first, b_id, "cdn_tls")
        s.add(A(team_id=1, asset_key=_own(a_row, "srcA"), source_ref="srcA", status="in_progress", wave=2,
                owner="alice", note="rotate the cert", last_updated=dt.datetime(2026, 11, 1)))
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="open", ticket_key="SEC-3",
                ticket_url="https://jira.example/browse/SEC-3", ticket_state="created",
                last_updated=dt.datetime(2026, 11, 20)))
        s.commit()
        return first, ID.node_label(a_row), _own(a_row, "srcA"), _own(b_row, "srcB")


def test_a_ticket_only_copy_never_replaces_a_real_plan(engine):
    first, label, a_key, _b_key = _r1(engine)
    with Session(engine) as s:
        shown = _item(s, 1, first, label, "cdn_tls")
    plan = shown["assignment"]
    assert (plan["status"], plan["wave"], plan["owner"], plan["ticket_key"]) == ("in_progress", 2, "alice", "SEC-3")
    assert shown["asset_key"] == a_key  # a change edits alice's plan, not the ticket-only record


def test_the_backfill_merges_plan_and_ticket_and_the_downgrade_splits_them(engine):
    first, label, a_key, b_key = _r1(engine)
    _backfill(engine)
    with Session(engine) as s:
        item = _item(s, 1, first, label, "cdn_tls")
        group = s.exec(select(A).where(A.asset_key == item["group_key"])).one()
        assert (group.status, group.wave, group.owner, group.note, group.ticket_key) == (
            "in_progress", 2, "alice", "rotate the cert", "SEC-3")  # 3f3107f4: open / None / None / SEC-3
        assert group.source_ref == f"group-backfill:{a_key}|{b_key}"
        assert item["assignment"]["status"] == "in_progress" and item["assignment"]["owner"] == "alice"
    _backfill(engine, reverse=True)
    with Session(engine) as s:
        rows = {r.asset_key: r for r in s.exec(select(A)).all()}
    assert set(rows) == {a_key, b_key}
    assert (rows[a_key].status, rows[a_key].owner, rows[a_key].ticket_key) == ("in_progress", "alice", None)
    assert (rows[b_key].status, rows[b_key].ticket_key) == ("open", "SEC-3")


# ------------------------------------------------------------------------------------------------ M3 (P8)
def test_results_statuses_follow_a_source_deletion(engine):
    from backend.utilities.cbom_sources import run_results as RR

    first, _second, a_id, b_id = _two_runs(engine)
    RR._STATUS_CACHE.clear()
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, first)
        b_row = _row(s, first, b_id)  # run 1: B finished last, its row is shown
        label = ID.node_label(b_row)
        item = _item(s, 1, first, label)
        s.add(A(team_id=1, asset_key=item["asset_key"], source_ref="srcB", status="in_progress"))
        s.commit()
        assert RR._resolved_statuses(s, 1, run)[bytes.fromhex(item["own_key"])] == "in_progress"  # cache warm
        for job in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == b_id)).all():
            job.source_id = None
            s.add(job)
        s.delete(s.get(CbomCollectionSource, b_id))
        s.commit()
    with Session(engine) as s:  # the next request (a deletion is its own request; the fold memo is per request)
        run = s.get(CbomCollectionRun, first)
        a_row = next(r for r in s.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.run_id == first, CbomCollectedAsset.source_id == a_id,
            CbomCollectedAsset.asset_type == "kms_key")).all() if ID.node_label(r) == label)
        now_kept = _item(s, 1, first, label)
        assert now_kept["asset_id"] == a_row.id and now_kept["assignment"]["status"] == "in_progress"
        actions, _metrics = RR._remediation(s, 1, {bytes.fromhex(_own(a_row, "srcA")): (1 << 2) | 1}, run)
    assert actions["total_in_progress"] == 1 and actions["total_not_started"] == 0  # 3f3107f4: 0 / 1


# ------------------------------------------------------------------------------------------------ m1 (R0, R3)
def test_the_backfill_reports_purged_and_conflicting_records(engine, monkeypatch):
    from backend.utilities.cbom_sources import remediation_backfill as RB

    logged: list[tuple[str, dict]] = []
    monkeypatch.setattr("backend.utilities.cbom_sources.common.log", lambda what, **kw: logged.append((what, kw)))
    first, _second, a_id, b_id = _two_runs(engine)
    with Session(engine) as s:
        a_row, b_row = _row(s, first, a_id), _row(s, first, b_id)
        # R0: two issues for one resource
        s.add(A(team_id=1, asset_key=_own(a_row, "srcA"), source_ref="srcA", status="in_progress", ticket_key="SEC-1",
                last_updated=dt.datetime(2026, 11, 1)))
        s.add(A(team_id=1, asset_key=_own(b_row, "srcB"), source_ref="srcB", status="done", ticket_key="SEC-2",
                last_updated=dt.datetime(2026, 11, 2)))
        # R3: a plan whose rows were purged
        s.add(A(team_id=1, asset_key="f" * 40, source_ref="srcGone", status="accepted_risk", owner="bob"))
        s.commit()
    with engine.begin() as conn:
        totals = RB.backfill_all(conn)
    assert (totals["unplaced"], totals["ticket_conflicts"]) == (1, 1)
    conflict = next(kw for what, kw in logged if what.endswith("ticket conflict"))
    assert conflict["shown"] == "SEC-2" and conflict["not_shown"] == "SEC-1"  # the newer plan's ticket is shown
    unplaced = next(kw for what, kw in logged if what.endswith("unplaced"))
    assert unplaced["count"] == 1 and unplaced["keys"] == "f" * 12
    team = next(kw for what, kw in logged if what.endswith("backfill team"))
    assert team["unplaced"] == 1 and team["ticket_conflicts"] == 1
    with Session(engine) as s:  # the purged record stays where it is
        assert s.exec(select(A).where(A.asset_key == "f" * 40)).one().owner == "bob"


# ------------------------------------------------------------------------------------------------ n1
def test_a_key_move_bumps_row_version(engine):
    from backend.utilities.cbom_sources import identity_migration as M

    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=0.0))
        s.add(A(team_id=1, asset_key="a" * 40, source_ref="s", status="in_progress", row_version=3))
        s.commit()
        assert M._move_assignments(s, 1, {"a" * 40: "b" * 40}) == 1
        s.commit()
        moved = s.exec(select(A)).one()
    assert (moved.asset_key, moved.row_version) == ("b" * 40, 4)


# ------------------------------------------------------------------------------------------------ m2 q110 retries
@pytest.fixture()
def pg(tmp_path):
    url = pg_test_url()
    if not url:
        pytest.skip("set CBOM_TEST_PG_URL (a database whose name contains 'test') to run against PostgreSQL")
    engine = create_engine(url)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    SQLModel.metadata.drop_all(engine)
    engine.dispose()


def _q110(lock: str, retry: float):
    import importlib.util

    spec = importlib.util.spec_from_file_location("q110", VERSIONS / "q110linkuq001_estate_link_unique.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.LOCK_TIMEOUT, module.RETRY_SECONDS = lock, retry
    return module


def _index(engine):
    with engine.connect() as conn:
        return conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar()


def _hold(engine):
    """An idle-in-transaction session that wrote to the table (holds ROW EXCLUSIVE: a CONCURRENTLY build and drop wait
    for it, and so does a plain DROP INDEX), as an older worker's unfinished write does."""
    conn = engine.connect()
    conn.execute(sa.text("UPDATE cbomestatelink SET component = component WHERE false"))
    return conn


def test_q110_makes_three_attempts_against_a_held_transaction(pg):
    from test_cbom_q109_followups import Q110, _step_tx

    with pg.begin() as conn:
        conn.execute(sa.text("DROP INDEX IF EXISTS uq_cbomestatelink_link"))
    module = _q110("2s", 1)
    calls: list[str] = []
    for name in ("create_index", "drop_index"):
        real = getattr(module.op, name)
        monkey = (lambda real, name: lambda *a, **k: calls.append(name) or real(*a, **k))(real, name)
        setattr(module.op, name, monkey)
    holder = _hold(pg)
    try:
        started = time.monotonic()
        with pytest.raises(sa.exc.OperationalError):
            _step_tx(pg, Q110, "upgrade", module=module)
        took = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()
    # 3f3107f4: [create, drop, drop] and raised after the first build attempt (the start-of-attempt drop escaped)
    assert calls == ["create_index", "drop_index", "drop_index", "drop_index"]
    assert 9 <= took < 20  # 4 waits of 2 s + 2 pauses of 1 s (the README's 4 x 60 + 2 x 10 at full scale)


def test_q110_retries_until_the_transaction_ends_and_leaves_a_valid_index(pg):
    from test_cbom_q109_followups import Q110, _step_tx

    with pg.begin() as conn:
        conn.execute(sa.text("DROP INDEX IF EXISTS uq_cbomestatelink_link"))
    holder = _hold(pg)
    release = threading.Timer(3.0, lambda: (holder.rollback(), holder.close()))
    release.start()
    try:
        _step_tx(pg, Q110, "upgrade", module=_q110("2s", 1))
    finally:
        release.join()
    assert _index(pg) is True  # valid, and no INVALID one left behind
    with pg.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE NOT i.indisvalid")).scalar() == 0


def test_the_pg_tests_never_drop_tables_in_a_database_not_named_test():
    assert _test_database_name("cbom") == "cbom_cbom_test" and _test_database_name("cbom_test") == "cbom_test"
    url = pg_test_url()
    if url is not None:  # with CBOM_TEST_PG_URL set: the URL handed to the fixtures names a test database
        assert "test" in (sa.engine.make_url(url).database or "")
