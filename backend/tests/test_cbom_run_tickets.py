"""CB-38 PR-4: Jira tickets for CBOM Sources run findings, the team's Jira project for them, ``done_at`` for the
remediation metrics, and migration cb38ticket001.

Same SQLite + real-router harness as test_cbom_sources_api.py / test_cbom_wp10_outputs.py; the Jira client is replaced
by a fake (``run_tickets.JIRA.create_issue_in_project``), never called over the network. The PostgreSQL migration test
runs when ``CBOM_TEST_PG_URL`` is set, as in CI.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import USERS, enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import OLD_CERT, OPENSSL, WEAK_TLS, _claim, _collect, _run  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionSettings,
    CbomRemediationAssignment,
    Team,
)
from backend.utilities.cbom_sources import run_tickets as RT  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402

api = HARNESS.api  # the shared fixtures (SQLite world, real routers and JWTs)
world = HARNESS.world
ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "prod_database_migrations/migrations/versions/cb38ticket001_run_tickets_done_at.py"
JIRA_TOKEN = "jira-token-canary-9f1c2b"
CLEAN_TLS = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443",
             "facts": {"protocols": ["TLSv1.3"], "group": "X25519MLKEM768"}}


class FakeJira:
    """Stands in for ``create_issue_in_project``: numbered keys, optional failure for one summary substring, optional
    delay (so two concurrent requests overlap inside the Jira call)."""

    def __init__(self):
        self.calls: list[dict] = []
        self.fail_on: str | None = None
        self.delay = 0.0
        self.lock = threading.Lock()

    def __call__(self, **kw):
        with self.lock:
            self.calls.append(kw)
            n = len(self.calls)
        time.sleep(self.delay)
        if self.fail_on and self.fail_on in kw["summary"]:
            raise Exception("Failed to create issue in Jira: {\"errors\":{\"issuetype\":\"invalid\"}}")
        return {"id": str(10000 + n), "key": f"SEC-{n}"}


@pytest.fixture()
def jira(monkeypatch):
    fake = FakeJira()
    monkeypatch.setattr(RT.JIRA, "create_issue_in_project", fake)
    return fake


def _connect_jira(engine, team_id=1, project="SEC"):
    with Session(engine) as s:
        team = s.get(Team, team_id)
        team.integration_settings = {"jira": {"url": "https://bank.atlassian.net", "email": "ops@bank.test",
                                              "api_token": JIRA_TOKEN}}
        s.add(team)
        s.commit()


@pytest.fixture()
def runs(api, world):
    return _make_runs(api, world[0])


def _make_runs(api, engine) -> dict:
    """Two runs of one source that saw the same weak TLS endpoint, certificate and library, plus a clean endpoint."""
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    run1 = _run(api, "cb38-tickets-0001")
    _collect(api, hdr, _claim(api, hdr), [OLD_CERT, WEAK_TLS, OPENSSL, CLEAN_TLS])
    run2 = _run(api, "cb38-tickets-0002")
    _collect(api, hdr, _claim(api, hdr), [OLD_CERT, WEAK_TLS, OPENSSL, CLEAN_TLS])
    _connect_jira(engine)
    with Session(engine) as s:
        assets = {}
        for row in s.exec(select(CbomCollectedAsset).order_by(CbomCollectedAsset.id)).all():
            assets.setdefault(row.run_id, {})[(row.asset_type, row.location)] = row.id
    return {"engine": engine, "run1": run1, "run2": run2, "assets": assets}


def _ids(runs, run, *kinds):
    table = runs["assets"][runs[run]["id"]]
    return [table[k] for k in kinds]


TLS = ("tls_endpoint", "10.20.0.1:443")
CERT = ("certificate", OLD_CERT["location"])
LIB = ("crypto_library", "package:openssl")
CLEAN = ("tls_endpoint", "10.20.0.1:8443")


def _set_project(api, who="alice", **body):
    return api("PUT", "/1/cbom/sources/ticketing", who, json={"jira_project_key": "sec", **body})


# ------------------------------------------------------------------------------------------- B15 idempotency
def test_run_tickets_idempotent(api, runs, jira):
    """B15: the same request twice opens one issue per stable key; the second reports the existing issues. A later run
    that saw the same assets reuses them too (one ticket per asset across runs)."""
    assert _set_project(api).status_code == 200
    tls, cert = _ids(runs, "run1", TLS, CERT)
    url = f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets"
    first = api("POST", url, json={"asset_ids": [tls, cert], "ticket_type": "jira"})
    assert first.status_code == 200, first.text
    body = first.json()
    assert [c["asset_id"] for c in body["created"]] == [tls, cert] and body["existing"] == [] and body["failed"] == []
    assert {c["ticket_key"] for c in body["created"]} == {"SEC-1", "SEC-2"}
    assert body["created"][0]["ticket_url"] == "https://bank.atlassian.net/browse/SEC-1"
    assert len(body["created"][0]["asset_key"]) == 40
    second = api("POST", url, json={"asset_ids": [tls, cert], "ticket_type": "jira"}).json()
    assert second["created"] == [] and second["failed"] == []
    assert [(e["asset_id"], e["ticket_key"]) for e in second["existing"]] == [(tls, "SEC-1"), (cert, "SEC-2")]
    tls2, cert2, lib2 = _ids(runs, "run2", TLS, CERT, LIB)
    later = api("POST", f"/1/cbom/sources/runs/{runs['run2']['id']}/tickets",
                json={"asset_ids": [tls2, cert2, lib2]}).json()
    assert [e["ticket_key"] for e in later["existing"]] == ["SEC-1", "SEC-2"]
    assert [c["ticket_key"] for c in later["created"]] == ["SEC-3"]
    assert len(jira.calls) == 3  # one Jira issue per stable key, never one per run
    with Session(runs["engine"]) as s:
        rows = s.exec(select(CbomRemediationAssignment)).all()
        assert sorted(r.ticket_key for r in rows) == ["SEC-1", "SEC-2", "SEC-3"]
        assert len({r.asset_key for r in rows}) == 3


def test_issue_text_comes_from_the_kb_and_the_project_by_key_or_id(api, runs, jira):
    _set_project(api, jira_issue_type="Bug")
    tls, = _ids(runs, "run1", TLS)
    api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [tls]})
    call = jira.calls[0]
    assert call["project_key"] == "SEC" and call["issue_type"] == "Bug"
    assert call["jira_url"] == "https://bank.atlassian.net" and call["jira_email"] == "ops@bank.test"
    assert call["summary"].startswith("[CBOM] High: ") and "10.20.0.1:443" in call["summary"]
    assert len(call["summary"]) <= 255
    desc = call["description"]
    for needle in ("run #", "Impact: High", "Location: 10.20.0.1:443", "Source: src-a", "Codes: ", "PROTO_TLS10",
                   "Fix: ", "Asset key: "):
        assert needle in desc, needle
    assert RT.project_ref("10042") == {"project_id": "10042"}
    assert RT.project_ref("SEC") == {"project_id": "", "project_key": "SEC"}


def test_one_failed_issue_never_loses_the_others(api, runs, jira):
    _set_project(api)
    tls, cert, lib = _ids(runs, "run1", TLS, CERT, LIB)
    jira.fail_on = "openssl"
    r = api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [tls, lib, cert]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [c["asset_id"] for c in body["created"]] == [tls, cert]
    assert [f["asset_id"] for f in body["failed"]] == [lib] and "issuetype" in body["failed"][0]["error"]
    with Session(runs["engine"]) as s:  # the failed asset got no assignment row and no key
        keys = {r.ticket_key for r in s.exec(select(CbomRemediationAssignment)).all()}
    assert keys == {"SEC-1", "SEC-3"}
    jira.fail_on = None
    retry = api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [tls, lib, cert]}).json()
    assert [c["asset_id"] for c in retry["created"]] == [lib] and len(retry["existing"]) == 2


def test_clean_inventory_is_not_ticketed(api, runs, jira):
    _set_project(api)
    clean, tls = _ids(runs, "run1", CLEAN, TLS)
    body = api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [clean, tls]}).json()
    assert [f["asset_id"] for f in body["failed"]] == [clean] and "Not a finding" in body["failed"][0]["error"]
    assert [c["asset_id"] for c in body["created"]] == [tls] and len(jira.calls) == 1


# ------------------------------------------------------------------------------------------- tenancy and input
def test_tenancy_and_assets_of_another_run(api, runs, jira):
    _set_project(api)
    run1 = runs["run1"]["id"]
    tls1, = _ids(runs, "run1", TLS)
    tls2, = _ids(runs, "run2", TLS)
    # another team's run: 404 for its admin; a non-member of team 1: the existing 403
    assert api("POST", f"/2/cbom/sources/runs/{run1}/tickets", "carol", json={"asset_ids": [tls1]}).status_code == 404
    assert api("POST", f"/1/cbom/sources/runs/{run1}/tickets", "carol", json={"asset_ids": [tls1]}).status_code == 403
    assert api("POST", "/1/cbom/sources/runs/999999/tickets", json={"asset_ids": [tls1]}).status_code == 404
    # an asset of run 2 named on run 1: the whole request is refused, nothing is created
    r = api("POST", f"/1/cbom/sources/runs/{run1}/tickets", json={"asset_ids": [tls1, tls2]})
    assert r.status_code == 400 and "not in this run" in r.json()["detail"]
    assert jira.calls == []
    # a team member who is not an admin may create tickets (as on the code page)
    assert api("POST", f"/1/cbom/sources/runs/{run1}/tickets", "bob", json={"asset_ids": [tls1]}).status_code == 200


def test_input_validation(api, runs, jira):
    run1 = runs["run1"]["id"]
    url = f"/1/cbom/sources/runs/{run1}/tickets"
    assert api("POST", url, json={"asset_ids": []}).status_code == 400
    assert api("POST", url, json={"asset_ids": list(range(1, 52))}).status_code == 400
    assert api("POST", url, json={"asset_ids": [1], "ticket_type": "servicenow"}).status_code == 400
    assert api("POST", url, json={"asset_ids": [0]}).status_code == 400
    assert api("POST", url, json={"asset_ids": [1], "extra": 1}).status_code == 400


def test_honest_errors_when_jira_or_the_project_is_missing(api, runs, jira):
    tls, = _ids(runs, "run1", TLS)
    url = f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets"
    r = api("POST", url, json={"asset_ids": [tls]})
    assert r.status_code == 400 and r.json()["detail"] == RT.NO_PROJECT
    _set_project(api)
    with Session(runs["engine"]) as s:
        team = s.get(Team, 1)
        team.integration_settings = {"jira": None}
        s.add(team)
        s.commit()
    r = api("POST", url, json={"asset_ids": [tls]})
    assert r.status_code == 400 and r.json()["detail"] == RT.NOT_CONNECTED
    assert api("GET", "/1/cbom/sources/ticketing").json()["ticketing"]["connected"] is False
    assert jira.calls == []


def test_credentials_never_leave_the_server(api, runs, jira, capsys):
    _set_project(api)
    tls, lib = _ids(runs, "run1", TLS, LIB)
    jira.fail_on = "openssl"
    api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [tls, lib]})
    got = api("GET", "/1/cbom/sources/ticketing")
    out = capsys.readouterr()
    assert all(JIRA_TOKEN not in text for text in api.seen)
    assert JIRA_TOKEN not in out.out + out.err and "ops@bank.test" not in out.out + out.err
    assert "cbom sources run tickets" in out.out and "created=1" in out.out and "failed=1" in out.out
    assert set(got.json()["ticketing"]) == {"connected", "jira_project_key", "jira_issue_type", "issue_type_default",
                                            "is_admin", "row_version"}


def test_run_asset_list_carries_the_ticket(api, runs, jira):
    _set_project(api)
    tls, = _ids(runs, "run1", TLS)
    api("POST", f"/1/cbom/sources/runs/{runs['run1']['id']}/tickets", json={"asset_ids": [tls]})
    for run in ("run1", "run2"):  # the same asset in a later run shows the same ticket
        items = api("GET", f"/1/cbom/sources/runs/{runs[run]['id']}/assets?page_size=200").json()["items"]
        tickets = {(i["type"], i["location"]): (i["ticket_key"], i["ticket_url"]) for i in items}
        assert tickets[TLS] == ("SEC-1", "https://bank.atlassian.net/browse/SEC-1")
        assert tickets[CERT] == (None, None)
    remediation = api("GET", f"/1/cbom/sources/runs/{runs['run1']['id']}/remediation").json()["items"]
    assert next(i for i in remediation if i["asset_id"] == tls)["assignment"]["ticket_key"] == "SEC-1"


def _race(engine, run_id: int, asset_id: int) -> list[dict]:
    """Two requests for one asset at the same time (the fake Jira call takes 0.5 s, so they overlap)."""
    body = RT.TicketBody(asset_ids=[asset_id])
    results: list[dict] = []
    errors: list[BaseException] = []

    def one():
        try:
            results.append(RT.create_tickets(engine, 1, 1, run_id, body))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=one) for _ in range(2)]
    for t in threads:
        t.start()
        time.sleep(0.1)
    for t in threads:
        t.join()
    assert errors == []
    return results


def _plan_first(api, run_id: int, asset_id: int) -> None:
    """Give the asset an assignment (a wave) before any ticket, so the race is on an existing row."""
    items = api("GET", f"/1/cbom/sources/runs/{run_id}/remediation").json()["items"]
    key = next(i["asset_key"] for i in items if i["asset_id"] == asset_id)
    assert api("PUT", "/1/cbom/remediation", json={"run_id": run_id, "items": [{"asset_key": key, "wave": 2}]}) \
        .status_code == 200


@pytest.mark.parametrize("planned", [False, True], ids=["no-assignment-yet", "assignment-exists"])
def test_concurrent_requests_open_one_issue(api, runs, jira, planned):
    _set_project(api)
    tls, = _ids(runs, "run1", TLS)
    if planned:
        _plan_first(api, runs["run1"]["id"], tls)
    jira.delay = 0.5
    results = _race(runs["engine"], runs["run1"]["id"], tls)
    assert sorted((len(r["created"]), len(r["existing"])) for r in results) == [(0, 1), (1, 0)]
    assert len(jira.calls) == 1
    with Session(runs["engine"]) as s:
        assert [r.ticket_key for r in s.exec(select(CbomRemediationAssignment)).all()] == ["SEC-1"]


# ------------------------------------------------------------------------------------------- team setting (admin)
def test_project_setting_is_admin_only_and_versioned(api, runs):
    got = api("GET", "/1/cbom/sources/ticketing", "bob").json()["ticketing"]
    assert got["connected"] is True and got["jira_project_key"] is None and got["is_admin"] is False
    assert got["jira_issue_type"] == "Task"
    r = api("PUT", "/1/cbom/sources/ticketing", "bob", json={"jira_project_key": "SEC"})
    assert r.status_code == 400 and "team admin" in r.json()["detail"]
    r = _set_project(api, jira_issue_type="Story", expected_version=got["row_version"])
    assert r.status_code == 200, r.text
    saved = r.json()["ticketing"]
    assert saved["jira_project_key"] == "SEC" and saved["jira_issue_type"] == "Story"
    assert saved["row_version"] == got["row_version"] + 1
    assert _set_project(api, expected_version=got["row_version"]).status_code == 409  # stale form
    assert api("PUT", "/1/cbom/sources/ticketing", json={"jira_project_key": "10042"}).json()["ticketing"][
        "jira_project_key"] == "10042"
    for bad in ("se c", "1SEC", "S", "x" * 33, "SEC;DROP"):
        assert api("PUT", "/1/cbom/sources/ticketing", json={"jira_project_key": bad}).status_code == 400, bad
    cleared = api("PUT", "/1/cbom/sources/ticketing", json={"jira_project_key": ""}).json()["ticketing"]
    assert cleared["jira_project_key"] is None and cleared["jira_issue_type"] == "Story"  # untouched field kept
    assert api("GET", "/1/cbom/sources/ticketing", "carol").status_code == 403
    assert api("GET", "/2/cbom/sources/ticketing", "carol").json()["ticketing"]["jira_project_key"] is None
    with Session(runs["engine"]) as s:
        assert s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 2)).one().jira_project_key \
            is None


# ------------------------------------------------------------------------------------------- done_at and metrics
def test_done_at_is_set_and_cleared_by_the_remediation_upsert(api, runs):
    run1 = runs["run1"]["id"]
    items = api("GET", f"/1/cbom/sources/runs/{run1}/remediation").json()["items"]
    tls = next(i for i in items if i["type"] == "tls_endpoint" and i["impact"])
    put = lambda **f: api("PUT", "/1/cbom/remediation",  # noqa: E731
                          json={"run_id": run1, "items": [{"asset_key": tls["asset_key"], **f}]})

    def done_at():
        with Session(runs["engine"]) as s:
            return s.exec(select(CbomRemediationAssignment).where(
                CbomRemediationAssignment.asset_key == tls["asset_key"])).one().done_at

    assert put(status="in_progress").status_code == 200 and done_at() is None
    assert put(status="done").status_code == 200
    first = done_at()
    assert first is not None
    assert put(note="verified").status_code == 200 and done_at() == first  # other edits keep it
    assert put(status="done").status_code == 200 and done_at() == first  # re-saving done keeps the first time
    assert put(status="open").status_code == 200 and done_at() is None  # leaving done clears it
    assert put(status="done").status_code == 200 and done_at() is not None
    after = api("GET", f"/1/cbom/sources/runs/{run1}/remediation").json()["items"]
    assert next(i for i in after if i["asset_key"] == tls["asset_key"])["assignment"]["done_at"].endswith("Z")


def test_remediation_metrics_from_assignments():
    import datetime as dt

    now = dt.datetime(2026, 11, 14, 12, 0)
    items = [{"asset_key": "a", "impact": "Critical"}, {"asset_key": "b", "impact": "High"},
             {"asset_key": "c", "impact": "High"}, {"asset_key": "d", "impact": "Medium"},
             {"asset_key": "a", "impact": "Critical"}]  # the same asset twice (two job attempts): counted once
    none = RT.remediation_metrics(items, {}, now)
    assert none["metrics_available"] is False and none["high_priority_backlog"] == 3
    assert none["mean_time_to_remediate"] == [0, 0, 0]
    rows = {
        "a": CbomRemediationAssignment(team_id=1, asset_key="a", status="done", created_at=now - dt.timedelta(days=3),
                                       done_at=now - dt.timedelta(days=1)),
        "b": CbomRemediationAssignment(team_id=1, asset_key="b", status="accepted_risk", created_at=now),
        "d": CbomRemediationAssignment(team_id=1, asset_key="d", status="done",
                                       created_at=now - dt.timedelta(days=20, hours=6),
                                       done_at=now - dt.timedelta(days=10)),
    }
    m = RT.remediation_metrics(items, rows, now)
    assert m["metrics_available"] is True
    assert m["critical_issues_fixed"] == 1 and m["remediation_velocity"] == 1 and m["high_priority_backlog"] == 1
    assert m["mean_time_to_remediate"] == [6, 3, 0]  # (2 d + 10 d 6 h) / 2


def test_run_remediation_metrics_reads_the_run(api, runs):
    run1 = runs["run1"]["id"]
    items = api("GET", f"/1/cbom/sources/runs/{run1}/remediation").json()["items"]
    tls = next(i for i in items if i["type"] == "tls_endpoint" and i["impact"] == "High")
    api("PUT", "/1/cbom/remediation", json={"run_id": run1, "items": [{"asset_key": tls["asset_key"], "status": "done"}]})
    with Session(runs["engine"]) as s:
        from backend.new_models import CbomCollectionRun

        m = RT.run_remediation_metrics(s, 1, s.get(CbomCollectionRun, run1))
    assert m["metrics_available"] is True and m["remediation_velocity"] == 1
    assert W.STATUSES == ("open", "in_progress", "done", "accepted_risk")


# ------------------------------------------------------------------------------------------- migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb38ticket001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _revisions() -> dict[str, object]:
    out = {}
    for path in (ROOT / "prod_database_migrations/migrations/versions").glob("*.py"):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        out[mod.revision] = mod.down_revision
    return out


def test_migration_is_the_single_head():
    mod = _migration()
    assert mod.revision == "cb38ticket001" and mod.down_revision == "r6f14sshca002"
    revs = _revisions()
    parents = {p for d in revs.values() for p in ((d,) if isinstance(d, str) or d is None else d)}
    assert sorted(set(revs) - parents) == ["cb38ticket001"]


def _upgrade_downgrade(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomremediationassignment"))
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectionsettings"))
        conn.execute(sa.text("CREATE TABLE cbomremediationassignment (id integer PRIMARY KEY, team_id integer NOT NULL, "
                             "asset_key varchar(64) NOT NULL, status varchar(16) NOT NULL, "
                             "CONSTRAINT uq_cbomremediation_team_asset UNIQUE (team_id, asset_key))"))
        conn.execute(sa.text("CREATE TABLE cbomcollectionsettings (id integer PRIMARY KEY, team_id integer NOT NULL, "
                             "aws_external_id varchar(40) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO cbomremediationassignment VALUES (1, 1, 'k1', 'done')"))
        conn.execute(sa.text("INSERT INTO cbomcollectionsettings VALUES (1, 1, 'zs-ext')"))

    def columns(table):
        return {c["name"] for c in sa.inspect(engine).get_columns(table)}

    try:
        with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
            _migration().upgrade()
        assert {"ticket_key", "ticket_url", "done_at"} <= columns("cbomremediationassignment")
        assert {"jira_project_key", "jira_issue_type"} <= columns("cbomcollectionsettings")
        with engine.begin() as conn:
            row = conn.execute(sa.text("SELECT asset_key, status, ticket_key, done_at FROM cbomremediationassignment"))
            assert row.one() == ("k1", "done", None, None)  # existing rows kept, new columns empty
            conn.execute(sa.text("UPDATE cbomremediationassignment SET ticket_key = 'SEC-1'"))
            conn.execute(sa.text("UPDATE cbomcollectionsettings SET jira_project_key = 'SEC'"))
        with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
            _migration().downgrade()
        assert columns("cbomremediationassignment") == {"id", "team_id", "asset_key", "status"}
        assert columns("cbomcollectionsettings") == {"id", "team_id", "aws_external_id"}
        with engine.begin() as conn:
            assert conn.execute(sa.text("SELECT asset_key FROM cbomremediationassignment")).scalar() == "k1"
            with pytest.raises(sa.exc.IntegrityError):  # the unique key survived the SQLite table copy
                conn.execute(sa.text("INSERT INTO cbomremediationassignment VALUES (2, 1, 'k1', 'open')"))
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomremediationassignment"))
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectionsettings"))
        engine.dispose()


def test_migration_up_and_down_on_sqlite(tmp_path):
    _upgrade_downgrade(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))


PG = os.environ.get("CBOM_TEST_PG_URL")


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_migration_up_and_down_on_postgresql():
    engine = sa.create_engine(PG)
    with engine.begin() as conn:  # a schema of its own: never touches the tables other tests create
        conn.execute(sa.text("DROP SCHEMA IF EXISTS cb38ticket CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA cb38ticket"))
    try:
        _upgrade_downgrade(sa.create_engine(PG, connect_args={"options": "-csearch_path=cb38ticket"}))
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA IF EXISTS cb38ticket CASCADE"))
        engine.dispose()


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
@pytest.mark.parametrize("planned", [False, True], ids=["no-assignment-yet", "assignment-exists"])
def test_concurrent_requests_open_one_issue_on_postgresql(monkeypatch, jira, planned):
    """The assignment row is write-locked while its issue is created: two overlapping requests on PostgreSQL (READ
    COMMITTED; the second waits on the unique key of a new row, or on the row lock of an existing one) open one
    issue."""
    from fastapi.testclient import TestClient
    from sqlmodel import SQLModel

    from backend.main import app
    from backend.new_models import TeamMembership, User
    from backend.routers import cbom_node, cbom_vendor_public
    from backend.utilities.auth import auth_utils
    from backend.utilities.cbom_sources import http as cbom_http
    from backend.utilities.cbom_sources import node_auth

    admin = sa.create_engine(PG)
    with admin.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA IF EXISTS cb38race CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA cb38race"))
    engine = sa.create_engine(PG, connect_args={"options": "-csearch_path=cb38race"}, pool_size=8)
    try:
        SQLModel.metadata.create_all(engine)
        with Session(engine) as s:
            s.add(Team(id=1, name="Bank One", credit_balance=100.0))
            s.add(Team(id=2, name="Bank Two", credit_balance=0.5))
            s.commit()
            for who, (email, team, role) in USERS.items():
                user = User(email=email, password="x", first_name=who, last_name="t", profile_photo=None,
                            session_active=True, default_team_id=team)
                s.add(user)
                s.commit()
                s.refresh(user)
                s.add(TeamMembership(team_id=team, user_id=user.id, role=role))
            s.commit()
        for module in (cbom_http, cbom_node, cbom_vendor_public, node_auth):
            monkeypatch.setattr(module, "get_db", lambda: engine)
        for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter):
            limiter.requests.clear()
        client = TestClient(app)
        token = auth_utils.create_access_token(USERS["alice"][0])

        def call(method, url, who="alice", **kwargs):
            headers = dict(kwargs.pop("headers", {}) or {})
            if who:
                headers["Authorization"] = f"Bearer {token}"
            return client.request(method, url, headers=headers, **kwargs)

        world_runs = _make_runs(call, engine)
        assert _set_project(call).status_code == 200
        tls, = _ids(world_runs, "run1", TLS)
        if planned:
            _plan_first(call, world_runs["run1"]["id"], tls)
        jira.delay = 0.5
        results = _race(engine, world_runs["run1"]["id"], tls)
        assert sorted((len(r["created"]), len(r["existing"])) for r in results) == [(0, 1), (1, 0)]
        assert len(jira.calls) == 1
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(sa.text("DROP SCHEMA IF EXISTS cb38race CASCADE"))
        admin.dispose()
