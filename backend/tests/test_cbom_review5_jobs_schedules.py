"""Round-5 review fixes, group C2: job claiming, schedules, source versions, optimistic locking and credits.

Every test here failed before its fix (the reviewers' repros, made deterministic: a frozen clock for schedules and an
interleaving hook instead of real concurrency).  Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import PASSWORD, _collect_job, api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
    Team,
)
from backend.routers import cbom_ops, cbom_sources  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.cbom_sources import azure_collect  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import posture as POSTURE  # noqa: E402
from backend.utilities.cbom_sources import schedules as S  # noqa: E402
from backend.utilities.cbom_sources.kinds import METADATA_FIELDS  # noqa: E402
from backend.utilities.cbom_sources.schemas import SettingsUpdate, SourceUpdate  # noqa: E402

ITEMS = "/1/cbom/sources/items"
ROLE = "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"
TENANT, CLIENT, SUB = ("11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000",
                       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
PASSED = {"status": "passed", "checks": [{"check": "Role assumed with external ID", "status": "pass", "detail": "ok"}]}


def _strip(engine, source_id: int, keys) -> None:
    """Make a stored row look like one saved before those config fields existed (no key in the JSON at all)."""
    with Session(engine) as s:
        row = s.get(CbomCollectionSource, source_id)
        row.config = {k: v for k, v in row.config.items() if k not in set(keys)}
        s.add(row)
        s.commit()


# ------------------------------------------------------------------------- 1. connection version of older rows
def test_metadata_edit_of_a_source_saved_before_round5_keeps_its_jobs_and_test(api, world, monkeypatch):
    """rev3 #2: the connection version hashed the stored JSON, and a metadata save rewrites it with the defaults of
    fields added since (AWS decrypt_lambda_cmk / read_glue ...), so the edit cancelled queued jobs and reset the test."""
    engine, _ = world
    monkeypatch.setattr(cbom_sources, "validate_aws_role", lambda *a, **_k: PASSED)
    aws = api("POST", ITEMS, json={"kind": "aws_account", "name": "payments-prod",
                                   "config": {"role_arn": ROLE, "regions": ["ap-south-1"]}}).json()["source"]
    _strip(engine, aws["id"], ("decrypt_lambda_cmk", "read_glue", *METADATA_FIELDS))
    assert api("POST", f"{ITEMS}/{aws['id']}/test").json()["status"] == "passed"
    node_id, token, _ = enroll_node(api)
    srv = api("POST", ITEMS, json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any")).json()["source"]
    _strip(engine, srv["id"], ("timeout_s", "parallel", "tier", *METADATA_FIELDS))
    ratelimit.reset_all()
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True, "servers": True},
                                                    "client_request_id": "legacy-rows-0001"})
    assert run.status_code == 201, run.text
    for src in (aws, srv):
        cur = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
        # exactly what the Review & Run criticality card sends: {...source.config, business_criticality}
        r = api("PATCH", f"{ITEMS}/{src['id']}", json={"config": {**cur["config"], "business_criticality": "high"},
                                                        "expected_version": cur["row_version"]})
        assert r.status_code == 200, r.text
        assert r.json()["source"]["last_test_status"] == cur["last_test_status"]
        assert r.json()["source"]["config"]["business_criticality"] == "high"
    with Session(engine) as s:
        jobs = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "collect")
                      .order_by(CbomCollectionJob.id)).all()
        assert [(j.status, j.error) for j in jobs] == [("pending", None), ("pending", None)]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert not any("Validate the AWS role" in (i["reason"] or "") for i in est["skipped"]), est["skipped"]
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token})
    assert claim.status_code == 200 and claim.json()["source"]["id"] == srv["id"]  # still valid at claim
    # a real connection change still counts
    cur = api("GET", f"{ITEMS}/{aws['id']}").json()["source"]
    moved = api("PATCH", f"{ITEMS}/{aws['id']}", json={"config": {**cur["config"], "regions": ["us-east-1"]},
                                                       "expected_version": cur["row_version"]}).json()["source"]
    assert moved["last_test_status"] == "never"


# ------------------------------------------------------------------------- 2. claim never blocked by waiting jobs
def test_jobs_that_cannot_run_now_never_hide_one_that_can(api, world, monkeypatch):
    """rev3 #3: claim_next looked at the 25 oldest pending jobs only; 25 jobs outside their window hid a connection
    test (which ignores the window) while the UI said "Waiting for the scan node to pick it up"."""
    engine, _ = world
    monkeypatch.setattr(J, "CLAIM_PAGE", 10, raising=False)  # several pages
    node_id, token, _ = enroll_node(api)
    hour = dt.datetime.utcnow().hour
    closed_now = [[h == (hour + 12) % 24 for h in range(24)] for _ in range(7)]
    for i in range(25):
        ratelimit.reset_all()
        r = api("POST", ITEMS, json=linux_body(name=f"night-{i}", node_id=node_id, targets=[f"10.20.0.{i + 1}"],
                                               window="custom", custom_window=closed_now))
        assert r.status_code == 201, r.text
    ratelimit.reset_all()
    assert api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                     "client_request_id": "night-run-0001"}).status_code == 201
    ratelimit.reset_all()
    day = api("POST", ITEMS, json=linux_body(name="any-time", node_id=node_id, targets=["10.30.0.1"],
                                             window="any")).json()["source"]
    ratelimit.reset_all()
    test = api("POST", f"{ITEMS}/{day['id']}/test").json()
    assert test["job"]["waiting_reason"] == "Waiting for the scan node to pick it up"
    ratelimit.reset_all()
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token})
    assert claim.status_code == 200, "the connection test was never offered to the node"
    assert claim.json()["job"]["id"] == test["job"]["id"]
    with Session(engine) as s:  # the night jobs wait for their window; none was cancelled or claimed
        statuses = s.exec(select(CbomCollectionJob.status).where(CbomCollectionJob.kind == "collect")).all()
        assert statuses == ["pending"] * 25


# ------------------------------------------------------------------------- 3-4. schedules
class _Clock:
    def __init__(self, now: dt.datetime) -> None:
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now


def _frozen(monkeypatch, start: dt.datetime) -> _Clock:
    clock = _Clock(start)
    for module in (cbom_sources, cbom_ops):
        monkeypatch.setattr(module, "utcnow", clock)
    return clock


def _schedule_world(api, world, monkeypatch, start: dt.datetime, tz: str):
    engine, _ = world
    clock = _frozen(monkeypatch, start)
    node_id, _token, _ = enroll_node(api)
    assert api("POST", ITEMS, json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any")).status_code == 201
    _set_zone(api, tz)
    return engine, clock


def _set_zone(api, tz: str) -> None:
    cur = api("GET", "/1/cbom/sources/settings").json()["settings"]
    r = api("PATCH", "/1/cbom/sources/settings", json={"window_timezone": tz, "expected_version": cur["row_version"]})
    assert r.status_code == 200, r.text


def _finish_all_jobs(engine) -> None:
    with Session(engine) as s:  # the run finished before the next slot (else plan_run skips "already queued")
        for j in s.exec(select(CbomCollectionJob)).all():
            j.status = "success"
            s.add(j)
        s.commit()


def _runs(engine, schedule_id: int) -> list[str]:
    with Session(engine) as s:
        return [r.client_request_id for r in s.exec(select(CbomCollectionRun).where(
            CbomCollectionRun.schedule_id == schedule_id).order_by(CbomCollectionRun.id)).all()]


def test_a_time_zone_change_moves_next_runs_to_the_new_zone(api, world, monkeypatch):
    """rev5 #4: a daily 09:00 schedule kept its UTC next run after the team moved to Asia/Kolkata, so it fired at
    14:30 IST."""
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 5, 0), "UTC")
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "09:00", "include": {"servers": True}}).json()["schedule"]
    assert sched["next_run_at"] == "2026-12-01T09:00:00Z"
    _set_zone(api, "Asia/Kolkata")  # 10:30 IST: today's 09:00 IST has passed
    listed = api("GET", "/1/cbom/sources/schedules").json()
    assert listed["timezone"] == "Asia/Kolkata" and listed["schedules"][0]["next_run_at"] == "2026-12-02T03:30:00Z"
    assert listed["schedules"][0]["row_version"] == sched["row_version"] + 1
    assert S.fire_due(engine, dt.datetime(2026, 12, 1, 9, 0, 30)) == []
    fired = S.fire_due(engine, dt.datetime(2026, 12, 2, 3, 30, 30))
    assert [(f["slot"], f["status"]) for f in fired] == [("2026-12-02T09:00", "queued")]


def test_a_slot_due_when_the_zone_changes_still_runs_once(api, world, monkeypatch):
    """The 09:00 UTC slot is due (the scheduler has not ticked) when the team moves to Asia/Kolkata: today's run is
    not dropped; it runs once, as today's 09:00 IST slot, and the next one is tomorrow's."""
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 5, 0), "UTC")
    api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "09:00", "include": {"servers": True}})
    clock.now = dt.datetime(2026, 12, 1, 9, 10)
    _set_zone(api, "Asia/Kolkata")
    assert api("GET", "/1/cbom/sources/schedules").json()["schedules"][0]["next_run_at"] == "2026-12-01T03:30:00Z"
    fired = S.fire_due(engine, dt.datetime(2026, 12, 1, 9, 10, 30))
    assert [(f["slot"], f["next_run_at"]) for f in fired] == [("2026-12-01T09:00", "2026-12-02T03:30:00Z")]


def test_a_time_zone_change_never_runs_a_local_slot_twice(api, world, monkeypatch):
    """rev3 #4: Asia/Kolkata -> UTC after the 09:00 IST run fired a stale 03:30 UTC slot and then 09:00 UTC: two
    charged runs in one day."""
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 1, 0), "Asia/Kolkata")
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "09:00", "include": {"servers": True}}).json()["schedule"]
    assert sched["next_run_at"] == "2026-12-01T03:30:00Z"
    assert [f["slot"] for f in S.fire_due(engine, dt.datetime(2026, 12, 1, 3, 30, 30))] == ["2026-12-01T09:00"]
    _finish_all_jobs(engine)
    clock.now = dt.datetime(2026, 12, 1, 5, 0)
    _set_zone(api, "UTC")  # today's 09:00 has already run (in IST): the next run is tomorrow's
    assert api("GET", "/1/cbom/sources/schedules").json()["schedules"][0]["next_run_at"] == "2026-12-02T09:00:00Z"
    for moment in (dt.datetime(2026, 12, 1, 9, 0, 30), dt.datetime(2026, 12, 2, 3, 30, 30)):
        assert S.fire_due(engine, moment) == []
    assert [f["slot"] for f in S.fire_due(engine, dt.datetime(2026, 12, 2, 9, 0, 30))] == ["2026-12-02T09:00"]
    assert _runs(engine, sched["id"]) == [f"sched-{sched['id']}-20261201T0900", f"sched-{sched['id']}-20261202T0900"]


def test_a_due_slot_that_already_ran_is_skipped_not_stuck(api, world, monkeypatch):
    """The schedule itself refuses a local slot it already ran (next_run_at written in another zone, e.g. by a
    scheduler racing the zone change on SQLite); before, the unique run id made it a "replay" that rolled back the
    advance, so the slot stayed due and was retried every tick for ever."""
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 1, 0), "Asia/Kolkata")
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "09:00", "include": {"servers": True}}).json()["schedule"]
    assert len(S.fire_due(engine, dt.datetime(2026, 12, 1, 3, 30, 30))) == 1
    _finish_all_jobs(engine)
    with Session(engine) as s:  # the zone changes without moving this schedule's next run
        settings = s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).one()
        settings.window_timezone = "UTC"
        row = s.get(CbomCollectionSchedule, sched["id"])
        row.next_run_at = dt.datetime(2026, 12, 1, 9, 0)  # local "2026-12-01T09:00" again, in UTC
        s.add(settings)
        s.add(row)
        s.commit()
    assert S.fire_due(engine, dt.datetime(2026, 12, 1, 9, 0, 30)) == []
    with Session(engine) as s:
        assert s.get(CbomCollectionSchedule, sched["id"]).next_run_at == dt.datetime(2026, 12, 2, 9, 0)
    assert _runs(engine, sched["id"]) == [f"sched-{sched['id']}-20261201T0900"]


def test_editing_a_schedule_keeps_a_due_slot_unless_its_timing_changes(api, world, monkeypatch):
    """rev3 #5: a rename while the 02:00 slot was due set next_run_at to tomorrow: no run and no skipped record."""
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 1, 0), "UTC")
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}).json()["schedule"]
    clock.now = dt.datetime(2026, 12, 1, 2, 0, 20)  # due; the scheduler has not ticked yet
    renamed = api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", json={
        "name": "nightly-renamed", "include": {"servers": True}, "expected_version": sched["row_version"]})
    assert renamed.status_code == 200 and renamed.json()["schedule"]["next_run_at"] == "2026-12-01T02:00:00Z"
    fired = S.fire_due(engine, dt.datetime(2026, 12, 1, 2, 0, 30))
    assert [(f["slot"], f["status"]) for f in fired] == [("2026-12-01T02:00", "queued")]
    # a change of WHEN it runs moves the next run (the user chose the new time)
    clock.now = dt.datetime(2026, 12, 1, 2, 30)
    cur = api("GET", "/1/cbom/sources/schedules").json()["schedules"][0]
    moved = api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", json={
        "time_of_day": "03:00", "expected_version": cur["row_version"]}).json()["schedule"]
    assert moved["next_run_at"] == "2026-12-01T03:00:00Z"
    paused = api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", json={
        "enabled": False, "expected_version": moved["row_version"]}).json()["schedule"]
    assert paused["next_run_at"] is None


# ------------------------------------------------------------------------- 5. compare-and-set versions
def _race(monkeypatch, module, competitor) -> None:
    """Run ``competitor`` (a whole edit, committed) right after this request passed its version check: what READ
    COMMITTED allows two concurrent PATCHes with the same expected_version to do."""
    real = module.check_version
    state = {"raced": False}

    def check_then_race(row, expected):
        real(row, expected)
        if not state["raced"]:
            state["raced"] = True
            competitor()

    monkeypatch.setattr(module, "check_version", check_then_race)


def test_two_edits_from_the_same_version_cannot_both_be_saved(api, world, monkeypatch):
    """rev3 #7: check_version then ``row_version += 1`` let both PATCHes succeed; the second silently overwrote."""
    engine, ids = world
    alice = ids["alice"]
    node_id, _token, _ = enroll_node(api)
    src = api("POST", ITEMS, json=linux_body(node_id=node_id)).json()["source"]
    v = src["row_version"]
    _race(monkeypatch, cbom_sources, lambda: cbom_sources._update_source(
        engine, 1, alice, src["id"], SourceUpdate(name="renamed-by-bob", expected_version=v)))
    with pytest.raises(HTTPException) as exc:
        cbom_sources._update_source(engine, 1, alice, src["id"], SourceUpdate(name="renamed-by-alice", expected_version=v))
    assert exc.value.status_code == 409
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["name"] == "renamed-by-bob" and got["row_version"] == v + 1
    # the compare-and-set runs after the flush, so a duplicate name is still the readable 409
    assert api("POST", ITEMS, json=linux_body(name="other", node_id=node_id)).status_code == 201
    dup = api("PATCH", f"{ITEMS}/{src['id']}", json={"name": "OTHER", "expected_version": v + 1})
    assert dup.status_code == 409 and "already exists" in dup.json()["detail"]

    sv = api("GET", "/1/cbom/sources/settings").json()["settings"]["row_version"]
    _race(monkeypatch, cbom_sources, lambda: cbom_sources._update_settings(
        engine, 1, alice, SettingsUpdate(cert_domains=["pay.bank.example"], expected_version=sv)))
    with pytest.raises(HTTPException) as exc:
        cbom_sources._update_settings(engine, 1, alice, SettingsUpdate(zeek_span=True, expected_version=sv))
    assert exc.value.status_code == 409
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert settings["cert_domains"] == ["pay.bank.example"] and settings["zeek_span"] is False

    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}).json()["schedule"]
    sv = sched["row_version"]
    _race(monkeypatch, cbom_ops, lambda: cbom_ops._update_schedule(
        engine, 1, alice, sched["id"], cbom_ops.ScheduleUpdate(name="by-bob", expected_version=sv)))
    with pytest.raises(HTTPException) as exc:
        cbom_ops._update_schedule(engine, 1, alice, sched["id"], cbom_ops.ScheduleUpdate(name="by-alice", expected_version=sv))
    assert exc.value.status_code == 409
    assert api("GET", "/1/cbom/sources/schedules").json()["schedules"][0]["name"] == "by-bob"


def test_an_old_connection_test_result_never_overwrites_a_reset(api, world, monkeypatch):
    """rev3 #7: a node's test result read the source, an edit changed the connection (reset the test) and committed,
    then the result was written over the reset: "passed" for targets that were never tested."""
    engine, ids = world
    node_id, token, _ = enroll_node(api)
    src = api("POST", ITEMS, json=linux_body(node_id=node_id, targets=["10.20.0.1"])).json()["source"]
    job_id = api("POST", f"{ITEMS}/{src['id']}/test").json()["job"]["id"]
    lease = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()["job"]["lease_id"]
    real = J._stop_reason
    state = {"raced": False}

    def edit_then_check(session, job, source, node):
        if not state["raced"]:
            state["raced"] = True
            cbom_sources._update_source(engine, 1, ids["alice"], src["id"], SourceUpdate(
                config={**src["config"], "targets": ["10.20.0.9"]}, secrets={"password": PASSWORD}))
        return real(session, job, source, node)

    monkeypatch.setattr(J, "_stop_reason", edit_then_check)
    with Session(engine) as s:
        J.finish_job(s, s.get(CbomScanNode, node_id), job_id, lease, "success",
                     {"samples": [{"target": "10.20.0.1", "status": "ready"}]}, None, dt.datetime.utcnow())
        s.commit()
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["config"]["targets"] == ["10.20.0.9"]
    assert got["last_test_status"] == "never" and got["last_test_job_id"] is None


# ------------------------------------------------------------------------- 6. live cloud tests
def test_a_cloud_test_survives_a_metadata_save_but_not_a_connection_change(api, world, monkeypatch):
    """rev3 #8: the Azure / Google Cloud test compared row_version, so a criticality save during the test dropped
    its result (AWS and IdP already compared the connection version)."""
    engine, ids = world
    src = api("POST", ITEMS, json={"kind": "azure_subscription", "name": "azure-prod", "config": {
        "tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": [SUB]}, "secrets": {"client_secret": "s3cr3t-value"}})
    assert src.status_code == 201, src.text
    src = src.json()["source"]
    during = [
        SourceUpdate(config={**src["config"], "business_criticality": "high"}),
        SourceUpdate(config={**src["config"], "client_id": "99999999-7777-8888-9999-000000000000"},
                     secrets={"client_secret": "another-secret"}),
    ]

    def fake_test(cfg, secrets):
        cbom_sources._update_source(engine, 1, ids["alice"], src["id"], during.pop(0))  # saved while the test runs
        return {"status": "passed", "message": "ok", "checks": [{"check": "Signed in", "status": "pass", "detail": "ok"}]}

    monkeypatch.setattr(azure_collect, "test_azure", fake_test)
    assert api("POST", f"{ITEMS}/{src['id']}/test").json()["status"] == "passed"
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["last_test_status"] == "passed" and got["config"]["business_criticality"] == "high"
    assert api("POST", f"{ITEMS}/{src['id']}/test").json()["status"] == "passed"  # the old account answered...
    assert api("GET", f"{ITEMS}/{src['id']}").json()["source"]["last_test_status"] == "never"  # ...not the new one


# ------------------------------------------------------------------------- 8-9. credits
def test_two_jobs_of_a_run_refunded_at_the_same_time_both_count(api, world):
    """rev2 L4: ``run.credits_refunded_c += amount`` was an ORM read-modify-write; the second refund overwrote the
    first, so the run said less was refunded than the team got back.  F1.1 (DA C2): a job end only marks its refund
    due on its own row; ``settle_refunds`` moves the money once per run, exactly once per job."""
    engine, _ = world
    node_id, _token, _ = enroll_node(api)
    for name, target in (("a", "10.20.0.1"), ("b", "10.20.0.2")):
        assert api("POST", ITEMS, json=linux_body(name=name, node_id=node_id, targets=[target],
                                                  window="any")).status_code == 201
    run_id = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                       "client_request_id": "two-refunds-0001"}).json()["run"]["id"]
    with Session(engine) as one, Session(engine) as two:
        jobs_one = one.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id).order_by(CbomCollectionJob.id)).all()
        jobs_two = two.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id).order_by(CbomCollectionJob.id)).all()
        assert J.refund_job(one, jobs_one[0]) == 20  # marked due, nothing paid yet
        one.commit()
        assert J.refund_job(two, jobs_two[1]) == 20
        two.commit()
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).credits_refunded_c == 0
        assert J.settle_refunds(s) == {"runs": 1, "jobs": 2, "centi": 40}
        s.commit()
        assert J.settle_refunds(s)["jobs"] == 0  # a second settlement pays nothing
        s.commit()
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).credits_refunded_c == 40
        assert s.get(Team, 1).credit_balance == pytest.approx(100.0)
        # a refund the run has already had in full is refused, never paid twice
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).first()
        job.refunded = False
        s.add(job)
        s.commit()
        assert J.settle_refunds(s, [run_id])["centi"] == 0
        s.commit()
        assert s.get(CbomCollectionRun, run_id).credits_refunded_c == 40
        assert s.get(Team, 1).credit_balance == pytest.approx(100.0)


def test_a_charge_of_exactly_the_balance_passes(world):
    """rev5 #12: the float balance 1.0 - 0.01 - 0.06 is 0.92999..., and a 0.93 charge was refused."""
    engine, _ = world
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = 1.0
        s.add(team)
        s.commit()
        assert J.charge_team(s, 1, 1) and J.charge_team(s, 1, 6)
        s.commit()
        s.refresh(team)
        assert team.credit_balance < 0.93  # what float arithmetic leaves
        assert J.charge_team(s, 1, 93)
        s.commit()
        s.refresh(team)
        assert team.credit_balance == 0.0  # not -0.0000000001
        assert not J.charge_team(s, 1, 1)


# ------------------------------------------------------------------------- 10. attempts (not a bug: evidence)
def test_a_requeued_job_only_ever_has_its_current_attempts_assets(api, world):
    """rev4 L2 claimed posture / CycloneDX show assets of an older attempt between a lease-expiry requeue and the next
    claim.  They cannot: a requeue keeps ``attempts`` (the stored assets ARE the current attempt's, so the attempt
    filter drift and OSCAL use selects the same rows) and the next claim deletes them in its own transaction."""
    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    job_id, lease = claim["job"]["id"], claim["job"]["lease_id"]
    batch = [{"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443", "facts": {"protocols": ["TLSv1.0"]}}]
    assert api("POST", f"/cbom/node/jobs/{job_id}/assets", None, headers=hdr,
               json={"lease_id": lease, "assets": batch}).json()["accepted"] == 1
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.lease_expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
        s.add(job)
        s.commit()
    assert api("GET", f"/1/cbom/sources/jobs/{job_id}").json()["job"]["status"] == "pending"  # the reaper requeued it

    def counts() -> tuple[int, int, int]:
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, job_id)
            rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job_id)).all()
            current = [r for r in rows if r.attempt == job.attempts]
            shown = POSTURE.run_posture(s, team_id=1, run_id=run["id"], risk_model=None)["assets"]
            return len(rows), len(current), shown

    assert counts() == (1, 1, 1)  # requeued: every stored row is the current attempt's
    assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 200
    assert counts() == (0, 0, 0)  # reclaimed: attempt 1's rows went with the claim
