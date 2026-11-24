"""FIX-B3: a run never stays "running" because a scan node went away, and a run says why it is partial.

Staging evidence (audit-B B-12, audit-A A-19): team 1 run #50 was ``running`` for 5 days because 4 jobs were pinned
to host-agent nodes that were offline (``waiting_reason`` "Scan node cbom-lab-2-worker is offline"); while it stayed
open, run #51 skipped 20 sources "Already queued in run #50".  Run #52 was ``partial`` with 19/19 jobs ``success``
(the Google Cloud job read its project with gaps) and nothing said so.

Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backend.new_models import (
    CbomCollectionAuditEvent,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomOpsCounter,
    CbomScanNode,
    Team,
)
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import limits as L
from backend.utilities.cbom_sources.run_status import status_reason
from backend.workers.cbom_cloud_worker import targets_summary
from test_cbom_sources_api import (  # noqa: F401
    _collect_job,
    api,
    enroll_node,
    linux_body,
    world,
)

HOURS_6 = dt.timedelta(hours=6)
_REAL_NOTE = J.note_reaper_pass
LONG_AGO = dt.datetime(2000, 1, 1)


@pytest.fixture(autouse=True)
def _backend_served_all_along(monkeypatch):
    """These tests move the node's and the job's clocks, not the reaper's: the backend served throughout.  The
    restart tests (review 6028153035 M1) put the real bookkeeping back."""
    monkeypatch.setattr(J, "note_reaper_pass", lambda _session, _now: LONG_AGO)
    monkeypatch.setattr(J, "_SERVING_SINCE", [None])


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def _queue_run(api, engine, rid="fixb3-run-000001", *, node_name="cbom-lab-2-worker"):  # noqa: F811
    """A server source pinned to an enrolled node, and a run whose one job waits for that node."""
    node_id, token, _ = enroll_node(api, name=node_name)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, window="any")).json()["source"]
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": rid})
    assert run.status_code == 201, run.text
    run = run.json()["run"]
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run["id"])).one()
    return node_id, token, src, run, job.id


def _age(engine, job_id: int, node_id: int, *, queued_ago: dt.timedelta, seen_ago: dt.timedelta | None) -> dt.datetime:
    """Move the job's queueing and the node's last heartbeat into the past (the reaper on read paths uses the clock)."""
    now = _now()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.created_at = now - queued_ago
        s.add(job)
        node = s.get(CbomScanNode, node_id)
        node.last_heartbeat_at = None if seen_ago is None else now - seen_ago
        s.add(node)
        s.commit()
        return node.last_heartbeat_at


def _job(engine, job_id: int) -> CbomCollectionJob:
    with Session(engine) as s:
        return s.get(CbomCollectionJob, job_id)


def _run_row(engine, run_id: int) -> CbomCollectionRun:
    with Session(engine) as s:
        return s.get(CbomCollectionRun, run_id)


def _balance(engine) -> float:
    with Session(engine) as s:
        return round(s.get(Team, 1).credit_balance, 2)


# ----------------------------------------------------------------------------- settings
def test_deadlines_have_sane_defaults_and_are_configurable(monkeypatch):
    monkeypatch.delenv("CBOM_JOB_NODE_OFFLINE_S", raising=False)
    monkeypatch.delenv("CBOM_JOB_QUEUE_TTL_S", raising=False)
    assert J.node_offline_deadline() == HOURS_6
    assert J.collect_job_ttl() == dt.timedelta(days=7)
    monkeypatch.setenv("CBOM_JOB_NODE_OFFLINE_S", "7200")
    monkeypatch.setenv("CBOM_JOB_QUEUE_TTL_S", "86400")
    assert J.node_offline_deadline() == dt.timedelta(hours=2)
    assert J.collect_job_ttl() == dt.timedelta(days=1)
    monkeypatch.setenv("CBOM_JOB_NODE_OFFLINE_S", "five hours")  # not a number: the default, logged once
    monkeypatch.setenv("CBOM_JOB_QUEUE_TTL_S", "10")  # below the range: the default
    assert J.node_offline_deadline() == HOURS_6 and J.collect_job_ttl() == dt.timedelta(days=7)
    monkeypatch.setenv("CBOM_JOB_NODE_OFFLINE_S", "600")  # never shorter than the lease (the lease rule goes first)
    assert J.node_offline_deadline() == dt.timedelta(seconds=L.lease_seconds()) >= dt.timedelta(seconds=600)


# ----------------------------------------------------------------------------- the run #50 / #51 case
def test_already_queued_block_ends_when_the_offline_nodes_job_expires(api, world):  # noqa: F811
    """Exactly staging: run A's job waits for an offline node, run B is refused "already queued"; once the node has
    been offline past the deadline the job expires with "node X offline since ...", is refunded, run A finishes
    (failed: its only job expired) and run B queues the source."""
    engine, _ = world
    node_id, _token, src, run_a, job_id = _queue_run(api, engine)
    charged = _balance(engine)
    seen = _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=2), seen_ago=dt.timedelta(hours=2))

    # while inside the deadline: the job waits, says when it expires, and still blocks a second run
    detail = api("GET", f"/1/cbom/sources/runs/{run_a['id']}").json()["run"]
    wait = detail["jobs"][0]["waiting_reason"]
    assert wait.startswith("Scan node cbom-lab-2-worker is offline since ") and "the job expires at" in wait
    assert detail["status"] == "queued" and "wait for an offline scan node" in detail["status_reason"]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in est["skipped"] if i["source_id"] == src["id"])
    assert item["reason"].startswith(f"Already queued in run #{run_a['id']} (Scan node cbom-lab-2-worker is offline")
    blocked = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "fixb3-run-000002"})
    assert blocked.status_code == 409 and "already queued" in blocked.json()["detail"].lower()
    assert _job(engine, job_id).status == "pending"

    # past the deadline (6 h since the last heartbeat): the next read path's reaper expires it
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=6, minutes=1))
    with Session(engine) as s:
        seen = s.get(CbomScanNode, node_id).last_heartbeat_at
    listed = api("GET", "/1/cbom/sources/runs").json()["runs"]
    job = _job(engine, job_id)
    assert job.status == "expired" and job.finished_at is not None
    assert job.error == (f"Scan node cbom-lab-2-worker offline since {seen.strftime('%Y-%m-%d %H:%M UTC')}; "
                         "the job expired after 6 h without it")
    assert job.refunded is True and _balance(engine) > charged
    run = _run_row(engine, run_a["id"])
    assert run.status == "failed" and run.finished_at is not None
    assert listed  # the list's reaper pass expired the job
    row = next(r for r in api("GET", "/1/cbom/sources/runs").json()["runs"] if r["id"] == run_a["id"])
    assert row["status"] == "failed" and "offline since" in row["status_reason"]
    detail = api("GET", f"/1/cbom/sources/runs/{run_a['id']}").json()["run"]
    assert detail["status"] == "failed" and "offline since" in detail["status_reason"]
    assert detail["status_reason_jobs"][0]["category"] == "expired"
    with Session(engine) as s:
        audit = s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.object_type == "job",
                                                              CbomCollectionAuditEvent.object_id == job_id,
                                                              CbomCollectionAuditEvent.action == "job.expired")).one()
        assert audit.changed_fields == ["node_offline"]

    # the source is no longer blocked
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    assert any(i["source_id"] == src["id"] and i["status"] == "queued" for i in est["items"])
    again = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "fixb3-run-000003"})
    assert again.status_code == 201, again.text


def test_the_deadline_boundary_is_exact(api, world):  # noqa: F811
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine)
    base = _now()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.created_at = base - dt.timedelta(days=1)
        node = s.get(CbomScanNode, node_id)
        node.last_heartbeat_at = base
        s.add(job)
        s.add(node)
        s.commit()
    with Session(engine) as s:
        assert J.reap(s, base + HOURS_6 - dt.timedelta(seconds=1)) == 0
        s.commit()
    assert _job(engine, job_id).status == "pending"
    with Session(engine) as s:
        assert J.reap(s, base + HOURS_6 + dt.timedelta(seconds=1)) >= 1  # the job, then the run reconcile
        s.commit()
    assert _job(engine, job_id).status == "expired"


def test_a_node_that_was_already_down_still_gives_a_new_job_the_full_window(api, world):  # noqa: F811
    """Offline counts from the later of the last heartbeat and the queueing: a job queued for a node that went down a
    week ago is not expired the moment the reaper sees it."""
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine)
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(minutes=5), seen_ago=dt.timedelta(days=7))
    with Session(engine) as s:
        assert J.reap(s, _now()) == 0
        s.commit()
        assert J.reap(s, _now() + HOURS_6) >= 1  # the job, then the run reconcile
        s.commit()
    assert _job(engine, job_id).status == "expired"


def test_a_node_that_never_connected_says_so(api, world):  # noqa: F811
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine)
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=None)
    with Session(engine) as s:
        assert J.reap(s, _now()) >= 1  # the job, then the run reconcile
        s.commit()
    error = _job(engine, job_id).error
    assert error.startswith("Scan node cbom-lab-2-worker has not connected since the job was queued (")
    assert error.endswith("the job expired after 6 h")


def test_an_online_node_never_has_its_waiting_job_expired_by_the_offline_rule(api, world):  # noqa: F811
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine)
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(days=3), seen_ago=dt.timedelta(seconds=10))
    with Session(engine) as s:
        assert J.reap(s, _now()) == 0
        s.commit()
    assert _job(engine, job_id).status == "pending"


def test_the_queue_ttl_is_configurable_and_names_itself(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    monkeypatch.setenv("CBOM_JOB_QUEUE_TTL_S", "86400")
    node_id, _t, _src, run, job_id = _queue_run(api, engine)
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(days=1, minutes=1), seen_ago=dt.timedelta(seconds=10))
    with Session(engine) as s:  # the node is online (outside its window, say): only the queue TTL applies
        assert J.reap(s, _now()) >= 1  # the job, then the run reconcile
        s.commit()
    job = _job(engine, job_id)
    assert (job.status, job.error) == ("expired", "No scan node picked this job up within 1 d of queueing")
    assert job.refunded is True and _run_row(engine, run["id"]).status == "failed"


def test_a_claimed_job_of_a_node_that_disappears_is_requeued_then_expired_and_refunded(api, world):  # noqa: F811
    engine, _ = world
    _src, run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    job = _job(engine, job_id)
    with Session(engine) as s:
        node = s.get(CbomScanNode, job.node_id)
        node.last_heartbeat_at = job.claimed_at
        s.add(node)
        s.commit()
    with Session(engine) as s:  # the lease goes first: the job goes back to the queue (a returning node may retry)
        J.reap(s, job.lease_expires_at + dt.timedelta(seconds=1))
        s.commit()
    assert _job(engine, job_id).status == "pending"
    with Session(engine) as s:
        assert J.reap(s, job.claimed_at + HOURS_6 + dt.timedelta(seconds=1)) >= 1  # the job, then the run reconcile
        s.commit()
    after = _job(engine, job_id)
    assert after.status == "expired" and "offline since" in after.error and after.refunded is True
    assert _run_row(engine, run["id"]).status == "failed"


def test_a_claimed_job_past_the_deadline_with_no_lease_rule_left_is_expired_guarded_on_its_lease(api, world):  # noqa: F811
    engine, _ = world
    _src, _run, claim, _hdr = _collect_job(api, engine)
    job_id = claim["job"]["id"]
    base = _now()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.lease_expires_at = base + dt.timedelta(days=2)  # a long lease: only the offline rule can end it
        job.created_at = base - dt.timedelta(hours=2)
        job.claimed_at = base - dt.timedelta(hours=1)
        node = s.get(CbomScanNode, job.node_id)
        node.last_heartbeat_at = base - dt.timedelta(hours=1)
        s.add(job)
        s.add(node)
        s.commit()
    with Session(engine) as s:
        stale = s.get(CbomCollectionJob, job_id)
        s.expunge(stale)
        stale.lease_id = "not-the-lease"  # a racing claim or result changed the lease: the guarded UPDATE misses
        assert J._expire_open(s, stale, base, "x", rule="node_offline") is False
        s.rollback()
    with Session(engine) as s:
        stats: dict[str, int] = {}
        assert J.reap(s, base + dt.timedelta(hours=5, minutes=1), stats=stats) >= 1  # the job, then the run reconcile
        s.commit()
        assert stats == {"node_offline": 1}
    after = _job(engine, job_id)
    assert (after.status, after.lease_id, after.lease_expires_at) == ("expired", None, None)


def test_a_partly_expired_run_is_partial_and_says_which_job_expired(api, world):  # noqa: F811
    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine)
    with Session(engine) as s:  # a second job of the same run that read everything
        first = s.get(CbomCollectionJob, job_id)
        s.add(CbomCollectionJob(team_id=1, run_id=run["id"], source_id=first.source_id, node_id=node_id,
                                kind="collect", status="success", outcome="ok", params={"source_name": "ok-source"},
                                created_at=_now(), finished_at=_now(), weight_c=0))
        s.commit()
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert detail["status"] == "partial"
    assert detail["status_reason"].startswith("1 of 2 jobs read everything; 1 expired. ")
    assert "offline since" in detail["status_reason"]


def test_no_secret_or_config_reaches_the_expiry_reason_or_logs(api, world, capsys):  # noqa: F811
    from test_cbom_sources_api import PASSWORD

    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine)
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    body = api("GET", f"/1/cbom/sources/runs/{run['id']}").text
    out = capsys.readouterr()
    assert "job expired" in out.out + out.err and "node_offline" in out.out + out.err
    assert PASSWORD not in body and PASSWORD not in out.out + out.err


# ----------------------------------------------------------------------------- run #52: partial with 19/19 success
def test_run_52_all_jobs_success_one_partly_read_is_partial_and_says_why(api, world):  # noqa: F811
    engine, _ = world
    _node_id, _t, _src, run, job_id = _queue_run(api, engine)
    now = _now()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.status, job.outcome, job.finished_at = "success", "partial", now
        job.result = {"summary": targets_summary([{"status": "partial"}]), "counts": {"total": 1, "partial": 1}}
        job.params = {**(job.params or {}), "source_name": "Google Cloud zeroshield-cbom-testing"}
        s.add(job)
        s.commit()
    with Session(engine) as s:
        assert J.close_run(s, run["id"], now) == "partial"
        s.commit()
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert detail["status"] == "partial" and detail["job_counts"] == {"success": 1}
    assert detail["status_reason"] == (
        "0 of 1 jobs read everything; 1 collected only part of its targets. "
        "linux-dc: collected only part of its targets (1 of 1 targets read (1 with gaps))")
    listed = next(r for r in api("GET", "/1/cbom/sources/runs").json()["runs"] if r["id"] == run["id"])
    assert listed["status_reason"] == detail["status_reason"]
    from backend.utilities.cbom_sources import run_list as RUN_LIST

    with Session(engine) as s:  # the CBOM Scans table's run rows (GET /{team}/cbom/scans runs_list_data)
        rows = RUN_LIST.list_run_rows(s, 1)["runs_list_data"]
    row = next(r for r in rows if r["id"] == run["id"])
    assert row["run_status"] == "partial" and "collected only part of its targets" in row["status_reason"]


def test_targets_summary_counts_a_target_read_with_gaps_as_read():
    assert targets_summary([{"status": "partial"}]) == "1 of 1 targets read (1 with gaps)"
    assert targets_summary([{"status": "ok"}, {"status": "error"}]) == "1 of 2 targets read"
    assert targets_summary([]) == "0 of 0 targets read"


@pytest.mark.parametrize("status,jobs,expected", [
    ("done", [{"status": "success", "outcome": "ok"}], None),
    ("running", [{"status": "pending", "waiting_reason": "Outside the scan window"}], None),
    ("failed", [{"id": 1, "status": "failure", "error": "auth_failed", "source_name": "K8s"}],
     "No job read anything: 1 failed. K8s: auth_failed"),
    ("cancelled", [{"id": 1, "status": "cancelled", "source_name": "A"}], "1 was cancelled. A: cancelled"),
])
def test_status_reason_rules(status, jobs, expected):
    assert status_reason(status, jobs)["status_reason"] == expected


def test_status_reason_names_three_and_counts_the_rest():
    jobs = [{"id": i, "status": "failure", "source_name": f"s{i}", "error": "no_route"} for i in range(5)]
    jobs.append({"id": 9, "status": "success", "outcome": "ok"})
    out = status_reason("partial", jobs)
    assert out["status_reason"].startswith("1 of 6 jobs read everything; 5 failed. s0: no_route; s1: no_route; s2")
    assert out["status_reason"].endswith("; and 2 more") and len(out["status_reason_jobs"]) == 5


# ----------------------------------------------------------------------------- review 6028153035 (#480)
def _mark(engine, *, since: dt.datetime, last_pass: dt.datetime) -> None:
    """The reaper's bookkeeping row: serving without a gap since ``since``, last pass at ``last_pass``."""
    with Session(engine) as s:
        s.merge(CbomOpsCounter(name=J.SERVING_MARK, value=int((since - dt.datetime(1970, 1, 1)).total_seconds()),
                               updated_at=last_pass))
        s.commit()


def test_m1_a_backend_outage_longer_than_the_deadline_does_not_expire_a_live_nodes_job(api, world, monkeypatch):  # noqa: F811
    """M1: the node heartbeated normally until the BACKEND went away for 6 h 5 min.  The first reaper pass after the
    restart runs before the node's next heartbeat; the job must survive and the node then claims it."""
    monkeypatch.setattr(J, "note_reaper_pass", _REAL_NOTE)
    engine, _ = world
    node_id, token, _src, run, job_id = _queue_run(api, engine, "fixb3-outage-00001")
    now = _now()
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=6, minutes=10), seen_ago=dt.timedelta(hours=6, minutes=5))
    _mark(engine, since=now - dt.timedelta(days=30), last_pass=now - dt.timedelta(hours=6, minutes=5))
    with Session(engine) as s:
        assert J.reap(s, now) == 0
        s.commit()
    assert _job(engine, job_id).status == "pending" and _run_row(engine, run["id"]).status == "queued"
    hdr = {"X-ZS-Node-Token": token}
    assert api("POST", "/cbom/node/heartbeat", None, headers=hdr, json={"version": "1.1"}).status_code == 200
    assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 200
    assert _job(engine, job_id).status == "claimed"


def test_m1_after_a_restart_the_offline_window_counts_from_the_restart(api, world, monkeypatch):  # noqa: F811
    """The node stays silent after the backend is back: the job expires once the backend has served a full deadline
    without hearing from it, and the reason still names the last heartbeat."""
    monkeypatch.setattr(J, "note_reaper_pass", _REAL_NOTE)
    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine, "fixb3-outage-00002")
    now = _now()
    seen = _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=6, minutes=10),
                seen_ago=dt.timedelta(hours=6, minutes=5))
    _mark(engine, since=now - dt.timedelta(days=30), last_pass=now - dt.timedelta(hours=6, minutes=5))
    with Session(engine) as s:
        assert J.reap(s, now) == 0  # the restart: serving since now
        tick = now
        while tick < now + HOURS_6 - dt.timedelta(seconds=60):  # a pass every 30 s, as the worker's reaper does
            tick += dt.timedelta(seconds=30)
            assert J.note_reaper_pass(s, tick) == now.replace(microsecond=0)
        s.commit()
        assert J.reap(s, now + HOURS_6 - dt.timedelta(seconds=1)) == 0
        s.commit()
        assert J.reap(s, now + HOURS_6 + dt.timedelta(seconds=1)) >= 1
        s.commit()
    job = _job(engine, job_id)
    assert job.status == "expired" and job.refunded is True
    assert job.error.startswith(f"Scan node cbom-lab-2-worker offline since {seen.strftime('%Y-%m-%d %H:%M UTC')}")
    assert _run_row(engine, run["id"]).status == "failed"


def test_m1_the_first_pass_of_a_new_deploy_waits_and_a_serving_backend_expires_at_once(api, world, monkeypatch):  # noqa: F811
    monkeypatch.setattr(J, "note_reaper_pass", _REAL_NOTE)
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine, "fixb3-outage-00003")
    now = _now()
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    with Session(engine) as s:  # no bookkeeping row yet (first deploy of this rule): serving since now
        s.exec(CbomOpsCounter.__table__.delete())  # type: ignore[call-overload]
        s.commit()
        assert J.reap(s, now) == 0
        s.commit()
    assert _job(engine, job_id).status == "pending"
    _mark(engine, since=now - dt.timedelta(days=30), last_pass=now - dt.timedelta(seconds=30))  # serving all along
    with Session(engine) as s:
        assert J.reap(s, now + dt.timedelta(seconds=30)) >= 1
        s.commit()
    assert _job(engine, job_id).status == "expired"


def test_m1_a_short_gap_between_passes_keeps_the_serving_run():
    from sqlmodel import SQLModel, create_engine

    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    t0 = dt.datetime(2026, 11, 24, 8, 0, 0)
    with Session(engine) as s:
        assert _REAL_NOTE(s, t0) == t0
        assert _REAL_NOTE(s, t0 + J.serving_gap()) == t0  # exactly the gap: still the same run
        assert _REAL_NOTE(s, t0 + 2 * J.serving_gap() + dt.timedelta(seconds=1)) == t0 + 2 * J.serving_gap() + dt.timedelta(seconds=1)
        s.commit()


def test_m1_a_heartbeat_between_the_read_and_the_update_saves_the_job(api, world, monkeypatch):  # noqa: F811
    """m1 (TOCTOU): the node's heartbeat commits after the offline rule read the node but before the guarded UPDATE."""
    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine, "fixb3-toctou-00001")
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=7), seen_ago=dt.timedelta(hours=7))
    real = J._expire_open

    def heartbeat_then_expire(*a, **k):
        with Session(engine) as other:
            node = other.get(CbomScanNode, node_id)
            node.last_heartbeat_at = _now()
            other.add(node)
            other.commit()
        return real(*a, **k)

    monkeypatch.setattr(J, "_expire_open", heartbeat_then_expire)
    with Session(engine) as s:
        stats: dict[str, int] = {}
        J.reap(s, _now(), stats=stats)
        s.commit()
    assert "node_offline" not in stats
    job = _job(engine, job_id)
    assert job.status == "pending" and job.refunded is False and _run_row(engine, run["id"]).status == "queued"


def _segment_node(s: Session, name: str, *, mode: str = "agentless", signed: bool = True,
                  seen: dt.datetime | None) -> CbomScanNode:
    node = CbomScanNode(team_id=1, owner_user_id=1, name=name, segment="Branch", mode=mode,
                        node_token_hash=(name + "-token-hash")[:64] if signed else None,
                        signing_public_key="A" * 43 + "=" if signed else None, last_heartbeat_at=seen)
    s.add(node)
    return node


@pytest.mark.parametrize("live", ["agent", "unsigned"])
def test_m2_a_segment_whose_only_live_node_cannot_take_the_job_is_expired(world, live):  # noqa: F811
    """m2: the reaper's candidate query counted an agent-mode (or unsigned) node's heartbeat for the segment, the
    rule did not, so the segment job waited out the 7 d queue TTL (the run #50 symptom)."""
    engine, _ = world
    now = _now()
    with Session(engine) as s:
        _segment_node(s, "branch-agentless", seen=now - dt.timedelta(hours=7))
        if live == "agent":
            _segment_node(s, "branch-host-agent", mode="agent", seen=now)
        else:
            _segment_node(s, "branch-unsigned", signed=False, seen=now)
        job = CbomCollectionJob(team_id=1, node_segment="Branch", kind="collect", status="pending",
                                created_at=now - dt.timedelta(hours=7), params={"source_name": "branch"})
        s.add(job)
        s.commit()
        job_id = job.id
    with Session(engine) as s:
        stats: dict[str, int] = {}
        J.reap(s, now, stats=stats)
        s.commit()
    assert stats.get("node_offline") == 1
    job = _job(engine, job_id)
    assert job.status == "expired" and job.error.startswith("Every scan node of segment Branch offline since ")


def test_m2_a_live_signed_agentless_member_keeps_the_segment_job(world):  # noqa: F811
    engine, _ = world
    now = _now()
    with Session(engine) as s:
        _segment_node(s, "branch-old", seen=now - dt.timedelta(hours=7))
        _segment_node(s, "branch-live", seen=now)
        job = CbomCollectionJob(team_id=1, node_segment="Branch", kind="collect", status="pending",
                                created_at=now - dt.timedelta(hours=7))
        s.add(job)
        s.commit()
        job_id = job.id
    with Session(engine) as s:
        J.reap(s, now)
        s.commit()
    assert _job(engine, job_id).status == "pending"


def test_m3_the_scans_table_row_says_what_the_run_detail_says(api, world):  # noqa: F811
    """m3: runs_list_data[].status_reason was built without the job summary and the waiting reason, so an open run
    waiting for an offline node said nothing and a partial run lost "(1 of 1 targets read (1 with gaps))"."""
    from backend.utilities.cbom_sources import run_list as RUN_LIST

    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine, "fixb3-list-0000001")
    _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=2), seen_ago=dt.timedelta(hours=2))
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert detail["status"] == "queued" and "wait for an offline scan node" in detail["status_reason"]
    with Session(engine) as s:
        row = next(r for r in RUN_LIST.list_run_rows(s, 1)["runs_list_data"] if r["id"] == run["id"])
    assert row["status_reason"] == detail["status_reason"]

    now = _now()
    with Session(engine) as s:  # now the run #52 case: finished partial, the job read its targets with gaps
        job = s.get(CbomCollectionJob, job_id)
        job.status, job.outcome, job.finished_at = "success", "partial", now
        job.result = {"summary": targets_summary([{"status": "partial"}]), "counts": {"total": 1, "partial": 1}}
        s.add(job)
        s.commit()
        assert J.close_run(s, run["id"], now) == "partial"
        s.commit()
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    with Session(engine) as s:
        row = next(r for r in RUN_LIST.list_run_rows(s, 1)["runs_list_data"] if r["id"] == run["id"])
    assert "(1 of 1 targets read (1 with gaps))" in detail["status_reason"]
    assert row["status_reason"] == detail["status_reason"]


# ----------------------------------------------------------------------------- review 6031262064 (#480)
_EPOCH = J._EPOCH


def _serving_since(engine) -> dt.datetime:
    with Session(engine) as s:
        return _EPOCH + dt.timedelta(seconds=int(s.get(CbomOpsCounter, J.SERVING_MARK).value))


def test_m_a_a_replica_whose_clock_is_behind_never_moves_the_last_pass_back():
    """m-a: replica A runs 300 s ahead of replica B.  B's pass used to write its own (earlier) time as the last pass,
    so A's next pass saw a gap of 30 s + 300 s > ``serving_gap()`` and restarted the window."""
    from sqlmodel import SQLModel, create_engine

    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    t0 = _now().replace(microsecond=0)  # replica A's clock
    b_pass = t0 - dt.timedelta(seconds=300) + dt.timedelta(seconds=30)  # B, 30 s later in real time
    with Session(engine) as s:
        assert _REAL_NOTE(s, t0) == t0  # A
        assert _REAL_NOTE(s, b_pass) == b_pass  # B: a start later than its clock is clamped to it (unchanged)
        s.commit()
        assert s.get(CbomOpsCounter, J.SERVING_MARK).updated_at == t0  # the last pass kept A's later time
        assert _REAL_NOTE(s, t0 + dt.timedelta(seconds=60)) == b_pass  # A again: a 60 s gap, the same run
        s.commit()


@pytest.mark.parametrize("skew_s", [215, 300])
def test_m_a_clock_skew_between_two_reaper_replicas_does_not_restart_the_window(api, world, monkeypatch, skew_s):  # noqa: F811
    """m-a (the review's B4): replicas A and B alternate passes every 30 s, A's clock ``skew_s`` ahead.  At about
    210 s and more of skew every pass restarted the window (419 of 419 at 300 s) and the dead node's job never
    expired by the offline rule.  Now the window starts once and the job expires about 6 h after the last
    heartbeat, give or take the skew."""
    monkeypatch.setattr(J, "note_reaper_pass", _REAL_NOTE)
    engine, _ = world
    node_id, _t, _src, run, job_id = _queue_run(api, engine, f"fixb3-skew-{skew_s:07d}")
    t0 = _now().replace(microsecond=0)
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        job.created_at = t0 - dt.timedelta(hours=1)
        s.add(job)
        node = s.get(CbomScanNode, node_id)
        node.last_heartbeat_at = t0
        s.add(node)
        s.commit()
    _mark(engine, since=t0 - dt.timedelta(days=3), last_pass=t0 - dt.timedelta(seconds=30))
    skew = dt.timedelta(seconds=skew_s)
    real, expired_at, resets, last_since = t0, None, 0, None
    with Session(engine) as s:
        for k in range(int(dt.timedelta(hours=7).total_seconds() // 30)):
            real += dt.timedelta(seconds=30)
            J.reap(s, real + skew if k % 2 == 0 else real)  # A, B, A, B ...
            s.commit()
            since = _serving_since(engine)
            resets += last_since is not None and since > last_since
            last_since = since
            s.expire_all()
            if s.get(CbomCollectionJob, job_id).status != "pending":
                expired_at = real
                break
    assert resets == 0
    assert expired_at is not None, "the offline rule never fired"
    assert abs((expired_at - t0) - HOURS_6) <= skew + dt.timedelta(seconds=60)
    assert _job(engine, job_id).status == "expired" and _run_row(engine, run["id"]).status == "failed"


def test_n_b_expires_at_reads_the_stored_serving_mark_in_a_process_that_has_not_reaped(api, world):  # noqa: F811
    """n-b: the estimate used only this process's last reading, which is empty before its first reap, so after a
    restart it promised an expiry 6 h after the heartbeat while the reaper waits 6 h after the restart."""
    engine, _ = world
    node_id, _t, _src, _run, job_id = _queue_run(api, engine, "fixb3-estimate-0001")
    now = _now().replace(microsecond=0)
    seen = _age(engine, job_id, node_id, queued_ago=dt.timedelta(hours=3), seen_ago=dt.timedelta(hours=3))
    restart = now - dt.timedelta(hours=1)
    _mark(engine, since=restart, last_pass=now - dt.timedelta(seconds=30))
    assert J._SERVING_SINCE[0] is None  # this process has not reaped
    with Session(engine) as s:
        job, node = s.get(CbomCollectionJob, job_id), s.get(CbomScanNode, node_id)
        wait = J.offline_wait_reason(job, node, now)
    assert f"the job expires at {(restart + HOURS_6).strftime('%Y-%m-%d %H:%M UTC')} " in wait, wait
    assert f"since {seen.strftime('%Y-%m-%d %H:%M UTC')}" in wait

    # the last pass is older than the serving gap: the next pass restarts the window, so it counts from now
    _mark(engine, since=restart, last_pass=now - J.serving_gap() - dt.timedelta(seconds=1))
    with Session(engine) as s:
        wait = J.offline_wait_reason(s.get(CbomCollectionJob, job_id), s.get(CbomScanNode, node_id), now)
    assert f"the job expires at {(now + HOURS_6).strftime('%Y-%m-%d %H:%M UTC')} " in wait, wait
