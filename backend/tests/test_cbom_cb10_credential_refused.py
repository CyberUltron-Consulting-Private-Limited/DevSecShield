"""CB-10 server side: a source whose credential the scan node stopped using ("credential refused") is not run again
until the credential is edited (or a connection test passes): manual runs skip it with the reason, and the next
scheduled run is not queued.

The node reports it in the job result (``credential_refused``: its breaker tripped after K refused logins in a row, or
every login it tried was refused).  Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import PASSWORD, _collect_job, api, world  # noqa: E402,F401
from test_cbom_review5_jobs_schedules import _frozen  # noqa: E402

from backend.new_models import CbomCollectionJob, CbomCollectionRun, CbomCollectionSchedule  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import schedules as S  # noqa: E402

ITEMS = "/1/cbom/sources/items"
TARGETS = [f"10.20.0.{i}" for i in range(1, 11)]
REFUSED = {"failures": 3, "skipped": 7, "limit": 3}


def _rows():
    return ([{"target": t, "status": "auth_failed", "error": "login as zs-cbom was refused"} for t in TARGETS[:3]]
            + [{"target": t, "status": "skipped_credential_refused", "error": "not tried"} for t in TARGETS[3:]])


def _finish(api, claim, hdr, refused=True):  # noqa: F811
    result = {"summary": "0 of 10 targets collected", "counts": {"total": 10, "ok": 0, "failed": 3, "skipped": 7},
              "targets": _rows(), "asset_count": 0}
    if refused:
        result["credential_refused"] = REFUSED
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "success", "result": result})
    assert r.status_code == 200, r.text


def _estimate_reason(api, source_id: int) -> str | None:  # noqa: F811
    ratelimit.reset_all()
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    for item in est["skipped"]:
        if item["source_id"] == source_id:
            return item["reason"]
    return None


def test_a_refused_credential_pauses_the_source_until_the_credential_is_edited(api, world):  # noqa: F811
    engine, _ = world
    src, _run, claim, hdr = _collect_job(api, engine, targets=TARGETS)
    _finish(api, claim, hdr)
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["last_test_status"] == "failed"
    assert got["last_test_summary"].startswith("Credential refused: 3 logins in a row were refused")
    assert got["last_test_result"]["credential_refused"] == {**REFUSED, "job_id": claim["job"]["id"]}
    reason = _estimate_reason(api, src["id"])
    assert reason and reason.startswith("Credential refused") and "until its credential is edited" in reason
    ratelimit.reset_all()
    again = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "after-refusal-1"})
    assert again.status_code == 400 and "Nothing to scan" in again.text

    # a rename is not a credential edit: still paused
    cur = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    ratelimit.reset_all()
    assert api("PATCH", f"{ITEMS}/{src['id']}", json={"name": "linux-dc-renamed",
                                                      "expected_version": cur["row_version"]}).status_code == 200
    assert (_estimate_reason(api, src["id"]) or "").startswith("Credential refused")

    # a new password resumes it
    cur = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    ratelimit.reset_all()
    edited = api("PATCH", f"{ITEMS}/{src['id']}", json={"config": cur["config"], "secrets": {"password": PASSWORD + "-new"},
                                                        "expected_version": cur["row_version"]})
    assert edited.status_code == 200, edited.text
    assert edited.json()["source"]["last_test_status"] == "never"
    assert _estimate_reason(api, src["id"]) is None


def test_the_next_scheduled_run_is_not_queued(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    clock = _frozen(monkeypatch, dt.datetime(2026, 12, 1, 5, 0))
    src, _run, claim, hdr = _collect_job(api, engine, targets=TARGETS)
    _finish(api, claim, hdr)
    ratelimit.reset_all()
    made = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "09:00", "include": {"servers": True}})
    assert made.status_code == 201, made.text
    sched = made.json()["schedule"]
    clock.now = dt.datetime.strptime(sched["next_run_at"], "%Y-%m-%dT%H:%M:%SZ") + dt.timedelta(seconds=30)
    fired = S.fire_due(engine, clock.now)
    assert [(f["status"], f["run_id"]) for f in fired] == [("skipped", None)]
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionRun).where(CbomCollectionRun.schedule_id == sched["id"])).all() == []
        assert s.get(CbomCollectionSchedule, sched["id"]).last_status == "skipped"


def test_a_job_without_a_refused_credential_leaves_the_source_alone(api, world):  # noqa: F811
    engine, _ = world
    src, _run, claim, hdr = _collect_job(api, engine, targets=TARGETS)
    before = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    _finish(api, claim, hdr, refused=False)
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["last_test_status"] == before["last_test_status"] and "credential_refused" not in got["last_test_result"]


def test_a_stale_job_never_pauses_a_source_whose_credential_was_edited_meanwhile(api, world):  # noqa: F811
    engine, _ = world
    src, _run, claim, hdr = _collect_job(api, engine, targets=TARGETS)
    cur = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    ratelimit.reset_all()
    assert api("PATCH", f"{ITEMS}/{src['id']}", json={"config": cur["config"], "secrets": {"password": PASSWORD + "-2"},
                                                      "expected_version": cur["row_version"]}).status_code == 200
    _finish(api, claim, hdr)  # the old credential's result arrives after the edit: the job is cancelled, not counted
    got = api("GET", f"{ITEMS}/{src['id']}").json()["source"]
    assert got["last_test_status"] == "never" and _estimate_reason(api, src["id"]) is None
    with Session(engine) as s:
        assert s.get(CbomCollectionJob, claim["job"]["id"]).status == "cancelled"


def test_the_backend_knows_the_new_target_status():
    assert "skipped_credential_refused" in J.TARGET_STATUSES
