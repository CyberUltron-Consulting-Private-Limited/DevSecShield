"""A running network range shows "N of M addresses" (round 5 customer testing: only a growing asset count, and a
discovery row read "Running on the scan node" until it finished).

The scan node sends ``progress: {done, total}`` with the asset posts it already makes (an empty batch when there is
nothing else to post).  The server keeps it on the job (``result.progress``, JSON: no migration) for the current
attempt and serves it as the job's ``progress`` while the job runs.  Older nodes send none: ``progress`` is null and
everything else is as before.  Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401


def _post(api, job_id, hdr, body):
    return api("POST", f"/cbom/node/jobs/{job_id}/assets", None, headers=hdr, json=body)


def _job(api, job_id):
    r = api("GET", f"/1/cbom/sources/jobs/{job_id}")
    assert r.status_code == 200, r.text
    return r.json()["job"] if "job" in r.json() else r.json()


def test_a_running_job_serves_the_nodes_progress_and_drops_it_when_it_ends(api, world):
    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    job_id, lease = claim["job"]["id"], claim["job"]["lease_id"]
    # an older node: no progress field, nothing shown
    assert _post(api, job_id, hdr, {"lease_id": lease, "batch_id": "b1", "assets": []}).status_code == 200
    assert _job(api, job_id)["progress"] is None
    # a progress-only post (no assets) while the sweep runs
    r = _post(api, job_id, hdr, {"lease_id": lease, "batch_id": "b2", "assets": [], "progress": {"done": 3, "total": 254}})
    assert r.status_code == 200, r.text
    job = _job(api, job_id)
    assert job["status"] == "claimed" and job["progress"] == {"done": 3, "total": 254}
    assert "progress" not in job["result"] and job["waiting_reason"] == "Running on the scan node"
    # the run view (Review & Run) carries it too
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]["jobs"]
    assert listed[0]["progress"] == {"done": 3, "total": 254}
    # a count past the total is capped; an unknown field is refused like any other
    _post(api, job_id, hdr, {"lease_id": lease, "batch_id": "b3", "assets": [], "progress": {"done": 999, "total": 254}})
    assert _job(api, job_id)["progress"] == {"done": 254, "total": 254}
    bad = _post(api, job_id, hdr, {"lease_id": lease, "assets": [], "progress": {"done": 1, "total": 2, "eta": 5}})
    assert bad.status_code in (400, 422), bad.text
    assert _post(api, job_id, hdr, {"lease_id": lease, "assets": [], "progress": {"done": -1, "total": 2}}).status_code in (400, 422)
    # a stale lease cannot write it
    assert _post(api, job_id, hdr, {"lease_id": "0" * 24, "assets": [], "progress": {"done": 1, "total": 254}}).status_code == 409
    assert _job(api, job_id)["progress"] == {"done": 254, "total": 254}
    # the result replaces it: an ended job shows no progress
    done = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=hdr, json={
        "lease_id": lease, "status": "success", "result": {"counts": {"total": 2, "ok": 2, "failed": 0, "skipped": 0}}})
    assert done.status_code == 200, done.text
    ended = _job(api, job_id)
    assert ended["status"] == "success" and ended["progress"] is None and "progress" not in ended["result"]
