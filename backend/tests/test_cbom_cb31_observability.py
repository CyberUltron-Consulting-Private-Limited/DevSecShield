"""CB-31 observability minimum (DEVILS-ADVOCATE CB-31; GAP-MATRIX section X; R4 OBS-5, OBS-7, OBS-8).

* X3 / OBS-7: a 500 logs its traceback frames (``file:line:function``) next to its ref, never the exception's
  message or locals (they can hold secrets). dev: the line carries only the exception class.
* OBS-5 / R4 p2: the node reports ``sent``, ``rejected`` and ``duplicate``, and the server derives the asset-count
  mismatch from them. dev: 5 sent, 3 stored (2 refused by the server) gives no mismatch badge, because the node's
  ``asset_count`` is the server's own ``accepted`` count.
* X1 / OBS-8: an admin-only Prometheus text endpoint (``GET /cbom/ops/metrics``): queue depth per kind, oldest
  pending age, lease expiries, ingest rejects, node heartbeat age, integration backlog. dev: 404.
* X2 (request id), X4 (build identity) and X5 (log timestamps) are on dev already: tests/test_build_identity.py.

Real routers on SQLite (the harness of test_cbom_sources_api.py).

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb31_observability.py
"""
from __future__ import annotations

import datetime as dt
import re
import time

from sqlmodel import Session, select

from tests import test_cbom_sources_api as H
from tests.test_cbom_sources_api import enroll_node, linux_body

from backend.new_models import CbomCollectionJob, CbomScanNode, IntegrationDelivery, Team, User  # noqa: F401
from backend.utilities.cbom_sources import common as COMMON
from backend.utilities.cbom_sources import jobs as J

api, world = H.api, H.world  # the harness's fixtures: SQLite + real routers + real JWTs
SECRET = "hunter2-do-not-log"


def _hdr(token: str) -> dict:
    return {"X-ZS-Node-Token": token}


def _failed_lines(capsys) -> list[str]:
    return [ln for ln in capsys.readouterr().out.splitlines() if "FAILED" in ln]


# ----------------------------------------------------------------------------- X3: frames next to the 500 ref
def _explode(*_args, **_kwargs):
    raise RuntimeError(f"password={SECRET}")


def test_a_forced_500_logs_its_frames_and_not_its_message(api, world, monkeypatch, capsys):
    from backend.routers import cbom_ops

    monkeypatch.setattr(cbom_ops.DRIFT, "previous_comparable_run", _explode)
    monkeypatch.setattr(cbom_ops, "_owned_run", lambda *_a: object())
    capsys.readouterr()
    r = api("GET", "/1/cbom/sources/runs/1/diff")
    assert r.status_code == 500
    ref = re.search(r"ref ([0-9a-f]{8})", r.json()["detail"]).group(1)
    (line,) = [ln for ln in _failed_lines(capsys) if f"ref={ref}" in ln]
    frames = re.search(r" frames=(\S+)", line)
    assert frames, line  # dev: "cbom sources cbom ops run diff FAILED ref=... error=RuntimeError team=1"
    listed = frames.group(1).split(",")
    assert all(re.fullmatch(r"[\w./-]+:\d+:[\w<>.]+", f) for f in listed), listed
    assert any(f.startswith("backend/routers/cbom_ops.py:") and f.endswith(":_run_diff") for f in listed)
    assert listed[-1].endswith(":_explode")  # innermost last: where it was raised
    assert SECRET not in line and "password" not in line


def test_frames_are_logged_only_with_a_ref_inside_an_exception(capsys):
    capsys.readouterr()
    try:
        _explode()
    except RuntimeError:
        COMMON.log("thing FAILED", ref="abcd1234", error="RuntimeError")
        COMMON.log("thing retried", job=1)  # no ref: an ordinary line keeps its shape
    COMMON.log("later FAILED", ref="ef012345", error="RuntimeError")  # no exception in flight: nothing to add
    out = capsys.readouterr().out.splitlines()
    assert "frames=" in out[0] and out[0].split(" frames=")[1].split(",")[-1].endswith(":_explode")
    assert "frames=" not in out[1] and "frames=" not in out[2]


def test_frames_cap_and_shape():
    def deep(n):
        if n == 0:
            raise ValueError("secret")
        deep(n - 1)

    try:
        deep(60)
    except ValueError as exc:
        text = COMMON.frames(exc)
    listed = text.split(",")
    assert listed[0] == "…" and len(listed) == COMMON.FRAMES_CAP + 1  # the innermost frames kept, marked as cut
    assert listed[-1].startswith("backend/tests/test_cbom_cb31_observability.py:") and listed[-1].endswith(":deep")


def test_the_cloud_worker_logs_frames_with_its_job_failure_ref(capsys):
    """``cbom_cloud_worker.py`` logs "cloud job FAILED ref=..." inside its except (frames come with it), and for a
    batch the store refused, which a collector may swallow, keeps the store failure's frames for the ref it logs
    later."""
    from backend.workers import cbom_cloud_worker as W

    source = W.__file__
    text = open(source, encoding="utf-8").read()
    assert "self.store_failed_frames = frames(exc)" in text and "frames=self.store_failed_frames" in text


# ----------------------------------------------------------------------------- OBS-5: sent / rejected / duplicate
def _collect(api):
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any"))
    assert src.status_code == 201, src.text
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "cb31-run-0001"})
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    return run.json()["run"]["id"], claim["job"], token


def _tls(i: int) -> dict:
    ip = "10.20.0.1"
    return {"type": "tls_endpoint", "target": ip, "location": f"{ip}:{443 + i}", "facts": {"protocols": ["TLSv1.2"]}}


def _finish(api, job, token, result):
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=_hdr(token),
            json={"lease_id": job["lease_id"], "status": "success", "result": result})
    assert r.status_code == 200, r.text


def _job(world, job_id: int) -> CbomCollectionJob:
    with Session(world[0]) as s:
        return s.get(CbomCollectionJob, job_id)


def test_r4_p2_assets_the_server_refused_raise_the_mismatch(api, world):
    run_id, job, token = _collect(api)
    batch = [_tls(0), _tls(1), _tls(2), {"type": "not_a_type", "location": "x"}, {"type": "tls_endpoint", "location": ""}]
    out = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=_hdr(token),
              json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": batch}).json()
    assert out["accepted"] == 3 and out["rejected"] == 2
    # what jobctx.result now sends: asset_count is the server's own accepted count, so it cannot show the loss
    _finish(api, job, token, {"counts": {"total": 1, "ok": 1, "failed": 0, "skipped": 0}, "asset_count": 3,
                              "sent": 5, "rejected": 2, "duplicate": 0, "assets_lost": 0})
    stored = _job(world, job["id"])
    assert stored.result.get("asset_mismatch") == {"reported": 5, "stored": 3, "sent": 5, "duplicate": 0,
                                                   "rejected": 2, "lost": 0}
    assert stored.outcome == "partial" and stored.result["rejected"] == 2
    detail = api("GET", f"/1/cbom/sources/runs/{run_id}").json()["run"]
    assert detail["jobs"][0]["result"]["asset_mismatch"]["rejected"] == 2  # what the UI badge reads


def test_a_retried_batch_counted_as_duplicate_is_no_mismatch(api, world):
    _run_id, job, token = _collect(api)
    batch = [_tls(0), _tls(1), _tls(2)]
    for _ in range(2):  # the node posted the batch, lost the answer and posted it again
        api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=_hdr(token),
            json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": batch})
    _finish(api, job, token, {"counts": {"total": 1, "ok": 1, "failed": 0, "skipped": 0}, "asset_count": 3,
                              "sent": 6, "rejected": 0, "duplicate": 3, "assets_lost": 0})
    stored = _job(world, job["id"])
    assert "asset_mismatch" not in stored.result and stored.outcome == "ok"


def test_an_older_node_without_the_counters_keeps_the_old_check(api, world):
    _run_id, job, token = _collect(api)
    api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=_hdr(token),
        json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": [_tls(0), _tls(1)]})
    _finish(api, job, token, {"counts": {"total": 1, "ok": 1, "failed": 0, "skipped": 0}, "asset_count": 2})
    assert _job(world, job["id"]).outcome == "ok"


# ----------------------------------------------------------------------------- X1: the metrics endpoint
METRICS = "/cbom/ops/metrics"


def _superuser(world, who: str = "alice") -> None:
    engine, ids = world
    with Session(engine) as s:
        user = s.get(User, ids[who])
        user.is_superuser = True
        s.add(user)
        s.commit()


def _samples(text: str) -> dict[str, float]:
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, value = line.rsplit(" ", 1)
        out[name] = float(value)
    return out


def test_metrics_are_admin_only(api, world, monkeypatch):
    assert api("GET", METRICS, None).status_code == 401  # dev: 404 (no endpoint)
    assert api("GET", METRICS, "alice").status_code == 403  # a team admin is not a platform admin
    _superuser(world)
    r = api("GET", METRICS, "alice")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")
    monkeypatch.setenv("CBOM_METRICS_TOKEN", "scrape-" + "x" * 32)
    assert api("GET", METRICS, None, headers={"Authorization": "Bearer scrape-" + "x" * 32}).status_code == 200
    assert api("GET", METRICS, None, headers={"Authorization": "Bearer scrape-wrong"}).status_code == 401


def test_metrics_report_queues_leases_rejects_nodes_and_integration_backlog(api, world):
    engine, _ids = world
    _superuser(world)
    now = dt.datetime.utcnow()
    _run_id, job, token = _collect(api)  # one collect job, claimed by the node
    api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=_hdr(token),
        json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": [_tls(0), {"type": "not_a_type", "location": "x"}]})
    with Session(engine) as s:
        node = s.exec(select(CbomScanNode)).first()
        s.add(CbomCollectionJob(team_id=1, node_id=node.id, kind="test_connection", status="pending",
                                created_at=now - dt.timedelta(minutes=10)))
        s.add(CbomCollectionJob(team_id=1, node_id=node.id, kind="test_connection", status="pending",
                                created_at=now - dt.timedelta(minutes=2)))
        stale = CbomScanNode(team_id=1, owner_user_id=_ids["alice"], name="old-node", node_token_hash="f" * 64,
                             last_heartbeat_at=now - dt.timedelta(hours=2))
        s.add(stale)
        claimed = s.get(CbomCollectionJob, job["id"])
        claimed.lease_expires_at = now - dt.timedelta(minutes=1)  # the node stopped renewing
        s.add(claimed)
        s.add(IntegrationDelivery(team_id=1, integration_id=_integration(s), kind="webhook", event_uid="e1",
                                  event_type="finding.opened", status="pending", created_at=now - dt.timedelta(minutes=5)))
        s.add(IntegrationDelivery(team_id=1, integration_id=_integration(s), kind="webhook", event_uid="e2",
                                  event_type="finding.opened", status="dead"))
        s.commit()
        J.reap(s, now)  # the expired lease goes back to pending (attempt 1 of 3)
        s.commit()
    text = api("GET", METRICS, "alice").text
    m = _samples(text)
    assert m['cbom_jobs{kind="test_connection",status="pending"}'] == 2
    assert m['cbom_jobs{kind="collect",status="pending"}'] == 1  # requeued by the reaper
    assert 590 <= m['cbom_jobs_oldest_pending_age_seconds{kind="test_connection"}'] <= 900
    assert m['cbom_job_lease_expiries_total{outcome="requeued"}'] == 1
    assert m["cbom_ingest_rejected_assets_total"] == 1
    assert m['cbom_nodes{state="online"}'] == 1 and m['cbom_nodes{state="offline"}'] == 1
    assert m['cbom_node_heartbeat_age_seconds_bucket{le="300"}'] == 1
    assert m['cbom_node_heartbeat_age_seconds_bucket{le="+Inf"}'] == 2
    assert 7100 <= m["cbom_node_heartbeat_age_seconds_max"] <= 7300
    assert m['cbom_integration_deliveries{status="pending"}'] == 1
    assert m['cbom_integration_deliveries{status="dead"}'] == 1
    assert 290 <= m["cbom_integration_oldest_pending_age_seconds"] <= 600
    for name in ("cbom_jobs", "cbom_job_lease_expiries_total", "cbom_ingest_rejected_assets_total", "cbom_nodes"):
        assert f"# TYPE {name} " in text and f"# HELP {name} " in text
    assert "team" not in text  # aggregates only: no tenant names or ids


def _integration(s) -> int:
    from backend.new_models import TeamIntegration

    found = s.exec(select(TeamIntegration)).first()
    if found is None:
        found = TeamIntegration(team_id=1, kind="webhook", name="hook", config={}, enabled=True)
        s.add(found)
        s.flush()
    return found.id


def test_a_scrape_with_10k_nodes_is_fast(api, world):
    """Exit S: a scrape <= 50 ms with 10k nodes (F1.1 bench). The bound here is loose (a shared CI runner); the PR
    records the measured time."""
    engine, ids = world
    _superuser(world)
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        for i in range(10_000):
            s.add(CbomScanNode(team_id=1, owner_user_id=ids["alice"], name=f"n{i}", node_token_hash=f"{i:064x}",
                               last_heartbeat_at=now - dt.timedelta(seconds=i)))
        for i in range(5_000):
            s.add(CbomCollectionJob(team_id=1, kind="collect" if i % 2 else "test_connection", status="pending",
                                    created_at=now - dt.timedelta(seconds=i)))
        s.commit()
    from backend.utilities.cbom_sources import ops_metrics as OM

    with Session(engine) as s:
        OM.render(s, now)  # warm
        times = []
        for _ in range(5):
            t0 = time.perf_counter()
            text = OM.render(s, now)
            times.append(time.perf_counter() - t0)
    assert _samples(text)['cbom_node_heartbeat_age_seconds_bucket{le="+Inf"}'] == 10_000
    median = sorted(times)[2]
    print(f"scrape median {median * 1000:.1f} ms with 10,000 nodes and 5,000 pending jobs")
    assert median < 0.5
