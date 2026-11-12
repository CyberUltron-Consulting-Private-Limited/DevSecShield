"""F1.1 round 7: the devil's-advocate implementation list (f1-1/DEVILS-ADVOCATE.md section 3) and security review
5869370742.  Each test names its item (A1, B1..E4).  SQLite + the real routers (the test_cbom_sources_api harness);
the PostgreSQL tests run when CBOM_TEST_PG_URL is set (CI sets it).

    cd backend && PYTHONPATH=..:../scan_node JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x \\
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 python -m pytest tests/test_cbom_f1_1_r7.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import text, update
from sqlmodel import Session, select

import test_cbom_f1_node_api as F

from backend.new_models import (
    CbomCollectionJob,
    CbomCollectionSettings,
    CbomNodeNonce,
    CbomNodePool,
    CbomScanNode,
)
from backend.utilities.cbom_sources import dispatch as D
from backend.utilities.cbom_sources import http as H
from backend.utilities.cbom_sources import limits as LIM
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources import node_obs as OBS
from backend.utilities.cbom_sources import settings as SETTINGS
from backend.utilities.cbom_sources.settings import get_or_create_settings
from zs_scan_node import api as node_api

needs_pg = F.needs_pg
api, world = F.api, F.world  # the SQLite world and API client fixtures, used by name
DAY_US = 86_400 * 1_000_000


@pytest.fixture(autouse=True)
def _fresh_dispatch():
    """Each test starts with a fresh dispatcher at the default rate (a test that measures the rate builds its own)."""
    D.reset(None)
    yield
    D.reset(None)


def _seq(offset_us: int = 0) -> int:
    return ((time.time_ns() // 1000) + offset_us) << NA.SEQ_SHIFT


def _post(api, path: str, key, token: str, seq: int, body: dict | None = None):
    raw = json.dumps(body or {}).encode()
    return api.client.post(path, headers=F._p2_headers(key, "POST", path, raw, token, seq), content=raw)


def _hwm(engine, node_id: int) -> int:
    with Session(engine) as s:
        return s.get(CbomScanNode, node_id).replay_hwm


def _unsigned_node(engine, name="legacy-dc", segment="DC", team_id=1) -> tuple[int, str]:
    token = "zsn_" + name.replace("-", "") + "x" * 30
    with Session(engine) as s:
        n = CbomScanNode(team_id=team_id, owner_user_id=1, name=name, segment=segment, enrolled_at=dt.datetime.utcnow(),
                         node_token_hash=hashlib.sha256(token.encode()).hexdigest(),
                         capabilities={"collectors": ["linux_servers"]})
        s.add(n)
        s.commit()
        return n.id, token


class _WithDate:
    """The ASGI test client without the ``Date`` header a real server (uvicorn) sends: the node learns skew from it."""

    def __init__(self, client) -> None:
        self._client = client

    def request(self, *args, **kwargs):
        import email.utils

        r = self._client.request(*args, **kwargs)
        r.headers["Date"] = email.utils.formatdate(usegmt=True)
        return r

    def __getattr__(self, name):
        return getattr(self._client, name)


# ============================================================================= B1: a refused request changes nothing
def test_b1_a_replayed_pool_rebind_is_refused_and_changes_nothing(api, world):
    """rv-sec41 probe 2: the replayed re-bind (byte for byte, inside the 300 s timestamp window, after a second Reset)
    is refused, the node keeps no token, and the real pod re-enrolls onto the same node."""
    engine, _ = world
    r = api("POST", "/1/cbom/sources/node-pools", "alice",
            json={"name": "k8s", "segment": "Cluster", "expires_in_hours": 24, "max_enrollments": 3})
    assert r.status_code == 201, r.text
    pool_token = r.json()["registration_token"]
    key = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()

    def enroll_raw(seq):
        body = json.dumps({"registration_token": pool_token, "hostname": "pod-a", "version": "1.2", "mode": "agent",
                           "node_name": "k8s-worker-a", "capabilities": {"collectors": ["host_agent"], "mode": "agent"},
                           "signing_public_key": pub}).encode()
        h = F._p2_headers(key, "POST", "/cbom/node/enroll", body, "", seq)
        h.pop("X-ZS-Node-Token")
        return body, h

    base = _seq()
    b0, h0 = enroll_raw(base)
    first = api.client.post("/cbom/node/enroll", headers=h0, content=b0)
    assert first.status_code == 200, first.text
    node_id = first.json()["node_id"]
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/reset").status_code == 200
    b1, h1 = enroll_raw(base + 10)
    rebind = api.client.post("/cbom/node/enroll", headers=h1, content=b1)
    assert rebind.status_code == 200, rebind.text
    good = rebind.json()["node_token"]
    assert _post(api, "/cbom/node/heartbeat", key, good, base + 20).status_code == 200
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/reset").status_code == 200
    replay = api.client.post("/cbom/node/enroll", headers=h1, content=b1)
    assert replay.status_code == 403 and replay.headers.get("X-ZS-Refused") == "replay"
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        assert node.node_token_hash is None and node.enrolled_at is None  # the refusal changed nothing
        assert s.exec(select(CbomNodePool)).first().enrollments == 1
    b2, h2 = enroll_raw(base + 100)
    again = api.client.post("/cbom/node/enroll", headers=h2, content=b2)
    assert again.status_code == 200 and again.json()["node_id"] == node_id  # same node, rebound
    with Session(engine) as s:
        assert len(s.exec(select(CbomScanNode).where(CbomScanNode.pool_id.is_not(None))).all()) == 1


def test_b1_a_refused_window_step_rolls_back_the_callers_work(world):
    """``_record_seq`` commits only an accepted request; a refusal rolls back whatever the caller did before it."""
    engine, _ = world
    with Session(engine) as s:
        s.add(CbomScanNode(id=9, team_id=1, owner_user_id=1, name="n9", node_token_hash="9" * 64, replay_hwm=_seq(),
                           replay_bits=1))
        s.commit()
    with Session(engine) as s:
        s.exec(update(CbomScanNode).where(CbomScanNode.id == 9).values(hostname="changed-before-the-refusal"))
        assert NA._record_seq(s, 9, _seq(-DAY_US), None) is False  # far below the window: refused
    with Session(engine) as s:
        assert s.get(CbomScanNode, 9).hostname is None


@needs_pg
def test_b1_settings_created_concurrently_during_a_heartbeat_do_not_lose_its_release(monkeypatch):
    """S-9: a heartbeat released a job (its node no longer reported it), then created the team's settings row at the
    same moment as another request: the IntegrityError rollback in get_or_create_settings discarded the release."""
    from backend.utilities.cbom_sources import jobs as J

    engine = F._pg_world()
    old = dt.datetime.utcnow() - dt.timedelta(seconds=600)
    with Session(engine) as s:
        node = CbomScanNode(team_id=1, owner_user_id=1, name="n", node_token_hash="1" * 64)
        s.add(node)
        s.commit()
        job = CbomCollectionJob(team_id=1, node_id=node.id, kind="test_connection", status="claimed", lease_id="a" * 24,
                                lease_expires_at=old + dt.timedelta(hours=1), claimed_at=old, attempts=1)
        s.add(job)
        s.exec(text("DELETE FROM cbomcollectionsettings WHERE team_id = 1"))
        s.commit()
        job_id, node_id = job.id, node.id
    real = SETTINGS.new_external_id

    def created_elsewhere():  # another request inserts and commits the row between our SELECT and our INSERT
        with Session(engine) as other:
            other.add(CbomCollectionSettings(team_id=1, aws_external_id=real(), ports=[443]))
            other.commit()
        return real()

    monkeypatch.setattr(SETTINGS, "new_external_id", created_elsewhere)
    with Session(engine) as s:  # the heartbeat's order: release, then the settings read
        node = s.get(CbomScanNode, node_id)
        released = J.renew_leases(s, node, dt.datetime.utcnow(), [], J.claimed_jobs(s, node))
        assert released == [job_id]
        settings = get_or_create_settings(s, 1, commit=False)
        assert settings.team_id == 1
        s.commit()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        assert job.status == "pending" and job.lease_id is None  # the release persisted


# ============================================================================= B2: S1 corrected (E4, E5, E8)
def test_b2_window_is_reachable_after_an_injected_sequence_and_a_reset_starts_it_again(api, world):
    """rv-sec41 probe 1, corrected: a far-future floor is refused by the node and a far-future sequence by the server;
    a high sequence inside the bound (a stolen key) does not lock the node out (it re-bases); after a Reset, a fresh
    install enrolls and the window starts at 0."""
    engine, _ = world
    node_id, client, key, _ = F._signed_node(api)
    top = (1 << 63) - 1
    fake = httpx.Response(403, headers={"X-ZS-Deployment": client.deployment_id, "X-ZS-Refused": "replay_window",
                                        "X-ZS-Seq-Next": str(top)})
    assert client._rebase(fake) is False  # S7: a floor far beyond this node's clock is ignored
    r = _post(api, "/cbom/node/heartbeat", key, client.token, top)
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "seq_out_of_range"
    assert int(r.headers["X-ZS-Seq-Next"]) >= _seq(-60_000_000)
    assert _hwm(engine, node_id) < top
    stolen = _seq(29 * DAY_US)  # inside the bound: accepted (a stolen key can do this)
    assert _post(api, "/cbom/node/heartbeat", key, client.token, stolen).status_code == 200
    node_api._SEQ[0] = _seq()  # the real node restarts: below the window, re-bases once, works
    assert "server_time" in client.heartbeat({})
    assert _hwm(engine, node_id) > stolen
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200, reset.text
    assert _hwm(engine, node_id) == 0
    key2 = ed25519.Ed25519PrivateKey.generate()
    fresh = node_api.Api("http://testserver", None, signing_key=key2)
    fresh.client, fresh._wait = api.client, (lambda seconds: None)
    node_api._SEQ[0] = _seq()
    data = fresh.enroll({"registration_token": reset.json()["registration_token"], "hostname": "dc-01",
                         "version": "1.2", "capabilities": {"collectors": ["linux_servers"], "protocol": 2},
                         "signing_public_key": base64.b64encode(key2.public_key().public_bytes_raw()).decode()})
    assert data["node_id"] == node_id
    assert _hwm(engine, node_id) == 0  # the enrollment does not step a window; the new credential starts at 0


def test_b2_a_request_verified_with_the_old_credential_and_committed_after_a_reset_is_refused(api, world, monkeypatch):
    """E5: the window UPDATE is bound to the credential, so a request in flight across a Reset cannot step the window
    the next enrollment starts with."""
    engine, _ = world
    node_id, client, key, _ = F._signed_node(api)
    real = NA._record_seq

    def reset_in_between(session, nid, seq, touch, key_b64=None, token_hash=None):
        with Session(engine) as admin:  # what the Reset route writes
            admin.exec(update(CbomScanNode).where(CbomScanNode.id == nid)
                       .values(node_token_hash=None, enrolled_at=None, replay_hwm=0, replay_bits=0))
            admin.commit()
        return real(session, nid, seq, touch, key_b64, token_hash)

    monkeypatch.setattr(NA, "_record_seq", reset_in_between)
    r = _post(api, "/cbom/node/heartbeat", key, client.token, _seq())
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "credential_changed"
    assert _hwm(engine, node_id) == 0


def test_b2_an_s2_nonce_beyond_2_63_is_refused_not_stored_as_a_protocol_1_nonce(api, world):
    """E8: ``s2_9999999999999999999`` used to fall back to a random nonce (an INSERT into cbomnodenonce)."""
    engine, _ = world
    _node_id, client, key, _ = F._signed_node(api)
    raw = b"{}"
    ts = str(int(time.time()))
    nonce = "s2_9999999999999999999"
    sig = key.sign(NA.signing_message("POST", "/cbom/node/heartbeat", ts, nonce, raw))
    r = api.client.post("/cbom/node/heartbeat", content=raw, headers={
        "X-ZS-Node-Token": client.token, "X-ZS-Timestamp": ts, "X-ZS-Nonce": nonce,
        "X-ZS-Signature": base64.b64encode(sig).decode(), "Content-Type": "application/json"})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_invalid"
    with Session(engine) as s:
        assert not s.exec(select(CbomNodeNonce).where(CbomNodeNonce.nonce == nonce)).all()


@pytest.mark.parametrize("days", [-40, 40])
def test_b2_a_node_clock_40_days_off_works_after_learning_the_skew(api, world, monkeypatch, days):
    """Guard (the S1 fix as first planned failed it): a node clock behind or ahead by 40 days."""
    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    assert "server_time" in client.heartbeat({})  # the window is at real time now
    real_time = time.time
    off = days * 86_400
    import types

    monkeypatch.setattr(node_api, "time", types.SimpleNamespace(  # the node's clock only, not the server's
        time=lambda: real_time() + off, time_ns=lambda: int((real_time() + off) * 1e9), monotonic=time.monotonic,
        sleep=time.sleep))
    node_api._SEQ[0] = int((real_time() + off) * 1_000_000) << node_api.SEQ_SHIFT  # restarted with the bad clock
    client.client = _WithDate(api.client)  # uvicorn sends Date; the test client does not
    client.skew = 0.0
    assert "server_time" in client.heartbeat({})
    assert abs(client.skew + off) < 120
    assert "server_time" in client.heartbeat({})  # and keeps working
    assert (_hwm(engine, node_id) >> NA.SEQ_SHIFT) <= real_time() * 1_000_000 + 30 * DAY_US


def test_b6_the_node_refuses_a_floor_more_than_30_days_ahead_of_its_corrected_clock(api, world):
    _node_id, client, _key, _ = F._signed_node(api)
    ahead = _seq(31 * DAY_US)
    resp = httpx.Response(403, headers={"X-ZS-Deployment": client.deployment_id, "X-ZS-Refused": "replay_window",
                                        "X-ZS-Seq-Next": str(ahead)})
    before = node_api._SEQ[0]
    assert client._rebase(resp) is False and node_api._SEQ[0] == before
    near = _seq(DAY_US)
    resp = httpx.Response(403, headers={"X-ZS-Seq-Next": str(near)})
    assert client._rebase(resp) is True and node_api._SEQ[0] == near - 1


def test_b6_a_claim_plugin_without_known_secrets_fails_at_load(monkeypatch):
    import sys
    import types

    from backend.utilities.cbom_sources import secret_refs as SR

    fake = types.ModuleType("zz_fake_claim_plugin")
    fake.claim_extras = lambda session, source, node, now, acc: acc
    fake.version_input = lambda session, source: None
    monkeypatch.setitem(sys.modules, "zz_fake_claim_plugin", fake)
    monkeypatch.setattr(SR, "PLUGINS", ("zz_fake_claim_plugin",))
    SR.reset_plugins()
    try:
        with pytest.raises(ImportError, match="known_secrets"):
            SR.plugins()
    finally:
        SR.reset_plugins()


# ============================================================================= B3: segment jobs need signed nodes
def test_b3_only_signed_agentless_nodes_take_segment_jobs(api, world):
    """rv-sec41 probe 5: the unsigned node of the segment gets 204 and no claim grant; the signed one gets the job."""
    engine, _ = world
    _uid, token = _unsigned_node(engine)
    _sid, signed, _k, _ = F._signed_node(api, "dc-signed", segment="DC")
    F._segment_sources(engine, 1)
    F._run(api)
    hb = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": token}, json={})
    assert hb.status_code == 200 and hb.json()["pending_jobs"] == 0 and hb.json()["claim"] == 0
    assert api.client.post("/cbom/node/jobs/claim", headers={"X-ZS-Node-Token": token}).status_code == 204
    payload = signed.claim()
    assert payload is not None and payload["job"]["kind"] == "collect"


def test_b3_a_segment_job_an_unsigned_node_held_before_the_change_goes_back_to_the_segment(api, world):
    engine, _ = world
    uid, token = _unsigned_node(engine)
    F._signed_node(api, "dc-signed", segment="DC")
    F._segment_sources(engine, 1)
    run_id = F._run(api)
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).one()
        job.status, job.node_id, job.lease_id, job.claimed_at, job.attempts = "claimed", uid, "c" * 24, now, 1
        job.lease_expires_at = now + dt.timedelta(minutes=15)
        s.add(job)
        s.commit()
        job_id = job.id
    hb = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": token},
                         json={"running": [{"job_id": job_id, "lease_id": "c" * 24}]})
    assert job_id in hb.json()["cancel_job_ids"]
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        assert (job.status, job.node_id, job.attempts) == ("pending", None, 0)  # handed back, never cancelled


def test_b3_planning_counts_only_signed_segment_nodes(api, world):
    engine, _ = world
    _unsigned_node(engine)
    F._segment_sources(engine, 1)
    overview = api("GET", "/1/cbom/sources/overview")
    assert overview.status_code == 200, overview.text
    assert "No enrolled, signed agentless scan node is in segment DC" in json.dumps(overview.json())


# ============================================================================= C: database contention (PostgreSQL)
import threading  # noqa: E402

from backend.new_models import CbomCollectionRun, CbomCollectionSource, Team  # noqa: E402,F811
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources.kinds import KINDS  # noqa: E402


def _pg_fleet(engine, jobs: int, *, weight: int = 10, kind: str = "collect", claimed: bool = True,
              lease_s: int = 900, attempts: int = 1) -> tuple[int, int, list[tuple[int, str]]]:
    """A node, ``jobs`` sources pinned to it, one run charged their weight, and its jobs (claimed by the node, or
    pending).  Returns (node id, run id, [(job id, lease id)])."""
    now = dt.datetime.utcnow()
    spec = KINDS["linux_servers"]
    with Session(engine) as s:
        node = CbomScanNode(team_id=1, owner_user_id=1, name=f"node-{time.time_ns()}", segment="DC",
                            node_token_hash=hashlib.sha256(str(time.time_ns()).encode()).hexdigest(),
                            signing_public_key="k" * 44, capabilities={"collectors": ["linux_servers"], "max_jobs": 2})
        s.add(node)
        s.flush()
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"r-{time.time_ns()}",
                                status="running" if claimed else "queued", credits_charged_c=jobs * weight)
        s.add(run)
        s.flush()
        out = []
        for i in range(jobs):
            src = None
            if kind == "collect":
                cfg = spec.model.model_validate({"targets": [f"10.7.{i // 250}.{i % 250 + 1}"], "window": "any"})
                src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name=f"p-{run.id}-{i}",
                                           name_lower=f"p-{run.id}-{i}", node_id=node.id,
                                           config=cfg.model_dump(mode="json"), last_test_status="passed")
                s.add(src)
                s.flush()
            lease = f"{i:024d}"
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id if src else None, node_id=node.id,
                                    kind=kind, weight_c=weight if kind == "collect" else 0,
                                    params={"conn_v": J.connection_version(src)} if src else {},
                                    status="claimed" if claimed else "pending",
                                    lease_id=lease if claimed else None,
                                    lease_expires_at=now + dt.timedelta(seconds=lease_s) if claimed else None,
                                    claimed_at=now if claimed else None, attempts=attempts if claimed else 0)
            s.add(job)
            s.flush()
            out.append((job.id, lease))
        s.commit()
        return node.id, run.id, out


class _LockSampler:
    """Samples pg_stat_activity every few ms for backends waiting on a lock in a statement on the run or team row.
    ``long`` counts waits older than 50 ms (what ``log_lock_waits`` reports at deadlock_timeout = 50 ms, the DA probe's
    setting); ``max`` is the most backends waiting at once, however briefly."""

    def __init__(self, engine) -> None:
        self.engine, self.max, self.long, self.samples, self._stop = engine, 0, 0, 0, threading.Event()
        self.queries: list[tuple[float, str]] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with self.engine.connect() as conn:
            while not self._stop.is_set():
                rows = conn.execute(text(
                    "SELECT extract(epoch FROM clock_timestamp() - query_start) * 1000, query FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock' "
                    "AND (query ILIKE '%cbomcollectionrun%' OR query ILIKE '%UPDATE team%')")).all()
                conn.commit()
                self.samples += 1
                self.max = max(self.max, len(rows))
                self.long += sum(1 for ms, _q in rows if float(ms) > 50)
                self.queries += [(round(float(ms), 1), q[:120]) for ms, q in rows]
                time.sleep(0.003)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.thread.join(5)


def _end_jobs(engine, node_id: int, jobs: list[tuple[int, str]], statuses: list[tuple[str, dict]],
              threads: int = 24) -> list[BaseException]:
    errors: list[BaseException] = []
    work = list(zip(jobs, statuses))
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker() -> None:
        try:
            barrier.wait(10)
            while True:
                with lock:
                    if not work:
                        return
                    (job_id, lease), (status, result) = work.pop()
                with Session(engine) as s:
                    node = s.get(CbomScanNode, node_id)
                    J.finish_job(s, node, job_id, lease, status, result, None if status == "success" else "x",
                                 dt.datetime.utcnow())
                    J.defer_closers(s)
                    s.commit()
                    J.run_closers(s)
        except BaseException as exc:  # pragma: no cover - reported by the caller
            errors.append(exc)

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(120)
    return errors


@needs_pg
def test_c1_300_successful_job_ends_at_the_tail_take_no_run_row_lock():
    """F2/C1: no blocking ``SELECT ... FROM cbomcollectionrun ... FOR UPDATE`` and no lock wait on the run row, while
    the run still closes once (``done``)."""
    from sqlalchemy import event

    engine = F._pg_world()
    node_id, run_id, jobs = _pg_fleet(engine, 300, kind="discovery")
    seen: list[str] = []
    listener = lambda *a: seen.append(a[2]) if "cbomcollectionrun" in a[2] and "FOR UPDATE" in a[2] else None  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        with _LockSampler(engine) as sampler:
            errors = _end_jobs(engine, node_id, jobs, [("success", {"counts": {"ok": 1}})] * len(jobs))
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert not errors, errors[:3]
    blocking = [q for q in seen if "SKIP LOCKED" not in q]
    assert blocking == [] and len(seen) <= 24  # only the closers that saw no open job probe the run row, never waiting
    assert sampler.max == 0 and sampler.samples > 10, sampler.queries[:5]
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "done"


@needs_pg
@pytest.mark.parametrize("m", [2, 4, 8])
def test_c1_the_last_jobs_ending_together_close_the_run_exactly_once(monkeypatch, m):
    """cx3 p4: 150 trials of m concurrent last job ends: 0 runs left open, 0 double winners."""
    engine = F._pg_world()
    real = J.close_run
    wins: list[int] = []
    wins_lock = threading.Lock()

    def counted(session, run_id, now):
        out = real(session, run_id, now)
        if out is not None:
            with wins_lock:
                wins.append(run_id)
        return out

    monkeypatch.setattr(J, "close_run", counted)
    open_runs = []
    for _trial in range(150):
        node_id, run_id, jobs = _pg_fleet(engine, m, kind="discovery")
        assert not _end_jobs(engine, node_id, jobs, [("success", {"counts": {"ok": 1}})] * m, threads=m)
        with Session(engine) as s:
            if s.get(CbomCollectionRun, run_id).status != "done":
                open_runs.append(run_id)
    assert open_runs == []
    assert sorted(wins) == sorted(set(wins)) and len(wins) == 150


def test_c1_a_job_end_whose_closer_never_ran_is_closed_by_one_reaper_pass(api, world):
    engine, _ = world
    _node_id, client, _key, _ = F._signed_node(api)
    F._segment_sources(engine, 1)
    run_id = F._run(api)
    payload = client.claim()
    with Session(engine) as s:  # the job end commits, the process "dies" before its closer runs
        node = s.get(CbomScanNode, _node_id)
        job = payload["job"]
        J.finish_job(s, node, job["id"], job["lease_id"], "success", {"counts": {"ok": 1}}, None, dt.datetime.utcnow())
        J.defer_closers(s)
        s.commit()
        s.info.clear()
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "running"
        assert J.reap(s, dt.datetime.utcnow()) == 1
        s.commit()
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "done"


def _mix(n: int) -> list[tuple[str, dict]]:
    """50% failure, 10% success with every target skipped (refund due), 40% success."""
    out = []
    for i in range(n):
        if i % 10 < 5:
            out.append(("failure", {"counts": {"failed": 1}}))
        elif i % 10 == 5:
            out.append(("success", {"counts": {"skipped": 1}}))
        else:
            out.append(("success", {"counts": {"ok": 1}}))
    return out


@needs_pg
def test_c2_failing_job_ends_take_no_lock_on_the_run_or_team_row_and_the_money_is_exact():
    """DA probe B: 300 concurrent job ends, 50% failure and 10% all-skipped, 24 threads: today 20.7 backends wait on
    the run and team rows; with refunds marked due and settled per run, none."""
    engine = F._pg_world()
    node_id, run_id, jobs = _pg_fleet(engine, 300)
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    with _LockSampler(engine) as sampler:
        errors = _end_jobs(engine, node_id, jobs, _mix(len(jobs)))
    assert not errors, errors[:3]
    assert sampler.max == 0 and sampler.samples > 10, sampler.queries[:5]
    with Session(engine) as s:
        due = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id,
                                                     CbomCollectionJob.refund_due == True)).all()  # noqa: E712
        assert len(due) == 180  # 150 failures + 30 all-skipped
        run = s.get(CbomCollectionRun, run_id)
        assert run.status == "partial" and run.credits_refunded_c == 1800  # the closer settled the ended run
        assert s.get(Team, 1).credit_balance == pytest.approx(before + 18.0, abs=1e-6 * 300)
        assert all(j.refunded for j in due)


@needs_pg
def test_c2_eight_concurrent_settlers_refund_each_job_exactly_once():
    """DA probe X: 8 threads settle the same 100 due jobs: the run delta equals the sum of weights, once."""
    engine = F._pg_world()
    _node_id, run_id, jobs = _pg_fleet(engine, 100, weight=20)
    with Session(engine) as s:
        s.exec(update(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)
               .values(status="failure", refund_due=True, lease_id=None))
        s.commit()
        before = s.get(Team, 1).credit_balance
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def settle() -> None:
        try:
            barrier.wait(10)
            with Session(engine) as s:
                J.settle_refunds(s, [run_id])
                s.commit()
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    pool = [threading.Thread(target=settle) for _ in range(8)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(60)
    assert not errors, errors
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).credits_refunded_c == 2000
        assert s.get(Team, 1).credit_balance == pytest.approx(before + 20.0, abs=1e-6)
        assert len(s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id,
                                                          CbomCollectionJob.refunded == True)).all()) == 100  # noqa: E712


@needs_pg
def test_c2_the_reaper_and_live_results_of_one_run_do_not_deadlock():
    """cx2 probe C: the reaper failing 150 jobs (third attempt, lease expired) in one pass while 150 live results of the
    same run arrive: with no run or team write in either, there is no lock cycle (it used to end in DeadlockDetected,
    a lost result and 409s for the node's retries)."""
    engine = F._pg_world()
    node_id, run_id, live = _pg_fleet(engine, 150)
    with Session(engine) as s:
        expired_at = dt.datetime.utcnow() - dt.timedelta(seconds=5)
        dead = []
        for i in range(150):
            job = CbomCollectionJob(team_id=1, run_id=run_id, node_id=node_id, kind="discovery", status="claimed",
                                    lease_id=f"d{i:023d}", lease_expires_at=expired_at, claimed_at=expired_at,
                                    attempts=J.MAX_ATTEMPTS)
            s.add(job)
            dead.append(job)
        s.commit()
    errors: list[BaseException] = []

    def reaper() -> None:
        try:
            with Session(engine) as s:
                J.reap(s, dt.datetime.utcnow(), limit=500)
                s.commit()
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=reaper)
    t.start()
    errors += _end_jobs(engine, node_id, live, _mix(len(live)), threads=16)
    t.join(60)
    assert not errors, [type(e).__name__ for e in errors[:3]]
    with Session(engine) as s:
        statuses = {j.status for j in s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).all()}
        assert "claimed" not in statuses


def test_c2_a_refund_due_job_is_settled_by_the_next_reaper_pass_once(api, world):
    from backend.workers.cbom_cloud_worker import reap_all

    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    F._segment_sources(engine, 2)
    run_id = F._run(api)
    p = client.claim()
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    F._finish(client, p, status="failure")  # the run still has a pending job: nothing is settled yet
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).credits_refunded_c == 0
        assert s.get(Team, 1).credit_balance == pytest.approx(before)
    reap_all(engine)
    reap_all(engine)
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        assert run.credits_refunded_c == run.credits_charged_c // 2
        assert s.get(Team, 1).credit_balance == pytest.approx(before + run.credits_refunded_c / 100)


@needs_pg
def test_c3_queue_run_holds_the_team_row_only_from_the_charge_to_the_commit(monkeypatch):
    """cx3 P5: a concurrent team UPDATE issued 50 ms after the charge, during a 3,000-job insert, waited 2.41 s."""
    from backend.utilities.cbom_sources import runs as RUNS
    from backend.utilities.cbom_sources.schemas import RunCreate

    engine = F._pg_world()
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = 1_000_000.0
        s.add(team)
        node = CbomScanNode(team_id=1, owner_user_id=1, name="seg", segment="DC", node_token_hash="2" * 64,
                            signing_public_key="k" * 44, enrolled_at=dt.datetime.utcnow(),
                            last_heartbeat_at=dt.datetime.utcnow())
        s.add(node)
        s.commit()
    F._segment_sources(engine, 3000)
    charged = threading.Event()
    real = J.charge_team
    marks: dict[str, float] = {}

    def charge(session, team_id, centi):
        ok = real(session, team_id, centi)
        marks["charged"] = time.perf_counter()
        charged.set()
        return ok

    monkeypatch.setattr(J, "charge_team", charge)
    waited: list[float] = []

    def other_update() -> None:
        charged.wait(60)
        time.sleep(0.05)
        t0 = time.perf_counter()
        with Session(engine) as s:
            s.exec(text("UPDATE team SET name = name WHERE id = 1"))
            s.commit()
        waited.append(time.perf_counter() - t0)

    t = threading.Thread(target=other_update)
    t.start()
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        body = RunCreate(include={"servers": True}, client_request_id="c3-" + str(time.time_ns()), soc_ack=True)
        marks["start"] = time.perf_counter()
        run, replayed = RUNS.queue_run(s, 1, 1, body, settings, dt.datetime.utcnow())
        run_id = run.id
        s.commit()
        assert not replayed
    t.join(60)
    with Session(engine) as s:
        assert len(s.exec(select(CbomCollectionJob.id).where(CbomCollectionJob.run_id == run_id)).all()) == 3000
    insert_s = marks["charged"] - marks["start"]  # planning and inserting 3,000 jobs: before the charge now
    # the team row is held from the charge to the commit only: the waiter (issued 50 ms after the charge) waits for
    # the commit, never for the insert (before: it waited for all of it, 2.41 s)
    assert waited and waited[0] < max(0.1, 0.25 * insert_s) and waited[0] < 0.5, (waited, insert_s)


@needs_pg
def test_c4_a_slow_claim_plugin_never_holds_the_node_row(monkeypatch):
    """S-10: ``last_claim_at`` was written (and the node row locked) before the claim plugins ran; a heartbeat of the
    same node waited for an SSH CA to mint.  Now the node row is the claim's last statement."""
    import types

    from backend.utilities.cbom_sources import secret_refs as SR

    engine = F._pg_world()
    node_id, _run_id, jobs = _pg_fleet(engine, 1, claimed=False)
    inside = threading.Event()

    def slow_extras(session, source, node, now, acc):
        session.exec(select(CbomCollectionSource.id).limit(1)).all()  # a real plugin reads its rows (autoflush)
        inside.set()
        time.sleep(1.0)
        return acc

    plugin = types.SimpleNamespace(__name__="slow_plugin", claim_extras=slow_extras,
                                   known_secrets=lambda session, source: [], version_input=lambda session, source: None)
    monkeypatch.setattr(SR, "_loaded", [plugin])
    from backend.routers import cbom_node as ROUTE

    monkeypatch.setattr(ROUTE, "get_db", lambda: engine)
    out: list = []

    def claim() -> None:
        with Session(engine) as s:
            node = s.get(CbomScanNode, node_id)
            out.append(J.claim_next(s, node, get_or_create_settings(s, 1, commit=False), dt.datetime.utcnow()))
            s.exec(update(CbomScanNode).where(CbomScanNode.id == node_id).values(last_claim_at=dt.datetime.utcnow()))
            s.commit()

    t = threading.Thread(target=claim)
    t.start()
    assert inside.wait(30)
    t0 = time.perf_counter()
    with Session(engine) as s:
        assert NA._record_seq(s, node_id, _seq(), {"last_seen_ip": "10.0.0.9"})
    took = time.perf_counter() - t0
    t.join(30)
    assert out and out[0] is not None
    assert took < 0.05, took


# ============================================================================= D1: one runnable predicate
from backend.utilities.cbom_sources import capabilities as CAPS  # noqa: E402
from backend.utilities.cbom_sources.settings import window_allows  # noqa: E402

CLOSED = [[False] * 24 for _ in range(7)]


def _close_team_window(engine, team_id: int = 1) -> None:
    with Session(engine) as s:
        settings = get_or_create_settings(s, team_id)
        settings.scan_window = CLOSED
        s.add(settings)
        s.commit()


def _pinned_jobs(engine, node_id: int, n: int, window: str = "network", start: int = 0, team_id: int = 1) -> list[int]:
    spec = KINDS["linux_servers"]
    ids = []
    with Session(engine) as s:
        for i in range(start, start + n):
            cfg = spec.model.model_validate({"targets": [f"10.6.{i // 250}.{i % 250 + 1}"], "window": window})
            src = CbomCollectionSource(team_id=team_id, owner_user_id=1, kind="linux_servers", name=f"w-{i}",
                                       name_lower=f"w-{i}", node_id=node_id, config=cfg.model_dump(mode="json"),
                                       last_test_status="passed")
            s.add(src)
            s.flush()
            job = CbomCollectionJob(team_id=team_id, source_id=src.id, node_id=node_id, kind="collect",
                                    params={"conn_v": J.connection_version(src)})
            s.add(job)
            s.flush()
            ids.append(job.id)
        s.commit()
    return ids


@needs_pg
def test_d1_closed_window_jobs_are_never_locked_or_hinted():
    """cx2 probe B / cx5 E3: 2,100 jobs outside their window and one ``any`` job: the hint says 1 (not 100) and the
    claim takes that job in at most 20 statements, locking at most 2 rows (2,001 rows were locked, 44 statements)."""
    from sqlalchemy import event

    engine = F._pg_world()
    _close_team_window(engine)
    node_id, _run, _jobs = _pg_fleet(engine, 0, claimed=False)
    _pinned_jobs(engine, node_id, 2100, window="network")
    target = _pinned_jobs(engine, node_id, 1, window="any", start=5000)[0]
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        settings = get_or_create_settings(s, 1)
        assert J.claimable_count(s, node, settings, dt.datetime.utcnow()) == 1
    stats = {"statements": 0, "locked": 0}

    def after(conn, cursor, statement, params, context, executemany):
        stats["statements"] += 1
        if "FOR UPDATE" in statement:
            stats["locked"] += max(cursor.rowcount, 0)

    event.listen(engine, "after_cursor_execute", after)
    try:
        with Session(engine) as s:
            node = s.get(CbomScanNode, node_id)
            payload = J.claim_next(s, node, get_or_create_settings(s, 1), dt.datetime.utcnow())
            s.commit()
    finally:
        event.remove(engine, "after_cursor_execute", after)
    assert payload["job"]["id"] == target
    assert stats["statements"] <= 20 and stats["locked"] <= 2, stats


def test_d1_all_jobs_outside_the_window_hint_nothing(api, world):
    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    _close_team_window(engine)
    _pinned_jobs(engine, node_id, 30, window="network")
    hb = client.heartbeat({})
    assert hb["pending_jobs"] == 0 and hb["claim"] == 0
    assert client.claim() is None


def test_d1_a_node_without_the_capability_is_not_hinted(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setitem(CAPS._BY_KIND, "linux_servers", "cap_x")
    plain_id, plain, _k1, _ = F._signed_node(api, "plain")
    _pinned_jobs(engine, plain_id, 3, window="any")
    hb = plain.heartbeat({})
    assert hb["pending_jobs"] == 0 and hb["claim"] == 0 and plain.claim() is None
    able_id, able, _k2, _ = F._signed_node(api, "able")
    with Session(engine) as s:
        node = s.get(CbomScanNode, able_id)
        node.capabilities = {"collectors": ["linux_servers", "cap_x"], "protocol": 2}
        s.add(node)
        s.commit()
    _pinned_jobs(engine, able_id, 1, window="any", start=100)
    assert able.heartbeat({"capabilities": {"collectors": ["linux_servers", "cap_x"], "protocol": 2}})["claim"] == 1
    assert able.claim() is not None


def test_d1_blocked_pinned_jobs_never_hide_a_segment_job(api, world):
    """cx5 E11: 2,500 pinned jobs outside their window filled the claim's scan budget before the segment set."""
    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api, "busy", segment="DC")
    _close_team_window(engine)
    _pinned_jobs(engine, node_id, 2500, window="network")
    F._segment_sources(engine, 1)
    with Session(engine) as s:
        src = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.node_segment == "DC")).one()
        job = CbomCollectionJob(team_id=1, source_id=src.id, node_segment="DC", kind="collect",
                                params={"conn_v": J.connection_version(src)})
        s.add(job)
        s.commit()
        seg_id = job.id
    payload = client.claim()
    assert payload is not None and payload["job"]["id"] == seg_id


def test_d1_a_waiting_segment_job_says_what_it_waits_for(world):
    engine, _ = world
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        job = CbomCollectionJob(team_id=1, node_segment="DC", kind="test_connection", status="pending")
        reason = J.job_waiting_reason(job, None, settings, dt.datetime.utcnow())
    assert reason != "Queued for the ZeroShield cloud worker" and "segment DC" in reason


@pytest.mark.parametrize("pg", [False, pytest.param(True, marks=needs_pg)])
def test_d1_the_sql_window_matches_window_allows_for_every_hour(world, pg):
    """Parity: the Python window check and the SQL predicate agree over 168 weekday-hours x {any, team, custom} x 3
    time zones (random grids)."""
    import random as _random

    engine = F._pg_world() if pg else world[0]
    rnd = _random.Random(7)
    team_grid = [[rnd.random() < 0.5 for _ in range(24)] for _ in range(7)]
    custom_grid = [[rnd.random() < 0.5 for _ in range(24)] for _ in range(7)]
    spec = KINDS["linux_servers"]
    with Session(engine) as s:
        node = CbomScanNode(team_id=1, owner_user_id=1, name="parity", node_token_hash="3" * 64)
        s.add(node)
        s.flush()
        import types as _types

        sources = {}
        for kind in ("any", "network", "custom"):  # "network": the team's window
            cfg = {"targets": ["10.5.0.1"], "window": kind}
            if kind == "custom":
                cfg["custom_window"] = custom_grid
            cfg = spec.model.model_validate(cfg).model_dump(mode="json")
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name=f"par-{kind}",
                                       name_lower=f"par-{kind}", node_id=node.id, config=cfg, last_test_status="passed")
            s.add(src)
            s.flush()
            s.add(CbomCollectionJob(team_id=1, source_id=src.id, node_id=node.id, kind="collect"))
            sources[kind] = _types.SimpleNamespace(kind=src.kind, config=dict(src.config or {}))
        s.commit()
        node_id = node.id
    base = dt.datetime(2026, 11, 9, 0, 30)  # a Monday, UTC
    mismatches = []
    for tz in ("UTC", "Asia/Kolkata", "America/New_York"):
        with Session(engine) as s:
            settings = get_or_create_settings(s, 1)
            settings.scan_window, settings.window_timezone = team_grid, tz
            s.add(settings)
            s.commit()
        with Session(engine) as s:
            settings = get_or_create_settings(s, 1)
            node = s.get(CbomScanNode, node_id)
            for h in range(168):
                now = base + dt.timedelta(hours=h)
                want = sum(window_allows(J._job_window(src, settings), tz, now) for src in sources.values())
                got = J.claimable_count(s, node, settings, now)
                if want != got:
                    mismatches.append((tz, h, want, got))
    assert mismatches == []


# ============================================================================= D2: dispatch
def _virtual(start: float = 1000.0):
    clock = {"t": start}
    return clock, (lambda: clock["t"])


def test_d2_hint_fan_out_through_the_real_routers_is_bounded_by_the_rate(api, world, monkeypatch):
    """1,000 nodes of one segment, all with work waiting (a 1,000-job run), W = 0: a node posts its result at once
    and claims again within its grants; heartbeats keep coming (every 5 virtual seconds here).  Claims stay within
    1.1 x rate in every 1 s window (today every hinted node claims at once, and again after each result)."""
    import secrets as _secrets

    engine, _ = world
    rate, nodes_n = 20, 1000
    clock, now = _virtual()
    D.reset(D.Dispatcher(rate, clock=now, start_full=False))
    key = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    nodes = []
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = 10_000.0
        s.add(team)
        for i in range(nodes_n):
            token = "zsn_" + _secrets.token_urlsafe(24)
            s.add(CbomScanNode(team_id=1, owner_user_id=1, name=f"fan-{i}", segment="DC", enrolled_at=dt.datetime.utcnow(),
                               node_token_hash=hashlib.sha256(token.encode()).hexdigest(), signing_public_key=pub,
                               capabilities={"collectors": ["linux_servers"], "max_jobs": 2, "protocol": 2}))
            nodes.append([token, 0])  # token, grants
        s.commit()
    F._segment_sources(engine, nodes_n)
    F._run(api)
    base_seq = _seq()
    counter = [0]

    def call(token, path, body=None):
        counter[0] += 1
        return _post(api, path, key, token, base_seq + counter[0], body)

    claims_per_window: dict[int, int] = {}
    for step in range(50):  # 5 virtual seconds in 0.1 s steps; every node beats once in them
        clock["t"] = 1000.0 + step * 0.1
        window = int(clock["t"] - 1000.0)
        for node in nodes[step * 20:(step + 1) * 20]:
            node[1] = call(node[0], "/cbom/node/heartbeat").json()["claim"]
        for node in nodes:
            while node[1] > 0:
                node[1] -= 1
                r = call(node[0], "/cbom/node/jobs/claim")
                if r.status_code != 200:
                    node[1] = 0
                    break
                claims_per_window[window] = claims_per_window.get(window, 0) + 1
                job = r.json()["job"]
                done = call(node[0], f"/cbom/node/jobs/{job['id']}/result",
                            {"lease_id": job["lease_id"], "status": "success", "result": {"counts": {"ok": 1}}})
                node[1] = r.json()["claim"] + done.json()["claim"]
    assert claims_per_window and max(claims_per_window.values()) <= 1.1 * rate, claims_per_window
    assert sum(claims_per_window.values()) >= 4 * rate, claims_per_window  # and it does dispatch at the rate


def test_d2_a_protocol_1_claim_with_an_empty_bucket_is_204_without_reading_the_queue(api, world, monkeypatch):
    engine, _ = world
    clock, now = _virtual()
    D.reset(D.Dispatcher(5, clock=now, start_full=False))
    _uid, token = _unsigned_node(engine, "p1-node", segment="")
    calls = []
    monkeypatch.setattr(J, "claim_next", lambda *a, **k: calls.append(1))
    r = api.client.post("/cbom/node/jobs/claim", headers={"X-ZS-Node-Token": token})
    assert r.status_code == 204 and calls == []


def test_d2_a_forged_max_jobs_buys_at_most_8_claims(api, world):
    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    _pinned_jobs(engine, node_id, 30, window="any")
    hb = client.heartbeat({"capabilities": {"collectors": ["linux_servers"], "max_jobs": 1_000_000, "protocol": 2}})
    assert 1 <= hb["claim"] <= 8 and hb["pending_jobs"] == 30


def test_d2_a_claim_that_finds_nothing_returns_its_permit(api, world):
    _node_id, client, _key, _ = F._signed_node(api)
    clock, now = _virtual()
    dispatcher = D.Dispatcher(10, clock=now, start_full=True)
    D.reset(dispatcher)
    level = dispatcher.level()
    assert client.claim() is None
    assert dispatcher.level() == level and dispatcher.counters["dispatch_returned"] == 1


def test_d2_one_team_draining_the_bucket_cannot_starve_another_team():
    """Max-min share: team A's 2,000 nodes saturate the worker's bucket; team B's single job is granted within one
    heartbeat interval (a single bucket made it wait 47-250 s, cx5 E10)."""
    import random as _random

    clock, now = _virtual()
    d = D.Dispatcher(25, clock=now, start_full=True)
    rnd = _random.Random(5)
    beats = sorted((rnd.uniform(0, 60), n) for n in range(2000))  # A's heartbeats over one 60 s interval
    b_at, b_granted = 10.0, None
    i = 0
    t = 0.0
    while t < 72.0 and b_granted is None:
        t += 0.01
        clock["t"] = 1000.0 + t
        while i < len(beats) and beats[i][0] <= t:
            n = d.grant(beats[i][1], 1, 2)
            for _ in range(n):  # A's nodes claim, finish at once, and are granted again: A wants everything
                d.admit(beats[i][1], 1)
            i += 1
            if i >= len(beats):
                i, beats = 0, [(b + 60.0, n) for b, n in beats]
        if t >= b_at and b_granted is None and d.grant(99_999, 2, 1) > 0:
            b_granted = t
    assert b_granted is not None and b_granted - b_at <= 72.0


# ============================================================================= D3, D4, D5
def test_d3_an_undelivered_claim_is_handed_back_at_once_without_counting_the_attempt(api, world):
    """cx4 P2: the node gave up (disconnected) while its claim was being served; the job used to stay claimed for
    120 s and then count an attempt."""
    import asyncio

    from backend.main import app

    engine, _ = world
    node_id, client, key, _ = F._signed_node(api)
    job_id = _pinned_jobs(engine, node_id, 1, window="any")[0]
    raw = b""
    headers = F._p2_headers(key, "POST", "/cbom/node/jobs/claim", raw, client.token, _seq())
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": "/cbom/node/jobs/claim", "raw_path": b"/cbom/node/jobs/claim",
             "query_string": b"", "root_path": "", "client": ("10.0.0.5", 5000), "server": ("testserver", 80),
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    sent: list[dict] = []
    messages = [{"type": "http.request", "body": raw, "more_body": False}, {"type": "http.disconnect"}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    before = OBS.STATS.totals.get("undelivered", 0)
    asyncio.run(app(scope, receive, send))
    assert OBS.STATS.totals.get("undelivered", 0) == before + 1
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        assert (job.status, job.node_id, job.attempts, job.lease_id) == ("pending", node_id, 0, None)


def test_d4_the_lease_never_falls_below_the_heartbeat_floor(monkeypatch):
    monkeypatch.setenv("CBOM_JOB_LEASE_S", "60")
    assert LIM.lease_seconds() >= 600
    monkeypatch.setenv("CBOM_JOB_LEASE_S", "86400")
    assert LIM.lease_seconds() == 86400
    monkeypatch.setenv("CBOM_NODE_HEARTBEAT_S", "3600")
    monkeypatch.setenv("CBOM_JOB_LEASE_S", "60")
    assert LIM.lease_seconds() >= 3 * 1.2 * 600  # nodes honour at most 600 s


def test_d4_a_busy_node_whose_heartbeats_time_out_three_times_keeps_its_job(api, world, monkeypatch):
    """rv-sec41 probe 4 with CBOM_JOB_LEASE_S=60, on the real renew and reap: the node claims, its next three
    heartbeats time out (62 s each: 30 s timeout + one retry), and the reaper runs every 30 s meanwhile."""
    monkeypatch.setenv("CBOM_JOB_LEASE_S", "60")
    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    job_id = _pinned_jobs(engine, node_id, 1, window="any")[0]
    payload = client.claim()
    assert payload["job"]["lease_seconds"] >= 600
    t0 = dt.datetime.utcnow()
    for k in range(1, 9):  # reaper passes at +30 s ... +240 s
        with Session(engine) as s:
            assert J.reap(s, t0 + dt.timedelta(seconds=30 * k)) == 0
            s.commit()
    with Session(engine) as s:  # the fourth heartbeat gets through at about 36 + 3 x 62 s = 222 s
        node = s.get(CbomScanNode, node_id)
        at = t0 + dt.timedelta(seconds=222)
        J.renew_leases(s, node, at, [(job_id, payload["job"]["lease_id"])], J.claimed_jobs(s, node))
        s.commit()
        job = s.get(CbomCollectionJob, job_id)
        assert job.status == "claimed" and job.lease_id == payload["job"]["lease_id"] and job.lease_expires_at > at


def test_d5_claims_and_enrollments_are_shed_first_heartbeats_and_results_never(api, world, monkeypatch):
    from sqlalchemy import event

    engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    monkeypatch.setenv("CBOM_NODE_MAX_INFLIGHT", "10")
    monkeypatch.setattr(OBS.STATS, "inflight", 100)  # ten times the threshold already in flight on this worker
    statements = [0]
    listener = lambda *a: statements.__setitem__(0, statements[0] + 1)  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        r = api.client.post("/cbom/node/jobs/claim", headers={"X-ZS-Node-Token": client.token})
        e = api.client.post("/cbom/node/enroll", json={"registration_token": "zsr_x"})
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert r.status_code == 429 and 5 <= int(r.headers["Retry-After"]) <= 15 and e.status_code == 429
    assert statements[0] == 0 and r.headers.get("X-ZS-Deployment")
    assert "server_time" in client.heartbeat({})  # never shed
    monkeypatch.setattr(OBS.STATS, "inflight", 0)
    job_id = _pinned_jobs(engine, node_id, 1, window="any")[0]
    p = client.claim()
    monkeypatch.setattr(OBS.STATS, "inflight", 100)
    assert F._finish(client, p)["job_id"] == job_id  # never shed


# ============================================================================= E: per-request cost
def test_e1_a_cache_hit_slides_the_expiry(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(H.time, "monotonic", lambda: clock["t"])
    H._NODE_KEYS.clear()
    H._remember_node_id("d1", 7)
    for _ in range(10):
        clock["t"] += H.NODE_KEY_TTL_S - 1
        assert H._cached_node_id("d1") == 7  # each hit pushes the expiry further
    clock["t"] += H.NODE_KEY_TTL_S + 1
    assert H._cached_node_id("d1") is None


def test_e1_one_node_on_nine_workers_misses_at_most_1_percent(monkeypatch):
    """The 85% miss rate on EC2 was fragmentation x absolute expiry: one cache per worker, nodes beating every
    48-72 s on a random worker.  Two virtual hours, 9 workers."""
    import random as _random

    rnd = _random.Random(11)
    clock = {"t": 0.0}
    monkeypatch.setattr(H.time, "monotonic", lambda: clock["t"])
    caches = [dict() for _ in range(9)]
    lookups = misses = 0
    while clock["t"] < 7200:
        clock["t"] += rnd.uniform(48, 72)
        w = rnd.randrange(9)
        monkeypatch.setattr(H, "_NODE_KEYS", caches[w].setdefault("od", __import__("collections").OrderedDict()))
        lookups += 1
        if H._cached_node_id("node") is None:
            misses += 1
            H._remember_node_id("node", 1)
    assert misses / lookups <= 0.01 + 9 / lookups  # one cold miss per worker, then hits


def test_e1_after_a_reset_the_old_token_is_charged_to_its_address(api, world):
    _engine, _ = world
    node_id, client, _key, _ = F._signed_node(api)
    H._NODE_KEYS.clear()
    assert "server_time" in client.heartbeat({})
    digest = hashlib.sha256(client.token.encode()).hexdigest()
    assert H._cached_node_id(digest) == node_id
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/reset").status_code == 200
    r = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": client.token}, json={})
    assert r.status_code == 401 and r.headers["X-ZS-Refused"] == "node_token_revoked"
    assert H._cached_node_id(digest) is None  # evicted: the next request is charged to the address


def test_e2_node_requests_never_borrow_the_global_threadpool(api, world):
    """200 concurrent node requests run on the node limiter; the process-wide anyio limiter the other 56 call sites
    share stays at 0 borrowed."""
    import asyncio

    import anyio.to_thread

    from backend.main import app

    _engine, _ = world
    _node_id, client, key, _ = F._signed_node(api)
    peak = [0]

    async def main():
        transport = httpx.ASGITransport(app=app)
        limiter = anyio.to_thread.current_default_thread_limiter()
        stop = asyncio.Event()

        async def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], limiter.statistics().borrowed_tokens)
                await asyncio.sleep(0.001)

        sampler = asyncio.create_task(sample())
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            base = _seq()
            reqs = []
            for i in range(200):
                raw = b"{}"
                h = F._p2_headers(key, "POST", "/cbom/node/heartbeat", raw, client.token, base + i)
                reqs.append(http.post("/cbom/node/heartbeat", headers=h, content=raw))
            out = await asyncio.gather(*reqs)
        stop.set()
        await sampler
        return out

    out = asyncio.run(main())
    # 200 requests of one node in flight at once arrive in any order: those more than 63 behind are refused (403)
    # (and those over the node's 120-a-minute budget get 429 from the rate limiter)
    assert all(r.status_code in (200, 403, 429) for r in out) and sum(r.status_code == 200 for r in out) >= 63
    assert peak[0] == 0


def test_e4_a_protocol_2_heartbeat_does_not_sweep_nonces(api, world):
    from sqlalchemy import event

    engine, _ = world
    _node_id, client, _key, _ = F._signed_node(api)
    NA._SWEPT[0] = 0.0
    seen: list[str] = []
    listener = lambda *a: seen.append(a[2]) if "cbomnodenonce" in a[2].lower() else None  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        client.heartbeat({})
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert not [q for q in seen if q.upper().startswith("DELETE")]


# ============================================================================= A1: instrumentation
def test_a1_every_node_response_carries_server_timing_and_a_request_id(api, world):
    _engine, _ = world
    _node_id, client, key, _ = F._signed_node(api)
    raw = b"{}"
    h = F._p2_headers(key, "POST", "/cbom/node/heartbeat", raw, client.token, _seq())
    ok = api.client.post("/cbom/node/heartbeat", headers={**h, "X-ZS-Request-Id": "trace-abc.123"}, content=raw)
    bad = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": "zsn_" + "q" * 30}, json={})
    none = api.client.post("/cbom/node/jobs/claim", headers=F._p2_headers(key, "POST", "/cbom/node/jobs/claim", b"",
                                                                         client.token, _seq() + 1))
    for r in (ok, bad, none):
        timing = r.headers.get("Server-Timing", "")
        assert "app;dur=" in timing and "tp;dur=" in timing and "pool;dur=" in timing, (r.status_code, timing)
        assert r.headers.get("X-ZS-Request-Id")
    assert (ok.status_code, bad.status_code, none.status_code) == (200, 401, 204)
    assert ok.headers["X-ZS-Request-Id"] == "trace-abc.123"


def test_a1_a_claim_whose_commit_fails_is_not_logged_as_claimed(api, world, capsys, monkeypatch):
    from sqlalchemy import event

    engine, _ = world
    node_id, client, key, _ = F._signed_node(api)
    _pinned_jobs(engine, node_id, 1, window="any")
    real = J.claim_next

    def claim_then_fail_commit(session, node, settings, now):
        out = real(session, node, settings, now)

        def fail(_session):
            raise RuntimeError("injected commit failure")

        event.listen(session, "before_commit", fail, once=True)
        return out

    monkeypatch.setattr(J, "claim_next", claim_then_fail_commit)
    capsys.readouterr()
    r = api.client.post("/cbom/node/jobs/claim",
                        headers=F._p2_headers(key, "POST", "/cbom/node/jobs/claim", b"", client.token, _seq()))
    assert r.status_code == 500
    out = capsys.readouterr().out
    assert "cbom node claim FAILED" in out and "job claimed" not in out


# ============================================================================= E3: one connection per request
def test_e3_a_heartbeat_takes_one_connection_from_the_pool(api, world):
    from sqlalchemy import event

    engine, _ = world
    _node_id, client, _key, _ = F._signed_node(api)
    client.heartbeat({})
    checkouts = [0]
    listener = lambda *a: checkouts.__setitem__(0, checkouts[0] + 1)  # noqa: E731
    event.listen(engine, "checkout", listener)
    try:
        client.heartbeat({})
    finally:
        event.remove(engine, "checkout", listener)
    assert checkouts[0] == 1


def test_e3_the_helper_refuses_a_connection_that_already_ran_a_statement(world):
    engine, _ = world
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        with pytest.raises(RuntimeError, match="fresh connection"):
            NA.bind_fresh(conn)


@needs_pg
def test_e3_the_window_step_is_committed_before_the_work_and_survives_its_failure(monkeypatch):
    """cx3 S-1 trio on the bound connection: the window advance is visible from another connection before the work;
    the node row is not held during the work (NOWAIT succeeds); a request whose work fails (500) cannot be replayed
    (the same signed bytes get 403)."""
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.routers import cbom_node as ROUTE

    engine = F._pg_world()
    key = ed25519.Ed25519PrivateKey.generate()
    token = "zsn_" + __import__("secrets").token_urlsafe(24)
    with Session(engine) as s:
        node = CbomScanNode(team_id=1, owner_user_id=1, name="bound", node_token_hash=hashlib.sha256(token.encode()).hexdigest(),
                            signing_public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                            enrolled_at=dt.datetime.utcnow(), capabilities={"protocol": 2})
        s.add(node)
        s.commit()
        node_id = node.id
    from backend.utilities.cbom_sources import http as CBOM_HTTP

    for module in (ROUTE, NA, CBOM_HTTP):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (CBOM_HTTP.node_limiter, CBOM_HTTP.enroll_limiter):
        limiter.requests.clear()
    seen: dict = {}
    real = J.claimed_jobs

    def during_work(session, node):
        with engine.connect() as other:
            seen["hwm"] = other.execute(text(f"SELECT replay_hwm FROM cbomscannode WHERE id = {node_id}")).scalar()
            other.execute(text(f"SELECT id FROM cbomscannode WHERE id = {node_id} FOR UPDATE NOWAIT"))
            other.rollback()
        if seen.get("fail"):
            raise RuntimeError("the work fails")
        return real(session, node)

    monkeypatch.setattr(J, "claimed_jobs", during_work)
    seq = _seq()
    raw = b"{}"
    headers = F._p2_headers(key, "POST", "/cbom/node/heartbeat", raw, token, seq)
    client = TestClient(app)  # no lifespan: the test JWT secrets are short
    assert client.post("/cbom/node/heartbeat", headers=headers, content=raw).status_code == 200
    assert seen["hwm"] == seq
    seen["fail"] = True
    headers = F._p2_headers(key, "POST", "/cbom/node/heartbeat", raw, token, seq + 1)
    assert client.post("/cbom/node/heartbeat", headers=headers, content=raw).status_code == 500
    assert client.post("/cbom/node/heartbeat", headers=headers, content=raw).status_code == 403
