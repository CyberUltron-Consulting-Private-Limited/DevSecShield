"""F1.1 lean node API: replay window without a nonce row, server-driven heartbeat with a claim hint, run status without
reading every job, segment jobs claimed by any node of a segment (SKIP LOCKED on PostgreSQL), lease re-queue,
configurable caps, the extension points other parts plug into, and the scan node 1.0 client against the new server.

SQLite + the real routers (the test_cbom_sources_api harness).  The PostgreSQL tests run when CBOM_TEST_PG_URL is set
(CI sets it): concurrent claims of one segment, the last two jobs of a run ending at once, the replay window SQL.

    cd backend && PYTHONPATH=..:../scan_node JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x \\
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 python -m pytest tests/test_cbom_f1_node_api.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import os
import random
import secrets
import sys
import threading
import time
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))  # the real node client
import test_cbom_sources_api as base  # noqa: E402  (its SQLite world and API client fixtures)

from backend.new_models import (  # noqa: E402
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomNodeNonce,
    CbomScanNode,
    Team,
    TeamMembership,
    User,
)
from backend.routers import cbom_node  # noqa: E402
from backend.utilities.cbom_sources import capabilities as CAPS  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import limits as LIM  # noqa: E402
from backend.utilities.cbom_sources import node_auth as NA  # noqa: E402
from backend.utilities.cbom_sources import secret_refs as SR  # noqa: E402
from backend.utilities.cbom_sources.kinds import KINDS  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402
from zs_scan_node import api as node_api  # noqa: E402

PG_URL = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG_URL, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
api, world, enroll_node = base.api, base.world, base.enroll_node  # fixtures, used by name
LEGACY_API = Path(__file__).resolve().parent / "fixtures/scan_node_1_0/api.py"  # dev 3399452, verbatim


# ----------------------------------------------------------------------------- helpers
def _p2_headers(key, method: str, path: str, body: bytes, token: str, seq: int, ts: int | None = None) -> dict:
    ts_s = str(int(time.time()) if ts is None else ts)
    nonce = f"s2_{seq:019d}"
    sig = key.sign(NA.signing_message(method, path, ts_s, nonce, body))
    return {"X-ZS-Node-Token": token, "X-ZS-Timestamp": ts_s, "X-ZS-Nonce": nonce,
            "X-ZS-Signature": base64.b64encode(sig).decode(), "Content-Type": "application/json"}


def _signed_node(api, name="dc-01", segment="DC", client_cls=None, protocol=2):
    """A node created through the API and enrolled with a signing key by the real node client (protocol 2)."""
    r = api("POST", "/1/cbom/sources/nodes", json={"name": name, "segment": segment})
    assert r.status_code == 201, r.text
    node_id, reg = r.json()["node"]["id"], r.json()["registration_token"]
    key = ed25519.Ed25519PrivateKey.generate()
    client = (client_cls or node_api.Api)("http://testserver", None, signing_key=key)
    client.client = api.client
    client._wait = lambda seconds: None
    caps = {"collectors": ["linux_servers"], **({"protocol": 2} if protocol >= 2 else {})}
    data = client.enroll({"registration_token": reg, "hostname": name, "version": "1.2" if protocol >= 2 else "1.0.0",
                          "capabilities": caps,
                          "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    client.token, client.deployment_id = data["node_token"], data["deployment_id"]
    return node_id, client, key, data


def _segment_sources(engine, n: int, segment: str = "DC", team_id: int = 1) -> list[int]:
    spec = KINDS["linux_servers"]
    ids = []
    with Session(engine) as s:
        for i in range(n):
            cfg = spec.model.model_validate({"targets": [f"10.9.{i // 250}.{i % 250 + 1}"], "window": "any"})
            src = CbomCollectionSource(team_id=team_id, owner_user_id=1, kind="linux_servers", name=f"seg-{i}",
                                       name_lower=f"seg-{i}", node_id=None, node_segment=segment,
                                       config=cfg.model_dump(mode="json"), last_test_status="passed")
            s.add(src)
            s.flush()
            ids.append(src.id)
        s.commit()
    return ids


def _run(api) -> int:
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "soc_ack": True,
                                                  "client_request_id": "f1-" + secrets.token_hex(8)})
    assert r.status_code == 201, r.text
    return r.json()["run"]["id"]


def _finish(client, payload, status="success"):
    job = payload["job"]
    return client.result(job["id"], job["attempt"], {"lease_id": job["lease_id"], "status": status,
                                                     "result": {"counts": {"ok": 1}}, "error": None})


# ----------------------------------------------------------------------------- replay window
def test_window_reference_accepts_reordering_and_refuses_repeats_and_old_sequences():
    hwm = bits = 0
    seen = set()
    rnd = random.Random(11)
    seqs = list(range(1_000, 1_400))
    for i in range(0, len(seqs) - 8, 8):  # shuffle within blocks of 8: requests that overtake each other
        block = seqs[i:i + 8]
        rnd.shuffle(block)
        seqs[i:i + 8] = block
    for seq in seqs:
        ok, hwm, bits = NA.window_accepts(hwm, bits, seq)
        assert ok, seq
        seen.add(seq)
        again, hwm2, bits2 = NA.window_accepts(hwm, bits, seq)
        assert not again and (hwm2, bits2) == (hwm, bits)
    assert not NA.window_accepts(hwm, bits, hwm - NA.REPLAY_WINDOW)[0]  # below the window: refused
    assert NA.window_accepts(hwm, bits, hwm + 10_000)[0]  # a big jump (a restart) is accepted
    assert bits < (1 << NA.REPLAY_WINDOW)


def _window_db_matches_reference(engine):
    with Session(engine) as s:
        s.add(Team(id=1, name="t"))
        s.commit()
        s.add(User(id=1, email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None))
        s.commit()
        s.add(CbomScanNode(id=5, team_id=1, owner_user_id=1, name="n", node_token_hash="h" * 64))
        s.commit()
    rnd = random.Random(3)
    hwm = bits = 0
    base = 3_600_000_000_000_000_000
    seqs = [base + i for i in range(300)]
    seqs += [base + rnd.randrange(0, 300) for _ in range(200)]  # repeats
    seqs += [base + 500 + rnd.randrange(0, 80) for _ in range(200)]  # reordered inside and across the window
    seqs += [base + 10_000, base + 9_999, base + 9_000, base + 9_937, base + 9_938]  # edges of the window
    for seq in seqs:
        want, hwm, bits = NA.window_accepts(hwm, bits, seq)
        with Session(engine) as s:
            got = NA._record_seq(s, 5, seq, {"last_seen_ip": "10.0.0.1"})
        assert got == want, seq
        with Session(engine) as s:
            node = s.get(CbomScanNode, 5)
            assert (node.replay_hwm, node.replay_bits) == (hwm, bits), seq


def test_window_sql_matches_the_reference_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'w.db'}")
    SQLModel.metadata.create_all(engine)
    _window_db_matches_reference(engine)


@needs_pg
def test_window_sql_matches_the_reference_postgres():
    engine = create_engine(PG_URL)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    _window_db_matches_reference(engine)


def test_protocol2_replay_is_refused_without_a_nonce_row(api, world):
    engine, _ = world
    node_id, client, key, _data = _signed_node(api)
    body = b'{"version":"1.2"}'
    path = "/cbom/node/heartbeat"
    with Session(engine) as s:
        before = len(s.exec(select(CbomNodeNonce)).all())
    seq = 3_700_000_000_000_000_000
    first = _p2_headers(key, "POST", path, body, client.token, seq)
    assert api.client.post(path, headers=first, content=body).status_code == 200
    replay = api.client.post(path, headers=first, content=body)  # the captured request, byte for byte
    assert replay.status_code == 403 and replay.headers["X-ZS-Refused"] == "replay"
    # overtaken requests inside the window are accepted, each exactly once
    for s_ in (seq + 5, seq + 3, seq + 4, seq + 1):
        h = _p2_headers(key, "POST", path, body, client.token, s_)
        assert api.client.post(path, headers=h, content=body).status_code == 200
        assert api.client.post(path, headers=h, content=body).headers["X-ZS-Refused"] == "replay"
    old = api.client.post(path, headers=_p2_headers(key, "POST", path, body, client.token, seq - 200), content=body)
    assert old.status_code == 403 and old.headers["X-ZS-Refused"] == "replay_window"
    assert int(old.headers["X-ZS-Seq-Next"]) == seq + 6
    with Session(engine) as s:
        assert len(s.exec(select(CbomNodeNonce)).all()) == before  # no nonce row for protocol 2
        node = s.get(CbomScanNode, node_id)
        assert node.replay_hwm == seq + 5 and node.last_seen_ip


def test_a_replay_to_another_worker_is_refused_too(api, world, tmp_path, monkeypatch):
    """Two workers = two engines (two connection pools) on one database: the window is in the shared row."""
    engine_a, _ = world
    _node_id, client, key, _ = _signed_node(api)
    body = b"{}"
    path = "/cbom/node/heartbeat"
    h = _p2_headers(key, "POST", path, body, client.token, 3_700_000_000_000_000_123)
    assert api.client.post(path, headers=h, content=body).status_code == 200
    engine_b = create_engine(str(engine_a.url), connect_args={"check_same_thread": False})
    for module in (cbom_node, NA):
        monkeypatch.setattr(module, "get_db", lambda: engine_b)
    r = api.client.post(path, headers=h, content=body)
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "replay"


def test_protocol1_random_nonces_keep_the_nonce_table(api, world):
    engine, _ = world
    _node_id, client, key, _ = _signed_node(api)
    body = b"{}"
    path = "/cbom/node/heartbeat"
    nonce = secrets.token_urlsafe(18)
    ts = str(int(time.time()))
    sig = base64.b64encode(key.sign(NA.signing_message("POST", path, ts, nonce, body))).decode()
    h = {"X-ZS-Node-Token": client.token, "X-ZS-Timestamp": ts, "X-ZS-Nonce": nonce, "X-ZS-Signature": sig}
    assert api.client.post(path, headers=h, content=body).status_code == 200
    assert api.client.post(path, headers=h, content=body).headers["X-ZS-Refused"] == "replay"
    with Session(engine) as s:
        assert s.exec(select(CbomNodeNonce).where(CbomNodeNonce.nonce == nonce)).first() is not None


def test_the_node_client_rebases_its_sequence_after_replay_window(api, world):
    node_id, client, _key, _ = _signed_node(api)
    with Session(world[0]) as s:  # the server saw much higher sequences (the node's clock went back, say)
        node = s.get(CbomScanNode, node_id)
        node.replay_hwm = node_api._SEQ[0] + 10_000_000
        s.add(node)
        s.commit()
        hwm = node.replay_hwm
    assert client.heartbeat({})["pending_jobs"] == 0  # refused once with replay_window, re-signed, accepted
    with Session(world[0]) as s:
        assert s.get(CbomScanNode, node_id).replay_hwm == hwm + 1  # continued exactly at X-ZS-Seq-Next


# ----------------------------------------------------------------------------- heartbeat
def test_heartbeat_interval_is_server_driven_with_jitter_and_carries_a_claim_hint(api, world, monkeypatch):
    engine, _ = world
    node_id, client, _key, data = _signed_node(api)
    assert 48 <= data["heartbeat_interval_s"] <= 72 and data["protocol"] == 2
    values = {client.heartbeat({})["heartbeat_interval_s"] for _ in range(15)}
    assert all(48 <= v <= 72 for v in values) and len(values) > 1  # jitter
    hb = client.heartbeat({})
    assert hb["claim"] is False and hb["pending_jobs"] == 0
    assert {"server_time", "stop_all_network", "never_scan", "pending_jobs", "cancel_job_ids",
            "heartbeat_interval_s"} <= set(hb)  # every protocol-1 key is still there
    monkeypatch.setenv("CBOM_NODE_HEARTBEAT_S", "300")
    assert 240 <= client.heartbeat({})["heartbeat_interval_s"] <= 360
    monkeypatch.setenv("CBOM_NODE_HEARTBEAT_S", "nonsense")
    assert 48 <= client.heartbeat({})["heartbeat_interval_s"] <= 72  # an invalid value falls back to the default
    with Session(engine) as s:
        s.add(CbomCollectionJob(team_id=1, node_id=node_id, kind="collect", status="pending"))
        s.commit()
    hb = client.heartbeat({})
    assert hb["claim"] is True and hb["pending_jobs"] == 1


def test_an_idle_heartbeat_does_not_read_the_queue_or_write_a_nonce(api, world):
    """Statement budget of an idle protocol-2 heartbeat, whatever the queue holds for other nodes."""
    engine, _ = world
    node_id, client, _key, _ = _signed_node(api)
    _other, _c2, _k2, _ = _signed_node(api, "dc-02", segment="OTHER")
    with Session(engine) as s:
        for _ in range(300):
            s.add(CbomCollectionJob(team_id=1, node_id=_other, kind="collect", status="pending"))
        s.commit()
    client.heartbeat({})  # settles first-time writes (capabilities)
    stmts: list[str] = []
    listener = lambda *a: stmts.append(a[2].split()[0].upper() + (" " + a[2][:90] if os.environ.get("F1_DEBUG") else ""))  # noqa: E731
    event.listen(engine, "before_cursor_execute", listener)
    try:
        client.heartbeat({})
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    if os.environ.get("F1_DEBUG"):
        print("\n".join(stmts))
    assert "INSERT" not in stmts and stmts.count("UPDATE") == 1, stmts  # the window + last-seen UPDATE only
    assert len(stmts) <= 8, stmts


# ----------------------------------------------------------------------------- runs
def _count_statements(engine, fn) -> int:
    n = [0]

    def listener(*_a):
        n[0] += 1

    event.listen(engine, "before_cursor_execute", listener)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    return n[0]


@pytest.mark.parametrize("jobs", [20, 400])
def test_claim_and_finish_cost_does_not_grow_with_the_run(api, world, jobs):
    engine, _ = world
    node_id, client, _key, _ = _signed_node(api)
    with Session(engine) as s:
        for i in range(jobs):
            cfg = KINDS["linux_servers"].model.model_validate({"targets": [f"10.8.{i // 250}.{i % 250 + 1}"],
                                                              "window": "any"})
            s.add(CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name=f"s-{i}",
                                       name_lower=f"s-{i}", node_id=node_id, config=cfg.model_dump(mode="json"),
                                       last_test_status="passed"))
        s.commit()
    run_id = _run(api)
    payloads = []
    claim_cost = _count_statements(engine, lambda: payloads.append(client.claim()))
    finish_cost = _count_statements(engine, lambda: _finish(client, payloads[0]))
    payloads.clear()
    second_claim = _count_statements(engine, lambda: payloads.append(client.claim()))
    costs = test_claim_and_finish_cost_does_not_grow_with_the_run.costs  # type: ignore[attr-defined]
    costs[jobs] = (claim_cost, finish_cost, second_claim)
    if len(costs) == 2:
        assert costs[20] == costs[400], costs  # the same statements for 20 and 400 jobs: no O(jobs) step
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "running"


test_claim_and_finish_cost_does_not_grow_with_the_run.costs = {}  # type: ignore[attr-defined]


def test_run_status_follows_its_jobs_to_the_end(api, world):
    engine, _ = world
    node_id, client, _key, _ = _signed_node(api)
    _segment_sources(engine, 3)
    run_id = _run(api)
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "queued"
    p = [client.claim() for _ in range(3)]
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "running"
    _finish(client, p[0])
    _finish(client, p[1], status="failure")
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "running"
    _finish(client, p[2])
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        assert run.status == "partial" and run.finished_at is not None


def test_the_reaper_closes_a_run_left_running_with_no_open_job(api, world):
    """The safety net for the one race recompute_run does not lock against (a cancel ending many jobs while a job end
    saw many open): the reaper (cloud worker, read paths) closes such a run."""
    engine, _ = world
    with Session(engine) as s:
        s.add(CbomCollectionRun(id=70, team_id=1, owner_user_id=1, client_request_id='r-reconcile', status='running'))
        s.commit()
        s.add(CbomCollectionJob(team_id=1, run_id=70, kind='collect', status='success', outcome='ok'))
        s.add(CbomCollectionJob(team_id=1, run_id=70, kind='collect', status='cancelled'))
        s.commit()
        assert J.reap(s, dt.datetime.utcnow()) == 1
        s.commit()
        assert s.get(CbomCollectionRun, 70).status == 'partial'
    assert api('GET', '/1/cbom/sources/runs').status_code == 200  # read paths reap (and reconcile) too


# ----------------------------------------------------------------------------- segment jobs
def test_segment_jobs_go_to_any_agentless_node_of_the_segment_and_back_on_lease_expiry(api, world, monkeypatch):
    engine, _ = world
    a_id, a, _ka, _ = _signed_node(api, "dc-a", segment="DC")
    b_id, b, _kb, _ = _signed_node(api, "dc-b", segment="DC")
    _o_id, other, _ko, _ = _signed_node(api, "far-1", segment="FAR")
    _segment_sources(engine, 2)
    run_id = _run(api)
    with Session(engine) as s:
        jobs = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).all()
        assert {(j.node_id, j.node_segment) for j in jobs} == {(None, "DC")}
    assert other.heartbeat({})["claim"] is False and other.claim() is None  # another segment never sees them
    assert a.heartbeat({})["claim"] is True and b.heartbeat({})["pending_jobs"] == 2
    pa, pb = a.claim(), b.claim()
    assert pa["job"]["id"] != pb["job"]["id"]
    assert set(pa) == {"job", "scope", "source"} and set(pa["job"]) == {"id", "kind", "lease_id", "lease_seconds",
                                                                        "attempt", "run_id"}
    with Session(engine) as s:
        assert s.get(CbomCollectionJob, pa["job"]["id"]).node_id == a_id
    # node a dies holding its job: once the lease is over, the reaper puts it back in the segment, b takes it
    now = dt.datetime.utcnow()
    with Session(engine) as s:  # a stopped heartbeating: its lease runs out (b keeps renewing its own)
        job = s.get(CbomCollectionJob, pa['job']['id'])
        assert job.lease_expires_at > now + dt.timedelta(seconds=LIM.lease_seconds() - 60)
        job.lease_expires_at = now - dt.timedelta(seconds=1)
        s.add(job)
        s.commit()
        assert J.reap(s, now) == 1
        s.commit()
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, pa["job"]["id"])
        assert (job.status, job.node_id, job.node_segment) == ("pending", None, "DC")
    _finish(b, pb)
    again = b.claim()
    assert again["job"]["id"] == pa["job"]["id"] and again["job"]["attempt"] == 2
    with Session(engine) as s:
        assert s.get(CbomCollectionJob, again["job"]["id"]).node_id == b_id
    _finish(b, again)
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "done"
    with pytest.raises(node_api.LeaseLost):  # a's late result is refused: its lease is gone
        _finish(a, pa)


def test_cloud_worker_and_agent_nodes_never_take_segment_jobs(api, world):
    engine, _ = world
    _segment_sources(engine, 1)
    _signed_node(api, "dc-a", segment="DC")
    _run(api)
    with Session(engine) as s:
        assert J.claim_cloud_job(s, dt.datetime.utcnow(), "test") is None
        s.commit()
        node = CbomScanNode(team_id=1, owner_user_id=1, name="agent-dc", segment="DC", mode="agent",
                            node_token_hash="a" * 64)
        s.add(node)
        s.commit()
        assert J.claim_next(s, node, get_or_create_settings(s, 1), dt.datetime.utcnow()) is None
        s.commit()
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.node_segment == "DC")).one()
        assert job.status == "pending" and job.node_id is None  # left for an agentless node, never cancelled


def test_plan_says_when_a_segment_has_no_node(api, world):
    engine, _ = world
    _segment_sources(engine, 1, segment="NOBODY")
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in plan["items"] if i["name"] == "seg-0")
    assert item["status"] == "skipped" and "segment NOBODY" in item["reason"]
    _signed_node(api, "nb-1", segment="NOBODY")
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    item = next(i for i in plan["items"] if i["name"] == "seg-0")
    assert item["status"] == "queued" and item["node_name"] == "segment NOBODY"


def test_a_job_needing_a_capability_waits_for_a_node_that_has_it(api, world, monkeypatch):
    engine, _ = world
    _a_id, plain, _k, _ = _signed_node(api, "dc-plain", segment="DC")
    _segment_sources(engine, 1)
    _run(api)
    monkeypatch.setattr(CAPS, "_BY_KIND", {"linux_servers": "x_new_transport"})
    assert CAPS.required_capabilities("linux_servers", {}) == {"x_new_transport"}
    assert plain.claim() is None  # skipped, not cancelled
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionJob)).one().status == "pending"
    node_id, able, _k2, _ = _signed_node(api, "dc-able", segment="DC")
    able.heartbeat({"capabilities": {"collectors": ["linux_servers", "x_new_transport"], "protocol": 2}})
    assert able.claim()["source"]["kind"] == "linux_servers"
    assert CAPS.required_capabilities("ssh_like", {"credential_type": "ssh_ca"}) == {"ssh_ca"}


# ----------------------------------------------------------------------------- extension points
def test_secret_refs_plugins_extend_the_claim_and_the_version(api, world, monkeypatch):
    engine, _ = world
    _nid, client, _k, _ = _signed_node(api, "dc-a", segment="DC")
    (source_id,) = _segment_sources(engine, 1)
    with Session(engine) as s:
        before = J.connection_version(s.get(CbomCollectionSource, source_id))
    plugin = types.ModuleType("backend.utilities.cbom_sources.fleet.claim")
    plugin.claim_extras = lambda session, source, node, now, acc: {  # type: ignore[attr-defined]
        "config": {**acc["config"], "transport": "awx"}, "secrets": {**acc["secrets"], "token": "plug-secret-1"}}
    plugin.version_input = lambda session, source: "cred-7@v3"  # type: ignore[attr-defined]
    plugin.known_secrets = lambda session, source: ["plug-secret-1"]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "backend.utilities.cbom_sources.fleet", types.ModuleType("fleet"))
    monkeypatch.setitem(sys.modules, "backend.utilities.cbom_sources.fleet.claim", plugin)
    SR.reset_plugins()
    try:
        with Session(engine) as s:
            assert J.connection_version(s.get(CbomCollectionSource, source_id)) != before
        _run(api)
        payload = client.claim()
        assert payload["source"]["config"]["transport"] == "awx"
        assert payload["source"]["secrets"]["token"] == "plug-secret-1"
        with Session(engine) as s:
            assert "plug-secret-1" in SR.known_secrets(s, s.get(CbomCollectionSource, source_id))
    finally:
        monkeypatch.delitem(sys.modules, "backend.utilities.cbom_sources.fleet.claim")
        monkeypatch.delitem(sys.modules, "backend.utilities.cbom_sources.fleet")
        SR.reset_plugins()
    with Session(engine) as s:  # no plugin: the version of every existing source is what it was
        assert J.connection_version(s.get(CbomCollectionSource, source_id)) == before


def test_a_missing_plugin_is_skipped_but_a_broken_one_fails(monkeypatch):
    SR.reset_plugins()
    assert SR.plugins() == []  # none of the three modules exists yet
    broken = ModuleNotFoundError("No module named 'paramiko_x'", name="paramiko_x")
    assert not SR._missing(broken, "backend.utilities.cbom_sources.sshca.claim")
    assert SR._missing(ModuleNotFoundError("x", name="backend.utilities.cbom_sources.sshca"),
                       "backend.utilities.cbom_sources.sshca.claim")
    SR.reset_plugins()


def test_public_authenticate_node_and_leased_job(api, world):
    engine, _ = world
    node_id, client, key, _ = _signed_node(api)
    body = b"{}"
    h = _p2_headers(key, "POST", "/cbom/node/x", body, client.token, 3_700_000_000_000_000_999)
    req = NA.NodeRequest(method="POST", path="/cbom/node/x", timestamp=h["X-ZS-Timestamp"], nonce=h["X-ZS-Nonce"],
                         signature=h["X-ZS-Signature"])
    with Session(engine) as s:
        node = cbom_node.authenticate_node(s, client.token, req, body, dt.datetime.utcnow())
        assert node.id == node_id
    _segment_sources(engine, 1)
    _run(api)
    payload = client.claim()
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        job = J.leased_job(s, node, payload["job"]["id"], payload["job"]["lease_id"])
        assert job.status == "claimed"
        with pytest.raises(Exception) as err:
            J.leased_job(s, node, payload["job"]["id"], "0" * 24)
        assert getattr(err.value, "status_code", None) == 409
        other = CbomScanNode(id=999, team_id=1, owner_user_id=1, name="x", node_token_hash="z" * 64)
        with pytest.raises(Exception) as err:
            J.leased_job(s, other, payload["job"]["id"], payload["job"]["lease_id"])
        assert getattr(err.value, "status_code", None) == 404


# ----------------------------------------------------------------------------- caps
def test_caps_come_from_the_environment(api, world, monkeypatch):
    monkeypatch.setenv("CBOM_MAX_AGENTLESS_NODES", "2")
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "n1"}).status_code == 201
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "n2"}).status_code == 201
    r = api("POST", "/1/cbom/sources/nodes", json={"name": "n3"})
    assert r.status_code == 400 and "at most 2 scan nodes" in r.text
    monkeypatch.setenv("CBOM_MAX_AGENTLESS_NODES", "4")
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "n3"}).status_code == 201
    node_id, _token, _reg = enroll_node(api)
    monkeypatch.setenv("CBOM_MAX_SOURCES", "1")
    assert api("POST", "/1/cbom/sources/items", json=base.linux_body(node_id=node_id)).status_code == 201
    r = api("POST", "/1/cbom/sources/items", json=base.linux_body(name="linux-2", node_id=node_id))
    assert r.status_code == 400 and "at most 1 sources" in r.text
    monkeypatch.setenv("CBOM_MAX_POOL_ENROLLMENTS", "10")
    r = api("POST", "/1/cbom/sources/node-pools", json={"name": "k8s", "max_enrollments": 11})
    assert r.status_code == 400 and "at most 10" in r.text
    assert api("POST", "/1/cbom/sources/node-pools", json={"name": "k8s", "max_enrollments": 10}).status_code == 201
    monkeypatch.setenv("CBOM_MAX_POOLS", "1")
    assert api("POST", "/1/cbom/sources/node-pools", json={"name": "k8s-2"}).status_code == 400


def test_limit_defaults_are_sized_for_an_enterprise_fleet(monkeypatch):
    for name in ("CBOM_MAX_AGENTLESS_NODES", "CBOM_MAX_SOURCES", "CBOM_MAX_AGENT_NODES", "CBOM_MAX_POOLS",
                 "CBOM_MAX_POOL_ENROLLMENTS", "CBOM_JOB_LEASE_S"):
        monkeypatch.delenv(name, raising=False)
    assert (LIM.max_agentless_nodes(), LIM.max_sources(), LIM.max_agent_nodes(), LIM.max_pools()) == \
        (500, 5_000, 20_000, 200)  # F1 contract, section 3 (were 50 / 500 / 1,000 / 50)
    assert LIM.lease_seconds() == 900
    monkeypatch.setenv("CBOM_MAX_SOURCES", "0")
    assert LIM.max_sources() == 5_000  # out of range: the default


# ----------------------------------------------------------------------------- old nodes
def _legacy_module():
    spec = importlib.util.spec_from_file_location("zs_scan_node_legacy_api", LEGACY_API)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_scan_node_1_0_client_works_against_the_new_server(api, world):
    """The dev 3399452 node client (random nonces, polls claim, reads only protocol-1 keys) enrolls, heartbeats, claims
    a pinned job and a segment job, and posts results; its nonces go through the nonce table."""
    engine, _ = world
    legacy = _legacy_module()
    node_id, client, _key, data = _signed_node(api, "old-1", segment="DC", client_cls=legacy.Api, protocol=1)
    assert data["signing"] == "required"
    hb = client.heartbeat({"hostname": "old-1", "version": "1.0.0", "running": []})
    assert min(hb["heartbeat_interval_s"], 60) >= 5 and hb["pending_jobs"] == 0  # the 1.0 node clamps to [5, 60]
    _segment_sources(engine, 1)
    with Session(engine) as s:
        cfg = KINDS["linux_servers"].model.model_validate({"targets": ["10.7.0.1"], "window": "any"})
        s.add(CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name="pinned",
                                   name_lower="pinned", node_id=node_id, config=cfg.model_dump(mode="json"),
                                   last_test_status="passed"))
        s.commit()
    run_id = _run(api)
    first, second = client.claim(), client.claim()
    assert client.claim() is None
    for payload in (first, second):
        assert set(payload["job"]) == {"id", "kind", "lease_id", "lease_seconds", "attempt", "run_id"}
        assert payload["source"]["secrets"] == {}
        out = client.result(payload["job"]["id"], 1, {"lease_id": payload["job"]["lease_id"], "status": "success",
                                                      "result": {"counts": {"ok": 1}}})
        assert out["status"] == "success"
    with Session(engine) as s:
        assert s.get(CbomCollectionRun, run_id).status == "done"
        assert len(s.exec(select(CbomNodeNonce).where(CbomNodeNonce.node_id == node_id)).all()) >= 6


# ----------------------------------------------------------------------------- PostgreSQL races
def _pg_world():
    engine = create_engine(PG_URL, pool_size=20, max_overflow=10)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=1000.0))
        s.commit()
        s.add(User(id=1, email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None,
                   default_team_id=1))
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=1, role="admin"))
        s.commit()
        get_or_create_settings(s, 1)
    return engine


@needs_pg
def test_many_nodes_claim_one_segment_at_once_without_a_double_claim():
    engine = _pg_world()
    nodes = []
    with Session(engine) as s:
        for i in range(12):
            n = CbomScanNode(team_id=1, owner_user_id=1, name=f"n{i}", segment="DC", node_token_hash=f"{i:064d}")
            s.add(n)
            s.flush()
            nodes.append(n.id)
        s.add(CbomCollectionRun(id=1, team_id=1, owner_user_id=1, client_request_id="r-000001", status="queued"))
        s.commit()
    _segment_sources(engine, 60)
    with Session(engine) as s:
        for src in s.exec(select(CbomCollectionSource)).all():
            s.add(CbomCollectionJob(team_id=1, run_id=1, source_id=src.id, node_segment="DC", kind="collect",
                                    params={"conn_v": J.connection_version(src)}))
        s.commit()
    claimed: list[tuple[int, int]] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(len(nodes))

    def worker(node_id: int) -> None:
        try:
            barrier.wait(timeout=10)
            while True:
                with Session(engine) as s:
                    node = s.get(CbomScanNode, node_id)
                    payload = J.claim_next(s, node, get_or_create_settings(s, 1), dt.datetime.utcnow())
                    s.commit()
                if payload is None:
                    return
                claimed.append((payload["job"]["id"], node_id))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors
    ids = [j for j, _n in claimed]
    assert len(ids) == 60 and len(set(ids)) == 60  # every job once, none twice
    assert len({n for _j, n in claimed}) > 1  # spread over several nodes
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionJob)).all()
        assert all(j.status == "claimed" and j.node_id is not None and j.attempts == 1 for j in rows)
        assert s.get(CbomCollectionRun, 1).status == "running"


@needs_pg
def test_the_last_two_jobs_ending_together_finish_the_run(monkeypatch):
    """Before F1.1 each transaction saw the other job still claimed and the run stayed "running" for ever."""
    engine = _pg_world()
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        n = CbomScanNode(team_id=1, owner_user_id=1, name="n", segment="DC", node_token_hash="1" * 64)
        s.add(n)
        s.add(CbomCollectionRun(id=1, team_id=1, owner_user_id=1, client_request_id="r-000002", status="running"))
        s.commit()
        node_id = n.id
        for i in range(2):
            s.add(CbomCollectionJob(team_id=1, run_id=1, node_id=node_id, kind="discovery", status="claimed",
                                    lease_id=f"lease{i:019d}", lease_expires_at=now + dt.timedelta(minutes=5),
                                    claimed_at=now, attempts=1))
        s.commit()
        job_ids = [j.id for j in s.exec(select(CbomCollectionJob)).all()]
    real = J.recompute_run
    barrier = threading.Barrier(2)

    def both_ended_then_recompute(session, run_id, at):
        try:
            barrier.wait(timeout=2)  # both job UPDATEs are done (uncommitted) before either decides the run
        except threading.BrokenBarrierError:
            pass
        return real(session, run_id, at)

    monkeypatch.setattr(J, "recompute_run", both_ended_then_recompute)
    errors: list[BaseException] = []

    def end(i: int) -> None:
        try:
            with Session(engine) as s:
                node = s.get(CbomScanNode, node_id)
                J.finish_job(s, node, job_ids[i], f"lease{i:019d}", "success", {"counts": {"ok": 1}}, None,
                             dt.datetime.utcnow())
                s.commit()
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=end, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors, errors
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, 1)
        assert run.status == "done" and run.finished_at is not None
