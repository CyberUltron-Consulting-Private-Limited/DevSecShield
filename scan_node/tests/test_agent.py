"""The node loop against a fake ZeroShield API that follows the contract (enroll, heartbeat, claim, assets, result)."""
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from zs_scan_node import agent as A


class FakeApi:
    def __init__(self):
        self.calls = []
        self.jobs = []
        self.assets = {}
        self.results = {}
        self.heartbeats = []
        self.cancel = set()
        self.lease_lost = set()
        self.stop = False
        self.enrolled = False
        self.lock = threading.Lock()

    def handle(self, path, body, headers):
        self.calls.append(path)
        if path == "/cbom/node/enroll":
            if body.get("registration_token") != "zsr_good_token_0123456789":
                return 401, {"detail": "Registration token is invalid or expired"}
            assert body["ssh_public_key"].startswith("ssh-ed25519 ")
            self.enrolled = True
            return 200, {"node_id": 7, "team_id": 3, "node_token": "zsn_node_token_ABCDEFGHIJKLMNOP", "heartbeat_interval_s": 5}
        if headers.get("X-ZS-Node-Token") != "zsn_node_token_ABCDEFGHIJKLMNOP":
            return 401, {"detail": "Invalid node token"}
        if path == "/cbom/node/heartbeat":
            self.heartbeats.append(body)
            return 200, {"cancel_job_ids": sorted(self.cancel), "never_scan": [], "stop_all_network": self.stop,
                         "heartbeat_interval_s": 5}
        if path == "/cbom/node/jobs/claim":
            with self.lock:
                if not self.jobs:
                    return 204, None
                return 200, self.jobs.pop(0)
        job_id = int(path.split("/")[4])
        if path.endswith("/assets"):
            if job_id in self.lease_lost:
                return 409, {"detail": "This job is no longer leased to this node"}
            self.assets.setdefault(job_id, []).extend(body["assets"])
            assert headers.get("X-ZS-Job", "").startswith(f"{job_id}/")
            return 200, {"accepted": len(body["assets"]), "duplicate": 0, "rejected": 0,
                         "total_for_attempt": len(self.assets[job_id]), "cap_reached": False}
        if path.endswith("/result"):
            if job_id in self.lease_lost:
                return 409, {"detail": "This job is no longer leased to this node"}
            self.results[job_id] = body
            return 200, {"job_id": job_id, "status": body["status"]}
        return 404, {"detail": "no"}


@pytest.fixture()
def server():
    api = FakeApi()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"null") if length else None
            status, data = api.handle(self.path, body or {}, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if data is not None:
                self.wfile.write(json.dumps(data).encode())

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield api, f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def run():
        while True:
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                return

    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1]


def _job(job_id, port, secret="s3cr3t-password-value"):
    return {"job": {"id": job_id, "kind": "collect", "lease_id": "lease0000abcd", "lease_seconds": 900, "attempt": 1,
                    "run_id": 11},
            "scope": {"ranges": [{"cidr": "127.0.0.1/32", "mode": "fragile"}], "never_scan": [],
                      "ports": [{"port": port, "protocol": "tls", "label": "x"}], "max_runtime_s": 60,
                      "rate_limits": {"connections_per_second": 50, "parallel_per_server": 2, "handshakes_per_endpoint": 2}},
            "source": {"id": 5, "kind": "network_range", "name": "lab", "config": {"cidr": "127.0.0.1/32"},
                       "secrets": {"password": secret}}}


def _agent(tmp_path, url, monkeypatch):
    monkeypatch.setenv("ZS_API_URL", url)
    monkeypatch.setenv("ZS_ALLOW_INSECURE_HTTP", "1")  # the fake API is plain HTTP on loopback
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", "zsr_good_token_0123456789")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    return A.Agent()


def _wait(pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.1)
    return False


def test_enroll_run_job_and_report(server, tmp_path, monkeypatch):
    api, url = server
    srv, port = _listener()
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    assert api.enrolled and ag.state.node_token
    assert oct(os.stat(ag.state.key_path).st_mode & 0o777) == "0o600"
    state = json.load(open(os.path.join(ag.state.directory, "state.json")))
    assert state["node_token"].startswith("zsn_") and "zsr_good" not in json.dumps(state)
    api.jobs.append(_job(41, port))
    t = threading.Thread(target=ag.claim_loop, daemon=True)
    t.start()
    assert _wait(lambda: 41 in api.results)
    ag.heartbeat_once()
    ag.shutdown.set()
    res = api.results[41]
    assert res["lease_id"] == "lease0000abcd" and res["status"] in ("success", "failure")
    assert res["result"]["counts"]["total"] == 1 and "node_version" in res["result"]
    assert "s3cr3t-password-value" not in json.dumps(res) + json.dumps(api.assets)
    srv.close()


def test_heartbeat_reports_running_and_cancel_stops_job(server, tmp_path, monkeypatch):
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    # a range of many addresses with a closed port keeps the job busy long enough to cancel it
    job = _job(42, 9)
    job["scope"]["ranges"] = [{"cidr": "127.0.1.0/24", "mode": "full"}]
    job["scope"]["rate_limits"]["connections_per_second"] = 5
    ag.start_job(job)
    assert _wait(lambda: 42 in ag.running, 5)
    ag.heartbeat_once()
    assert api.heartbeats[-1]["running"] == [{"job_id": 42, "lease_id": "lease0000abcd"}]
    api.cancel.add(42)
    ag.heartbeat_once()
    assert _wait(lambda: 42 in api.results, 20)
    assert api.results[42]["status"] == "cancelled"
    counts = api.results[42]["result"]["counts"]
    assert counts["skipped"] >= 1


def test_resume_is_not_undone_by_a_stale_stop_flag(server, tmp_path, monkeypatch):
    """Edge run 2026-10-31: network jobs claimed in the 30 s after 'resume' were skipped as stopped (jobs 167, 168)."""
    api, url = server
    srv, port = _listener()
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    api.stop = True
    ag.heartbeat_once()
    assert ag.stop_network.is_set()
    api.stop = False  # the user resumes; the node's next heartbeat is up to 30 s away
    api.jobs.append(_job(44, port))
    t = threading.Thread(target=ag.claim_loop, daemon=True)
    t.start()
    assert _wait(lambda: 44 in api.results)
    ag.shutdown.set()
    assert api.results[44]["result"]["counts"]["skipped"] == 0
    assert not ag.stop_network.is_set()
    # an answer to a heartbeat sent before that claim arrives late: it must not stop network work again
    ag.apply_control({"stop_all_network": True, "never_scan": ["10.0.0.0/8"]}, sent=0.0)
    assert not ag.stop_network.is_set() and ag.team_never is None
    # a heartbeat sent after the claim is newer and applies
    ag.apply_control({"stop_all_network": True, "never_scan": []}, sent=time.monotonic())
    assert ag.stop_network.is_set()
    srv.close()


def test_plain_http_api_url_is_refused_without_the_lab_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("ZS_API_URL", "http://zeroshield.example")
    monkeypatch.delenv("ZS_ALLOW_INSECURE_HTTP", raising=False)
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(SystemExit):
        A.Agent()


def test_a_stuck_collector_is_ended_and_frees_its_slot(server, tmp_path, monkeypatch):
    """Security review 2026-10-31: a target that stops answering must not hold a node job slot forever."""
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    monkeypatch.setattr(A, "STUCK_GRACE_S", 1)
    release = threading.Event()

    def hang(ctx, job, scope, source):
        release.wait(30)  # ignores cancel and deadline, like a socket read that never returns
        return "success", None, None

    monkeypatch.setattr(A, "run_job", hang)
    job = _job(45, 9)
    job["scope"]["max_runtime_s"] = 1
    ag.start_job(job)
    assert _wait(lambda: 45 in api.results, 20)
    assert api.results[45]["status"] == "failure" and "stopped answering" in api.results[45]["error"]
    assert _wait(lambda: 45 not in ag.running, 5)
    release.set()  # the collector finally returns: its late result must not be posted again
    time.sleep(1)
    assert api.calls.count("/cbom/node/jobs/45/result") == 1


def test_a_non_network_claim_does_not_hide_a_stop(tmp_path, monkeypatch):
    """Second review: only a network claim says anything about the stop flag."""
    monkeypatch.setenv("ZS_API_URL", "https://zeroshield.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    ag = A.Agent()
    ag.claimed(10.0, is_network=False)
    ag.apply_control({"stop_all_network": True, "never_scan": ["10.9.0.0/16"]}, sent=5.0)  # sent before that claim
    assert ag.stop_network.is_set() and ag.team_never is None
    ag.claimed(20.0, is_network=True)
    assert not ag.stop_network.is_set()


def test_lease_lost_posts_no_result(server, tmp_path, monkeypatch):
    api, url = server
    srv, port = _listener()
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    api.lease_lost.add(43)
    job = _job(43, port)
    ag.start_job(job)
    assert _wait(lambda: 43 not in ag.running, 20)
    assert 43 not in api.results
    srv.close()


def test_bad_registration_token_is_not_retried_in_a_loop(server, tmp_path, monkeypatch):
    api, url = server
    monkeypatch.setenv("ZS_API_URL", url)
    monkeypatch.setenv("ZS_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", "zsr_wrong_token_0123456789")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    ag = A.Agent()
    threading.Timer(1.0, ag.shutdown.set).start()
    ag.ensure_enrolled()
    assert api.calls.count("/cbom/node/enroll") == 1 and not ag.state.node_token


def test_heartbeat_loop_marks_the_node_alive_even_when_the_server_fails(server, tmp_path, monkeypatch):
    """The image HEALTHCHECK reads the age of <state dir>/alive: every pass of the heartbeat loop refreshes it, whether
    the heartbeat succeeded or not (the loop is turning; a stuck loop is what must turn the container unhealthy)."""
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    alive = os.path.join(ag.state.directory, A.ALIVE_FILE)
    assert not os.path.exists(alive)
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: os.path.exists(alive))
    assert api.heartbeats and time.time() - os.path.getmtime(alive) < 5
    ag.shutdown.set()
    t.join(10)

    def down():
        raise A.ApiError("server down")

    stale = time.time() - 600
    os.utime(alive, (stale, stale))
    ag.shutdown.clear()
    monkeypatch.setattr(ag, "heartbeat_once", down)
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: os.path.getmtime(alive) > stale + 60)
    ag.shutdown.set()
    t.join(10)
