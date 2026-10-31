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
            return 200, {"cancel_job_ids": sorted(self.cancel), "never_scan": [], "stop_all_network": False,
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
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", "zsr_wrong_token_0123456789")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    ag = A.Agent()
    threading.Timer(1.0, ag.shutdown.set).start()
    ag.ensure_enrolled()
    assert api.calls.count("/cbom/node/enroll") == 1 and not ag.state.node_token
