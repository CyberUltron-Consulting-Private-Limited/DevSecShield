"""The node loop against a fake ZeroShield API that follows the contract (enroll, heartbeat, claim, assets, result)."""
import base64
import email.utils
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from zs_scan_node import agent as A
from zs_scan_node.api import signing_message


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
        # like the real server: a deployment id on every answer, signatures checked with the key sent at enrollment
        self.deployment = "dep-A"
        self.send_deployment = True
        self.pubkey: str | None = None
        self.state_dir: str | None = None  # where the node keeps its signing key (checked at enrollment)
        self.nonces: set[str] = set()
        self.signed: list[str] = []
        self.clock_offset = 0  # the server clock minus real time
        # Answer every node call with a 401: "own" (this deployment says the credential is revoked), "own-implicit"
        # (this deployment's id, no revocation code), "other" (another ZeroShield deployment, which does not know
        # the token either) or "none" (no deployment id: not ZeroShield, or a proxy answered).
        self.force_401: str | None = None
        self.force_403: str | None = None  # "other" | "none": a wrong server or a proxy forbids every node call
        self.strip_token = False  # a proxy in front of this server drops the X-ZS-Node-Token header
        self.registration_tokens = {"zsr_good_token_0123456789"}  # accepted at enrollment (add an agent pool token)
        self.enroll_bodies: list[dict] = []

    def check_signature(self, method, path, headers, raw, key):
        ts, nonce, sig = (headers.get(h) for h in ("X-ZS-Timestamp", "X-ZS-Nonce", "X-ZS-Signature"))
        if not (ts and nonce and sig):
            return 403, {"detail": "signature headers missing"}, {"X-ZS-Refused": "signature_required"}
        if abs(int(ts) - (time.time() + self.clock_offset)) > 300:
            return 403, {"detail": "clock"}, {"X-ZS-Refused": "clock_skew"}
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(
            base64.b64decode(sig), signing_message(method, path, ts, nonce, raw))  # raises on a bad signature
        assert nonce not in self.nonces, "nonce reused"
        self.nonces.add(nonce)
        self.signed.append(path)
        return None

    def handle(self, path, body, headers, raw=b""):
        self.calls.append(path)
        # like the real server: a 401 says explicitly why (backend/routers/cbom_node.py)
        revoked = "registration_token_refused" if path == "/cbom/node/enroll" else "node_token_revoked"
        if self.force_401:
            dep, code = {"own": (self.deployment, revoked), "own-implicit": (self.deployment, None),
                         "other": ("dep-OTHER", revoked), "none": (None, None)}[self.force_401]
            return 401, {"detail": "Invalid node token"}, {"X-ZS-Deployment": dep or "", "X-ZS-Refused": code or ""}
        if self.force_403:
            dep = {"other": "dep-OTHER", "none": None}[self.force_403]
            return 403, {"detail": "Forbidden"}, {"X-ZS-Deployment": dep or ""}
        if path == "/cbom/node/enroll":
            self.enroll_bodies.append(body)
            if body.get("registration_token") not in self.registration_tokens:
                return 401, {"detail": "Registration token is invalid or expired"}, {"X-ZS-Refused": revoked}
            assert body["ssh_public_key"].startswith("ssh-ed25519 ")
            if body.get("signing_public_key"):
                refused = self.check_signature("POST", path, headers, raw, body["signing_public_key"])
                if refused:
                    return refused
                if self.state_dir:  # the private half was on disk before the key was sent
                    with open(os.path.join(self.state_dir, "signing_ed25519"), "rb") as f:
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

                        on_disk = Ed25519PrivateKey.from_private_bytes(f.read()).public_key().public_bytes_raw()
                    assert base64.b64encode(on_disk).decode() == body["signing_public_key"]
                self.pubkey = body["signing_public_key"]
            self.enrolled = True
            return 200, {"node_id": 7, "team_id": 3, "node_token": "zsn_node_token_ABCDEFGHIJKLMNOP", "heartbeat_interval_s": 5,
                         "deployment_id": self.deployment, "signing": "required" if self.pubkey else "legacy"}
        token = None if self.strip_token else headers.get("X-ZS-Node-Token")
        if token != "zsn_node_token_ABCDEFGHIJKLMNOP":
            return 401, {"detail": "Invalid node token"}, {"X-ZS-Refused": "node_token_revoked" if token else
                                                           "node_token_missing"}
        if self.pubkey:
            refused = self.check_signature("POST", path, headers, raw, self.pubkey)
            if refused:
                return refused
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
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw or b"null") if length else None
            status, data, *extra = api.handle(self.path, body or {}, self.headers, raw)
            headers = {"X-ZS-Deployment": api.deployment} if api.send_deployment else {}
            headers.update(extra[0] if extra else {})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for k, v in headers.items():
                if v:
                    self.send_header(k, v)
            self.end_headers()
            if data is not None:
                self.wfile.write(json.dumps(data).encode())

        def log_message(self, *a):
            pass

        def date_time_string(self, timestamp=None):  # the server's clock, which may differ from the node's
            return email.utils.formatdate(time.time() + api.clock_offset, usegmt=True)

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
