"""Signed requests, the deployment id rule for 401s, and mTLS, against the fake ZeroShield API of test_agent.py
(which, like the real server, stamps X-ZS-Deployment and verifies every signature with the enrolled key)."""
import datetime as dt
import json
import os
import ssl
import threading

import pytest

from test_agent import _agent, _job as _collect_job, _listener, _wait, server  # noqa: F401  (server is a fixture)
from zs_scan_node import agent as A
from zs_scan_node import api as api_mod


def _job(job_id, port):
    """A discovery job: it reports the listener's open port as an asset, so the node posts an asset batch."""
    job = _collect_job(job_id, port)
    job["job"]["kind"] = "discovery"
    return job


# ----------------------------------------------------------------------------- signed requests (C9)
def test_every_request_is_signed_with_the_key_saved_before_enrollment(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    srv, port = _listener()
    ag = _agent(tmp_path, url, monkeypatch)
    api.state_dir = ag.state.directory  # the fake checks the key file at the moment the enroll call arrives
    ag.ensure_enrolled()
    assert api.pubkey and api.signed == ["/cbom/node/enroll"]
    key_file = os.path.join(ag.state.directory, "signing_ed25519")
    assert oct(os.stat(key_file).st_mode & 0o777) == "0o600"
    api.jobs.append(_job(46, port))
    ag.heartbeat_once()
    t = threading.Thread(target=ag.claim_loop, daemon=True)
    t.start()
    assert _wait(lambda: 46 in api.results)
    ag.shutdown.set()
    # heartbeat, claim, assets and result: each verified over the exact bytes received, each with its own nonce
    assert {"/cbom/node/heartbeat", "/cbom/node/jobs/claim", "/cbom/node/jobs/46/assets",
            "/cbom/node/jobs/46/result"} <= set(api.signed)
    assert len(api.nonces) == len(api.signed)
    # a restarted node signs with the same key (loaded from the state directory)
    ag2 = _agent(tmp_path, url, monkeypatch)
    ag2.heartbeat_once()
    assert api.signed[-1] == "/cbom/node/heartbeat"
    srv.close()


def test_a_new_enrollment_gets_a_new_signing_key(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    first = api.pubkey
    ag.on_unauthorized()  # reset in ZeroShield
    ag.state.enrolled_with = None
    ag.ensure_enrolled()
    assert api.pubkey and api.pubkey != first


def test_clock_skew_refusal_is_corrected_from_the_server_date(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    api.clock_offset = 3600  # the server's clock is an hour ahead of the node's
    ag.heartbeat_once()  # 403 clock_skew -> re-signed with the offset from the Date header -> accepted
    assert api.signed[-1] == "/cbom/node/heartbeat" and abs(ag.api.skew - 3600) < 5


def test_the_node_and_server_sign_the_same_bytes():
    from pathlib import Path

    server_src = (Path(__file__).resolve().parents[2] / "backend/utilities/cbom_sources/node_auth.py").read_text()
    assert ('"\\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()'
            in server_src)
    assert api_mod.signing_message("post", "/p", "1", "n", b"{}") == (
        b"POST\n/p\n1\nn\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")


# ----------------------------------------------------------------------------- wrong-server 401 (deployment id)
def test_enrollment_stores_the_deployment_id(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    state = json.load(open(os.path.join(ag.state.directory, "state.json")))
    assert state["deployment_id"] == "dep-A" and ag.api.deployment_id == "dep-A"


@pytest.mark.parametrize("who", ["other", "none"])
def test_a_401_from_a_wrong_server_keeps_the_token_and_is_reported(server, tmp_path, monkeypatch, who):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    monkeypatch.setattr(ag.api, "_wait", lambda s: None)  # no real back-off sleeps in the test
    api.force_401 = who
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: ag.last_error is not None, 10)
    ag.shutdown.set()
    t.join(10)
    assert ag.state.node_token == "zsn_node_token_ABCDEFGHIJKLMNOP"  # kept, in memory and on disk
    assert json.load(open(os.path.join(ag.state.directory, "state.json")))["node_token"]
    assert f"server at {url} did not accept this node" in ag.last_error
    assert "not the ZeroShield this node enrolled with?" in ag.last_error
    api.force_401 = None  # the right server answers again: the next heartbeat reports what happened
    ag.heartbeat_once()
    assert "did not accept this node" in api.heartbeats[-1]["last_error"]
    assert ag.last_error is None


@pytest.mark.parametrize("how", ["proxy-drops-token", "own-implicit", "forbidden-other", "forbidden-none"])
def test_only_an_explicit_revocation_from_its_own_deployment_ends_the_credential(server, tmp_path, monkeypatch,  # noqa: F811
                                                                                 how):
    """A proxy in front of the right ZeroShield that drops the token header (the server answers 401
    node_token_missing), a 401 from its own deployment that does not say the token was revoked, and a 403 from a
    wrong server or a proxy: the node keeps its credential, backs off and says which server did not accept it."""
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    monkeypatch.setattr(ag.api, "_wait", lambda s: None)
    if how == "proxy-drops-token":
        api.strip_token = True
    elif how == "own-implicit":
        api.force_401 = "own-implicit"
    else:
        api.force_403 = how.split("-", 1)[1]
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: ag.last_error is not None, 10)
    ag.shutdown.set()
    t.join(10)
    assert ag.state.node_token == "zsn_node_token_ABCDEFGHIJKLMNOP"
    assert json.load(open(os.path.join(ag.state.directory, "state.json")))["node_token"]
    assert f"server at {url} did not accept this node" in ag.last_error
    if how == "proxy-drops-token":
        assert "did not reach ZeroShield" in ag.last_error
    api.strip_token, api.force_401, api.force_403 = False, None, None
    ag.heartbeat_once()  # the path is fixed: the same credential works and the problem is reported
    assert "did not accept this node" in api.heartbeats[-1]["last_error"]


def test_a_pool_pod_enrolls_again_only_after_an_explicit_revocation(server, tmp_path, monkeypatch):  # noqa: F811
    """Agent pool (zsp_) pods: a 401 that is not an explicit revocation keeps the node (no new enrollment); ZeroShield
    saying the node token is revoked (node reset) makes the pod enroll again with its pool token and its node id."""
    api, url = server
    pool = "zsp_" + "P" * 43
    api.registration_tokens.add(pool)
    monkeypatch.setenv("ZS_MODE", "agent")
    monkeypatch.setenv("ZS_NODE_NAME", "k8s-worker-a")
    ag = _agent(tmp_path, url, monkeypatch)
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", pool)
    ag.ensure_enrolled()
    assert ag.state.node_id == 7 and len(api.enroll_bodies) == 1
    monkeypatch.setattr(ag.api, "_wait", lambda s: None)
    for how in ("own-implicit", "other", "none"):
        api.force_401 = how
        with pytest.raises(api_mod.WrongServer):
            ag.heartbeat_once()
    assert ag.state.node_token and len(api.enroll_bodies) == 1
    api.force_401 = "own"
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: ag.state.node_token is None, 10)
    ag.shutdown.set()
    t.join(10)
    ag.shutdown.clear()
    api.force_401 = None
    ag.ensure_enrolled()
    assert ag.state.node_token and len(api.enroll_bodies) == 2
    assert api.enroll_bodies[-1]["registration_token"] == pool and api.enroll_bodies[-1]["node_id"] == 7


def test_a_403_refusal_from_its_own_deployment_is_not_a_wrong_server(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    api.pubkey = "AAAA"  # the server now holds another key: every signature is refused (403 with a refusal code)
    orig = api.check_signature
    api.check_signature = lambda *a: (403, {"detail": "bad signature"}, {"X-ZS-Refused": "signature_invalid"})
    with pytest.raises(api_mod.ApiError) as err:
        ag.heartbeat_once()
    assert not isinstance(err.value, api_mod.WrongServer) and err.value.refused == "signature_invalid"
    assert ag.state.node_token
    api.check_signature = orig


def test_a_401_from_its_own_deployment_clears_the_token(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    api.force_401 = "own"
    t = threading.Thread(target=ag.heartbeat_loop, daemon=True)
    t.start()
    assert _wait(lambda: ag.state.node_token is None, 10)
    ag.shutdown.set()
    t.join(10)
    assert json.load(open(os.path.join(ag.state.directory, "state.json")))["node_token"] is None


def test_state_from_before_deployment_ids_adopts_it_from_the_first_success(server, tmp_path, monkeypatch):  # noqa: F811
    api, url = server
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    (state_dir / "state.json").write_text(json.dumps({"node_token": "zsn_node_token_ABCDEFGHIJKLMNOP", "node_id": 7,
                                                      "team_id": 3, "enrolled_with": "x"}))
    ag = _agent(tmp_path, url, monkeypatch)
    assert ag.state.deployment_id is None and ag.api.signing_key is None  # legacy: enrolled before signing
    ag.heartbeat_once()
    assert ag.state.deployment_id == "dep-A"
    assert json.load(open(state_dir / "state.json"))["deployment_id"] == "dep-A"
    assert api.heartbeats and "/cbom/node/heartbeat" not in api.signed  # a legacy node still sends unsigned
    api.force_401 = "other"  # from now on a 401 from another deployment is recognised as a wrong server
    monkeypatch.setattr(ag.api, "_wait", lambda s: None)
    with pytest.raises(api_mod.WrongServer):
        ag.heartbeat_once()


def test_enrollment_401_from_another_deployment_does_not_burn_the_registration_token(server, tmp_path,  # noqa: F811
                                                                                       monkeypatch):
    api, url = server
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    ag.on_unauthorized()  # the node was reset: it waits for a new registration token
    ag.state.enrolled_with = None
    api.force_401 = "other"  # ZS_API_URL now points at another ZeroShield (staging instead of production)
    threading.Timer(1.0, ag.shutdown.set).start()
    ag.ensure_enrolled()
    assert ag.state.enrolled_with is None and ag.state.refused_with is None  # still usable once ZS_API_URL is fixed
    ag.shutdown.clear()
    api.force_401 = "own"  # its own deployment refuses it: spent or expired, so it is not retried
    threading.Timer(1.0, ag.shutdown.set).start()
    ag.ensure_enrolled()
    assert ag.state.refused_with is not None


def test_401_while_posting_assets(server, tmp_path, monkeypatch):  # noqa: F811
    """Own deployment: the job stops, posts no result, and the token is cleared.  Another server: the token is kept
    and the batch is counted as lost (reported in the result), never silently dropped."""
    api, url = server
    srv, port = _listener()
    ag = _agent(tmp_path, url, monkeypatch)
    ag.ensure_enrolled()
    monkeypatch.setattr(ag.api, "_wait", lambda s: None)
    orig = api.handle

    def assets_401(who):
        def handle(path, body, headers, raw=b""):
            if path.endswith("/assets"):
                api.force_401 = who
                try:
                    return orig(path, body, headers, raw)
                finally:
                    api.force_401 = None
            return orig(path, body, headers, raw)
        return handle

    api.handle = assets_401("other")
    ag.start_job(_job(47, port))
    assert _wait(lambda: 47 in api.results, 20)
    assert ag.state.node_token and api.results[47]["result"]["assets_lost"] >= 1
    api.handle = assets_401("own")
    ag.start_job(_job(48, port))
    assert _wait(lambda: 48 not in ag.running, 20)
    assert 48 not in api.results and ag.state.node_token is None
    srv.close()


# ----------------------------------------------------------------------------- mTLS (node side)
def _pki(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def make(cn, issuer_key=None, issuer=None, ca=False, san=None):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
             .not_valid_after(now + dt.timedelta(hours=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if san:
            b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return key, b.sign(issuer_key or key, hashes.SHA256())

    def write(name, key, cert):
        (tmp_path / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tmp_path / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                                 serialization.PrivateFormat.PKCS8,
                                                                 serialization.NoEncryption()))

    import ipaddress

    ca_key, ca = make("wp5 test CA", ca=True)
    write("ca", ca_key, ca)
    s_key, s_cert = make("127.0.0.1", ca_key, ca.subject, san=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    write("server", s_key, s_cert)
    c_key, c_cert = make("scan-node-1", ca_key, ca.subject)
    write("client", c_key, c_cert)
    return tmp_path


def test_node_presents_its_client_certificate_and_trusts_only_zs_ca_file(tmp_path, monkeypatch):
    """A TLS server that requires a client certificate signed by the CA: the node gets through with ZS_CLIENT_CERT /
    ZS_CLIENT_KEY and ZS_CA_FILE, and is refused without its certificate."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    pki = _pki(tmp_path)
    peers = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            peers.append(self.connection.getpeercert())
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.send_header("X-ZS-Deployment", "dep-M")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    sctx.load_verify_locations(pki / "ca.crt")
    sctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{httpd.server_port}"
    try:
        monkeypatch.setenv("ZS_CA_FILE", str(pki / "ca.crt"))
        monkeypatch.setenv("ZS_CLIENT_CERT", str(pki / "client.crt"))
        monkeypatch.setenv("ZS_CLIENT_KEY", str(pki / "client.key"))
        client = api_mod.Api(url, "zsn_x")
        assert client.heartbeat({}) == {} and client.deployment_id == "dep-M"
        assert dict(x[0] for x in peers[-1]["subject"])["commonName"] == "scan-node-1"
        monkeypatch.delenv("ZS_CLIENT_CERT")
        monkeypatch.delenv("ZS_CLIENT_KEY")
        no_cert = api_mod.Api(url, "zsn_x")
        monkeypatch.setattr(no_cert, "_wait", lambda s: None)
        with pytest.raises(api_mod.ApiError):
            no_cert.heartbeat({})
        monkeypatch.setenv("ZS_CLIENT_CERT", str(pki / "client.crt"))
        with pytest.raises(SystemExit):  # a certificate without its key is a configuration error, said at start
            api_mod.Api(url, "zsn_x")
    finally:
        httpd.shutdown()


def test_agent_wires_signing_key_deployment_and_stop_event(tmp_path, monkeypatch):
    monkeypatch.setenv("ZS_API_URL", "https://zeroshield.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    for name in ("ZS_CA_FILE", "ZS_CLIENT_CERT", "ZS_CLIENT_KEY"):
        monkeypatch.delenv(name, raising=False)
    ag = A.Agent()
    assert ag.api.stop is ag.shutdown and ag.api.signing_key is None and ag.api.deployment_id is None
