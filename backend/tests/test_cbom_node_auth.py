"""Scan-node request authentication (WP5): deployment id on every node response, Ed25519 signed requests (signed,
unsigned, replayed, skewed, tampered, downgrade, require-signed team setting) and the proxy's mTLS headers.

The node side of the conversation is the real scan-node client (scan_node/zs_scan_node/api.py) talking to the real
routes through the TestClient, so both ends of the signature format are exercised together.  Run:

    cd backend && PYTHONPATH=..:../scan_node JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x \\
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 python -m pytest tests/test_cbom_node_auth.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from sqlmodel import Session, SQLModel, create_engine, select

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))  # the real node client

from test_cbom_sources_api import api, linux_body, world  # noqa: E402,F401  (fixtures)
from backend.new_models import CbomDeployment, CbomNodeNonce, CbomScanNode  # noqa: E402
from backend.routers import cbom_node  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cbom_sources import node_auth  # noqa: E402
from zs_scan_node import api as node_api  # noqa: E402

DEP = "X-ZS-Deployment"


def _registration(api, name="dc-signed-01"):
    r = api("POST", "/1/cbom/sources/nodes", json={"name": name, "segment": "DC"})
    assert r.status_code == 201, r.text
    return r.json()["node"]["id"], r.json()["registration_token"]


def _node_client(api, key=None, token=None, deployment=None) -> node_api.Api:
    client = node_api.Api("http://testserver", token, signing_key=key, deployment_id=deployment)
    client.client = api.client  # the TestClient is an httpx.Client: the real node code talks to the real routes
    client._wait = lambda seconds: None
    return client


def _enroll_signed(api, name="dc-signed-01"):
    node_id, reg = _registration(api, name)
    key = ed25519.Ed25519PrivateKey.generate()
    client = _node_client(api, key)
    data = client.enroll({"registration_token": reg, "hostname": "n1", "version": "1.1",
                          "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    client.token, client.deployment_id = data["node_token"], data["deployment_id"]
    return node_id, client, data


def _signed_headers(key, method, path, body: bytes, token, ts=None, nonce=None):
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(18)
    sig = key.sign(node_auth.signing_message(method, path, ts, nonce, body))
    return {"X-ZS-Node-Token": token, "X-ZS-Timestamp": ts, "X-ZS-Nonce": nonce,
            "X-ZS-Signature": base64.b64encode(sig).decode(), "Content-Type": "application/json"}


# ----------------------------------------------------------------------------- deployment id
def test_every_node_response_carries_the_deployment_id(api, world):
    engine, _ = world
    node_id, client, data = _enroll_signed(api)
    dep = data["deployment_id"]
    with Session(engine) as s:
        assert s.get(CbomDeployment, 1).deployment_id == dep
    c = api.client
    assert c.post("/cbom/node/heartbeat", json={}).headers[DEP] == dep  # 401 (no token) raised in the auth step
    assert c.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": "zsn_wrong"}, json={}).headers[DEP] == dep
    assert c.post("/cbom/node/enroll", json={"registration_token": "zsr_" + "x" * 30}).headers[DEP] == dep  # 401
    assert c.post("/cbom/node/enroll", json={"bad": 1}).headers[DEP] == dep  # 400
    assert c.post("/cbom/node/nope", json={}).headers[DEP] == dep  # 404 from the router
    assert c.get("/cbom/node/heartbeat").headers[DEP] == dep  # 405
    assert DEP not in c.get("/health").headers  # only the node API is stamped
    # a new worker (empty cache) reads the same row; it is never re-created
    node_auth._DEPLOYMENT.clear()
    assert node_auth.deployment_id(engine) == dep
    assert c.post("/cbom/node/heartbeat", json={}).headers[DEP] == dep


def test_rate_limited_node_answers_are_stamped_too(api, world, monkeypatch):
    _enroll_signed(api)
    monkeypatch.setattr(cbom_http.enroll_limiter, "times", 0)
    r = api.client.post("/cbom/node/enroll", json={"registration_token": "zsr_" + "x" * 30})
    assert r.status_code == 429 and r.headers.get(DEP)


def test_wrong_server_401_two_backends_with_different_deployment_ids(api, world, monkeypatch, tmp_path):
    """Backend A enrolled the node.  Backend B (another deployment: staging, a restored copy elsewhere) answers 401
    with ITS id: the node keeps its token (WrongServer).  A's own 401 (node reset) is authoritative (Unauthorized)."""
    engine_a, _ = world
    node_id, client, data = _enroll_signed(api)
    assert client.heartbeat({"version": "1.1"})["stop_all_network"] is False
    engine_b = create_engine(f"sqlite:///{tmp_path / 'b.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine_b)
    for module in (cbom_http, cbom_node, node_auth):
        monkeypatch.setattr(module, "get_db", lambda: engine_b)
    raw = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": client.token}, json={})
    assert raw.status_code == 401 and raw.headers[DEP] != data["deployment_id"]
    with pytest.raises(node_api.WrongServer):
        client.heartbeat({})
    with pytest.raises(node_api.WrongServer):  # an enroll refused by B does not count as A refusing it
        client.enroll({"registration_token": "zsr_" + "y" * 30})
    for module in (cbom_http, cbom_node, node_auth):
        monkeypatch.setattr(module, "get_db", lambda: engine_a)
    assert client.heartbeat({})["pending_jobs"] == 0  # back on A: the kept token still works
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/reset").status_code == 200
    with pytest.raises(node_api.Unauthorized) as err:
        client.heartbeat({})
    assert err.value.deployment == data["deployment_id"]


# ----------------------------------------------------------------------------- signed requests
def test_signed_node_full_round_trip(api, world):
    engine, _ = world
    node_id, client, data = _enroll_signed(api)
    assert data["signing"] == "required"
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any")).json()["source"]
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "signed-run-0001"})
    assert run.status_code == 201, run.text
    payload = client.claim()
    job = payload["job"]
    out = client.assets(job["id"], job["attempt"], job["lease_id"], "b1", [
        {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443", "facts": {"protocols": ["TLSv1.0"]}}])
    assert out["accepted"] == 1
    done = client.result(job["id"], job["attempt"], {"lease_id": job["lease_id"], "status": "success",
                                                     "result": {"counts": {"total": 1, "ok": 1}}})
    assert done["status"] == "success"
    node = api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]
    assert node["signing"] == "required"
    with Session(engine) as s:
        assert len(s.exec(select(CbomNodeNonce).where(CbomNodeNonce.node_id == node_id)).all()) >= 4
    assert src["id"]


def test_unsigned_replayed_skewed_and_tampered_requests_are_refused(api, world):
    node_id, client, data = _enroll_signed(api)
    key, token, c = client.signing_key, client.token, api.client
    path, body = "/cbom/node/heartbeat", b'{"version":"1.1"}'
    # downgrade: this node has a key on file, so an unsigned request (a stolen token alone) is refused
    r = c.post(path, headers={"X-ZS-Node-Token": token, "Content-Type": "application/json"}, content=body)
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_required"
    good = _signed_headers(key, "POST", path, body, token)
    assert c.post(path, headers=good, content=body).status_code == 200
    r = c.post(path, headers=good, content=body)  # the same request again
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "replay"
    for skew in (-400, 400):
        r = c.post(path, headers=_signed_headers(key, "POST", path, body, token, ts=int(time.time()) + skew), content=body)
        assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "clock_skew"
    near = _signed_headers(key, "POST", path, body, token, ts=int(time.time()) - 200)  # inside the window
    assert c.post(path, headers=near, content=body).status_code == 200
    tampered = _signed_headers(key, "POST", path, body, token)
    r = c.post(path, headers=tampered, content=b'{"version":"9.9"}')
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_invalid"
    other_path = _signed_headers(key, "POST", "/cbom/node/jobs/claim", b"", token)
    r = c.post(path, headers=other_path, content=b"")
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_invalid"
    stranger = ed25519.Ed25519PrivateKey.generate()
    r = c.post(path, headers=_signed_headers(stranger, "POST", path, body, token), content=body)
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_invalid"
    bad_nonce = _signed_headers(key, "POST", path, body, token, nonce="short")
    assert c.post(path, headers=bad_nonce, content=body).headers["X-ZS-Refused"] == "signature_invalid"
    # the signature is checked before the body is parsed: invalid JSON with a bad signature is a 403, not a 400
    assert c.post(path, headers=_signed_headers(stranger, "POST", path, b"{", token), content=b"{").status_code == 403
    # a refused request never answers 401 (which would make the node drop its token)
    assert client.heartbeat({"version": "1.1"})["pending_jobs"] == 0


def test_enrollment_signature_is_checked_before_the_registration_token_is_spent(api, world):
    node_id, reg = _registration(api)
    key = ed25519.Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    body = json.dumps({"registration_token": reg, "signing_public_key": pub}).encode()
    wrong = ed25519.Ed25519PrivateKey.generate()
    r = api.client.post("/cbom/node/enroll", content=body,
                        headers={**_signed_headers(wrong, "POST", "/cbom/node/enroll", body, None)} | {"X-ZS-Node-Token": ""})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signature_invalid"
    unsigned = api.client.post("/cbom/node/enroll", content=body, headers={"Content-Type": "application/json"})
    assert unsigned.status_code == 403 and unsigned.headers["X-ZS-Refused"] == "signature_required"
    assert api.client.post("/cbom/node/enroll", json={"registration_token": reg, "signing_public_key": "AAAA"}).status_code == 400
    ok = api.client.post("/cbom/node/enroll", content=body,
                         headers={**_signed_headers(key, "POST", "/cbom/node/enroll", body, None)} | {"X-ZS-Node-Token": ""})
    assert ok.status_code == 200, ok.text  # the token was still valid after the refusals
    assert ok.json()["signing"] == "required"


def test_legacy_nodes_work_until_the_team_requires_signed_nodes(api, world):
    engine, _ = world
    node_id, reg = _registration(api, "dc-legacy-01")
    e = api.client.post("/cbom/node/enroll", json={"registration_token": reg, "hostname": "old", "version": "1.0"})
    assert e.status_code == 200 and e.json()["signing"] == "legacy"
    token = e.json()["node_token"]
    hdr = {"X-ZS-Node-Token": token}
    assert api.client.post("/cbom/node/heartbeat", headers=hdr, json={}).status_code == 200
    assert api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]["signing"] == "legacy"
    # only an admin may require signed nodes; null leaves it as it is
    assert api("PATCH", "/1/cbom/sources/settings", "bob", json={"require_signed_nodes": True}).status_code == 400
    assert api("PATCH", "/1/cbom/sources/settings", json={"require_signed_nodes": None}).json()["settings"]["require_signed_nodes"] is False
    on = api("PATCH", "/1/cbom/sources/settings", json={"require_signed_nodes": True})
    assert on.status_code == 200 and on.json()["settings"]["require_signed_nodes"] is True
    r = api.client.post("/cbom/node/heartbeat", headers=hdr, json={})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signed_nodes_required"
    assert api.client.post("/cbom/node/jobs/claim", headers=hdr).status_code == 403
    node = api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]
    assert "requires signed scan nodes" in node["last_node_error"]
    # an old node cannot enroll either, and its registration token stays usable for a signed node
    node2, reg2 = _registration(api, "dc-legacy-02")
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg2, "version": "1.0"})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "signed_nodes_required"
    key = ed25519.Ed25519PrivateKey.generate()
    client = _node_client(api, key)
    data = client.enroll({"registration_token": reg2, "signing_public_key":
                          base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    client.token = data["node_token"]
    assert client.heartbeat({})["pending_jobs"] == 0  # signed nodes are unaffected
    # the reset node enrolls again with a key and is accepted (the error clears)
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/reset").status_code == 200
    reg3 = api("POST", f"/1/cbom/sources/nodes/{node_id}/registration-token").json()["registration_token"]
    data = client.enroll({"registration_token": reg3, "signing_public_key":
                          base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    assert data["signing"] == "required"
    node = api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]
    assert node["signing"] == "required" and node["last_node_error"] is None


def test_expired_nonces_are_swept(api, world):
    engine, _ = world
    node_id, client, _ = _enroll_signed(api)
    with Session(engine) as s:
        s.add(CbomNodeNonce(node_id=node_id, nonce="old" + "x" * 20, expires_at=dt.datetime(2020, 1, 1)))
        s.commit()
    node_auth._SWEPT[0] = 0.0
    client.heartbeat({})
    with Session(engine) as s:
        nonces = s.exec(select(CbomNodeNonce.nonce).where(CbomNodeNonce.node_id == node_id)).all()
    assert "old" + "x" * 20 not in nonces and len(nonces) >= 2


def test_deleting_a_node_deletes_its_nonces(api, world):
    engine, _ = world
    node_id, client, _ = _enroll_signed(api)
    client.heartbeat({})
    assert api("DELETE", f"/1/cbom/sources/nodes/{node_id}").status_code == 200
    with Session(engine) as s:
        assert s.exec(select(CbomNodeNonce).where(CbomNodeNonce.node_id == node_id)).all() == []


# ----------------------------------------------------------------------------- mTLS headers from the proxy
def _client_cert(cn="scan-node-1"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    import hashlib

    return quote(pem, safe=""), hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def test_mtls_headers_are_ignored_unless_the_deployment_trusts_them(api, world, monkeypatch):
    engine, _ = world
    for name in ("CBOM_MTLS_HEADER_TRUSTED", "CBOM_MTLS_REQUIRED", "CBOM_MTLS_PIN"):
        monkeypatch.delenv(name, raising=False)
    escaped, fp = _client_cert()
    node_id, reg = _registration(api)
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg},
                        headers={"X-ZS-Client-Verify": "SUCCESS", "X-ZS-Client-Cert": escaped})  # spoofed by a client
    assert r.status_code == 200
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).client_cert_sha256 is None


def test_mtls_required_and_pinned(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_MTLS_HEADER_TRUSTED", "1")
    monkeypatch.setenv("CBOM_MTLS_REQUIRED", "1")
    monkeypatch.setenv("CBOM_MTLS_PIN", "1")
    escaped, fp = _client_cert()
    other, _fp2 = _client_cert("someone-else")
    node_id, reg = _registration(api)
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "client_cert_required"
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg},
                        headers={"X-ZS-Client-Verify": "FAILED:certificate has expired", "X-ZS-Client-Cert": escaped})
    assert r.status_code == 403
    ok_hdr = {"X-ZS-Client-Verify": "SUCCESS", "X-ZS-Client-Cert": escaped}
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg}, headers=ok_hdr)
    assert r.status_code == 200, r.text  # the refusals above left the registration token usable
    token = r.json()["node_token"]
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).client_cert_sha256 == fp
    assert api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]["client_cert_sha256"] == fp
    assert api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": token, **ok_hdr}, json={}).status_code == 200
    r = api.client.post("/cbom/node/heartbeat", headers={"X-ZS-Node-Token": token}, json={})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "client_cert_required"
    r = api.client.post("/cbom/node/heartbeat", json={},
                        headers={"X-ZS-Node-Token": token, "X-ZS-Client-Verify": "SUCCESS", "X-ZS-Client-Cert": other})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "client_cert_mismatch"
    monkeypatch.delenv("CBOM_MTLS_PIN")
    r = api.client.post("/cbom/node/heartbeat", json={},
                        headers={"X-ZS-Node-Token": token, "X-ZS-Client-Verify": "SUCCESS", "X-ZS-Client-Cert": other})
    assert r.status_code == 200  # without pinning any certificate the proxy verified is enough


def test_mtls_required_without_trusted_headers_fails_closed(api, world, monkeypatch):
    monkeypatch.delenv("CBOM_MTLS_HEADER_TRUSTED", raising=False)
    monkeypatch.setenv("CBOM_MTLS_REQUIRED", "1")
    escaped, _ = _client_cert()
    _, reg = _registration(api)
    r = api.client.post("/cbom/node/enroll", json={"registration_token": reg},
                        headers={"X-ZS-Client-Verify": "SUCCESS", "X-ZS-Client-Cert": escaped})
    assert r.status_code == 403 and r.headers["X-ZS-Refused"] == "client_cert_required"
