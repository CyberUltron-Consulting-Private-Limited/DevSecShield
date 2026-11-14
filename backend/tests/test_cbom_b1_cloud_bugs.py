"""Owner bugs of 14 Nov 2026, Cloud & Identity lane B1 (recorded provider answers, no network):

* C1  Save and validate proves the account can READ every configured Google Cloud project (permissions held on the
      project + one real Cloud KMS read) and every configured Azure subscription; listing Cloud KMS locations, which
      Google answers for any project, is no proof.
* C2  A cloud job that read 0 of N targets (only coverage rows) fails and is refunded, never "success".
* C4  An Azure subscription that read assets while some vaults refused their keys is "Partly read · N read, G gaps",
      never "Nothing read · 0 read" (collector status, job outcome and the run API's assets_read / gaps).
* C9  A key with no automatic rotation gets the same finding (code and severity) in Google Cloud KMS, Azure Key Vault
      and Vault transit.
* C10a A fetch that runs out of time is reported as a timeout, never as a document that is "not JSON".

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_b1_cloud_bugs.py -q
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent))
import test_cbom_azure_gcp_collect as recorded
from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    Team,
)
from backend.utilities.cbom_sources import (
    azure_collect,
    cloud_http,
    gcp_collect,
    idp_collect,
    safe_fetch,
)
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.classify import classify
from backend.workers import cbom_cloud_worker
from sqlmodel import Session, select
from test_cbom_cloud_sources_api_wp4 import (
    api,  # noqa: F401  (the API + SQLite fixture)
)

UNREADABLE = "ai-mesh-firewall"
CRM = "https://cloudresourcemanager.googleapis.com/v3"
KMS = "https://cloudkms.googleapis.com/v1"
DENIED = {"error": {"code": 403, "message": "The caller does not have permission", "status": "PERMISSION_DENIED"}}


def _kms_denied(project: str) -> dict:
    return {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": (
        f"Permission 'cloudkms.keyRings.list' denied on resource 'projects/{project}/locations/global' (or it may "
        "not exist).")}}


def _gcp_unreadable_routes(project: str = UNREADABLE) -> list:
    """Google's answers for a project the service account has no role on: Cloud KMS and CA Service list their
    locations for anyone (that was the only validation check), every real list is refused."""
    loc = f"projects/{project}/locations/asia-south1"
    return [
        (recorded._at("https://oauth2.googleapis.com/token"),
         (200, {"access_token": recorded.GCP_TOKEN, "expires_in": 3599, "token_type": "Bearer"})),
        (recorded._at(f"{CRM}/projects/{project}:testIamPermissions"), (403, DENIED)),
        (recorded._at(f"{KMS}/projects/{project}/locations"), (200, {"locations": [{"name": loc, "locationId": "asia-south1"}]})),
        (lambda r, _f: r.url.host == "cloudkms.googleapis.com" and r.url.path.endswith("/keyRings"), (403, _kms_denied(project))),
        (recorded._at(f"https://privateca.googleapis.com/v1/projects/{project}/locations"),
         (200, {"locations": [{"name": loc, "locationId": "asia-south1"}]})),
        (lambda r, _f: r.url.host == "privateca.googleapis.com", (403, DENIED)),
        (lambda r, _f: r.url.host in ("secretmanager.googleapis.com", "certificatemanager.googleapis.com",
                                      "compute.googleapis.com", "storage.googleapis.com"), (403, DENIED)),
    ]


# what the collector lists (keys, key versions, CA pools and CAs, secrets): the permissions Save and validate asks for
COLLECTOR_PERMISSIONS = ["cloudkms.keyRings.list", "cloudkms.cryptoKeys.list", "cloudkms.cryptoKeyVersions.list",
                         "privateca.caPools.list", "privateca.certificateAuthorities.list", "secretmanager.secrets.list"]


def _all_permissions(project: str):
    return (recorded._at(f"{CRM}/projects/{project}:testIamPermissions"), (200, {"permissions": COLLECTOR_PERMISSIONS}))


def _validate_gcp(routes, cfg):
    rec = recorded.Recorder(routes)
    return gcp_collect.test_gcp(cfg, {"service_account_key": recorded.SA_JSON}, transport=httpx.MockTransport(rec)), rec


# ----------------------------------------------------------------------------- C1
def test_c1_gcp_validation_fails_for_a_project_the_account_cannot_read():
    out, rec = _validate_gcp(_gcp_unreadable_routes(), {**recorded.GCP_CFG, "project_ids": [UNREADABLE]})
    assert out["status"] == "failed", out
    failed = {c["check"]: c["detail"] for c in out["checks"] if c["status"] == "fail"}
    assert f"Read project {UNREADABLE}" in failed and f"cannot read project {UNREADABLE}" in failed[f"Read project {UNREADABLE}"]
    assert "cloudkms.keyRings.list refused" in failed[f"List Cloud KMS key rings in {UNREADABLE}"]
    assert UNREADABLE in out["message"]
    # the permission check asked for exactly what the collector uses
    post = next(r for r in rec.seen if r["url"].endswith(":testIamPermissions"))
    assert post["method"] == "POST" and post["auth"] == f"Bearer {recorded.GCP_TOKEN}"
    assert list(gcp_collect.READ_PERMISSIONS) == COLLECTOR_PERMISSIONS


def test_c1_gcp_validation_checks_every_configured_project_and_names_missing_permissions():
    readable = [*recorded._gcp_routes()]
    readable.insert(0, _all_permissions(recorded.PROJECT))
    # project 2 grants only part of what the collector needs
    partial = (recorded._at(f"{CRM}/projects/half-granted:testIamPermissions"),
               (200, {"permissions": ["cloudkms.keyRings.list", "cloudkms.cryptoKeys.list"]}))
    ring = (recorded._at(f"{KMS}/projects/half-granted/locations/global/keyRings"), (200, {}))
    routes = [partial, ring, *readable, *_gcp_unreadable_routes()]
    out, _rec = _validate_gcp(routes, {**recorded.GCP_CFG, "project_ids": [recorded.PROJECT, "half-granted", UNREADABLE]})
    by_check = {c["check"]: c for c in out["checks"]}
    assert out["status"] == "failed"
    assert by_check[f"Read project {recorded.PROJECT}"]["status"] == "pass"
    half = by_check["Read project half-granted"]
    assert half["status"] == "fail" and "privateca.caPools.list" in half["detail"] and "secretmanager.secrets.list" in half["detail"]
    assert by_check[f"Read project {UNREADABLE}"]["status"] == "fail"


def test_c1_gcp_validation_passes_only_with_proven_read_access():
    routes = [_all_permissions(recorded.PROJECT), *recorded._gcp_routes()]
    out, rec = _validate_gcp(routes, recorded.GCP_CFG)
    assert out["status"] == "passed", out
    assert out["message"] == f"Read access proven on 1 project(s): {recorded.PROJECT}"
    assert any(r["url"].startswith(f"{KMS}/projects/{recorded.PROJECT}/locations/global/keyRings") for r in rec.seen)
    assert all(r["host"].endswith(".googleapis.com") for r in rec.seen)


def test_c1_azure_validation_reads_every_configured_subscription():
    sub2 = "11111111-1111-1111-1111-111111111111"
    denied = (recorded._path(f"https://management.azure.com/subscriptions/{sub2}/providers/Microsoft.KeyVault/vaults?"),
              (403, {"error": {"code": "AuthorizationFailed", "message": (
                  f"The client does not have authorization to perform action 'Microsoft.KeyVault/vaults/read' over "
                  f"scope '/subscriptions/{sub2}'")}}))
    rec = recorded.Recorder([denied, *recorded._azure_routes()])
    out = azure_collect.test_azure({**recorded.AZ_CFG, "subscription_ids": [recorded.SUB, sub2]},
                                   {"client_secret": recorded.CLIENT_SECRET}, transport=httpx.MockTransport(rec))
    assert out["status"] == "failed", out
    by_check = {c["check"]: c for c in out["checks"]}
    assert by_check[f"List key vaults in {recorded.SUB}"]["status"] == "pass"
    assert by_check[f"List key vaults in {sub2}"]["status"] == "fail"
    assert f"cannot read subscription {sub2}" in by_check[f"List key vaults in {sub2}"]["detail"]


# ----------------------------------------------------------------------------- C2
def _replay(monkeypatch, routes):
    rec = recorded.Recorder(routes)
    real = cloud_http.CloudHttp.__init__
    monkeypatch.setattr(cloud_http.CloudHttp, "__init__", lambda self, transport=None: real(self, httpx.MockTransport(rec)))
    return rec


def test_c2_gcp_job_that_read_0_of_1_projects_fails_and_refunds_its_credits(api, monkeypatch):  # noqa: F811
    rec = _replay(monkeypatch, [_all_permissions(UNREADABLE),
                                (recorded._at(f"{KMS}/projects/{UNREADABLE}/locations/global/keyRings"), (200, {})),
                                *_gcp_unreadable_routes()])
    created = api("POST", "/1/cbom/sources/items", json={
        "kind": "gcp_project", "name": "gcp-ai-mesh", "test_after_save": True,
        "config": {"project_ids": [UNREADABLE], "service_account_email": recorded.GCP_CFG["service_account_email"]},
        "secrets": {"service_account_key": recorded.SA_JSON}})
    assert created.status_code == 201 and created.json()["source"]["last_test_status"] == "passed", created.text
    rec.routes[:] = _gcp_unreadable_routes()  # the access is withdrawn after validation (or was never real: C1)
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "gcp-c2-run"})
    assert run.status_code == 201, run.text
    with Session(api.engine) as s:
        assert s.get(Team, 1).credit_balance == pytest.approx(96.0)  # one cloud account: 4 credits charged
    assert cbom_cloud_worker.run_once(api.engine, "test-worker") is True
    with Session(api.engine) as s:
        job = s.exec(select(CbomCollectionJob)).one()
        run_row = s.get(CbomCollectionRun, job.run_id)
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id)).all()
        balance = s.get(Team, 1).credit_balance
    assert job.status == "failure" and job.outcome == "failed"
    assert job.error.startswith("No target could be read (0 of 1): gcp:ai-mesh-firewall")
    assert job.refunded is True and run_row.credits_refunded_c == run_row.credits_charged_c == 400
    assert balance == pytest.approx(100.0)
    assert run_row.status == "failed"
    # what was refused stays on the run, as coverage rows
    assert rows and {r.asset_type for r in rows} == {"coverage"}
    assert job.result["counts"] == {"total": 1, "ok": 0, "partial": 0, "failed": 1, "skipped": 0}


def test_c2_a_job_that_stored_only_coverage_rows_is_refunded_like_one_that_stored_nothing():
    """The shared refund rule (finish_job): outcome "failed" and no ASSET read.  Before, any coverage row counted as
    "stored", so a job whose every target was refused kept its credits."""
    result = {"counts": {"total": 2, "ok": 0, "partial": 0, "failed": 2, "skipped": 0}}
    collect = SimpleNamespace(kind="collect")
    assert J._outcome(collect, "success", result, stored=5, read=0) == ("failed", {})
    assert J._outcome(collect, "success", result, stored=5, read=3) == ("partial", {})  # something WAS read (C4)
    assert J._outcome(collect, "success", result, stored=5) == ("failed", {})  # callers without read: unchanged


# ----------------------------------------------------------------------------- C4
LOCKED_2 = {**recorded.LOCKED_VAULT, "id": recorded.LOCKED_VAULT["id"].replace("locked-vault", "locked-vault2"),
            "name": "locked-vault2",
            "properties": {**recorded.LOCKED_VAULT["properties"], "vaultUri": "https://locked-vault2.vault.azure.net/"}}
RBAC_403 = {"error": {"code": "Forbidden", "message": "Caller is not authorized to perform action on resource.",
                      "innererror": {"code": "ForbiddenByRbac"}}}


def _azure_two_gaps():
    return [(recorded._path("https://locked-vault2.vault.azure.net/"), (403, RBAC_403)),
            *recorded._azure_routes(vaults=(recorded.SAMPLE_VAULT, recorded.LOCKED_VAULT, LOCKED_2))]


def test_c4_azure_subscription_read_with_two_refused_vaults_is_partial_not_failed():
    out, found, _rec = recorded._azure(_azure_two_gaps())
    target = out["targets"][0]
    assert target["status"] == "partial" and target["services"]["keyvault"] == "partial", target
    assert out["counts"] == {"total": 1, "ok": 0, "partial": 1, "failed": 0, "skipped": 0}
    assert "2 vault(s) not fully read: locked-vault, locked-vault2" in target["error"]
    read = [a for a in found if a["type"] != "coverage"]
    gaps = [a for a in found if a["type"] == "coverage"]
    assert len(read) == 6 and len(gaps) == 6  # 3 vault rows, key, certificate, secret; keys/certs/secrets x 2 vaults
    # each gap names the part of the vault it left out, so drift never reads a refused vault's keys as removed
    assert {tuple(g["facts"]["scope"]) for g in gaps} == {
        (f"https://{v}.vault.azure.net/{p}/",) for v in ("locked-vault", "locked-vault2") for p in ("keys", "certificates", "secrets")}


def test_c4_run_api_says_partly_read_with_assets_read_and_gaps(api, monkeypatch):  # noqa: F811
    _replay(monkeypatch, _azure_two_gaps())
    created = api("POST", "/1/cbom/sources/items", json={
        "kind": "azure_subscription", "name": "azure-prod", "test_after_save": True,
        "config": {"tenant_id": recorded.TENANT, "client_id": recorded.CLIENT, "subscription_ids": [recorded.SUB]},
        "secrets": {"client_secret": recorded.CLIENT_SECRET}})
    assert created.json()["source"]["last_test_status"] == "passed", created.text
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "azure-c4-run"}).json()["run"]
    assert cbom_cloud_worker.run_once(api.engine, "test-worker") is True
    page = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?page_size=50").json()
    job = page["targets"][0]
    assert job["status"] == "success" and job["outcome"] == "partial", job
    assert job["assets_read"] == 6 and job["gaps"] == 2 and job["asset_count"] == 12
    with Session(api.engine) as s:
        assert s.get(CbomCollectionJob, job["job_id"]).refunded is False  # it read something: charged


# ----------------------------------------------------------------------------- C9
def test_c9_no_rotation_is_the_same_finding_in_google_azure_and_vault():
    _out, gcp_found, _rec = recorded._gcp(recorded._gcp_routes())
    gcp_key = next(a for a in gcp_found if a["type"] == "kms_key" and a["name"] == "no-rotation")
    no_policy = {"id": "https://myvault.vault.azure.net/keys/CreateSoftKeyTest/rotationpolicy", "lifetimeActions": [
        {"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}], "attributes": {}}
    azure_key = azure_collect._key_asset(recorded.GET_KEY, no_policy, None, "myvault", "azure:sub")
    assert azure_key["facts"]["rotation_enabled"] is False
    cases = {
        "gcp": classify("kms_key", gcp_key["algorithm"], gcp_key["key_size"], None, gcp_key["facts"]),
        "azure": classify("kms_key", azure_key["algorithm"], azure_key["key_size"], None, azure_key["facts"]),
        "vault": classify("managed_key", "AES", 256, None, {"store": "vault_transit", "key_class": "secret",
                                                           "auto_rotate_period_s": 0}),
    }
    for name, out in cases.items():
        assert "KMS_NO_ROTATION" in out["finding_codes"], (name, out["finding_codes"])
        assert "KEY_NO_ROTATION" not in out["finding_codes"], name
    assert cases["azure"]["finding_codes"] == ["KMS_NO_ROTATION", "QUANTUM_VULNERABLE"]
    assert cases["vault"]["finding_codes"] == cases["gcp"]["finding_codes"] == ["KMS_NO_ROTATION"]
    # same severity, finding by finding
    assert {name: out["impacts"]["KMS_NO_ROTATION"] for name, out in cases.items()} == {
        "gcp": "Medium", "azure": "Medium", "vault": "Medium"}
    assert "az keyvault key rotation-policy update" in cases["azure"]["texts"]["KMS_NO_ROTATION"]
    assert "auto_rotate_period" in cases["vault"]["texts"]["KMS_NO_ROTATION"]


def test_c9_rotated_or_unknown_rotation_raises_nothing():
    rotated = azure_collect._key_asset(recorded.GET_KEY, recorded.ROTATION, None, "myvault", "azure:sub")
    unknown = azure_collect._key_asset(recorded.GET_KEY, None, "Forbidden", "myvault", "azure:sub")
    for key in (rotated, unknown):
        assert "KMS_NO_ROTATION" not in classify("kms_key", key["algorithm"], key["key_size"], None, key["facts"])["finding_codes"]
    vault_on = classify("managed_key", "AES", 256, None, {"store": "vault_transit", "key_class": "secret",
                                                          "auto_rotate_period_s": 2592000})
    assert "KMS_NO_ROTATION" not in vault_on["finding_codes"]


# ----------------------------------------------------------------------------- C10a
IDP_HOST = "sso.slow.example"
PUBLIC_IP = "93.184.216.34"  # a public address: the test resolver answers it, the connection lands on loopback


@pytest.fixture
def slow_idp(tmp_path, monkeypatch):
    """A real HTTPS IdP whose discovery answer stops after 20 of 400 bytes; ``mode`` "hang" keeps the connection
    open (a server that stalls), "close" hangs up early."""
    for name in ("CBOM_IDP_ALLOWED_PRIVATE", "CBOM_LAB_ALLOW_PRIVATE_FETCH", "CBOM_LAB_CA_FILE"):
        monkeypatch.delenv(name, raising=False)
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, IDP_HOST)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(3)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(IDP_HOST)]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    state = {"mode": "hang"}
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "400")
            self.end_headers()
            self.wfile.write(b'{"issuer": "https://s')
            self.wfile.flush()
            if state["mode"] == "hang":
                release.wait(10)
            self.close_connection = True

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    real_connect, real_resolve = socket.create_connection, socket.getaddrinfo
    monkeypatch.setattr(safe_fetch.socket, "getaddrinfo", lambda host, p, *a, **k: (
        real_resolve(host, p, *a, **k) if host == "127.0.0.1" else [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, p))]))
    monkeypatch.setattr(safe_fetch.socket, "create_connection",
                        lambda address, *a, **k: real_connect(("127.0.0.1", address[1]), *a, **k))
    monkeypatch.setenv("CBOM_EXTRA_CA_FILE", str(tmp_path / "c.pem"))
    yield SimpleNamespace(url=f"https://{IDP_HOST}:{port}/.well-known/openid-configuration", state=state)
    release.set()
    srv.shutdown()


def test_c10a_the_whole_fetch_timing_out_is_a_timeout_not_a_bad_document(slow_idp, monkeypatch):
    monkeypatch.setattr(safe_fetch, "TOTAL_TIMEOUT", 1.0)  # the 30 s deadline, shortened; per-read wait stays 10 s
    started = time.monotonic()
    out = idp_collect.collect_idp({"provider": "oidc_discovery", "metadata_url": slow_idp.url}, "slow-sso")
    target = out["targets"][0]
    assert "JSON" not in target["error"] and "timed out" in target["error"], target
    assert target["status"] == "timeout", target
    assert time.monotonic() - started < 5  # the deadline holds even when the response closes the connection
    gap = next(a for a in out["assets"] if a["type"] == "coverage")
    assert gap["facts"]["status"] == "timeout"


def test_c10a_one_read_timing_out_is_a_timeout(slow_idp, monkeypatch):
    monkeypatch.setattr(safe_fetch, "TIMEOUT", 0.5)  # a read that waits longer than the per-read limit
    with pytest.raises(safe_fetch.FetchTimeout, match="timed out"):
        safe_fetch.fetch(slow_idp.url)


def test_c10a_a_server_that_hangs_up_early_is_not_a_bad_document_either(slow_idp):
    slow_idp.state["mode"] = "close"
    with pytest.raises(safe_fetch.FetchError, match="closed the connection after 21 of 400 bytes") as err:
        safe_fetch.fetch(slow_idp.url)
    assert not isinstance(err.value, safe_fetch.FetchTimeout)
