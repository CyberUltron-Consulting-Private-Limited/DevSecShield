"""Cloud sources through the API and the cloud worker on SQLite: template switches, the Azure / Google Cloud test
button, credits, and a full Azure collection run (recorded responses, no network).

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_cloud_sources_api_wp4.py -q
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "cbom-sources-test-secret-wp4-0123456789abcdef")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-sources-test-refresh-wp4-0123456789abcdef")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import CbomCollectedAsset, CbomCollectionJob, Team, TeamMembership, User  # noqa: E402
from backend.routers import cbom_node, cbom_vendor_public  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import cloud_http  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402
from backend.workers import cbom_cloud_worker  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
import test_cbom_azure_gcp_collect as recorded  # noqa: E402

EMAIL = "alice@wp4.test"


@pytest.fixture()
def api(tmp_path, monkeypatch):
    _get_fernet.cache_clear()
    engine = create_engine(f"sqlite:///{tmp_path / 'w.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=100.0))
        s.commit()
        user = User(email=EMAIL, password="x", first_name="a", last_name="t", profile_photo=None, session_active=True,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        s.commit()
    for module in (cbom_http, cbom_node, cbom_vendor_public):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter, cbom_http.enroll_limiter,
                    cbom_http.vendor_limiter):
        limiter.requests.clear()
    client = TestClient(app)
    token = auth_utils.create_access_token(EMAIL)
    seen: list[str] = []

    def call(method, url, **kwargs):
        response = client.request(method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs)
        seen.append(response.text)
        return response

    call.engine, call.seen = engine, seen  # type: ignore[attr-defined]
    return call


def test_template_endpoint_sets_the_switch_defaults(api, monkeypatch):
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")
    off = api("GET", "/1/cbom/sources/aws/template?scope=account")
    on = api("GET", "/1/cbom/sources/aws/template?scope=account&lambda_cmk=true&glue=true")
    assert off.status_code == on.status_code == 200
    assert 'DecryptCustomerKeyLambdaEnvironments:\n    Type: String\n    Default: "false"' in off.text
    assert 'DecryptCustomerKeyLambdaEnvironments:\n    Type: String\n    Default: "true"' in on.text
    assert 'ReadGlueConnections:\n    Type: String\n    Default: "true"' in on.text
    azure = api("GET", "/1/cbom/sources/templates/azure-reader").text
    assert '--role "Key Vault Reader"' in azure and "--secret-permissions list >" in azure  # secrets: list, never get
    assert "Secrets User" not in azure and "Crypto User" not in azure and "Certificate User" not in azure
    gcp = api("GET", "/1/cbom/sources/templates/gcp-reader").text
    assert "roles/cloudkms.viewer roles/privateca.auditor roles/secretmanager.viewer" in gcp
    assert "secretAccessor" not in gcp and "cryptoKeyDecrypter" not in gcp


def test_aws_switches_are_saved_and_change_what_validation_checks(api, monkeypatch):
    from backend.routers import cbom_sources

    calls = []
    monkeypatch.setattr(cbom_sources, "validate_aws_role", lambda *a, **kw: calls.append(kw) or {
        "status": "passed", "checks": [{"check": "Role assumed with external ID", "status": "pass", "detail": "ok"}]})
    src = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "core", "test_after_save": True, "config": {
        "role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader", "decrypt_lambda_cmk": True}}).json()["source"]
    assert src["config"]["decrypt_lambda_cmk"] is True and src["config"]["read_glue"] is False
    assert calls[-1] == {"lambda_cmk": True, "read_glue": False}
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
        "config": {**src["config"], "read_glue": True}, "expected_version": src["row_version"]})
    assert r.status_code == 200 and r.json()["source"]["last_test_status"] == "never"  # a switch change needs validation again


def _azure_source(api, test=True):
    return api("POST", "/1/cbom/sources/items", json={
        "kind": "azure_subscription", "name": "azure-prod", "test_after_save": test,
        "config": {"tenant_id": recorded.TENANT, "client_id": recorded.CLIENT, "subscription_ids": [recorded.SUB]},
        "secrets": {"client_secret": recorded.CLIENT_SECRET}})


def _replay(monkeypatch):
    rec = recorded.Recorder(recorded._azure_routes())
    real = cloud_http.CloudHttp.__init__

    def init(self, transport=None):
        real(self, httpx.MockTransport(rec))

    monkeypatch.setattr(cloud_http.CloudHttp, "__init__", init)
    return rec


def test_azure_test_button_runs_live_and_stores_checks_without_the_secret(api, monkeypatch):
    _replay(monkeypatch)
    r = _azure_source(api)
    assert r.status_code == 201, r.text
    test, source = r.json()["test"], r.json()["source"]
    assert test["status"] == "passed" and [c["check"] for c in test["checks"]][0] == "Signed in to Azure Resource Manager"
    assert source["last_test_status"] == "passed" and source["last_test_result"]["checks"]
    again = api("POST", f"/1/cbom/sources/items/{source['id']}/test").json()
    assert again["status"] == "passed" and "vault(s) in subscription" in again["message"]
    assert not any(recorded.CLIENT_SECRET in text for text in api.seen)


def test_azure_test_failure_blocks_the_run_and_never_echoes_the_secret(api, monkeypatch):
    rec = _replay(monkeypatch)
    rec.routes.insert(0, (recorded._path(f"https://login.microsoftonline.com/{recorded.TENANT}/"), (401, {
        "error": "invalid_client", "error_description": f"AADSTS7000215: Invalid client secret {recorded.CLIENT_SECRET} provided."})))
    source = _azure_source(api).json()["source"]
    assert source["last_test_status"] == "failed"
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 0 and "test failed" in est["skipped"][0]["reason"]
    assert not any(recorded.CLIENT_SECRET in text for text in api.seen)


def test_azure_run_is_collected_by_the_cloud_worker(api, monkeypatch):
    _replay(monkeypatch)
    _azure_source(api)
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 4.0  # one cloud account
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "azure-run-01"})
    assert run.status_code == 201, run.text
    assert run.json()["run"]["jobs"][0]["node_id"] is None
    assert cbom_cloud_worker.run_once(api.engine, "test-worker") is True
    with Session(api.engine) as s:
        job = s.exec(select(CbomCollectionJob)).one()
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id)).all()
    assert job.status == "success" and job.asset_count == len(rows) > 0
    by_type = {}
    for row in rows:
        by_type.setdefault(row.asset_type, []).append(row)
    assert by_type["key_vault"][0].finding_codes == ["KV_NO_PURGE_PROTECTION", "KV_PUBLIC_NETWORK"]
    assert by_type["kms_key"][0].key_size == 2048 and by_type["certificate"][0].cdx_type == "certificate"
    assert all(recorded.CLIENT_SECRET not in repr(r.facts) for r in rows)


def test_azure_and_gcp_are_not_available_until_the_tenant_is_connected(api, monkeypatch):
    """Saved without a passing Save and validate (no tenant connected yet): listed, never collected or charged."""
    _azure_source(api, test=False)
    api("POST", "/1/cbom/sources/items", json={
        "kind": "gcp_project", "name": "gcp-prod", "test_after_save": False,
        "config": {"project_ids": [recorded.PROJECT], "service_account_email": recorded.GCP_CFG["service_account_email"]},
        "secrets": {"service_account_key": recorded.SA_JSON}})
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 0
    reasons = sorted(s["reason"] for s in est["skipped"])
    assert reasons == ["Not available until the Azure tenant is connected: Save and validate must pass first",
                       "Not available until the Google Cloud project is connected: Save and validate must pass first"]
    # the worker refuses too, should a job for an unvalidated source ever be claimed
    from backend.utilities.cbom_sources.planning import CLOUD_NOT_CONNECTED

    job = cbom_cloud_worker._Job(api.engine, {"job": {"id": 0, "team_id": 1, "lease_id": "x", "attempt": 1},
                                             "source": {"id": 0, "kind": "gcp_project", "config": {}, "last_test_status": "never"}})
    finished = {}
    monkeypatch.setattr(cbom_cloud_worker.J, "finish_job", lambda *a, **kw: finished.update(status=a[4], error=a[6]) or
                        type("J", (), {"asset_count": 0})())
    job.run()
    assert finished == {"status": "failure", "error": CLOUD_NOT_CONNECTED["gcp_project"]}
