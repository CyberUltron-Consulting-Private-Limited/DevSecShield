"""CT discovery through the API and the cloud worker on SQLite, with recorded provider answers (fixtures/ct):
the server flag, one source per team, the saved-domain move, limits, the estimate equal to the charge, a full
collection, a refund when nothing was read, drift (a new certificate is a new_asset event), correlation with the
same certificate seen elsewhere (fingerprint, serial), and the CycloneDX export's provenance.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_ct_api.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "cbom-sources-test-secret-ct-0123456789abcdef")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-sources-test-refresh-ct-0123456789abcdef")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun,  # noqa: E402
                                CbomCollectionSource, CbomDriftEvent, Team, TeamMembership, User)
from backend.routers import cbom_node, cbom_vendor_public  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import collections_view as CV  # noqa: E402
from backend.utilities.cbom_sources import ct_providers as P  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402
from backend.workers import cbom_cloud_worker  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from test_cbom_ct_provider import Replay, oracle, recorded  # noqa: E402

EMAIL = "alice@ct.test"
BASE = "/1/cbom/sources"


@pytest.fixture()
def api(tmp_path, monkeypatch):
    _get_fernet.cache_clear()
    engine = create_engine(f"sqlite:///{tmp_path / 'ct.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=1000.0))
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
    monkeypatch.setenv("CBOM_CT_DISCOVERY", "1")
    monkeypatch.setenv("CBOM_CT_PROVIDER", "certspotter,crtsh")
    monkeypatch.setattr(P, "CACHE", P.AnswerCache(0))
    monkeypatch.setattr(P, "bucket", lambda name, default: P.TokenBucket(1000, 100000))
    replay = Replay()
    real_init = P.CtHttp.__init__

    def init(self, transport=None, clock=None, rng=None):
        real_init(self, transport=replay.transport(), clock=clock, rng=rng)

    monkeypatch.setattr(P.CtHttp, "__init__", init)
    client = TestClient(app)
    token = auth_utils.create_access_token(EMAIL)

    def call(method, url, **kwargs):
        return client.request(method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs)

    call.engine, call.replay = engine, replay  # type: ignore[attr-defined]
    return call


def _ct(api, domains, **extra):
    return api("POST", f"{BASE}/items", json={"kind": "ct_logs", "name": "anything", "config": {"domains": domains, **extra}})


def _run(api, rid):
    run = api("POST", f"{BASE}/runs", json={"include": {"cloud": True}, "client_request_id": rid})
    assert run.status_code == 201, run.text
    while cbom_cloud_worker.run_once(api.engine, "ct-test-worker"):
        pass
    with Session(api.engine) as s:
        return s.get(CbomCollectionRun, run.json()["run"]["id"])


# ----------------------------------------------------------------------------- flag, singleton, saved domains, limits
def test_flag_off_refuses_the_source_and_says_so(api, monkeypatch):
    monkeypatch.setenv("CBOM_CT_DISCOVERY", "0")
    settings = api("GET", f"{BASE}/settings").json()["settings"]
    assert settings["ct_discovery_enabled"] is False and settings["ct_providers"] == ["certspotter", "crtsh"]
    r = _ct(api, ["zeroshield.ai"])
    assert r.status_code == 400 and "not enabled on this server" in r.text


def test_one_source_per_team_with_a_fixed_name(api):
    first = _ct(api, ["zeroshield.ai"])
    assert first.status_code == 201, first.text
    source = first.json()["source"]
    assert source["name"] == "Certificate Transparency" and source["kind"] == "ct_logs" and source["node_id"] is None
    again = _ct(api, ["example.com"])
    assert again.status_code == 409 and "already has a Certificate Transparency source" in again.text
    rename = api("PATCH", f"{BASE}/items/{source['id']}", json={"name": "Other", "expected_version": source["row_version"]})
    assert rename.status_code == 400 and "keeps its name" in rename.text


def test_saved_domains_move_into_the_source_in_one_step(api):
    sv = api("GET", f"{BASE}/settings").json()["settings"]["row_version"]
    put = api("PATCH", f"{BASE}/settings", json={"cert_domains": ["zeroshield.ai", "example.com"], "expected_version": sv})
    assert put.status_code == 200, put.text
    r = api("POST", f"{BASE}/items", json={"kind": "ct_logs", "name": "x", "import_saved_domains": True,
                                           "config": {"domains": ["bücher.de", "example.com"]}})
    assert r.status_code == 201, r.text
    assert r.json()["source"]["config"]["domains"] == ["xn--bcher-kva.de", "example.com", "zeroshield.ai"]
    assert api("GET", f"{BASE}/settings").json()["settings"]["cert_domains"] == []
    audit = api("GET", f"{BASE}/audit").json()
    assert any("cert_domains:moved_to_source" in (e.get("changed_fields") or []) for e in audit.get("events", audit.get("items", [])))


def test_import_is_only_for_ct_and_bad_names_are_refused(api):
    r = api("POST", f"{BASE}/items", json={"kind": "idp", "name": "x", "import_saved_domains": True,
                                           "config": {"provider": "oidc_discovery", "metadata_url": "https://idp.example/.well-known/openid-configuration"}})
    assert r.status_code == 400 and "import_saved_domains" in r.text
    r = _ct(api, ["10.0.0.1"])
    assert r.status_code == 400 and "IP address" in r.text
    r = _ct(api, [f"d{i}.example" for i in range(1001)])
    assert r.status_code == 400 and "at most 1000" in r.text
    assert _ct(api, [f"d{i}.example" for i in range(1000)]).status_code == 201


# ----------------------------------------------------------------------------- estimate = charge, full run
def test_estimate_counts_searched_domains_and_equals_the_charge(api):
    assert _ct(api, ["zeroshield.ai", "www.zeroshield.ai", "example.com"]).status_code == 201
    est = api("POST", f"{BASE}/estimate", json={"include": {"cloud": True}}).json()
    item = next(i for i in est["items"] if i["kind"] == "ct_logs")
    assert (item["units"], item["unit"], item["credits"], item["status"]) == (2, "domains", 0.4, "queued")
    assert est["total_credits"] == 0.4
    overview = api("GET", f"{BASE}/overview").json()
    assert overview["rates"]["ct_domain"] == 0.2 and overview["settings"]["ct_discovery_enabled"] is True
    run = _run(api, "ct-estimate-01")
    assert run.credits_charged_c == 40 and run.credits_refunded_c == 0


def test_flag_turned_off_later_skips_the_source_with_its_reason(api, monkeypatch):
    assert _ct(api, ["zeroshield.ai"]).status_code == 201
    monkeypatch.setenv("CBOM_CT_DISCOVERY", "0")
    est = api("POST", f"{BASE}/estimate", json={"include": {"cloud": True}}).json()
    item = next(i for i in est["items"] if i["kind"] == "ct_logs")
    assert item["status"] == "skipped" and item["reason"] == "Certificate Transparency discovery is not enabled on this server"
    assert est["total_credits"] == 0


def test_cloud_worker_collects_and_the_api_classifies(api):
    assert _ct(api, ["zeroshield.ai", "example.com"], expected_issuers=["Let's Encrypt", "Google Trust"]).status_code == 201
    run = _run(api, "ct-full-01")
    with Session(api.engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).one()
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id)).all()
    certs = [r for r in rows if r.asset_type == "certificate"]
    assert job.status == "success" and job.outcome == "ok" and job.node_id is None
    gaps = [r for r in rows if r.asset_type == "coverage"]
    assert len(certs) == 25 + 17 and job.asset_count == len(certs) + len(gaps)
    # the only gap: example.com's 8 certificates whose revocation status Cert Spotter does not know (revoked: null)
    assert [g.facts["check"] for g in gaps] == ["CT revocation status"] and gaps[0].facts["detail"].startswith("8 ")
    want = {r["serial"] for r in oracle("certspotter_zeroshield")} | {r["serial"] for r in oracle("certspotter_example")}
    assert {r.facts["serial"] for r in certs} == want
    assert all(r.cdx_type == "certificate" and r.quantum_vulnerable is True for r in certs)
    codes = {c for r in certs for c in r.finding_codes}
    assert {"CERT_UNEXPECTED_CA", "CERT_REVOKED", "CERT_WILDCARD_SPRAWL", "CERT_EXPIRES_30D"} <= codes
    # each domain: its page, then the empty page that ends the listing (Cert Spotter's documented rule)
    assert job.result["targets"][0]["provider"] == "certspotter" and job.result["provider_calls"] == {"certspotter": 4}
    assert len(api.replay.calls) == 4


def test_a_run_that_reads_no_domain_fails_and_is_refunded(api):
    status, headers, body = recorded("crtsh_reliability_00")  # 502 from both providers, for every try
    api.replay.override[("certspotter", "zeroshield.ai")] = lambda r: httpx.Response(status, headers=headers, content=body)
    api.replay.override[("crtsh", "zeroshield.ai")] = lambda r: httpx.Response(status, headers=headers, content=body)
    assert _ct(api, ["zeroshield.ai"]).status_code == 201
    run = _run(api, "ct-fail-01")
    with Session(api.engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).one()
        team = s.get(Team, 1)
    assert job.status == "failure" and job.error.startswith("No domain could be searched") and "HTTP 502" in job.error
    assert job.refunded and run.credits_refunded_c == run.credits_charged_c == 20 and team.credit_balance == 1000.0


def test_the_next_run_searches_first_what_the_last_run_could_not(api):
    status, headers, body = recorded("crtsh_reliability_00")
    api.replay.override[("certspotter", "zeroshield.ai")] = lambda r: httpx.Response(status, headers=headers, content=body)
    api.replay.override[("crtsh", "zeroshield.ai")] = lambda r: httpx.Response(status, headers=headers, content=body)
    assert _ct(api, ["zeroshield.ai", "example.com"]).status_code == 201
    first = _run(api, "ct-order-01")
    with Session(api.engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == first.id)).one()
    assert job.outcome == "partial" and [t["target"] for t in job.result["targets"]] == ["example.com", "zeroshield.ai"]
    api.replay.override.clear()
    api.replay.calls.clear()
    _run(api, "ct-order-02")
    order = list(dict.fromkeys(parse_qs(urlsplit(u).query)["domain"][0] for u in api.replay.calls))
    assert order == ["zeroshield.ai", "example.com"]


# ----------------------------------------------------------------------------- drift
def test_a_new_certificate_for_a_domain_is_a_new_asset_drift_event(api):
    """Derived first answer: the recorded zeroshield.ai answer without its newest issuance; second run: the recording."""
    rows = json.loads(recorded("certspotter_zeroshield")[2])
    newest = max(rows, key=lambda r: r["not_before"])
    older = json.dumps([r for r in rows if r["id"] != newest["id"]]).encode()
    api.replay.override[("certspotter", "zeroshield.ai")] = lambda r: httpx.Response(200, content=older)
    assert _ct(api, ["zeroshield.ai"]).status_code == 201
    first = _run(api, "ct-drift-01")
    api.replay.override.pop(("certspotter", "zeroshield.ai"))
    second = _run(api, "ct-drift-02")
    from backend.utilities.cbom_sources.drift import record_run_drift

    now = dt.datetime.utcnow()
    with Session(api.engine) as s:
        for run in (first, second):
            record_run_drift(s, s.get(CbomCollectionRun, run.id), now)
        s.commit()
        events = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == second.id)).all()
    new = [e for e in events if e.kind == "new_asset"]
    assert len(new) == 1
    der = base64.b64decode(newest["cert_der"])
    from cryptography import x509

    serial = format(x509.load_der_x509_certificate(der).serial_number, "x")
    assert serial in json.dumps(new[0].detail) + (new[0].asset_label or "")
    assert not [e for e in events if e.kind == "removed_asset"]


# ----------------------------------------------------------------------------- correlation (CB-21 slice)
def _node_row(s, team_id, kind, facts, *, run_id, target="10.0.0.5:443", location="tls:10.0.0.5:443#chain0"):
    source = CbomCollectionSource(team_id=team_id, owner_user_id=1, kind=kind, name=f"{kind}-src", name_lower=f"{kind}-src",
                                  config={}, created_at=dt.datetime.utcnow())
    s.add(source)
    s.flush()
    job = CbomCollectionJob(team_id=team_id, run_id=run_id, source_id=source.id, kind="collect", status="success",
                            attempts=1, finished_at=dt.datetime.utcnow() - dt.timedelta(days=1), params={})
    s.add(job)
    s.flush()
    s.add(CbomCollectedAsset(team_id=team_id, run_id=run_id, job_id=job.id, source_id=source.id, attempt=1,
                             asset_key=f"k-{kind}", asset_type="certificate", cdx_type="certificate", target=target,
                             location=location, name="node", algorithm="ECDSA", key_size=256, facts=facts,
                             finding_codes=[]))


def test_ct_merges_with_the_node_by_fingerprint_and_with_acm_by_serial(api):
    assert _ct(api, ["zeroshield.ai"]).status_code == 201
    run = _run(api, "ct-corr-01")
    zs = {r["serial"]: r for r in oracle("certspotter_zeroshield")}
    final = next(r for r in zs.values() if not r["precert_poison"])
    precert = next(r for r in zs.values() if r["precert_poison"])
    with Session(api.engine) as s:
        # the node read the final certificate on a SAN-only basis (no CN: cert_identity has no key for it)
        _node_row(s, 1, "linux_servers", {"subject": "", "issuer": final["issuer"], "serial": final["serial"],
                                          "not_after": final["not_after"], "fingerprint_sha256": final["sha256"]},
                  run_id=run.id)
        # ACM spells the issuer "Amazon" and the serial with colons; the CT side only has the precertificate
        colon = ":".join(precert["serial"].zfill(len(precert["serial"]) + len(precert["serial"]) % 2)[i:i + 2]
                         for i in range(0, len(precert["serial"]) + len(precert["serial"]) % 2, 2))
        _node_row(s, 1, "aws_account", {"subject": f"CN={precert['subject_cn']}", "issuer": "Amazon", "serial": colon,
                                        "not_before": precert["not_before"], "not_after": precert["not_after"]},
                  run_id=run.id, target="123456789012", location="arn:aws:acm:ap-south-1:123456789012:certificate/x")
        s.commit()
        result = CV.load_sources_result(s, 1)
    by_source: dict[str, dict[str, str]] = {}
    for item in result.rows:
        by_source.setdefault(item.collection.source_kind, {})[item.facts.get("serial", "").replace(":", "").lstrip("0")] = item.identity
    ct = by_source["ct_logs"]
    assert by_source["linux_servers"][final["serial"]] == ct[final["serial"]]
    assert by_source["aws_account"][precert["serial"]] == ct[precert["serial"]]
    resolved = CV.resolve([], result.rows)
    assert len(resolved.sources_rows) == len(zs)  # 25 certificates, not 27


def test_small_private_serials_link_only_under_the_same_issuer():
    """CB-21 replaced the CT slice's ``cert_link_keys``: a short serial links with the same issuer DN (two private CAs
    both count 1, 2, 3...), a 64-bit or longer serial links on its own (ACM's Issuer "Amazon")."""
    from backend.utilities.cbom_sources import asset_keys as AK

    def serial_key(facts):
        return [k.value for k in AK.link_keys({"asset_type": "certificate", "facts": facts}) if k.basis == "serial"]

    assert serial_key({"serial": "1f", "not_after": "2027-01-01T00:00:00Z"}) == []  # no issuer: no serial key
    assert serial_key({"serial": "1f", "issuer": "CN=Lab CA", "not_after": "2027-01-01T00:00:00Z"}) == [
        "1f|2027-01-01|cn=lab ca"]
    keys = AK.link_keys({"asset_type": "certificate", "facts": {
        "serial": "0a:1b:2c:3d:4e:5f:60:71:82", "not_after": "2027-01-01T00:00:00Z", "fingerprint_sha256": "AB" * 32}})
    assert [(k.basis, k.value) for k in keys] == [("serial", "a1b2c3d4e5f607182|2027-01-01"), ("sha256", "ab" * 32)]


# ----------------------------------------------------------------------------- export
def test_cyclonedx_export_carries_ct_provenance(api):
    assert _ct(api, ["zeroshield.ai"]).status_code == 201
    run = _run(api, "ct-export-01")
    doc = api("GET", f"{BASE}/runs/{run.id}/cbom").json()
    comps = [c for c in doc["components"] if any(p["name"] == "zs:collector" and p["value"] == "ct" for p in c.get("properties", []))]
    assert len(comps) == 25
    zs = {r["serial"]: r for r in oracle("certspotter_zeroshield")}
    for comp in comps:
        props = {}
        for p in comp["properties"]:
            props.setdefault(p["name"], []).append(p["value"])
        o = zs[props["zs:serial"][0]]
        # one provenance emitter (CB-06 provenance.py): collector ct, method api, the cloud worker, unsigned
        assert props["zs:collector"] == ["ct"] and props["zs:method"] == ["api"] and props["zs:signed"] == ["false"]
        assert props["zs:ct_provider"] == ["certspotter"]
        assert props["zs:ct_entry_id"] == [o["id"]] and props["zs:tbs_sha256"] == [o["tbs_sha256"]]
        assert props["zs:ct_matched_domain"] == ["zeroshield.ai"] and props["zs:source"] == ["Certificate Transparency"]
        if o["precert_poison"]:
            assert props["zs:precert_sha256"] == [o["sha256"]] and "zs:fingerprint_sha256" not in props
        else:
            assert props["zs:fingerprint_sha256"] == [o["sha256"]]
        cert = comp["cryptoProperties"]["certificateProperties"]
        assert cert["notValidAfter"] == o["not_after"] and cert["certificateExtension"] == "der"
