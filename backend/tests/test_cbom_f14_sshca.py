"""F1.4: SSH certificate authority (contract section 3, PARALLEL-PLAN "F1.4").

SQLite with the real routers and JWTs (the ``world``/``api`` fixtures of test_cbom_sources_api): CA lifecycle, the node
certificate route and its authorisation, certificate fields, the audit row per certificate, TTL bounds, rotation
overlap, revocation through an OpenSSH KRL (checked with ``ssh-keygen -Q`` when it is installed), KMS wrapping with
moto, the Vault provider against a fake SSH engine, and that key material never reaches a log or a response.
The live proofs (real sshd containers, real KMS, Vault dev server) are in bench/f1_sshca/.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import logging
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlmodel import Session, select

import test_cbom_sources_api as _base
from backend.main import app
from backend.new_models import CbomCollectionAuditEvent, CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.routers import cbom_node_sshca, cbom_sshca
from backend.utilities.cbom_sources import common
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team
from backend.utilities.cbom_sources.kinds import KINDS, METADATA_FIELDS, ServersConfig
from backend.utilities.cbom_sources.sshca import ca as CA
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import claim as CLAIM
from backend.utilities.cbom_sources.sshca import issue as ISSUE
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import krl as KRL
from backend.utilities.cbom_sources.sshca import registry as R
from backend.utilities.cbom_sources.sshca import vault as V
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued

world = _base.world  # the shared fixtures (SQLite world, real routers and JWTs)
api = _base.api
BASE = "/1/cbom/sources/fleet/ssh-ca"
SSH_KEYGEN = shutil.which("ssh-keygen")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def _mount() -> None:
    """The routers are included through F1.2's fleet aggregator once it is on dev; until then the tests mount them."""
    paths = {getattr(r, "path", None) for r in app.router.routes}
    if BASE.replace("/1/", "/{team_id}/") not in paths:
        app.include_router(cbom_sshca.router)
    if "/cbom/node/jobs/{job_id}/ssh-cert" not in paths:
        app.include_router(cbom_node_sshca.router)


@pytest.fixture()
def ca_world(world, api, monkeypatch):
    engine, ids = world
    _mount()
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    monkeypatch.delenv(KW.KMS_ENV, raising=False)
    monkeypatch.setattr(cbom_node_sshca, "get_db", lambda: engine)
    KW.forget()
    return engine, ids


def node_key_line() -> tuple[ed25519.Ed25519PrivateKey, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return key, key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


def enroll(api, name="dc-1", source_ips=("10.20.1.15",), team=1, who="alice", mode=None):
    r = api("POST", f"/{team}/cbom/sources/nodes", who, json={"name": name, "segment": "dc"})
    assert r.status_code == 201, r.text
    node, reg = r.json()["node"], r.json()["registration_token"]
    _key, line = node_key_line()
    body = {"registration_token": reg, "hostname": name, "version": "1.2", "source_ips": list(source_ips),
            "ssh_public_key": line, "capabilities": {"collectors": ["linux_ssh", "ssh_ca"]}}
    if mode:
        body["mode"] = mode
    e = api("POST", "/cbom/node/enroll", None, json=body)
    assert e.status_code == 200, e.text
    return node["id"], e.json()["node_token"], line


def create_ca(api, name="prod-ca", who="alice", **kw):
    r = api("POST", BASE, who, json={"name": name, **kw})
    assert r.status_code == 201, r.text
    return r.json()["ca"]


def ssh_ca_source(api, node_id, ca_id, name="linux-ca", who="alice", principals=("zs-1-prod",), **cfg):
    body = {"kind": "linux_servers", "name": name, "node_id": node_id, "test_after_save": True,
            "config": {"targets": ["10.20.0.5"], "credential_type": "ssh_ca", "ssh_ca_id": ca_id,
                       "ssh_principals": list(principals), **cfg}}
    r = api("POST", "/1/cbom/sources/items", who, json=body)
    assert r.status_code == 201, r.text
    return r.json()["source"], r.json()["test"]


def claim(api, token):
    r = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}, json={})
    assert r.status_code == 200, r.text
    return r.json()


def cert_route(api, token, job_id, lease_id):
    return api("POST", f"/cbom/node/jobs/{job_id}/ssh-cert", None, headers={"X-ZS-Node-Token": token},
               json={"lease_id": lease_id})


def setup_job(api, **source_cfg):
    node_id, token, line = enroll(api)
    ca = create_ca(api)
    source, test = ssh_ca_source(api, node_id, ca["id"], **source_cfg)
    payload = claim(api, token)
    assert payload["job"]["id"] == test["job_id"]
    return {"node_id": node_id, "token": token, "line": line, "ca": ca, "source": source,
            "job_id": test["job_id"], "lease": payload["job"]["lease_id"], "payload": payload}


# ----------------------------------------------------------------------------- CA lifecycle and visibility
def test_ca_create_is_admin_only_and_never_returns_private_material(api, ca_world):
    assert api("POST", BASE, "bob", json={"name": "x"}).status_code == 400  # member: 400, never 403
    ca = create_ca(api)
    assert ca["state"] == "active" and ca["provider"] == "builtin" and ca["key_alg"] == "ed25519"
    assert ca["key_wrap"] == "fernet" and ca["default_ttl_s"] == 300 and ca["lineage_id"] == ca["id"]
    assert ca["public_key"].startswith("ssh-ed25519 ") and ca["fingerprint"] == C.fingerprint(ca["public_key"])
    listed = api("GET", BASE, "bob").json()
    assert [c["id"] for c in listed["cas"]] == [ca["id"]] and listed["default_key_wrap"] == "fernet"
    assert api("GET", "/2/cbom/sources/fleet/ssh-ca", "alice").status_code == 403  # not a member of team 2
    assert api("GET", f"/2/cbom/sources/fleet/ssh-ca/{ca['id']}", "carol").status_code == 404  # another team's CA
    for body in api.seen:
        assert "PRIVATE KEY" not in body and "fernet:" not in body and "private_key" not in body
    ecdsa = create_ca(api, name="p256", key_alg="ecdsa-p256")
    assert ecdsa["public_key"].startswith("ecdsa-sha2-nistp256 ")


def test_flag_off_hides_every_route_and_refuses_ssh_ca_at_save(api, ca_world, monkeypatch):
    ca = create_ca(api)
    node_id, token, _ = enroll(api)
    monkeypatch.setenv("CBOM_SSH_CA", "0")
    assert api("GET", BASE).status_code == 404
    assert api("POST", BASE, json={"name": "x"}).status_code == 404
    assert api("GET", BASE + "/trusted-keys").status_code == 404
    assert cert_route(api, token, 1, "lease0000").status_code == 404
    r = api("POST", "/1/cbom/sources/items", json={"kind": "linux_servers", "name": "x", "node_id": node_id, "config": {
        "targets": ["10.0.0.1"], "credential_type": "ssh_ca", "ssh_ca_id": ca["id"], "ssh_principals": ["zs-1-prod"]}})
    assert r.status_code == 400 and "turned off" in r.json()["detail"]


def test_ttl_bounds_on_the_ca_and_on_issue(api, ca_world):
    for bad in (59, 3601, 0, -5):
        r = api("POST", BASE, json={"name": f"bad{abs(bad)}", "default_ttl_s": bad})
        assert r.status_code == 400 and "default_ttl_s" in r.json()["detail"]
    assert create_ca(api, name="min", default_ttl_s=60)["default_ttl_s"] == 60
    assert create_ca(api, name="max", default_ttl_s=3600)["default_ttl_s"] == 3600
    assert (CA.clamp_ttl(1), CA.clamp_ttl(300), CA.clamp_ttl(10 ** 6)) == (60, 300, 3600)
    assert CA.clamp_ttl(dt.timedelta(hours=5)) == 3600


# ----------------------------------------------------------------------------- the node route and the certificate
def test_issued_certificate_fields_and_one_audit_row(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    before = _utcnow().replace(microsecond=0)
    r = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == 200, r.text
    out = r.json()
    facts = C.read_cert(out["certificate"])  # parses and checks the CA signature
    assert facts.cert_type == "user" and facts.key_type == "ssh-ed25519-cert-v01@openssh.com"
    assert facts.signature_key_blob == C.public_blob(s["ca"]["public_key"])
    assert facts.public_key_blob == C.public_blob(s["line"])  # the node's own key: its private key never left it
    assert facts.principals == ("zs-1-prod",)
    assert facts.critical_options == {"source-address": "10.20.1.15"}  # the node's reported address
    assert facts.extensions == ()  # no pty, forwarding, agent or user-rc
    assert facts.valid_before - facts.valid_after == 300 + 60  # TTL 300 s, valid_after = now - 60 s
    assert abs(facts.valid_after - (int(before.replace(tzinfo=dt.timezone.utc).timestamp()) - 60)) <= 5
    assert facts.serial == out["serial"] == 1
    assert facts.key_id == f"zs:1:{s['node_id']}:{s['job_id']}:1"
    assert out["expires_in_s"] in range(295, 301) and out["refresh_before_s"] == 120
    with Session(engine) as session:
        rows = session.exec(select(CbomSshCertIssued)).all()
        assert len(rows) == 1
        row = rows[0]
        assert (row.ca_id, row.serial, row.node_id, row.job_id, row.source_id, row.via) == (
            s["ca"]["id"], 1, s["node_id"], s["job_id"], s["source"]["id"], "refresh")
        assert row.principals == ["zs-1-prod"] and row.source_addresses == ["10.20.1.15"]
        assert row.cert_public_key_sha256 == C.blob_sha256_hex(C.public_blob(s["line"]))
    if SSH_KEYGEN:
        text = subprocess.run([SSH_KEYGEN, "-L", "-f", "-"], input=out["certificate"], capture_output=True, text=True,
                              check=True).stdout
        assert "user certificate" in text and "source-address 10.20.1.15" in text and "Extensions: (none)" in text
    audit = api("GET", BASE + "/certificates", "bob").json()["certificates"]
    assert [c["serial"] for c in audit] == [1] and audit[0]["status"] == "valid"


def test_issue_route_authorisation(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    other_id, other_token, _ = enroll(api, name="dc-2")
    # no token, another node of the team, another team's node, a wrong or old lease
    assert api("POST", f"/cbom/node/jobs/{s['job_id']}/ssh-cert", None, json={"lease_id": s["lease"]}).status_code == 401
    assert cert_route(api, other_token, s["job_id"], s["lease"]).status_code == 404
    _t2, t2_token, _ = enroll(api, name="t2-node", team=2, who="carol")
    assert cert_route(api, t2_token, s["job_id"], s["lease"]).status_code == 404
    assert cert_route(api, s["token"], s["job_id"], "wronglease0000").status_code == 409
    assert cert_route(api, s["token"], 999999, s["lease"]).status_code == 404
    bad = api("POST", f"/cbom/node/jobs/{s['job_id']}/ssh-cert", None, headers={"X-ZS-Node-Token": s["token"]},
              json={"lease_id": s["lease"], "principals": ["root"]})
    assert bad.status_code == 400  # the node cannot ask for principals, addresses or a TTL
    # a job the node holds, but of a source that does not use the CA
    plain = api("POST", "/1/cbom/sources/items", json={"kind": "linux_servers", "name": "plain", "node_id": other_id,
                                                        "test_after_save": True,
                                                        "config": {"targets": ["10.0.0.9"]}}).json()
    job2 = claim(api, other_token)
    assert job2["job"]["id"] == plain["test"]["job_id"]
    r = cert_route(api, other_token, job2["job"]["id"], job2["job"]["lease_id"])
    assert r.status_code == 400 and "does not use SSH CA" in r.json()["detail"]
    with Session(engine) as session:
        assert session.exec(select(CbomSshCertIssued)).all() == []  # nothing was issued by any refusal


def test_agent_nodes_and_finished_jobs_never_get_certificates(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    with Session(engine) as session:
        node = session.get(CbomScanNode, s["node_id"])
        node.mode = "agent"
        session.add(node)
        session.commit()
    r = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code in (400, 409)
    with Session(engine) as session:
        node = session.get(CbomScanNode, s["node_id"])
        node.mode = "agentless"
        session.add(node)
        job = session.get(CbomCollectionJob, s["job_id"])
        job.status, job.lease_id = "success", None
        session.add(job)
        session.commit()
    assert cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 409
    with Session(engine) as session:
        assert session.exec(select(CbomSshCertIssued)).all() == []


def test_only_sources_an_admin_saved_get_certificates(api, ca_world):
    node_id, token, _ = enroll(api)
    ca = create_ca(api)
    source, test = ssh_ca_source(api, node_id, ca["id"], who="bob")  # a member saved it
    payload = claim(api, token)
    r = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"])
    assert r.status_code == 400 and "team admin" in r.json()["detail"]


def test_refresh_only_near_expiry(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    assert cert_route(api, s["token"], s["job_id"], s["lease"]).status_code == 200
    again = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert again.status_code == 400 and "ask again" in again.json()["detail"]
    with Session(engine) as session:  # the certificate has 100 s left: inside the 120 s window
        row = session.exec(select(CbomSshCertIssued)).one()
        row.valid_before = _utcnow() + dt.timedelta(seconds=100)
        session.add(row)
        session.commit()
    r = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == 200 and r.json()["serial"] == 2
    assert (ISSUE.refresh_window(60), ISSUE.refresh_window(300), ISSUE.refresh_window(3600)) == (30, 120, 120)


def test_principals_and_source_addresses(api, ca_world):
    node_id, _token, _ = enroll(api)
    ca = create_ca(api)
    for bad in (["root"], ["zs-1-"], ["ZS-1-prod"], [], ["zs-1-prod x"]):
        r = api("POST", "/1/cbom/sources/items", json={"kind": "linux_servers", "name": "bad", "node_id": node_id,
                                                        "config": {"targets": ["10.0.0.1"], "credential_type": "ssh_ca",
                                                                   "ssh_ca_id": ca["id"], "ssh_principals": bad}})
        assert r.status_code == 400, bad
    r = api("POST", "/1/cbom/sources/items", json={"kind": "linux_servers", "name": "noca", "node_id": node_id,
                                                    "config": {"targets": ["10.0.0.1"], "credential_type": "ssh_ca",
                                                               "ssh_principals": ["zs-1-prod"]}})
    assert r.status_code == 400 and "ssh_ca_id" in r.text.lower().replace(" ", "_")
    with pytest.raises(C.CertError, match="another team"):
        C.check_principals(["zs-2-prod"], 1)
    assert C.source_address_list(["10.0.0.5", "10.1.0.0/16", "10.0.0.5/32", "2001:db8::1"]) == (
        "10.0.0.5", "10.1.0.0/16", "2001:db8::1")
    src, test = ssh_ca_source(api, node_id, ca["id"], name="nat", ssh_source_addresses=["192.0.2.10", "10.9.0.0/24"])
    payload = claim(api, _token)
    out = cert_route(api, _token, payload["job"]["id"], payload["job"]["lease_id"]).json()
    assert C.read_cert(out["certificate"]).critical_options == {"source-address": "192.0.2.10,10.9.0.0/24"}


def test_unbound_certificates_are_never_issued(api, ca_world):
    node_id, token, _ = enroll(api, source_ips=())
    ca = create_ca(api)
    ssh_ca_source(api, node_id, ca["id"])
    payload = claim(api, token)
    r = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"])
    assert r.status_code == 400 and "addresses" in r.json()["detail"]


def test_serials_are_unique_and_every_certificate_has_an_audit_row(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    with Session(engine) as session:
        node = session.get(CbomScanNode, s["node_id"])
        job = session.get(CbomCollectionJob, s["job_id"])
        source = session.get(CbomCollectionSource, s["source"]["id"])
        serials = []
        for _ in range(25):
            minted = ISSUE.issue_for_job(session, node, job, source, _utcnow(), via="claim")
            serials.append(minted.cert.serial)
        session.commit()
        rows = session.exec(select(CbomSshCertIssued)).all()
    assert serials == list(range(1, 26))
    assert sorted(r.serial for r in rows) == serials and len({(r.ca_id, r.serial) for r in rows}) == 25
    with Session(engine) as session:
        session.add(CbomSshCertIssued(team_id=1, ca_id=s["ca"]["id"], serial=5, key_id="dup", principals=[],
                                      valid_after=_utcnow(), valid_before=_utcnow(),
                                      cert_public_key_sha256="0" * 64))
        with pytest.raises(Exception):
            session.commit()  # the database refuses a second serial 5 for the same CA


# ----------------------------------------------------------------------------- rotation and revocation
def _trusted(api) -> list[str]:
    text = api("GET", BASE + "/trusted-keys", "bob").text
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def test_rotation_trusts_both_keys_during_the_overlap(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    old = s["ca"]
    nxt = api("POST", f"{BASE}/{old['id']}/rotate").json()["ca"]
    assert nxt["state"] == "next" and nxt["lineage_id"] == old["id"] and nxt["rotated_from_id"] == old["id"]
    assert api("POST", f"{BASE}/{old['id']}/rotate").status_code == 409  # one rotation at a time
    assert api("POST", f"{BASE}/{nxt['id']}/rotate").status_code in (400, 409)
    assert len(_trusted(api)) == 2
    first = cert_route(api, s["token"], s["job_id"], s["lease"]).json()  # the old CA still signs until promote
    assert C.read_cert(first["certificate"]).signature_key_blob == C.public_blob(old["public_key"])
    assert api("POST", f"{BASE}/{old['id']}/promote").status_code == 400  # only a "next" CA is promoted
    promoted = api("POST", f"{BASE}/{nxt['id']}/promote").json()["ca"]
    assert promoted["state"] == "active"
    cas = {c["id"]: c for c in api("GET", BASE).json()["cas"]}
    assert cas[old["id"]]["state"] == "retired" and cas[old["id"]]["trusted"] is True
    assert len(_trusted(api)) == 2  # retired key still trusted: its certificates may still be live
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        row.valid_before = _utcnow() + dt.timedelta(seconds=30)
        session.add(row)
        session.commit()
    second = cert_route(api, s["token"], s["job_id"], s["lease"]).json()  # the source follows its lineage
    assert C.read_cert(second["certificate"]).signature_key_blob == C.public_blob(nxt["public_key"])
    assert second["serial"] == 1  # serials are per CA key
    with Session(engine) as session:
        retired = session.get(CbomSshCa, old["id"])
        retired.retired_at = _utcnow() - R.OVERLAP - dt.timedelta(seconds=1)
        session.add(retired)
        session.commit()
    assert _trusted(api) == [f"{nxt['public_key']} zs-ca-{nxt['id']}-active"]


def test_revocation_goes_into_the_krl_and_stops_issuing(api, ca_world, tmp_path):
    engine, _ = ca_world
    s = setup_job(api)
    first = cert_route(api, s["token"], s["job_id"], s["lease"]).json()
    cert_id = api("GET", BASE + "/certificates").json()["certificates"][0]["id"]
    assert api("POST", f"{BASE}/certificates/{cert_id}/revoke", "bob", json={"reason": "x"}).status_code == 400
    r = api("POST", f"{BASE}/certificates/{cert_id}/revoke", json={"reason": "node disk stolen"})
    assert r.status_code == 200 and r.json()["certificate"]["status"] == "revoked"
    krl = api("GET", BASE + "/revoked")
    assert krl.status_code == 200 and krl.headers["content-type"] == "application/octet-stream"
    assert krl.content.startswith(b"SSHKRL\n\x00")
    if SSH_KEYGEN:
        (tmp_path / "zs.krl").write_bytes(krl.content)
        (tmp_path / "c-cert.pub").write_text(first["certificate"] + "\n")
        q = subprocess.run([SSH_KEYGEN, "-Q", "-f", str(tmp_path / "zs.krl"), str(tmp_path / "c-cert.pub")],
                           capture_output=True, text=True)
        assert q.returncode != 0 and "REVOKED" in q.stdout
    # revoke the CA: it signs nothing more, leaves trusted-keys, and its key is in the KRL
    assert api("POST", f"{BASE}/{s['ca']['id']}/revoke", json={"reason": "compromised"}).status_code == 200
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        row.valid_before = _utcnow() + dt.timedelta(seconds=10)
        session.add(row)
        session.commit()
    refused = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert refused.status_code == 400 and "no active key" in refused.json()["detail"]
    assert _trusted(api) == []
    keys = api("GET", BASE + "/revoked?format=keys").text
    assert s["ca"]["public_key"] in keys
    if SSH_KEYGEN:
        key = ed25519.Ed25519PrivateKey.generate()  # any certificate the revoked CA signed is refused
        line = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
        (tmp_path / "zs2.krl").write_bytes(api("GET", BASE + "/revoked").content)
        with Session(engine) as session:
            ca_row = session.get(CbomSshCa, s["ca"]["id"])
            ca_key = KW.cached_private_key(ca_row.id, 1, ca_row.fingerprint, ca_row.private_key_encrypted)
        now = _utcnow()
        other = C.sign_user_cert(ca_key, line, serial=77, key_id="x", principals=["zs-1-prod"], valid_after=now,
                                 valid_before=now + dt.timedelta(minutes=5), source_addresses=[])
        (tmp_path / "d-cert.pub").write_text(other + "\n")
        q = subprocess.run([SSH_KEYGEN, "-Q", "-f", str(tmp_path / "zs2.krl"), str(tmp_path / "d-cert.pub")],
                           capture_output=True, text=True)
        assert q.returncode != 0 and "REVOKED" in q.stdout


def test_krl_writer_layout():
    blob = C.public_blob(node_key_line()[1])
    data = KRL.build(revoked_ca_blobs=[blob], revoked_serials={blob: [3, 1, 3]}, krl_version=7, generated=9)
    assert data[:8] == b"SSHKRL\n\x00" and data[8:12] == b"\x00\x00\x00\x01"
    assert data[12:20] == (7).to_bytes(8, "big") and data[20:28] == (9).to_bytes(8, "big")
    assert data.count((1).to_bytes(8, "big")) >= 1 and b"\x20" in data
    assert KRL.build(revoked_ca_blobs=[], revoked_serials={}, krl_version=1, generated=1).startswith(b"SSHKRL")


# ----------------------------------------------------------------------------- the claim plugin
def test_claim_plugin_mints_in_the_claim_and_never_raises(api, ca_world):
    engine, _ = ca_world
    node_id, token, line = enroll(api)
    ca = create_ca(api)
    source, test = ssh_ca_source(api, node_id, ca["id"])
    now = _utcnow()
    with Session(engine) as session:  # what F1.1's claim does before secret_refs.source_secrets
        job = session.get(CbomCollectionJob, test["job_id"])
        job.status, job.lease_id, job.claimed_at = "claimed", "lease-plugin-1", now
        session.add(job)
        session.flush()
        node = session.get(CbomScanNode, node_id)
        src = session.get(CbomCollectionSource, source["id"])
        acc = {"config": dict(src.config), "secrets": {}}
        out = CLAIM.claim_extras(session, src, node, now, acc)
        session.commit()
    facts = C.read_cert(out["secrets"]["ssh_certificate"])
    assert facts.public_key_blob == C.public_blob(line) and facts.serial == out["config"]["ssh_ca"]["serial"]
    assert out["config"]["ssh_ca"]["refresh_before_s"] == 120 and out["config"]["ssh_ca"]["expires_in_s"] >= 295
    with Session(engine) as session:
        rows = session.exec(select(CbomSshCertIssued)).all()
        assert [(r.job_id, r.via) for r in rows] == [(test["job_id"], "claim")]
    # a revoked CA: the plugin reports the reason instead of raising, and the claim's own writes stay
    api("POST", f"{BASE}/{ca['id']}/revoke", json={"reason": "test"})
    with Session(engine) as session:
        node = session.get(CbomScanNode, node_id)
        src = session.get(CbomCollectionSource, source["id"])
        out = CLAIM.claim_extras(session, src, node, now, {"config": dict(src.config), "secrets": {}})
        assert "ssh_certificate" not in out["secrets"] and "no active key" in out["config"]["ssh_ca"]["error"]
    # other sources, agent nodes, the cloud worker and a turned-off flag: untouched
    with Session(engine) as session:
        src = session.get(CbomCollectionSource, source["id"])
        node = session.get(CbomScanNode, node_id)
        assert CLAIM.claim_extras(session, src, None, now, {"config": {}, "secrets": {}}) is None
        assert CLAIM.version_input(session, src) is None and CLAIM.known_secrets(session, src) == []


def test_existing_server_configs_dump_and_hash_as_before():
    """New ServersConfig fields are omitted unless credential_type is ssh_ca, so no existing source's connection
    version changes at deploy (which would cancel its open jobs)."""
    dev_keys = ['application', 'business_criticality', 'credential_type', 'custom_window', 'data_classification',
                'data_lifetime_years', 'environment', 'exclusions', 'exposure', 'host_key_policy', 'known_hosts',
                'login_user', 'owner', 'parallel', 'port', 'targets', 'tier', 'timeout_s', 'vault', 'window']
    for kind in ("linux_servers", "windows_servers", "active_directory"):
        dump = KINDS[kind].model.model_validate({"targets": ["10.0.0.1"]}).model_dump(mode="json")
        assert sorted(dump) == sorted(dev_keys + ([] if kind == "linux_servers" else ["ca_pem"])), kind
    stored = ServersConfig.model_validate({"targets": ["10.0.0.1"], "ssh_principals": ["zs-1-a"]}).model_dump()
    assert "ssh_principals" not in stored  # cleared and omitted for another credential type
    source = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name="a", name_lower="a",
                                  node_id=3, config={"targets": ["10.0.0.1"]})
    expected = {"kind": "linux_servers", "node_id": 3, "secret": hashlib.sha256(b"").hexdigest(), "config": {
        k: v for k, v in sorted(ServersConfig.model_validate({"targets": ["10.0.0.1"]}).model_dump(mode="json").items())
        if k not in METADATA_FIELDS}}
    blob = json.dumps(expected, sort_keys=True, separators=(",", ":"), default=str)
    assert J.connection_version(source) == hashlib.sha256(blob.encode()).hexdigest()[:32]


# ----------------------------------------------------------------------------- key wrapping
def test_fernet_wrapped_key_is_bound_to_its_team_and_ca(api, ca_world):
    engine, _ = ca_world
    a = create_ca(api, name="a")
    b = create_ca(api, name="b")
    with Session(engine) as session:
        ra, rb = session.get(CbomSshCa, a["id"]), session.get(CbomSshCa, b["id"])
        assert ra.private_key_encrypted.startswith("fernet:") and "PRIVATE" not in ra.private_key_encrypted
        with pytest.raises(KW.WrapError, match="another CA"):
            KW.unwrap(ra.private_key_encrypted, team_id=1, ca_fingerprint=rb.fingerprint)
        with pytest.raises(KW.WrapError, match="another CA"):
            KW.unwrap(ra.private_key_encrypted, team_id=2, ca_fingerprint=ra.fingerprint)
        KW.forget()
        with pytest.raises(KW.WrapError):  # a wrapped key copied onto another CA row is refused
            KW.cached_private_key(rb.id, 1, rb.fingerprint, ra.private_key_encrypted)


def test_kms_envelope_wrap_with_moto(api, ca_world, monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        arn = kms.create_key(Description="zs sshca test", Tags=[{"TagKey": "Project", "TagValue": "DevSecShield"}])[
            "KeyMetadata"]["Arn"]
        KW.set_kms_client_factory(lambda region: boto3.client("kms", region_name=region))
        try:
            r = api("POST", BASE, json={"name": "kms", "key_wrap": "aws_kms", "kms_key_ref": arn})
            assert r.status_code == 400 and KW.KMS_ENV in r.json()["detail"]  # not in the deployment's allow-list
            monkeypatch.setenv(KW.KMS_ENV, arn)
            assert api("GET", BASE).json()["default_key_wrap"] == "aws_kms"
            ca = create_ca(api, name="kms")  # KMS is the default once the deployment configures a key
            assert ca["key_wrap"] == "aws_kms" and ca["kms_key_ref"] == arn
            engine, _ = ca_world
            with Session(engine) as session:
                row = session.get(CbomSshCa, ca["id"])
                blob = row.private_key_encrypted
                assert blob.startswith("aws_kms:") and "PRIVATE" not in blob
                doc = json.loads(blob.split(":", 1)[1])
                assert set(doc) == {"v", "key_ref", "edk", "nonce", "ct"}
                pem = KW.unwrap(blob, team_id=1, ca_fingerprint=row.fingerprint)
                assert C.fingerprint(C.public_line(C.private_from_openssh(pem))) == row.fingerprint
                with pytest.raises(KW.WrapError):  # the EncryptionContext binds the team
                    KW.unwrap(blob, team_id=2, ca_fingerprint=row.fingerprint)
                with pytest.raises(KW.WrapError):  # and the CA
                    KW.unwrap(blob, team_id=1, ca_fingerprint="SHA256:other")
            node_id, token, _ = enroll(api)
            source, test = ssh_ca_source(api, node_id, ca["id"])
            payload = claim(api, token)
            out = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"])
            assert out.status_code == 200 and C.read_cert(out.json()["certificate"]).signature_key_blob == \
                C.public_blob(ca["public_key"])
        finally:
            KW.set_kms_client_factory(None)
            KW.forget()


# ----------------------------------------------------------------------------- Vault provider (fake SSH engine)
class FakeVault:
    """The three Vault endpoints the provider uses, signing with a local CA key; ``mutate`` breaks the answer."""

    def __init__(self):
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.public = C.public_line(self.key)
        self.calls: list[tuple[str, str, dict | None, str | None]] = []
        self.mutate: dict = {}
        self.serial = 0xC73F26D2340276AA  # Vault serials are random 64-bit numbers (above 2^63 here)

    def __call__(self, cfg, method, path, *, token=None, body=None):
        self.calls.append((method, path, body, token))
        if path.endswith("/public_key"):
            return 200, self.public + "\n"
        if path.endswith("/approle/login"):
            return 200, {"auth": {"client_token": "hvs.fake-approle-token-000000000000"}}
        now = int(dt.datetime.now(dt.timezone.utc).timestamp())
        ttl = int(body["ttl"].rstrip("s"))
        principals = body["valid_principals"].split(",")
        opts = dict(body.get("critical_options") or {})
        signer = self.key
        if self.mutate.get("principals"):
            principals = self.mutate["principals"]
        if self.mutate.get("ttl"):
            ttl = self.mutate["ttl"]
        if self.mutate.get("no_source_address"):
            opts = {}
        if self.mutate.get("other_ca"):
            signer = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder, SSHCertificateType, \
            load_ssh_public_key
        b = (SSHCertificateBuilder().public_key(load_ssh_public_key(body["public_key"].encode()))
             .serial(self.serial).type(SSHCertificateType.USER).key_id(body["key_id"].encode())
             .valid_principals([p.encode() for p in principals]).valid_after(now - 30).valid_before(now + ttl))
        for name, value in sorted(opts.items()):
            b = b.add_critical_option(name.encode(), value.encode())
        if self.mutate.get("pty"):
            b = b.add_extension(b"permit-pty", b"")
        return 200, {"data": {"serial_number": format(self.serial, "x"), "signed_key": b.sign(signer).public_bytes().decode()}}


def test_vault_provider_signs_through_the_engine_and_checks_its_answer(api, ca_world, monkeypatch):
    engine, _ = ca_world
    fake = FakeVault()
    monkeypatch.setattr(V, "call", fake)
    vault_cfg = {"addr": "https://vault.bank.example:8200", "mount": "ssh-client-signer", "role": "zs-cbom"}
    r = api("POST", BASE, json={"name": "vault", "provider": "vault", "vault_config": vault_cfg,
                                "secrets": {"role_id": "role-id-1234", "secret_id": "secret-id-5678"}})
    assert r.status_code == 201, r.text
    ca = r.json()["ca"]
    assert ca["public_key"] == fake.public and ca["secrets_set"] == ["role_id", "secret_id"]
    assert "secret-id-5678" not in r.text and ca["vault_config"]["addr"] == vault_cfg["addr"]
    node_id, token, line = enroll(api)
    source, test = ssh_ca_source(api, node_id, ca["id"])
    payload = claim(api, token)
    out = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"])
    assert out.status_code == 200, out.text
    sign_call = [c for c in fake.calls if "/sign/" in c[1]][-1]
    assert sign_call[1] == "/v1/ssh-client-signer/sign/zs-cbom" and sign_call[3] == "hvs.fake-approle-token-000000000000"
    assert sign_call[2]["cert_type"] == "user" and sign_call[2]["extensions"] == {} and sign_call[2]["ttl"] == "300s"
    assert sign_call[2]["critical_options"] == {"source-address": "10.20.1.15"}
    assert out.json()["serial"] == fake.serial
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        assert CA.from_db_serial(row.serial) == fake.serial  # stored in a signed BIGINT, shown unsigned
    for mutate, words in (({"principals": ["zs-1-other"]}, "principals"), ({"ttl": 7200}, "validity"),
                          ({"no_source_address": True}, "source-address"), ({"other_ca": True}, "another CA"),
                          ({"pty": True}, "extensions")):
        fake.mutate = mutate
        with Session(engine) as session:
            row = session.exec(select(CbomSshCertIssued)).all()[-1]
            row.valid_before = _utcnow() + dt.timedelta(seconds=5)
            session.add(row)
            session.commit()
        bad = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"])
        assert bad.status_code == 400 and words in bad.json()["detail"], (mutate, bad.text)
    with Session(engine) as session:
        assert len(session.exec(select(CbomSshCertIssued)).all()) == 1  # refused answers are never recorded


def test_vault_config_is_checked_and_private_addresses_need_the_operator(monkeypatch):
    for bad in ({"addr": "http://v:8200", "role": "r"}, {"addr": "https://v/x", "role": "r"},
                {"addr": "https://v:22", "role": "r"}, {"addr": "https://v", "role": "../x"},
                {"addr": "https://v", "role": "r", "mount": "a/../b"}, {"addr": "https://v", "role": "r", "x": 1}):
        with pytest.raises(V.VaultError):
            V.check_config(bad)
    with pytest.raises(V.VaultError):
        V.check_secrets({"token": "hvs.abcdefgh", "role_id": "abcdefgh1"})
    monkeypatch.delenv(V.ALLOW_ENV, raising=False)
    with pytest.raises(V.VaultError, match="private or reserved"):
        V.call(V.check_config({"addr": "https://127.0.0.1:8200", "role": "r"}), "GET", "/v1/sys/health")
    monkeypatch.setenv(V.ALLOW_ENV, "127.0.0.0/8")  # loopback and metadata stay blocked whatever is listed
    with pytest.raises(V.VaultError):
        V.call(V.check_config({"addr": "https://169.254.169.254", "role": "r"}), "GET", "/v1/sys/health")


# ----------------------------------------------------------------------------- key material never logged
def test_key_material_never_reaches_logs_or_responses(api, ca_world, monkeypatch, caplog):
    from rich.console import Console

    sink = io.StringIO()
    monkeypatch.setattr(common, "console", Console(file=sink, width=400))
    caplog.set_level(logging.DEBUG)
    engine, _ = ca_world
    s = setup_job(api)
    issued = cert_route(api, s["token"], s["job_id"], s["lease"]).json()
    api("POST", f"{BASE}/{s['ca']['id']}/rotate")
    api("GET", BASE + "/trusted-keys")
    api("GET", BASE + "/revoked")
    api("GET", BASE + "/certificates")
    with Session(engine) as session:
        row = session.get(CbomSshCa, s["ca"]["id"])
        wrapped = row.private_key_encrypted
        pem = KW.unwrap(wrapped, team_id=1, ca_fingerprint=row.fingerprint).decode()
    raw = C.private_from_openssh(pem.encode()).private_bytes_raw()
    secrets_ = [pem.strip(), wrapped, wrapped.split(":", 1)[1][:40], base64.b64encode(raw).decode(), raw.hex(),
                "".join(pem.strip().splitlines()[1:3])]
    logs = sink.getvalue() + "\n" + caplog.text
    assert "ssh ca created" in logs and "ssh certificate issued" in logs  # the lines exist (ids only)
    for value in secrets_:
        assert value not in logs
        assert all(value not in body for body in api.seen)
    cert_b64 = issued["certificate"].split()[1]
    assert cert_b64 not in logs  # a certificate is public, but it is not logged either
    assert "PRIVATE KEY" not in logs and "PRIVATE KEY" not in "".join(api.seen)


def test_team_delete_removes_ca_rows(api, ca_world):
    engine, _ = ca_world
    s = setup_job(api)
    cert_route(api, s["token"], s["job_id"], s["lease"])
    counts = delete_cbom_sources_for_team(engine, 1)
    assert counts["cbomsshca"] == 1 and counts["cbomsshcertissued"] == 1


def test_templates_scope_the_ca_to_the_zs_cbom_login(api, ca_world, tmp_path):
    sshd = api("GET", BASE + "/templates/sshd-config", "bob")
    assert sshd.status_code == 200 and sshd.headers["content-type"].startswith("text/plain")
    body = sshd.text
    assert "Match User zs-cbom" in body and "TrustedUserCAKeys" in body and "RevokedKeys" in body
    assert "AuthorizedPrincipalsFile /etc/ssh/zs-cbom/principals/%u" in body
    assert api("GET", BASE + "/templates/principals?group=prod").text.strip().endswith("zs-1-prod")
    assert api("GET", BASE + "/templates/principals?group=Bad Group").status_code == 400
    assert api("GET", BASE + "/templates/other").status_code == 400
    sshd_bin = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
    if sshd_bin:
        tmp = tmp_path
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "hk")], check=True)
        (tmp / "sshd_config").write_text(f"HostKey {tmp / 'hk'}\nPidFile {tmp / 'pid'}\nUsePAM no\n" + body)
        check = subprocess.run([sshd_bin, "-t", "-f", str(tmp / "sshd_config")], capture_output=True, text=True)
        assert check.returncode == 0, check.stderr


def test_audit_events_for_every_ca_write(api, ca_world):
    engine, _ = ca_world
    ca = create_ca(api)
    nxt = api("POST", f"{BASE}/{ca['id']}/rotate").json()["ca"]
    api("POST", f"{BASE}/{nxt['id']}/promote")
    api("POST", f"{BASE}/{nxt['id']}/revoke", json={"reason": "drill"})
    with Session(engine) as session:
        actions = [e.action for e in session.exec(select(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.object_type == "ssh_ca")).all()]
    assert actions == ["sshca.create", "sshca.rotate", "sshca.promote", "sshca.revoke"]


def test_usable_ca_seam_for_policies(api, ca_world, monkeypatch):
    engine, _ = ca_world
    ca = create_ca(api)
    with Session(engine) as session:
        assert R.usable_ca(session, 1, ca["id"]) is True
        assert R.usable_ca(session, 2, ca["id"]) is False  # another team's lineage
        monkeypatch.setenv("CBOM_SSH_CA", "0")
        assert R.usable_ca(session, 1, ca["id"]) is False
