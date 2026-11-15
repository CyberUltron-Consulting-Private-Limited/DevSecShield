"""#61: an SSH CA whose private key the customer keeps on the scan node (``provider: node``).

ZeroShield stores only the public key.  At the claim (and on renewal through ``.../ssh-cert``) it records the
certificate it allows in ``cbomsshcertissued`` (serial, key id, principals, source addresses, validity, the node's key)
and sends the node a grant; the node signs it with its CA key file and reports the certificate
(``.../ssh-cert/report``), which must match the record exactly or the serial is revoked (and so goes into the KRL).
"""
from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder, SSHCertificateType, load_ssh_public_identity
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_f14_sshca import BASE, ca_world, cert_route, claim, enroll, ssh_ca_source  # noqa: E402,F401
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued  # noqa: E402

SSH_KEYGEN = shutil.which("ssh-keygen")


def _line(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _node_ca(api, key=None, **extra):  # noqa: F811
    key = key or ed25519.Ed25519PrivateKey.generate()
    r = api("POST", BASE, json={"name": "customer-ca", "provider": "node", "public_key": _line(key.public_key()) +
                                " customer@bank", **extra})
    return key, r


def _job(api):  # noqa: F811
    node_id, token, node_line = enroll(api)
    ca_key, r = _node_ca(api)
    assert r.status_code == 201, r.text
    ca = r.json()["ca"]
    source, test = ssh_ca_source(api, node_id, ca["id"])
    payload = claim(api, token)
    s = {"node_id": node_id, "token": token, "node_line": node_line, "ca_key": ca_key, "ca": ca, "source": source,
         "job_id": test["job_id"], "lease": payload["job"]["lease_id"], "payload": payload}
    r = cert_route(api, token, s["job_id"], s["lease"])  # the node asks before its first login (as for Vault)
    assert r.status_code == 200, r.text
    s["first"] = r.json()
    s["grant"] = s["first"]["node_sign"]
    return s


def _sign(ca_key, node_line, grant, **over):
    g = {**grant, **over}
    b = (SSHCertificateBuilder().public_key(load_ssh_public_identity(node_line.encode())).serial(g["serial"])
         .type(g.get("type", SSHCertificateType.USER)).key_id(g["key_id"].encode())
         .valid_principals([p.encode() for p in g["principals"]]).valid_after(g["valid_after"])
         .valid_before(g["valid_before"]))
    if g["source_addresses"]:
        b = b.add_critical_option(b"source-address", ",".join(g["source_addresses"]).encode())
    for name in g.get("extensions", ()):
        b = b.add_extension(name.encode(), b"")
    return b.sign(ca_key).public_bytes().decode()


def _report(api, s, certificate):  # noqa: F811
    return api("POST", f"/cbom/node/jobs/{s['job_id']}/ssh-cert/report", None, headers={"X-ZS-Node-Token": s["token"]},
               json={"lease_id": s["lease"], "certificate": certificate})


# ----------------------------------------------------------------------------- the CA row
def test_a_node_ca_stores_only_the_public_key(api, ca_world):  # noqa: F811
    engine, _ = ca_world
    key, r = _node_ca(api)
    assert r.status_code == 201, r.text
    ca = r.json()["ca"]
    assert ca["provider"] == "node" and ca["public_key"] == _line(key.public_key()) and ca["key_wrap"] is None
    with Session(engine) as session:
        row = session.get(CbomSshCa, ca["id"])
        assert row.private_key_encrypted is None and row.secret_encrypted is None and row.key_alg == "ed25519"
    trusted = api("GET", BASE + "/trusted-keys").text
    assert _line(key.public_key()) in trusted  # servers trust it like any team CA


@pytest.mark.parametrize("body,message", [
    ({"public_key": None}, "public_key: paste the public key of the CA key installed on the scan node"),
    ({"public_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"},
     "public_key: this is a private key"),
    ({"public_key": "ssh-ed25519-cert-v01@openssh.com AAAA"}, "public_key: paste the CA's public key"),
    ({"key_wrap": "fernet"}, "key_wrap: the key stays on the scan node"),
    ({"vault_config": {"addr": "https://vault"}}, "vault_config: only for provider vault"),
])
def test_a_node_ca_is_refused_with_anything_but_a_public_key(api, ca_world, body, message):  # noqa: F811
    key = ed25519.Ed25519PrivateKey.generate()
    payload = {"name": "customer-ca", "provider": "node", "public_key": _line(key.public_key()), **body}
    if payload.get("public_key") is None:
        payload.pop("public_key")
    r = api("POST", BASE, json=payload)
    assert r.status_code == 400 and message in r.json()["detail"], r.text


def test_a_public_key_on_a_builtin_ca_is_refused(api, ca_world):  # noqa: F811
    key = ed25519.Ed25519PrivateKey.generate()
    r = api("POST", BASE, json={"name": "x", "provider": "builtin", "public_key": _line(key.public_key())})
    assert r.status_code == 400 and "public_key: only for provider node" in r.json()["detail"]


def test_an_rsa_node_ca_is_refused(api, ca_world):  # noqa: F811
    key = rsa.generate_private_key(65537, 3072)
    _key, r = _node_ca(api, key=key)
    assert r.status_code == 400 and "Ed25519 or ECDSA" in r.json()["detail"]


# ----------------------------------------------------------------------------- the grant at the claim
def test_the_certificate_route_answers_with_a_grant_and_records_it(api, ca_world):  # noqa: F811
    engine, _ = ca_world
    s = _job(api)
    ssh_ca = s["first"]
    assert ssh_ca.get("certificate") is None
    grant = ssh_ca["node_sign"]
    assert grant["ca_public_key"] == s["ca"]["public_key"] and grant["principals"] == ["zs-1-prod"]
    assert grant["source_addresses"] == ["10.20.1.15"] and grant["ttl_s"] == 300
    assert grant["valid_before"] - grant["valid_after"] == 300 and grant["serial"] == ssh_ca["serial"] == 1
    assert grant["key_id"] == f"zs:1:{s['node_id']}:{s['job_id']}:1"
    assert ssh_ca["expires_in_s"] in range(235, 241)
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        assert (row.ca_id, row.serial, row.job_id, row.node_id, row.via) == (s["ca"]["id"], 1, s["job_id"],
                                                                              s["node_id"], "node_grant")
        assert row.key_id == grant["key_id"] and row.principals == ["zs-1-prod"]


def test_the_claim_plugin_carries_the_grant_too(api, ca_world):  # noqa: F811
    from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
    from backend.utilities.cbom_sources.sshca import claim as CLAIM

    engine, _ = ca_world
    node_id, _token, _line_ = enroll(api)
    _key, r = _node_ca(api)
    _source, test = ssh_ca_source(api, node_id, r.json()["ca"]["id"])
    now = dt.datetime.utcnow().replace(microsecond=0)
    with Session(engine) as session:  # what F1.1's claim does before secret_refs.source_secrets
        job = session.get(CbomCollectionJob, test["job_id"])
        job.status, job.lease_id, job.claimed_at = "claimed", "lease-plugin-61", now
        session.add(job)
        session.flush()
        src = session.get(CbomCollectionSource, job.source_id)
        out = CLAIM.claim_extras(session, src, session.get(CbomScanNode, node_id), now,
                                 {"config": dict(src.config), "secrets": {}})
        session.commit()
    assert "ssh_certificate" not in out["secrets"]
    assert out["config"]["ssh_ca"]["node_sign"]["serial"] == out["config"]["ssh_ca"]["serial"] == 1
    with Session(engine) as session:
        assert [r.via for r in session.exec(select(CbomSshCertIssued)).all()] == ["node_grant"]


def test_a_renewal_is_a_new_grant(api, ca_world):  # noqa: F811
    engine, _ = ca_world
    s = _job(api)
    with Session(engine) as session:  # the claim's certificate is about to run out
        row = session.exec(select(CbomSshCertIssued)).one()
        row.valid_before = dt.datetime.utcnow() + dt.timedelta(seconds=30)
        session.add(row)
        session.commit()
    r = cert_route(api, s["token"], s["job_id"], s["lease"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert "certificate" not in out or out["certificate"] is None
    assert out["node_sign"]["serial"] == 2 and out["node_sign"]["principals"] == ["zs-1-prod"]


# ----------------------------------------------------------------------------- the report
def test_a_certificate_signed_as_granted_is_recorded(api, ca_world):  # noqa: F811
    engine, _ = ca_world
    s = _job(api)
    grant = s["grant"]
    r = _report(api, s, _sign(s["ca_key"], s["node_line"], grant))
    assert r.status_code == 200 and r.json() == {"recorded": True, "serial": 1}, r.text
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        assert row.via == "node_signed" and row.revoked_at is None
    audit = api("GET", BASE + "/certificates", "bob").json()["certificates"]
    assert [(c["serial"], c["via"], c["status"]) for c in audit] == [(1, "node_signed", "valid")]


@pytest.mark.parametrize("over,problem", [
    ({"principals": ["zs-1-prod", "zs-1-admin"]}, "its principals"),
    ({"valid_before_add": 3600}, "its validity"),
    ({"source_addresses": ["0.0.0.0/0"]}, "its source-address"),
    ({"extensions": ["permit-pty"]}, "extensions"),
    ({"key_id": "something-else"}, "its key id"),
    ({"type": SSHCertificateType.HOST}, "not a user certificate"),
])
def test_a_certificate_that_differs_from_the_grant_is_refused_and_revoked(api, ca_world, tmp_path, over, problem):  # noqa: F811,E501
    engine, _ = ca_world
    s = _job(api)
    grant = dict(s["grant"])
    if "valid_before_add" in over:
        over = {"valid_before": grant["valid_before"] + over["valid_before_add"]}
    cert = _sign(s["ca_key"], s["node_line"], grant, **over)
    r = _report(api, s, cert)
    assert r.status_code == 400 and problem in r.json()["detail"], r.text
    with Session(engine) as session:
        row = session.exec(select(CbomSshCertIssued)).one()
        assert row.revoked_at is not None and "differs from its grant" in row.revoked_reason
    if SSH_KEYGEN:  # the serial is in the KRL, so servers refuse that certificate
        (tmp_path / "zs.krl").write_bytes(api("GET", BASE + "/revoked").content)
        (tmp_path / "c-cert.pub").write_text(cert + "\n")
        q = subprocess.run([SSH_KEYGEN, "-Q", "-f", str(tmp_path / "zs.krl"), str(tmp_path / "c-cert.pub")],
                           capture_output=True, text=True)
        assert q.returncode != 0 and "REVOKED" in q.stdout


def test_a_certificate_from_another_key_or_another_node_key_is_refused(api, ca_world):  # noqa: F811
    s = _job(api)
    grant = s["grant"]
    other_ca = ed25519.Ed25519PrivateKey.generate()
    r = _report(api, s, _sign(other_ca, s["node_line"], grant))
    assert r.status_code == 400 and "not signed by this job's CA" in r.json()["detail"]
    other_node = _line(ed25519.Ed25519PrivateKey.generate().public_key())
    r = _report(api, s, _sign(s["ca_key"], other_node, grant))
    assert r.status_code == 400 and "another key than the scan node's" in r.json()["detail"]


def test_a_serial_that_was_never_granted_is_refused(api, ca_world):  # noqa: F811
    s = _job(api)
    grant = s["grant"]
    r = _report(api, s, _sign(s["ca_key"], s["node_line"], grant, serial=999))
    assert r.status_code == 400 and "no certificate with serial 999 was granted to this job" in r.json()["detail"]


def test_a_report_needs_the_lease(api, ca_world):  # noqa: F811
    s = _job(api)
    grant = s["grant"]
    cert = _sign(s["ca_key"], s["node_line"], grant)
    r = api("POST", f"/cbom/node/jobs/{s['job_id']}/ssh-cert/report", None, headers={"X-ZS-Node-Token": s["token"]},
            json={"lease_id": "x" * 24, "certificate": cert})
    assert r.status_code == 409


def test_a_builtin_ca_still_sends_the_certificate_itself(api, ca_world):  # noqa: F811
    node_id, token, _line_ = enroll(api)
    ca = api("POST", BASE, json={"name": "builtin-ca"}).json()["ca"]
    _source, _test = ssh_ca_source(api, node_id, ca["id"])
    payload = claim(api, token)
    out = cert_route(api, token, payload["job"]["id"], payload["job"]["lease_id"]).json()
    assert out["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com ") and "node_sign" not in out


def test_rotating_a_node_ca_says_how(api, ca_world):  # noqa: F811
    _key, r = _node_ca(api)
    ca = r.json()["ca"]
    rot = api("POST", f"{BASE}/{ca['id']}/rotate", json={})
    assert rot.status_code == 400 and "install the new key on the scan node" in rot.json()["detail"]
