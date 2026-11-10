"""A server (leaf) certificate kept in a trust-store location is its own certificate row (round 5, G3 item 4).

On Debian, server certificates live in /etc/ssl/certs next to the hashed CA links. The node folded them into the
"Trust store directory" row: it counted them (expired, RSA < 2048, SHA-1) but the backend treats that row as
inventory, so they never became findings or calendar entries. CA trust anchors stay one summary row."""
from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from test_wp8b_agent_registry import _ctx, _host_root
from zs_scan_node import linux_parsers as P
from zs_scan_node.collectors import run_job


def _expired_weak_leaf(cn: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Issuing CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=400))
            .not_valid_after(now - dt.timedelta(days=5))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))  # SHA-1 signing is refused by this OpenSSL
    return cert.public_bytes(serialization.Encoding.PEM)


def test_leaf_certificates_in_a_trust_store_directory_are_certificate_rows(tmp_path, monkeypatch):
    root = _host_root(tmp_path)  # /etc/ssl/certs holds three CA certificates (ca0..ca2.pem)
    (root / "etc/ssl/certs/www.example.internal.pem").write_bytes(_expired_weak_leaf("www.example.internal"))
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.delenv("ZS_HOST_PROC", raising=False)
    ctx = _ctx(agent=True)
    status, error, _ = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    assert (status, error) == ("success", None), error
    certs = {r["location"]: r for r in ctx.collected if r["type"] == "certificate"}
    summary = certs["/etc/ssl/certs"]
    assert summary["facts"]["trust_store"] is True
    assert summary["facts"]["count"] == 3 and summary["facts"]["files"] == 3  # the CA anchors only
    assert summary["facts"]["expired"] == 0 and summary["facts"]["rsa_under_2048"] == 0
    leaf = certs["/etc/ssl/certs/www.example.internal.pem"]
    assert "trust_store" not in leaf["facts"]
    assert leaf["key_size"] == 1024 and leaf["facts"]["is_ca"] is False
    assert leaf["facts"]["not_after"] < dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_a_leaf_inside_a_ca_bundle_file_is_its_own_row(tmp_path, monkeypatch):
    root = _host_root(tmp_path)
    from test_wp8b_agent_registry import _cert

    anchors = b"".join(_cert(ec.generate_private_key(ec.SECP256R1()), f"Root {i}", ca=True)
                       .public_bytes(serialization.Encoding.PEM) for i in range(2))
    (root / "etc/ssl/certs/ca-certificates.crt").write_bytes(anchors + _expired_weak_leaf("leaf.in.bundle"))
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.delenv("ZS_HOST_PROC", raising=False)
    ctx = _ctx(agent=True)
    status, error, _ = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    assert (status, error) == ("success", None), error
    certs = {r["location"]: r for r in ctx.collected if r["type"] == "certificate"}
    # the bundle has a leaf, so it is not folded into the directory row; its CAs are one row, the leaf another
    assert certs["/etc/ssl/certs"]["facts"]["count"] == 3
    assert certs["/etc/ssl/certs/ca-certificates.crt"]["facts"]["count"] == 2
    assert certs["/etc/ssl/certs/ca-certificates.crt#2"]["key_size"] == 1024


def test_split_trust_anchors():
    anchors, leaves = P.split_trust_anchors([{"is_ca": True}, {"is_ca": False, "n": 1}, {"n": 2}])
    assert anchors == [{"is_ca": True}]
    assert leaves == [(1, {"is_ca": False, "n": 1}), (2, {"n": 2})]
