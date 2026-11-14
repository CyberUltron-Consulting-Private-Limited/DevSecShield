"""Asset locations of the form host:port bracket an IPv6 address ("[fd00::5]:5696"), so the port can be read back.

Without brackets "fd00::5:5696" is ambiguous: the results page (certWhere) cannot split host and port and drops the
port, and the same certificate on two ports reads as one place (#268 review of PR #285). network.py, database.py and
appliance.py already bracket; kmip.py, oracle.py and the Kubernetes API server rows did not.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from zs_scan_node import netutil
from zs_scan_node.collectors import kmip, oracle
from zs_scan_node.netutil import Target

ROOT = Path(__file__).resolve().parents[1] / "zs_scan_node"


@pytest.mark.parametrize("host,port,want", [
    ("fd00::5", 5696, "[fd00::5]:5696"),
    ("[fd00::5]", 5696, "[fd00::5]:5696"),
    ("fe80::1%eth0", 443, "[fe80::1%eth0]:443"),
    ("::ffff:10.0.0.1", 443, "[::ffff:10.0.0.1]:443"),
    ("10.0.0.5", 5696, "10.0.0.5:5696"),
    ("kms.lab", 5696, "kms.lab:5696"),
])
def test_host_port(host, port, want):
    assert netutil.host_port(host, port) == want


class _Ctx:
    never_scan = None

    def __init__(self):
        self.rows = []
        self.names = {}

    def emit(self, asset_type, target, location, **kw):
        self.rows.append((asset_type, target, location))
        self.names[asset_type] = kw.get("name")


def _der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kms.lab")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize("label,ip,host", [("fd00::5", "fd00::5", "[fd00::5]"), ("10.0.0.5", "10.0.0.5", "10.0.0.5")])
def test_kmip_locations(monkeypatch, label, ip, host):
    der = _der()

    class FakeClient:
        def __init__(self, ctx, target, port, sslctx):
            pass

        def open(self):
            return {"cert_der": der, "negotiated_cipher": "TLS_AES_128_GCM_SHA256", "negotiated_version": "TLSv1.3"}

        def close(self):
            pass

    seen = {}

    def fake_read(ctx, client, where):
        seen["where"] = where
        return 0, {}

    monkeypatch.setattr(kmip, "_target", lambda ctx, config: Target(label, ip))
    monkeypatch.setattr(kmip, "_context", lambda config, secrets: None)
    monkeypatch.setattr(kmip, "Client", FakeClient)
    monkeypatch.setattr(kmip, "read", fake_read)
    ctx = _Ctx()
    _, status, _, _ = kmip.run(ctx, {"host": label, "port": 5696}, {})
    assert status == "ok"
    places = {t: loc for t, _, loc in ctx.rows}
    assert places["certificate"] == f"{host}:5696#chain[0]"
    assert places["tls_endpoint"] == f"{host}:5696"
    assert ctx.names["tls_endpoint"] == f"kmip {host}:5696"
    assert seen["where"] == f"kmip://{host}:5696"
    assert places["key_store"] == f"kmip://{host}:5696"


def test_oracle_policy_location_brackets_ipv6():
    ctx = _Ctx()
    oracle._classify(ctx, Target("fd00::7", "fd00::7"), 1521, {}, "DPY-3001",
                     "network encryption requires thick mode")
    assert ctx.rows and ctx.rows[0][2] == "[fd00::7]:1521#native-encryption"


def test_kubernetes_api_server_rows_use_host_port():
    src = (ROOT / "collectors" / "kubernetes.py").read_text()
    assert 'f"{ip}:{api.port}' not in src, "the API server rows build host:port with netutil.host_port"
    assert src.count("host_port(ip, api.port)") >= 2


def test_no_unbracketed_label_port_left():
    for rel in ("collectors/kmip.py", "collectors/oracle.py"):
        src = (ROOT / rel).read_text()
        assert 'f"{target.label}:{port}' not in src, rel
        assert 'f"kmip://{target.label}:{port}"' not in src, rel
