"""KMIP collector against a real KMIP server (PyKMIP 0.10 server; skipped unless ZS_TEST_KMIP_PYTHON is set).

ZS_TEST_KMIP_PYTHON is a Python 3.11 interpreter with PyKMIP installed (PyKMIP does not run on 3.12, which is why
the node has its own TTLV client).  The test makes a CA, a server and a client certificate, starts the server on
127.0.0.1 with TLS client authentication, seeds AES-128, AES-256 (value known to the test), RSA-1024 and a 3DES key,
revokes one key as compromised, then collects with KMIP 2.0 and 1.2 and checks attributes, findings and that no key
value reached the assets.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

PY = os.environ.get("ZS_TEST_KMIP_PYTHON")
pytestmark = pytest.mark.skipif(not PY or not os.path.isfile(PY), reason="ZS_TEST_KMIP_PYTHON (PyKMIP) not set")
KNOWN = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1ff")


def _pki(tmp: Path) -> dict[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("wp6 test CA")).issuer_name(name("wp6 test CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    out = {"ca": tmp / "ca.pem"}
    out["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for who, eku in (("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name(f"wp6-{who}")).issuer_name(ca.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))
        out[f"{who}_cert"] = tmp / f"{who}.pem"
        out[f"{who}_key"] = tmp / f"{who}.key"
        out[f"{who}_cert"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        out[f"{who}_key"].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
    return {k: str(v) for k, v in out.items()}


@pytest.fixture(scope="module")
def kmip_server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("kmip")
    pki = _pki(tmp)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    (tmp / "policies").mkdir()
    conf = tmp / "server.conf"
    conf.write_text(textwrap.dedent(f"""\
        [server]
        hostname=127.0.0.1
        port={port}
        certificate_path={pki['server_cert']}
        key_path={pki['server_key']}
        ca_path={pki['ca']}
        auth_suite=TLS1.2
        policy_path={tmp / 'policies'}
        enable_tls_client_auth=True
        logging_level=ERROR
        database_path={tmp / 'kmip.db'}
        """))
    proc = subprocess.Popen([PY, "-m", "kmip.services.server.server", "-f", str(conf), "-l", str(tmp / "server.log")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), 1).close()
            break
        except OSError:
            time.sleep(0.5)
    seed = textwrap.dedent(f"""\
        import datetime, time
        from kmip.pie.client import ProxyKmipClient
        from kmip.pie import objects
        from kmip.core import enums
        c = ProxyKmipClient(hostname="127.0.0.1", port={port}, cert={pki['client_cert']!r}, key={pki['client_key']!r},
                            ca={pki['ca']!r}, ssl_version="PROTOCOL_TLSv1_2", kmip_version=enums.KMIPVersion.KMIP_1_2)
        with c:
            a = c.create(enums.CryptographicAlgorithm.AES, 128, name="aes-128",
                         cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT, enums.CryptographicUsageMask.DECRYPT])
            c.activate(a)
            k = objects.SymmetricKey(enums.CryptographicAlgorithm.AES, 256, bytes.fromhex({KNOWN.hex()!r}),
                                     name="aes-256-known")
            c.register(k)
            pub, priv = c.create_key_pair(enums.CryptographicAlgorithm.RSA, 1024, public_name="rsa-1024-pub",
                                          private_name="rsa-1024-priv",
                                          public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
                                          private_usage_mask=[enums.CryptographicUsageMask.SIGN])
            d = objects.SymmetricKey(enums.CryptographicAlgorithm.TRIPLE_DES, 192, bytes(range(24)), name="3des-legacy")
            c.register(d)
            x = c.create(enums.CryptographicAlgorithm.AES, 256, name="aes-compromised")
            c.revoke(enums.RevocationReasonCode.KEY_COMPROMISE, x, compromise_occurrence_date=int(time.time()) - 60)
        print("seeded")
        """)
    done = subprocess.run([PY, "-c", seed], capture_output=True, text=True, timeout=120)
    if "seeded" not in done.stdout:
        proc.terminate()
        pytest.fail("seeding the KMIP server failed: " + done.stderr[-2000:])
    yield {"port": port, **pki}
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)


def _ctx(kind="collect"):
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="key_manager", scrubber=Scrubber(),
                      never_scan=NeverScan(), deadline=time.monotonic() + 120)


def _config(srv, ca=True):
    cfg = {"provider": "kmip", "host": "127.0.0.1", "port": srv["port"]}
    if ca:
        cfg["ca_pem"] = Path(srv["ca"]).read_text()
    return cfg, {"client_cert": Path(srv["client_cert"]).read_text(), "client_key": Path(srv["client_key"]).read_text()}


def test_kmip_inventory_and_no_key_values(kmip_server):
    from zs_scan_node.collectors import kmip

    ctx = _ctx()
    cfg, secrets = _config(kmip_server)
    kmip.collect(ctx, cfg, secrets, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"], ctx.outcomes
    store = [a for a in ctx.collected if a["type"] == "key_store"][0]["facts"]
    assert "2.0" in store["protocol_versions"] and store["protocol_version"] == "2.0"
    keys = {a["name"]: a for a in ctx.collected if a["type"] == "managed_key"}
    assert keys["aes-128"]["algorithm"] == "AES" and keys["aes-128"]["key_size"] == 128
    assert keys["aes-128"]["facts"]["state"] == "Active"
    assert keys["rsa-1024-priv"]["algorithm"] == "RSA" and keys["rsa-1024-priv"]["key_size"] == 1024
    assert keys["rsa-1024-priv"]["facts"]["key_class"] == "private"
    assert keys["3des-legacy"]["algorithm"] == "3DES"
    assert keys["aes-compromised"]["facts"]["state"] == "Compromised"
    blob = json.dumps(ctx.collected)
    for form in (KNOWN.hex(), KNOWN.hex().upper(), base64.b64encode(KNOWN).decode(), bytes(range(24)).hex()):
        assert form not in blob
    assert "PRIVATE KEY" not in blob
    # the findings the server-side rules give these facts
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    classify = pytest.importorskip("backend.utilities.cbom_sources.classify")
    codes = {n: set(classify.classify("managed_key", a["algorithm"], a["key_size"], None, a["facts"])["finding_codes"])
             for n, a in keys.items()}
    assert "RSA_LT_2048" in codes["rsa-1024-priv"] and "QUANTUM_VULNERABLE" in codes["rsa-1024-priv"]
    assert "KEY_WEAK_SYMMETRIC" in codes["3des-legacy"]
    assert "KEY_COMPROMISED" in codes["aes-compromised"]
    assert not codes["aes-128"] - {"KEY_NO_ROTATION"}


def test_kmip_1_2_server_path(kmip_server, monkeypatch):
    from zs_scan_node.collectors import kmip

    monkeypatch.setattr(kmip, "VERSIONS", ((1, 2),))
    ctx = _ctx()
    cfg, secrets = _config(kmip_server)
    kmip.collect(ctx, cfg, secrets, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"]
    keys = {a["name"]: a for a in ctx.collected if a["type"] == "managed_key"}
    assert keys["aes-256-known"]["key_size"] == 256 and keys["3des-legacy"]["algorithm"] == "3DES"
    assert [a for a in ctx.collected if a["type"] == "key_store"][0]["facts"]["protocol_version"] == "1.2"


def test_kmip_wrong_ca_is_identity_unverified_and_never_scan_blocks(kmip_server):
    from zs_scan_node.collectors import kmip

    ctx = _ctx()
    cfg, secrets = _config(kmip_server)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        cfg["ca_pem"] = Path(_pki(Path(d))["ca"]).read_text()  # an unrelated CA
        kmip.collect(ctx, cfg, secrets, {})
    assert [o.status for o in ctx.outcomes] == ["identity_unverified"]
    ctx = _ctx()
    ctx.never_scan.update(["127.0.0.1"])
    cfg, secrets = _config(kmip_server)
    kmip.collect(ctx, cfg, secrets, {})
    assert [o.status for o in ctx.outcomes] == ["skipped_never_scan"]


def test_kmip_test_connection(kmip_server):
    from zs_scan_node.collectors import kmip

    ctx = _ctx("test_connection")
    cfg, secrets = _config(kmip_server, ca=False)
    kmip.test(ctx, cfg, secrets, {})
    assert ctx.samples[0]["status"] == "ready" and ctx.samples[0]["login"] is True
