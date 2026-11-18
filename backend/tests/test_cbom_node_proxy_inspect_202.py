"""#202: "My proxy inspects TLS" needs a proxy and the proxy's CA, on create and on edit. A node whose proxy is
removed stops claiming TLS inspection (there is nothing left to inspect) instead of refusing the edit."""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401

NODES = "/1/cbom/sources/nodes"
PROXY = "http://proxy.bank.local:8080"


def proxy_ca() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bank inspection CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_inspection_needs_a_proxy_and_its_ca_on_create(api, world):  # noqa: F811 (pytest fixtures)
    ca = proxy_ca()
    for body, field in (({"proxy_tls_inspect": True}, "proxy_url"),
                        ({"proxy_tls_inspect": True, "proxy_url": PROXY}, "proxy_ca_pem"),
                        ({"proxy_tls_inspect": True, "proxy_ca_pem": ca}, "proxy_url")):
        r = api("POST", NODES, json={"name": f"n-{field}-{len(body)}", **body})
        assert r.status_code in (400, 422) and field in r.text, (body, r.text)
    ok = api("POST", NODES, json={"name": "inspected", "proxy_url": PROXY, "proxy_ca_pem": ca, "proxy_tls_inspect": True})
    assert ok.status_code == 201, ok.text
    node = ok.json()["node"]
    assert node["proxy_tls_inspect"] is True and node["has_proxy_ca"] is True
    # a proxy without inspection still needs no CA
    assert api("POST", NODES, json={"name": "plain-proxy", "proxy_url": PROXY}).status_code == 201


def test_inspection_rules_on_edit(api, world):  # noqa: F811 (pytest fixtures)
    plain = api("POST", NODES, json={"name": "plain", "proxy_url": PROXY}).json()["node"]
    r = api("PATCH", f"{NODES}/{plain['id']}", json={"proxy_tls_inspect": True, "expected_version": plain["row_version"]})
    assert r.status_code == 400 and "proxy_ca_pem" in r.json()["detail"], r.text
    ca = proxy_ca()
    node = api("POST", NODES, json={"name": "insp", "proxy_url": PROXY, "proxy_ca_pem": ca,
                                    "proxy_tls_inspect": True}).json()["node"]
    # removing the proxy turns inspection off with it (the edit dialog has no inspection box)
    r = api("PATCH", f"{NODES}/{node['id']}", json={"proxy_url": None, "expected_version": node["row_version"]})
    assert r.status_code == 200, r.text
    assert r.json()["node"]["proxy_url"] is None and r.json()["node"]["proxy_tls_inspect"] is False
    # turning it on again without a proxy is refused
    after = r.json()["node"]
    r = api("PATCH", f"{NODES}/{node['id']}", json={"proxy_tls_inspect": True, "expected_version": after["row_version"]})
    assert r.status_code == 400 and "proxy_url" in r.json()["detail"], r.text
