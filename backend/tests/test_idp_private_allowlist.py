"""Identity-provider metadata on a private network: CBOM_IDP_ALLOWED_PRIVATE (operator) and CBOM_EXTRA_CA_FILE."""
import datetime as dt
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from backend.utilities.cbom_sources import idp_collect, safe_fetch

PRIVATE_IP = "10.250.7.9"
IDP_HOST = "sso.corp.example"


_REAL_GETADDRINFO = socket.getaddrinfo


def _resolver(mapping):
    """Test DNS: the mapped names resolve to the given address; literal addresses resolve as usual."""
    def getaddrinfo(host, port, *a, **k):
        if host in mapping:
            return [(socket.AF_INET6 if ":" in mapping[host] else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     (mapping[host], port))]
        if host in ("127.0.0.1", "::1"):
            return _REAL_GETADDRINFO(host, port, *a, **k)
        raise socket.gaierror(f"no such host {host}")
    return getaddrinfo


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("CBOM_IDP_ALLOWED_PRIVATE", "CBOM_LAB_ALLOW_PRIVATE_FETCH", "CBOM_EXTRA_CA_FILE", "CBOM_LAB_CA_FILE"):
        monkeypatch.delenv(name, raising=False)


def test_always_blocked_addresses_cannot_be_opened():
    allow = safe_fetch.parse_private_allowlist("0.0.0.0/0,::/0,metadata.internal", "TEST")
    for address in ("127.0.0.1", "169.254.169.254", "100.64.3.4", "0.0.0.0", "224.0.0.1", "240.0.0.1",
                    "::1", "fe80::1", "fd00:ec2::254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"):
        assert safe_fetch.always_blocked(address), address
        assert allow.permits("metadata.internal", address) is None, address
    assert allow.permits("anything", "10.1.2.3") == "cidr 0.0.0.0/0"
    assert allow.permits("anything", "fd12::5") == "cidr ::/0"


def test_cidr_and_host_entries(monkeypatch):
    allow = safe_fetch.parse_private_allowlist(" 10.250.0.0/16 , ADFS.corp.local., 192.168.4.7 ,fd12:3456::/48", "T")
    assert allow.permits("anything.example", "10.250.7.9").startswith("cidr 10.250.0.0/16")
    assert allow.permits("anything.example", "::ffff:10.250.7.9").startswith("cidr")  # mapped form, same rule
    assert allow.permits("x", "192.168.4.7") == "cidr 192.168.4.7/32"
    assert allow.permits("x", "192.168.4.8") is None
    assert allow.permits("adfs.corp.local", "172.16.9.9") == "host"
    assert allow.permits("other.corp.local", "172.16.9.9") is None
    assert allow.permits("x", "fd12:3456::9") == "cidr fd12:3456::/48"


def test_invalid_entries_are_ignored(capsys):
    allow = safe_fetch.parse_private_allowlist("10.0.0.0/33,bad host,https://x.y/,ok.lab", "T-INVALID")
    assert allow.hosts == frozenset({"ok.lab"}) and allow.networks == ()
    assert capsys.readouterr().out.count("entry_ignored") == 3


def test_resolve_uses_the_allowlist_only_when_given(monkeypatch):
    monkeypatch.setattr(safe_fetch.socket, "getaddrinfo", _resolver({IDP_HOST: PRIVATE_IP, "meta.corp": "169.254.169.254"}))
    with pytest.raises(safe_fetch.FetchError, match="private or reserved"):
        safe_fetch._resolve(IDP_HOST, 443, False)  # every other caller of safe_fetch stays public-only
    monkeypatch.setenv("CBOM_IDP_ALLOWED_PRIVATE", "10.250.0.0/16,meta.corp")
    allow = safe_fetch.idp_private_allowlist()
    assert safe_fetch._resolve(IDP_HOST, 443, False, allow) == [PRIVATE_IP]
    with pytest.raises(safe_fetch.FetchError) as err:
        safe_fetch._resolve("meta.corp", 443, False, allow)  # listed by name, but the metadata service never opens
    assert "CBOM_IDP_ALLOWED_PRIVATE" not in str(err.value)
    monkeypatch.setenv("CBOM_IDP_ALLOWED_PRIVATE", "10.99.0.0/16")
    with pytest.raises(safe_fetch.FetchError, match="can be allowed in CBOM_IDP_ALLOWED_PRIVATE"):
        safe_fetch._resolve(IDP_HOST, 443, False, safe_fetch.idp_private_allowlist())


@pytest.fixture
def private_idp(tmp_path, monkeypatch):
    """A real HTTPS IdP (OIDC discovery + JWKS) whose certificate comes from a private CA, reached at a private
    address: the test resolver answers 10.250.7.9 and the connection to that address lands on a loopback server."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Test Root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, IDP_HOST)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(2)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(IDP_HOST)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    state = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            base = f"https://{IDP_HOST}:{state['port']}"
            if self.path == "/.well-known/openid-configuration":
                body = {"issuer": base, "jwks_uri": f"{base}/jwks", "id_token_signing_alg_values_supported": ["ES256"]}
            elif self.path == "/jwks":
                body = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig"}]}
            else:
                self.send_response(404)
                self.end_headers()
                return
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "leaf.pem", tmp_path / "leaf.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    state["port"] = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    real_connect = socket.create_connection
    connected = []

    def create_connection(address, *a, **k):
        connected.append(address[0])
        if address[0] == PRIVATE_IP:
            return real_connect(("127.0.0.1", address[1]), *a, **k)
        raise OSError("unexpected destination")

    monkeypatch.setattr(safe_fetch.socket, "getaddrinfo", _resolver({IDP_HOST: PRIVATE_IP}))
    monkeypatch.setattr(safe_fetch.socket, "create_connection", create_connection)
    yield {"url": f"https://{IDP_HOST}:{state['port']}/.well-known/openid-configuration", "ca": str(tmp_path / "ca.pem"),
           "connected": connected}
    srv.shutdown()


def test_private_idp_is_refused_until_the_operator_lists_it(private_idp, monkeypatch):
    cfg = {"provider": "oidc_discovery", "metadata_url": private_idp["url"]}
    out = idp_collect.collect_idp(cfg, "corp-sso")
    assert out["counts"]["ok"] == 0 and "private or reserved" in out["targets"][0]["error"]
    assert private_idp["connected"] == []  # refused before any connection

    monkeypatch.setenv("CBOM_IDP_ALLOWED_PRIVATE", "10.250.0.0/16")
    out = idp_collect.collect_idp(cfg, "corp-sso")
    assert out["counts"]["ok"] == 0 and "not trusted" in out["targets"][0]["error"]  # private CA not trusted yet

    monkeypatch.setenv("CBOM_EXTRA_CA_FILE", private_idp["ca"])
    out = idp_collect.collect_idp(cfg, "corp-sso")
    assert out["counts"] == {"total": 1, "ok": 1, "partial": 0, "failed": 0, "skipped": 0}
    types = sorted(a["type"] for a in out["assets"])
    assert types == ["identity_provider", "signing_key"]
    assert set(private_idp["connected"]) == {PRIVATE_IP}


def test_old_lab_ca_name_still_works_and_host_entries_open_the_name(private_idp, monkeypatch):
    monkeypatch.setenv("CBOM_IDP_ALLOWED_PRIVATE", IDP_HOST)
    monkeypatch.setenv("CBOM_LAB_CA_FILE", private_idp["ca"])
    out = idp_collect.collect_idp({"provider": "oidc_discovery", "metadata_url": private_idp["url"]}, "corp-sso")
    assert out["counts"]["ok"] == 1


def test_other_safe_fetch_callers_ignore_the_idp_allowlist(private_idp, monkeypatch):
    monkeypatch.setenv("CBOM_IDP_ALLOWED_PRIVATE", "10.250.0.0/16")
    monkeypatch.setenv("CBOM_EXTRA_CA_FILE", private_idp["ca"])
    with pytest.raises(safe_fetch.FetchError, match="private or reserved"):
        safe_fetch.fetch(private_idp["url"])  # no private_allowlist argument: public only
