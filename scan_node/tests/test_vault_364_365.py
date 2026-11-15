"""#365: the vault path prefix in either KV v2 form, and a Vault with a private CA. #364: what the node reports about
its vault support (providers it can read, its prefix, per-provider setup), so ZeroShield can check an import.

* ``ZS_VAULT_PATH_PREFIX=secret/data/cbom`` (the natural KV v2 form, and the UI's own examples) refused every path
  on dev: the KV v2 ``data`` segment was dropped from the path but not from the prefix. Both forms now mean the same.
  The KV v2 rule is HashiCorp's only: an AWS Secrets Manager name with a ``data`` segment is read as written (dev
  read another secret: ``app/data/db`` became ``app/db``).
* A Vault with a private CA: ``ZS_VAULT_CA_FILE`` (or Vault's own ``VAULT_CACERT`` / ``VAULT_CAPATH``) is trusted
  for the Vault connection only. dev: "vault not reachable (ConnectError)" unless the whole trust store was
  replaced.

A real TLS Vault stub on 127.0.0.1 with a certificate from a private CA.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node import vault as V
from zs_scan_node.collectors import ConfigError

TOKEN = "hvs.test-token-not-real"
ENV = ("ZS_VAULT_CA_FILE", "VAULT_CACERT", "VAULT_CAPATH", "VAULT_ADDR", "VAULT_TOKEN", "HTTPS_PROXY", "https_proxy",
       "SSL_CERT_FILE", "SSL_CERT_DIR")


# ----------------------------------------------------------------------------- #365 the prefix, both forms
@pytest.mark.parametrize("prefix", ["secret/cbom", "secret/data/cbom", "secret/data/cbom/", "/secret/cbom/"])
@pytest.mark.parametrize("path", ["secret/cbom/pg-lab", "secret/data/cbom/pg-lab"])
def test_365_both_kv2_forms_of_prefix_and_path_mean_the_same(prefix, path):
    assert V.check_prefix(path, prefix) == ["secret", "cbom", "pg-lab"]  # dev: refused for prefix secret/data/cbom


@pytest.mark.parametrize("prefix", ["secret/cbom", "secret/data/cbom"])
@pytest.mark.parametrize("path", ["secret/other/x", "secret/data/other/x", "secret/cbomx/y", "secret/data/cbomx/y",
                                  "secret/cbom/../x", "other/data/cbom/x", "secret/metadata/cbom/x"])
def test_365_a_path_outside_the_prefix_is_still_refused(prefix, path):
    with pytest.raises(ConfigError):
        V.check_prefix(path, prefix)


def test_365_the_refusal_names_the_prefix_in_both_forms():
    with pytest.raises(ConfigError) as err:
        V.check_prefix("secret/other/x", "secret/data/cbom")
    assert "secret/cbom/..." in str(err.value) and "secret/data/cbom/..." in str(err.value)


def test_365_aws_secret_names_are_read_as_written(monkeypatch):
    """The KV v2 rule is HashiCorp's: an AWS secret named app/data/db is that secret, not app/db (dev)."""
    assert V.check_prefix("app/data/db", "app", provider="aws_secrets_manager") == ["app", "data", "db"]
    asked = []

    class Client:
        def get_secret_value(self, SecretId):
            asked.append(SecretId)
            return {"SecretString": json.dumps({"password": "pw"})}

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *a, **k: Client())
    assert V.fetch("aws_secrets_manager", "app/data/db", "app") == {"password": "pw"}
    assert asked == ["app/data/db"]  # dev: "app/db", another secret


# ----------------------------------------------------------------------------- #365 a Vault with a private CA
def _pki(tmp_path):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bank Internal Root")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vault")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False).sign(ca_key, hashes.SHA256()))
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "vault.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "vault.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
    return tmp_path / "ca.pem", tmp_path / "vault.pem", tmp_path / "vault.key"


@pytest.fixture()
def vault_server(tmp_path, monkeypatch):
    import ssl

    ca, cert, key = _pki(tmp_path)
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append(self.path)
            if self.headers.get("X-Vault-Token") != TOKEN:
                self.send_response(403)
                self.end_headers()
                return
            if self.path == "/v1/secret/data/cbom/pg-lab":
                body = json.dumps({"data": {"data": {"password": "pw-from-vault"}}}).encode()
                self.send_response(200)
            else:
                body = b"{}"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)
    server.socket = sctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VAULT_ADDR", f"https://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("VAULT_TOKEN", TOKEN)
    yield SimpleNamespace(ca=str(ca), seen=seen)
    server.shutdown()
    server.server_close()


def test_365_a_private_ca_vault_without_its_ca_says_so(vault_server):
    with pytest.raises(ConfigError) as err:
        V.fetch("hashicorp", "secret/data/cbom/pg-lab", "secret/data/cbom")
    msg = str(err.value)  # dev: "vault not reachable (ConnectError)"
    assert msg.startswith("the Vault server certificate is not trusted (")
    assert "set ZS_VAULT_CA_FILE to the CA certificate that issued it" in msg and TOKEN not in msg


@pytest.mark.parametrize("variable", ["ZS_VAULT_CA_FILE", "VAULT_CACERT"])
def test_365_the_vault_ca_file_is_trusted_for_the_vault(vault_server, monkeypatch, variable):
    monkeypatch.setenv(variable, vault_server.ca)
    assert V.fetch("hashicorp", "secret/data/cbom/pg-lab", "secret/data/cbom") == {"password": "pw-from-vault"}
    assert vault_server.seen == ["/v1/secret/data/cbom/pg-lab"]


def test_365_a_ca_directory_works_too(vault_server, monkeypatch, tmp_path):
    import shutil
    import subprocess

    capath = tmp_path / "capath"
    capath.mkdir()
    shutil.copy(vault_server.ca, capath / "bank.pem")
    rehash = shutil.which("openssl")
    if rehash is None:
        pytest.skip("openssl is needed to hash the CA directory")
    subprocess.run([rehash, "rehash", str(capath)], check=True, capture_output=True)
    monkeypatch.setenv("VAULT_CAPATH", str(capath))
    assert V.fetch("hashicorp", "secret/cbom/pg-lab", "secret/cbom") == {"password": "pw-from-vault"}


def test_365_an_unreadable_vault_ca_file_is_named(vault_server, monkeypatch, tmp_path):
    monkeypatch.setenv("ZS_VAULT_CA_FILE", str(tmp_path / "missing.pem"))
    with pytest.raises(ConfigError) as err:
        V.fetch("hashicorp", "secret/cbom/pg-lab", "secret/cbom")
    assert "ZS_VAULT_CA_FILE" in str(err.value) and "cannot be read" in str(err.value)


def test_365_a_missing_secret_is_still_a_clear_refusal(vault_server, monkeypatch):
    monkeypatch.setenv("ZS_VAULT_CA_FILE", vault_server.ca)
    with pytest.raises(ConfigError, match=r"vault refused the secret \(404\)"):
        V.fetch("hashicorp", "secret/cbom/nope", "secret/cbom")


# ----------------------------------------------------------------------------- #364 what the node reports
def test_364_cyberark_and_azure_say_not_available_yet():
    for provider, label in (("cyberark", "CyberArk"), ("azure_key_vault", "Azure Key Vault")):
        with pytest.raises(ConfigError) as err:
            V.fetch(provider, "secret/cbom/x", "secret/cbom")
        assert str(err.value) == (f"{label} is not available yet on scan nodes: use HashiCorp Vault or AWS Secrets "
                                  "Manager for this credential")


def test_364_the_heartbeat_reports_vault_support_and_setup_never_the_token(monkeypatch):
    from zs_scan_node import agent as A

    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.bank.local:8200")
    monkeypatch.setenv("VAULT_TOKEN", TOKEN)
    me = SimpleNamespace(agent_mode=False, max_jobs=2, vault_prefix="secret/data/cbom")
    caps = A.Agent.capabilities(me)
    assert caps["vault"] is True  # unchanged for older servers
    assert caps["vault_providers"] == ["hashicorp", "aws_secrets_manager"]  # dev: not reported
    assert caps["vault_prefix"] == "secret/cbom"  # the prefix as the node compares it
    assert caps["vault_setup"] == {"hashicorp": "ready", "aws_secrets_manager": "ready"}
    assert TOKEN not in json.dumps(caps)
    monkeypatch.delenv("VAULT_TOKEN")
    caps = A.Agent.capabilities(me)
    assert caps["vault_setup"]["hashicorp"] == "VAULT_ADDR and VAULT_TOKEN are not set on this scan node"
    off = A.Agent.capabilities(SimpleNamespace(agent_mode=False, max_jobs=2, vault_prefix=None))
    assert off["vault"] is False and off["vault_prefix"] is None and off["vault_providers"] == [
        "hashicorp", "aws_secrets_manager"]
