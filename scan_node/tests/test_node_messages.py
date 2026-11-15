"""Scan-node messages that name the cause in the customer's words, never a raw exception class.

* #152: a host that accepts TCP on 22 and never sends an SSH banner is held at most the source's "Timeout per
  server", not a fixed 15 s, and is reported as a timeout that says so (dev: 15 s, "SSH handshake failed
  (SSHException)").
* #153: connection-test notes say "no route to ...", "port ... refused", "answered HTTPS but is not a WinRM
  endpoint ..." (dev: "OSError", "ConnectionError", "WinRMTransportError").
* #198: a ZeroShield API certificate the node does not trust is logged and reported as that, with the ZS_CA_FILE
  hint (dev: "api unreachable ... error=ConnectError").
* #214: databases, registry and HSM: a missing PostgreSQL database, a pg_hba refusal, a MySQL certificate the CA
  does not sign (the password was not sent), an Oracle service the listener does not know, a registry certificate
  the node does not trust, a wrong HSM PIN and a token label that matches none of the module's tokens.

Real sockets and TLS servers on 127.0.0.1 where the cause is a network one; the drivers' own error objects where
the cause is a server's answer.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node.collectors.linux_ssh import TargetFail
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, expand_targets
from zs_scan_node.scrub import Scrubber


def _ctx(kind: str = "test_connection", source_kind: str = "linux_servers") -> JobContext:
    return JobContext(job_id=7, attempt=1, run_id=None, kind=kind, source_kind=source_kind, scrubber=Scrubber(),
                      never_scan=NeverScan([]), deadline=time.monotonic() + 120)


def _target(ip: str):
    targets, _skipped = expand_targets([ip], NeverScan([]))
    return targets[0]


class _Tarpit:
    """Accepts TCP and never writes (a hung sshd, a tarpit)."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.conns: list[socket.socket] = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.conns.append(conn)

    def close(self):
        for c in self.conns:
            c.close()
        self.srv.close()


def _self_signed(cn: str = "mitmproxy") -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


class _TlsServer:
    """A TLS server with a self-signed certificate (what a TLS-inspecting proxy looks like without its CA)."""

    def __init__(self, tmp_path):
        cert, key = _self_signed()
        (tmp_path / "c.pem").write_bytes(cert)
        (tmp_path / "k.pem").write_bytes(key)
        self.sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            try:
                self.sctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()

    def close(self):
        self.srv.close()


# ----------------------------------------------------------------------------- #152 SSH banner timeout
def test_152_a_host_without_an_ssh_banner_is_held_only_the_per_server_timeout(tmp_path):
    pit = _Tarpit()
    try:
        config = {"port": pit.port, "timeout_s": 2, "host_key_policy": "tofu", "credential_type": "key"}
        ctx = _ctx()
        ctx.state_dir = str(tmp_path)
        started = time.monotonic()
        with pytest.raises(TargetFail) as err:
            L.open_session(ctx, _target("127.0.0.1"), config, {"key": object()})
        elapsed = time.monotonic() - started
    finally:
        pit.close()
    assert elapsed < 5, elapsed  # dev: 15 s (banner_timeout = 15)
    assert err.value.status == "timeout"
    assert err.value.error == ("no SSH banner from 127.0.0.1 within 2 s (not an SSH server, or sshd is hung)")


def test_152_the_handshake_never_outlives_the_job(tmp_path):
    pit = _Tarpit()
    try:
        ctx = _ctx()
        ctx.state_dir = str(tmp_path)
        ctx.deadline = time.monotonic() + 1.5  # the job's window ends before the per-server timeout would
        config = {"port": pit.port, "timeout_s": 600, "host_key_policy": "tofu", "credential_type": "key"}
        started = time.monotonic()
        with pytest.raises(TargetFail):
            L.open_session(ctx, _target("127.0.0.1"), config, {"key": object()})
        assert time.monotonic() - started < 5
    finally:
        pit.close()


# ----------------------------------------------------------------------------- #153 plain socket and WinRM notes
@pytest.mark.parametrize("exc, status, note", [
    (OSError(113, "No route to host"), "no_route", "no route to 10.232.0.2"),
    (OSError(101, "Network is unreachable"), "no_route", "no route to 10.232.0.2"),
    (ConnectionRefusedError(111, "Connection refused"), "refused", "port 22 refused"),
    (socket.timeout("timed out"), "timeout", "no answer from 10.232.0.2 on port 22"),
    (ConnectionResetError(104, "Connection reset by peer"), "unreachable",
     "10.232.0.2:22 closed the connection (connection reset)"),
    (OSError(99, "Cannot assign requested address"), "unreachable",
     "could not connect to 10.232.0.2:22 (Cannot assign requested address)"),
])
def test_153_socket_errors_are_plain_words(monkeypatch, exc, status, note):
    def connect(*_a, **_k):
        raise exc

    monkeypatch.setattr(L.netutil, "connect", connect)
    with pytest.raises(TargetFail) as err:
        L.open_session(_ctx(), _target("10.232.0.2"), {"port": 22, "host_key_policy": "tofu"}, {"key": object()})
    assert (err.value.status, err.value.error) == (status, note)  # dev: ("no_route", "OSError") ...
    assert "Error" not in err.value.error


def _winrm_fail(exc):
    from zs_scan_node.collectors import windows_winrm as W

    class Sess:
        def run_ps(self, _script):
            raise exc

    with pytest.raises(W._Fail) as err:
        W._run(Sess(), next(iter(W.SCRIPTS)))
    return err.value


def test_153_winrm_on_a_closed_port_says_refused():
    import requests

    exc = requests.exceptions.ConnectionError(
        "HTTPSConnectionPool(host='win01', port=5986): Max retries exceeded with url: /wsman (Caused by "
        "NewConnectionError('<urllib3.connection.HTTPSConnection object>: Failed to establish a new connection: "
        "[Errno 111] Connection refused'))")
    fail = _winrm_fail(exc)
    assert (fail.status, fail.error) == ("refused", "WinRM port 5986 on win01 refused the connection")


def test_153_an_https_server_that_is_not_winrm_says_so():
    from winrm.exceptions import WinRMTransportError

    fail = _winrm_fail(WinRMTransportError("http", 405, "Bad HTTP response returned from server. Code 405"))
    assert fail.status == "not_supported"
    assert fail.error == "the server answered HTTPS but is not a WinRM endpoint (HTTP 405 on /wsman)"


def test_153_winrm_with_no_route_says_so():
    import requests

    exc = requests.exceptions.ConnectionError("... Failed to establish a new connection: [Errno 113] No route to host")
    fail = _winrm_fail(exc)
    assert (fail.status, fail.error) == ("no_route", "no route to the WinRM server")


# ----------------------------------------------------------------------------- #198 API certificate not trusted
def test_198_an_untrusted_api_certificate_is_named_with_the_ca_hint(tmp_path, monkeypatch):
    import httpx

    from zs_scan_node import api as A
    from zs_scan_node import errtext

    srv = _TlsServer(tmp_path)
    lines: list[tuple[str, dict]] = []
    monkeypatch.setattr(A, "log", lambda msg, **kw: lines.append((msg, kw)))
    try:
        client = httpx.Client(base_url=f"https://127.0.0.1:{srv.port}", timeout=5)
        try:
            client.get("/cbom/node/heartbeat")
        except httpx.HTTPError as exc:
            text = errtext.api_transport_error(exc)
    finally:
        srv.close()
    assert text.startswith("the ZeroShield API certificate is not trusted (")
    assert "self-signed certificate" in text  # OpenSSL's verify message, not the class name
    assert "If a proxy inspects TLS, set ZS_CA_FILE to its CA certificate" in text
    assert "ConnectError" not in text


def test_198_the_api_client_logs_and_raises_the_tls_cause(tmp_path, monkeypatch):
    from zs_scan_node import api as A

    srv = _TlsServer(tmp_path)
    lines: list[tuple[str, dict]] = []
    monkeypatch.setattr(A, "log", lambda msg, **kw: lines.append((msg, kw)))
    try:
        api = A.Api.__new__(A.Api)
        import httpx

        api.client = httpx.Client(base_url=f"https://127.0.0.1:{srv.port}", timeout=5)
        api.base = f"https://127.0.0.1:{srv.port}"
        api._headers = lambda job=None: {}
        api._sign = lambda *a: {}
        api._wait = lambda s: None
        with pytest.raises(A.ApiError) as err:
            api.call("POST", "/cbom/node/heartbeat", {}, retries=1)
    finally:
        srv.close()
    assert "certificate is not trusted" in str(err.value) and "ZS_CA_FILE" in str(err.value)
    retry = [kw for msg, kw in lines if msg == "api unreachable, retrying"]
    assert retry and "certificate is not trusted" in retry[0]["cause"]  # dev: only error=ConnectError


# ----------------------------------------------------------------------------- #214 databases, registry, HSM
def _pg_fail(monkeypatch, message: str):
    import psycopg

    from zs_scan_node.collectors import database as D

    def connect(**_k):
        raise psycopg.OperationalError(message)

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(D, "checked_target", lambda target, never: target.ip)
    with pytest.raises(D.DbFail) as err:
        D._postgres(_ctx(source_kind="database"), _target("10.232.0.7"),
                    {"port": 5432, "login": "zs", "database_name": "nosuchdb"}, "pw", D._CaFile(None))
    return err.value


def test_214_a_missing_postgres_database_is_not_unreachable(monkeypatch):
    fail = _pg_fail(monkeypatch, 'connection failed: connection to server at "10.232.0.7", port 5432 failed: '
                                 'FATAL:  database "nosuchdb" does not exist')
    assert (fail.status, fail.error) == ("error", 'PostgreSQL is reachable and the login worked, but the database '
                                                  '"nosuchdb" does not exist: check the database name')


def test_214_a_pg_hba_refusal_is_not_a_wrong_password(monkeypatch):
    fail = _pg_fail(monkeypatch, 'connection failed: connection to server at "10.232.0.7", port 5432 failed: FATAL:  '
                                 'no pg_hba.conf entry for host "10.232.1.15", user "zs", database "postgres", '
                                 'SSL encryption')
    assert fail.status == "auth_failed"
    assert fail.error == ("PostgreSQL has no pg_hba.conf entry for this scan node (10.232.1.15, user zs): add a "
                          "hostssl line for it; the password was not checked")


def test_214_a_wrong_postgres_password_still_says_so(monkeypatch):
    fail = _pg_fail(monkeypatch, 'connection failed: FATAL:  password authentication failed for user "zs"')
    assert (fail.status, fail.error) == ("auth_failed", "PostgreSQL refused the login (wrong user name or password)")


def test_214_a_mysql_certificate_the_ca_does_not_sign_withholds_the_password(monkeypatch):
    import pymysql

    from zs_scan_node.collectors import database as D

    def connect(*_a, **_k):
        raise pymysql.err.OperationalError(2003, "Can't connect to MySQL server on '10.232.0.8' ([SSL: "
                                                 "CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get "
                                                 "local issuer certificate (_ssl.c:1006))")

    monkeypatch.setattr(D, "_mysql_connect", connect)
    with pytest.raises(D.DbFail) as err:
        D._mysql(_ctx(source_kind="database"), _target("10.232.0.8"), {"port": 3306}, "pw", D._CaFile(None), True)
    assert err.value.status == "identity_unverified"
    assert err.value.error == ("the MySQL server's certificate is not signed by the uploaded CA (unable to get local "
                               "issuer certificate); the password was not sent")


def test_214_an_oracle_service_the_listener_does_not_know_is_named(monkeypatch):
    from zs_scan_node.collectors import oracle as O

    message = ('DPY-6005: cannot connect to database (CONNECTION_ID=abc).\nDPY-6001: Service "NOSUCH" is not '
               'registered with the listener at host "10.232.0.9" port 1521. (Similar to ORA-12514)')
    code, line = O.thin_error(Exception(message))
    fail = O._classify(_ctx(source_kind="database"), _target("10.232.0.9"), 1521, {"database_name": "NOSUCH"},
                       code, line)
    assert (fail.status, fail.error) == ("error", 'the Oracle listener on 10.232.0.9:1521 is reachable but does not '
                                                  'know the service "NOSUCH": check the service name')


def test_214_a_registry_certificate_the_node_does_not_trust_is_named(tmp_path):
    from zs_scan_node.collectors import container_images as CI

    srv = _TlsServer(tmp_path)
    try:
        import httpx

        try:
            httpx.get(f"https://127.0.0.1:{srv.port}/v2/", timeout=5)
        except httpx.HTTPError as exc:
            status, note = CI.registry_error(exc, "127.0.0.1")
    finally:
        srv.close()
    assert status == "tls_unavailable"
    assert note == ("127.0.0.1: the registry certificate is not trusted (self-signed certificate); upload the CA "
                    "that issued it")


class _Token:
    def __init__(self, label):
        self.label = label


def test_214_hsm_pin_and_label_messages(monkeypatch):
    from pkcs11.exceptions import PinIncorrect

    from zs_scan_node.collectors import hsm_pkcs11 as H

    assert H.pkcs11_note(PinIncorrect()) == ("auth_failed", "the HSM refused the PIN (CKR_PIN_INCORRECT); check the "
                                                            "PIN of this token with the HSM administrator")
    note = H.no_token_note("payments", ["backup", "ca-root"])
    assert note == ('no token labelled "payments" on this module (its tokens: backup, ca-root); check the token '
                    'label')
    assert H.no_token_note("", []) == "no initialised token is present on this module"
