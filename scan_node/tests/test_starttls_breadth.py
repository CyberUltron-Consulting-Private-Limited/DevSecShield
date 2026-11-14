"""CB-34: STARTTLS on POP3 (STLS, RFC 2595), FTP (AUTH TLS, RFC 4217) and XMPP (RFC 6120, client and server
streams), next to the SMTP/submission, IMAP, LDAP, PostgreSQL and MySQL preambles the node already speaks.

Each protocol runs against a LOCAL TEST SERVER in this file: it speaks the protocol's plaintext dialogue exactly as
the RFC describes it, then a real TLS handshake (Python's ssl, a throwaway self-signed certificate). The node's raw
ClientHello probe, its Python full handshake and ``openssl s_client -starttls <proto>`` (when openssl is installed)
must all reach TLS through it and read the certificate. Refusals (no STLS in CAPA, AUTH TLS 530, an XMPP stream
error or no <starttls/> feature) are "no TLS here" (StarttlsUnavailable), never a crash or a false TLS result."""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node import tlsprobe as T

_DIR = Path(tempfile.mkdtemp(prefix="zs-starttls-"))


def _tls_context() -> ssl.SSLContext:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.bank.example")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(4242).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    (_DIR / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (_DIR / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(_DIR / "c.pem", _DIR / "k.pem")
    return ctx


TLS = _tls_context()


def _line(conn) -> bytes:
    buf = b""
    while not buf.endswith(b"\n"):
        ch = conn.recv(1)
        if not ch:
            raise OSError("closed")
        buf += ch
    return buf


def _until(conn, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


class Server:
    """A plaintext dialogue (``dialogue(conn, self)`` returns True to start TLS), then TLS 1.2/1.3."""

    def __init__(self, dialogue):
        self.dialogue, self.seen = dialogue, []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        conn.settimeout(5)
        try:
            if self.dialogue(conn, self):
                tls = TLS.wrap_socket(conn, server_side=True)
                try:
                    tls.recv(1)  # until the client closes
                except (OSError, ssl.SSLError):
                    pass
                tls.close()
                return
        except (OSError, ssl.SSLError):
            pass
        conn.close()

    def close(self):
        self.srv.close()


# --------------------------------------------------------------------------------------- protocol dialogues
def pop3(stls=True, capa=True, refuse=False):
    def run(conn, srv):
        conn.sendall(b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n")
        while True:
            cmd = _line(conn).strip().upper()
            srv.seen.append(cmd)
            if cmd == b"CAPA":
                if not capa:
                    conn.sendall(b"-ERR unknown command\r\n")
                    continue
                conn.sendall(b"+OK Capability list follows\r\nTOP\r\nUSER\r\n" + (b"STLS\r\n" if stls else b"") +
                             b"UIDL\r\n.\r\n")
            elif cmd == b"STLS":
                if refuse or not stls:
                    conn.sendall(b"-ERR command not permitted\r\n")
                    return False
                conn.sendall(b"+OK Begin TLS negotiation\r\n")
                return True
            elif cmd == b"QUIT":  # openssl s_client sends nothing else; a probe may close
                return False
            else:
                conn.sendall(b"-ERR\r\n")
    return run


def ftp(code=b"234", multiline=True):
    def run(conn, srv):
        if multiline:
            conn.sendall(b"220-Welcome to the bank FTP service\r\n220-Authorised users only\r\n220 FTP ready\r\n")
        else:
            conn.sendall(b"220 FTP ready\r\n")
        while True:
            cmd = _line(conn).strip().upper()
            srv.seen.append(cmd)
            if cmd == b"AUTH TLS":
                if code == b"234":
                    conn.sendall(b"234 AUTH TLS successful\r\n")
                    return True
                conn.sendall(code + b" Please login with USER and PASS\r\n")
                return False
            if cmd == b"FEAT":
                conn.sendall(b"211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n")
            else:
                conn.sendall(b"500 Unknown command\r\n")
    return run


def xmpp(domain="chat.bank.example", ns=b"jabber:client", offer=True, required=True, failure=False):
    def run(conn, srv):
        head = _until(conn, b">")
        while b"stream:stream" not in head or not head.rstrip().endswith(b">") or b"version" not in head:
            head += _until(conn, b">")
        srv.seen.append(head)
        to = head.split(b"to=", 1)[1][1:].split(head.split(b"to=", 1)[1][:1], 1)[0] if b"to=" in head else b""
        stream = (b"<?xml version='1.0'?><stream:stream xmlns='" + ns + b"' xmlns:stream='http://etherx.jabber.org/"
                  b"streams' id='s1' from='" + domain.encode() + b"' version='1.0'>")
        if to.decode() != domain:
            conn.sendall(stream + b"<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                         b"</stream:error></stream:stream>")
            return False
        tls = (b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>" + (b"<required/>" if required else b"") +
               b"</starttls>") if offer else b""
        conn.sendall(stream + b"<stream:features>" + tls + b"<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                     b"<mechanism>PLAIN</mechanism></mechanisms></stream:features>")
        if not offer:
            return False
        srv.seen.append(_until(conn, b"/>"))
        if failure:
            conn.sendall(b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>")
            return False
        conn.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        return True
    return run


def _hello():
    return T.build_client_hello(T.TLS12, T.TLS13_SUITES + T.LEGACY_SUITES, tls13=True,
                                groups=T.CLASSICAL_GROUPS, key_share_groups=[29],
                                versions13=[T.TLS13, T.TLS12])


def _reaches_tls(protocol, dialogue, *, xmpp_name=None):
    srv = Server(dialogue)
    try:
        with T.starttls_name(xmpp_name):
            r = T.probe("127.0.0.1", srv.port, protocol, _hello())
            assert r.ok and r.version_name in ("TLSv1.2", "TLSv1.3"), r
            fh = T.python_handshake("127.0.0.1", srv.port, protocol, None)
            assert fh.ok and fh.certs_der, fh
            if T.have_openssl():
                sc = T.s_client("127.0.0.1", srv.port, protocol, None)
                assert sc.ok and sc.certs_der, sc
                assert x509.load_der_x509_certificate(sc.certs_der[0]).serial_number == 4242
        return srv
    finally:
        srv.close()


# --------------------------------------------------------------------------------------- reaching TLS
def test_pop3_stls_reaches_tls():
    srv = _reaches_tls("starttls-pop3", pop3())
    assert b"STLS" in srv.seen


def test_pop3_without_capa_is_asked_stls_anyway():
    _reaches_tls("starttls-pop3", pop3(capa=False))


def test_ftp_auth_tls_reaches_tls_after_a_multi_line_greeting():
    srv = _reaches_tls("starttls-ftp", ftp())
    assert b"AUTH TLS" in srv.seen


def test_xmpp_client_and_server_streams_reach_tls_with_the_endpoints_name():
    srv = _reaches_tls("starttls-xmpp", xmpp(), xmpp_name="chat.bank.example")
    assert any(b"to='chat.bank.example'" in s or b'to="chat.bank.example"' in s for s in srv.seen), srv.seen
    _reaches_tls("starttls-xmpp-server", xmpp(ns=b"jabber:server"), xmpp_name="chat.bank.example")


def test_xmpp_without_a_name_names_the_address():
    srv = Server(xmpp(domain="127.0.0.1"))
    try:
        sock, facts = T.open_tls_socket("127.0.0.1", srv.port, "starttls-xmpp", 5)
        sock.close()
        assert facts == {"xmpp_domain": "127.0.0.1", "xmpp_required": True}
    finally:
        srv.close()


# --------------------------------------------------------------------------------------- no TLS here
@pytest.mark.parametrize("protocol,dialogue,reason", [
    ("starttls-pop3", pop3(stls=False), "STLS not offered"),
    ("starttls-pop3", pop3(capa=False, refuse=True), "STLS refused"),
    ("starttls-ftp", ftp(code=b"530"), "AUTH TLS refused (530)"),
    ("starttls-ftp", ftp(code=b"502", multiline=False), "AUTH TLS refused (502)"),
    ("starttls-xmpp", xmpp(offer=False), "XMPP STARTTLS not offered"),
    ("starttls-xmpp", xmpp(failure=True), "XMPP STARTTLS refused"),
])
def test_a_refusal_is_no_tls_here(protocol, dialogue, reason):
    srv = Server(dialogue)
    try:
        with T.starttls_name("chat.bank.example"):
            with pytest.raises(T.StarttlsUnavailable) as exc:
                T.open_tls_socket("127.0.0.1", srv.port, protocol, 5)
            assert str(exc.value) == reason
            fh = T.python_handshake("127.0.0.1", srv.port, protocol, None)
            assert not fh.ok and fh.error == reason
    finally:
        srv.close()


@pytest.mark.parametrize("protocol,greeting", [
    ("starttls-pop3", b"220 smtp.bank.example ESMTP\r\n"),   # an SMTP server on the POP3 port
    ("starttls-ftp", b"+OK POP3 ready\r\n"),                 # a POP3 server on the FTP port
    ("starttls-xmpp", b"HTTP/1.1 400 Bad Request\r\n\r\n"),  # a web server on the XMPP port
])
def test_another_service_on_the_port_is_a_probe_error(protocol, greeting):
    def wrong(conn, _srv):
        conn.sendall(greeting)
        time.sleep(0.3)
        return False

    srv = Server(wrong)
    try:
        with pytest.raises(T.ProbeError):
            T.open_tls_socket("127.0.0.1", srv.port, protocol, 3)
    finally:
        srv.close()


def test_an_xmpp_stream_error_is_a_probe_error_that_names_the_domain_never_plaintext():
    srv = Server(xmpp(domain="other.example"))  # host-unknown says nothing about TLS on the right domain
    try:
        with T.starttls_name("chat.bank.example"), pytest.raises(T.ProbeError) as exc:
            T.open_tls_socket("127.0.0.1", srv.port, "starttls-xmpp", 5)
        assert not isinstance(exc.value, T.StarttlsUnavailable)
        assert exc.value.detail.startswith("XMPP stream error host-unknown for chat.bank.example: add the server's")
    finally:
        srv.close()


def test_hostile_xmpp_domains_are_never_sent():
    srv = Server(xmpp())
    try:
        with T.starttls_name("x' onload='y"), pytest.raises(T.ProbeError, match="no usable XMPP domain"):
            T.open_tls_socket("127.0.0.1", srv.port, "starttls-xmpp", 3)
    finally:
        srv.close()


# --------------------------------------------------------------------------------------- the scan wires them
def test_the_network_collector_probes_the_new_protocols_and_names_the_xmpp_domain(monkeypatch):
    from zs_scan_node.collectors import network as N

    for proto in ("starttls-pop3", "starttls-ftp", "starttls-xmpp", "starttls-xmpp-server"):
        assert proto in N.TCP_PROTOCOLS and proto in N.TLS_LIKE and proto in T.PREAMBLES and proto in T.S_CLIENT_STARTTLS
    seen = {}
    scan = N.NetworkScan.__new__(N.NetworkScan)
    monkeypatch.setattr(N.NetworkScan, "sni_names_for", lambda self, ip: ["chat.bank.example", "alt.example"])
    monkeypatch.setattr(N.NetworkScan, "_tls_endpoint",
                        lambda self, ep, mode, names: seen.setdefault(ep.protocol, (T.XMPP_DOMAIN.get(), names)) and ("ok", None, 0))
    scan._tls(N.Endpoint("10.0.0.5", 5222, "starttls-xmpp", "XMPP"), "normal")
    scan._tls(N.Endpoint("10.0.0.5", 110, "starttls-pop3", "POP3"), "normal")
    assert seen["starttls-xmpp"][0] == "chat.bank.example" and seen["starttls-pop3"][0] is None
    assert T.XMPP_DOMAIN.get() is None  # reset after the endpoint


# --------------------------------------------------------------------------------------- end to end: the real scan
def _scan(protocol, dialogue, monkeypatch, names=(), *, openssl=True):
    from zs_scan_node import netutil
    from zs_scan_node.collectors import network as N
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    if not openssl:
        monkeypatch.setattr(T, "have_openssl", lambda: False)
    monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: ["127.0.0.1"] if name in names else [])
    srv = Server(dialogue)
    try:
        ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                         scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 120)
        scan = N.NetworkScan(ctx, {"sni_hostnames": list(names), "rate_limits": {
            "connections_per_second": 500, "parallel_per_server": 4, "handshakes_per_endpoint": 40}})
        result = scan.scan_endpoint(N.Endpoint("127.0.0.1", srv.port, protocol, protocol), "normal")
        ctx.flush()
        return result, ctx.collected, srv
    finally:
        srv.close()


def _rows(rows, kind):
    return [r for r in rows if r["type"] == kind]


@pytest.mark.parametrize("openssl", [True, False], ids=["openssl", "python-ssl"])
@pytest.mark.parametrize("protocol,dialogue,names", [
    ("starttls-pop3", pop3(), ()),
    ("starttls-ftp", ftp(), ()),
    ("starttls-xmpp", xmpp(), ("chat.bank.example",)),
    ("starttls-xmpp-server", xmpp(ns=b"jabber:server"), ("chat.bank.example",)),
])
def test_the_scan_reads_tls_and_the_certificate_through_each_new_preamble(protocol, dialogue, names, openssl,
                                                                          monkeypatch):
    if openssl and not T.have_openssl():
        pytest.skip("needs the openssl binary (the node image has it)")
    (status, err, _), rows, srv = _scan(protocol, dialogue, monkeypatch, names, openssl=openssl)
    assert status == "ok", (status, err, rows)
    tls = _rows(rows, "tls_endpoint")
    assert len(tls) == 1 and tls[0]["facts"]["tls"] is True and tls[0]["facts"]["service"] == protocol, tls
    assert tls[0]["facts"]["handshake_tool"] == ("openssl" if openssl else "python-ssl"), tls[0]["facts"]
    assert [r["name"] for r in _rows(rows, "certificate")] == ["CN=mail.bank.example"]
    if protocol.startswith("starttls-xmpp"):  # every stream named the endpoint's domain, never the address
        assert srv.seen and all(b"to='chat.bank.example'" in h for h in srv.seen if h.startswith(b"<?xml"))


@pytest.mark.parametrize("protocol,dialogue,names,detail", [
    ("starttls-pop3", pop3(stls=False), (), "STLS not offered"),
    ("starttls-ftp", ftp(code=b"530"), (), "AUTH TLS refused (530)"),
    ("starttls-xmpp", xmpp(offer=False), ("chat.bank.example",), "XMPP STARTTLS not offered"),
])
def test_a_service_without_starttls_is_reported_plaintext_only(protocol, dialogue, names, detail, monkeypatch):
    (status, err, _), rows, _srv = _scan(protocol, dialogue, monkeypatch, names)
    assert status == "ok", (status, err, rows)
    tls = _rows(rows, "tls_endpoint")
    assert len(tls) == 1 and tls[0]["facts"]["tls"] is False and tls[0]["facts"]["plaintext_only"] is True
    assert tls[0]["facts"]["detail"] == detail


def test_an_xmpp_server_that_does_not_serve_the_name_is_an_error_never_plaintext_only(monkeypatch):
    (status, err, _), rows, _srv = _scan("starttls-xmpp", xmpp(domain="chat.bank.example"), monkeypatch, ())
    assert status == "error" and err.startswith("XMPP stream error host-unknown for 127.0.0.1"), (status, err)
    assert not [r for r in _rows(rows, "tls_endpoint") if r["facts"].get("plaintext_only")], rows
