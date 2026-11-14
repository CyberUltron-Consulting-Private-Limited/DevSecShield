"""CB-34 legacy TLS: servers that still accept SSLv3, TLS 1.0 / 1.1 and RC4, 3DES, NULL, EXPORT and anonymous suites.

Two kinds of local server:

* **openssl s_server** (the local OpenSSL 3, at ``@SECLEVEL=0``) for what it can still serve: TLS 1.0 only, TLS 1.1
  only, anonymous DH only;
* **an emulated legacy server** (:class:`LegacyServer`) for what OpenSSL 3 no longer builds: SSLv3, RC4, EXPORT,
  NULL and 3DES. It reads the node's ClientHello and answers the way RFC 5246 / RFC 6101 servers do: the highest
  version it has at or below the client's, its first preferred suite the client offers, then ServerHello,
  Certificate (a real certificate made here), ServerKeyExchange for DH suites, ServerHelloDone; ``protocol_version``
  or ``handshake_failure`` alerts when there is no match. Those are the bytes a legacy server sends in the clear,
  and all the node reads of them. It never finishes a handshake, like a real legacy server facing a modern client
  (OpenSSL 3 and Python ``ssl`` fail against it, which is the case CB-34 fixes: the certificate is read from the
  raw flight).

The scan is the real ``NetworkScan.scan_endpoint``; the assertions read the emitted rows.
"""
from __future__ import annotations

import datetime as dt
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

_DIR = Path(tempfile.mkdtemp(prefix="zs-legacy-tls-"))
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.lab")])
_NOW = dt.datetime.now(dt.timezone.utc)
CERT = (x509.CertificateBuilder().subject_name(_NAME).issuer_name(_NAME).public_key(_KEY.public_key())
        .serial_number(3402).not_valid_before(_NOW - dt.timedelta(days=1)).not_valid_after(_NOW + dt.timedelta(days=30))
        .sign(_KEY, hashes.SHA256()))
DER = CERT.public_bytes(serialization.Encoding.DER)
(_DIR / "c.pem").write_bytes(CERT.public_bytes(serialization.Encoding.PEM))
(_DIR / "k.pem").write_bytes(_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
# a 2048-bit MODP prime (RFC 3526 group 14) for the DH suites' ServerKeyExchange
P2048 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
            "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411"
            "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5"
            "29077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)


class LegacyServer:
    """Answers ClientHellos as a legacy TLS server would (see the module docstring)."""

    def __init__(self, versions: set[int], suites: list[int]) -> None:
        self.versions, self.suites = versions, suites
        self.hellos: list[tuple[int, list[int]]] = []
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(32)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self) -> None:
        self.srv.close()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    @staticmethod
    def _read(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def _one(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            head = self._read(conn, 5)
            if head[0] != 22:
                return
            body = self._read(conn, struct.unpack("!H", head[3:5])[0])
            client_version = struct.unpack("!H", body[4:6])[0]
            i = 6 + 32
            i += 1 + body[i]
            n = struct.unpack("!H", body[i:i + 2])[0]
            offered = [struct.unpack("!H", body[i + 2 + k:i + 4 + k])[0] for k in range(0, n, 2)]
            self.hellos.append((client_version, offered))
            fit = [v for v in self.versions if v <= client_version]
            if not fit:
                conn.sendall(self._record(21, 0x0301, b"\x02\x46"))  # fatal protocol_version
                return
            version = max(fit)
            suite = next((s for s in self.suites if s in offered), None)
            if suite is None:
                conn.sendall(self._record(21, version, b"\x02\x28"))  # fatal handshake_failure
                return
            name = T.CIPHERS.get(suite, "")
            msgs = self._msg(2, struct.pack("!H", version) + os.urandom(32) + b"\x00" + struct.pack("!H", suite) + b"\x00")
            if "anon" not in name:
                entry = len(DER).to_bytes(3, "big") + DER
                msgs += self._msg(11, len(entry).to_bytes(3, "big") + entry)
            if "DH" in name and "ECDH" not in name:
                p = P2048.to_bytes(256, "big")
                ske = struct.pack("!H", len(p)) + p + b"\x00\x01\x02" + struct.pack("!H", 256) + os.urandom(256)
                if "anon" not in name:
                    ske += struct.pack("!H", 256) + os.urandom(256)  # a signature the node never checks
                msgs += self._msg(12, ske)
            msgs += self._msg(14, b"")
            conn.sendall(self._record(22, version, msgs))
            conn.recv(4096)  # a real server would now wait for the ClientKeyExchange
        except OSError:
            pass
        finally:
            conn.close()

    @staticmethod
    def _msg(mtype: int, body: bytes) -> bytes:
        return bytes([mtype]) + len(body).to_bytes(3, "big") + body

    @staticmethod
    def _record(rtype: int, version: int, payload: bytes) -> bytes:
        return bytes([rtype]) + struct.pack("!HH", version, len(payload)) + payload


def _scan(port: int, monkeypatch, *, openssl: bool = True):
    if not openssl:
        monkeypatch.setattr(T, "have_openssl", lambda: False)
    monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: [])
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 120)
    scan = N.NetworkScan(ctx, {"sni_hostnames": [], "rate_limits": {
        "connections_per_second": 500, "parallel_per_server": 4, "handshakes_per_endpoint": 120}})
    result = scan.scan_endpoint(N.Endpoint("127.0.0.1", port, "tls", "https"), "full")
    ctx.flush()
    rows = ctx.collected
    tls = [r for r in rows if r["type"] == "tls_endpoint"]
    certs = [r for r in rows if r["type"] == "certificate"]
    return result, (tls[0]["facts"] if tls else {}), certs


SSL3, TLS10, TLS11, TLS12 = T.SSL3, T.TLS10, T.TLS11, T.TLS12


# ----------------------------------------------------------------------------- the raw flight
def test_the_certificate_message_is_parsed_from_the_flight():
    entry = len(DER).to_bytes(3, "big") + DER
    assert T.parse_certificate_list(len(entry).to_bytes(3, "big") + entry) == [DER]
    for bad in (b"\x00", b"\x00\x00\x05\x00\x00\x09ab", (len(entry) + 1).to_bytes(3, "big") + entry):
        with pytest.raises(ValueError):
            T.parse_certificate_list(bad)


@pytest.mark.parametrize("version,suite", [
    (SSL3, 0x0004),    # SSLv3 with RC4-MD5
    (TLS10, 0x0003),   # TLS 1.0 with EXPORT RC4-40
    (TLS12, 0x0002),   # TLS 1.2 with NULL-SHA
    (TLS10, 0x000A),   # TLS 1.0 with 3DES
])
def test_a_probe_reads_the_legacy_servers_certificate(version, suite):
    srv = LegacyServer({version}, [suite])
    try:
        r = T.probe("127.0.0.1", srv.port, "tls", T.build_client_hello(version, T.LEGACY_SUITES), want_cert=True)
        assert r.ok and r.version == version and r.cipher == suite and r.certs_der == [DER]
        plain = T.probe("127.0.0.1", srv.port, "tls", T.build_client_hello(version, T.LEGACY_SUITES))
        assert plain.ok and plain.certs_der == []  # without want_cert the flight stops at the ServerHello
    finally:
        srv.close()


# ----------------------------------------------------------------------------- the scan, end to end
@pytest.mark.parametrize("openssl", [True, False], ids=["openssl", "python-ssl"])
# openssl_reads: OpenSSL 3 at @SECLEVEL=0 still negotiates NULL-SHA, so s_client reads that one itself
@pytest.mark.parametrize("versions,suites,version_name,weak,openssl_reads", [
    ({SSL3}, [0x0004, 0x0005], "SSLv3", "TLS_RSA_WITH_RC4_128_MD5", False),
    ({SSL3, TLS10}, [0x0003, 0x0008], "TLSv1.0", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", False),
    ({TLS12}, [0x0002, 0x0001], "TLSv1.2", "TLS_RSA_WITH_NULL_SHA", True),
    ({TLS10, TLS11}, [0x000A], "TLSv1.1", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", False),
])
def test_a_legacy_only_server_is_reported_with_its_certificate(versions, suites, version_name, weak, openssl_reads,
                                                               openssl, monkeypatch):
    if openssl and not T.have_openssl():
        pytest.skip("needs the openssl binary (the node image has it)")
    srv = LegacyServer(versions, suites)
    try:
        (status, err, _), facts, certs = _scan(srv.port, monkeypatch, openssl=openssl)
    finally:
        srv.close()
    assert status == "ok", (status, err)
    assert {k for k, v in facts["versions"].items() if v} == {T.VERSION_NAMES[v] for v in versions}
    if openssl and openssl_reads:
        assert facts["handshake_tool"] == "openssl" and "certificate_source" not in facts
    else:
        assert facts["certificate_source"] == "raw_flight" and facts["handshake_tool"] == "raw-flight"
        assert facts["full_handshake_error"]  # the modern client's attempt failed, and the facts say so
    assert facts["negotiated_version"] == version_name
    assert [c["name"] for c in certs] == ["CN=legacy.lab"] and facts["leaf"]["subject"] == "CN=legacy.lab"
    assert certs[0]["facts"]["fingerprint_sha256"]
    assert weak in facts["weak_ciphers_accepted"]["obsolete"]
    assert set(facts["ciphers"]) >= {T.CIPHERS[s] for s in suites}


def test_an_anonymous_only_server_has_no_certificate_to_read(monkeypatch):
    srv = LegacyServer({TLS12}, [0x0034])  # TLS_DH_anon_WITH_AES_128_CBC_SHA
    try:
        (status, err, _), facts, certs = _scan(srv.port, monkeypatch)
    finally:
        srv.close()
    assert status == "ok", (status, err)
    assert certs == [] and facts["chain_length"] == 0
    assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" in facts["weak_ciphers_accepted"]["obsolete"]


def test_a_modern_server_is_read_by_the_full_handshake_as_before(monkeypatch):
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(_DIR / "c.pem", _DIR / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(3)
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass
    threading.Thread(target=loop, daemon=True).start()
    try:
        (status, err, _), facts, certs = _scan(port, monkeypatch)
    finally:
        srv.close()
    assert status == "ok", (status, err)
    assert "certificate_source" not in facts and facts["handshake_tool"] in ("openssl", "python-ssl")
    assert [c["name"] for c in certs] == ["CN=legacy.lab"]
    assert not facts["versions"]["SSLv3"] and not facts["versions"]["TLSv1.0"]


# ----------------------------------------------------------------------------- real OpenSSL servers
def _s_server(*args: str):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    proc = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(_DIR / "c.pem"),
                             "-key", str(_DIR / "k.pem"), "-quiet", *args],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "OPENSSL_CONF": "/dev/null"})
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    pytest.skip("openssl s_server did not start")


needs_openssl = pytest.mark.skipif(not T.have_openssl(), reason="needs the openssl binary")


@needs_openssl
@pytest.mark.parametrize("flag,name", [("-tls1", "TLSv1.0"), ("-tls1_1", "TLSv1.1")])
def test_an_openssl_server_on_tls_1_0_or_1_1_only(flag, name, monkeypatch):
    proc, port = _s_server(flag, "-cipher", "ALL:@SECLEVEL=0")
    try:
        (status, err, _), facts, certs = _scan(port, monkeypatch)
    finally:
        proc.kill()
    assert status == "ok", (status, err)
    assert {k for k, v in facts["versions"].items() if v} == {name}
    assert [c["name"] for c in certs] == ["CN=legacy.lab"]


@needs_openssl
def test_an_openssl_server_with_anonymous_suites_only(monkeypatch):
    proc, port = _s_server("-tls1_2", "-cipher", "aNULL:@SECLEVEL=0", "-nocert")
    try:
        (status, err, _), facts, _certs = _scan(port, monkeypatch)
    finally:
        proc.kill()
    assert status == "ok", (status, err)
    anon = [c for c in facts["weak_ciphers_accepted"]["obsolete"] if "anon" in c]
    assert anon, facts["weak_ciphers_accepted"]
