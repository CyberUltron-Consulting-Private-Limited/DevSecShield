"""CB-13: the SSH host-key reader (``sshprobe``) against an in-process stub server.

The stub speaks only the unencrypted start of SSH-2 (RFC 4253 section 7): banner, KEXINIT, the client's key-exchange
init message, and the server's reply carrying ``K_S``.  It checks what the client sends against the sizes the
specifications fix (RFC 10042 hybrid ML-KEM, RFC 8731 curve25519, RFC 5656 ECDH, RFC 4253/8268 DH, RFC 4419 GEX,
draft-harrison pure ML-KEM, OpenSSH sntrup761x25519), and answers with host keys / certificates built by
``cryptography`` (never by the code under test).  KF-6 (PQ-only host key unread) and KF-17 (one host key of several)
are the DA rows these tests pin.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import socket
import struct
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

from zs_scan_node import sshprobe as S

Q = 3329  # FIPS 203 modulus


# ----------------------------------------------------------------------------- wire helpers (test-local)
def _str(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _names(names) -> bytes:
    return _str(",".join(names).encode())


def _packet(payload: bytes) -> bytes:
    pad = 8 - ((5 + len(payload)) % 8)
    pad = pad + 8 if pad < 4 else pad
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def _read_packet(sock) -> bytes:
    plen, pad = struct.unpack("!IB", _recv_exact(sock, 5))
    body = _recv_exact(sock, plen - 1)
    return body[: plen - 1 - pad]


def _parse_names(payload: bytes, pos: int):
    n = struct.unpack("!I", payload[pos:pos + 4])[0]
    return payload[pos + 4:pos + 4 + n].decode().split(",") if n else [], pos + 4 + n


def _openssh_blob(public_key) -> bytes:
    line = public_key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return base64.b64decode(line.split()[1])


def _fp(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


ED = ed25519.Ed25519PrivateKey.generate()
RSA1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
EC256 = ec.generate_private_key(ec.SECP256R1())
EC384 = ec.generate_private_key(ec.SECP384R1())
DSA1024 = dsa.generate_private_key(key_size=1024)
BLOBS = {"ssh-ed25519": _openssh_blob(ED.public_key()), "ssh-rsa": _openssh_blob(RSA1024.public_key()),
         "ecdsa-sha2-nistp256": _openssh_blob(EC256.public_key()),
         "ecdsa-sha2-nistp384": _openssh_blob(EC384.public_key()), "ssh-dss": _openssh_blob(DSA1024.public_key())}

C_INIT = {  # bytes of the client's share, by key exchange (the specifications' sizes)
    "mlkem768x25519-sha256": 1184 + 32, "mlkem768nistp256-sha256": 1184 + 65, "mlkem1024nistp384-sha384": 1568 + 97,
    "sntrup761x25519-sha512": 1158 + 32, "sntrup761x25519-sha512@openssh.com": 1158 + 32,
    "mlkem512-sha256": 800, "mlkem768-sha256": 1184, "mlkem1024-sha384": 1568,
    "curve25519-sha256": 32, "curve25519-sha256@libssh.org": 32, "curve448-sha512": 56,
    "ecdh-sha2-nistp256": 65, "ecdh-sha2-nistp384": 97, "ecdh-sha2-nistp521": 133,
}
MLKEM_EK = {"mlkem768x25519-sha256": 1184, "mlkem768nistp256-sha256": 1184, "mlkem1024nistp384-sha384": 1568,
            "mlkem512-sha256": 800, "mlkem768-sha256": 1184, "mlkem1024-sha384": 1568}
DH_BITS = {"diffie-hellman-group1-sha1": 1024, "diffie-hellman-group14-sha1": 2048,
           "diffie-hellman-group14-sha256": 2048, "diffie-hellman-group16-sha512": 4096,
           "diffie-hellman-group18-sha512": 8192}


def _ek_valid(ek: bytes) -> bool:
    """FIPS 203 section 7.2 encapsulation-key check: every 12-bit coefficient of t-hat is below q."""
    body = ek[:-32]
    for i in range(0, len(body), 3):
        b0, b1, b2 = body[i], body[i + 1], body[i + 2]
        if (b0 | ((b1 & 0x0F) << 8)) >= Q or ((b1 >> 4) | (b2 << 4)) >= Q:
            return False
    return True


class Stub:
    """One SSH server endpoint on 127.0.0.1; every accepted connection is recorded in ``self.seen``."""

    def __init__(self, kex, hostkeys, blobs=None, refuse=None, gex_bits=2048, ciphers=("aes128-ctr",),
                 macs=("hmac-sha2-256",), pre_banner=()):
        self.kex, self.hostkeys, self.blobs = list(kex), list(hostkeys), dict(blobs or BLOBS)
        self.refuse, self.gex_bits, self.ciphers, self.macs, self.pre_banner = refuse, gex_bits, ciphers, macs, pre_banner
        self.seen: list[dict] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _family_blob(self, alg: str) -> bytes:
        if alg in self.blobs:
            return self.blobs[alg]
        if alg in ("rsa-sha2-256", "rsa-sha2-512"):
            return self.blobs["ssh-rsa"]
        if alg in ("rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com"):
            return self.blobs["ssh-rsa-cert-v01@openssh.com"]
        raise KeyError(alg)

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        rec: dict = {}
        self.seen.append(rec)
        try:
            conn.settimeout(5)
            if self.refuse is not None:
                conn.sendall(self.refuse)
                return
            for line in self.pre_banner:
                conn.sendall(line)
            conn.sendall(b"SSH-2.0-StubSSH_1.0\r\n")
            kexinit = (b"\x14" + os.urandom(16) + _names(self.kex) + _names(self.hostkeys) + _names(self.ciphers) * 2
                       + _names(self.macs) * 2 + _names(["none"]) * 2 + _names([]) * 2 + b"\x00" + b"\x00" * 4)
            conn.sendall(_packet(kexinit))
            banner = b""
            while not banner.endswith(b"\n"):
                banner += conn.recv(1)
            rec["client_banner"] = banner
            ck = _read_packet(conn)
            assert ck[0] == 20
            pos = 17
            lists = []
            for _ in range(10):
                names, pos = _parse_names(ck, pos)
                lists.append(names)
            rec["client_kex"], rec["client_hostkeys"] = lists[0], lists[1]
            kex = next(k for k in lists[0] if k in self.kex)
            alg = next(h for h in lists[1] if h in self.hostkeys)
            rec["kex"], rec["hostkey"] = kex, alg
            blob = self._family_blob(alg)
            sig = _str(_str(alg.replace("-cert-v01@openssh.com", "").encode()) + _str(os.urandom(64)))
            if kex.startswith("rsa"):  # RFC 4432: the host key comes first, before the client sends anything
                conn.sendall(_packet(b"\x1e" + _str(blob) + _str(_openssh_blob(RSA1024.public_key()))))
                rec["init"] = _read_packet(conn)
                return
            if kex.startswith("diffie-hellman-group-exchange"):
                req = _read_packet(conn)
                assert req[0] == 34, req[0]
                rec["gex_request"] = struct.unpack("!III", req[1:13])
                p = (1 << (self.gex_bits - 1)) | (1 << 64) | 0xFFFFFFFFFFFFFFC5  # an odd modulus of the right size
                conn.sendall(_packet(b"\x1f" + _str(p.to_bytes(self.gex_bits // 8 + 1, "big")) + _str(b"\x02")))
                init = _read_packet(conn)
                assert init[0] == 32, init[0]
            else:
                init = _read_packet(conn)
                assert init[0] == 30, init[0]
            n = struct.unpack("!I", init[1:5])[0]
            share = init[5:5 + n]
            rec["init_type"], rec["share"] = init[0], share
            if kex in C_INIT:
                assert len(share) == C_INIT[kex], (kex, len(share))
            if kex in MLKEM_EK:
                rec["ek_valid"] = _ek_valid(share[:MLKEM_EK[kex]])
            if kex in DH_BITS:
                e = int.from_bytes(share, "big")
                rec["dh_e_ok"] = 1 < e < (1 << (DH_BITS[kex] - 1))
            if kex.startswith("ecdh-sha2-"):
                curve = {"ecdh-sha2-nistp256": ec.SECP256R1(), "ecdh-sha2-nistp384": ec.SECP384R1(),
                         "ecdh-sha2-nistp521": ec.SECP521R1()}[kex]
                ec.EllipticCurvePublicKey.from_encoded_point(curve, share)  # raises if not on the curve
                rec["ec_point_ok"] = True
            reply_type = b"\x21" if kex.startswith("diffie-hellman-group-exchange") else b"\x1f"
            server_share = os.urandom(32 if kex.startswith("curve25519") else 64)
            conn.sendall(_packet(reply_type + _str(blob) + _str(server_share) + sig))
            try:
                rec["after"] = _read_packet(conn)[0]  # the client's DISCONNECT
            except (EOFError, OSError):
                rec["after"] = None
        except (AssertionError, KeyError, StopIteration, EOFError, OSError, ValueError) as exc:
            rec["error"] = repr(exc)
        finally:
            conn.close()

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=3)

    def settled(self, timeout=3.0):
        """Every connection's handler has finished (the client may close before the stub has read its last bytes)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end and not all("after" in r or "error" in r or "init" in r for r in self.seen):
            time.sleep(0.01)
        return self.seen

    def close(self):
        self.sock.close()


def _read_all(stub, max_connections=8):
    used = []

    def open_conn():
        if len(used) >= max_connections:
            raise S.Stop("budget")
        used.append(1)
        return stub.connect()

    return S.read_server(open_conn, time.monotonic() + 30), len(used)


# ----------------------------------------------------------------------------- KF-6: PQ-only key exchange
@pytest.mark.parametrize("kex", ["mlkem768x25519-sha256", "sntrup761x25519-sha512",
                                 "sntrup761x25519-sha512@openssh.com", "mlkem768nistp256-sha256",
                                 "mlkem1024nistp384-sha384", "mlkem512-sha256", "mlkem768-sha256",
                                 "mlkem1024-sha384"])
def test_pq_only_server_host_key_is_read(kex):
    stub = Stub([kex], ["ssh-ed25519"])
    try:
        got, conns = _read_all(stub)
    finally:
        stub.close()
    rec = stub.seen[0]
    assert "error" not in rec, rec
    assert rec["kex"] == kex and len(rec["share"]) == C_INIT[kex]
    if kex in MLKEM_EK:
        assert rec["ek_valid"] is True  # the server's FIPS 203 modulus check passes
    assert got["host_keys_status"] == "complete" and conns == 1
    [key] = got["host_keys"]
    assert (key["type"], key["bits"], key["fingerprint"]) == ("ssh-ed25519", 256, _fp(BLOBS["ssh-ed25519"]))
    assert key["fingerprint_sha256"] == hashlib.sha256(BLOBS["ssh-ed25519"]).hexdigest()
    assert key["kex_used"] == kex and key["read_by"] == "kex_reply"
    assert got["kex"] == [kex]


@pytest.mark.parametrize("kex", ["curve25519-sha256", "curve25519-sha256@libssh.org", "curve448-sha512",
                                 "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                                 "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                                 "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
                                 "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256",
                                 "diffie-hellman-group-exchange-sha1", "rsa1024-sha1", "rsa2048-sha256"])
def test_classical_key_exchanges_read_the_host_key(kex):
    stub = Stub([kex], ["ecdsa-sha2-nistp256"])
    try:
        got, _ = _read_all(stub)
    finally:
        stub.close()
    rec = stub.seen[0]
    assert "error" not in rec, rec
    if kex in DH_BITS:
        assert rec["dh_e_ok"] is True
    if kex.startswith("ecdh"):
        assert rec["ec_point_ok"] is True
    [key] = got["host_keys"]
    assert (key["type"], key["bits"], key["curve"]) == ("ecdsa-sha2-nistp256", 256, "nistp256")
    if kex.startswith("diffie-hellman-group-exchange"):
        assert rec["gex_request"][0] <= 2048 <= rec["gex_request"][2]
        assert got["gex_modulus_bits"] == 2048


def test_classical_exchange_is_preferred_and_pq_only_when_nothing_else():
    assert S.choose_kex(["mlkem768x25519-sha256", "curve25519-sha256", "ext-info-s"]) == "curve25519-sha256"
    assert S.choose_kex(["sntrup761x25519-sha512@openssh.com", "kex-strict-s-v00@openssh.com"]) == \
        "sntrup761x25519-sha512@openssh.com"
    assert S.choose_kex(["gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==", "ext-info-s"]) is None


# ----------------------------------------------------------------------------- KF-17: every host-key family
def test_every_offered_host_key_family_is_read_one_connection_each():
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256",
                                        "ssh-rsa", "ssh-dss"])
    try:
        got, conns = _read_all(stub)
    finally:
        stub.close()
    assert conns == 4  # ed25519, ecdsa, the RSA family (three algorithms, one key), dss
    keys = {k["type"]: k for k in got["host_keys"]}
    assert set(keys) == {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", "ssh-dss"}
    assert keys["ssh-rsa"]["bits"] == 1024 and keys["ssh-dss"]["bits"] == 1024
    assert keys["ssh-rsa"]["algorithms"] == ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
    assert keys["ssh-rsa"]["signature_algorithm"] == "rsa-sha2-512"  # the server signed with what was offered first
    for t, k in keys.items():
        assert k["fingerprint"] == _fp(BLOBS[t])
    # the RSA family offered exactly the server's RSA algorithms, nothing else
    rsa_conn = next(r for r in stub.seen if r.get("hostkey", "").startswith("rsa-sha2"))
    assert rsa_conn["client_hostkeys"] == ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
    assert got["host_keys_status"] == "complete" and got["host_key"]["key_type"] == "ssh-ed25519"
    assert all(r.get("after") == 1 for r in stub.settled())  # every exchange ends with SSH_MSG_DISCONNECT


def test_primary_host_key_keeps_the_order_paramiko_preferred():
    """``host_key`` (the endpoint's algorithm and size, compared by drift) must stay the key dev reported."""
    stub = Stub(["curve25519-sha256"], ["rsa-sha2-512", "ecdsa-sha2-nistp384", "ssh-ed25519"])
    try:
        got, _ = _read_all(stub)
    finally:
        stub.close()
    assert got["host_key"] == {"key_type": "ssh-ed25519", "bits": 256,
                               "fingerprint_sha256": hashlib.sha256(BLOBS["ssh-ed25519"]).hexdigest()}
    assert [k["type"] for k in got["host_keys"]] == ["ssh-rsa", "ecdsa-sha2-nistp384", "ssh-ed25519"]


def test_connection_budget_leaves_the_rest_listed_as_unread():
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"])
    try:
        got, conns = _read_all(stub, max_connections=2)
    finally:
        stub.close()
    assert conns == 2 and got["host_keys_status"] == "partial"
    assert [k["type"] for k in got["host_keys"]] == ["ssh-ed25519", "ecdsa-sha2-nistp256"]
    assert got["host_keys_unread"] == [{"algorithms": ["rsa-sha2-512"], "reason": "budget"}]


# ----------------------------------------------------------------------------- certificates
def _host_cert(key, ca, valid_after, valid_before, cert_type=serialization.SSHCertificateType.HOST):
    b = (serialization.SSHCertificateBuilder().public_key(key.public_key()).serial(42).type(cert_type)
         .key_id(b"web01-host").valid_principals([b"web01.example", b"10.0.0.5"])
         .valid_after(valid_after).valid_before(valid_before))
    cert = b.sign(ca)
    return base64.b64decode(cert.public_bytes().split()[1])


def test_host_certificates_are_read_with_their_ca_and_validity():
    ca = ed25519.Ed25519PrivateKey.generate()
    now = int(time.time())
    blobs = dict(BLOBS)
    blobs["ssh-ed25519-cert-v01@openssh.com"] = _host_cert(ED, ca, now - 86400, now + 30 * 86400)
    blobs["ssh-rsa-cert-v01@openssh.com"] = _host_cert(RSA1024, ca, 1577836800, 1609459200)  # 2020 only
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com",
                                        "ssh-ed25519", "rsa-sha2-512"], blobs=blobs)
    try:
        got, conns = _read_all(stub)
    finally:
        stub.close()
    assert conns == 4
    certs = [k for k in got["host_keys"] if k.get("certificate")]
    assert [c["type"] for c in certs] == ["ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"]
    ed_cert, rsa_cert = (c["certificate"] for c in certs)
    ca_blob = _openssh_blob(ca.public_key())
    assert ed_cert["ca"] == {"type": "ssh-ed25519", "bits": 256, "fingerprint": _fp(ca_blob),
                             "fingerprint_sha256": hashlib.sha256(ca_blob).hexdigest()}
    assert ed_cert["cert_type"] == "host" and ed_cert["key_id"] == "web01-host" and ed_cert["serial"] == 42
    assert ed_cert["principals"] == ["web01.example", "10.0.0.5"]
    assert ed_cert["valid_after"] == dt.datetime.fromtimestamp(now - 86400, dt.timezone.utc).isoformat()
    assert ed_cert["signature_algorithm"] == "ssh-ed25519"
    assert rsa_cert["valid_before"] == "2021-01-01T00:00:00+00:00"
    assert certs[1]["bits"] == 1024 and certs[1]["key_type"] == "ssh-rsa"  # the certified key
    assert certs[0]["fingerprint"] == _fp(blobs["ssh-ed25519-cert-v01@openssh.com"])


def test_certificate_valid_forever_and_unknown_host_key_types():
    ca = ed25519.Ed25519PrivateKey.generate()
    blob = _host_cert(ED, ca, 0, 2 ** 64 - 1)
    facts = S.parse_host_key(blob)
    assert facts["certificate"]["valid_before"] == "forever" and facts["certificate"]["valid_after"] == \
        "1970-01-01T00:00:00+00:00"
    pq = _str(b"ssh-mldsa-65") + _str(os.urandom(1952))
    facts = S.parse_host_key(pq)
    assert facts["type"] == "ssh-mldsa-65" and facts["bits"] is None and facts["fingerprint"] == _fp(pq)
    for bad in (b"", b"\x00\x00\x00\x07ssh-rsa", b"\xff\xff\xff\xff"):
        assert S.parse_host_key(bad)["type"] in ("unknown", "ssh-rsa")  # never raises on a hostile blob


def test_families_group_algorithms_that_use_the_same_key():
    assert S.families(["rsa-sha2-512", "ssh-ed25519", "rsa-sha2-256", "ssh-rsa", "ecdsa-sha2-nistp256",
                       "rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com", "ssh-mldsa-65"]) == [
        ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"], ["ssh-ed25519"], ["ecdsa-sha2-nistp256"],
        ["rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"], ["ssh-mldsa-65"]]


# ----------------------------------------------------------------------------- what cannot be read
def test_no_key_exchange_the_reader_speaks_is_kex_unsupported_with_the_list():
    stub = Stub(["gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==", "ext-info-s"], ["ssh-ed25519"])
    try:
        got, conns = _read_all(stub)
    finally:
        stub.close()
    assert conns == 1 and got["host_keys"] == [] and got["host_keys_status"] == "kex_unsupported"
    assert got["host_keys_unread"] == [{"algorithms": ["ssh-ed25519"], "reason": "kex_unsupported"}]
    assert got["kex"] == ["gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==", "ext-info-s"]


def test_a_server_that_refuses_before_the_banner_stops_every_later_connection():
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519"], refuse=b"Not allowed at this time\r\n")
    try:
        with pytest.raises(S.ServerRefused) as raised:
            _read_all(stub)
    finally:
        stub.close()
    assert "Not allowed at this time" in str(raised.value)


def test_a_refusal_after_the_first_family_ends_the_reads_as_server_refused():
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"])
    calls = []

    def open_conn():
        calls.append(1)
        if len(calls) == 2:
            stub.refuse = b"Not allowed at this time\r\n"
        return stub.connect()

    try:
        got = S.read_server(open_conn, time.monotonic() + 30)
    finally:
        stub.close()
    assert len(calls) == 2  # no third connection after the refusal
    assert got["host_keys_status"] == "server_refused" and [k["type"] for k in got["host_keys"]] == ["ssh-ed25519"]
    assert got["host_keys_unread"][0]["reason"].startswith("server_refused")


def test_pre_banner_lines_are_allowed_and_the_banner_is_kept():
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519"], pre_banner=(b"Welcome\r\n",))
    try:
        got, _ = _read_all(stub)
    finally:
        stub.close()
    assert got["banner"] == "SSH-2.0-StubSSH_1.0" and got["host_keys_status"] == "complete"


def test_kexinit_lists_are_complete_and_unchanged():
    stub = Stub(["diffie-hellman-group1-sha1", "mlkem768x25519-sha256", "ext-info-s"], ["ssh-ed25519"],
                ciphers=("3des-cbc", "aes128-ctr", "chacha20-poly1305@openssh.com"), macs=("hmac-md5", "hmac-sha1"))
    try:
        got, _ = _read_all(stub)
    finally:
        stub.close()
    assert got["kex"] == ["diffie-hellman-group1-sha1", "mlkem768x25519-sha256", "ext-info-s"]
    assert got["ciphers_c2s"] == got["ciphers_s2c"] == ["3des-cbc", "aes128-ctr", "chacha20-poly1305@openssh.com"]
    assert got["macs_c2s"] == ["hmac-md5", "hmac-sha1"] and got["host_key_algs"] == ["ssh-ed25519"]
    # the client offered the server's own cipher and MAC lists, so negotiation cannot fail there
    assert stub.seen[0]["client_kex"] == ["diffie-hellman-group1-sha1"]


# ----------------------------------------------------------------------------- the network collector (network._ssh)
def _net(monkeypatch, stubs: dict, spacing=0.0, max_conns=None, ports=(22,)):
    """run_network over the addresses in ``stubs`` (address -> Stub; every port of an address reaches its stub)."""
    from zs_scan_node.collectors import network as N
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    starts: list[tuple[str, float]] = []

    def tcp(ip, port, never, timeout):
        starts.append((ip, time.monotonic()))
        return stubs[ip].connect()

    monkeypatch.setattr(N, "_tcp", tcp)
    monkeypatch.setattr(N, "SSH_SPACING_S", spacing)
    if max_conns is not None:
        monkeypatch.setattr(N, "SSH_MAX_CONNECTIONS_PER_ADDRESS", max_conns)
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 60)
    scope = {"ranges": [{"cidr": f"{ip}/32", "mode": "full"} for ip in stubs],
             "ports": [{"port": p, "protocol": "ssh", "label": "ssh"} for p in ports],
             "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}}
    N.run_network(ctx, scope)
    ctx.flush()
    return ctx, starts


def test_network_endpoint_carries_every_host_key_and_keeps_the_primary(monkeypatch):
    stub = Stub(["curve25519-sha256"], ["rsa-sha2-512", "ssh-ed25519", "ecdsa-sha2-nistp256"])
    try:
        ctx, starts = _net(monkeypatch, {"192.0.2.10": stub})
    finally:
        stub.close()
    [ep] = [a for a in ctx.collected if a["type"] == "ssh_endpoint"]
    assert (ep["algorithm"], ep["key_size"]) == ("ssh-ed25519", 256)
    assert sorted((k["type"], k["bits"]) for k in ep["facts"]["host_keys"]) == [
        ("ecdsa-sha2-nistp256", 256), ("ssh-ed25519", 256), ("ssh-rsa", 1024)]
    assert ep["facts"]["host_keys_status"] == "complete"
    assert not [a for a in ctx.collected if a["type"] == "coverage"]
    assert len(starts) == 1 + 3  # the sweep's connect, then one connection per host-key family


def test_network_ssh_connections_to_one_address_are_paced(monkeypatch):
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"])
    try:
        _ctx, starts = _net(monkeypatch, {"192.0.2.10": stub}, spacing=0.25)
    finally:
        stub.close()
    ssh = [t for _ip, t in starts][1:]  # after the sweep
    gaps = [b - a for a, b in zip(ssh, ssh[1:])]
    assert len(ssh) == 3 and all(g >= 0.24 for g in gaps), gaps


def test_network_per_address_budget_spans_ports_and_leaves_a_scoped_coverage_row(monkeypatch):
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"])
    try:
        ctx, starts = _net(monkeypatch, {"192.0.2.10": stub}, max_conns=4, ports=(22, 2222))
    finally:
        stub.close()
    eps = {a["location"]: a for a in ctx.collected if a["type"] == "ssh_endpoint"}
    assert len(starts) == 2 + 4  # two sweep connects, then the address's 4 SSH connections, whatever the port
    read = sorted(len(e["facts"]["host_keys"]) for e in eps.values())
    assert sum(read) == 4 and read[0] < 3
    partial = {where for where, e in eps.items() if e["facts"]["host_keys_status"] == "partial"}
    cov = [a for a in ctx.collected if a["type"] == "coverage"]
    assert partial and len(cov) == len(partial)  # each partly read endpoint has its own row, scoped to it
    for row in cov:
        f = row["facts"]
        assert f["status"] == "truncated" and f["incomplete"] is True and "budget" in f["detail"]
        assert len(f["scope"]) == 1 and f["scope"][0] in partial


def test_network_kex_unsupported_keeps_the_lists_and_names_the_server_kex(monkeypatch):
    stub = Stub(["gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==", "ext-info-s"], ["ssh-ed25519"])
    try:
        ctx, _ = _net(monkeypatch, {"192.0.2.10": stub})
    finally:
        stub.close()
    [ep] = [a for a in ctx.collected if a["type"] == "ssh_endpoint"]
    assert ep["algorithm"] is None and ep["facts"]["kex"][0].startswith("gss-gex-sha1-")
    [cov] = [a for a in ctx.collected if a["type"] == "coverage"]
    assert cov["facts"]["status"] == "kex_unsupported" and "gss-gex-sha1-" in cov["facts"]["detail"]
    assert cov["facts"]["scope"] == ["192.0.2.10:22"] and cov["facts"]["incomplete"] is True


def test_network_refusal_stops_ssh_to_the_address(monkeypatch):
    stub = Stub(["curve25519-sha256"], ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"])
    from zs_scan_node.collectors import network as N

    real = []

    def refuse_after_first_ssh(*_a):
        real.append(1)
        if len(real) == 2:  # sweep connect, first SSH connection, then the server starts refusing
            stub.refuse = b"Not allowed at this time\r\n"

    try:
        orig_slot = N.NetworkScan._ssh_slot

        def slot(self, ip):
            orig_slot(self, ip)
            refuse_after_first_ssh()

        monkeypatch.setattr(N.NetworkScan, "_ssh_slot", slot)
        ctx, starts = _net(monkeypatch, {"192.0.2.10": stub}, ports=(22, 2222))
    finally:
        stub.close()
    eps = [a for a in ctx.collected if a["type"] == "ssh_endpoint"]
    statuses = {o.target: o.status for o in ctx.outcomes}
    # one port read its first family, then saw the refusal; the other port made no SSH connection at all, or one
    assert len(starts) <= 2 + 3
    assert any(e["facts"]["host_keys_status"] == "server_refused" for e in eps) or "refused" in str(statuses)
    cov = [a for a in ctx.collected if a["type"] == "coverage"]
    assert any(c["facts"]["status"] == "refused" for c in cov)


# ----------------------------------------------------------------------------- the Linux collector's login
def _login(monkeypatch, stub, tmp_path):
    """linux_ssh.open_session against ``stub`` (every gated connect reaches it); returns the TargetFail it raised."""
    import paramiko

    from zs_scan_node import netutil
    from zs_scan_node.collectors import linux_ssh as L
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan, Target
    from zs_scan_node.scrub import Scrubber

    monkeypatch.setattr(netutil, "connect", lambda ip, port, never, timeout: stub.connect())
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 60,
                     state_dir=str(tmp_path))
    creds = {"key": paramiko.RSAKey.generate(2048)}
    with pytest.raises(L.TargetFail) as raised:
        L.open_session(ctx, Target("192.0.2.20", "192.0.2.20"), {"port": 22}, creds)
    return raised.value


def test_login_to_a_pq_only_server_is_kex_unsupported_with_the_servers_list(monkeypatch, tmp_path):
    """DA X4 / RC-5: the Linux source on a PQ-only host said only "error: SSH handshake failed (IncompatiblePeer)"."""
    stub = Stub(["mlkem768x25519-sha256", "sntrup761x25519-sha512"], ["ssh-ed25519"])
    try:
        fail = _login(monkeypatch, stub, tmp_path)
    finally:
        stub.close()
    assert fail.status == "kex_unsupported"
    assert "mlkem768x25519-sha256, sntrup761x25519-sha512" in fail.error and "curve25519-sha256" in fail.error
    assert len(stub.seen) == 2  # the login attempt, then one KEXINIT read to name the server's key exchanges


def test_login_negotiates_the_rfc8731_curve25519_name(monkeypatch, tmp_path):
    """RC-1b: a server offering ``curve25519-sha256`` (RFC 8731) without the libssh alias refused every login.  The
    stub answers with an unsigned reply, so the login still fails, but only after paramiko started curve25519."""
    stub = Stub(["curve25519-sha256", "mlkem768x25519-sha256"], ["ssh-ed25519"])
    try:
        fail = _login(monkeypatch, stub, tmp_path)
    finally:
        stub.close()
    rec = stub.settled()[0]
    assert rec.get("kex") == "curve25519-sha256" and rec.get("init_type") == 30 and len(rec["share"]) == 32
    assert fail.status == "error"  # the stub's reply carries no valid signature


def test_rfc8731_name_is_added_to_one_transport_only():
    import paramiko
    from paramiko.kex_curve25519 import KexCurve25519

    from zs_scan_node.collectors import linux_ssh as L

    a, b = socket.socketpair()
    try:
        t = paramiko.Transport(a)
        L._accept_rfc8731_curve25519(t)
        assert t.get_security_options().kex[0] == "curve25519-sha256"
        assert t._kex_info["curve25519-sha256"] is KexCurve25519
        assert "curve25519-sha256" not in paramiko.Transport._kex_info  # the class table is untouched
    finally:
        a.close()
        b.close()


def test_every_key_exchange_the_reader_speaks_is_a_registered_name():
    """The reader's names are the IANA / OpenSSH ones algid (CB-04) resolves: PQ ones safe or hybrid, the rest not."""
    from zs_scan_node import algid

    for name in S.PQ_KEX:
        assert algid.ssh_kex(name).quantum in ("safe", "hybrid"), name
    for name in S.CLASSICAL_KEX:
        assert algid.ssh_kex(name).quantum == "vulnerable", name
