import socket
import struct
import threading
import time

import pytest

from zs_scan_node import tlsprobe as T


def _server_hello(version=0x0303, cipher=0xC02F, exts=b"", random=None, sid=b""):
    random = random or bytes(32)
    body = struct.pack("!H", version) + random + bytes([len(sid)]) + sid + struct.pack("!H", cipher) + b"\x00"
    if exts:
        body += struct.pack("!H", len(exts)) + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _serve(payload: bytes, delay: float = 0.0, chunk: int | None = None):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        c, _ = srv.accept()
        try:
            c.recv(65536)
            time.sleep(delay)
            if chunk:
                for i in range(0, len(payload), chunk):
                    c.sendall(payload[i:i + chunk])
                    time.sleep(0.05)
            else:
                c.sendall(payload)
            time.sleep(0.3)
        except OSError:
            pass
        finally:
            c.close()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def test_client_hello_is_well_formed():
    rec = T.build_client_hello(T.TLS12, T.LEGACY_SUITES, sni="example.com")
    assert rec[0] == 0x16 and struct.unpack("!H", rec[3:5])[0] == len(rec) - 5
    hs = rec[5:]
    assert hs[0] == 1 and int.from_bytes(hs[1:4], "big") == len(hs) - 4
    assert len(rec) - 5 >= 512 or len(rec) - 5 < 256  # F5 padding rule
    rec13 = T.build_client_hello(T.TLS12, T.TLS13_SUITES, tls13=True, groups=T.PQ_GROUPS, key_share_groups=[])
    assert b"\x00\x2b\x00\x03\x02\x03\x04" in rec13  # supported_versions = TLS 1.3
    ssl3 = T.build_client_hello(T.SSL3, T.LEGACY_SUITES)
    assert ssl3[1:3] == b"\x03\x00"


def test_parse_server_hello_tls13_and_hrr():
    exts = struct.pack("!HHH", 43, 2, 0x0304) + struct.pack("!HHH", 51, 2, 0x11EC)
    raw = _server_hello(cipher=0x1302, exts=exts, random=T.HRR_RANDOM)
    r = T.parse_server_hello(raw[9:])
    assert r.hrr and r.version == T.TLS13 and r.group == 0x11EC


@pytest.mark.parametrize("bad", [b"", b"\x03\x03" + b"\x00" * 10, b"\x03\x03" + bytes(32) + b"\x20" + b"\x00" * 3,
                                 b"\x03\x03" + bytes(32) + b"\x00\xc0\x2f\x00\x00\x10\x00\x2b"])
def test_parse_server_hello_rejects_truncated(bad):
    with pytest.raises(ValueError):
        T.parse_server_hello(bad)


def test_read_flight_alert_garbage_and_large():
    port = _serve(b"\x15\x03\x03\x00\x02\x02\x46")  # fatal protocol_version
    r = T.probe("127.0.0.1", port, "tls", T.build_client_hello(T.TLS10, T.LEGACY_SUITES), 3.0)
    assert not r.ok and r.alert == "protocol_version"
    port = _serve(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    with pytest.raises(T.ProbeError):
        T.probe("127.0.0.1", port, "tls", T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 3.0)
    port = _serve(b"\x16\x03\x03\xff\xff" + b"\x00" * 100)  # record length over the TLS limit
    with pytest.raises(T.ProbeError):
        T.probe("127.0.0.1", port, "tls", T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 3.0)


def test_read_flight_slow_drip_is_bounded():
    port = _serve(b"\x16\x03\x03\x40\x00" + b"\x00" * 50, chunk=1)  # 1 byte every 50 ms of a 16 KB record
    started = time.monotonic()
    with pytest.raises(T.ProbeError) as err:
        T.probe("127.0.0.1", port, "tls", T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 1.5)
    assert err.value.code in ("timeout", "error")
    assert time.monotonic() - started < 4


def test_read_flight_fragmented_server_hello():
    port = _serve(_server_hello(cipher=0x002F), chunk=7)
    r = T.probe("127.0.0.1", port, "tls", T.build_client_hello(T.TLS12, T.LEGACY_SUITES), 3.0)
    assert r.ok and r.cipher_name == "TLS_RSA_WITH_AES_128_CBC_SHA" and r.version_name == "TLSv1.2"


def test_server_key_exchange():
    p = (1 << 1023) | 1
    body = struct.pack("!H", 128) + p.to_bytes(128, "big") + b"\x00\x01\x02" + b"\x00\x01\x05"
    assert T.parse_server_key_exchange(body, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == (1024, None)
    assert T.parse_server_key_exchange(b"\x03\x00\x1d\x20", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == (None, 29)
    assert T.parse_server_key_exchange(b"\xff", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == (None, None)


def test_kexinit_and_truncation():
    def nl(items):
        s = ",".join(items).encode()
        return struct.pack("!I", len(s)) + s
    payload = b"\x14" + bytes(16) + nl(["curve25519-sha256"]) + nl(["ssh-ed25519"]) + nl(["aes128-ctr"]) * 2 + \
        nl(["hmac-sha2-256"]) * 2 + nl(["none"]) * 2 + nl([]) * 2 + b"\x00" + bytes(4)
    d = T.parse_kexinit(payload)
    assert d["kex"] == ["curve25519-sha256"] and d["host_key_algs"] == ["ssh-ed25519"]
    with pytest.raises(ValueError):
        T.parse_kexinit(payload[:30])
    with pytest.raises(ValueError):
        T.parse_kexinit(b"\x14" + bytes(16) + struct.pack("!I", 10 ** 6))


def test_rdp_and_tds_parsers():
    rsp = bytes([3, 0, 0, 19, 14, 0xD0, 0, 0, 0x12, 0x34, 0]) + struct.pack("<BBHI", 2, 0, 8, 2)
    assert T.parse_rdp_response(rsp)["selected_name"] == "CredSSP (NLA)"
    fail = bytes([3, 0, 0, 19, 14, 0xD0, 0, 0, 0x12, 0x34, 0]) + struct.pack("<BBHI", 3, 0, 8, 5)
    assert T.parse_rdp_response(fail)["tls"] is False
    with pytest.raises(T.ProbeError):
        T.parse_rdp_response(b"\x03\x00\x00\x0b\x06\xf0\x00\x00\x00\x00\x00")
    body = struct.pack("!BHH", 0x00, 11, 6) + struct.pack("!BHH", 0x01, 17, 1) + b"\xff" + bytes(6) + b"\x03"
    assert T.parse_tds_prelogin(body)["encryption_name"] == "ENCRYPT_REQ"
    with pytest.raises(T.ProbeError):
        T.parse_tds_prelogin(b"\xff")


def test_parse_s_client_output():
    out = """CONNECTED(00000003)
---
Certificate chain
 0 s:CN = a
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUY3Rlc3Q=
-----END CERTIFICATE-----
---
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
SSL-Session:
    Protocol  : TLSv1.3
"""
    fh = T.parse_s_client(out)
    assert fh.ok and fh.version == "TLSv1.3" and fh.cipher == "TLS_AES_256_GCM_SHA384" and fh.group == "X25519"
    assert fh.peer_sig_type == "ECDSA" and fh.secure_renegotiation is False and len(fh.certs_der) == 1
    failed = T.parse_s_client("CONNECTED(00000003)\nNew, (NONE), Cipher is (NONE)\n")
    assert not failed.ok and failed.error
    dh = T.parse_s_client("New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\nServer Temp Key: ECDH, prime256v1, 256 bits\n")
    assert dh.group == "prime256v1"
    v35 = T.parse_s_client("Peer signature type: ecdsa_secp256r1_sha256\nPeer Temp Key: X25519, 253 bits\n"
                           "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")  # OpenSSL 3.5 wording
    assert v35.group == "X25519" and v35.peer_sig_type == "ecdsa_secp256r1_sha256"


def test_ldap_result_code_at_the_very_end_is_a_probe_error_not_a_crash():
    """Security review 2026-10-31: the answer 30 02 0a 01 raised IndexError and ended the whole network job."""
    a, b = socket.socketpair()
    try:
        b.sendall(bytes.fromhex("30020a01"))
        with pytest.raises(T.ProbeError):
            T._ldap(a, time.monotonic() + 5)
    finally:
        a.close()
        b.close()
