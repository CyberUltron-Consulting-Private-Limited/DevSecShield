"""Raw TLS ClientHello probes, STARTTLS/RDP/TDS preambles, SSH KEXINIT and an ``openssl s_client`` wrapper.

Each probe is one TCP connection and one ClientHello; the server's first flight is parsed only far enough to
learn the answer (ServerHello, HelloRetryRequest, ServerKeyExchange or an alert).  Everything read from the
network is length-checked, size-capped and time-boxed by a wall-clock deadline, so a tarpit, a slow drip, a
garbage stream or a 40-certificate chain cannot hang or crash the node.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

SSL3, TLS10, TLS11, TLS12, TLS13 = 0x0300, 0x0301, 0x0302, 0x0303, 0x0304
VERSION_NAMES = {SSL3: "SSLv3", TLS10: "TLSv1.0", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()
MAX_FLIGHT = 256 * 1024
MAX_RECORD = 18432

# ----------------------------------------------------------------------------- cipher suites (IANA)
CIPHERS: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256", 0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA", 0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA", 0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
}
TLS13_SUITES = [0x1302, 0x1301, 0x1303, 0x1304, 0x1305]
LEGACY_SUITES = [c for c in CIPHERS if c not in TLS13_SUITES]
OBSOLETE = [c for c, n in CIPHERS.items() if any(t in n for t in ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "anon",
                                                                    "IDEA", "SEED", "RC2"))]
STATIC_RSA = [c for c, n in CIPHERS.items() if n.startswith("TLS_RSA_WITH_") and "NULL" not in n and "RC4" not in n
              and "DES" not in n and "IDEA" not in n and "SEED" not in n]
CBC_FS = [c for c, n in CIPHERS.items() if ("ECDHE" in n or "DHE" in n) and "CBC" in n and "3DES" not in n
          and "_DES_" not in n and "EXPORT" not in n and "anon" not in n]
DHE_SUITES = [c for c, n in CIPHERS.items() if n.startswith("TLS_DHE_") and "EXPORT" not in n]

GROUPS: dict[int, str] = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00", 0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}
CLASSICAL_GROUPS = [29, 23, 24, 25, 30, 256, 257]
PQ_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x6399, 0x0201, 0x0202]
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B,
           0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0402, 0x0202]
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 43: "unsupported_certificate", 47: "illegal_parameter", 50: "decode_error",
          51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
          86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension", 110: "unsupported_extension",
          112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol"}


class ProbeError(Exception):
    """A connection-level failure (timeout, refused, reset, garbage); ``code`` is a target status."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


class StarttlsUnavailable(Exception):
    """The service is up but does not offer TLS (no STARTTLS, Postgres 'N', MySQL without CLIENT_SSL)."""


@dataclass
class HelloResult:
    ok: bool = False  # ServerHello received
    version: int | None = None
    cipher: int | None = None
    hrr: bool = False
    group: int | None = None
    alert: str | None = None
    closed: bool = False
    dh_bits: int | None = None
    ecdhe_group: int | None = None
    error: str | None = None

    @property
    def version_name(self) -> str | None:
        return VERSION_NAMES.get(self.version or 0)

    @property
    def cipher_name(self) -> str | None:
        if self.cipher is None:
            return None
        return CIPHERS.get(self.cipher, f"0x{self.cipher:04X}")


# ----------------------------------------------------------------------------- ClientHello
def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def build_client_hello(version: int, suites: list[int], sni: str | None = None, groups: list[int] | None = None,
                       tls13: bool = False, key_share_groups: list[int] | None = None,
                       fallback_scsv: bool = False) -> bytes:
    """A ClientHello record.  ``version`` is the legacy client_version (TLS 1.3 uses 0x0303 + supported_versions)."""
    rnd = os.urandom(32)
    session_id = os.urandom(32) if tls13 else b""
    cs = list(suites) + ([0x5600] if fallback_scsv else [])
    body = struct.pack("!H", version) + rnd + bytes([len(session_id)]) + session_id
    body += struct.pack("!H", 2 * len(cs)) + b"".join(struct.pack("!H", c) for c in cs)
    body += b"\x01\x00"  # null compression only
    exts = b""
    if version >= TLS10:
        if sni:
            name = sni.encode("idna")
            entry = b"\x00" + struct.pack("!H", len(name)) + name
            exts += _ext(0, struct.pack("!H", len(entry)) + entry)
        g = groups if groups is not None else CLASSICAL_GROUPS
        exts += _ext(10, struct.pack("!H", 2 * len(g)) + b"".join(struct.pack("!H", x) for x in g))
        exts += _ext(11, b"\x01\x00")  # ec_point_formats: uncompressed
        if version >= TLS12 or tls13:
            exts += _ext(13, struct.pack("!H", 2 * len(SIGALGS)) + b"".join(struct.pack("!H", s) for s in SIGALGS))
        exts += _ext(0xFF01, b"\x00")  # renegotiation_info (empty)
        if tls13:
            exts += _ext(43, b"\x02" + struct.pack("!H", TLS13))
            exts += _ext(45, b"\x01\x01")  # psk_key_exchange_modes: psk_dhe_ke
            shares = b""
            for grp in key_share_groups or []:
                if grp == 29:
                    shares += struct.pack("!HH", 29, 32) + os.urandom(32)
            exts += _ext(51, struct.pack("!H", len(shares)) + shares)
        # F5 "ClientHello 256-511 bytes" bug: pad to 512
        hello_len = 4 + len(body) + 2 + len(exts)
        if 256 <= hello_len < 512:
            pad = 512 - hello_len - 4
            exts += _ext(21, b"\x00" * max(pad, 0))
        body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record_version = SSL3 if version == SSL3 else TLS10
    return b"\x16" + struct.pack("!HH", record_version, len(handshake)) + handshake


# ----------------------------------------------------------------------------- reading the server flight
def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise ProbeError("timeout", "server too slow")
        sock.settimeout(min(left, 2.0))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            continue
        except ConnectionResetError:
            raise ProbeError("refused", "connection reset") from None
        except OSError as exc:
            raise ProbeError("error", exc.__class__.__name__) from None
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def parse_server_hello(body: bytes) -> HelloResult:
    """Parse a ServerHello body (without the 4-byte handshake header).  Raises ValueError on malformed input."""
    if len(body) < 38:
        raise ValueError("short ServerHello")
    version = struct.unpack("!H", body[0:2])[0]
    random = body[2:34]
    sid_len = body[34]
    pos = 35 + sid_len
    if pos + 3 > len(body):
        raise ValueError("truncated ServerHello")
    cipher = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 3  # cipher + compression
    res = HelloResult(ok=True, version=version, cipher=cipher, hrr=random == HRR_RANDOM)
    if pos + 2 <= len(body):
        ext_len = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_len
        if end > len(body):
            raise ValueError("truncated extensions")
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            data = body[pos:pos + elen]
            if len(data) != elen:
                raise ValueError("truncated extension")
            pos += elen
            if etype == 43 and elen == 2:
                res.version = struct.unpack("!H", data)[0]
            elif etype == 51 and elen >= 2:
                res.group = struct.unpack("!H", data[:2])[0]
    return res


def parse_server_key_exchange(body: bytes, cipher_name: str) -> tuple[int | None, int | None]:
    """(dh_bits, ecdhe_group) from a TLS <= 1.2 ServerKeyExchange."""
    if "ECDHE" in cipher_name or "ECDH_anon" in cipher_name:
        if len(body) >= 3 and body[0] == 3:
            return None, struct.unpack("!H", body[1:3])[0]
        return None, None
    if "DHE" in cipher_name or "DH_anon" in cipher_name:
        if len(body) >= 2:
            plen = struct.unpack("!H", body[:2])[0]
            p = body[2:2 + plen]
            if len(p) == plen and plen:
                return int.from_bytes(p, "big").bit_length(), None
    return None, None


def read_flight(sock: socket.socket, deadline: float, want_kex: bool = False) -> HelloResult:
    """Read records until ServerHello (and, with ``want_kex``, the ServerKeyExchange/ServerHelloDone)."""
    hs = b""
    total = 0
    result: HelloResult | None = None
    while True:
        try:
            header = _recv_exact(sock, 5, deadline)
        except EOFError:
            if result is not None:
                return result
            return HelloResult(closed=True, error="closed")
        rtype, _rver, rlen = header[0], struct.unpack("!H", header[1:3])[0], struct.unpack("!H", header[3:5])[0]
        if rtype not in (20, 21, 22, 23) or rlen > MAX_RECORD:
            if result is not None:
                return result
            raise ProbeError("error", "not a TLS response")
        total += 5 + rlen
        if total > MAX_FLIGHT:
            if result is not None:
                return result
            raise ProbeError("error", "server flight too large")
        try:
            payload = _recv_exact(sock, rlen, deadline)
        except EOFError:
            if result is not None:
                return result
            return HelloResult(closed=True, error="closed mid-record")
        if rtype == 21:
            desc = payload[1] if len(payload) >= 2 else -1
            alert = ALERTS.get(desc, f"alert_{desc}")
            if result is not None:
                result.alert = result.alert or alert
                return result
            return HelloResult(alert=alert)
        if rtype != 22:
            if result is not None:
                return result
            continue
        hs += payload
        while len(hs) >= 4:
            mtype = hs[0]
            mlen = int.from_bytes(hs[1:4], "big")
            if mlen > MAX_FLIGHT:
                raise ProbeError("error", "handshake message too large")
            if len(hs) < 4 + mlen:
                break
            msg, hs = hs[4:4 + mlen], hs[4 + mlen:]
            if mtype == 2:
                try:
                    result = parse_server_hello(msg)
                except ValueError as exc:
                    raise ProbeError("error", str(exc)) from None
                if result.hrr or (result.version or 0) >= TLS13 or not want_kex:
                    return result
            elif mtype == 12 and result is not None:
                result.dh_bits, result.ecdhe_group = parse_server_key_exchange(msg, result.cipher_name or "")
                return result
            elif mtype == 14 and result is not None:  # ServerHelloDone without a key exchange (static RSA)
                return result


# ----------------------------------------------------------------------------- connecting and preambles
def connect(ip: str, port: int, timeout: float = 3.0) -> socket.socket:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except socket.timeout:
        sock.close()
        raise ProbeError("timeout", "connect timed out") from None
    except ConnectionRefusedError:
        sock.close()
        raise ProbeError("refused", "connection refused") from None
    except OSError as exc:
        sock.close()
        code = "no_route" if getattr(exc, "errno", None) in (101, 113, 51, 65) else "unreachable"
        raise ProbeError(code, exc.__class__.__name__) from None
    return sock


def _read_line(sock: socket.socket, deadline: float, limit: int = 4096) -> bytes:
    buf = b""
    while not buf.endswith(b"\n"):
        left = deadline - time.monotonic()
        if left <= 0:
            raise ProbeError("timeout", "no banner")
        sock.settimeout(min(left, 2.0))
        try:
            ch = sock.recv(1)
        except socket.timeout:
            continue
        except OSError:
            raise ProbeError("error", "connection reset during banner") from None
        if not ch:
            raise ProbeError("error", "closed during banner")
        buf += ch
        if len(buf) > limit:
            raise ProbeError("error", "banner too long")
    return buf


def _smtp(sock, deadline):
    def reply():
        lines = []
        for _ in range(64):
            line = _read_line(sock, deadline)
            lines.append(line)
            if len(line) < 4 or line[3:4] != b"-":
                return lines
        raise ProbeError("error", "SMTP reply too long")
    banner = reply()
    if not banner[0].startswith(b"220"):
        raise ProbeError("error", "not an SMTP banner")
    sock.sendall(b"EHLO zeroshield-scan.invalid\r\n")
    caps = reply()
    if not any(b"STARTTLS" in line.upper() for line in caps):
        raise StarttlsUnavailable("STARTTLS not offered")
    sock.sendall(b"STARTTLS\r\n")
    resp = reply()
    if not resp[-1].startswith(b"220"):
        raise StarttlsUnavailable("STARTTLS refused")
    return {"banner": banner[0][:120].decode("latin-1", "replace").strip()}


def _imap(sock, deadline):
    first = _read_line(sock, deadline)
    if not first.startswith(b"* OK"):
        raise ProbeError("error", "not an IMAP banner")
    sock.sendall(b"a1 CAPABILITY\r\n")
    caps = b""
    for _ in range(32):
        line = _read_line(sock, deadline)
        caps += line
        if line.startswith(b"a1 "):
            break
    if b"STARTTLS" not in caps.upper():
        raise StarttlsUnavailable("STARTTLS not offered")
    sock.sendall(b"a2 STARTTLS\r\n")
    for _ in range(8):
        line = _read_line(sock, deadline)
        if line.startswith(b"a2 "):
            if not line.startswith(b"a2 OK"):
                raise StarttlsUnavailable("STARTTLS refused")
            return {}
    raise ProbeError("error", "no STARTTLS answer")


LDAP_STARTTLS = bytes.fromhex("301d02010177188016") + b"1.3.6.1.4.1.1466.20037"


def _ldap(sock, deadline):
    sock.sendall(LDAP_STARTTLS)
    data = _recv_exact(sock, 2, deadline)
    if data[0] != 0x30:
        raise ProbeError("error", "not an LDAP response")
    length = data[1]
    if length & 0x80:
        n = length & 0x7F
        if n > 3:
            raise ProbeError("error", "LDAP length too large")
        length = int.from_bytes(_recv_exact(sock, n, deadline), "big")
    if length > 4096:
        raise ProbeError("error", "LDAP response too large")
    body = _recv_exact(sock, length, deadline)
    idx = body.find(b"\x0a\x01")
    if idx < 0 or idx + 2 >= len(body):  # "0a 01" at the very end has no result byte (hostile or truncated)
        raise ProbeError("error", "no LDAP result code")
    if body[idx + 2] != 0:
        raise StarttlsUnavailable(f"LDAP StartTLS result {body[idx + 2]}")
    return {}


def _postgres(sock, deadline):
    sock.sendall(struct.pack("!II", 8, 80877103))
    answer = _recv_exact(sock, 1, deadline)
    if answer == b"S":
        return {}
    if answer == b"N":
        raise StarttlsUnavailable("PostgreSQL refused SSLRequest (ssl=off)")
    raise ProbeError("error", "unexpected answer to SSLRequest")


def _mysql(sock, deadline):
    header = _recv_exact(sock, 4, deadline)
    length = int.from_bytes(header[:3], "little")
    if length > 4096 or length < 10:
        raise ProbeError("error", "not a MySQL greeting")
    payload = _recv_exact(sock, length, deadline)
    if payload[0] == 0xFF:
        raise ProbeError("refused", "MySQL refused the connection")
    end = payload.find(b"\x00", 1)
    if payload[0] != 10 or end < 0 or end + 1 + 4 + 8 + 1 + 2 > len(payload):
        raise ProbeError("error", "unsupported MySQL greeting")
    version = payload[1:end].decode("latin-1", "replace")[:60]
    pos = end + 1 + 4 + 8 + 1
    caps = struct.unpack("<H", payload[pos:pos + 2])[0]
    if not caps & 0x0800:
        raise StarttlsUnavailable(f"MySQL {version} does not offer TLS")
    client_caps = 0x0800 | 0x0200 | 0x8000 | 0x0001 | 0x00080000
    req = struct.pack("<IIB", client_caps, 16 * 1024 * 1024, 33) + b"\x00" * 23
    sock.sendall(len(req).to_bytes(3, "little") + b"\x01" + req)
    return {"server_version": version}


RDP_PROTOCOLS = {0: "RDP standard security", 1: "TLS", 2: "CredSSP (NLA)", 8: "CredSSP early user auth"}


def rdp_negotiate(sock, deadline) -> dict:
    neg = struct.pack("<BBHI", 1, 0, 8, 0x0000000B)
    x224 = bytes([6 + len(neg), 0xE0, 0, 0, 0, 0, 0]) + neg
    sock.sendall(struct.pack("!BBH", 3, 0, 4 + len(x224)) + x224)
    head = _recv_exact(sock, 4, deadline)
    if head[0] != 3:
        raise ProbeError("error", "not an RDP response")
    total = struct.unpack("!H", head[2:4])[0]
    if total < 11 or total > 512:
        raise ProbeError("error", "bad RDP length")
    rest = _recv_exact(sock, total - 4, deadline)
    return parse_rdp_response(head + rest)


def parse_rdp_response(data: bytes) -> dict:
    if len(data) < 11 or data[5] != 0xD0:
        raise ProbeError("error", "no X.224 connection confirm")
    if len(data) < 19:
        return {"selected": 0, "selected_name": RDP_PROTOCOLS[0], "tls": False}
    neg_type = data[11]
    value = struct.unpack("<I", data[15:19])[0]
    if neg_type == 2:
        return {"selected": value, "selected_name": RDP_PROTOCOLS.get(value, f"0x{value:x}"), "tls": value != 0}
    if neg_type == 3:
        return {"selected": None, "failure_code": value, "tls": False}
    raise ProbeError("error", "unknown RDP negotiation answer")


TDS_ENCRYPTION = {0: "ENCRYPT_OFF (login only)", 1: "ENCRYPT_ON", 2: "ENCRYPT_NOT_SUP", 3: "ENCRYPT_REQ"}


def tds_prelogin(sock, deadline) -> dict:
    options = [(0x00, b"\x0f\x00\x07\xd0\x00\x00"), (0x01, b"\x00"), (0x02, b"\x00"), (0x03, b"\x00\x00\x00\x00")]
    header_len = 5 * len(options) + 1
    table, data = b"", b""
    for token, value in options:
        table += struct.pack("!BHH", token, header_len + len(data), len(value))
        data += value
    payload = table + b"\xff" + data
    sock.sendall(struct.pack("!BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 1, 0) + payload)
    head = _recv_exact(sock, 8, deadline)
    length = struct.unpack("!H", head[2:4])[0]
    if head[0] != 0x04 or length < 8 or length > 4096:
        raise ProbeError("error", "not a TDS response")
    body = _recv_exact(sock, length - 8, deadline)
    return parse_tds_prelogin(body)


def parse_tds_prelogin(body: bytes) -> dict:
    pos = 0
    while pos + 5 <= len(body) and body[pos] != 0xFF:
        token, offset, length = struct.unpack("!BHH", body[pos:pos + 5])
        if token == 0x01 and length >= 1 and offset < len(body):
            value = body[offset]
            return {"encryption": value, "encryption_name": TDS_ENCRYPTION.get(value, f"0x{value:x}")}
        pos += 5
    raise ProbeError("error", "no ENCRYPTION option in PRELOGIN response")


PREAMBLES = {"starttls-smtp": _smtp, "starttls-imap": _imap, "starttls-ldap": _ldap, "starttls-postgres": _postgres,
             "starttls-mysql": _mysql}
S_CLIENT_STARTTLS = {"starttls-smtp": "smtp", "starttls-imap": "imap", "starttls-ldap": "ldap",
                     "starttls-postgres": "postgres", "starttls-mysql": "mysql"}


def open_tls_socket(ip: str, port: int, protocol: str, timeout: float = 10.0) -> tuple[socket.socket, dict]:
    """Connected socket ready for a ClientHello (STARTTLS/RDP done), plus preamble facts."""
    deadline = time.monotonic() + timeout
    sock = connect(ip, port, min(3.0, timeout))
    try:
        facts: dict[str, Any] = {}
        if protocol in PREAMBLES:
            facts = PREAMBLES[protocol](sock, deadline) or {}
        elif protocol == "rdp":
            facts = rdp_negotiate(sock, deadline)
            if not facts.get("tls"):
                raise StarttlsUnavailable(f"RDP uses {facts.get('selected_name') or 'no TLS'}")
        return sock, facts
    except BaseException:
        sock.close()
        raise


def probe(ip: str, port: int, protocol: str, hello: bytes, timeout: float = 8.0, want_kex: bool = False) -> HelloResult:
    deadline = time.monotonic() + timeout
    sock, _facts = open_tls_socket(ip, port, protocol, timeout)
    try:
        sock.sendall(hello)
        return read_flight(sock, deadline, want_kex=want_kex)
    except OSError as exc:
        raise ProbeError("error", exc.__class__.__name__) from None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------------- full handshake
@dataclass
class FullHandshake:
    ok: bool = False
    version: str | None = None
    cipher: str | None = None
    group: str | None = None
    temp_key: str | None = None
    peer_sig_type: str | None = None
    peer_sig_digest: str | None = None
    secure_renegotiation: bool | None = None
    client_auth_requested: bool = False
    certs_der: list[bytes] = field(default_factory=list)
    error: str | None = None
    tool: str = "openssl"


_PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def parse_s_client(out: str) -> FullHandshake:
    import base64

    fh = FullHandshake()
    m = re.search(r"^New, (\S+), Cipher is (\S+)", out, re.M)
    if m and m.group(2) != "(NONE)":
        fh.ok = True
        fh.version, fh.cipher = m.group(1).rstrip(","), m.group(2)
    m = re.search(r"^\s*Protocol\s*:\s*(\S+)", out, re.M)
    if m and fh.ok:
        fh.version = m.group(1)
    m = re.search(r"^(?:Server|Peer) Temp Key: (.+)$", out, re.M)  # 3.0 says Server, 3.5 says Peer
    if m:
        fh.temp_key = m.group(1).strip()
        first = fh.temp_key.split(",")[0].strip()
        if first in ("ECDH",) and "," in fh.temp_key:
            fh.group = fh.temp_key.split(",")[1].strip()
        elif first == "DH":
            fh.group = "ffdhe/DH " + fh.temp_key.split(",")[-1].strip()
        else:
            fh.group = first
    m = re.search(r"^Negotiated TLS1\.3 group: (\S+)", out, re.M)
    if m:
        fh.group = m.group(1)
    m = re.search(r"^Peer signature type: (\S+)", out, re.M)
    if m:
        fh.peer_sig_type = m.group(1)
    m = re.search(r"^Peer signing digest: (\S+)", out, re.M)
    if m:
        fh.peer_sig_digest = m.group(1)
    if "Secure Renegotiation IS supported" in out:
        fh.secure_renegotiation = True
    elif "Secure Renegotiation IS NOT supported" in out:
        fh.secure_renegotiation = False
    if re.search(r"^Acceptable client certificate CA names", out, re.M) or "Client Certificate Types:" in out:
        fh.client_auth_requested = True
    for pem in _PEM.findall(out)[:60]:
        body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
        try:
            fh.certs_der.append(base64.b64decode(body))
        except Exception:
            continue
    if not fh.ok:
        fh.error = "handshake failed"
    return fh


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


def s_client(ip: str, port: int, protocol: str, sni: str | None, timeout: float = 15.0) -> FullHandshake:
    host = f"[{ip}]" if ":" in ip else ip
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts", "-legacy_server_connect",
           "-cipher", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"]
    cmd += ["-servername", sni] if sni else ["-noservername"]
    if protocol in S_CLIENT_STARTTLS:
        cmd += ["-starttls", S_CLIENT_STARTTLS[protocol]]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "OPENSSL_CONF": "/dev/null", "LC_ALL": "C"}
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return FullHandshake(error="timeout")
    except OSError as exc:
        return FullHandshake(error=f"openssl not usable: {exc.__class__.__name__}")
    out = proc.stdout[:2_000_000].decode("latin-1", "replace")
    return parse_s_client(out)


def python_handshake(ip: str, port: int, protocol: str, sni: str | None, timeout: float = 10.0) -> FullHandshake:
    """Fallback full handshake with Python's ssl (also used after RDP negotiation)."""
    try:
        sock, _ = open_tls_socket(ip, port, protocol, timeout)
    except StarttlsUnavailable as exc:
        return FullHandshake(error=str(exc))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ssl.SSLError, ValueError):
        pass
    sock.settimeout(timeout)
    try:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            return FullHandshake(ok=True, version=tls.version(), cipher=cipher[0] if cipher else None,
                                 certs_der=[der] if der else [], tool="python-ssl")
    except (OSError, ssl.SSLError) as exc:
        return FullHandshake(error=exc.__class__.__name__)
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------------- SSH
def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    if len(payload) < 17 or payload[0] != 20:
        raise ValueError("not a KEXINIT")
    pos = 17
    names = ["kex", "host_key_algs", "ciphers_c2s", "ciphers_s2c", "macs_c2s", "macs_s2c", "compression_c2s",
             "compression_s2c"]
    out: dict[str, list[str]] = {}
    for key in names:
        if pos + 4 > len(payload):
            raise ValueError("truncated KEXINIT")
        n = struct.unpack("!I", payload[pos:pos + 4])[0]
        if n > 8192 or pos + 4 + n > len(payload):
            raise ValueError("bad name-list")
        raw = payload[pos + 4:pos + 4 + n].decode("ascii", "replace")
        out[key] = [x for x in raw.split(",") if x][:100]
        pos += 4 + n
    return out


def ssh_kexinit(ip: str, port: int, timeout: float = 8.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    sock = connect(ip, port, 3.0)
    try:
        banner = b""
        for _ in range(10):  # RFC 4253 allows lines before the version string
            line = _read_line(sock, deadline, limit=1024)
            if line.startswith(b"SSH-"):
                banner = line
                break
        if not banner:
            raise ProbeError("error", "no SSH version string")
        sock.sendall(b"SSH-2.0-ZeroShieldScan_1.0\r\n")
        head = _recv_exact(sock, 5, deadline)
        plen, padlen = struct.unpack("!IB", head)
        if plen > 35000 or plen < 2:
            raise ProbeError("error", "bad SSH packet length")
        body = _recv_exact(sock, plen - 1, deadline)
        payload = body[: plen - 1 - padlen]
        try:
            algs = parse_kexinit(payload)
        except ValueError as exc:
            raise ProbeError("error", str(exc)) from None
        algs["banner"] = banner.decode("latin-1", "replace").strip()[:200]  # type: ignore[assignment]
        return algs
    except EOFError:
        raise ProbeError("error", "closed during SSH handshake") from None
    finally:
        sock.close()


def ssh_host_key(ip: str, port: int, timeout: float = 10.0) -> dict[str, Any] | None:
    """Complete key exchange only (never authenticates) to learn the host key type and size."""
    import paramiko

    sock = connect(ip, port, 3.0)
    transport = paramiko.Transport(sock)
    try:
        opts = transport.get_security_options()
        try:
            opts.kex = tuple(transport._preferred_kex) + tuple(k for k in ("diffie-hellman-group1-sha1",
                                                                            "diffie-hellman-group14-sha1",
                                                                            "diffie-hellman-group-exchange-sha1")
                                                                if k in transport._kex_info and k not in transport._preferred_kex)
            opts.ciphers = tuple(transport._preferred_ciphers) + tuple(c for c in ("aes128-cbc", "aes256-cbc", "3des-cbc")
                                                                        if c in transport._cipher_info and c not in transport._preferred_ciphers)
            opts.digests = tuple(transport._preferred_macs) + tuple(m for m in ("hmac-sha1", "hmac-md5")
                                                                     if m in transport._mac_info and m not in transport._preferred_macs)
            opts.key_types = tuple(transport._preferred_keys) + tuple(k for k in ("ssh-rsa", "ssh-dss")
                                                                       if k in transport._key_info and k not in transport._preferred_keys)
        except Exception:
            pass
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        bits = key.get_bits()
        return {"key_type": key.get_name(), "bits": bits,
                "fingerprint_sha256": hashlib.sha256(key.asbytes()).hexdigest()}
    except Exception as exc:  # paramiko raises many types for legacy/odd servers
        return {"error": exc.__class__.__name__}
    finally:
        try:
            transport.close()
        except Exception:
            pass
        sock.close()
