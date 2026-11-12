"""SSH server reading without logging in: the KEXINIT lists and every host key the server holds (CB-13).

One SSH connection reads the server's banner and KEXINIT (RFC 4253 section 7.1) and then the host key of the first
host-key *family* (algorithms that use one key: ``ssh-rsa``, ``rsa-sha2-256`` and ``rsa-sha2-512``; each certificate
type with its RSA signature aliases; every other name alone).  Each further family costs one more connection.  On each
connection the client offers one key exchange and that family's host-key algorithms, sends the key exchange's first
message, and reads the server's reply, whose ``K_S`` is the host key (or host certificate) the server holds for the
family.  The exchange is never completed (no NEWKEYS, no authentication): the client sends SSH_MSG_DISCONNECT and
closes.  ssh-audit reads host keys the same way; OpenSSH's own ssh-keyscan uses one connection per key type too.

Why not paramiko (the node's SSH library): it negotiates one host key per handshake and implements none of the
post-quantum key exchanges (``mlkem768x25519-sha256``, ``sntrup761x25519-sha512``, RFC 10042's NIST-curve hybrids),
so a PQ-only server's host key was never read (KF-6) and a second host key never seen (KF-17).  The node image has no
OpenSSH client either.

The reply's signature is not verified: that needs the key exchange's shared secret, and for ML-KEM the decapsulation
key, which this node's ``cryptography`` does not provide.  Every key is reported with ``read_by: "kex_reply"``.
The Linux collector, which sends credentials, keeps paramiko's verified handshake and host-key pinning.

This module never opens a connection: the caller hands in sockets it opened through the network gate (never-scan,
stop-all, rate limits), one per call of ``open_conn``.  Client key shares are generated at run time; the ML-KEM
encapsulation key is a valid FIPS 203 encoding (every coefficient below q) whose secret half is never needed.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
import secrets
import socket
import struct
import time
from typing import Any, Callable

from zs_scan_node import tlsprobe as T

CLIENT_BANNER = b"SSH-2.0-ZeroShieldScan_1.0\r\n"  # the same version string the KEXINIT probe always sent
MAX_PACKET = 65536
MAX_PRE_BANNER_LINES = 10
EXCHANGE_TIMEOUT = 10.0

MSG_DISCONNECT, MSG_IGNORE, MSG_DEBUG, MSG_KEXINIT = 1, 2, 4, 20
MSG_KEX_INIT, MSG_KEX_REPLY = 30, 31  # KEXDH / KEX_ECDH / KEX_HYBRID (RFC 4253, 5656, 10042); KEXRSA_PUBKEY = 30
MSG_GEX_REQUEST, MSG_GEX_GROUP, MSG_GEX_INIT, MSG_GEX_REPLY = 34, 31, 32, 33  # RFC 4419

ML_KEM_EK = {512: 800, 768: 1184, 1024: 1568}  # FIPS 203 encapsulation-key bytes (384 k + 32)
SNTRUP761_PK = 1158
# Key exchanges the reader speaks, in the order it picks them.  Classical first (smallest messages); the post-quantum
# and hybrid ones are used when the server offers nothing else.  Names: IANA "Key Exchange Method Names" (RFC 4253,
# 4419, 4432, 5656, 8268, 8731, 10042), OpenSSH aliases, draft-harrison-mlkem-ssh (pure ML-KEM).
CLASSICAL_KEX = ("curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
                 "ecdh-sha2-nistp521", "curve448-sha512", "diffie-hellman-group14-sha256",
                 "diffie-hellman-group16-sha512", "diffie-hellman-group15-sha512", "diffie-hellman-group18-sha512",
                 "diffie-hellman-group17-sha512", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha256",
                 "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1", "rsa2048-sha256", "rsa1024-sha1")
PQ_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
          "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "mlkem768-sha256", "mlkem512-sha256",
          "mlkem1024-sha384")
READER_KEX = CLASSICAL_KEX + PQ_KEX
_DH_BITS = {"diffie-hellman-group1-sha1": 1024, "diffie-hellman-group14-sha1": 2048,
            "diffie-hellman-group14-sha256": 2048, "diffie-hellman-group15-sha512": 3072,
            "diffie-hellman-group16-sha512": 4096, "diffie-hellman-group17-sha512": 6144,
            "diffie-hellman-group18-sha512": 8192}
GEX_REQUEST = (1024, 2048, 8192)  # min / preferred / max modulus bits: as wide as servers allow, to read the key
_RSA_ALIASES = ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
_RSA_CERT_ALIASES = ("rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
                     "ssh-rsa-cert-v01@openssh.com")
# The order paramiko preferred host keys in (the key the endpoint's algorithm and size reported before CB-13), so the
# primary ``host_key`` of an endpoint does not change.
_PRIMARY_ORDER = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
                  "ssh-dss")


class ServerRefused(Exception):
    """The server closed the connection before its banner (OpenSSH PerSourcePenalties / MaxStartups)."""


class Stop(Exception):
    """Raised by the caller's ``open_conn`` when no further connection may be made (pacing budget, stop-all,
    never-scan, an earlier refusal); ``reason`` says why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Fail(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ----------------------------------------------------------------------------- wire
def _string(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _mpint(n: int) -> bytes:
    if n == 0:
        return _string(b"")
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big")  # a leading zero byte when the top bit is set
    return _string(raw)


def _names(names: list[str]) -> bytes:
    return _string(",".join(names).encode("ascii", "replace"))


def _packet(payload: bytes) -> bytes:
    pad = 8 - ((5 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def raw(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack("!I", self.raw(4))[0]

    def u64(self) -> int:
        return struct.unpack("!Q", self.raw(8))[0]

    def string(self) -> bytes:
        return self.raw(self.u32())

    def text(self) -> str:
        return self.string().decode("utf-8", "replace")

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big", signed=True)


def _recv_packet(sock: socket.socket, deadline: float) -> bytes:
    head = T._recv_exact(sock, 5, deadline)
    plen, padlen = struct.unpack("!IB", head)
    if plen > MAX_PACKET or plen < 2 or padlen >= plen:
        raise _Fail("bad SSH packet length")
    body = T._recv_exact(sock, plen - 1, deadline)
    return body[: plen - 1 - padlen]


def _recv_message(sock: socket.socket, deadline: float, want: tuple[int, ...]) -> bytes:
    """The next message of a type in ``want``; IGNORE/DEBUG are skipped, DISCONNECT ends the exchange."""
    for _ in range(32):
        payload = _recv_packet(sock, deadline)
        if not payload:
            raise _Fail("empty SSH packet")
        kind = payload[0]
        if kind in want:
            return payload
        if kind in (MSG_IGNORE, MSG_DEBUG):
            continue
        if kind == MSG_DISCONNECT:
            r = _Reader(payload[1:])
            try:
                code, text = r.u32(), r.text()
            except ValueError:
                code, text = 0, ""
            raise _Fail(f"server disconnected ({code}: {text[:120]})")
        raise _Fail(f"unexpected SSH message {kind}")
    raise _Fail("too many SSH messages")


# ----------------------------------------------------------------------------- banner and KEXINIT
def _line(sock: socket.socket, deadline: float, limit: int = 1024) -> bytes | None:
    """One banner-phase line; None when the server closed (or reset) the connection before sending anything more."""
    buf = b""
    while not buf.endswith(b"\n"):
        left = deadline - time.monotonic()
        if left <= 0:
            raise T.ProbeError("timeout", "no SSH banner")
        sock.settimeout(min(left, 2.0))
        try:
            ch = sock.recv(1)
        except socket.timeout:
            continue
        except ConnectionResetError:
            ch = b""
        except OSError as exc:
            raise T.ProbeError("error", exc.__class__.__name__) from None
        if not ch:
            return buf or None
        buf += ch
        if len(buf) > limit:
            raise T.ProbeError("error", "SSH banner line too long")
    return buf


def read_kexinit(sock: socket.socket, deadline: float) -> dict[str, Any]:
    """Banner exchange and the server's KEXINIT: ``{"banner", "pre_banner", "lists": {...}}``.  ServerRefused when
    the server closes before its version string (OpenSSH drops a penalised source or a MaxStartups overflow that way,
    after an optional one-line reason such as "Not allowed at this time")."""
    pre: list[str] = []
    banner = b""
    for _ in range(MAX_PRE_BANNER_LINES):  # RFC 4253 4.2 allows other lines before the version string
        line = _line(sock, deadline)
        if line is None:
            break
        if line.startswith(b"SSH-"):
            banner = line
            break
        pre.append(line.decode("latin-1", "replace").strip()[:200])
        if not line.endswith(b"\n"):
            break  # closed in the middle of a line
    if not banner:
        said = "; ".join(p for p in pre if p)
        if len(pre) >= MAX_PRE_BANNER_LINES:
            raise T.ProbeError("error", "no SSH version string")
        raise ServerRefused("the server closed the connection before its SSH banner" + (f" ({said})" if said else ""))
    try:
        sock.sendall(CLIENT_BANNER)
        payload = _recv_message(sock, deadline, (MSG_KEXINIT,))
        lists = T.parse_kexinit(payload)
    except EOFError:
        raise T.ProbeError("error", "closed during SSH handshake") from None
    except _Fail as exc:
        raise T.ProbeError("error", exc.reason) from None
    except ValueError as exc:
        raise T.ProbeError("error", str(exc)) from None
    except OSError as exc:
        raise T.ProbeError("error", exc.__class__.__name__) from None
    return {"banner": banner.decode("latin-1", "replace").strip()[:200], "pre_banner": pre, "lists": lists}


def choose_kex(server_kex: list[str]) -> str | None:
    offered = set(server_kex)
    return next((k for k in READER_KEX if k in offered), None)


def families(host_key_algs: list[str]) -> list[list[str]]:
    """Group the server's host-key algorithms by the key they use, in the server's order."""
    out: list[list[str]] = []
    index: dict[str, int] = {}
    for alg in host_key_algs:
        if alg in _RSA_ALIASES:
            fam = "rsa"
        elif alg in _RSA_CERT_ALIASES:
            fam = "rsa-cert"
        else:
            fam = alg
        if fam not in index:
            index[fam] = len(out)
            out.append([])
        if alg not in out[index[fam]]:
            out[index[fam]].append(alg)
    for group in out:  # within the RSA families: SHA-512, SHA-256, then SHA-1, whatever the server's order
        if group[0] in _RSA_ALIASES or group[0] in _RSA_CERT_ALIASES:
            order = _RSA_ALIASES if group[0] in _RSA_ALIASES else _RSA_CERT_ALIASES
            group.sort(key=order.index)
    return out


# ----------------------------------------------------------------------------- client key shares
def _mlkem_ek(k: int) -> bytes:
    """A FIPS 203 encapsulation key: ByteEncode12 of 256 k coefficients drawn below q = 3329, then a random rho."""
    out = bytearray()
    for _ in range(128 * k):
        a, b = secrets.randbelow(3329), secrets.randbelow(3329)
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(out) + os.urandom(32)


def _x25519() -> bytes:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _x448() -> bytes:
    from cryptography.hazmat.primitives.asymmetric import x448
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return x448.X448PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ec_point(curve_name: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    curve = {"nistp256": ec.SECP256R1(), "nistp384": ec.SECP384R1(), "nistp521": ec.SECP521R1()}[curve_name]
    return ec.generate_private_key(curve).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def _client_share(kex: str) -> bytes:
    if kex in ("curve25519-sha256", "curve25519-sha256@libssh.org"):
        return _x25519()
    if kex == "curve448-sha512":
        return _x448()
    if kex.startswith("ecdh-sha2-"):
        return _ec_point(kex[len("ecdh-sha2-"):])
    if kex == "mlkem768x25519-sha256":
        return _mlkem_ek(3) + _x25519()  # RFC 10042: C_INIT = C_PK2 (ML-KEM) || C_PK1 (classical)
    if kex == "mlkem768nistp256-sha256":
        return _mlkem_ek(3) + _ec_point("nistp256")
    if kex == "mlkem1024nistp384-sha384":
        return _mlkem_ek(4) + _ec_point("nistp384")
    if kex in ("sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"):
        return os.urandom(SNTRUP761_PK) + _x25519()  # OpenSSH kexsntrup761x25519.c: sntrup761 pk || X25519
    if kex == "mlkem512-sha256":
        return _mlkem_ek(2)
    if kex == "mlkem768-sha256":
        return _mlkem_ek(3)
    if kex == "mlkem1024-sha384":
        return _mlkem_ek(4)
    raise ValueError(kex)


def _dh_public(bits: int) -> int:
    """A valid DH public value for a ``bits``-bit safe-prime group (RFC 4253 8: 1 < e < p - 1): below 2^(bits-1),
    which every such modulus exceeds, with more than one bit set."""
    return secrets.randbits(bits - 2) | (1 << (bits - 3)) | 3


# ----------------------------------------------------------------------------- one exchange
def _client_kexinit(kex: str, host_key_algs: list[str], lists: dict[str, list[str]]) -> bytes:
    # The server's own cipher, MAC and compression lists: negotiation cannot fail on them, and they are never used.
    return (bytes([MSG_KEXINIT]) + os.urandom(16) + _names([kex]) + _names(host_key_algs)
            + _names(lists.get("ciphers_c2s") or ["aes128-ctr"]) + _names(lists.get("ciphers_s2c") or ["aes128-ctr"])
            + _names(lists.get("macs_c2s") or ["hmac-sha2-256"]) + _names(lists.get("macs_s2c") or ["hmac-sha2-256"])
            + _names(lists.get("compression_c2s") or ["none"]) + _names(lists.get("compression_s2c") or ["none"])
            + _names([]) + _names([]) + b"\x00" + b"\x00\x00\x00\x00")


def exchange(sock: socket.socket, lists: dict[str, list[str]], kex: str, host_key_algs: list[str],
             deadline: float) -> dict[str, Any]:
    """After ``read_kexinit`` on ``sock``: one key-exchange start that makes the server send its host key."""
    out: dict[str, Any] = {}
    try:
        sock.sendall(_packet(_client_kexinit(kex, host_key_algs, lists)))
        if kex.startswith("rsa"):  # RFC 4432: KEXRSA_PUBKEY carries K_S before the client sends anything
            r = _Reader(_recv_message(sock, deadline, (MSG_KEX_INIT,))[1:])
            k_s, sig_alg = r.string(), None
        else:
            if kex.startswith("diffie-hellman-group-exchange"):
                sock.sendall(_packet(bytes([MSG_GEX_REQUEST]) + struct.pack("!III", *GEX_REQUEST)))
                g = _Reader(_recv_message(sock, deadline, (MSG_GEX_GROUP,))[1:])
                p, gen = g.mpint(), g.mpint()
                if p.bit_length() < 512 or not 1 < gen < p:
                    raise _Fail("unusable DH group exchange group")
                out["gex_modulus_bits"] = p.bit_length()
                e = pow(gen, secrets.randbits(256) | 1, p)
                sock.sendall(_packet(bytes([MSG_GEX_INIT]) + _mpint(e)))
                reply = MSG_GEX_REPLY
            elif kex in _DH_BITS:
                sock.sendall(_packet(bytes([MSG_KEX_INIT]) + _mpint(_dh_public(_DH_BITS[kex]))))
                reply = MSG_KEX_REPLY
            else:
                sock.sendall(_packet(bytes([MSG_KEX_INIT]) + _string(_client_share(kex))))
                reply = MSG_KEX_REPLY
            r = _Reader(_recv_message(sock, deadline, (reply,))[1:])
            k_s = r.string()
            r.string()  # the server's share (mpint f, Q_S or S_REPLY): not needed
            sig = _Reader(r.string())
            sig_alg = sig.text()[:64]
        out.update(parse_host_key(k_s))
        out["signature_algorithm"] = sig_alg
        return out
    except EOFError:
        raise _Fail("the server closed the connection during the key exchange") from None
    except ValueError as exc:
        raise _Fail(f"malformed key exchange reply ({exc})") from None
    finally:
        try:  # SSH_MSG_DISCONNECT, reason 11 (by application): the server logs a clean disconnect
            sock.sendall(_packet(bytes([MSG_DISCONNECT]) + struct.pack("!I", 11) + _string(b"host key read")
                                 + _string(b"")))
        except OSError:
            pass


# ----------------------------------------------------------------------------- host-key blobs
def _fingerprints(blob: bytes) -> dict[str, str]:
    digest = hashlib.sha256(blob).digest()
    return {"fingerprint": "SHA256:" + base64.b64encode(digest).decode().rstrip("="),
            "fingerprint_sha256": digest.hex()}


def _when(seconds: int) -> str:
    if seconds >= 2 ** 64 - 1:
        return "forever"
    try:
        return _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return "forever"


def _plain_key(name: str, r: _Reader) -> dict[str, Any]:
    """Size facts of the public-key fields that follow the type name (OpenSSH PROTOCOL / RFC 4253, 5656, 8709)."""
    if name == "ssh-rsa":
        r.mpint()
        return {"bits": r.mpint().bit_length()}
    if name == "ssh-dss":
        p = r.mpint()
        r.mpint(), r.mpint(), r.mpint()
        return {"bits": p.bit_length()}
    if name.startswith("ecdsa-sha2-") or name.startswith("sk-ecdsa-sha2-"):
        curve = r.text()[:32]
        r.string()
        bits = {"nistp256": 256, "nistp384": 384, "nistp521": 521}.get(curve)
        out: dict[str, Any] = {"bits": bits, "curve": curve}
        if name.startswith("sk-"):
            out["application"] = r.text()[:100]
        return out
    if name in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        r.string()
        out = {"bits": 256}
        if name.startswith("sk-"):
            out["application"] = r.text()[:100]
        return out
    if name == "ssh-ed448":
        r.string()
        return {"bits": 448}
    return {"bits": None}


def _certificate(name: str, r: _Reader) -> dict[str, Any]:
    """OpenSSH certificate fields (PROTOCOL.certkeys): the certified key, serial, type, key id, principals, validity,
    and the CA's key and signature algorithm."""
    key_type = name.replace("-cert-v01@openssh.com", "")
    r.string()  # nonce
    key = _plain_key(key_type, r)
    serial, ctype, key_id = r.u64(), r.u32(), r.text()[:200]
    principals_r = _Reader(r.string())
    principals = []
    while principals_r.pos < len(principals_r.data) and len(principals) < 20:
        principals.append(principals_r.text()[:200])
    valid_after, valid_before = r.u64(), r.u64()
    r.string(), r.string(), r.string()  # critical options, extensions, reserved
    ca_blob = r.string()
    sig = _Reader(r.string())
    ca = parse_host_key(ca_blob)
    cert = {"cert_type": {1: "user", 2: "host"}.get(ctype, str(ctype)), "serial": serial, "key_id": key_id,
            "principals": principals, "valid_after": _when(valid_after), "valid_before": _when(valid_before),
            "ca": {"type": ca.get("type"), "bits": ca.get("bits"), "fingerprint": ca.get("fingerprint"),
                   "fingerprint_sha256": ca.get("fingerprint_sha256")},
            "signature_algorithm": sig.text()[:64]}
    return {"key_type": key_type, **key, "certificate": cert}


def _x509v3(name: str, r: _Reader) -> dict[str, Any]:
    """RFC 6187 x509v3-* host keys: a certificate chain; the leaf's key and validity."""
    from zs_scan_node.certparse import cert_facts, load_certs

    count = r.u32()
    if not count:
        return {"bits": None}
    leaf = r.string()
    for cert in load_certs(leaf):
        facts = cert_facts(cert, "ssh-x509")
        return {"bits": facts.get("key_size"), "key_type": facts.get("key_alg"), "chain_length": count,
                "x509": {k: facts.get(k) for k in ("subject", "issuer", "not_before", "not_after", "sig_alg",
                                                   "fingerprint_sha256", "self_signed")}}
    return {"bits": None, "chain_length": count}


def parse_host_key(blob: bytes) -> dict[str, Any]:
    """Facts of one public host key or certificate blob as the server sent it.  Never raises."""
    out: dict[str, Any] = {"type": "unknown", "bits": None, **_fingerprints(blob)}
    r = _Reader(blob)
    try:
        name = r.string().decode("ascii")
        if not name or len(name) > 64 or not name.isprintable():
            return out
        out["type"] = name
        if name.endswith("-cert-v01@openssh.com"):
            out.update(_certificate(name, r))
        elif name.startswith("x509v3-"):
            out.update(_x509v3(name, r))
        else:
            out.update(_plain_key(name, r))
    except (ValueError, UnicodeDecodeError, struct.error) as exc:
        out["parse_error"] = exc.__class__.__name__
    return out


# ----------------------------------------------------------------------------- the whole server
def _primary(keys: list[dict[str, Any]]) -> dict[str, Any] | None:
    plain = [k for k in keys if k.get("type") in _PRIMARY_ORDER]
    pick = min(plain, key=lambda k: _PRIMARY_ORDER.index(k["type"])) if plain else (keys[0] if keys else None)
    if pick is None:
        return None
    return {"key_type": pick.get("key_type") or pick.get("type"), "bits": pick.get("bits"),
            "fingerprint_sha256": pick.get("fingerprint_sha256")}


def read_server(open_conn: Callable[[], socket.socket], deadline: float,
                timeout: float = EXCHANGE_TIMEOUT) -> dict[str, Any]:
    """KEXINIT lists and every host-key family of one SSH server.

    ``open_conn()`` returns a connected socket; it raises Stop when no further connection may be made (budget,
    pacing, stop-all, never-scan) and tlsprobe.ProbeError for a connect failure.  The first connection must succeed:
    its failure (Stop, connect error, no banner, no KEXINIT, ServerRefused) is raised, as the endpoint was not read.
    Later failures leave their family in ``host_keys_unread`` with the reason; a Stop or a refusal ends the reads.
    """
    def until() -> float:
        return min(deadline, time.monotonic() + timeout)

    sock = open_conn()
    try:
        hello = read_kexinit(sock, until())
    except BaseException:
        sock.close()
        raise
    lists = hello["lists"]
    out: dict[str, Any] = {"banner": hello["banner"], **lists}
    if hello["pre_banner"]:
        out["pre_banner"] = hello["pre_banner"][:3]
    kex = choose_kex(lists.get("kex") or [])
    groups = families(lists.get("host_key_algs") or [])
    keys: list[dict[str, Any]] = []
    unread: list[dict[str, Any]] = []
    status = "complete"
    if kex is None:
        sock.close()
        out.update({"host_keys": [], "host_keys_status": "kex_unsupported",
                    "host_keys_unread": [{"algorithms": g, "reason": "kex_unsupported"} for g in groups]})
        out["host_key"] = None
        return out
    stopped: str | None = None
    for i, algs in enumerate(groups):
        if stopped:
            unread.append({"algorithms": algs, "reason": stopped})
            continue
        try:
            if i > 0:
                sock = None
                try:
                    sock = open_conn()
                except Stop as exc:
                    stopped = exc.reason[:200]
                    unread.append({"algorithms": algs, "reason": stopped})
                    status = "server_refused" if stopped.startswith("server_refused") else "partial"
                    continue
                except T.ProbeError as exc:
                    unread.append({"algorithms": algs, "reason": f"{exc.code}: {exc.detail}"[:200]})
                    status = "partial"
                    continue
                try:
                    again = read_kexinit(sock, until())
                except ServerRefused as exc:
                    stopped = f"server_refused: {exc}"[:200]
                    unread.append({"algorithms": algs, "reason": stopped})
                    status = "server_refused"
                    continue
                except T.ProbeError as exc:
                    unread.append({"algorithms": algs, "reason": f"{exc.code}: {exc.detail}"[:200]})
                    status = "partial"
                    continue
                lists_now = again["lists"]
            else:
                lists_now = lists
            key = exchange(sock, lists_now, kex, algs, until())
            key["algorithms"] = algs
            key["kex_used"] = kex
            key["read_by"] = "kex_reply"
            gex = key.pop("gex_modulus_bits", None)
            if gex is not None:
                out.setdefault("gex_modulus_bits", gex)
            keys.append(key)
        except _Fail as exc:
            unread.append({"algorithms": algs, "reason": exc.reason[:200]})
            status = "partial"
        except T.ProbeError as exc:
            unread.append({"algorithms": algs, "reason": f"{exc.code}: {exc.detail}"[:200]})
            status = "partial"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    out.update({"host_keys": keys, "host_keys_status": status, "host_key": _primary(keys)})
    if unread:
        out["host_keys_unread"] = unread
    return out
