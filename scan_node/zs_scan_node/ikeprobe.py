"""IKE proposal probing of VPN gateways (UDP 500, and 4500 with the RFC 3948 non-ESP marker).

Only the FIRST message of an exchange is ever sent, so no IKE SA is completed and no credential is involved:
  * IKEv2 IKE_SA_INIT requests (RFC 7296 section 1.2): HDR, [N(COOKIE)], SA, KE, Ni [, N(INTERMEDIATE_EXCHANGE_SUPPORTED)].
    One retry with the group named by INVALID_KE_PAYLOAD (RFC 7296 section 1.2) or with the responder's COOKIE
    (section 2.6, same SPI and nonce, cookie as the first payload).
  * IKEv1 Main Mode message 1 (RFC 2409 section 5: HDR, SA) and Aggressive Mode message 1 (HDR, SA, KE, Ni, IDii).
A responder answers IKE_SA_INIT with the one proposal it chose (SA payload), N(NO_PROPOSAL_CHOSEN), N(INVALID_KE_PAYLOAD)
naming the group it wants, or N(COOKIE); IKEv1 answers with the chosen transform or an Informational
N(NO-PROPOSAL-CHOSEN).  Codepoints are from the IANA "IKEv2 Parameters" and "IKE Attributes" registries.

Post-quantum: RFC 9370 Additional Key Exchange transform types 6-12 carry ML-KEM ids 35-37 (IANA, from
draft-kampanakis-ml-kem-ikev2).  A responder without RFC 9370 skips a proposal that carries them (RFC 9370 section 2.2.2),
so the probe offers the same algorithms without ADDKE as a further proposal and reads which one was chosen.

Key shares are real group elements: ECP and Curve25519/448 keys from ``cryptography`` (RFC 5903 section 7: x || y),
RFC 5114 groups 22-24 as g^x mod p (RFC 6989 requires responders to check them), and for the safe-prime MODP groups a
random value 1 < y < p of the prime's length (all that RFC 6989 section 2.1 lets a responder check).  The private
halves are thrown away: no shared secret is ever computed.

This module opens no sockets.  ``IkeProber`` gets a ``send(packet, ident) -> bytes | None`` callable from the
collector, which applies the network gate, the rate limiter, the per-target spacing and stop/never-scan.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

# ----------------------------------------------------------------------------- IKEv2 codepoints (RFC 7296, IANA)
V2_SA, V2_KE, V2_NONCE, V2_NOTIFY, V2_VID = 33, 34, 40, 41, 43
V2_IKE_SA_INIT = 34
V2_FLAG_I, V2_FLAG_R = 0x08, 0x20
T_ENCR, T_PRF, T_INTEG, T_KE, T_ADDKE1 = 1, 2, 3, 4, 6
ATTR_KEY_LENGTH = 14
N_INVALID_SYNTAX, N_NO_PROPOSAL_CHOSEN, N_INVALID_KE_PAYLOAD = 7, 14, 17
N_COOKIE, N_INTERMEDIATE_EXCHANGE_SUPPORTED = 16390, 16438
N_NAMES = {1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
           9: "INVALID_MESSAGE_ID", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED",
           16390: "COOKIE", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
           16404: "MULTIPLE_AUTH_SUPPORTED", 16430: "IKEV2_FRAGMENTATION_SUPPORTED",
           16431: "SIGNATURE_HASH_ALGORITHMS", 16438: "INTERMEDIATE_EXCHANGE_SUPPORTED", 16418: "CHILDLESS_IKEV2_SUPPORTED",
           16406: "REDIRECT_SUPPORTED", 16435: "USE_PPK"}

ENCR = {1: "DES-IV64", 2: "DES", 3: "3DES", 5: "IDEA", 6: "CAST", 7: "BLOWFISH", 11: "NULL", 12: "AES-CBC",
        13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12",
        20: "AES-GCM-16", 23: "CAMELLIA-CBC", 28: "CHACHA20-POLY1305"}
AEAD = frozenset({14, 15, 16, 18, 19, 20, 28})
PRF = {1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "AES128-XCBC", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512",
       8: "AES128-CMAC"}
INTEG = {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK-MD5", 5: "AES-XCBC-96", 6: "HMAC-MD5-128",
         7: "HMAC-SHA1-160", 8: "AES-CMAC-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192",
         14: "HMAC-SHA2-512-256"}
GROUPS = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
          17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 22: "MODP-1024-S160",
          23: "MODP-2048-S224", 24: "MODP-2048-S256", 25: "ECP-192", 26: "ECP-224", 28: "BRAINPOOL-P256R1",
          29: "BRAINPOOL-P384R1", 30: "BRAINPOOL-P512R1", 31: "CURVE25519", 32: "CURVE448", 35: "ML-KEM-512",
          36: "ML-KEM-768", 37: "ML-KEM-1024"}

# What counts as weak (RFC 8247 sections 2.1-2.4 and RFC 9395): 64-bit block ciphers, MD5/SHA-1 in the PRF and
# integrity, MODP groups below 2048 bits, the RFC 5114 groups (RFC 8247: SHOULD NOT) and the 192-bit ECP group.
WEAK_ENCR = (2, 3, 7)
WEAK_PRF = (1, 2)
WEAK_INTEG = (1, 2, 3, 4, 6, 7)
WEAK_DH = (1, 2, 5, 22, 23, 24, 25)
PQ_KE = (36, 37, 35)

# What the probes offer.  Lists hold every algorithm of a type the probe is not testing, weak ones included, so that
# the only thing a probe asks is the transform type under test.
CBC_ALL = [(12, 256), (12, 192), (12, 128), (13, 256), (13, 128), (23, 256), (23, 128), (3, None), (7, 128), (2, None)]
AEAD_ALL = [(20, 256), (20, 128), (19, 256), (18, 256), (16, 256), (16, 128), (28, None)]
CBC_STRONG = [(12, 256), (12, 128)]
AEAD_STRONG = [(20, 256), (20, 128), (28, None)]
PRF_ALL = [7, 6, 5, 8, 4, 2, 1]
PRF_STRONG = [7, 6, 5]
INTEG_ALL = [14, 13, 12, 8, 5, 2, 1, 7, 6]
INTEG_STRONG = [14, 13, 12]
DH_STRONG = [31, 19, 20, 21, 32, 14, 15, 16, 28, 29, 30]
DH_ALL = DH_STRONG + [17, 18, 26, 24, 23, 5, 2, 22, 25, 1]

# ----------------------------------------------------------------------------- key shares
_MODP_BYTES = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024}
# RFC 5114 section 2.1-2.3 (p, g, q), read from OpenSSL's named groups dh_1024_160, dh_2048_224, dh_2048_256.
RFC5114 = {
    22: (
        int("b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c69a6a9dca52d23b616073e28675a23d189838ef1e2ee652c0"
            "13ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd7098488e9c219a73724effd6fae5644738faa31a4ff55bccc0"
            "a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708df1fb2bc2e4a4371", 16),
        int("a4d1cbd5c3fd34126765a442efb99905f8104dd258ac507fd6406cff14266d31266fea1e5c41564b777e690f5504f213"
            "160217b4b01b886a5e91547f9e2749f4d7fbd7d3b9a92ee1909d0d2263f80a76a6a24c087a091f531dbf0a0169b6a28a"
            "d662a4d18e73afa32d779d5918d08bc8858f4dcef97c2a24855e6eeb22b3b2e5", 16),
        int("f518aa8781a8df278aba4e7d64b7cb9d49462353", 16),
    ),
    23: (
        int("ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1b54b1597b61d0a75e6fa141df95a56dbaf9a3c407ba1df15"
            "eb3d688a309c180e1de6b85a1274a0a66d3f8152ad6ac2129037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12207"
            "c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0a0b9c49708b3bf8a317091883681286130bc8985db1602e714415d9330"
            "278273c7de31efdc7310f7121fd5a07415987d9adc0a486dcdf93acc44328387315d75e198c641a480cd86a1b9e587e8"
            "be60e69cc928b2b9c52172e413042e9b23f10b0e16e79763c9b53dcf4ba80a29e3fb73c16b8e75b97ef363e2ffa31f71"
            "cf9de5384e71b81c0ac4dffe0c10e64f", 16),
        int("ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf74866a08cfe4ffe3a6824a4e10b9a6f0dd921f01a70c4afa"
            "ab739d7700c29f52c57db17c620a8652be5e9001a8d66ad7c17669101999024af4d027275ac1348bb8a762d0521bc98a"
            "e247150422ea1ed409939d54da7460cdb5f6c6b250717cbef180eb34118e98d119529a45d6f834566e3025e316a330ef"
            "bb77a86f0c1ab15b051ae3d428c8f8acb70a8137150b8eeb10e183edd19963ddd9e263e4770589ef6aa21e7f5f2ff381"
            "b539cce3409d13cd566afbb48d6c019181e1bcfe94b30269edfe72fe9b6aa4bd7b5a0f1c71cfff4c19c418e1f6ec0179"
            "81bc087f2a7065b384b890d3191f2bfa", 16),
        int("801c0d34c58d93fe997177101f80535a4738cebcbf389a99b36371eb", 16),
    ),
    24: (
        int("87a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa30"
            "16c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b"
            "6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0e"
            "f13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026"
            "c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f"
            "693877fad7ef09cadb094ae91e1a1597", 16),
        int("3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555"
            "be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b"
            "777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55"
            "a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915"
            "b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d4795451"
            "5e2327cfef98c582664b4c0f6cc41659", 16),
        int("8cf83642a709a097b447997640129da299b1a47d1eb3750ba308b0fe64f5fbd3", 16),
    ),
}


def _ec_share(curve_name: str, size: int) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec

        curve = getattr(ec, curve_name)()
        nums = ec.generate_private_key(curve).public_key().public_numbers()
        return nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")
    except Exception:  # a curve this OpenSSL build does not offer: the group is simply not offered
        return None


def key_share(group: int) -> bytes | None:
    """A public value for ``group`` (or None if this node cannot make one; the group is then not offered)."""
    if group in _MODP_BYTES:
        n = _MODP_BYTES[group]
        # p's top 64 bits are all ones (RFC 2409 / RFC 3526 primes), so a first byte below 0x80 keeps y < p - 1
        return bytes([1 + os.urandom(1)[0] % 0x7F]) + os.urandom(n - 1)
    if group in RFC5114:
        p, g, q = RFC5114[group]
        x = 2 + int.from_bytes(os.urandom(len(format(q, "x")) // 2 + 8), "big") % (q - 3)
        return pow(g, x, p).to_bytes((p.bit_length() + 7) // 8, "big")
    ec_curves = {19: ("SECP256R1", 32), 20: ("SECP384R1", 48), 21: ("SECP521R1", 66), 25: ("SECP192R1", 24),
                 26: ("SECP224R1", 28), 28: ("BrainpoolP256R1", 32), 29: ("BrainpoolP384R1", 48),
                 30: ("BrainpoolP512R1", 64)}
    if group in ec_curves:
        return _ec_share(*ec_curves[group])
    try:
        if group == 31:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            return X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if group == 32:
            from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            return X448PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:
        return None
    return None


_SHAREABLE: dict[int, bool] = {}


def can_share(group: int) -> bool:
    if group not in _SHAREABLE:
        _SHAREABLE[group] = key_share(group) is not None
    return _SHAREABLE[group]


# ----------------------------------------------------------------------------- IKEv2 messages
@dataclass
class Proposal:
    encr: list[tuple[int, int | None]]
    prf: list[int]
    integ: list[int]
    dh: list[int]
    addke: list[int] = field(default_factory=list)


def _attr_keylen(bits: int | None) -> bytes:
    return struct.pack("!HH", 0x8000 | ATTR_KEY_LENGTH, bits) if bits else b""


def _v2_transforms(p: Proposal) -> list[bytes]:
    out: list[tuple[int, int, bytes]] = []
    out += [(T_ENCR, tid, _attr_keylen(bits)) for tid, bits in p.encr]
    out += [(T_PRF, tid, b"") for tid in p.prf]
    out += [(T_INTEG, tid, b"") for tid in p.integ]
    out += [(T_KE, tid, b"") for tid in p.dh]
    out += [(T_ADDKE1, tid, b"") for tid in p.addke]
    raw = []
    for i, (ttype, tid, attrs) in enumerate(out):
        last = 0 if i == len(out) - 1 else 3
        raw.append(struct.pack("!BBHBBH", last, 0, 8 + len(attrs), ttype, 0, tid) + attrs)
    return raw


def _v2_sa(proposals: list[Proposal]) -> bytes:
    body = b""
    for n, p in enumerate(proposals, 1):
        transforms = _v2_transforms(p)
        inner = struct.pack("!BBBB", n, 1, 0, len(transforms)) + b"".join(transforms)  # protocol 1 = IKE, no SPI
        last = 0 if n == len(proposals) else 2
        body += struct.pack("!BBH", last, 0, 4 + len(inner)) + inner
    return body


def build_v2_sa_init(spi_i: bytes, proposals: list[Proposal], ke_group: int, ke_data: bytes, nonce: bytes,
                     cookie: bytes | None = None, intermediate: bool = False) -> bytes:
    """An IKE_SA_INIT request (RFC 7296 sections 3.1-3.4, 3.9, 3.10)."""
    payloads: list[tuple[int, bytes]] = []
    if cookie is not None:
        payloads.append((V2_NOTIFY, struct.pack("!BBH", 0, 0, N_COOKIE) + cookie))
    payloads.append((V2_SA, _v2_sa(proposals)))
    payloads.append((V2_KE, struct.pack("!HH", ke_group, 0) + ke_data))
    payloads.append((V2_NONCE, nonce))
    if intermediate:
        payloads.append((V2_NOTIFY, struct.pack("!BBH", 0, 0, N_INTERMEDIATE_EXCHANGE_SUPPORTED)))
    body = b""
    for i, (_ptype, data) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        body += struct.pack("!BBH", nxt, 0, 4 + len(data)) + data
    first = payloads[0][0]
    header = spi_i + b"\x00" * 8 + struct.pack("!BBBBII", first, 0x20, V2_IKE_SA_INIT, V2_FLAG_I, 0, 28 + len(body))
    return header + body


@dataclass
class V2Answer:
    kind: str  # accepted | no_proposal | invalid_ke | cookie | error
    proposal: int | None = None
    chosen: dict[int, tuple[int, int | None]] = field(default_factory=dict)
    group: int | None = None
    cookie: bytes | None = None
    notifies: list[str] = field(default_factory=list)
    vendor_ids: list[str] = field(default_factory=list)


def _payloads(data: bytes, first: int, start: int, limit: int = 64):
    """(type, body) for each payload of a message, bounds-checked."""
    ptype, pos = first, start
    for _ in range(limit):
        if ptype == 0:
            return
        if pos + 4 > len(data):
            raise ValueError("truncated payload header")
        nxt, _crit, plen = struct.unpack("!BBH", data[pos:pos + 4])
        if plen < 4 or pos + plen > len(data):
            raise ValueError("bad payload length")
        yield ptype, data[pos + 4:pos + plen]
        ptype, pos = nxt, pos + plen
    raise ValueError("too many payloads")


def _parse_v2_sa(body: bytes) -> tuple[int, dict[int, tuple[int, int | None]]]:
    if len(body) < 8:
        raise ValueError("short SA")
    _last, _r, plen, num, _proto, spi_size, ntrans = struct.unpack("!BBHBBBB", body[:8])
    if plen > len(body) or plen < 8 + spi_size:
        raise ValueError("bad proposal length")
    pos = 8 + spi_size
    chosen: dict[int, tuple[int, int | None]] = {}
    for _ in range(min(ntrans, 32)):
        if pos + 8 > plen:
            raise ValueError("short transform")
        _l, _r2, tlen, ttype, _r3, tid = struct.unpack("!BBHBBH", body[pos:pos + 8])
        if tlen < 8 or pos + tlen > plen:
            raise ValueError("bad transform length")
        bits = None
        attrs = body[pos + 8:pos + tlen]
        if len(attrs) >= 4:
            atype, aval = struct.unpack("!HH", attrs[:4])
            if atype == 0x8000 | ATTR_KEY_LENGTH:
                bits = aval
        chosen.setdefault(ttype, (tid, bits))
        pos += tlen
    return num, chosen


def parse_v2(data: bytes, spi_i: bytes) -> V2Answer:
    """Parse an IKE_SA_INIT response for our SPI.  Raises ValueError if it is not one (or malformed)."""
    if len(data) < 28:
        raise ValueError("short IKE header")
    if data[:8] != spi_i:
        raise ValueError("not our SPI")
    first, version, exch, flags, msgid, length = struct.unpack("!BBBBII", data[16:28])
    if version >> 4 != 2:
        raise ValueError("not IKEv2")
    if exch != V2_IKE_SA_INIT or not flags & V2_FLAG_R or msgid != 0:
        raise ValueError("not an IKE_SA_INIT response")
    if length > len(data) or length < 28:
        raise ValueError("bad length")
    data = data[:length]
    out = V2Answer("error")
    notify_types: list[int] = []
    for ptype, body in _payloads(data, first, 28):
        if ptype == V2_SA:
            out.proposal, out.chosen = _parse_v2_sa(body)
        elif ptype == V2_NOTIFY and len(body) >= 4:
            _proto, spi_size, ntype = struct.unpack("!BBH", body[:4])
            ndata = body[4 + spi_size:]
            notify_types.append(ntype)
            out.notifies.append(N_NAMES.get(ntype, str(ntype)))
            if ntype == N_INVALID_KE_PAYLOAD and len(ndata) >= 2:
                out.group = struct.unpack("!H", ndata[:2])[0]
            elif ntype == N_COOKIE and 1 <= len(ndata) <= 64:
                out.cookie = ndata
        elif ptype == V2_VID:
            out.vendor_ids.append(body[:16].hex())
    if N_COOKIE in notify_types and out.cookie:
        out.kind = "cookie"
    elif N_INVALID_KE_PAYLOAD in notify_types and out.group:
        out.kind = "invalid_ke"
    elif N_NO_PROPOSAL_CHOSEN in notify_types:
        out.kind = "no_proposal"
    elif out.chosen:
        out.kind = "accepted"
    return out


# ----------------------------------------------------------------------------- IKEv1 messages (RFC 2408, 2409)
V1_SA, V1_P, V1_T, V1_KE, V1_ID, V1_HASH, V1_SIG, V1_NONCE, V1_N, V1_VID = 1, 2, 3, 4, 5, 8, 9, 10, 11, 13
V1_MAIN, V1_AGGRESSIVE, V1_INFO = 2, 4, 5
A_ENC, A_HASH, A_AUTH, A_GROUP, A_LIFE_TYPE, A_LIFE, A_KEYLEN = 1, 2, 3, 4, 11, 12, 14
V1_ENC = {1: "DES", 2: "IDEA", 3: "BLOWFISH", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES-CBC", 8: "CAMELLIA-CBC"}
V1_HASH_NAMES = {1: "MD5", 2: "SHA1", 3: "TIGER", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
V1_AUTH = {1: "PSK", 2: "DSS", 3: "RSA-SIG", 4: "RSA-ENC", 5: "RSA-ENC-REV", 9: "ECDSA-256", 10: "ECDSA-384",
           11: "ECDSA-521", 65001: "XAUTH-PSK", 65005: "XAUTH-RSA-SIG"}
V1_WEAK_ENC = (1, 5, 3)
V1_WEAK_HASH = (1, 2)
V1_WEAK_GROUP = (1, 2, 5)
V1_NOTIFY = {14: "NO-PROPOSAL-CHOSEN", 16: "PAYLOAD-MALFORMED", 18: "INVALID-ID-INFORMATION",
             13: "ATTRIBUTES-NOT-SUPPORTED", 24: "AUTHENTICATION-FAILED", 1: "INVALID-PAYLOAD-TYPE"}
V1_AUTHS = (1, 3, 65001)


@dataclass(frozen=True)
class V1Transform:
    enc: int
    keylen: int | None
    hash: int
    auth: int
    group: int


def _v1_transform(n: int, t: V1Transform, last: bool) -> bytes:
    attrs = struct.pack("!HH", 0x8000 | A_ENC, t.enc)
    if t.keylen:
        attrs += struct.pack("!HH", 0x8000 | A_KEYLEN, t.keylen)
    attrs += struct.pack("!HHHHHHHHHH", 0x8000 | A_HASH, t.hash, 0x8000 | A_AUTH, t.auth, 0x8000 | A_GROUP, t.group,
                         0x8000 | A_LIFE_TYPE, 1, 0x8000 | A_LIFE, 28800)
    body = struct.pack("!BBH", n, 1, 0) + attrs  # transform-id KEY_IKE
    return struct.pack("!BBH", 0 if last else V1_T, 0, 4 + len(body)) + body


def build_v1_first(cookie_i: bytes, transforms: list[V1Transform], aggressive: bool = False, ke_data: bytes = b"",
                   nonce: bytes = b"", ident: bytes = b"") -> bytes:
    """Main Mode message 1 (HDR, SA) or Aggressive Mode message 1 (HDR, SA, KE, Ni, IDii)."""
    tr = b"".join(_v1_transform(i + 1, t, i == len(transforms) - 1) for i, t in enumerate(transforms[:255]))
    prop_body = struct.pack("!BBBB", 1, 1, 0, min(len(transforms), 255)) + tr  # proposal 1, PROTO_ISAKMP, no SPI
    prop = struct.pack("!BBH", 0, 0, 4 + len(prop_body)) + prop_body
    sa_body = struct.pack("!II", 1, 1) + prop  # DOI IPSEC, SIT_IDENTITY_ONLY
    payloads: list[tuple[int, bytes]] = [(V1_SA, sa_body)]
    if aggressive:
        payloads += [(V1_KE, ke_data), (V1_NONCE, nonce),
                     (V1_ID, struct.pack("!BBH", 2, 17, 500) + ident)]  # ID_FQDN, UDP, 500
    body = b""
    for i, (_t, data) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        body += struct.pack("!BBH", nxt, 0, 4 + len(data)) + data
    exch = V1_AGGRESSIVE if aggressive else V1_MAIN
    return cookie_i + b"\x00" * 8 + struct.pack("!BBBBII", V1_SA, 0x10, exch, 0, 0, 28 + len(body)) + body


@dataclass
class V1Answer:
    kind: str  # accepted | no_proposal | notify | error
    exchange: int = 0
    transform: V1Transform | None = None
    notify: str | None = None
    vendor_ids: list[str] = field(default_factory=list)
    auth_payload: bool = False  # aggressive mode answered with HASH_R or SIG_R (never stored)


def _parse_v1_transform(body: bytes) -> V1Transform:
    if len(body) < 8:
        raise ValueError("short IKEv1 proposal")
    spi_size, ntrans = body[2], body[3]
    pos = 4 + spi_size
    if ntrans < 1 or pos + 8 > len(body):
        raise ValueError("no transform")
    _nxt, _r, tlen = struct.unpack("!BBH", body[pos:pos + 4])
    if tlen < 8 or pos + tlen > len(body):
        raise ValueError("bad transform length")
    attrs = body[pos + 8:pos + tlen]
    values: dict[int, int] = {}
    i = 0
    while i + 4 <= len(attrs) and len(values) < 32:
        atype, aval = struct.unpack("!HH", attrs[i:i + 4])
        if atype & 0x8000:
            values[atype & 0x7FFF] = aval
            i += 4
        else:  # TLV (life duration as 4 bytes)
            if i + 4 + aval > len(attrs):
                raise ValueError("bad attribute length")
            i += 4 + aval
    return V1Transform(values.get(A_ENC, 0), values.get(A_KEYLEN), values.get(A_HASH, 0), values.get(A_AUTH, 0),
                       values.get(A_GROUP, 0))


def parse_v1(data: bytes, cookie_i: bytes) -> V1Answer:
    if len(data) < 28 or data[:8] != cookie_i:
        raise ValueError("not our cookie")
    first, version, exch, _flags, _msgid, length = struct.unpack("!BBBBII", data[16:28])
    if version >> 4 != 1:
        raise ValueError("not IKEv1")
    if length > len(data) or length < 28:
        raise ValueError("bad length")
    if _flags & 0x01:  # encrypted: never expected in an answer to message 1
        return V1Answer("error", exch)
    out = V1Answer("error", exch)
    for ptype, body in _payloads(data[:length], first, 28):
        if ptype == V1_SA and len(body) >= 8:
            prop_area = body[8:]
            if len(prop_area) >= 4:
                _n, _r, plen = struct.unpack("!BBH", prop_area[:4])
                out.transform = _parse_v1_transform(prop_area[4:plen])
        elif ptype == V1_N and len(body) >= 8:
            ntype = struct.unpack("!H", body[6:8])[0]
            out.notify = V1_NOTIFY.get(ntype, str(ntype))
        elif ptype == V1_VID:
            out.vendor_ids.append(body[:16].hex())
        elif ptype in (V1_HASH, V1_SIG):
            out.auth_payload = True
    if out.transform is not None and exch in (V1_MAIN, V1_AGGRESSIVE):
        out.kind = "accepted"
    elif out.notify == "NO-PROPOSAL-CHOSEN":
        out.kind = "no_proposal"
    elif out.notify:
        out.kind = "notify"
    return out




# ----------------------------------------------------------------------------- the probe plan
def _name(table: dict[int, str], tid: int, bits: int | None = None) -> str:
    base = table.get(tid, f"#{tid}")
    return f"{base}-{bits}" if bits else base


class Budget:
    def __init__(self, limit: int) -> None:
        self.limit, self.used = max(int(limit), 1), 0

    def left(self) -> int:
        return self.limit - self.used


class Stop(Exception):
    """The packet budget is used up: end the probe plan."""


Sender = Callable[[bytes, bytes], "bytes | None"]
Pause = Callable[[float], bool]

# A responder keeps a half-open IKE SA for every IKE_SA_INIT (or Main Mode message 1) it accepts, and stops answering
# a peer that holds too many (strongSwan charon.block_threshold, default 5 per address, half-open timeout 30 s).
# Answers that are refusals (NO_PROPOSAL_CHOSEN, INVALID_KE_PAYLOAD) leave no state behind.  So the weak-class probes
# send the key share of a rarely used group (the "probe group") and read acceptance from INVALID_KE_PAYLOAD: the
# responder names a group only when a proposal is acceptable (RFC 7296 section 1.2), and keeps nothing.
PROBE_GROUPS = (32, 30, 29, 28)
HALF_OPEN_WAIT = 32.0

V2_CLASSES = ((T_KE, "dh", WEAK_DH), (T_ENCR, "encryption", WEAK_ENCR), (T_INTEG, "integrity", WEAK_INTEG),
              (T_PRF, "prf", WEAK_PRF))


class IkeProber:
    """Runs the probe plan against one UDP endpoint through ``send(packet, spi_or_cookie) -> answer bytes | None``.

    full mode, in order of value: IKEv2 baseline (everything offered: is IKEv2 spoken, what does the gateway pick),
    IKEv1 Main Mode baseline, IKEv2 weak classes (DH, encryption, integrity, PRF; stateless), the IKEv2
    post-quantum probe, an all-weak IKEv1 transform set, Aggressive Mode, IKEv1 weak classes, then enumeration of
    further weak members while the budget lasts.  fragile mode: one strong IKEv2 proposal, one all-weakest IKEv2
    proposal and one IKEv1 Main Mode message.  ``primary=False`` (a second IKE port of the same address) sends only
    the IKEv2 baseline, and the IKEv1 baseline when IKEv2 is silent.

    ``pause(seconds) -> bool`` waits (interruptibly) when a gateway that answered before goes silent, which is how
    a half-open limit shows; it is used once per endpoint and returns False when there is no time or a stop."""

    def __init__(self, send: Sender, budget: int, mode: str = "full", primary: bool = True,
                 pause: Pause | None = None) -> None:
        self.send = send
        self.budget = Budget(budget)
        self.mode = mode
        self.primary = primary
        self.pause = pause
        self.paused = False
        self.answers = 0
        self.unknown: list[str] = []
        self.v2: dict[str, Any] = {"supported": None}
        self.v1: dict[str, Any] = {"supported": None}
        self.dh_ok: int | None = None
        self.cookie_required = False
        self.probe_group = next((g for g in PROBE_GROUPS if can_share(g)), None)

    # -------------------------------------------------------------- transport
    def _exchange(self, packet: bytes, ident: bytes) -> bytes | None:
        if self.budget.left() <= 0:
            raise Stop("budget")
        self.budget.used += 1
        raw = self.send(packet, ident)
        if raw is None and self.answers and not self.paused and self.pause is not None and self.budget.left() > 0:
            self.paused = True  # the gateway answered before: wait for its half-open SAs to expire, retry once
            if self.pause(HALF_OPEN_WAIT):
                self.budget.used += 1
                raw = self.send(packet, ident)
        if raw is not None:
            self.answers += 1
        return raw

    def _v2(self, proposals: list[Proposal], ke_group: int, retry_ke: bool = True,
            intermediate: bool = False) -> V2Answer | None:
        offered = {g for p in proposals for g in p.dh}
        spi, nonce, ke = os.urandom(8), os.urandom(32), key_share(ke_group)
        if ke is None or not proposals:
            return None
        cookie = None
        for _attempt in range(2):
            raw = self._exchange(build_v2_sa_init(spi, proposals, ke_group, ke, nonce, cookie, intermediate), spi)
            if raw is None:
                return None
            try:
                ans = parse_v2(raw, spi)
            except ValueError as exc:  # a hostile or broken answer costs this probe, never the plan
                return V2Answer("error", notifies=[f"malformed: {exc}"[:80]])
            if ans.kind == "cookie" and cookie is None:
                self.cookie_required = True
                cookie = ans.cookie
                continue
            if ans.kind == "invalid_ke" and retry_ke and ans.group in offered and ans.group != ke_group \
                    and can_share(ans.group):
                retry = self._v2(proposals, ans.group, retry_ke=False, intermediate=intermediate)
                return retry if retry is not None and retry.kind == "accepted" else ans
            return ans
        return None

    def _v1(self, transforms: list[V1Transform], aggressive: bool = False, group: int = 2) -> V1Answer | None:
        cookie = os.urandom(8)
        if aggressive:
            packet = build_v1_first(cookie, transforms, True, key_share(group) or b"", os.urandom(20),
                                    b"zs-probe.invalid")
        else:
            packet = build_v1_first(cookie, transforms)
        raw = self._exchange(packet, cookie)
        if raw is None:
            return None
        try:
            return parse_v1(raw, cookie)
        except ValueError as exc:
            return V1Answer("error", notify=f"malformed: {exc}"[:80])

    # -------------------------------------------------------------- IKEv2
    @staticmethod
    def _props(encr=None, prf=None, integ=None, dh=None, addke=None) -> list[Proposal]:
        """Proposals with the given transform types restricted; the others offer everything, weak ones included, so
        a probe asks about one transform type only.  AEAD and other ciphers go in separate proposals (RFC 5282
        section 8: an AEAD proposal carries no integrity transform)."""
        dh = [g for g in (dh or DH_ALL) if can_share(g)]
        prf = prf or PRF_ALL
        encr = encr if encr is not None else CBC_ALL + AEAD_ALL
        aead = [e for e in encr if e[0] in AEAD]
        cbc = [e for e in encr if e[0] not in AEAD]
        out = []
        if aead and integ is None:
            out.append(Proposal(aead, prf, [], dh, list(addke or [])))
        if cbc:
            out.append(Proposal(cbc, prf, integ or INTEG_ALL, dh, list(addke or [])))
        return out

    def _note(self, ans: V2Answer) -> None:
        notes = self.v2.setdefault("notifies", [])
        for n in ans.notifies:
            if n not in notes and n != "COOKIE" and len(notes) < 12:
                notes.append(n)

    def _v2_baseline(self, strong_only: bool) -> None:
        if strong_only:
            props = self._props(encr=CBC_STRONG + AEAD_STRONG, prf=PRF_STRONG, integ=INTEG_STRONG, dh=DH_STRONG)
            props.insert(0, Proposal(AEAD_STRONG, PRF_STRONG, [], [g for g in DH_STRONG if can_share(g)]))
        else:
            props = self._props()
        ans = self._v2(props, next(g for g in (19, 31, 14) if can_share(g)))
        if ans is None:
            return
        # any IKE_SA_INIT response (even NO_PROPOSAL_CHOSEN) proves IKEv2; an IKEv1-format answer means IKEv1 only
        self.v2["supported"] = not (ans.kind == "error" and any("not IKEv2" in n for n in ans.notifies))
        self.v2["baseline"] = ans.kind
        self._note(ans)
        if ans.kind == "accepted":
            c = ans.chosen
            self.v2["chosen"] = {
                "encryption": _name(ENCR, *c[T_ENCR]) if T_ENCR in c else None,
                "prf": _name(PRF, c[T_PRF][0]) if T_PRF in c else None,
                "integrity": _name(INTEG, c[T_INTEG][0]) if T_INTEG in c and c[T_INTEG][0] else None,
                "group": _name(GROUPS, c[T_KE][0]) if T_KE in c else None,
            }
            if T_KE in c:
                self.dh_ok = c[T_KE][0]
            if ans.vendor_ids:
                self.v2["vendor_ids"] = ans.vendor_ids[:8]
        elif ans.kind == "no_proposal" and not strong_only:
            self.v2["proposals_accepted"] = False  # everything was offered: this gateway accepts no IKEv2 proposal

    def _v2_usable(self) -> bool:
        return bool(self.v2.get("supported")) and self.v2.get("proposals_accepted") is not False

    def _v2_class_probe(self, ttype: int, members: list[int]) -> tuple[str, int | None]:
        """('yes', member | None) | ('no', None) | ('unknown', None): is any of ``members`` acceptable?"""
        pg = self.probe_group
        if ttype == T_KE:
            groups = members + ([pg] if pg and pg not in members else [])
            ans = self._v2(self._props(dh=groups), pg or members[0], retry_ke=False)
        else:
            encr = [(m, 128 if m == 7 else None) for m in members] if ttype == T_ENCR else None
            props = self._props(encr=encr, integ=members if ttype == T_INTEG else None,
                                prf=members if ttype == T_PRF else None)
            if ttype == T_INTEG:
                props = [p for p in props if p.integ]
            ans = self._v2(props, pg or self.dh_ok or 14, retry_ke=pg is None)
        if ans is None:
            return "unknown", None
        self._note(ans)
        if ans.kind == "invalid_ke":
            return "yes", (ans.group if ttype == T_KE else (members[0] if len(members) == 1 else None))
        if ans.kind == "accepted":
            got = ans.chosen.get(ttype)
            if ttype == T_KE and not (got and got[0] in members):
                self.probe_group = None  # the gateway accepts the probe group itself: this answer says nothing
                return "unknown", None
            return "yes", got[0] if got and got[0] in members else (members[0] if len(members) == 1 else None)
        if ans.kind == "no_proposal":
            return "no", None
        return "unknown", None

    def _weak_v2(self, ttype: int, key: str, members: tuple[int, ...], enumerate_all: bool) -> None:
        table = {T_KE: GROUPS, T_ENCR: ENCR, T_INTEG: INTEG, T_PRF: PRF}[ttype]
        state = self.v2.setdefault("weak", {}).setdefault(key, {"accepted": [], "complete": False})
        if state["complete"]:
            return
        remaining = [m for m in members if (ttype != T_KE or can_share(m)) and _name(table, m) not in state["accepted"]]
        remaining = [m for m in remaining if m not in state.get("refused_ids", [])]
        while remaining:
            if ttype == T_KE or len(remaining) == 1 or not state.get("any"):
                verdict, member = self._v2_class_probe(ttype, remaining)
            else:  # the class is known to be accepted: attribute members one at a time
                verdict, member = self._v2_class_probe(ttype, remaining[:1])
                if verdict == "no":
                    state.setdefault("refused_ids", []).append(remaining.pop(0))
                    continue
            if verdict == "unknown":
                self.unknown.append(f"IKEv2 weak {key}: no answer")
                return
            if verdict == "no":
                state["complete"] = True
                return
            state["any"] = True
            if member is None or member not in remaining:
                if not enumerate_all:
                    state["any_of"] = [_name(table, m) for m in remaining]
                    return
                continue
            state["accepted"].append(_name(table, member))
            state.pop("any_of", None)
            remaining.remove(member)
            if not enumerate_all:
                return
        state["complete"] = True

    def _pq_v2(self) -> None:
        with_pq = self._props(addke=list(PQ_KE))
        without = self._props()
        ans = self._v2(with_pq + without, self.dh_ok or 19, intermediate=True)
        if ans is None:
            self.unknown.append("IKEv2 post-quantum: no answer")
            return
        self._note(ans)
        if ans.kind == "accepted":
            add = ans.chosen.get(T_ADDKE1)
            pq = bool(add and add[0] in PQ_KE)
            self.v2["pq"] = {"supported": pq, "method": _name(GROUPS, add[0]) if pq else None}
        elif ans.kind == "no_proposal":
            self.v2["pq"] = {"supported": False, "method": None}

    def _fragile_weak_v2(self) -> None:
        props = [Proposal([(m, 128 if m == 7 else None) for m in WEAK_ENCR], list(WEAK_PRF), list(WEAK_INTEG),
                          [g for g in WEAK_DH if can_share(g)] + ([self.probe_group] if self.probe_group else []))]
        ans = self._v2(props, self.probe_group or 2, retry_ke=False)
        if ans is None:
            self.unknown.append("IKEv2 weakest proposal: no answer")
            return
        self._note(ans)
        weak = self.v2.setdefault("weak", {})
        if ans.kind in ("accepted", "invalid_ke"):
            weak["suite"] = True  # an all-weak proposal (64-bit ciphers, MD5/SHA-1, small groups) is acceptable
            for ttype, key, table, members in ((T_ENCR, "encryption", ENCR, WEAK_ENCR), (T_PRF, "prf", PRF, WEAK_PRF),
                                               (T_INTEG, "integrity", INTEG, WEAK_INTEG), (T_KE, "dh", GROUPS, WEAK_DH)):
                got = ans.chosen.get(ttype) if ans.kind == "accepted" else ((ans.group,) if ttype == T_KE else None)
                if got and got[0] in members:
                    weak[key] = {"accepted": [_name(table, got[0])], "complete": False}
                else:
                    weak[key] = {"accepted": [], "any_of": [_name(table, m) for m in members], "complete": False}
        elif ans.kind == "no_proposal":
            weak["suite"] = False

    # -------------------------------------------------------------- IKEv1
    @staticmethod
    def _v1_set(encs, hashes, groups, auths=V1_AUTHS) -> list[V1Transform]:
        return [V1Transform(e, k, h, a, g) for e, k in encs for h in hashes for a in auths for g in groups]

    def _note_v1(self, ans: V1Answer) -> None:
        if ans.vendor_ids and "vendor_ids" not in self.v1:
            self.v1["vendor_ids"] = ans.vendor_ids[:8]

    @staticmethod
    def _t_name(t: V1Transform) -> dict[str, Any]:
        return {"encryption": _name(V1_ENC, t.enc, t.keylen), "hash": V1_HASH_NAMES.get(t.hash, f"#{t.hash}"),
                "auth": V1_AUTH.get(t.auth, f"#{t.auth}"), "group": GROUPS.get(t.group, f"#{t.group}")}

    def _v1_baseline(self, second: bool = True) -> None:
        """Main Mode message 1 with common transforms, then (if refused) a second set: ECDSA/XAUTH-RSA
        authentication, SHA-384, ECP groups.  A daemon that answers IKEv1 is only 'speaking' it; IKEv1 counts as
        enabled when a transform is accepted (strongSwan answers NO-PROPOSAL-CHOSEN with no IKEv1 connection at all)."""
        sets = [self._v1_set([(7, 256), (7, 128), (5, None)], [4, 2], [14, 2])]
        if second:
            sets.append(self._v1_set([(7, 256)], [5, 4], [19, 20, 15], auths=(9, 10, 65005, 1)))
        for ts in sets:
            ans = self._v1(ts)
            if ans is None:
                return
            self._note_v1(ans)
            if ans.kind not in ("accepted", "no_proposal", "notify"):
                return
            self.v1["supported"] = True  # the gateway speaks IKEv1
            self.v1["baseline"] = ans.kind
            if ans.transform is not None:
                self.v1["chosen"] = self._t_name(ans.transform)
                self.v1["accepts"] = True
                return
            if ans.kind != "no_proposal":
                return
        self.v1.setdefault("accepts", False)

    def _v1_record(self, t: V1Transform) -> None:
        self.v1["accepts"] = True
        weak = self.v1.setdefault("weak", {})
        for key, value, members, label in (("encryption", t.enc, (1, 5), V1_ENC.get(t.enc, f"#{t.enc}")),
                                           ("hash", t.hash, V1_WEAK_HASH, V1_HASH_NAMES.get(t.hash, f"#{t.hash}")),
                                           ("group", t.group, V1_WEAK_GROUP, GROUPS.get(t.group, f"#{t.group}"))):
            state = weak.setdefault(key, {"accepted": [], "complete": False})
            if value in members and label not in state["accepted"]:
                state["accepted"].append(label)

    def _v1_all_weak(self) -> None:
        ans = self._v1(self._v1_set([(1, None), (5, None)], [1, 2], [1, 2, 5]))
        if ans is None:
            self.unknown.append("IKEv1 weak transforms: no answer")
            return
        self._note_v1(ans)
        if ans.kind == "accepted" and ans.transform is not None:
            self._v1_record(ans.transform)
            self.v1["weak_suite"] = True
        elif ans.kind == "no_proposal":
            self.v1["weak_suite"] = False

    def _weak_v1(self, key: str, enumerate_all: bool) -> None:
        state = self.v1.setdefault("weak", {}).setdefault(key, {"accepted": [], "complete": False})
        if state["complete"]:
            return
        names = {"encryption": V1_ENC, "hash": V1_HASH_NAMES, "group": GROUPS}[key]
        members = {"encryption": [(1, None), (5, None)], "hash": [1, 2], "group": [1, 2, 5]}[key]
        remaining = [m for m in members if names.get(m[0] if isinstance(m, tuple) else m) not in state["accepted"]]
        while remaining:
            if key == "encryption":
                ts = self._v1_set(remaining, [2, 4, 1], [2, 14])
            elif key == "hash":
                ts = self._v1_set([(7, 128), (7, 256), (5, None)], remaining, [2, 14])
            else:
                ts = self._v1_set([(7, 128), (5, None)], [2, 4], remaining)
            ans = self._v1(ts)
            if ans is None:
                self.unknown.append(f"IKEv1 weak {key}: no answer")
                return
            self._note_v1(ans)
            if ans.kind != "accepted" or ans.transform is None:
                state["complete"] = ans.kind == "no_proposal"
                return
            self._v1_record(ans.transform)
            t = ans.transform
            pick = {"encryption": (t.enc, None), "hash": t.hash, "group": t.group}[key]
            if pick not in remaining:
                return
            remaining.remove(pick)
            if not enumerate_all:
                return
        state["complete"] = True

    def _aggressive(self) -> None:
        for group in (2, 14):
            ts = self._v1_set([(7, 256), (7, 128), (5, None)], [2, 4], [group], auths=(1, 65001))
            ans = self._v1(ts, aggressive=True, group=group)
            if ans is None:
                continue
            self._note_v1(ans)
            if ans.kind == "accepted" and ans.exchange == V1_AGGRESSIVE:
                self.v1["aggressive"] = True
                self.v1["accepts"] = True
                self.v1["aggressive_auth"] = V1_AUTH.get(ans.transform.auth, "?") if ans.transform else None
                self.v1["aggressive_hash_returned"] = ans.auth_payload  # the hash itself is never kept
                return
            if ans.notify:
                self.v1["aggressive_notify"] = ans.notify
            if ans.kind != "no_proposal":  # refused for another reason (identity, policy): another group changes nothing
                break
        self.v1.setdefault("aggressive", None)

    # -------------------------------------------------------------- plan
    def run(self) -> dict[str, Any]:
        try:
            self._plan()
        except Stop:
            self.unknown.append("packet budget used up")
        return self.facts()

    def _plan(self) -> None:
        fragile = self.mode == "fragile"
        self._v2_baseline(strong_only=fragile)
        if not self.primary:
            if not self.v2.get("supported"):
                self._v1_baseline(second=False)
            return
        if fragile:
            if self.v2.get("supported"):
                self._fragile_weak_v2()
            self._v1_baseline(second=False)
            return
        self._v1_baseline()
        if self._v2_usable():
            for ttype, key, members in V2_CLASSES:
                self._weak_v2(ttype, key, members, enumerate_all=False)
            self._pq_v2()
        elif self.v2.get("supported"):
            self.v2["pq"] = {"supported": False, "method": None}
        if self.v1.get("supported"):
            self._v1_all_weak()
        if self.v1.get("accepts"):  # Aggressive Mode and weak classes only where some IKEv1 transform is accepted
            self._aggressive()
            for key in ("encryption", "hash", "group"):
                self._weak_v1(key, enumerate_all=False)
        # spend what is left enumerating more weak members (each class continues where it stopped)
        if self._v2_usable():
            for ttype, key, members in V2_CLASSES:
                if (self.v2.get("weak") or {}).get(key, {}).get("any"):
                    self._weak_v2(ttype, key, members, enumerate_all=True)
        if self.v1.get("accepts"):
            for key in ("encryption", "hash", "group"):
                if (self.v1.get("weak") or {}).get(key, {}).get("accepted"):
                    self._weak_v1(key, enumerate_all=True)

    def facts(self) -> dict[str, Any]:
        for side in (self.v2, self.v1):
            for state in (side.get("weak") or {}).values():
                if isinstance(state, dict):
                    state.pop("refused_ids", None)
        return {"ikev2": self.v2, "ikev1": self.v1, "cookie_required": self.cookie_required,
                "packets_used": self.budget.used, "packet_budget": self.budget.limit, "mode": self.mode,
                "half_open_wait": self.paused, "unknown": self.unknown[:20]}


def answered(facts: dict[str, Any]) -> bool:
    return bool((facts.get("ikev2") or {}).get("supported") or (facts.get("ikev1") or {}).get("supported"))
