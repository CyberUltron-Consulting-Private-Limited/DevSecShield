"""Independent readers for the CB-02 self-check (oracle rule O-3): pure Python, standard library only.

The generator builds the oracle with OpenSSL (`openssl x509 -text`), keytool (`keytool -list -v`), OpenSC
(`pkcs11-tool --list-objects`) and ssh-keygen, and parses their text output. These readers decode the artefacts
themselves (DER, the JKS file format, the SoftHSM2 object store, SSH wire-format key blobs), so a parser bug or a tool
bug on the generator side shows up as a disagreement instead of being copied into both sides.

Nothing here imports the product (rule O-1) or calls a tool.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import re
import struct

# ------------------------------------------------------------------ object identifiers (public registries)
# Key algorithms: RFC 3279 / RFC 5480 (rsaEncryption, id-ecPublicKey), RFC 8410 (Ed25519/Ed448), NIST CSOR
# "Computer Security Objects Register" (ML-DSA, FIPS 204: id-ml-dsa-44/65/87).
KEY_ALG = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "ED25519", "1.3.101.113": "ED448",
           "1.2.840.10040.4.1": "DSA", "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
           "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}
# Named curves: RFC 5480 §2.1.1.1 (secp256r1 = prime256v1, secp384r1, secp521r1); NIST names as CB-01's §6.
CURVE = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384), "1.3.132.0.35": ("P-521", 521)}
# Signature algorithms, by the names OpenSSL and Java print: RFC 3279 §2.2.1 (sha1WithRSAEncryption), RFC 4055 §5
# (sha256/384/512WithRSAEncryption), RFC 5758 §3.2 (ecdsa-with-SHA256/384/512), RFC 8410 (Ed25519), NIST CSOR (ML-DSA).
SIG_ALG = {
    "sha1WithRSAEncryption": "1.2.840.113549.1.1.5", "SHA1withRSA": "1.2.840.113549.1.1.5",
    "sha256WithRSAEncryption": "1.2.840.113549.1.1.11", "SHA256withRSA": "1.2.840.113549.1.1.11",
    "sha384WithRSAEncryption": "1.2.840.113549.1.1.12", "SHA384withRSA": "1.2.840.113549.1.1.12",
    "sha512WithRSAEncryption": "1.2.840.113549.1.1.13", "SHA512withRSA": "1.2.840.113549.1.1.13",
    "ecdsa-with-SHA256": "1.2.840.10045.4.3.2", "SHA256withECDSA": "1.2.840.10045.4.3.2",
    "ecdsa-with-SHA384": "1.2.840.10045.4.3.3", "SHA384withECDSA": "1.2.840.10045.4.3.3",
    "ecdsa-with-SHA512": "1.2.840.10045.4.3.4", "SHA512withECDSA": "1.2.840.10045.4.3.4",
    "ED25519": "1.3.101.112", "Ed25519": "1.3.101.112",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17", "ML-DSA-65": "2.16.840.1.101.3.4.3.18", "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
}
# Attribute types of a Name (RFC 4514 §3 short names; OpenSSL prints emailAddress for PKCS#9).
NAME_ATTR = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
             "2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
             "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.5": "serialNumber"}


def sig_oid(name: str | None) -> str | None:
    """The OID of a signature algorithm named as OpenSSL or Java prints it (None when unknown)."""
    return SIG_ALG.get(name or "")


# ------------------------------------------------------------------ DER
class DerError(ValueError):
    pass


def der_read(buf: bytes, i: int = 0) -> tuple[int, bytes, int]:
    """One TLV at `i`: (tag byte, value bytes, index after the value). Definite lengths only (DER)."""
    if i + 2 > len(buf):
        raise DerError("truncated TLV")
    tag, length = buf[i], buf[i + 1]
    i += 2
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not used in X.509")
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or i + n > len(buf):
            raise DerError("bad length")
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + length > len(buf):
        raise DerError("value beyond the buffer")
    return tag, buf[i:i + length], i + length


def der_items(value: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(value):
        tag, v, i = der_read(value, i)
        out.append((tag, v))
    return out


def der_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    first = value[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def der_int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def der_time(tag: int, value: bytes) -> str:
    """UTCTime (0x17, RFC 5280 §4.1.2.5.1: YY >= 50 is 19YY) or GeneralizedTime (0x18) -> UTC ISO `...Z`."""
    text = value.decode("ascii")
    if tag == 0x17:
        yy = int(text[:2])
        text = f"{1900 + yy if yy >= 50 else 2000 + yy}{text[2:]}"
    elif tag != 0x18:
        raise DerError(f"tag {tag:#x} is not a time")
    t = dt.datetime.strptime(text.rstrip("Z"), "%Y%m%d%H%M%S")
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc4514_value(v: str) -> str:
    out = re.sub(r'([,+"\\<>;=])', r"\\\1", v)
    if out.startswith(("#", " ")):
        out = "\\" + out
    if out.endswith(" ") and not out.endswith("\\ "):
        out = out[:-1] + "\\ "
    return out


def der_name(value: bytes) -> str:
    """A Name as an RFC 4514 string: RDNs in reverse order, comma-separated (what `openssl -nameopt RFC2253` and
    Go's pkix.Name.String() print)."""
    rdns = []
    for _tag, rdn in der_items(value):            # SET OF AttributeTypeAndValue
        atvs = []
        for _t, atv in der_items(rdn):
            (_, oid_v), (_, val) = der_items(atv)[:2]
            oid = der_oid(oid_v)
            atvs.append(f"{NAME_ATTR.get(oid, oid)}={_rfc4514_value(val.decode('utf-8', 'replace'))}")
        rdns.append("+".join(atvs))
    return ",".join(reversed(rdns))


def name_key(name: str | None) -> str | None:
    """Comparison form of an RFC 4514 string: attribute types are case-insensitive (§2.3), values compared as written."""
    if name is None:
        return None
    parts = re.split(r"(?<!\\),", name)
    return ",".join(p.split("=", 1)[0].strip().upper() + "=" + p.split("=", 1)[-1] for p in parts if p)


def _spki(value: bytes) -> dict:
    """SubjectPublicKeyInfo -> algorithm family, key size, curve."""
    (_, alg), (_, bits) = der_items(value)[:2]
    alg_items = der_items(alg)
    oid = der_oid(alg_items[0][1])
    family = KEY_ALG.get(oid, oid)
    out = {"algorithm": family, "key_size": None, "curve": None, "key_alg_oid": oid}
    if family == "RSA":
        (_, rsa), = der_items(bits[1:])[:1]             # BIT STRING: first byte = unused bits
        modulus = der_items(rsa)[0][1]
        out["key_size"] = der_int(modulus).bit_length()
    elif family == "EC" and len(alg_items) > 1 and alg_items[1][0] == 0x06:
        name, size = CURVE.get(der_oid(alg_items[1][1]), (der_oid(alg_items[1][1]), None))
        out["curve"], out["key_size"] = name, size
    elif family == "ED25519":
        out["key_size"] = 256
    elif family == "ED448":
        out["key_size"] = 456
    return out


def x509_facts(der: bytes) -> dict:
    """The oracle's certificate fields, decoded from DER (no OpenSSL, no Java, no Go)."""
    _tag, cert, _ = der_read(der)
    tbs_tag, tbs, *_ = der_read(cert)
    items = der_items(tbs)
    if items and items[0][0] == 0xA0:                    # [0] EXPLICIT version
        items = items[1:]
    serial, _sig_inner, issuer, validity, subject, spki = items[:6]
    (nb_t, nb), (na_t, na) = der_items(validity[1])[:2]
    outer = der_items(cert)
    sig_alg = der_oid(der_items(outer[1][1])[0][1])
    return {"fingerprint_sha256": hashlib.sha256(der).hexdigest(), "serial": format(der_int(serial[1]), "x"),
            "signature_algorithm_oid": sig_alg, "issuer": der_name(issuer[1]), "subject": der_name(subject[1]),
            "not_before": der_time(nb_t, nb), "not_after": der_time(na_t, na), **_spki(spki[1])}


def pem_blocks(text: str, label: str = "CERTIFICATE") -> list[bytes]:
    return [base64.b64decode("".join(m.group(1).split()))
            for m in re.finditer(rf"-----BEGIN {label}-----(.+?)-----END {label}-----", text, re.S)]


def pkcs8_facts(pem: str) -> dict:
    """An unencrypted PKCS#8 private key (RFC 5208 PrivateKeyInfo, what `openssl genpkey` writes): algorithm and
    size. Only the modulus length is read; nothing about the key is returned or written."""
    blocks = pem_blocks(pem, "PRIVATE KEY")
    if not blocks:
        raise DerError("no PKCS#8 PRIVATE KEY block")
    _t, info, _ = der_read(blocks[0])
    items = der_items(info)
    alg_items = der_items(items[1][1])
    family = KEY_ALG.get(der_oid(alg_items[0][1]), der_oid(alg_items[0][1]))
    out = {"algorithm": family, "key_size": None}
    if family == "RSA":
        rsa = der_items(der_read(items[2][1])[1])      # OCTET STRING { RSAPrivateKey }
        out["key_size"] = der_int(rsa[1][1]).bit_length()
    elif family == "EC" and len(alg_items) > 1:
        out["key_size"] = CURVE.get(der_oid(alg_items[1][1]), (None, None))[1]
    return out


# ------------------------------------------------------------------ JKS (the Sun "JKS" keystore format)
JKS_MAGIC = 0xFEEDFEED


def _jks_utf(buf: bytes, i: int) -> tuple[str, int]:
    (n,) = struct.unpack(">H", buf[i:i + 2])
    return buf[i + 2:i + 2 + n].decode("utf-8", "replace"), i + 2 + n


def jks_entries(data: bytes, password: str | None = None) -> dict:
    """Entries of a JKS file: {"format","version","integrity","entries":[{alias,type,certs:[DER]}]}.
    Layout: magic FEEDFEED, version 2, count; per entry a tag (1 private key, 2 trusted certificate), alias, date,
    then the protected key + chain or one certificate; a trailing SHA-1 over password (UTF-16BE) + "Mighty Aphrodite"
    + everything before it. `integrity` is True/False when a password is given, else None."""
    magic, version, count = struct.unpack(">III", data[:12])
    if magic != JKS_MAGIC:
        raise ValueError("not a JKS file (magic)")
    i, entries = 12, []
    for _ in range(count):
        (tag,) = struct.unpack(">I", data[i:i + 4])
        alias, i = _jks_utf(data, i + 4)
        i += 8                                            # creation date (ms)
        certs = []
        if tag == 1:
            (klen,) = struct.unpack(">I", data[i:i + 4])
            i += 4 + klen                                 # protected key: skipped, never decoded
            (n,) = struct.unpack(">I", data[i:i + 4])
            i += 4
            for _c in range(n):
                _ctype, i = _jks_utf(data, i)
                (clen,) = struct.unpack(">I", data[i:i + 4])
                certs.append(data[i + 4:i + 4 + clen])
                i += 4 + clen
        elif tag == 2:
            _ctype, i = _jks_utf(data, i)
            (clen,) = struct.unpack(">I", data[i:i + 4])
            certs.append(data[i + 4:i + 4 + clen])
            i += 4 + clen
        else:
            raise ValueError(f"unknown JKS entry tag {tag}")
        entries.append({"alias": alias, "type": {1: "PrivateKeyEntry", 2: "trustedCertEntry"}[tag], "certs": certs})
    integrity = None
    if password is not None:
        digest = hashlib.sha1(password.encode("utf-16-be") + b"Mighty Aphrodite" + data[:i]).digest()
        integrity = digest == data[i:i + 20]
    return {"format": "JKS", "version": version, "integrity": integrity, "entries": entries}


# ------------------------------------------------------------------ SoftHSM2 object store (file backend)
# SoftHSM2 ObjectFile: a generation counter, then attributes as (CK_ATTRIBUTE_TYPE, kind, value), every integer an
# 8-byte big-endian unsigned long; kinds 1 bool (1 byte), 2 unsigned long, 3 byte string (length + bytes),
# 4 mechanism set (count + longs), 5 attribute map (length + bytes). Byte strings of private objects are encrypted
# with the token key, integers and booleans are not. Attribute types: PKCS#11 v2.40 §2 (CKA_*), and SoftHSM's own
# token label (CKA_VENDOR_DEFINED + "SI" = 0x80005349).
CKA = {"class": 0x0, "label": 0x3, "key_type": 0x100, "modulus_bits": 0x121, "value_len": 0x161,
       "extractable": 0x162, "token_label": 0x80005349}
CKO = {2: "Public Key", 3: "Private Key", 4: "Secret Key"}
CKK = {0x0: "RSA", 0x3: "EC", 0x1F: "AES", 0x15: "DES3", 0x10: "GENERIC_SECRET"}


def softhsm_attributes(data: bytes) -> dict[int, object]:
    i, out = 8, {}
    while i < len(data):
        if i + 16 > len(data):
            raise ValueError("truncated attribute header")
        typ, kind = struct.unpack(">QQ", data[i:i + 16])
        i += 16
        if kind == 1:
            out[typ] = data[i] != 0
            i += 1
        elif kind == 2:
            (out[typ],) = struct.unpack(">Q", data[i:i + 8])
            i += 8
        elif kind in (3, 5):
            (n,) = struct.unpack(">Q", data[i:i + 8])
            out[typ] = data[i + 8:i + 8 + n]
            i += 8 + n
        elif kind == 4:
            (n,) = struct.unpack(">Q", data[i:i + 8])
            i += 8 + 8 * n
        else:
            raise ValueError(f"unknown SoftHSM attribute kind {kind}")
    return out


def softhsm_object(data: bytes) -> dict:
    """class, key type, size, extractable and (for public objects) the label of one SoftHSM2 .object file."""
    a = softhsm_attributes(data)
    cls = CKO.get(a.get(CKA["class"]), a.get(CKA["class"]))
    label = a.get(CKA["label"])
    bits = None
    if a.get(CKA["value_len"]) is not None:
        bits = 8 * int(a[CKA["value_len"]])
    elif a.get(CKA["modulus_bits"]) is not None:
        bits = int(a[CKA["modulus_bits"]])
    try:
        label_text = label.decode("utf-8") if isinstance(label, bytes) else None
    except UnicodeDecodeError:
        label_text = None                                 # encrypted (private object)
    return {"class": cls, "key_type": CKK.get(a.get(CKA["key_type"])), "bits": bits,
            "extractable": a.get(CKA["extractable"]), "label": label_text}


def softhsm_token_label(token_object: bytes) -> str:
    raw = softhsm_attributes(token_object).get(CKA["token_label"]) or b""
    return raw.decode("utf-8", "replace").rstrip()


# ------------------------------------------------------------------ SSH public key blobs (RFC 4253 §6.6)
def _ssh_string(buf: bytes, i: int) -> tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[i:i + 4])
    return buf[i + 4:i + 4 + n], i + 4 + n


def ssh_key_facts(b64: str) -> dict:
    """Type, size and SHA256 fingerprint (as `ssh-keygen -l -E sha256` prints it) of one public key blob."""
    blob = base64.b64decode(b64)
    typ, i = _ssh_string(blob, 0)
    typ_s = typ.decode()
    bits = None
    if typ_s == "ssh-rsa":
        _e, i = _ssh_string(blob, i)
        n, i = _ssh_string(blob, i)
        bits = int.from_bytes(n, "big").bit_length()
    elif typ_s == "ssh-ed25519":
        bits = 256
    elif typ_s.startswith("ecdsa-sha2-nistp"):
        bits = int(typ_s.removeprefix("ecdsa-sha2-nistp"))
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"type": typ_s, "bits": bits, "fingerprint_sha256": fp}
