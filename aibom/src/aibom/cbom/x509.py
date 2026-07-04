"""Minimal, pure-stdlib X.509 certificate reader for the CBOM certificate lane.

The CBOM lane must capture certificate validity/expiry, subject, issuer,
self-signed status, signature algorithm and public-key size **deterministically
and offline** — and the ``aibom`` package ships intentionally-light dependencies
(no ``cryptography``/``pyOpenSSL``), so this is a small, defensive DER/ASN.1
reader over the certificate structure RFC 5280 defines. It extracts only the few
fields the C2 certificate scanner records; it is not a general ASN.1 library.

Lane discipline: this is pure parsing knowledge — it produces facts, it never
scores, flags, or serializes. The scanner turns these facts into
``crypto_asset`` (certificate) components.
"""

from __future__ import annotations

from dataclasses import dataclass

# ASN.1 tags we care about.
_SEQUENCE = 0x30
_OID = 0x06
_UTC_TIME = 0x17
_GENERALIZED_TIME = 0x18
_CTX_0 = 0xA0  # [0] EXPLICIT (TBSCertificate version)

# OID -> human name (signature + public-key algorithms seen in the wild).
_OID_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}
_CN_OID = "2.5.4.3"


class _Asn1Error(ValueError):
    """Raised when the DER stream is malformed — callers treat as 'unparseable'."""


@dataclass(frozen=True)
class Certificate:
    """The handful of certificate facts the CBOM certificate lane records."""

    subject_cn: str | None
    issuer_cn: str | None
    self_signed: bool
    not_before: str | None  # ISO-8601 UTC, e.g. "2026-06-29T09:56:21Z"
    not_after: str | None
    signature_algorithm: str | None
    public_key_algorithm: str | None
    key_size: int | None


# --------------------------------------------------------------------------- #
# Primitive DER reader
# --------------------------------------------------------------------------- #


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        raise _Asn1Error("truncated length")
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or i + n > len(data):
        raise _Asn1Error("bad long-form length")
    return int.from_bytes(data[i : i + n], "big"), i + n


def _read_tlv(data: bytes, i: int) -> tuple[int, bytes, bytes, int]:
    """Read one TLV at ``i`` -> (tag, value, raw_tlv, next_offset)."""
    if i >= len(data):
        raise _Asn1Error("truncated tag")
    tag = data[i]
    length, j = _read_len(data, i + 1)
    end = j + length
    if end > len(data):
        raise _Asn1Error("value overruns buffer")
    return tag, data[j:end], data[i:end], end


def _children(value: bytes) -> list[tuple[int, bytes, bytes]]:
    """Split a constructed value into its TLV children -> [(tag, value, raw)]."""
    out: list[tuple[int, bytes, bytes]] = []
    i = 0
    while i < len(value):
        tag, val, raw, i = _read_tlv(value, i)
        out.append((tag, val, raw))
    return out


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for b in value[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def _first_oid_name(algid_value: bytes) -> str | None:
    """AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }."""
    for tag, val, _ in _children(algid_value):
        if tag == _OID:
            oid = _decode_oid(val)
            return _OID_NAMES.get(oid, oid)
    return None


def _name_cn(name_value: bytes) -> str | None:
    """Pull the commonName from an RDNSequence (Name)."""
    for _set_tag, set_val, _ in _children(name_value):  # RDN (SET)
        for _atv_tag, atv_val, _ in _children(set_val):  # AttributeTypeAndValue
            atv = _children(atv_val)
            if len(atv) < 2 or atv[0][0] != _OID:
                continue
            if _decode_oid(atv[0][1]) == _CN_OID:
                return atv[1][1].decode("utf-8", "ignore")
    return None


def _parse_time(tag: int, value: bytes) -> str | None:
    s = value.decode("ascii", "ignore").strip()
    try:
        if tag == _UTC_TIME:  # YYMMDDHHMMSSZ
            yy = int(s[0:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy  # RFC 5280 §4.1.2.5.1
            rest = s[2:]
        elif tag == _GENERALIZED_TIME:  # YYYYMMDDHHMMSSZ
            year = int(s[0:4])
            rest = s[4:]
        else:
            return None
        mo, da, ho, mi = rest[0:2], rest[2:4], rest[4:6], rest[6:8]
        se = rest[8:10] if len(rest) >= 10 and rest[8:10].isdigit() else "00"
        return f"{year:04d}-{mo}-{da}T{ho}:{mi}:{se}Z"
    except (ValueError, IndexError):
        return None


def _rsa_key_size(spki_value: bytes) -> int | None:
    """SubjectPublicKeyInfo -> RSA modulus bit length (None if not RSA/parseable)."""
    kids = _children(spki_value)
    if len(kids) < 2:
        return None
    bit_string = kids[1][1]  # subjectPublicKey BIT STRING
    if len(bit_string) < 2:
        return None
    inner = bit_string[1:]  # drop the unused-bits count byte
    try:
        seq_tag, seq_val, _, _ = _read_tlv(inner, 0)
        if seq_tag != _SEQUENCE:
            return None
        modulus = _children(seq_val)[0][1]  # RSAPublicKey.modulus (INTEGER)
    except (_Asn1Error, IndexError):
        return None
    modulus = modulus.lstrip(b"\x00")  # strip ASN.1 sign byte
    return len(modulus) * 8 or None


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def parse_certificate(der: bytes) -> Certificate | None:
    """Parse a DER-encoded X.509 certificate into a :class:`Certificate`.

    Returns ``None`` (never raises) when the bytes are not a parseable
    certificate, so a malformed/non-cert file in a scanned repo can never crash
    the scan.
    """
    try:
        tag, cert_val, _, _ = _read_tlv(der, 0)
        if tag != _SEQUENCE:
            return None
        top = _children(cert_val)
        tbs_value = top[0][1]
        sig_alg = _first_oid_name(top[1][1]) if len(top) > 1 else None

        tbs = _children(tbs_value)
        p = 1 if tbs and tbs[0][0] == _CTX_0 else 0  # optional [0] version
        # order: serialNumber, signature, issuer, validity, subject, spki
        p += 1  # serialNumber
        p += 1  # signature AlgorithmIdentifier
        issuer_raw = tbs[p][2]
        issuer_cn = _name_cn(tbs[p][1])
        p += 1
        validity = _children(tbs[p][1])
        p += 1
        not_before = _parse_time(validity[0][0], validity[0][1]) if validity else None
        not_after = (
            _parse_time(validity[1][0], validity[1][1]) if len(validity) > 1 else None
        )
        subject_raw = tbs[p][2]
        subject_cn = _name_cn(tbs[p][1])
        p += 1
        spki_value = tbs[p][1]
        spki_kids = _children(spki_value)
        # SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT }
        pk_alg = _first_oid_name(spki_kids[0][1]) if spki_kids else None
        key_size = _rsa_key_size(spki_value) if pk_alg == "rsaEncryption" else None

        return Certificate(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            self_signed=issuer_raw == subject_raw,
            not_before=not_before,
            not_after=not_after,
            signature_algorithm=sig_alg,
            public_key_algorithm=pk_alg,
            key_size=key_size,
        )
    except (_Asn1Error, IndexError, ValueError):
        return None


__all__ = ["Certificate", "parse_certificate"]
