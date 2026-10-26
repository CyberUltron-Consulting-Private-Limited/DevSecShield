"""PKCS#3 Diffie-Hellman prime size. Malformed DER returns None."""

from __future__ import annotations

from aibom.cbom.x509 import _read_len, _read_tlv

_SEQUENCE = 0x30
_INTEGER = 0x02
_MIN_BITS = 64


def prime_bits(der: bytes) -> int | None:
    """Bit length of the PKCS#3 prime, or None when ``der`` is not one."""
    return _prime_bits(der)


def _prime_bits(der: bytes) -> int | None:
    """Total reader. The prime is the first INTEGER of the outer SEQUENCE."""
    try:
        tag, value, raw, _end = _read_tlv(der, 0)
        if tag != _SEQUENCE:
            return None
        length, after = _read_len(raw, 1)
        if after + length != len(raw):
            return None
        prime_tag, prime, _prime_raw, _next = _read_tlv(value, 0)
        if prime_tag != _INTEGER or not prime:
            return None
        bits = int.from_bytes(prime, "big").bit_length()
    except Exception:
        return None
    if bits < _MIN_BITS:
        return None
    return bits
