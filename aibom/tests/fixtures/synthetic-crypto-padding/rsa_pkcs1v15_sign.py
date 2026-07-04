"""FIPS-approved RSA SIGNATURE padding fixture (C16) — the critical NEGATIVE.

``priv.sign(..., padding.PKCS1v15(), ...)`` is an RSA PKCS#1 v1.5 *signature*,
which is FIPS 186-5-approved — NOT the encryption padding oracle. The same
padding token (``pkcs1v15``) as the positive case, but the operation is ``sign``,
so the operation gate leaves it un-flagged. This reproduces the exact shape the
story forbids flagging (the frozen ``synthetic-crypto-dataflow`` rsa_pkcs1v15_sign).

NOTHING here is a real credential or a production code path — a labeled detection
target only.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sign_message(priv, message: bytes) -> bytes:
    """RSA PKCS#1 v1.5 signature — FIPS-approved; must NOT be flagged."""
    return priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
