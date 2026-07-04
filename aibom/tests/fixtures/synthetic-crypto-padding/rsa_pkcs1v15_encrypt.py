"""Weak RSA ENCRYPTION padding fixture (C16) — the POSITIVE case.

``pub.encrypt(..., padding.PKCS1v15())`` is RSA encryption under PKCS#1 v1.5,
the Bleichenbacher / ROBOT chosen-ciphertext padding oracle (CWE-780). The C1
detection lane captures ``crypto:padding=pkcs1v15`` + ``crypto:operation=encrypt``
(both readable on the one call line), and the C16 weak-padding predicate raises a
WEAK_PADDING flag on the resulting RSA asset.

NOTHING here is a real credential or a production code path — a labeled detection
target only.
"""
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_secret(pub, message: bytes) -> bytes:
    """RSA encryption with PKCS#1 v1.5 padding — the weak, oracle-able case."""
    return pub.encrypt(message, padding.PKCS1v15())
