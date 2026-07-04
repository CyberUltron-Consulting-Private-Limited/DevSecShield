"""Safe RSA ENCRYPTION padding fixture (C16) — a NEGATIVE control.

``pub.encrypt(..., padding.OAEP(...))`` is RSA encryption under OAEP, which HAS
chosen-ciphertext security. The operation is encryption (like the PKCS#1 v1.5
case), so this proves the predicate keys on the PADDING, not merely on the
operation: OAEP encryption must NOT be flagged.

NOTHING here is a real credential or a production code path — a labeled detection
target only.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_secret(pub, message: bytes) -> bytes:
    """RSA-OAEP encryption — the safe padding; never flagged."""
    return pub.encrypt(message, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
