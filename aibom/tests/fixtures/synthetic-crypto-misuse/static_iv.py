"""Synthetic crypto-misuse target (C6): static IV + reused nonce.

Hand-labeled detection target for the related-crypto-material weakness lane.
NOTHING here is a real credential — every literal is a planted fake so the C6
misuse scanner has a deterministic oracle for STATIC_IV (CWE-329) and
REUSED_NONCE (CWE-323).
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_cbc_static_iv(key: bytes, data: bytes) -> bytes:
    """AES-CBC with a HARDCODED, predictable IV — CWE-329 (static IV)."""
    iv = b"0000000000000000"  # constant 16-byte IV reaching the cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def encrypt_gcm_reused_nonce(key: bytes, a: bytes, b: bytes) -> bytes:
    """AES-GCM where ONE constant nonce secures TWO messages — CWE-323
    (nonce reuse is catastrophic for GCM: it breaks confidentiality AND
    forgeability). The same ``nonce`` symbol feeds two cipher constructions."""
    nonce = b"cafecafecafe"  # constant 12-byte nonce, reused below
    c1 = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    c2 = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    return c1.update(a) + c1.finalize() + c2.update(b) + c2.finalize()
