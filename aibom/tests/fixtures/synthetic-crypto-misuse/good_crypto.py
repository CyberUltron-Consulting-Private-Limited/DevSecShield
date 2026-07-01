"""Synthetic NEGATIVE control (C6): correct crypto-material handling.

Everything here is secure — a CSPRNG-derived key + per-message random IV. The
C6 misuse scanner must raise ZERO flags on this file (no static IV, no weak RNG,
no hardcoded key). It guards against false positives on good code.
"""
import os
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_correctly(data: bytes) -> bytes:
    """AES-CBC with a CSPRNG key and a fresh per-message random IV — safe."""
    key = os.urandom(32)  # secure key material (not a constant, not weak RNG)
    iv = os.urandom(16)  # fresh random IV (not static, not weak RNG)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def fresh_token() -> bytes:
    """A token from a CSPRNG — secure, must NOT be flagged as weak RNG."""
    token = secrets.token_bytes(32)
    return token
