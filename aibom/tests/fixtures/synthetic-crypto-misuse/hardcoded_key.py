"""Synthetic crypto-misuse target (C6): hardcoded symmetric key — CWE-321.

A symmetric key embedded as a source literal reaching a cipher. NOT a real
credential — a planted fake. The C6 misuse scanner flags HARDCODED_KEY.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_with_hardcoded_key(iv: bytes, data: bytes) -> bytes:
    """AES-CBC keyed with a source-embedded key literal — CWE-321."""
    secret_key = b"hardcodedsecret0"  # 16-byte hardcoded AES key
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()
