"""Synthetic crypto-misuse target (C6): weak (non-crypto) RNG for key material.

CWE-338: a non-cryptographic PRNG (``random.*``) is used to produce
key/IV/token material. Predictable, so an attacker can reconstruct the material.
The negative control (``good_crypto.py``) uses ``os.urandom`` / ``secrets`` and
must NOT be flagged. Non-crypto uses of ``random`` (see ``game_score`` below)
must NOT be flagged either — the crypto-material context gate excludes them.
"""
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def weak_key_from_prng() -> bytes:
    """A symmetric key drawn from a non-crypto PRNG — CWE-338."""
    key = random.getrandbits(128).to_bytes(16, "big")  # weak-RNG key material
    return key


def weak_iv_from_prng(key: bytes, data: bytes) -> bytes:
    """An IV drawn from ``random.randbytes`` — predictable IV via weak RNG."""
    iv = random.randbytes(16)  # weak-RNG IV material
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def game_score() -> float:
    """NON-crypto randomness — must NOT be flagged (no crypto-material var)."""
    roll = random.random() * 100
    return roll
