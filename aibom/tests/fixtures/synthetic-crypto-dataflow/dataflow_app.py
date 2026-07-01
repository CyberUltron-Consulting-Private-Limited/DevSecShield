"""Data-flow-lite + receiver-rule detection fixture (C1).

Every crypto usage below is deliberately shaped so the PREVIOUS same-line regex
corpus could NOT resolve its parameters — the parameter is bound one line up, or
carried by a byte-length, or expressed as an argument role — and the clean-room
:mod:`aibom.cbom.detect` rule engine (receiver+method+arg-role model + intra-file
data-flow-lite symbol table) now resolves it:

  * RSA key size assigned to a variable on a PRIOR line (``key_size=RSA_BITS``)
    -> RSA-2048 / RSA-1024 (same-line ``extract_key_size`` returned None here).
  * AES key size inferred from the key literal's byte length
    (``os.urandom(32)`` -> 256-bit) + mode from ``modes.CBC`` -> AES-256-CBC.
  * RSA padding captured as an arg-role (``padding.OAEP`` / ``PKCS1v15``).

NOTHING here is a real credential or a production code path — a labeled detection
target only.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- key sizes bound to names (resolved cross-line by the symbol table) ------
RSA_BITS = 2048
WEAK_RSA_BITS = 1024


def strong_rsa():
    """RSA-2048 — the key size lives on a prior line, not this call."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def weak_rsa():
    """RSA-1024 — undersized, size bound to a prior-line variable."""
    return rsa.generate_private_key(public_exponent=65537, key_size=WEAK_RSA_BITS)


def aes_256_cbc(data: bytes) -> bytes:
    """AES-256-CBC — key size inferred from the 32-byte key literal length."""
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def rsa_oaep(pub, msg: bytes) -> bytes:
    """RSA-OAEP — padding captured as an argument role."""
    return pub.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_pkcs1v15_sign(priv, msg: bytes) -> bytes:
    """RSA PKCS#1 v1.5 signature — the weak padding a C6 predicate later flags."""
    return priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())
