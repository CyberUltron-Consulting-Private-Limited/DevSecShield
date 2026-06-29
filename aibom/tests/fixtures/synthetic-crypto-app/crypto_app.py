"""Synthetic crypto application — fully hand-labeled (see expected_crypto.json).

The CBOM ground-truth oracle. Exercises every crypto-asset lane the CBOM scanner
(C1-C8) must reconcile/detect:

  * STRONG algorithms: RSA-2048, AES-256-GCM, SHA-256
  * WEAK   algorithms: MD5, DES, RC4, AES-128-ECB, RSA-1024
  * a hardcoded private key (related-crypto-material)

Plus a self-signed ``cert.pem`` (certificate lane) and ``tls_config.py``
(protocol lane, TLS 1.0). Every asset, weak/strong flag, and quantum-vulnerable
flag is enumerated exactly in ``expected_crypto.json``.

NOTHING here is a real credential or a production code path — it is a labeled
detection target only.
"""
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- PLANTED FAKE hardcoded private key (related-crypto-material lane) -------
# Throwaway RSA-2048 test key, NOT a real credential. Pairs with cert.pem.
HARDCODED_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRa6UzUIcM6eir
LfCVMF2kWvieW6JuxAP+jH5EVV3g1x99Mu3WK9u9otuuQmdsEM46ijVLDFrFADs7
UoZblDvQZufTS+OIyJ2qcgMe0GI7Wodxq5HUjAXLH//3idaPxbg0r40M+/xlscmy
nOHwOqJkn3FWvidldCVHZF7ETIChVFpMOFa2cDiS8S3V59Zoyuaop/ehjDYcoSu5
-----END PRIVATE KEY-----"""


# --- STRONG algorithms ------------------------------------------------------
def strong_rsa_2048():
    """RSA-2048 — strong key size, but asymmetric => quantum-vulnerable."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def strong_aes_256_gcm(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-256-GCM — authenticated encryption, strong + quantum-safe."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def strong_sha256(data: bytes) -> str:
    """SHA-256 — strong digest."""
    return hashlib.sha256(data).hexdigest()


# --- WEAK algorithms --------------------------------------------------------
def weak_md5(data: bytes) -> str:
    """MD5 — broken hash (collision)."""
    return hashlib.md5(data).hexdigest()


def weak_des(key: bytes, data: bytes) -> bytes:
    """DES — 56-bit block cipher, brute-forceable."""
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b"\x00" * 8))  # DES core
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def weak_rc4(key: bytes, data: bytes) -> bytes:
    """RC4 — broken stream cipher."""
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    enc = cipher.encryptor()
    return enc.update(data)


def weak_aes_128_ecb(key: bytes, data: bytes) -> bytes:
    """AES-128 in ECB mode — leaks plaintext structure."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def weak_rsa_1024():
    """RSA-1024 — undersized key, weak AND quantum-vulnerable."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def load_hardcoded_key():
    return serialization.load_pem_private_key(
        HARDCODED_PRIVATE_KEY.encode(), password=None
    )


_ = hashes  # noqa: F401  (import-presence for the crypto-library scanner)
