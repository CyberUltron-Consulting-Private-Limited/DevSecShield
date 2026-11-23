import hashlib
import os

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCRYPT_SALT = b"constant-scrypt-salt"


def stretch(password: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, b"0123456789abcdef", 600000, 64)


def scrypt_key(password: bytes) -> bytes:
    return hashlib.scrypt(password, salt=SCRYPT_SALT, n=16384, r=8, p=1, dklen=32)


def session_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"protocol-v1", info=b"session").derive(shared)


HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


def encrypt(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(b"fixed-iv-16bytes")).encryptor()
    return enc.update(data) + enc.finalize() + os.urandom(1)
