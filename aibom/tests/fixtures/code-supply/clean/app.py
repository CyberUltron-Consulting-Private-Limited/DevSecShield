import hashlib


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
