"""Application code that USES two algorithms the environment policy disables.

The java.security fixture disables RC4 and MD5 (jdk.tls / jdk.certpath
disabledAlgorithms); this module uses both — a disabled-but-used violation the
C11 compliance cross-reference flags.
"""

import hashlib

from Crypto.Cipher import ARC4


def fingerprint(data: bytes) -> bytes:
    # MD5 is disabled by jdk.certpath.disabledAlgorithms.
    return hashlib.md5(data).digest()


def stream_encrypt(key: bytes, data: bytes) -> bytes:
    # RC4 (ARC4) is disabled by jdk.tls.disabledAlgorithms.
    cipher = ARC4.new(key)
    return cipher.encrypt(data)
