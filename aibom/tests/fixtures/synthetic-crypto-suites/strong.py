"""C13 negative control — a modern TLS 1.3 + SSH config with only AEAD suites.

Neither the TLS asset nor the SSH asset must raise ``WEAK_CIPHER_SUITE``: TLS 1.3
AEAD suites, curve25519 kex, ed25519 / rsa-sha2 host keys, AES-GCM /
ChaCha20-Poly1305 ciphers, and HMAC-SHA2 MACs are all acceptable under the
modern baselines. This proves the predicate does not over-flag.
"""
import ssl

import paramiko

STRONG_TLS_SUITES = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
STRONG_KEX = ["curve25519-sha256", "diffie-hellman-group16-sha512"]
STRONG_HOST_KEYS = ["ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp384"]
STRONG_CIPHERS = ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
STRONG_MACS = ["hmac-sha2-256", "hmac-sha2-512"]


def make_tls() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def make_ssh(host: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.connect(host)
    return client
