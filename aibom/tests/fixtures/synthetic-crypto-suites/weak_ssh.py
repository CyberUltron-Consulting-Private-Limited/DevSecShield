"""C13 fixture — a paramiko SSH client pinned to weak negotiated primitives.

No wire version is pinned (so no ``WEAK_PROTOCOL``); the finding is entirely
``WEAK_CIPHER_SUITE`` over the SSH kex / host-key / cipher / MAC tokens:
  * diffie-hellman-group1-sha1 — DH group 1 / SHA-1 kex (Logjam-class);
  * ssh-rsa (SHA-1 host-key signature), ssh-dss (1024-bit DSA);
  * 3des-cbc (SWEET32), arcfour (RC4), blowfish-cbc (64-bit block);
  * hmac-md5 (broken MAC), umac-64 (truncated MAC).
"""
import paramiko

WEAK_KEX = ["diffie-hellman-group1-sha1"]
WEAK_HOST_KEYS = ["ssh-rsa", "ssh-dss"]
WEAK_CIPHERS = ["3des-cbc", "arcfour", "blowfish-cbc"]
WEAK_MACS = ["hmac-md5", "umac-64@openssh.com"]


def connect(host: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    transport = client.get_transport()
    opts = transport.get_security_options()
    opts.kex = WEAK_KEX
    opts.key_types = WEAK_HOST_KEYS
    opts.ciphers = WEAK_CIPHERS
    opts.digests = WEAK_MACS
    client.connect(host)
    return client
