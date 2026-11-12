"""Tables transcribed from public standards and registries (O-2), used where the lab oracle does not state a value
(INTERFACES.md v7 §A.2, §A.3). Never from product code (O-1). Each table names its source; O-9 (two-agent rule)
applies: the PR review records the second check.

PQ_TLS_GROUPS
    IANA "TLS Supported Groups" registry (https://www.iana.org/assignments/tls-parameters/, group names as registered):
    0x0200 MLKEM512, 0x0201 MLKEM768, 0x0202 MLKEM1024 (draft-ietf-tls-mlkem); 0x11EB SecP256r1MLKEM768,
    0x11EC X25519MLKEM768, 0x11ED SecP384r1MLKEM1024 (draft-ietf-tls-ecdhe-mlkem); 0x6399 X25519Kyber768Draft00
    (obsolete pre-standard hybrid, still deployed).
PQ_SSH_KEX
    mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex; OpenSSH 9.9 release notes), sntrup761x25519-sha512 and
    sntrup761x25519-sha512@openssh.com (draft-ietf-sshm-ntruprime-ssh; OpenSSH 9.0 release notes).
WEAK_SUITE_CLASSES
    IANA "TLS Cipher Suites" registry naming: TLS_RSA_WITH_* = RSA key transport (no forward secrecy, NIST SP 800-52r2
    §3.3.1); *_CBC_* = CBC mode (SP 800-52r2 prefers AEAD); 3DES, RC4, NULL, EXPORT (RFC 7465, SP 800-131A r2).
"""
from __future__ import annotations

from typing import Iterable

PQ_TLS_GROUPS = frozenset({"MLKEM512", "MLKEM768", "MLKEM1024", "SecP256r1MLKEM768", "X25519MLKEM768",
                           "SecP384r1MLKEM1024", "X25519Kyber768Draft00"})
PQ_SSH_KEX = frozenset({"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"})
# SSH signalling pseudo-algorithms (RFC 8308 ext-info, OpenSSH strict KEX): not key exchanges
SSH_PSEUDO_PREFIXES = ("ext-info-", "kex-strict-")

WEAK_SUITE_CLASSES = {
    "static-rsa": lambda s: s.startswith("TLS_RSA_WITH_"),
    "cbc": lambda s: "_CBC_" in s,
    "3des": lambda s: "3DES" in s,
    "rc4": lambda s: "_RC4_" in s,
    "null": lambda s: s.endswith("_NULL_SHA") or "_WITH_NULL_" in s,
    "export": lambda s: "_EXPORT" in s,
}
GROUP_CLASSES = {
    "pq": lambda g: g in PQ_TLS_GROUPS,
    "classical": lambda g: g not in PQ_TLS_GROUPS,
}


def kex_quantum_vulnerable(accepted: Iterable[str], pq: frozenset[str]) -> bool | None:
    """HNDL verdict of a key exchange from what the server accepts: every accepted method PQ/hybrid -> False, none ->
    True, a mix (or nothing) -> None (not derived: the verdict then depends on the client)."""
    names = [a for a in accepted if a and not str(a).startswith(SSH_PSEUDO_PREFIXES)]
    if not names:
        return None
    flags = {a in pq for a in names}
    if flags == {True}:
        return False
    if flags == {False}:
        return True
    return None


def classes_present(names: Iterable[str], classes: dict) -> set[str]:
    return {cls for cls, test in classes.items() for n in names if test(str(n))}
