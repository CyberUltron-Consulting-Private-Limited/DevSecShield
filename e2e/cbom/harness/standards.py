"""Tables transcribed from public standards and registries (O-2), used where the lab oracle does not state a value
(INTERFACES.md v7 §A.2, §A.3). Never from product code (O-1). Each table names its source; O-9 (two-agent rule)
applies: the PR review records the second check.

The key-exchange tables are CLOSED (review 5878413538): a name in neither the PQ nor the classical table is unknown,
and a verdict over an unknown name is not derived (None), never read as classical.

TLS_GROUPS_PQ / TLS_GROUPS_CLASSICAL
    IANA "TLS Supported Groups" registry, tls-parameters-8.csv read 2026-11-12T17:21Z (sha256 d35959b2...), every
    assigned row transcribed. PQ (pure ML-KEM or an ML-KEM / Kyber hybrid): 512 MLKEM512, 513 MLKEM768, 514 MLKEM1024
    (RFC-ietf-tls-mlkem); 4585 SecP256r1MLKEM512, 4586 MLKEM512X25519 (draft-rosomakho-tls-ecdhe-mlkem512);
    4587 SecP256r1MLKEM768, 4588 X25519MLKEM768, 4589 SecP384r1MLKEM1024 (RFC 10024); 4590 curveSM2MLKEM768
    (draft-yang-tls-hybrid-sm2-mlkem); 4591 MLKEM1024X448 (draft-preussmattsson-tls-mlkem1024-x448); 25497
    X25519Kyber768Draft00, 25498 SecP256r1Kyber768Draft00 (both OBSOLETE pre-standard Kyber hybrids, still deployed).
    Classical: 1-44 (sect*, secp*, brainpool*, x25519, x448, GC256A-D, GC512A-C, curveSM2, bign-curve*), 256-260
    ffdhe*, 65281/65282 arbitrary_explicit_*_curves.
SSH_KEX_PQ / SSH_KEX_CLASSICAL
    IANA "Secure Shell (SSH) Protocol Parameters", Key Exchange Method Names (ssh-parameters-16.csv read
    2026-11-12T17:22Z, sha256 982273d0...). PQ: sntrup761x25519-sha512 (RFC 9941), mlkem768x25519-sha256,
    mlkem768nistp256-sha256, mlkem1024nistp384-sha384 (RFC 10042 = draft-ietf-sshm-mlkem-hybrid-kex-10 §2.3),
    mlkem512-sha256, mlkem768-sha256, mlkem1024-sha384 (draft-harrison-mlkem-ssh); plus OpenSSH's vendor name
    sntrup761x25519-sha512@openssh.com (OpenSSH 9.0 release notes). Classical: every other registered method
    (diffie-hellman-group*, diffie-hellman-group-exchange-*, ecdh-sha2-* by RFC 5656 §6.3, ecmqv-sha2, gss-* by
    RFC 4462/8732, rsa1024-sha1, rsa2048-sha256, curve25519-sha256, curve448-sha512) and OpenSSH's
    curve25519-sha256@libssh.org (RFC 8731 §1: the name used before standardisation).
TLS13_SUITES
    RFC 8446 Appendix B.4: the only cipher suites TLS 1.3 defines.
WEAK_SUITE_CLASSES
    IANA "TLS Cipher Suites" registry naming: TLS_RSA_WITH_* = RSA key transport (no forward secrecy, NIST SP 800-52r2
    §3.3.1); *_CBC_* = CBC mode (SP 800-52r2 prefers AEAD); 3DES, RC4, NULL, EXPORT (RFC 7465, SP 800-131A r2).
"""
from __future__ import annotations

import re
from typing import Iterable

TLS_GROUPS_PQ = frozenset({
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "SecP256r1MLKEM512", "MLKEM512X25519",
    "SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024",
    "curveSM2MLKEM768", "MLKEM1024X448",
    "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00",
})
TLS_GROUPS_CLASSICAL = frozenset({
    "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1",
    "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1",
    "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1",
    "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "x25519", "x448",
    "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13",
    "GC256A", "GC256B", "GC256C", "GC256D", "GC512A", "GC512B", "GC512C", "curveSM2",
    "bign-curve256v1", "bign-curve384v1", "bign-curve512v1",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
    "arbitrary_explicit_prime_curves", "arbitrary_explicit_char2_curves",
})
SSH_KEX_PQ = frozenset({
    "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384",
    "mlkem512-sha256", "mlkem768-sha256", "mlkem1024-sha384",
})
SSH_KEX_CLASSICAL = frozenset({
    "diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256", "diffie-hellman-group15-sha512",
    "diffie-hellman-group16-sha512", "diffie-hellman-group17-sha512", "diffie-hellman-group18-sha512",
    "ecmqv-sha2", "rsa1024-sha1", "rsa2048-sha256", "curve25519-sha256", "curve448-sha512",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "curve25519-sha256@libssh.org",
})
# registry wildcards: ecdh-sha2-<curve OID> (RFC 5656 §6.3), gss-<method>-<mechanism OID hash> (RFC 4462, RFC 8732)
SSH_KEX_CLASSICAL_PATTERNS = (re.compile(r"^ecdh-sha2-[\w.]+$"),
                              re.compile(r"^gss-(group1|group14|group15|group16|group17|group18|gex|nistp256|"
                                         r"nistp384|nistp521|curve25519|curve448)-sha\d+-\S+$"))
# kept for callers of the v2 names: the PQ halves of the closed tables
PQ_TLS_GROUPS = TLS_GROUPS_PQ
PQ_SSH_KEX = SSH_KEX_PQ
# SSH signalling pseudo-algorithms (RFC 8308 ext-info, OpenSSH strict KEX): not key exchanges
SSH_PSEUDO_PREFIXES = ("ext-info-", "kex-strict-")
TLS13_SUITES = frozenset({"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                          "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"})

_TLS_LOWER = {**{g.lower(): "classical" for g in TLS_GROUPS_CLASSICAL}, **{g.lower(): "pq" for g in TLS_GROUPS_PQ}}

WEAK_SUITE_CLASSES = {
    "static-rsa": lambda s: s.startswith("TLS_RSA_WITH_"),
    "cbc": lambda s: "_CBC_" in s,
    "3des": lambda s: "3DES" in s,
    "rc4": lambda s: "_RC4_" in s,
    "null": lambda s: s.endswith("_NULL_SHA") or "_WITH_NULL_" in s,
    "export": lambda s: "_EXPORT" in s,
}


def tls_group_class(name: str) -> str | None:
    """'pq', 'classical' or None (not in the registry): names compare case-insensitively, as OpenSSL and the IANA
    registry spell them differently (x25519 / X25519)."""
    return _TLS_LOWER.get(re.sub(r"\s*\(obsolete\)$", "", str(name).strip(), flags=re.I).lower())


def ssh_kex_class(name: str) -> str | None:
    n = str(name).strip()
    if n in SSH_KEX_PQ:
        return "pq"
    if n in SSH_KEX_CLASSICAL or any(p.match(n) for p in SSH_KEX_CLASSICAL_PATTERNS):
        return "classical"
    return None


GROUP_CLASSES = {
    "pq": lambda g: tls_group_class(g) == "pq",
    "classical": lambda g: tls_group_class(g) == "classical",
}


def kex_quantum_vulnerable(accepted: Iterable[str], table: str | frozenset[str]) -> bool | None:
    """HNDL verdict of a key exchange from what the server accepts: every accepted method PQ/hybrid -> False, none ->
    True; a mix, nothing, or any name the closed table does not know -> None (not derived)."""
    classify = tls_group_class if table in ("tls", TLS_GROUPS_PQ) else ssh_kex_class
    names = [a for a in accepted if a and not str(a).startswith(SSH_PSEUDO_PREFIXES)]
    if not names:
        return None
    kinds = {classify(a) for a in names}
    if None in kinds:
        return None
    if kinds == {"pq"}:
        return False
    if kinds == {"classical"}:
        return True
    return None


def classes_present(names: Iterable[str], classes: dict) -> set[str]:
    return {cls for cls, test in classes.items() for n in names if test(str(n))}
