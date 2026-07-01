"""Classical security-strength grade + approved-algorithm allowlist (C15).

The enrichment peer of the C7 PQC grader (:mod:`aibom.cbom.pqc`). Where C7 grades
an asset's resistance to a *quantum* adversary (``nistQuantumSecurityLevel``),
this module grades its resistance to a *classical* adversary — the comparable
effective **security strength in bits** from NIST SP 800-57 Part 1 Rev. 5
Table 2 (AES-128 -> 128, AES-256 -> 256, RSA-2048 -> 112, RSA-3072 -> 128,
P-256 -> 128, SHA-256 -> 128 collision, ...). It ALSO owns the per-framework
``APPROVED_ALGORITHM`` allowlist SETS (FIPS 140-3 / BSI TR-02102-1) — the
positive inversion of the C5 weak-algorithm deny-list.

Lane discipline (the reason this is a scanner-lane module, not a compliance one):
scanners EMIT graph facts, compliance QUERIES them. This module is the pure
grader + the allowlist DATA; the C15 scanner
(:mod:`aibom.cbom.scanners.strength_scan`) APPLIES the grade
(``crypto:securityStrengthBits``), and the C8 compliance frameworks read that
fact + call :func:`is_approved_algorithm`. Nothing here scores, flags, or
serializes, and no framework LOGIC lives here — only the standards-derived
constants (SP 800-57 comparable strengths, SP 800-140C / SP 800-131A approved
functions, BSI TR-02102-1 approved mechanisms) that the frameworks consume.

Clean-room: the strength table and the allowlist sets are our own transcription
of the public standards (URLs in ``docs/cbom-research/LEDGER.md``), not any tool's
source. A quantum-vulnerable public key is graded by its modulus/curve; every
other primitive reuses the C7 NIST category anchor (whose classical bits are, by
construction, the SP 800-57 comparable strengths) so the two graders never
disagree. ``None`` means "not gradeable from the inventory" — the caller then
omits the property rather than asserting a strength it cannot prove.
"""

from __future__ import annotations

from aibom.cbom.pqc import nist_quantum_level
from aibom.model.component import AIComponent

# --------------------------------------------------------------------------- #
# SP 800-57 Table 2 — comparable classical security strengths.
# --------------------------------------------------------------------------- #

# The five NIST PQC categories are anchored to classical primitives (AES-128 =
# 128-bit, AES-192 = 192-bit, AES-256 = 256-bit; SHA-256 collision = 128-bit,
# SHA-384 = 192-bit collision). The C7 grader (nist_quantum_level) already maps a
# quantum-safe symmetric / hash / PQC asset to one of those categories, so a
# category -> comparable-classical-bits map reproduces SP 800-57 Table 2 exactly
# for those primitives (cat 1/2 -> 128, cat 3/4 -> 192, cat 5 -> 256) without a
# second parsing pass.
_NIST_CATEGORY_BITS: dict[int, int] = {1: 128, 2: 128, 3: 192, 4: 192, 5: 256}

# RSA / finite-field-DH / DSA modulus (bits) -> comparable strength (SP 800-57
# Table 2). Descending; the first modulus the key meets or exceeds wins.
_INTEGER_FACTORIZATION_STRENGTH: tuple[tuple[int, int], ...] = (
    (15360, 256), (7680, 192), (3072, 128), (2048, 112),
    (1024, 80), (768, 64), (512, 56),
)
# ECC field / curve size token -> comparable strength (≈ half the field size).
_ECC_CURVE_STRENGTH: tuple[tuple[str, int], ...] = (
    ("521", 256), ("512", 256), ("448", 224), ("384", 192),
    ("256", 128), ("255", 128), ("224", 112), ("192", 96), ("160", 80),
)

# Legacy / broken primitives below NIST category 1 (so the C7 anchor path returns
# None) still have a documented comparable strength worth reporting: DES 56-bit
# key, three-key TDEA 112-bit (meet-in-the-middle), MD5 / SHA-1 collision. These
# grade a number for inventory + coverage; the "disallowed" judgement is a
# separate concern owned by the C5 weak-algorithm deny-list + the framework
# allowlist below (compliance ANDs strength>=floor WITH no-weak-flag).
_LEGACY_STRENGTH: dict[str, int] = {
    "des": 56, "3des": 112, "rc2": 64, "rc4": 128, "blowfish": 128,
    "md5": 64, "md4": 64, "sha1": 80,
}


# --------------------------------------------------------------------------- #
# Canonical algorithm family — normalizes a display name to an allowlist token.
# --------------------------------------------------------------------------- #

# Ordered (most-specific first) so a composite / PQC name is classified before a
# substring family: ML-DSA / SLH-DSA before DSA, ECDSA / EdDSA before DSA,
# 3DES before DES, ECDH / X25519 before DH, SHA-2/3 before SHA-1.
_FAMILY_TOKENS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hybrid", ("HYBRID",)),
    ("ml-kem", ("ML-KEM", "MLKEM", "KYBER")),
    ("ml-dsa", ("ML-DSA", "MLDSA", "DILITHIUM")),
    ("slh-dsa", ("SLH-DSA", "SPHINCS")),
    ("falcon", ("FALCON", "FN-DSA")),
    ("xmss", ("XMSS",)),
    ("lms", ("LMS", "HSS")),
    ("3des", ("3DES", "TRIPLEDES", "TRIPLE-DES", "DES-EDE", "DESEDE", "DES3")),
    ("chacha20", ("CHACHA",)),
    ("aes", ("AES",)),
    ("rc4", ("RC4", "ARCFOUR", "ARC4")),
    ("rc2", ("RC2",)),
    ("blowfish", ("BLOWFISH",)),
    ("des", ("DES",)),
    ("md5", ("MD5",)),
    ("md4", ("MD4",)),
    ("sha3", ("SHA3", "SHA-3")),
    ("shake", ("SHAKE",)),
    ("sha2", ("SHA-224", "SHA224", "SHA-256", "SHA256",
              "SHA-384", "SHA384", "SHA-512", "SHA512")),
    ("sha1", ("SHA-1", "SHA1")),
    ("blake2", ("BLAKE2",)),
    ("ecdsa", ("ECDSA",)),
    ("ecdh", ("ECDH",)),
    ("eddsa", ("ED25519", "ED448", "EDDSA")),
    ("xdh", ("X25519", "X448")),
    ("rsa", ("RSA",)),
    ("dsa", ("DSA",)),
    ("dh", ("DIFFIE", "DH",)),
    ("hmac", ("HMAC",)),
    ("cmac", ("CMAC",)),
    ("poly1305", ("POLY1305",)),
    ("pbkdf2", ("PBKDF2",)),
    ("scrypt", ("SCRYPT",)),
    ("argon2", ("ARGON2",)),
    ("bcrypt", ("BCRYPT",)),
    ("hkdf", ("HKDF",)),
)


def _is_algorithm(component: AIComponent) -> dict[str, str] | None:
    """Return the ``crypto:`` props iff ``component`` is an algorithm asset."""
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "algorithm":
        return None
    return props


def canonical_algorithm_family(component: AIComponent) -> str | None:
    """Normalize an algorithm asset's display name to an allowlist family token.

    ``AES-256-GCM`` -> ``aes``, ``RSA-2048`` -> ``rsa``, ``SHA-384`` -> ``sha2``,
    ``ML-KEM-768`` -> ``ml-kem``, ``3DES`` -> ``3des``. ``None`` for a
    non-algorithm asset or a name matching no known family.
    """
    if _is_algorithm(component) is None:
        return None
    name = (component.name or "").upper()
    for family, tokens in _FAMILY_TOKENS:
        if any(tok in name for tok in tokens):
            return family
    return None


def _public_key_strength(props: dict[str, str], name: str) -> int | None:
    """Comparable strength of a quantum-vulnerable public key (modulus / curve)."""
    key_size = props.get("crypto:keySize")
    if key_size is not None:
        try:
            bits = int(key_size)
        except ValueError:
            bits = 0
        for modulus, strength in _INTEGER_FACTORIZATION_STRENGTH:
            if bits >= modulus:
                return strength
    haystack = f"{props.get('crypto:curve') or ''} {name}"
    for token, strength in _ECC_CURVE_STRENGTH:
        if token in haystack:
            return strength
    return None


def security_strength_bits(component: AIComponent) -> int | None:
    """Comparable classical security strength (bits) for ``component``, or ``None``.

    Pure + total over every ``algorithm`` crypto-asset:

    * a quantum-vulnerable public key (RSA / DH / DSA / ECC) is graded from its
      modulus or curve via the SP 800-57 Table 2 comparable-strength map;
    * a quantum-safe symmetric / hash / PQC asset reuses the C7 NIST category
      anchor (cat 1/2 -> 128, 3/4 -> 192, 5 -> 256) — the same numbers SP 800-57
      Table 2 assigns those primitives;
    * a legacy primitive below category 1 (DES / RC4 / MD5 / SHA-1 / 3DES) grades
      its documented comparable strength;
    * ``None`` for a primitive with no comparable-strength anchor (a bare
      keyed-MAC / KDF whose strength depends on an underlying primitive we did not
      capture) — the caller omits the property rather than over-claiming.
    """
    props = _is_algorithm(component)
    if props is None:
        return None
    name = component.name or ""

    if props.get("crypto:quantumVulnerable") == "true":
        return _public_key_strength(props, name)

    level = nist_quantum_level(component)
    if level is not None and level >= 1:
        return _NIST_CATEGORY_BITS.get(level)

    return _LEGACY_STRENGTH.get(canonical_algorithm_family(component) or "")


# --------------------------------------------------------------------------- #
# Approved-algorithm allowlists — the positive inversion of the C5 deny-list.
# Each set holds canonical family tokens (from canonical_algorithm_family). C8's
# FIPS / BSI frameworks QUERY these via is_approved_algorithm; not-in-set -> fail.
# --------------------------------------------------------------------------- #

# FIPS 140-3 approved security functions (SP 800-140C) that survive the SP
# 800-131A transitions: AES, SHA-2/SHA-3/SHAKE, RSA / ECDSA / EdDSA (FIPS 186-5),
# safe-prime DH / ECDH, HMAC / CMAC, HKDF / PBKDF2, and the FIPS 203/204/205 +
# SP 800-208 PQC suite. Excludes the deprecated/disallowed set: DES, two/three-key
# TDEA (disallowed after 2023), RC2/RC4/Blowfish, MD5/MD4/SHA-1, plain DSA (removed
# in FIPS 186-5), and non-approved ciphers/MACs (ChaCha20, Poly1305, scrypt,
# Argon2, bcrypt).
_FIPS_140_3_APPROVED: frozenset[str] = frozenset({
    "aes", "sha2", "sha3", "shake", "rsa", "ecdsa", "eddsa", "dh", "ecdh",
    "hmac", "cmac", "hkdf", "pbkdf2",
    "ml-kem", "ml-dsa", "slh-dsa", "lms", "hss", "xmss", "hybrid",
})

# BSI TR-02102-1 (2026-01) approved mechanisms — stricter than FIPS: the only
# approved symmetric cipher is AES (ChaCha20 excluded), approved hashes are
# SHA-2/SHA-3, approved asymmetric are RSA / ECDSA / ECDH / EdDSA / DH, approved
# MACs HMAC / CMAC, and the endorsed quantum-safe / hybrid schemes (ML-KEM,
# ML-DSA, SLH-DSA, XMSS/LMS, hybrid). Floors (RSA>=3000, EC>=250, >=120-bit) are a
# separate check owned by C8 — this set is membership only.
_BSI_TR_02102_APPROVED: frozenset[str] = frozenset({
    "aes", "sha2", "sha3", "rsa", "ecdsa", "ecdh", "eddsa", "dh",
    "hmac", "cmac", "hkdf",
    "ml-kem", "ml-dsa", "slh-dsa", "lms", "hss", "xmss", "hybrid",
})

# Framework id -> approved family set. Framework ids match the C8 registry keys.
APPROVED_ALGORITHMS: dict[str, frozenset[str]] = {
    "fips_140_3": _FIPS_140_3_APPROVED,
    "bsi_tr_02102": _BSI_TR_02102_APPROVED,
}


def is_approved_algorithm(framework: str, component: AIComponent) -> bool | None:
    """Is ``component``'s algorithm on ``framework``'s approved allowlist?

    ``True`` / ``False`` for an algorithm asset whose family is / is not approved;
    ``None`` when the framework has no allowlist here or the component is not a
    classifiable algorithm asset (out of scope — the caller skips it, never
    counting it as a fail). C8 inverts a ``False`` into a compliance failure.
    """
    approved = APPROVED_ALGORITHMS.get(framework)
    if approved is None:
        return None
    family = canonical_algorithm_family(component)
    if family is None:
        return None
    return family in approved


__all__ = [
    "APPROVED_ALGORITHMS",
    "canonical_algorithm_family",
    "is_approved_algorithm",
    "security_strength_bits",
]
