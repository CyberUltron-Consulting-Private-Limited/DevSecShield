"""Algorithm identity: one answer to "which algorithm is this, is it quantum-safe?".

Identifiers come in many shapes: dotted OIDs (X.509, PKCS#8), IANA TLS group and
signature-scheme codepoints, SSH key-exchange names, IKEv2 transform ids, cloud API
enums and the names OpenSSL prints. ``resolve`` maps each one to an ``Identity``: a
canonical name, the family label the CBOM rules use, the FIPS 203/204/205 parameter
set and NIST category, the construction (pure, hybrid, composite, classical) and the
quantum verdict.

This file is vendored BYTE-IDENTICAL into the scan node
(scan_node/zs_scan_node/algid.py), the backend (backend/utilities/cbom_sources/algid.py)
and the code lane (aibom/src/aibom/cbom/algid.py), because those packages cannot import
each other; a backend test fails when the copies differ. The tables between the
GENERATED markers are written by scripts/algid/build_algid.py from the captured
registries in scripts/algid/sources: change a source and regenerate, never edit a table
by hand. Stdlib only. The tables are read-only and nothing is memoised, so a lookup
never changes module state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple


class Identity(NamedTuple):
    """What an identifier names (``name`` is None for marker/fallback/prefix hits)."""

    name: str | None
    # PQ RSA EC ECDSA ECDH ED25519 ED448 EDDSA X25519 X448 DSA DH SM2, or None
    family_label: str | None
    primitive: str | None  # CycloneDX 1.6: signature, kem, key-agree, pke, ...
    oid: str | None
    standard: str | None  # FIPS 204, SP 800-208, RFC 10073, ...
    status: str | None  # standard, draft, obsolete, pre-standard, candidate
    parameter_set: str | None  # ML-DSA-65, SLH-DSA-SHA2-128s, ...
    nist_category: int | None  # FIPS 203/204/205 (206 draft) only
    construction: str | None  # pure, hybrid, composite, classical
    quantum: str | None  # vulnerable, safe, hybrid; None: no public-key verdict
    key_size: int | None  # curve bits (EC, SM2, GOST), RSA modulus; None for PQ
    components: tuple[str, ...]
    stateful: bool  # LMS, HSS, XMSS, XMSS^MT
    matched_by: str  # oid codepoint enum name alias marker fallback oid-prefix


# --- BEGIN GENERATED (scripts/algid/build_algid.py) ---
SOURCES_SHA256 = "2198a98071ef1c9ac58805cb1a7a97a1318e7b33c7d7e2e93c47858d8911ffe0"

# canonical name -> (family_label, primitive, standard, status, parameter_set,
#                    nist_category, construction, quantum, key_size, components)
_RAW_ALGS: dict[str, tuple[Any, ...]] = {
    "AES-256-GCM": (
        None, "ae", None, "standard", None, None, "classical", None, 256, (),
    ),
    "BIKE": ("PQ", "kem", None, "candidate", None, None, "pure", "safe", None, ()),
    "BRAINPOOL-P224R1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "BRAINPOOL-P256R1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "BRAINPOOL-P384R1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "BRAINPOOL-P512R1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "CURVE25519": (
        "X25519", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "CURVE448": (
        "X448", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        448, (),
    ),
    "Classic McEliece": (
        "PQ", "kem", None, "candidate", None, None, "pure", "safe", None, (),
    ),
    "DH": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "DSA": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "Dilithium2": (
        "PQ", "signature", None, "pre-standard", "ML-DSA-44", None, "pure", "safe",
        None, (),
    ),
    "Dilithium3": (
        "PQ", "signature", None, "pre-standard", "ML-DSA-65", None, "pure", "safe",
        None, (),
    ),
    "Dilithium5": (
        "PQ", "signature", None, "pre-standard", "ML-DSA-87", None, "pure", "safe",
        None, (),
    ),
    "EC": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ECP-192": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        192, (),
    ),
    "ECP-224": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "ECP-256": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "ECP-384": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "ECP-521": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        521, (),
    ),
    "Ed25519": (
        "ED25519", "signature", None, "standard", None, None, "classical",
        "vulnerable", 256, (),
    ),
    "Ed25519ph": (
        "ED25519", "signature", None, "standard", None, None, "classical",
        "vulnerable", 256, (),
    ),
    "Ed448": (
        "ED448", "signature", None, "standard", None, None, "classical", "vulnerable",
        456, (),
    ),
    "FN-DSA-1024": (
        "PQ", "signature", "FIPS 206", "draft", "FN-DSA-1024", 5, "pure", "safe", None,
        (),
    ),
    "FN-DSA-512": (
        "PQ", "signature", "FIPS 206", "draft", "FN-DSA-512", 1, "pure", "safe", None,
        (),
    ),
    "Falcon-1024": (
        "PQ", "signature", None, "pre-standard", "FN-DSA-1024", None, "pure", "safe",
        None, (),
    ),
    "Falcon-512": (
        "PQ", "signature", None, "pre-standard", "FN-DSA-512", None, "pure", "safe",
        None, (),
    ),
    "FrodoKEM": ("PQ", "kem", None, "candidate", None, None, "pure", "safe", None, ()),
    "GC256A": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GC256B": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GC256C": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GC256D": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GC512A": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "GC512B": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "GC512C": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "GOST R 34.10-2012-256": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GOST R 34.10-2012-512": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "GOST3410-2012-256": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "GOST3410-2012-512": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "HMAC-SHA224": (
        None, "mac", None, "standard", None, None, "classical", None, None, (),
    ),
    "HMAC-SHA256": (
        None, "mac", None, "standard", None, None, "classical", None, None, (),
    ),
    "HMAC-SHA384": (
        None, "mac", None, "standard", None, None, "classical", None, None, (),
    ),
    "HMAC-SHA512": (
        None, "mac", None, "standard", None, None, "classical", None, None, (),
    ),
    "HQC": ("PQ", "kem", None, "candidate", None, None, "pure", "safe", None, ()),
    "HSS": (
        "PQ", "signature", "SP 800-208", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "HashML-DSA-44-with-SHA512": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-44", 2, "pure", "safe",
        None, (),
    ),
    "HashML-DSA-65-with-SHA512": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-65", 3, "pure", "safe",
        None, (),
    ),
    "HashML-DSA-87-with-SHA512": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-87", 5, "pure", "safe",
        None, (),
    ),
    "HashSLH-DSA-SHA2-128f-with-SHA256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-128f", 1, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHA2-128s-with-SHA256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-128s", 1, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHA2-192f-with-SHA512": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-192f", 3, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHA2-192s-with-SHA512": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-192s", 3, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHA2-256f-with-SHA512": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-256f", 5, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHA2-256s-with-SHA512": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-256s", 5, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-128f-with-SHAKE128": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-128f", 1, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-128s-with-SHAKE128": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-128s", 1, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-192f-with-SHAKE256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-192f", 3, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-192s-with-SHAKE256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-192s", 3, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-256f-with-SHAKE256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-256f", 5, "pure",
        "safe", None, (),
    ),
    "HashSLH-DSA-SHAKE-256s-with-SHAKE256": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-256s", 5, "pure",
        "safe", None, (),
    ),
    "Kyber1024": (
        "PQ", "kem", None, "pre-standard", "ML-KEM-1024", None, "pure", "safe", None,
        (),
    ),
    "Kyber512": (
        "PQ", "kem", None, "pre-standard", "ML-KEM-512", None, "pure", "safe", None,
        (),
    ),
    "Kyber768": (
        "PQ", "kem", None, "pre-standard", "ML-KEM-768", None, "pure", "safe", None,
        (),
    ),
    "LMS": (
        "PQ", "signature", "SP 800-208", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "ML-DSA": (
        "PQ", "signature", "FIPS 204", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "ML-DSA-44": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-44", 2, "pure", "safe",
        None, (),
    ),
    "ML-DSA-65": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-65", 3, "pure", "safe",
        None, (),
    ),
    "ML-DSA-87": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-87", 5, "pure", "safe",
        None, (),
    ),
    "ML-KEM": (
        "PQ", "kem", "FIPS 203", "standard", None, None, "pure", "safe", None, (),
    ),
    "ML-KEM-1024": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-1024", 5, "pure", "safe", None,
        (),
    ),
    "ML-KEM-512": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-512", 1, "pure", "safe", None, (),
    ),
    "ML-KEM-768": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "pure", "safe", None, (),
    ),
    "MLDSA44-ECDSA-P256-SHA256": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-44", 2, "composite",
        "hybrid", None, ("ML-DSA-44", "ECDSA-P256-SHA256"),
    ),
    "MLDSA44-Ed25519-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-44", 2, "composite",
        "hybrid", None, ("ML-DSA-44", "Ed25519-SHA512"),
    ),
    "MLDSA44-RSA2048-PKCS15-SHA256": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-44", 2, "composite",
        "hybrid", None, ("ML-DSA-44", "RSA2048-PKCS15-SHA256"),
    ),
    "MLDSA44-RSA2048-PSS-SHA256": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-44", 2, "composite",
        "hybrid", None, ("ML-DSA-44", "RSA2048-PSS-SHA256"),
    ),
    "MLDSA65-ECDSA-P256-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "ECDSA-P256-SHA512"),
    ),
    "MLDSA65-ECDSA-P384-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "ECDSA-P384-SHA512"),
    ),
    "MLDSA65-ECDSA-brainpoolP256r1-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "ECDSA-brainpoolP256r1-SHA512"),
    ),
    "MLDSA65-Ed25519-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "Ed25519-SHA512"),
    ),
    "MLDSA65-RSA3072-PKCS15-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "RSA3072-PKCS15-SHA512"),
    ),
    "MLDSA65-RSA3072-PSS-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "RSA3072-PSS-SHA512"),
    ),
    "MLDSA65-RSA4096-PKCS15-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "RSA4096-PKCS15-SHA512"),
    ),
    "MLDSA65-RSA4096-PSS-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-65", 3, "composite",
        "hybrid", None, ("ML-DSA-65", "RSA4096-PSS-SHA512"),
    ),
    "MLDSA87-ECDSA-P384-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "ECDSA-P384-SHA512"),
    ),
    "MLDSA87-ECDSA-P521-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "ECDSA-P521-SHA512"),
    ),
    "MLDSA87-ECDSA-brainpoolP384r1-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "ECDSA-brainpoolP384r1-SHA512"),
    ),
    "MLDSA87-Ed448-SHAKE256": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "Ed448-SHAKE256"),
    ),
    "MLDSA87-RSA3072-PSS-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "RSA3072-PSS-SHA512"),
    ),
    "MLDSA87-RSA4096-PSS-SHA512": (
        "PQ", "signature", "RFC 10073", "standard", "ML-DSA-87", 5, "composite",
        "hybrid", None, ("ML-DSA-87", "RSA4096-PSS-SHA512"),
    ),
    "MLKEM1024": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-1024", 5, "pure", "safe", None,
        (),
    ),
    "MLKEM1024-ECDH-P384-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-1024", 5, "composite", "hybrid", None,
        ("ML-KEM-1024", "ECDH-P384-SHA3-256"),
    ),
    "MLKEM1024-ECDH-P521-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-1024", 5, "composite", "hybrid", None,
        ("ML-KEM-1024", "ECDH-P521-SHA3-256"),
    ),
    "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-1024", 5, "composite", "hybrid", None,
        ("ML-KEM-1024", "ECDH-brainpoolP384r1-SHA3-256"),
    ),
    "MLKEM1024-RSA3072-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-1024", 5, "composite", "hybrid", None,
        ("ML-KEM-1024", "RSA3072-SHA3-256"),
    ),
    "MLKEM1024-X448-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-1024", 5, "composite", "hybrid", None,
        ("ML-KEM-1024", "X448-SHA3-256"),
    ),
    "MLKEM1024X448": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-1024", 5, "hybrid", "hybrid", None,
        ("ML-KEM-1024", "X448"),
    ),
    "MLKEM512": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-512", 1, "pure", "safe", None, (),
    ),
    "MLKEM512X25519": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-512", 1, "hybrid", "hybrid", None,
        ("ML-KEM-512", "X25519"),
    ),
    "MLKEM768": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "pure", "safe", None, (),
    ),
    "MLKEM768-ECDH-P256-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "ECDH-P256-SHA3-256"),
    ),
    "MLKEM768-ECDH-P384-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "ECDH-P384-SHA3-256"),
    ),
    "MLKEM768-ECDH-brainpoolP256r1-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "ECDH-brainpoolP256r1-SHA3-256"),
    ),
    "MLKEM768-RSA2048-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "RSA2048-SHA3-256"),
    ),
    "MLKEM768-RSA3072-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "RSA3072-SHA3-256"),
    ),
    "MLKEM768-RSA4096-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "RSA4096-SHA3-256"),
    ),
    "MLKEM768-X25519-SHA3-256": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "composite", "hybrid", None,
        ("ML-KEM-768", "X25519-SHA3-256"),
    ),
    "MODP-1024": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1024, (),
    ),
    "MODP-1024-S160": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1024, (),
    ),
    "MODP-1536": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1536, (),
    ),
    "MODP-2048": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "MODP-2048-S224": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "MODP-2048-S256": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "MODP-3072": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        3072, (),
    ),
    "MODP-4096": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        4096, (),
    ),
    "MODP-6144": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        6144, (),
    ),
    "MODP-768": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        768, (),
    ),
    "MODP-8192": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        8192, (),
    ),
    "P-192": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        192, (),
    ),
    "P-224": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "P-256": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "P-384": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "P-521": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        521, (),
    ),
    "RSA": (
        "RSA", "pke", None, "standard", None, None, "classical", "vulnerable", None,
        (),
    ),
    "RSA-1024": (
        "RSA", "pke", None, "standard", None, None, "classical", "vulnerable", 1024,
        (),
    ),
    "RSA-2048": (
        "RSA", "pke", None, "standard", None, None, "classical", "vulnerable", 2048,
        (),
    ),
    "RSA-3072": (
        "RSA", "pke", None, "standard", None, None, "classical", "vulnerable", 3072,
        (),
    ),
    "RSA-4096": (
        "RSA", "pke", None, "standard", None, None, "classical", "vulnerable", 4096,
        (),
    ),
    "RSA-SHA3-224": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSA-SHA3-256": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSA-SHA3-384": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSA-SHA3-512": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSASSA-PSS": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSASSA-PSS-SHAKE128": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "RSASSA-PSS-SHAKE256": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "SLH-DSA": (
        "PQ", "signature", "FIPS 205", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "SLH-DSA-SHA2-128f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-128f", 1, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHA2-128s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-128s", 1, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHA2-192f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-192f", 3, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHA2-192s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-192s", 3, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHA2-256f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-256f", 5, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHA2-256s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHA2-256s", 5, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-128f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-128f", 1, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-128s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-128s", 1, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-192f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-192f", 3, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-192s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-192s", 3, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-256f": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-256f", 5, "pure",
        "safe", None, (),
    ),
    "SLH-DSA-SHAKE-256s": (
        "PQ", "signature", "FIPS 205", "standard", "SLH-DSA-SHAKE-256s", 5, "pure",
        "safe", None, (),
    ),
    "SM2": (
        "SM2", "signature", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "SM2-with-SM3": (
        "SM2", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "SPHINCS+": (
        "PQ", "signature", None, "pre-standard", None, None, "pure", "safe", None, (),
    ),
    "SecP256r1Kyber768Draft00": (
        "PQ", "kem", "FIPS 203", "obsolete", "ML-KEM-768", None, "hybrid", "hybrid",
        None, ("P-256", "Kyber768"),
    ),
    "SecP256r1MLKEM512": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-512", 1, "hybrid", "hybrid", None,
        ("P-256", "ML-KEM-512"),
    ),
    "SecP256r1MLKEM768": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("P-256", "ML-KEM-768"),
    ),
    "SecP384r1MLKEM1024": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-1024", 5, "hybrid", "hybrid",
        None, ("P-384", "ML-KEM-1024"),
    ),
    "X-Wing": (
        "PQ", "kem", None, "draft", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("ML-KEM-768", "X25519"),
    ),
    "X25519": (
        "X25519", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "X25519Kyber768Draft00": (
        "PQ", "kem", "FIPS 203", "obsolete", "ML-KEM-768", None, "hybrid", "hybrid",
        None, ("X25519", "Kyber768"),
    ),
    "X25519MLKEM768": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("X25519", "ML-KEM-768"),
    ),
    "X448": (
        "X448", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        448, (),
    ),
    "XMSS": (
        "PQ", "signature", "SP 800-208", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "XMSS^MT": (
        "PQ", "signature", "SP 800-208", "standard", None, None, "pure", "safe", None,
        (),
    ),
    "arbitrary_explicit_char2_curves": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "arbitrary_explicit_prime_curves": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "bign-curve256v1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "bign-curve384v1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "bign-curve512v1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "bign-with-bash384": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "bign-with-bash512": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "bign-with-hbelt": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "brainpoolP224r1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "brainpoolP256r1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "brainpoolP256r1tls13": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "brainpoolP320r1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        320, (),
    ),
    "brainpoolP384r1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "brainpoolP384r1tls13": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "brainpoolP512r1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "brainpoolP512r1tls13": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        512, (),
    ),
    "curve25519-sha256": (
        "X25519", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "curve448-sha512": (
        "X448", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        448, (),
    ),
    "curveSM2": (
        "SM2", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "curveSM2MLKEM768": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("SM2", "ML-KEM-768"),
    ),
    "des40": (None, "other", None, "standard", None, None, "classical", None, None, ()),
    "dh-sig-hmac-sha1": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-sha1": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-sha224": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-sha256": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-sha384": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-sha512": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-static-sha224-hmac-sha224": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-static-sha256-hmac-sha256": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-static-sha384-hmac-sha384": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dhPop-static-sha512-hmac-sha512": (
        "DH", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "diffie-hellman-group-exchange-sha1": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "diffie-hellman-group-exchange-sha256": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "diffie-hellman-group1-sha1": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1024, (),
    ),
    "diffie-hellman-group14-sha1": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "diffie-hellman-group14-sha256": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "diffie-hellman-group15-sha512": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        3072, (),
    ),
    "diffie-hellman-group16-sha512": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        4096, (),
    ),
    "diffie-hellman-group17-sha512": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        6144, (),
    ),
    "diffie-hellman-group18-sha512": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        8192, (),
    ),
    "dsa-with-SHA1": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA224": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA256": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA3-224": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA3-256": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA3-384": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA3-512": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA384": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "dsa-with-SHA512": (
        "DSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "eccsi-with-sha256": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "eccsi_sha256": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "ecdh-sha2-*": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdh-sha2-nistp256": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "ecdh-sha2-nistp384": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "ecdh-sha2-nistp521": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        521, (),
    ),
    "ecdhPop-static-sha224-hmac-sha224": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdhPop-static-sha256-hmac-sha256": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdhPop-static-sha384-hmac-sha384": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdhPop-static-sha512-hmac-sha512": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA1": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA224": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA256": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA3-224": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA3-256": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA3-384": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA3-512": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA384": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-SHA512": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-shake128": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa-with-shake256": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_brainpoolP256r1tls13_sha256": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_brainpoolP384r1tls13_sha384": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_brainpoolP512r1tls13_sha512": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_secp256r1_sha256": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_secp384r1_sha384": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_secp521r1_sha512": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecdsa_sha1": (
        "ECDSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ecmqv-sha2": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ed25519": (
        "ED25519", "signature", None, "standard", None, None, "classical",
        "vulnerable", None, (),
    ),
    "ed448": (
        "ED448", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "ffdhe2048": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "ffdhe3072": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        3072, (),
    ),
    "ffdhe4096": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        4096, (),
    ),
    "ffdhe6144": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        6144, (),
    ),
    "ffdhe8192": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        8192, (),
    ),
    "gostr34102012_256a": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_256b": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_256c": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_256d": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_512a": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_512b": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gostr34102012_512c": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gss-curve25519-sha256-*": (
        "X25519", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "gss-curve448-sha512-*": (
        "X448", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        448, (),
    ),
    "gss-gex-sha1-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "gss-group1-sha1-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1024, (),
    ),
    "gss-group14-sha1-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "gss-group14-sha256-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "gss-group15-sha512-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        3072, (),
    ),
    "gss-group16-sha512-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        4096, (),
    ),
    "gss-group17-sha512-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        6144, (),
    ),
    "gss-group18-sha512-*": (
        "DH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        8192, (),
    ),
    "gss-nistp256-sha256-*": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "gss-nistp384-sha384-*": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "gss-nistp521-sha512-*": (
        "ECDH", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        521, (),
    ),
    "iso_chinese_ibs": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "iso_ibs1": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "iso_ibs2": (
        "EC", "signature", None, "draft", None, None, "classical", "vulnerable", None,
        (),
    ),
    "md2WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "md4WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "md5WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "mldsa44": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-44", 2, "pure", "safe",
        None, (),
    ),
    "mldsa65": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-65", 3, "pure", "safe",
        None, (),
    ),
    "mldsa87": (
        "PQ", "signature", "FIPS 204", "standard", "ML-DSA-87", 5, "pure", "safe",
        None, (),
    ),
    "mlkem1024-sha384": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-1024", 5, "pure", "safe", None, (),
    ),
    "mlkem1024nistp384-sha384": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-1024", 5, "hybrid", "hybrid",
        None, ("ML-KEM-1024", "P-384"),
    ),
    "mlkem512-sha256": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-512", 1, "pure", "safe", None, (),
    ),
    "mlkem768-sha256": (
        "PQ", "kem", "FIPS 203", "draft", "ML-KEM-768", 3, "pure", "safe", None, (),
    ),
    "mlkem768nistp256-sha256": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("ML-KEM-768", "P-256"),
    ),
    "mlkem768x25519-sha256": (
        "PQ", "kem", "FIPS 203", "standard", "ML-KEM-768", 3, "hybrid", "hybrid", None,
        ("ML-KEM-768", "X25519"),
    ),
    "mtcProof": (None, "other", None, "draft", None, None, "classical", None, None, ()),
    "noSignature": (
        None, "other", None, "standard", None, None, "classical", None, None, (),
    ),
    "rsa1024-sha1": (
        "RSA", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        1024, (),
    ),
    "rsa2048-sha256": (
        "RSA", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        2048, (),
    ),
    "rsa_pkcs1_sha1": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha256": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha256_legacy": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha384": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha384_legacy": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha512": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pkcs1_sha512_legacy": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_pss_sha256": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_pss_sha384": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_pss_sha512": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_rsae_sha256": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_rsae_sha384": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "rsa_pss_rsae_sha512": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "secp160k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        160, (),
    ),
    "secp160r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        160, (),
    ),
    "secp160r2": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        160, (),
    ),
    "secp192k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        192, (),
    ),
    "secp192r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        192, (),
    ),
    "secp224k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "secp224r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        224, (),
    ),
    "secp256k1": (
        "EC", "signature", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "secp256r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "secp384r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        384, (),
    ),
    "secp521r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        521, (),
    ),
    "sect163k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        163, (),
    ),
    "sect163r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        163, (),
    ),
    "sect163r2": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        163, (),
    ),
    "sect193r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        193, (),
    ),
    "sect193r2": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        193, (),
    ),
    "sect233k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        233, (),
    ),
    "sect233r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        233, (),
    ),
    "sect239k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        239, (),
    ),
    "sect283k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        283, (),
    ),
    "sect283r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        283, (),
    ),
    "sect409k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        409, (),
    ),
    "sect409r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        409, (),
    ),
    "sect571k1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        571, (),
    ),
    "sect571r1": (
        "EC", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        571, (),
    ),
    "sha1WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "sha224WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "sha256WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "sha384WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "sha512WithRSAEncryption": (
        "RSA", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "slhdsa_sha2_128f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-128f", 1, "pure", "safe",
        None, (),
    ),
    "slhdsa_sha2_128s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-128s", 1, "pure", "safe",
        None, (),
    ),
    "slhdsa_sha2_192f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-192f", 3, "pure", "safe",
        None, (),
    ),
    "slhdsa_sha2_192s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-192s", 3, "pure", "safe",
        None, (),
    ),
    "slhdsa_sha2_256f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-256f", 5, "pure", "safe",
        None, (),
    ),
    "slhdsa_sha2_256s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHA2-256s", 5, "pure", "safe",
        None, (),
    ),
    "slhdsa_shake_128f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-128f", 1, "pure",
        "safe", None, (),
    ),
    "slhdsa_shake_128s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-128s", 1, "pure",
        "safe", None, (),
    ),
    "slhdsa_shake_192f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-192f", 3, "pure",
        "safe", None, (),
    ),
    "slhdsa_shake_192s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-192s", 3, "pure",
        "safe", None, (),
    ),
    "slhdsa_shake_256f": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-256f", 5, "pure",
        "safe", None, (),
    ),
    "slhdsa_shake_256s": (
        "PQ", "signature", "FIPS 205", "draft", "SLH-DSA-SHAKE-256s", 5, "pure",
        "safe", None, (),
    ),
    "sm2sig_sm3": (
        "SM2", "signature", None, "standard", None, None, "classical", "vulnerable",
        None, (),
    ),
    "sntrup761": (
        "PQ", "kem", None, "candidate", "sntrup761", None, "pure", "safe", None, (),
    ),
    "sntrup761x25519-sha512": (
        "PQ", "kem", None, "standard", "sntrup761", None, "hybrid", "hybrid", None,
        ("sntrup761", "X25519"),
    ),
    "unsigned": (
        None, "other", None, "standard", None, None, "classical", None, None, (),
    ),
    "x25519": (
        "X25519", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        256, (),
    ),
    "x448": (
        "X448", "key-agree", None, "standard", None, None, "classical", "vulnerable",
        448, (),
    ),
}

_RAW_OIDS: dict[str, str] = {
    "1.2.156.10197.1.301": "SM2",
    "1.2.156.10197.1.501": "SM2-with-SM3",
    "1.2.643.7.1.1.1.1": "GOST R 34.10-2012-256",
    "1.2.643.7.1.1.1.2": "GOST R 34.10-2012-512",
    "1.2.643.7.1.1.3.2": "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
    "1.2.643.7.1.1.3.3": "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10045.3.1.1": "P-192",
    "1.2.840.10045.3.1.7": "P-256",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10046.2.1": "DH",
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.9.16.3.17": "HSS",
    "1.3.6.1.5.5.7.6.1": "des40",
    "1.3.6.1.5.5.7.6.2": "noSignature",
    "1.3.6.1.5.5.7.6.3": "dh-sig-hmac-sha1",
    "1.3.6.1.5.5.7.6.4": "dhPop-sha1",
    "1.3.6.1.5.5.7.6.5": "dhPop-sha224",
    "1.3.6.1.5.5.7.6.6": "dhPop-sha256",
    "1.3.6.1.5.5.7.6.7": "dhPop-sha384",
    "1.3.6.1.5.5.7.6.8": "dhPop-sha512",
    "1.3.6.1.5.5.7.6.15": "dhPop-static-sha224-hmac-sha224",
    "1.3.6.1.5.5.7.6.16": "dhPop-static-sha256-hmac-sha256",
    "1.3.6.1.5.5.7.6.17": "dhPop-static-sha384-hmac-sha384",
    "1.3.6.1.5.5.7.6.18": "dhPop-static-sha512-hmac-sha512",
    "1.3.6.1.5.5.7.6.25": "ecdhPop-static-sha224-hmac-sha224",
    "1.3.6.1.5.5.7.6.26": "ecdhPop-static-sha256-hmac-sha256",
    "1.3.6.1.5.5.7.6.27": "ecdhPop-static-sha384-hmac-sha384",
    "1.3.6.1.5.5.7.6.28": "ecdhPop-static-sha512-hmac-sha512",
    "1.3.6.1.5.5.7.6.29": "eccsi-with-sha256",
    "1.3.6.1.5.5.7.6.30": "RSASSA-PSS-SHAKE128",
    "1.3.6.1.5.5.7.6.31": "RSASSA-PSS-SHAKE256",
    "1.3.6.1.5.5.7.6.32": "ecdsa-with-shake128",
    "1.3.6.1.5.5.7.6.33": "ecdsa-with-shake256",
    "1.3.6.1.5.5.7.6.34": "XMSS",
    "1.3.6.1.5.5.7.6.35": "XMSS^MT",
    "1.3.6.1.5.5.7.6.36": "unsigned",
    "1.3.6.1.5.5.7.6.37": "MLDSA44-RSA2048-PSS-SHA256",
    "1.3.6.1.5.5.7.6.38": "MLDSA44-RSA2048-PKCS15-SHA256",
    "1.3.6.1.5.5.7.6.39": "MLDSA44-Ed25519-SHA512",
    "1.3.6.1.5.5.7.6.40": "MLDSA44-ECDSA-P256-SHA256",
    "1.3.6.1.5.5.7.6.41": "MLDSA65-RSA3072-PSS-SHA512",
    "1.3.6.1.5.5.7.6.42": "MLDSA65-RSA3072-PKCS15-SHA512",
    "1.3.6.1.5.5.7.6.43": "MLDSA65-RSA4096-PSS-SHA512",
    "1.3.6.1.5.5.7.6.44": "MLDSA65-RSA4096-PKCS15-SHA512",
    "1.3.6.1.5.5.7.6.45": "MLDSA65-ECDSA-P256-SHA512",
    "1.3.6.1.5.5.7.6.46": "MLDSA65-ECDSA-P384-SHA512",
    "1.3.6.1.5.5.7.6.47": "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
    "1.3.6.1.5.5.7.6.48": "MLDSA65-Ed25519-SHA512",
    "1.3.6.1.5.5.7.6.49": "MLDSA87-ECDSA-P384-SHA512",
    "1.3.6.1.5.5.7.6.50": "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    "1.3.6.1.5.5.7.6.51": "MLDSA87-Ed448-SHAKE256",
    "1.3.6.1.5.5.7.6.52": "MLDSA87-RSA3072-PSS-SHA512",
    "1.3.6.1.5.5.7.6.53": "MLDSA87-RSA4096-PSS-SHA512",
    "1.3.6.1.5.5.7.6.54": "MLDSA87-ECDSA-P521-SHA512",
    "1.3.6.1.5.5.7.6.55": "MLKEM768-RSA2048-SHA3-256",
    "1.3.6.1.5.5.7.6.56": "MLKEM768-RSA3072-SHA3-256",
    "1.3.6.1.5.5.7.6.57": "MLKEM768-RSA4096-SHA3-256",
    "1.3.6.1.5.5.7.6.58": "MLKEM768-X25519-SHA3-256",
    "1.3.6.1.5.5.7.6.59": "MLKEM768-ECDH-P256-SHA3-256",
    "1.3.6.1.5.5.7.6.60": "MLKEM768-ECDH-P384-SHA3-256",
    "1.3.6.1.5.5.7.6.61": "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
    "1.3.6.1.5.5.7.6.62": "MLKEM1024-RSA3072-SHA3-256",
    "1.3.6.1.5.5.7.6.63": "MLKEM1024-ECDH-P384-SHA3-256",
    "1.3.6.1.5.5.7.6.64": "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
    "1.3.6.1.5.5.7.6.65": "MLKEM1024-X448-SHA3-256",
    "1.3.6.1.5.5.7.6.66": "MLKEM1024-ECDH-P521-SHA3-256",
    "1.3.6.1.5.5.7.6.67": "mtcProof",
    "1.3.36.3.3.2.8.1.1.5": "brainpoolP224r1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.9": "brainpoolP320r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.3.132.0.10": "secp256k1",
    "1.3.132.0.33": "P-224",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "2.16.840.1.101.3.4.3.1": "dsa-with-SHA224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
    "2.16.840.1.101.3.4.3.3": "dsa-with-SHA384",
    "2.16.840.1.101.3.4.3.4": "dsa-with-SHA512",
    "2.16.840.1.101.3.4.3.5": "dsa-with-SHA3-224",
    "2.16.840.1.101.3.4.3.6": "dsa-with-SHA3-256",
    "2.16.840.1.101.3.4.3.7": "dsa-with-SHA3-384",
    "2.16.840.1.101.3.4.3.8": "dsa-with-SHA3-512",
    "2.16.840.1.101.3.4.3.9": "ecdsa-with-SHA3-224",
    "2.16.840.1.101.3.4.3.10": "ecdsa-with-SHA3-256",
    "2.16.840.1.101.3.4.3.11": "ecdsa-with-SHA3-384",
    "2.16.840.1.101.3.4.3.12": "ecdsa-with-SHA3-512",
    "2.16.840.1.101.3.4.3.13": "RSA-SHA3-224",
    "2.16.840.1.101.3.4.3.14": "RSA-SHA3-256",
    "2.16.840.1.101.3.4.3.15": "RSA-SHA3-384",
    "2.16.840.1.101.3.4.3.16": "RSA-SHA3-512",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    "2.16.840.1.101.3.4.3.32": "HashML-DSA-44-with-SHA512",
    "2.16.840.1.101.3.4.3.33": "HashML-DSA-65-with-SHA512",
    "2.16.840.1.101.3.4.3.34": "HashML-DSA-87-with-SHA512",
    "2.16.840.1.101.3.4.3.35": "HashSLH-DSA-SHA2-128s-with-SHA256",
    "2.16.840.1.101.3.4.3.36": "HashSLH-DSA-SHA2-128f-with-SHA256",
    "2.16.840.1.101.3.4.3.37": "HashSLH-DSA-SHA2-192s-with-SHA512",
    "2.16.840.1.101.3.4.3.38": "HashSLH-DSA-SHA2-192f-with-SHA512",
    "2.16.840.1.101.3.4.3.39": "HashSLH-DSA-SHA2-256s-with-SHA512",
    "2.16.840.1.101.3.4.3.40": "HashSLH-DSA-SHA2-256f-with-SHA512",
    "2.16.840.1.101.3.4.3.41": "HashSLH-DSA-SHAKE-128s-with-SHAKE128",
    "2.16.840.1.101.3.4.3.42": "HashSLH-DSA-SHAKE-128f-with-SHAKE128",
    "2.16.840.1.101.3.4.3.43": "HashSLH-DSA-SHAKE-192s-with-SHAKE256",
    "2.16.840.1.101.3.4.3.44": "HashSLH-DSA-SHAKE-192f-with-SHAKE256",
    "2.16.840.1.101.3.4.3.45": "HashSLH-DSA-SHAKE-256s-with-SHAKE256",
    "2.16.840.1.101.3.4.3.46": "HashSLH-DSA-SHAKE-256f-with-SHAKE256",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

_RAW_TLS_GROUPS: dict[int, str] = {
    0x0001: "sect163k1",
    0x0002: "sect163r1",
    0x0003: "sect163r2",
    0x0004: "sect193r1",
    0x0005: "sect193r2",
    0x0006: "sect233k1",
    0x0007: "sect233r1",
    0x0008: "sect239k1",
    0x0009: "sect283k1",
    0x000A: "sect283r1",
    0x000B: "sect409k1",
    0x000C: "sect409r1",
    0x000D: "sect571k1",
    0x000E: "sect571r1",
    0x000F: "secp160k1",
    0x0010: "secp160r1",
    0x0011: "secp160r2",
    0x0012: "secp192k1",
    0x0013: "secp192r1",
    0x0014: "secp224k1",
    0x0015: "secp224r1",
    0x0016: "secp256k1",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001A: "brainpoolP256r1",
    0x001B: "brainpoolP384r1",
    0x001C: "brainpoolP512r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x001F: "brainpoolP256r1tls13",
    0x0020: "brainpoolP384r1tls13",
    0x0021: "brainpoolP512r1tls13",
    0x0022: "GC256A",
    0x0023: "GC256B",
    0x0024: "GC256C",
    0x0025: "GC256D",
    0x0026: "GC512A",
    0x0027: "GC512B",
    0x0028: "GC512C",
    0x0029: "curveSM2",
    0x002A: "bign-curve256v1",
    0x002B: "bign-curve384v1",
    0x002C: "bign-curve512v1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    0x11E9: "SecP256r1MLKEM512",
    0x11EA: "MLKEM512X25519",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x11EE: "curveSM2MLKEM768",
    0x11EF: "MLKEM1024X448",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0xFF01: "arbitrary_explicit_prime_curves",
    0xFF02: "arbitrary_explicit_char2_curves",
}

_RAW_TLS_SIGSCHEMES: dict[int, str] = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0420: "rsa_pkcs1_sha256_legacy",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0520: "rsa_pkcs1_sha384_legacy",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0620: "rsa_pkcs1_sha512_legacy",
    0x0704: "eccsi_sha256",
    0x0705: "iso_ibs1",
    0x0706: "iso_ibs2",
    0x0707: "iso_chinese_ibs",
    0x0708: "sm2sig_sm3",
    0x0709: "gostr34102012_256a",
    0x070A: "gostr34102012_256b",
    0x070B: "gostr34102012_256c",
    0x070C: "gostr34102012_256d",
    0x070D: "gostr34102012_512a",
    0x070E: "gostr34102012_512b",
    0x070F: "gostr34102012_512c",
    0x0710: "bign-with-hbelt",
    0x0711: "bign-with-bash384",
    0x0712: "bign-with-bash512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    0x081A: "ecdsa_brainpoolP256r1tls13_sha256",
    0x081B: "ecdsa_brainpoolP384r1tls13_sha384",
    0x081C: "ecdsa_brainpoolP512r1tls13_sha512",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
    0x0911: "slhdsa_sha2_128s",
    0x0912: "slhdsa_sha2_128f",
    0x0913: "slhdsa_sha2_192s",
    0x0914: "slhdsa_sha2_192f",
    0x0915: "slhdsa_sha2_256s",
    0x0916: "slhdsa_sha2_256f",
    0x0917: "slhdsa_shake_128s",
    0x0918: "slhdsa_shake_128f",
    0x0919: "slhdsa_shake_192s",
    0x091A: "slhdsa_shake_192f",
    0x091B: "slhdsa_shake_256s",
    0x091C: "slhdsa_shake_256f",
}

_RAW_SSH_KEX: dict[str, str] = {
    "curve25519-sha256": "curve25519-sha256",
    "curve25519-sha256@libssh.org": "curve25519-sha256",
    "curve448-sha512": "curve448-sha512",
    "diffie-hellman-group-exchange-sha1": "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256": "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group1-sha1": "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1": "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256": "diffie-hellman-group14-sha256",
    "diffie-hellman-group15-sha512": "diffie-hellman-group15-sha512",
    "diffie-hellman-group16-sha512": "diffie-hellman-group16-sha512",
    "diffie-hellman-group17-sha512": "diffie-hellman-group17-sha512",
    "diffie-hellman-group18-sha512": "diffie-hellman-group18-sha512",
    "ecdh-sha2-*": "ecdh-sha2-*",
    "ecdh-sha2-nistp256": "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384": "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521": "ecdh-sha2-nistp521",
    "ecmqv-sha2": "ecmqv-sha2",
    "gss-curve25519-sha256-*": "gss-curve25519-sha256-*",
    "gss-curve448-sha512-*": "gss-curve448-sha512-*",
    "gss-gex-sha1-*": "gss-gex-sha1-*",
    "gss-group1-sha1-*": "gss-group1-sha1-*",
    "gss-group14-sha1-*": "gss-group14-sha1-*",
    "gss-group14-sha256-*": "gss-group14-sha256-*",
    "gss-group15-sha512-*": "gss-group15-sha512-*",
    "gss-group16-sha512-*": "gss-group16-sha512-*",
    "gss-group17-sha512-*": "gss-group17-sha512-*",
    "gss-group18-sha512-*": "gss-group18-sha512-*",
    "gss-nistp256-sha256-*": "gss-nistp256-sha256-*",
    "gss-nistp384-sha384-*": "gss-nistp384-sha384-*",
    "gss-nistp521-sha512-*": "gss-nistp521-sha512-*",
    "mlkem1024-sha384": "mlkem1024-sha384",
    "mlkem1024nistp384-sha384": "mlkem1024nistp384-sha384",
    "mlkem512-sha256": "mlkem512-sha256",
    "mlkem768-sha256": "mlkem768-sha256",
    "mlkem768nistp256-sha256": "mlkem768nistp256-sha256",
    "mlkem768x25519-sha256": "mlkem768x25519-sha256",
    "rsa1024-sha1": "rsa1024-sha1",
    "rsa2048-sha256": "rsa2048-sha256",
    "sntrup761x25519-sha512": "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512",
}

_RAW_IKE_KE: dict[int, str] = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    22: "MODP-1024-S160",
    23: "MODP-2048-S224",
    24: "MODP-2048-S256",
    25: "ECP-192",
    26: "ECP-224",
    27: "BRAINPOOL-P224R1",
    28: "BRAINPOOL-P256R1",
    29: "BRAINPOOL-P384R1",
    30: "BRAINPOOL-P512R1",
    31: "CURVE25519",
    32: "CURVE448",
    33: "GOST3410-2012-256",
    34: "GOST3410-2012-512",
    35: "ML-KEM-512",
    36: "ML-KEM-768",
    37: "ML-KEM-1024",
}

_RAW_AWS: dict[str, dict[str, str]] = {
    "acm-pca.KeyAlgorithm": {
        "EC_prime256v1": "P-256",
        "EC_secp384r1": "P-384",
        "EC_secp521r1": "P-521",
        "ML_DSA_44": "ML-DSA-44",
        "ML_DSA_65": "ML-DSA-65",
        "ML_DSA_87": "ML-DSA-87",
        "RSA_2048": "RSA-2048",
        "RSA_3072": "RSA-3072",
        "RSA_4096": "RSA-4096",
        "SM2": "SM2",
    },
    "acm-pca.SigningAlgorithm": {
        "ML_DSA_44": "ML-DSA-44",
        "ML_DSA_65": "ML-DSA-65",
        "ML_DSA_87": "ML-DSA-87",
        "SHA256WITHECDSA": "ecdsa-with-SHA256",
        "SHA256WITHRSA": "sha256WithRSAEncryption",
        "SHA384WITHECDSA": "ecdsa-with-SHA384",
        "SHA384WITHRSA": "sha384WithRSAEncryption",
        "SHA512WITHECDSA": "ecdsa-with-SHA512",
        "SHA512WITHRSA": "sha512WithRSAEncryption",
        "SM3WITHSM2": "SM2-with-SM3",
    },
    "acm.KeyAlgorithm": {
        "EC_prime256v1": "P-256",
        "EC_secp384r1": "P-384",
        "EC_secp521r1": "P-521",
        "RSA_1024": "RSA-1024",
        "RSA_2048": "RSA-2048",
        "RSA_3072": "RSA-3072",
        "RSA_4096": "RSA-4096",
    },
    "kms.KeySpec": {
        "ECC_NIST_EDWARDS25519": "Ed25519",
        "ECC_NIST_P256": "P-256",
        "ECC_NIST_P384": "P-384",
        "ECC_NIST_P521": "P-521",
        "ECC_SECG_P256K1": "secp256k1",
        "HMAC_224": "HMAC-SHA224",
        "HMAC_256": "HMAC-SHA256",
        "HMAC_384": "HMAC-SHA384",
        "HMAC_512": "HMAC-SHA512",
        "ML_DSA_44": "ML-DSA-44",
        "ML_DSA_65": "ML-DSA-65",
        "ML_DSA_87": "ML-DSA-87",
        "RSA_2048": "RSA-2048",
        "RSA_3072": "RSA-3072",
        "RSA_4096": "RSA-4096",
        "SM2": "SM2",
        "SYMMETRIC_DEFAULT": "AES-256-GCM",
    },
    "kms.SigningAlgorithmSpec": {
        "ECDSA_SHA_256": "ecdsa-with-SHA256",
        "ECDSA_SHA_384": "ecdsa-with-SHA384",
        "ECDSA_SHA_512": "ecdsa-with-SHA512",
        "ED25519_PH_SHA_512": "Ed25519ph",
        "ED25519_SHA_512": "Ed25519",
        "ML_DSA_SHAKE_256": "ML-DSA",
        "RSASSA_PKCS1_V1_5_SHA_256": "sha256WithRSAEncryption",
        "RSASSA_PKCS1_V1_5_SHA_384": "sha384WithRSAEncryption",
        "RSASSA_PKCS1_V1_5_SHA_512": "sha512WithRSAEncryption",
        "RSASSA_PSS_SHA_256": "RSASSA-PSS",
        "RSASSA_PSS_SHA_384": "RSASSA-PSS",
        "RSASSA_PSS_SHA_512": "RSASSA-PSS",
        "SM2DSA": "SM2",
    },
}

_RAW_AWS_TLS_POLICY: dict[str, dict[str, tuple[str, ...]]] = {
    "apigateway": {
        "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09": (),
        "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09": (),
        "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09": (),
        "SecurityPolicy_TLS13_1_2_PQ_2025_09": (),
    },
    "elbv2": {
        "ELBSecurityPolicy-TLS13-1-0-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-0-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
        "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09": (
            "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768",
        ),
    },
}

_RAW_OPENSSL_TEXT: dict[str, str] = {
    "ED25519": "Ed25519",
    "ED448": "Ed448",
    "GOST R 34.10-2012 with 256 bit modulus": "GOST R 34.10-2012-256",
    "GOST R 34.10-2012 with 512 bit modulus": "GOST R 34.10-2012-512",
    "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)":
        "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
    "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)":
        "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)",
    "HASH-ML-DSA-65-WITH-SHA512": "HashML-DSA-65-with-SHA512",
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "ML-KEM-1024": "ML-KEM-1024",
    "ML-KEM-512": "ML-KEM-512",
    "ML-KEM-768": "ML-KEM-768",
    "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHAKE-128f": "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-128s": "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-192f": "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-192s": "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-256f": "SLH-DSA-SHAKE-256f",
    "SLH-DSA-SHAKE-256s": "SLH-DSA-SHAKE-256s",
    "SM2-with-SM3": "SM2-with-SM3",
    "X25519": "X25519",
    "X448": "X448",
    "dsaEncryption": "DSA",
    "dsa_with_SHA256": "dsa-with-SHA256",
    "ecdsa-with-SHA256": "ecdsa-with-SHA256",
    "id-ecPublicKey": "EC",
    "rsaEncryption": "RSA",
    "rsassaPss": "RSASSA-PSS",
    "sha256WithRSAEncryption": "sha256WithRSAEncryption",
}

_RAW_ALIASES: dict[str, str] = {
    "aes256gcm": "AES-256-GCM",
    "arbitraryexplicitchar2curves": "arbitrary_explicit_char2_curves",
    "arbitraryexplicitprimecurves": "arbitrary_explicit_prime_curves",
    "bigncurve256v1": "bign-curve256v1",
    "bigncurve384v1": "bign-curve384v1",
    "bigncurve512v1": "bign-curve512v1",
    "bignwithbash384": "bign-with-bash384",
    "bignwithbash512": "bign-with-bash512",
    "bignwithhbelt": "bign-with-hbelt",
    "bike": "BIKE",
    "brainpoolp224r1": "brainpoolP224r1",
    "brainpoolp256r1": "brainpoolP256r1",
    "brainpoolp256r1tls13": "brainpoolP256r1tls13",
    "brainpoolp320r1": "brainpoolP320r1",
    "brainpoolp384r1": "brainpoolP384r1",
    "brainpoolp384r1tls13": "brainpoolP384r1tls13",
    "brainpoolp512r1": "brainpoolP512r1",
    "brainpoolp512r1tls13": "brainpoolP512r1tls13",
    "classicmceliece": "Classic McEliece",
    "crystalsdilithium2": "Dilithium2",
    "crystalsdilithium3": "Dilithium3",
    "crystalsdilithium5": "Dilithium5",
    "crystalskyber1024": "Kyber1024",
    "crystalskyber512": "Kyber512",
    "crystalskyber768": "Kyber768",
    "curve25519": "CURVE25519",
    "curve25519sha256": "curve25519-sha256",
    "curve448": "CURVE448",
    "curve448sha512": "curve448-sha512",
    "curvesm2": "curveSM2",
    "curvesm2mlkem768": "curveSM2MLKEM768",
    "des40": "des40",
    "dh": "DH",
    "dhe": "DH",
    "dhpopsha1": "dhPop-sha1",
    "dhpopsha224": "dhPop-sha224",
    "dhpopsha256": "dhPop-sha256",
    "dhpopsha384": "dhPop-sha384",
    "dhpopsha512": "dhPop-sha512",
    "dhpopstaticsha224hmacsha224": "dhPop-static-sha224-hmac-sha224",
    "dhpopstaticsha256hmacsha256": "dhPop-static-sha256-hmac-sha256",
    "dhpopstaticsha384hmacsha384": "dhPop-static-sha384-hmac-sha384",
    "dhpopstaticsha512hmacsha512": "dhPop-static-sha512-hmac-sha512",
    "dhpublicnumber": "DH",
    "dhsighmacsha1": "dh-sig-hmac-sha1",
    "diffiehellmangroup14sha1": "diffie-hellman-group14-sha1",
    "diffiehellmangroup14sha256": "diffie-hellman-group14-sha256",
    "diffiehellmangroup15sha512": "diffie-hellman-group15-sha512",
    "diffiehellmangroup16sha512": "diffie-hellman-group16-sha512",
    "diffiehellmangroup17sha512": "diffie-hellman-group17-sha512",
    "diffiehellmangroup18sha512": "diffie-hellman-group18-sha512",
    "diffiehellmangroup1sha1": "diffie-hellman-group1-sha1",
    "diffiehellmangroupexchangesha1": "diffie-hellman-group-exchange-sha1",
    "diffiehellmangroupexchangesha256": "diffie-hellman-group-exchange-sha256",
    "dilithium2": "Dilithium2",
    "dilithium3": "Dilithium3",
    "dilithium5": "Dilithium5",
    "dsa": "DSA",
    "dsaencryption": "DSA",
    "dsawithsha1": "dsa-with-SHA1",
    "dsawithsha224": "dsa-with-SHA224",
    "dsawithsha256": "dsa-with-SHA256",
    "dsawithsha3224": "dsa-with-SHA3-224",
    "dsawithsha3256": "dsa-with-SHA3-256",
    "dsawithsha3384": "dsa-with-SHA3-384",
    "dsawithsha3512": "dsa-with-SHA3-512",
    "dsawithsha384": "dsa-with-SHA384",
    "dsawithsha512": "dsa-with-SHA512",
    "ec": "EC",
    "ecc": "EC",
    "eccsisha256": "eccsi_sha256",
    "eccsiwithsha256": "eccsi-with-sha256",
    "ecdhpopstaticsha224hmacsha224": "ecdhPop-static-sha224-hmac-sha224",
    "ecdhpopstaticsha256hmacsha256": "ecdhPop-static-sha256-hmac-sha256",
    "ecdhpopstaticsha384hmacsha384": "ecdhPop-static-sha384-hmac-sha384",
    "ecdhpopstaticsha512hmacsha512": "ecdhPop-static-sha512-hmac-sha512",
    "ecdhsha2*": "ecdh-sha2-*",
    "ecdhsha2nistp256": "ecdh-sha2-nistp256",
    "ecdhsha2nistp384": "ecdh-sha2-nistp384",
    "ecdhsha2nistp521": "ecdh-sha2-nistp521",
    "ecdsa": "EC",
    "ecdsabrainpoolp256r1tls13sha256": "ecdsa_brainpoolP256r1tls13_sha256",
    "ecdsabrainpoolp384r1tls13sha384": "ecdsa_brainpoolP384r1tls13_sha384",
    "ecdsabrainpoolp512r1tls13sha512": "ecdsa_brainpoolP512r1tls13_sha512",
    "ecdsasecp256r1sha256": "ecdsa_secp256r1_sha256",
    "ecdsasecp384r1sha384": "ecdsa_secp384r1_sha384",
    "ecdsasecp521r1sha512": "ecdsa_secp521r1_sha512",
    "ecdsasha1": "ecdsa_sha1",
    "ecdsawithsha1": "ecdsa-with-SHA1",
    "ecdsawithsha224": "ecdsa-with-SHA224",
    "ecdsawithsha256": "ecdsa-with-SHA256",
    "ecdsawithsha3224": "ecdsa-with-SHA3-224",
    "ecdsawithsha3256": "ecdsa-with-SHA3-256",
    "ecdsawithsha3384": "ecdsa-with-SHA3-384",
    "ecdsawithsha3512": "ecdsa-with-SHA3-512",
    "ecdsawithsha384": "ecdsa-with-SHA384",
    "ecdsawithsha512": "ecdsa-with-SHA512",
    "ecdsawithshake128": "ecdsa-with-shake128",
    "ecdsawithshake256": "ecdsa-with-shake256",
    "ecmqvsha2": "ecmqv-sha2",
    "ecp192": "ECP-192",
    "ecp224": "ECP-224",
    "ecp256": "ECP-256",
    "ecp384": "ECP-384",
    "ecp521": "ECP-521",
    "ecpublickey": "EC",
    "ed25519": "Ed25519",
    "ed25519ph": "Ed25519ph",
    "ed448": "Ed448",
    "falcon1024": "Falcon-1024",
    "falcon512": "Falcon-512",
    "ffdhe": "DH",
    "ffdhe2048": "ffdhe2048",
    "ffdhe3072": "ffdhe3072",
    "ffdhe4096": "ffdhe4096",
    "ffdhe6144": "ffdhe6144",
    "ffdhe8192": "ffdhe8192",
    "fndsa1024": "FN-DSA-1024",
    "fndsa512": "FN-DSA-512",
    "frodokem": "FrodoKEM",
    "gc256a": "GC256A",
    "gc256b": "GC256B",
    "gc256c": "GC256C",
    "gc256d": "GC256D",
    "gc512a": "GC512A",
    "gc512b": "GC512B",
    "gc512c": "GC512C",
    "gost34102012256": "GOST R 34.10-2012-256",
    "gost34102012512": "GOST R 34.10-2012-512",
    "gostr34102012256": "GOST R 34.10-2012-256",
    "gostr34102012256a": "gostr34102012_256a",
    "gostr34102012256b": "gostr34102012_256b",
    "gostr34102012256c": "gostr34102012_256c",
    "gostr34102012256d": "gostr34102012_256d",
    "gostr34102012512": "GOST R 34.10-2012-512",
    "gostr34102012512a": "gostr34102012_512a",
    "gostr34102012512b": "gostr34102012_512b",
    "gostr34102012512c": "gostr34102012_512c",
    "gostr34102012with256bitmodulus": "GOST R 34.10-2012-256",
    "gostr34102012with512bitmodulus": "GOST R 34.10-2012-512",
    "gostr34102012withgostr34112012256bit":
        "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
    "gostr34102012withgostr34112012512bit":
        "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)",
    "gsscurve25519sha256*": "gss-curve25519-sha256-*",
    "gsscurve448sha512*": "gss-curve448-sha512-*",
    "gssgexsha1*": "gss-gex-sha1-*",
    "gssgroup14sha1*": "gss-group14-sha1-*",
    "gssgroup14sha256*": "gss-group14-sha256-*",
    "gssgroup15sha512*": "gss-group15-sha512-*",
    "gssgroup16sha512*": "gss-group16-sha512-*",
    "gssgroup17sha512*": "gss-group17-sha512-*",
    "gssgroup18sha512*": "gss-group18-sha512-*",
    "gssgroup1sha1*": "gss-group1-sha1-*",
    "gssnistp256sha256*": "gss-nistp256-sha256-*",
    "gssnistp384sha384*": "gss-nistp384-sha384-*",
    "gssnistp521sha512*": "gss-nistp521-sha512-*",
    "hashmldsa44withsha512": "HashML-DSA-44-with-SHA512",
    "hashmldsa65withsha512": "HashML-DSA-65-with-SHA512",
    "hashmldsa87withsha512": "HashML-DSA-87-with-SHA512",
    "hashslhdsasha2128fwithsha256": "HashSLH-DSA-SHA2-128f-with-SHA256",
    "hashslhdsasha2128swithsha256": "HashSLH-DSA-SHA2-128s-with-SHA256",
    "hashslhdsasha2192fwithsha512": "HashSLH-DSA-SHA2-192f-with-SHA512",
    "hashslhdsasha2192swithsha512": "HashSLH-DSA-SHA2-192s-with-SHA512",
    "hashslhdsasha2256fwithsha512": "HashSLH-DSA-SHA2-256f-with-SHA512",
    "hashslhdsasha2256swithsha512": "HashSLH-DSA-SHA2-256s-with-SHA512",
    "hashslhdsashake128fwithshake128": "HashSLH-DSA-SHAKE-128f-with-SHAKE128",
    "hashslhdsashake128swithshake128": "HashSLH-DSA-SHAKE-128s-with-SHAKE128",
    "hashslhdsashake192fwithshake256": "HashSLH-DSA-SHAKE-192f-with-SHAKE256",
    "hashslhdsashake192swithshake256": "HashSLH-DSA-SHAKE-192s-with-SHAKE256",
    "hashslhdsashake256fwithshake256": "HashSLH-DSA-SHAKE-256f-with-SHAKE256",
    "hashslhdsashake256swithshake256": "HashSLH-DSA-SHAKE-256s-with-SHAKE256",
    "hmacsha224": "HMAC-SHA224",
    "hmacsha256": "HMAC-SHA256",
    "hmacsha384": "HMAC-SHA384",
    "hmacsha512": "HMAC-SHA512",
    "hqc": "HQC",
    "hss": "HSS",
    "idalgmlkem1024": "ML-KEM-1024",
    "idalgmlkem512": "ML-KEM-512",
    "idalgmlkem768": "ML-KEM-768",
    "idecpublickey": "EC",
    "idmldsa44": "ML-DSA-44",
    "idmldsa65": "ML-DSA-65",
    "idmldsa87": "ML-DSA-87",
    "isochineseibs": "iso_chinese_ibs",
    "isoibs1": "iso_ibs1",
    "isoibs2": "iso_ibs2",
    "kemxwing": "X-Wing",
    "kyber1024": "Kyber1024",
    "kyber512": "Kyber512",
    "kyber768": "Kyber768",
    "lms": "LMS",
    "mceliece": "Classic McEliece",
    "md2withrsaencryption": "md2WithRSAEncryption",
    "md4withrsaencryption": "md4WithRSAEncryption",
    "md5withrsaencryption": "md5WithRSAEncryption",
    "mldsa": "ML-DSA",
    "mldsa44": "ML-DSA-44",
    "mldsa44ecdsap256sha256": "MLDSA44-ECDSA-P256-SHA256",
    "mldsa44ed25519sha512": "MLDSA44-Ed25519-SHA512",
    "mldsa44rsa2048pkcs15sha256": "MLDSA44-RSA2048-PKCS15-SHA256",
    "mldsa44rsa2048psssha256": "MLDSA44-RSA2048-PSS-SHA256",
    "mldsa65": "ML-DSA-65",
    "mldsa65ecdsabrainpoolp256r1sha512": "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
    "mldsa65ecdsap256sha512": "MLDSA65-ECDSA-P256-SHA512",
    "mldsa65ecdsap384sha512": "MLDSA65-ECDSA-P384-SHA512",
    "mldsa65ed25519sha512": "MLDSA65-Ed25519-SHA512",
    "mldsa65rsa3072pkcs15sha512": "MLDSA65-RSA3072-PKCS15-SHA512",
    "mldsa65rsa3072psssha512": "MLDSA65-RSA3072-PSS-SHA512",
    "mldsa65rsa4096pkcs15sha512": "MLDSA65-RSA4096-PKCS15-SHA512",
    "mldsa65rsa4096psssha512": "MLDSA65-RSA4096-PSS-SHA512",
    "mldsa87": "ML-DSA-87",
    "mldsa87ecdsabrainpoolp384r1sha512": "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    "mldsa87ecdsap384sha512": "MLDSA87-ECDSA-P384-SHA512",
    "mldsa87ecdsap521sha512": "MLDSA87-ECDSA-P521-SHA512",
    "mldsa87ed448shake256": "MLDSA87-Ed448-SHAKE256",
    "mldsa87rsa3072psssha512": "MLDSA87-RSA3072-PSS-SHA512",
    "mldsa87rsa4096psssha512": "MLDSA87-RSA4096-PSS-SHA512",
    "mlkem": "ML-KEM",
    "mlkem1024": "ML-KEM-1024",
    "mlkem1024ecdhbrainpoolp384r1sha3256": "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
    "mlkem1024ecdhp384sha3256": "MLKEM1024-ECDH-P384-SHA3-256",
    "mlkem1024ecdhp521sha3256": "MLKEM1024-ECDH-P521-SHA3-256",
    "mlkem1024nistp384sha384": "mlkem1024nistp384-sha384",
    "mlkem1024rsa3072sha3256": "MLKEM1024-RSA3072-SHA3-256",
    "mlkem1024sha384": "mlkem1024-sha384",
    "mlkem1024x448": "MLKEM1024X448",
    "mlkem1024x448sha3256": "MLKEM1024-X448-SHA3-256",
    "mlkem512": "ML-KEM-512",
    "mlkem512sha256": "mlkem512-sha256",
    "mlkem512x25519": "MLKEM512X25519",
    "mlkem768": "ML-KEM-768",
    "mlkem768ecdhbrainpoolp256r1sha3256": "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
    "mlkem768ecdhp256sha3256": "MLKEM768-ECDH-P256-SHA3-256",
    "mlkem768ecdhp384sha3256": "MLKEM768-ECDH-P384-SHA3-256",
    "mlkem768nistp256sha256": "mlkem768nistp256-sha256",
    "mlkem768rsa2048sha3256": "MLKEM768-RSA2048-SHA3-256",
    "mlkem768rsa3072sha3256": "MLKEM768-RSA3072-SHA3-256",
    "mlkem768rsa4096sha3256": "MLKEM768-RSA4096-SHA3-256",
    "mlkem768sha256": "mlkem768-sha256",
    "mlkem768x25519sha256": "mlkem768x25519-sha256",
    "mlkem768x25519sha3256": "MLKEM768-X25519-SHA3-256",
    "modp1024": "MODP-1024",
    "modp1024s160": "MODP-1024-S160",
    "modp1536": "MODP-1536",
    "modp2048": "MODP-2048",
    "modp2048s224": "MODP-2048-S224",
    "modp2048s256": "MODP-2048-S256",
    "modp3072": "MODP-3072",
    "modp4096": "MODP-4096",
    "modp6144": "MODP-6144",
    "modp768": "MODP-768",
    "modp8192": "MODP-8192",
    "mtcproof": "mtcProof",
    "nistp256": "P-256",
    "nistp384": "P-384",
    "nistp521": "P-521",
    "nosignature": "noSignature",
    "p192": "P-192",
    "p224": "P-224",
    "p256": "P-256",
    "p384": "P-384",
    "p521": "P-521",
    "prime256v1": "P-256",
    "rsa": "RSA",
    "rsa1024": "RSA-1024",
    "rsa1024sha1": "rsa1024-sha1",
    "rsa2048": "RSA-2048",
    "rsa2048sha256": "rsa2048-sha256",
    "rsa3072": "RSA-3072",
    "rsa4096": "RSA-4096",
    "rsaencryption": "RSA",
    "rsapkcs1sha1": "rsa_pkcs1_sha1",
    "rsapkcs1sha256": "rsa_pkcs1_sha256",
    "rsapkcs1sha256legacy": "rsa_pkcs1_sha256_legacy",
    "rsapkcs1sha384": "rsa_pkcs1_sha384",
    "rsapkcs1sha384legacy": "rsa_pkcs1_sha384_legacy",
    "rsapkcs1sha512": "rsa_pkcs1_sha512",
    "rsapkcs1sha512legacy": "rsa_pkcs1_sha512_legacy",
    "rsapss": "RSASSA-PSS",
    "rsapsspsssha256": "rsa_pss_pss_sha256",
    "rsapsspsssha384": "rsa_pss_pss_sha384",
    "rsapsspsssha512": "rsa_pss_pss_sha512",
    "rsapssrsaesha256": "rsa_pss_rsae_sha256",
    "rsapssrsaesha384": "rsa_pss_rsae_sha384",
    "rsapssrsaesha512": "rsa_pss_rsae_sha512",
    "rsasha3224": "RSA-SHA3-224",
    "rsasha3256": "RSA-SHA3-256",
    "rsasha3384": "RSA-SHA3-384",
    "rsasha3512": "RSA-SHA3-512",
    "rsassapss": "RSASSA-PSS",
    "rsassapssshake128": "RSASSA-PSS-SHAKE128",
    "rsassapssshake256": "RSASSA-PSS-SHAKE256",
    "secp160k1": "secp160k1",
    "secp160r1": "secp160r1",
    "secp160r2": "secp160r2",
    "secp192k1": "secp192k1",
    "secp192r1": "secp192r1",
    "secp224k1": "secp224k1",
    "secp224r1": "secp224r1",
    "secp256k1": "secp256k1",
    "secp256r1": "P-256",
    "secp256r1kyber768draft00": "SecP256r1Kyber768Draft00",
    "secp256r1mlkem512": "SecP256r1MLKEM512",
    "secp256r1mlkem768": "SecP256r1MLKEM768",
    "secp384r1": "P-384",
    "secp384r1mlkem1024": "SecP384r1MLKEM1024",
    "secp521r1": "P-521",
    "sect163k1": "sect163k1",
    "sect163r1": "sect163r1",
    "sect163r2": "sect163r2",
    "sect193r1": "sect193r1",
    "sect193r2": "sect193r2",
    "sect233k1": "sect233k1",
    "sect233r1": "sect233r1",
    "sect239k1": "sect239k1",
    "sect283k1": "sect283k1",
    "sect283r1": "sect283r1",
    "sect409k1": "sect409k1",
    "sect409r1": "sect409r1",
    "sect571k1": "sect571k1",
    "sect571r1": "sect571r1",
    "sha1withrsaencryption": "sha1WithRSAEncryption",
    "sha224withrsaencryption": "sha224WithRSAEncryption",
    "sha256withrsaencryption": "sha256WithRSAEncryption",
    "sha384withrsaencryption": "sha384WithRSAEncryption",
    "sha512withrsaencryption": "sha512WithRSAEncryption",
    "slhdsa": "SLH-DSA",
    "slhdsasha2128f": "SLH-DSA-SHA2-128f",
    "slhdsasha2128s": "SLH-DSA-SHA2-128s",
    "slhdsasha2192f": "SLH-DSA-SHA2-192f",
    "slhdsasha2192s": "SLH-DSA-SHA2-192s",
    "slhdsasha2256f": "SLH-DSA-SHA2-256f",
    "slhdsasha2256s": "SLH-DSA-SHA2-256s",
    "slhdsashake128f": "SLH-DSA-SHAKE-128f",
    "slhdsashake128s": "SLH-DSA-SHAKE-128s",
    "slhdsashake192f": "SLH-DSA-SHAKE-192f",
    "slhdsashake192s": "SLH-DSA-SHAKE-192s",
    "slhdsashake256f": "SLH-DSA-SHAKE-256f",
    "slhdsashake256s": "SLH-DSA-SHAKE-256s",
    "sm2": "SM2",
    "sm2sigsm3": "sm2sig_sm3",
    "sm2withsm3": "SM2-with-SM3",
    "sntrup761": "sntrup761",
    "sntrup761x25519sha512": "sntrup761x25519-sha512",
    "sphincs+": "SPHINCS+",
    "sphincsplus": "SPHINCS+",
    "sshed25519": "Ed25519",
    "sshed448": "Ed448",
    "unsigned": "unsigned",
    "x25519": "X25519",
    "x25519kyber768draft00": "X25519Kyber768Draft00",
    "x25519mlkem768": "X25519MLKEM768",
    "x448": "X448",
    "xmss": "XMSS",
    "xmss^mt": "XMSS^MT",
    "xmssmt": "XMSS^MT",
    "xwing": "X-Wing",
}

_OID_PREFIXES: tuple[tuple[str, str, str | None], ...] = (
    ("2.16.840.1.114027.80.8.1.", "composite-prototype", "signature"),
    ("2.16.840.1.114027.80.9.1.", "composite-prototype", "signature"),
    ("2.16.840.1.114027.80.5.2.", "composite-prototype", "kem"),
    ("1.3.9999.", "oqs-arc", None),
    ("1.3.6.1.4.1.2.267.", "oqs-arc", None),
    ("1.3.6.1.4.1.22554.", "oqs-arc", None),
)

_RAW_CODE_LANE_X509_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.2.840.10045.4.3.1": "ecdsaWithSHA224",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.10040.4.3": "dsaWithSHA1",
    "2.16.840.1.101.3.4.3.2": "dsaWithSHA256",
}

_RAW_CODE_LANE_X509_KEYS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

_GREASE = (
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
)

_PQ_MARKERS = (
    "MLKEM", "MLDSA", "SLHDSA", "HASHMLDSA", "FNDSA", "FALCON",
    "LMS", "HSS", "XMSS", "KYBER", "DILITHIUM", "SPHINCS",
    "SNTRUP", "FRODO", "HQC", "MCELIECE", "BIKE", "XWING",
)

_PRE_STANDARD_MARKERS = (
    "KYBER", "DILITHIUM", "SPHINCS", "FALCON",
)

_CLASSICAL_MARKERS = (
    "RSA", "ECDSA", "ECDH", "ED25519", "ED448", "X25519",
    "X448", "P256", "P384", "P521", "SECP", "BRAINPOOL",
    "NISTP", "SM2",
)

TLS13_OFFER_GROUPS = (
    0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102,
    0x0103, 0x0104, 0x001F, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024,
    0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x11EC, 0x11EB,
    0x11ED, 0x6399, 0x0201, 0x0202, 0x0200, 0x11E9, 0x11EA, 0x11EE,
    0x11EF,
)

PQ_PROBE_GROUPS = (
    0x11EC, 0x11EB, 0x11ED, 0x6399, 0x0201, 0x0202, 0x0200, 0x11E9,
    0x11EA, 0x11EE, 0x11EF,
)

TLS13_SIGSCHEMES = (
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806,
    0x0809, 0x080A, 0x080B, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
    0x0402, 0x0202, 0x081A, 0x081B, 0x081C, 0x0708, 0x0709, 0x070A,
    0x070B, 0x070C, 0x070D, 0x070E, 0x070F, 0x0904, 0x0905, 0x0906,
    0x0911, 0x0912, 0x0913, 0x0914, 0x0915, 0x0916, 0x0917, 0x0918,
    0x0919, 0x091A, 0x091B, 0x091C,
)

S_CLIENT_GROUPS_35 = (
    "?*X25519MLKEM768/?*X25519:?secp256r1/?X448:?secp384r1:"
    "?secp521r1/?ffdhe2048:?ffdhe3072/?SecP256r1MLKEM768:?SecP384r1MLKEM1024:"
    "?MLKEM512:?MLKEM768:?MLKEM1024:?SecP256r1MLKEM512:?MLKEM512X25519:"
    "?curveSM2MLKEM768:?MLKEM1024X448:?brainpoolP256r1tls13:"
    "?brainpoolP384r1tls13:?brainpoolP512r1tls13:?ffdhe4096:?ffdhe6144:"
    "?ffdhe8192:?curveSM2"
)

TLS_CLASSICAL_SIGSCHEME_NAMES = (
    "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512", "ed25519",
    "ed448", "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
    "rsa_pss_pss_sha256", "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512", "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384", "rsa_pkcs1_sha512",
    "ecdsa_sha1", "rsa_pkcs1_sha1",
    "ecdsa_brainpoolP256r1tls13_sha256", "ecdsa_brainpoolP384r1tls13_sha384",
    "ecdsa_brainpoolP512r1tls13_sha512",
)
# --- END GENERATED ---

_ALGS: Mapping[str, tuple[Any, ...]] = MappingProxyType(_RAW_ALGS)
_OIDS: Mapping[str, str] = MappingProxyType(_RAW_OIDS)
_TLS_GROUPS: Mapping[int, str] = MappingProxyType(_RAW_TLS_GROUPS)
_TLS_SIGSCHEMES: Mapping[int, str] = MappingProxyType(_RAW_TLS_SIGSCHEMES)
_SSH_KEX: Mapping[str, str] = MappingProxyType(_RAW_SSH_KEX)
_IKE_KE: Mapping[int, str] = MappingProxyType(_RAW_IKE_KE)
_AWS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {k: MappingProxyType(v) for k, v in _RAW_AWS.items()}
)
_AWS_TLS_POLICY: Mapping[str, Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {k: MappingProxyType(v) for k, v in _RAW_AWS_TLS_POLICY.items()}
)
_OPENSSL_TEXT: Mapping[str, str] = MappingProxyType(_RAW_OPENSSL_TEXT)
_ALIASES: Mapping[str, str] = MappingProxyType(_RAW_ALIASES)
_X509_NAMES: Mapping[str, str] = MappingProxyType(_RAW_CODE_LANE_X509_NAMES)
_X509_KEYS: Mapping[str, str] = MappingProxyType(_RAW_CODE_LANE_X509_KEYS)
_REVERSE_OID: Mapping[str, str] = MappingProxyType(
    {name: oid for oid, name in reversed(list(_RAW_OIDS.items()))}
)
del _RAW_ALGS, _RAW_OIDS, _RAW_TLS_GROUPS, _RAW_TLS_SIGSCHEMES, _RAW_SSH_KEX
del _RAW_IKE_KE, _RAW_AWS, _RAW_AWS_TLS_POLICY, _RAW_OPENSSL_TEXT, _RAW_ALIASES
del _RAW_CODE_LANE_X509_NAMES, _RAW_CODE_LANE_X509_KEYS

NAMESPACES = ("tls_group", "tls_sigscheme", "ssh_kex", "ike_ke", "openssl_text", "name")
_SENTINELS = frozenset(
    {"", "<null>", "(none)", "none", "null", "unknown", "unknown oid"}
)
_OID_RE = re.compile(r"^[0-2](\.(0|[1-9][0-9]*))+$")
_STATEFUL = frozenset({"LMS", "HSS", "XMSS", "XMSS^MT"})
_KEM_MARKERS = frozenset(
    {"MLKEM", "KYBER", "FRODO", "HQC", "MCELIECE", "BIKE", "XWING", "SNTRUP"}
)
_QV_FAMILIES = frozenset(
    {"RSA", "DSA", "DH", "ECDSA", "ECDH", "EC", "ED25519", "ED448", "EDDSA"}
    | {"X25519", "X448", "SM2"}
)
# A DSA token that is part of a PQ name (ML-DSA, SLH-DSA, FN-DSA, HashML-DSA) or of
# ECDSA/EdDSA, with or without separators: never the classical DSA family.
_NOT_DSA = re.compile(r"(ML|SLH|FN|HASHML|EC|ED)DSA")
_OPENSSL_VERSION = re.compile(r"^OpenSSL (\d+)\.(\d+)")


def _bare(
    family: str | None,
    primitive: str | None,
    status: str | None,
    construction: str | None,
    quantum: str | None,
    stateful: bool,
    matched_by: str,
    oid: str | None = None,
    name: str | None = None,
) -> Identity:
    return Identity(
        name, family, primitive, oid, None, status, None, None, construction,
        quantum, None, (), stateful, matched_by,
    )


# RFC 8701 GREASE codepoints in a TLS group list: a sentinel, never an algorithm.
GREASE = _bare(None, None, None, None, None, False, "codepoint", name="GREASE")


def _norm(text: str) -> str:
    return re.sub(r"[-_ /.()]", "", text).casefold()


def _identity(name: str, matched_by: str, oid: str | None = None) -> Identity:
    a = _ALGS[name]
    return Identity(
        name, a[0], a[1], oid or _REVERSE_OID.get(name), a[2], a[3], a[4], a[5],
        a[6], a[7], a[8], tuple(a[9]), name in _STATEFUL, matched_by,
    )


def _by_oid(oid: str) -> Identity | None:
    name = _OIDS.get(oid)
    if name is not None:
        return _identity(name, "oid", oid)
    for prefix, hint_text, primitive in _OID_PREFIXES:
        if oid.startswith(prefix) and hint_text == "composite-prototype":
            return _bare(
                "PQ", primitive, "pre-standard", "composite", "hybrid", False,
                "oid-prefix", oid,
            )
    return None


def _marker(text: str) -> Identity | None:
    compact = _norm(text).upper()
    found = [m for m in _PQ_MARKERS if m in compact]
    if not found:
        return None
    kem = any(m in _KEM_MARKERS for m in found)
    classical = any(c in compact for c in _CLASSICAL_MARKERS) or "XWING" in found
    construction = ("hybrid" if kem else "composite") if classical else "pure"
    pre = any(m in _PRE_STANDARD_MARKERS for m in found)
    stateful = any(m in found for m in ("LMS", "HSS", "XMSS"))
    return _bare(
        "PQ", "kem" if kem else "signature", "pre-standard" if pre else None,
        construction, "hybrid" if classical else "safe", stateful, "marker",
    )


def _fallback(text: str) -> Identity | None:
    """classify.family's classical rules before algid, with a token-bounded DSA."""
    up = text.upper().replace("_", "-")
    compact = re.sub(r"[- /.]", "", up)
    family: str | None = None
    for name in ("ED25519", "ED448", "X25519", "X448", "EDDSA", "ECDSA", "ECDH"):
        if name in up:
            family = name
            break
    if family is None and "DSA" in up and "DSA" in _NOT_DSA.sub("", compact):
        family = "DSA"
    for name in ("RSA", "SM2"):
        if family is None and name in up:
            family = name
    if family is None and up.startswith(
        ("EC", "ID-EC", "PRIME256", "SECP", "P-256", "P-384", "P-521", "NIST")
    ):
        family = "EC"
    if family is None and (
        up in ("DH", "DHE", "FFDHE") or up.startswith(("DH-", "FFDHE", "DIFFIE"))
    ):
        family = "DH"
    if family is None:
        return None
    quantum = "vulnerable" if family in _QV_FAMILIES else None
    return _bare(family, None, None, "classical", quantum, False, "fallback")


def resolve(value: object, namespace: str | None = None) -> Identity | None:
    """The identity of ``value``, or None when it names nothing known.

    A dotted OID is looked up in the OID table. With ``namespace`` the lookup is exact
    in that namespace only (strict, no fallback). Otherwise: exact canonical or
    registry name, normalised alias, PQ marker scan, then the classical fallback.
    Sentinels ("<NULL>", "(NONE)", "Unknown OID", "") give None.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        if namespace == "tls_group":
            return tls_group(value)
        if namespace == "tls_sigscheme":
            return tls_sigscheme(value)
        if namespace == "ike_ke":
            return ike_ke(value)
        return None
    text = str(value).strip()
    if text.casefold() in _SENTINELS:
        return None
    if _OID_RE.match(text):
        return _by_oid(text)
    if namespace is not None:
        return _strict(text, namespace)
    if text in _ALGS:
        return _identity(text, "name")
    for table in (_SSH_KEX, _OPENSSL_TEXT):
        if text in table:
            return _identity(table[text], "name")
    alias = _ALIASES.get(_norm(text))
    if alias is not None:
        return _identity(alias, "alias")
    return _marker(text) or _fallback(text)


def _strict(text: str, namespace: str) -> Identity | None:
    if namespace == "openssl_text":
        name = _OPENSSL_TEXT.get(text)
        return _identity(name, "name") if name else None
    if namespace == "ssh_kex":
        return ssh_kex(text)
    if namespace == "name":
        if text in _ALGS:
            return _identity(text, "name")
        alias = _ALIASES.get(_norm(text))
        return _identity(alias, "alias") if alias else None
    tables = {
        "tls_group": _TLS_GROUPS,
        "tls_sigscheme": _TLS_SIGSCHEMES,
        "ike_ke": _IKE_KE,
    }
    if namespace in tables:
        found = text in tables[namespace].values()
        return _identity(text, "name") if found else None
    raise ValueError(f"unknown namespace {namespace!r}")


def tls_group(codepoint: int) -> Identity | None:
    """IANA TLS Supported Groups codepoint (RFC 8701 GREASE gives ``GREASE``)."""
    if codepoint in _GREASE:
        return GREASE
    name = _TLS_GROUPS.get(codepoint)
    return _identity(name, "codepoint") if name else None


def tls_sigscheme(codepoint: int) -> Identity | None:
    """IANA TLS SignatureScheme codepoint."""
    name = _TLS_SIGSCHEMES.get(codepoint)
    return _identity(name, "codepoint") if name else None


def ike_ke(transform_id: int) -> Identity | None:
    """IKEv2 Transform Type 4 id, named with the product's spellings (MODP-2048...)."""
    name = _IKE_KE.get(transform_id)
    return _identity(name, "codepoint") if name else None


def ssh_kex(method: str) -> Identity | None:
    """SSH key-exchange method, including OpenSSH @openssh.com / @libssh.org
    spellings and the registry's wildcard families (ecdh-sha2-*, gss-*)."""
    name = _SSH_KEX.get(method)
    if name is not None:
        return _identity(name, "name")
    best = ""
    for pattern in _SSH_KEX:
        if not pattern.endswith("*") or len(pattern) <= len(best):
            continue
        if method.startswith(pattern[:-1]):
            best = pattern
    return _identity(_SSH_KEX[best], "name") if best else None


def _enum_key(value: str) -> str:
    return value.strip().upper().replace("-", "_")


def aws(service: str, field: str, value: object) -> Identity | None:
    """An AWS API enum value, e.g. aws("acm-pca", "KeyAlgorithm", "ML_DSA_65"). Case,
    '-' and '_' are equivalent ("RSA-2048" is "RSA_2048")."""
    table = _AWS.get(f"{service}.{field}")
    if table is None or value is None:
        return None
    want = _enum_key(str(value))
    for enum_value, name in table.items():
        if _enum_key(enum_value) == want:
            return _identity(name, "enum")
    return None


def aws_tls_policy(service: str, name: object) -> tuple[str, ...] | None:
    """The hybrid groups a named AWS TLS policy offers: a tuple (empty when AWS
    documents the policy as post-quantum without naming groups), or None for a policy
    with no post-quantum key exchange."""
    table = _AWS_TLS_POLICY.get(service)
    if table is None or not isinstance(name, str):
        return None
    return table.get(name)


def openssl_text(text: str) -> Identity | None:
    """The algorithm text OpenSSL 3.0 or 3.5 prints in ``x509 -text`` (strict)."""
    return resolve(text, "openssl_text")


def hint(value: object) -> str | None:
    """Why an OID is unknown: "oqs-arc" or "composite-prototype" for known arcs."""
    text = str(value or "").strip()
    if not _OID_RE.match(text) or text in _OIDS:
        return None
    for prefix, hint_text, _primitive in _OID_PREFIXES:
        if text.startswith(prefix):
            return hint_text
    return None


def family_label(value: object) -> str | None:
    found = resolve(value)
    return found.family_label if found else None


def quantum_vulnerable(value: object) -> bool | None:
    """True for quantum-vulnerable public-key algorithms, False for PQ (pure, hybrid,
    composite), None when the value carries no public-key verdict."""
    found = resolve(value)
    if found is None:
        return None
    return {"vulnerable": True, "safe": False, "hybrid": False}.get(found.quantum or "")


def compare_key(value: object) -> object:
    """The canonical name when ``value`` is an identifier (a dotted OID or a cloud enum
    value), else ``value`` unchanged: an OID and its name compare equal, any other
    string compares as stored."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if _OID_RE.match(text):
        found = _by_oid(text)
        return found.name if found and found.name else value
    for table in _AWS.values():
        if text in table:
            return table[text]
    return value


def code_lane_x509_name(oid: str) -> str:
    """The code lane's string for a certificate algorithm OID: its historic strings
    unchanged (bom-refs use them), else the canonical name, else the OID."""
    return _X509_NAMES.get(oid) or _OIDS.get(oid) or oid


def code_lane_x509_key(oid: str) -> str | None:
    """The code lane's key-type label for a private-key AlgorithmIdentifier OID."""
    return _X509_KEYS.get(oid) or _OIDS.get(oid)


def openssl_major_minor(version_text: str) -> tuple[int, int] | None:
    """(major, minor) from ``openssl version`` output; None for LibreSSL or other."""
    m = _OPENSSL_VERSION.match(version_text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


# ------------------------------------------------------------------- DER readers
# They return OIDs only, and never return or log key bytes.
def _tlv(der: bytes, i: int, end: int) -> tuple[int, int, int] | None:
    """(tag, body start, body end) of the element at ``i``; None when malformed."""
    if i + 2 > end:
        return None
    tag, length, j = der[i], der[i + 1], i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or j + n > end:
            return None
        length, j = int.from_bytes(der[j : j + n], "big"), j + n
    if j + length > end:
        return None
    return tag, j, j + length


def _elements(
    der: bytes, start: int, end: int
) -> list[tuple[int, int, int, int]] | None:
    """(tag, element start, body start, body end) of each child in [start, end)."""
    out, i = [], start
    while i < end:
        item = _tlv(der, i, end)
        if item is None:
            return None
        out.append((item[0], i, item[1], item[2]))
        i = item[2]
    return out


def _oid_text(body: bytes) -> str | None:
    if not body or body[-1] & 0x80:
        return None
    top = min(body[0] // 40, 2)
    parts, val = [top, body[0] - 40 * top], 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _alg_id(der: bytes, start: int, end: int) -> tuple[str, str | None] | None:
    kids = _elements(der, start, end)
    if not kids or kids[0][0] != 0x06:
        return None
    oid = _oid_text(der[kids[0][2] : kids[0][3]])
    if oid is None:
        return None
    params: str | None = None
    if len(kids) > 1 and kids[1][0] == 0x06:
        params = _oid_text(der[kids[1][2] : kids[1][3]])
    elif len(kids) > 1 and kids[1][0] == 0x30:
        params = "explicit"
    return oid, params


def _top_children(der: bytes) -> list[tuple[int, int, int, int]] | None:
    top = _tlv(der, 0, len(der)) if der else None
    if top is None or top[0] != 0x30:
        return None
    return _elements(der, top[1], top[2])


def spki_alg(der: bytes) -> tuple[str, str | None] | None:
    """(algorithm OID, parameters OID | "explicit" | None) of a SubjectPublicKeyInfo."""
    kids = _top_children(der)
    if not kids or len(kids) < 2 or kids[0][0] != 0x30 or kids[1][0] != 0x03:
        return None
    return _alg_id(der, kids[0][2], kids[0][3])


def pkcs8_alg(der: bytes) -> str | None:
    """The algorithm OID of an unencrypted PKCS#8 PrivateKeyInfo / OneAsymmetricKey."""
    kids = _top_children(der)
    if not kids or len(kids) < 3 or kids[0][0] != 0x02 or kids[1][0] != 0x30:
        return None
    if kids[2][0] != 0x04:
        return None
    found = _alg_id(der, kids[1][2], kids[1][3])
    return found[0] if found else None


def tbs_spki_alg(tbs_der: bytes) -> tuple[str, str | None] | None:
    """``spki_alg`` of the SubjectPublicKeyInfo inside a TBSCertificate."""
    kids = _top_children(tbs_der)
    if kids and kids[0][0] == 0xA0:  # [0] EXPLICIT version
        kids = kids[1:]
    if not kids or len(kids) < 6:
        return None
    _tag, begin, _body, end = kids[5]
    return spki_alg(tbs_der[begin:end])
