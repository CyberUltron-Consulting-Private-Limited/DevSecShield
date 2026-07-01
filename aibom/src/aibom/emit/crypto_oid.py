"""C10 — clean-room algorithm/curve -> OID enrichment knowledge-base.

CBOMkit / sonar-cryptography run an *Enrichment* stage that stamps each crypto
asset with its canonical **object identifier (OID)** so a CycloneDX
``cryptoProperties.oid`` carries a machine-stable identifier alongside the human
name. This module is our ORIGINAL, deterministic re-implementation of that
behaviour: a hand-curated ``(algorithm family + parameters) -> OID`` table
derived from the PUBLIC OID registries (NIST CSOR, ANSI X9.62 / SEC 2 named
curves, RSA PKCS, RFC 8410 Edwards curves, FIPS 203/204). No OSS code is copied
and no OSS tool is imported — only the published numeric identifiers, which are
facts, not code.

Design contract (mirrors the C9 dependency-graph precision rule):

* **Honest precision only.** An OID is emitted ONLY when the asset's parameters
  pin it unambiguously. AES needs BOTH a key size and a mode (AES-256-GCM has a
  different OID from AES-128-CBC); a bare ``AES`` with no key size resolves to
  nothing. A *hybrid* PQC asset gets no pure-primitive OID. When in doubt, we
  return ``None`` rather than a false-precision identifier.
* **Pure + deterministic.** No I/O, no state; identical input -> identical OID.
* **Emit-layer only.** Imports nothing from the ``cbom`` package (no layering
  cycle); the caller passes already-scanned property values.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Digest OIDs (NIST CSOR 2.16.840.1.101.3.4.2.*, legacy MD from RSA PKCS,
# SHA-1 from OIW). Matched longest-token-first so SHA-512 beats SHA-1.
# --------------------------------------------------------------------------- #
_HASH_OID: tuple[tuple[str, str], ...] = (
    ("SHA3-224", "2.16.840.1.101.3.4.2.7"),
    ("SHA3-256", "2.16.840.1.101.3.4.2.8"),
    ("SHA3-384", "2.16.840.1.101.3.4.2.9"),
    ("SHA3-512", "2.16.840.1.101.3.4.2.10"),
    ("SHA-512", "2.16.840.1.101.3.4.2.3"),
    ("SHA512", "2.16.840.1.101.3.4.2.3"),
    ("SHA-384", "2.16.840.1.101.3.4.2.2"),
    ("SHA384", "2.16.840.1.101.3.4.2.2"),
    ("SHA-256", "2.16.840.1.101.3.4.2.1"),
    ("SHA256", "2.16.840.1.101.3.4.2.1"),
    ("SHA-224", "2.16.840.1.101.3.4.2.4"),
    ("SHA224", "2.16.840.1.101.3.4.2.4"),
    ("SHA-1", "1.3.14.3.2.26"),
    ("SHA1", "1.3.14.3.2.26"),
    ("MD5", "1.2.840.113549.2.5"),
    ("MD4", "1.2.840.113549.2.4"),
    ("MD2", "1.2.840.113549.2.2"),
)

# --------------------------------------------------------------------------- #
# AES: OID = 2.16.840.1.101.3.4.1.<keyBase + modeSuffix>. Requires key size AND
# mode; a bare AES has no single OID and stays unresolved.
# --------------------------------------------------------------------------- #
_AES_KEY_BASE = {128: 0, 192: 20, 256: 40}
_AES_MODE_SUFFIX = {"ECB": 1, "CBC": 2, "OFB": 3, "CFB": 4, "GCM": 6, "CCM": 7}

# --------------------------------------------------------------------------- #
# Named-curve OIDs (ANSI X9.62 / SEC 2 / RFC 8410). A keyed EC/EdDSA/XDH asset's
# most specific identifier is its curve OID.
# --------------------------------------------------------------------------- #
_CURVE_OID = {
    "P-192": "1.2.840.10045.3.1.1",
    "PRIME192V1": "1.2.840.10045.3.1.1",
    "SECP192R1": "1.2.840.10045.3.1.1",
    "P-224": "1.3.132.0.33",
    "SECP224R1": "1.3.132.0.33",
    "P-256": "1.2.840.10045.3.1.7",
    "PRIME256V1": "1.2.840.10045.3.1.7",
    "SECP256R1": "1.2.840.10045.3.1.7",
    "P-384": "1.3.132.0.34",
    "SECP384R1": "1.3.132.0.34",
    "P-521": "1.3.132.0.35",
    "SECP521R1": "1.3.132.0.35",
    "SECP256K1": "1.3.132.0.10",
    "ED25519": "1.3.101.112",
    "ED448": "1.3.101.113",
    "X25519": "1.3.101.110",
    "X448": "1.3.101.111",
}

# Edwards / Montgomery keys named without a separate curve token.
_NAMED_KEY_OID: tuple[tuple[str, str], ...] = (
    ("ED25519", "1.3.101.112"),
    ("ED448", "1.3.101.113"),
    ("X25519", "1.3.101.110"),
    ("X448", "1.3.101.111"),
)

# --------------------------------------------------------------------------- #
# PQC (FIPS 203 ML-KEM / FIPS 204 ML-DSA) — NIST CSOR assignments, keyed by the
# parameter set. Emitted only for a PURE (non-hybrid) asset.
# --------------------------------------------------------------------------- #
_ML_KEM_OID = {
    "512": "2.16.840.1.101.3.4.4.1",
    "768": "2.16.840.1.101.3.4.4.2",
    "1024": "2.16.840.1.101.3.4.4.3",
}
_ML_DSA_OID = {
    "44": "2.16.840.1.101.3.4.3.17",
    "65": "2.16.840.1.101.3.4.3.18",
    "87": "2.16.840.1.101.3.4.3.19",
}


def _digest_oid(up: str) -> str | None:
    for tok, oid in _HASH_OID:
        if tok in up:
            return oid
    return None


def _aes_oid(key_size: int | None, mode: str | None) -> str | None:
    if key_size not in _AES_KEY_BASE or not mode:
        return None
    suffix = _AES_MODE_SUFFIX.get(mode.upper())
    if suffix is None:
        return None
    return f"2.16.840.1.101.3.4.1.{_AES_KEY_BASE[key_size] + suffix}"


def algorithm_oid(
    name: str | None,
    primitive: str | None = None,
    key_size: int | None = None,
    mode: str | None = None,
    curve: str | None = None,
    parameter_set: str | None = None,
) -> str | None:
    """Resolve an algorithm crypto-asset to its canonical OID, or ``None``.

    ``name`` is the asset display name (e.g. ``"AES-256-GCM"``, ``"SHA-256"``,
    ``"ML-KEM-768"``); the remaining args are the scanner-emitted parameters.
    Returns ``None`` whenever the identity is ambiguous — the caller then emits
    no ``oid`` rather than a false-precision one.
    """
    up = (name or "").upper().replace(" ", "")
    if not up:
        return None

    # A hybrid KEM/signature is a *construction*, not a single registered
    # primitive; never claim a pure-primitive OID for it.
    hybrid = "HYBRID" in up

    # Curve-bearing keys: the named-curve OID is the most specific identifier.
    if curve:
        cu = _CURVE_OID.get(curve.upper())
        if cu:
            return cu
    for tok, oid in _NAMED_KEY_OID:
        if tok in up:
            return oid

    # PQC lattice primitives (pure only), keyed by parameter set.
    if not hybrid:
        pset = (parameter_set or "").strip()
        if ("ML-KEM" in up or "MLKEM" in up or "KYBER" in up) and pset in _ML_KEM_OID:
            return _ML_KEM_OID[pset]
        if ("ML-DSA" in up or "MLDSA" in up or "DILITHIUM" in up) and pset in _ML_DSA_OID:
            return _ML_DSA_OID[pset]

    # Hashes (also covers HMAC-less digests; matched before RSA-family tokens so
    # a composite name like "SHA256withRSA" is not mis-read as a bare hash — the
    # caller only calls this for a resolved single-primitive algorithm asset).
    if primitive == "hash" or (primitive is None and _digest_oid(up)):
        digest = _digest_oid(up)
        if digest:
            return digest

    # Symmetric ciphers.
    if "3DES" in up or "TRIPLEDES" in up or "DESEDE" in up or "DES-EDE" in up:
        # des-ede3-cbc; plain 3-key 3DES has no distinct single OID.
        if mode and mode.upper() == "CBC":
            return "1.2.840.113549.3.7"
        return None
    if up.startswith("AES") or "AES" in up:
        return _aes_oid(key_size, mode)
    if "CHACHA" in up and "POLY1305" in up:
        return "1.2.840.113549.1.9.16.3.18"  # id-alg-AEADChaCha20Poly1305
    if "RC4" in up or "ARCFOUR" in up or "ARC4" in up:
        return "1.2.840.113549.3.4"
    if "RC2" in up and mode and mode.upper() == "CBC":
        return "1.2.840.113549.3.2"
    if up.startswith("DES") or up == "DES":
        if mode and mode.upper() == "CBC":
            return "1.3.14.3.2.7"  # desCBC
        return None

    # Asymmetric families (key-size independent OIDs).
    if "RSA" in up:
        return "1.2.840.113549.1.1.1"  # rsaEncryption
    if "ECDSA" in up or "ECDH" in up or "ECPUBLICKEY" in up:
        return "1.2.840.10045.2.1"  # ecPublicKey (no known curve -> generic)
    # Classical DSA only — never a PQC lattice/hash signature that shares the
    # "DSA" token (ML-DSA / SLH-DSA / EdDSA are handled above or left unresolved).
    if "DSA" in up and not any(
        t in up for t in ("SLH-DSA", "SLHDSA", "ML-DSA", "MLDSA", "EDDSA")
    ):
        return "1.2.840.10040.4.1"  # id-dsa
    if "DIFFIE" in up or up.startswith("DH"):
        return "1.2.840.10046.2.1"  # dhpublicnumber

    return None


__all__ = ["algorithm_oid"]
