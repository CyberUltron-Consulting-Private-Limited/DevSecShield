"""Post-quantum-cryptography (PQC) readiness mapping (C6) — the pure grader.

Lane discipline: the C1 algorithm scanner INVENTORIES each ``crypto_asset`` and
records whether its primitive is broken by a cryptographically-relevant quantum
computer (``crypto:quantumVulnerable`` — true for RSA / ECC / DH / DSA, the
asymmetric primitives Shor's algorithm defeats). This module is the pure
function that, given such an asset, GRADES it:

* a ``nistQuantumSecurityLevel`` (0 for a quantum-vulnerable public-key
  algorithm — it offers no security against a quantum adversary), which the C4
  emitter passes straight through into CycloneDX ``algorithmProperties`` (the C4
  seam was built for exactly this — the emitter needs no change); and
* a concrete PQC **migration target** from the NIST-standardized suite —
  ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) — chosen by the
  asset's cryptographic primitive (key-establishment vs signature).

The PQC scanner (:mod:`aibom.cbom.scanners.pqc_scan`) applies this grade: it
ENRICHES the component's ``crypto:`` properties and raises one ``QUANTUM_VULNERABLE``
``Flag`` whose message carries the NIST migration timeline (deprecation after
2030, disallowed from 2035 — NIST SP 1800-38 / IR 8547). Nothing here scores or
serializes: the C8 scorer WEIGHTS the flag, the C4 emitter RENDERS the property.

Severity is SARIF ``warning`` (== Medium impact): a quantum-vulnerable algorithm
that is otherwise strong (e.g. RSA-2048) is a *future* exposure to migrate, not a
*today* break like the weak-crypto findings (C5, SARIF ``error`` == High).
"""

from __future__ import annotations

import re
from typing import NamedTuple

from aibom.model.component import AIComponent

# The flag this lane emits (the set the C8 scorer weights and the charts read).
QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
PQC_CODES = frozenset({QUANTUM_VULNERABLE})

# SARIF warning == Medium impact (C8: "quantum-vulnerable -> medium").
_SEV = "warning"

# A quantum-vulnerable public-key algorithm provides NO security against a
# cryptographically-relevant quantum computer: NIST quantum security level 0.
_QUANTUM_VULNERABLE_LEVEL = 0

# Cryptographic primitive -> NIST-standardized PQC migration target. The asset's
# function decides the replacement: key-establishment (RSA key transport, DH/ECDH
# key agreement) migrates to ML-KEM (FIPS 203); signatures migrate to ML-DSA
# (FIPS 204) or the hash-based SLH-DSA (FIPS 205). RSA (``pke``) is used for both
# key transport and signing, so it names both KEM and signature replacements
# (matching the CBOM oracle's ``pqc_migration_targets``).
PQC_MIGRATION_TARGETS: dict[str, str] = {
    "pke": "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)",
    "signature": "ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)",
    "key-agree": "ML-KEM (FIPS 203)",
    "kem": "ML-KEM (FIPS 203)",
}
# Fallback for an asymmetric primitive not enumerated above.
_DEFAULT_TARGET = "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"

# The migration timeline every quantum-vulnerable finding cites.
_TIMELINE = (
    "NIST deprecates RSA/ECC/DH after 2030 and disallows them from 2035 "
    "(NIST SP 1800-38 / IR 8547)"
)


def migration_target(primitive: str | None) -> str:
    """The NIST PQC replacement suite for a quantum-vulnerable primitive."""
    return PQC_MIGRATION_TARGETS.get(primitive or "", _DEFAULT_TARGET)


# --------------------------------------------------------------------------- #
# NIST quantum security-strength grading (C7). The five NIST PQC evaluation
# categories are ANCHORED to classical primitives (a documented derivation, not
# magic numbers): Cat 1 = AES-128 key search, Cat 2 = SHA-256 collision, Cat 3 =
# AES-192, Cat 4 = SHA-384 collision, Cat 5 = AES-256. Every quantum-safe asset is
# graded by comparison to those anchors; a quantum-vulnerable public-key algorithm
# meets no category (level 0).
#   https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
# --------------------------------------------------------------------------- #

# Symmetric / block-stream key length (bits) -> NIST category (1/3/5 anchors).
_SYMMETRIC_LEVEL: dict[int, int] = {128: 1, 192: 3, 256: 5}
# Hash / XOF output length (bits) -> collision-resistance category (2/4/5 anchors).
_HASH_LEVEL: dict[int, int] = {256: 2, 384: 4, 512: 5}
# PQC parameter set -> NIST category, per FIPS 203/204/205 claimed strength.
_MLKEM_LEVEL: dict[str, int] = {"512": 1, "768": 3, "1024": 5}      # FIPS 203
_MLDSA_LEVEL: dict[str, int] = {"44": 2, "65": 3, "87": 5}          # FIPS 204
_SLHDSA_LEVEL: dict[str, int] = {"128": 1, "192": 3, "256": 5}      # FIPS 205
_FALCON_LEVEL: dict[str, int] = {"512": 1, "1024": 5}              # FN-DSA (draft)
# Stateful-hash signatures (SP 800-208) are SHA-256-anchored by default -> Cat 2.
_STATEFUL_HASH_LEVEL = 2

_HASH_BITS_RE = re.compile(r"(\d{3})\b")


def _hash_output_bits(name: str) -> int | None:
    """Digest output length (bits) parsed from a normalized hash display name."""
    upper = name.upper()
    if "BLAKE2B" in upper:
        return 512
    if "BLAKE2S" in upper:
        return 256
    m = _HASH_BITS_RE.search(name)
    return int(m.group(1)) if m else None


def _pqc_signature_level(name: str, param: str | None) -> int | None:
    """Grade a quantum-safe signature by family (read from its FIPS name) + set."""
    upper = name.upper()
    if "ML-DSA" in upper or "DILITHIUM" in upper:
        return _MLDSA_LEVEL.get(param or "")
    if "SLH-DSA" in upper or "SPHINCS" in upper:
        return _SLHDSA_LEVEL.get(param or "")
    if "FALCON" in upper:
        return _FALCON_LEVEL.get(param or "")
    if any(t in upper for t in ("LMS", "HSS", "XMSS")):
        return _STATEFUL_HASH_LEVEL
    return None


def nist_quantum_level(component: AIComponent) -> int | None:
    """The NIST quantum security level (0-5) for ``component``, or ``None``.

    Pure + total over every ``algorithm`` crypto-asset (not just the vulnerable
    ones ``pqc_grade`` handles): a quantum-vulnerable public-key algorithm is 0;
    quantum-safe primitives are graded by their NIST category anchor. ``None``
    means "not gradeable from the inventory" (unknown key size / PQC set, or a
    primitive with no category anchor such as a bare KDF/MAC) — the caller then
    omits the property rather than asserting a level it cannot prove.
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "algorithm":
        return None
    if props.get("crypto:quantumVulnerable") == "true":
        return _QUANTUM_VULNERABLE_LEVEL

    primitive = props.get("crypto:primitive")
    param = props.get("crypto:parameterSet")
    name = component.name or ""

    # Hybrid KEX is graded at its ML-KEM component's category.
    if props.get("crypto:hybrid") == "true":
        return _MLKEM_LEVEL.get(param or "")
    if primitive in ("block-cipher", "stream-cipher", "ae"):
        bits = props.get("crypto:keySize")
        if bits is None and "CHACHA" in name.upper():
            return _SYMMETRIC_LEVEL.get(256)
        return _SYMMETRIC_LEVEL.get(int(bits)) if bits is not None else None
    if primitive in ("hash", "xof"):
        obits = _hash_output_bits(name)
        return _HASH_LEVEL.get(obits) if obits is not None else None
    if primitive == "kem":  # ML-KEM (the only KEM primitive in the inventory)
        return _MLKEM_LEVEL.get(param or "")
    if primitive == "signature":
        return _pqc_signature_level(name, param)
    return None


# --------------------------------------------------------------------------- #
# Migration ROADMAP (C7): the sized PQC target for a classical strength, plus the
# CNSA 2.0 National-Security-Systems milestones alongside the generic NIST
# timeline. A stronger classical asset migrates to a higher-category PQC set.
# --------------------------------------------------------------------------- #
# Classical effective strength (bits) -> sized ML-KEM / ML-DSA target set.
_SIZED_TARGET: tuple[tuple[int, str], ...] = (
    (256, "ML-KEM-1024 (FIPS 203) / ML-DSA-87 (FIPS 204)"),
    (192, "ML-KEM-1024 (FIPS 203) / ML-DSA-87 (FIPS 204)"),
    (128, "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"),
    (0, "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"),
)
# CNSA 2.0 National Security System transition milestones (NSA advisory, 2022).
_CNSA_TIMELINE = (
    "CNSA 2.0 NSS milestones: software/firmware signing 2025, "
    "networking 2030, all NSS by 2033-2035"
)

# RSA/DH modulus (or DSA) bit length -> comparable classical security strength
# (NIST SP 800-57 Table 2), used to size the roadmap for a public-key asset.
_RSA_STRENGTH: tuple[tuple[int, int], ...] = (
    (15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80),
)
# ECC curve bit length -> comparable strength (half the field size).
_ECC_CURVE_STRENGTH: tuple[tuple[str, int], ...] = (
    ("521", 256), ("512", 256), ("448", 224), ("384", 192),
    ("256", 128), ("255", 128), ("224", 112), ("192", 96),
)


def _classical_strength_bits(props: dict[str, str]) -> int:
    """Approximate the comparable classical strength of a vulnerable public key."""
    key_size = props.get("crypto:keySize")
    if key_size is not None:
        try:
            bits = int(key_size)
        except ValueError:
            bits = 0
        for modulus, strength in _RSA_STRENGTH:
            if bits >= modulus:
                return strength
    curve = props.get("crypto:curve") or ""
    for token, strength in _ECC_CURVE_STRENGTH:
        if token in curve:
            return strength
    return 0


def sized_migration_target(component: AIComponent) -> str:
    """A parameter-sized PQC migration target matched to the asset's strength."""
    props = component.properties or {}
    strength = _classical_strength_bits(props)
    for floor, target in _SIZED_TARGET:
        if strength >= floor:
            return target
    return _SIZED_TARGET[-1][1]


class PQCGrade(NamedTuple):
    """The PQC readiness grade applied to one quantum-vulnerable algorithm asset."""

    nist_quantum_security_level: int
    migration_target: str
    code: str
    severity: str
    message: str
    # The parameter-sized roadmap target (``ML-KEM-768 ...``) matched to the
    # asset's classical strength; the unsized ``migration_target`` stays the
    # primary property so the frozen oracle manifest is untouched.
    migration_roadmap: str = ""


def pqc_grade(component: AIComponent) -> PQCGrade | None:
    """Grade ``component`` for PQC readiness, or ``None`` if it is not in scope.

    Pure: depends only on the component's kind and ``crypto:`` properties. In
    scope iff it is a ``crypto_asset`` of assetType ``algorithm`` that the
    inventory marked ``crypto:quantumVulnerable == "true"`` (RSA / ECC / DH /
    DSA). Symmetric and hash primitives are quantum-resistant at adequate sizes
    and are not graded here.
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "algorithm":
        return None
    if props.get("crypto:quantumVulnerable") != "true":
        return None

    target = migration_target(props.get("crypto:primitive"))
    roadmap = sized_migration_target(component)
    message = (
        f"Quantum-vulnerable algorithm {component.name}: broken by Shor's "
        f"algorithm on a cryptographically-relevant quantum computer "
        f"(nistQuantumSecurityLevel 0). {_TIMELINE}; {_CNSA_TIMELINE}; "
        f"migrate to {roadmap} (target family {target})."
    )
    return PQCGrade(
        nist_quantum_security_level=_QUANTUM_VULNERABLE_LEVEL,
        migration_target=target,
        code=QUANTUM_VULNERABLE,
        severity=_SEV,
        message=message,
        migration_roadmap=roadmap,
    )


__all__ = [
    "QUANTUM_VULNERABLE",
    "PQC_CODES",
    "PQC_MIGRATION_TARGETS",
    "PQCGrade",
    "migration_target",
    "nist_quantum_level",
    "sized_migration_target",
    "pqc_grade",
]
