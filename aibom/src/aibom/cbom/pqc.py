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


class PQCGrade(NamedTuple):
    """The PQC readiness grade applied to one quantum-vulnerable algorithm asset."""

    nist_quantum_security_level: int
    migration_target: str
    code: str
    severity: str
    message: str


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
    message = (
        f"Quantum-vulnerable algorithm {component.name}: broken by Shor's "
        f"algorithm on a cryptographically-relevant quantum computer "
        f"(nistQuantumSecurityLevel 0). {_TIMELINE}; migrate to {target}."
    )
    return PQCGrade(
        nist_quantum_security_level=_QUANTUM_VULNERABLE_LEVEL,
        migration_target=target,
        code=QUANTUM_VULNERABLE,
        severity=_SEV,
        message=message,
    )


__all__ = [
    "QUANTUM_VULNERABLE",
    "PQC_CODES",
    "PQC_MIGRATION_TARGETS",
    "PQCGrade",
    "migration_target",
    "pqc_grade",
]
