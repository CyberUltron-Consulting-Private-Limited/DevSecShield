"""CBOM scanner (C15): classical security-strength enrichment.

The classical-adversary peer of the C7 PQC scanner. Runs AFTER the inventory
(algorithm=10, certificate=20, protocol=30), the weak flagger (=40), and the PQC
grader (=50) — so ``crypto:nistQuantumSecurityLevel`` is already set and the
strength grader can reuse the NIST category anchor for quantum-safe assets. For
every gradeable ``algorithm`` asset it ENRICHES the component with
``crypto:securityStrengthBits`` (SP 800-57 Table 2 comparable strength) from the
pure grader :func:`aibom.cbom.strength.security_strength_bits`.

Lane discipline: this scanner EMITS a graph fact only. The C8 FIPS/BSI/PCI
frameworks QUERY that fact (>=112 / >=120-bit floors) and the allowlist predicate
:func:`aibom.cbom.strength.is_approved_algorithm`; the C4 emitter RENDERS the
strength into CycloneDX ``algorithmProperties.classicalSecurityLevel``. It scores
nothing and raises no flag.
"""

from __future__ import annotations

from aibom.cbom.registry import cbom_register
from aibom.cbom.strength import security_strength_bits
from aibom.scan.registry import ScanContext, Scanner


@cbom_register
class SecurityStrengthScanner(Scanner):
    name = "crypto_strength"
    # After the PQC grader (50): quantum-safe assets are graded via their NIST
    # category anchor, which pqc_scan has already stamped on the component.
    order = 55
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for comp in ctx.components:
            bits = security_strength_bits(comp)
            if bits is None:
                continue
            props = comp.properties or {}
            props["crypto:securityStrengthBits"] = str(bits)
            comp.properties = props


__all__ = ["SecurityStrengthScanner"]
