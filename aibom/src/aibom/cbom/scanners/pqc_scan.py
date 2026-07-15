"""CBOM scanner (C6): post-quantum-cryptography (PQC) readiness mapping.

Runs AFTER the inventory scanners (algorithm=10, certificate=20, protocol=30)
and the weak-crypto flagger (=40), reading the inventory back off the shared
:class:`~aibom.scan.registry.ScanContext` — the same order-based "linker reads
earlier components" pattern as C5. For every quantum-vulnerable algorithm asset
(RSA / ECC / DH / DSA, marked ``crypto:quantumVulnerable`` by C1) it applies the
pure grade from :mod:`aibom.cbom.pqc`:

* ENRICHES the component's ``crypto:`` properties in place with
  ``crypto:nistQuantumSecurityLevel`` (0) and ``crypto:pqcMigrationTarget`` — the
  C4 emitter already passes ``crypto:nistQuantumSecurityLevel`` straight through
  into CycloneDX ``algorithmProperties``, so this needs no emitter change; and
* raises one ``QUANTUM_VULNERABLE`` ``Flag`` (SARIF ``warning`` == Medium) whose
  message carries the NIST migration timeline + target.

Lane discipline: this scanner FLAGS and tags the inventory; the C8 scorer WEIGHTS
the flag, the C4 emitter RENDERS the property. It computes no risk.
"""

from __future__ import annotations

from aibom.cbom.pqc import nist_quantum_level, pqc_grade
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner


@cbom_register
class PQCReadinessScanner(Scanner):
    name = "crypto_pqc"
    # After inventory (10/20/30) and the weak flagger (40): every crypto_asset is
    # present and the grade is independent of the weak findings.
    order = 50
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for comp in ctx.components:
            # C7 positive grading: EVERY gradeable algorithm asset (quantum-safe
            # included) carries its NIST category, so a report can state an asset
            # is quantum-safe (cat 1-5), not only that a vulnerable one is 0.
            level = nist_quantum_level(comp)
            if level is not None:
                props = comp.properties or {}
                props["crypto:nistQuantumSecurityLevel"] = str(level)
                comp.properties = props

            # Vulnerable assets additionally get the migration target + roadmap
            # and raise the QUANTUM_VULNERABLE flag the scorer weights.
            grade = pqc_grade(comp)
            if grade is None:
                continue
            props = comp.properties or {}
            props["crypto:pqcMigrationTarget"] = grade.migration_target
            if grade.migration_roadmap:
                props["crypto:pqcMigrationRoadmap"] = grade.migration_roadmap
            comp.properties = props
            ctx.add_flag(
                grade.code,
                comp.bom_ref,
                severity=grade.severity,
                message=grade.message,
            )


__all__ = ["PQCReadinessScanner"]
