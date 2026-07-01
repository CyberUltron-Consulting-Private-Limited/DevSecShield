"""CBOM scanner (C5): weak-algorithm / weak-crypto FLAGGING.

The first CBOM scanner that EMITS flags rather than components. Lane discipline:
the C1/C2/C3 scanners INVENTORY crypto assets onto the shared
:class:`~aibom.scan.registry.ScanContext`; this scanner runs AFTER them (higher
``order``), reads that inventory back off ``ctx.components``, and raises a
weak-crypto ``Flag`` (SARIF ``error`` == High impact) for every weak asset — via
the pure predicate in :mod:`aibom.cbom.weakness`. It computes no risk and emits
no components: the C8 scorer WEIGHTS these flags; the C4 emitter ignores them.

Flagged: MD5/SHA-1/DES/3DES/RC4/RC2/Blowfish (deprecated corpus), RSA/DSA/DH
keys below 2048 bits, ECB cipher mode, TLS < 1.2 / SSL protocols, and X.509
certificates past their notValidAfter date. Strong assets (RSA-2048+, AES-GCM,
SHA-256, TLS 1.2+, valid certificates) are left unflagged.
"""

from __future__ import annotations

from datetime import date

from aibom.cbom.registry import cbom_register
from aibom.cbom.weakness import (
    cert_expiry_finding,
    certificate_findings,
    weak_finding,
)
from aibom.scan.registry import ScanContext, Scanner


@cbom_register
class WeakCryptoScanner(Scanner):
    name = "crypto_weakness"
    # After the inventory scanners (algorithm=10, certificate=20, protocol=30) so
    # every crypto_asset is present on the context to be evaluated.
    order = 40
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        # A single reference date for the whole scan keeps every cert-expiry
        # decision consistent within one run.
        today = date.today()
        for comp in ctx.components:
            # A crypto asset can carry more than one weakness — a certificate may
            # be BOTH expired AND SHA-1-signed AND undersized — so every finding
            # is raised and the C8 scorer stacks them per component. Algorithm
            # weakness (weak_finding) is one-per-asset; certificate depth
            # (expiry + signature + key + self-signed-leaf) stacks.
            findings = []
            algo = weak_finding(comp)
            if algo is not None:
                findings.append(algo)
            expiry = cert_expiry_finding(comp, today)
            if expiry is not None:
                findings.append(expiry)
            findings.extend(certificate_findings(comp))
            for code, severity, message in findings:
                ctx.add_flag(code, comp.bom_ref, severity=severity, message=message)


__all__ = ["WeakCryptoScanner"]
