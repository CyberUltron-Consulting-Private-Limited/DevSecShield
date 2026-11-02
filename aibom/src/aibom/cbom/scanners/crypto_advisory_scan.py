"""Flag crypto libraries whose resolved version matches the offline advisory file."""

from __future__ import annotations

from aibom.cbom.advisories import AdvisoryHit, find_vulnerable
from aibom.cbom.files import file_walk
from aibom.cbom.gate import VULNERABLE_CRYPTO_LIBRARY
from aibom.cbom.registry import cbom_register
from aibom.model.component import FrameworkComponent
from aibom.scan.registry import ScanContext, Scanner


def _message(hit: AdvisoryHit) -> str:
    advisory = hit.advisory
    pin = hit.pin
    scope = "direct" if pin.direct else "transitive"
    fixed = f" Fixed in {advisory.fixed}." if advisory.fixed else ""
    return (
        f"{pin.name} {pin.declared} ({scope}, {pin.ecosystem}) matches "
        f"{advisory.id}: {advisory.summary}.{fixed} {advisory.source}"
    )


@cbom_register
class CryptoAdvisoryScanner(Scanner):
    """Direct and lockfile-transitive versions. No network and no install."""

    name = "crypto_advisory"
    order = 16
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for hit in find_vulnerable(ctx.root, file_walk(ctx)):
            ref = hit.ref
            if ctx.has_ref(ref):
                continue
            pin = hit.pin
            advisory = hit.advisory
            ctx.add_component(
                FrameworkComponent(
                    bom_ref=ref,
                    name=f"{pin.name}@{pin.declared}",
                    properties={
                        "crypto:role": "library",
                        "crypto:vulnerable": "true",
                        "crypto:advisory": advisory.id,
                        "crypto:version": pin.declared,
                        "crypto:ecosystem": pin.ecosystem,
                        "crypto:dependencyScope": (
                            "direct" if pin.direct else "transitive"
                        ),
                        "discovery:source": pin.path,
                    },
                )
            )
            ctx.add_flag(
                VULNERABLE_CRYPTO_LIBRARY,
                ref,
                severity="error",
                message=_message(hit),
            )
