"""Flag crypto libraries whose resolved version matches the offline advisory file."""

from __future__ import annotations

from aibom.cbom.advisories import VulnerablePin, find_vulnerable, group_by_pin
from aibom.cbom.files import file_walk
from aibom.cbom.gate import VULNERABLE_CRYPTO_LIBRARY
from aibom.cbom.library_versions import _label_of
from aibom.cbom.registry import cbom_register
from aibom.cbom.scanners.algorithm_scan import _slug
from aibom.model.component import FrameworkComponent
from aibom.scan.registry import ScanContext, Scanner

_LISTED = 8  # advisories named one by one in the finding text; the rest are counted (all are in crypto:advisory)


def _message(row: VulnerablePin) -> str:
    pin = row.pin
    scope = "direct" if pin.direct else "transitive"
    named = "; ".join(f"{a.id}: {a.summary}" for a in row.advisories[:_LISTED])
    more = len(row.advisories) - _LISTED
    if more > 0:
        named += f"; and {more} more"
    upgrade = row.upgrade_to
    if upgrade:
        advice = f" Upgrade to {upgrade} or later (fixes every listed advisory)."
    else:
        advice = " At least one advisory has no fixed release: replace the library."
    first = row.advisories[0].source if row.advisories else ""
    return f"{pin.name} {pin.declared} ({scope}, {pin.ecosystem}) matches {named}.{advice} {first}".strip()


def _library_row(ctx: ScanContext, pin):
    """The code lane's library row for this pinned package, if it lists one."""
    label = _label_of(pin)
    if not label:
        return None
    ref = f"crypto-lib-{_slug(label)}"
    return next((c for c in ctx.components if c.bom_ref == ref), None)


@cbom_register
class CryptoAdvisoryScanner(Scanner):
    """Direct and lockfile-transitive versions. No network and no install. One row per declared package version,
    carrying every advisory it matches."""

    name = "crypto_advisory"
    order = 16
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for row in group_by_pin(find_vulnerable(ctx.root, file_walk(ctx))):
            ref = row.ref
            if ctx.has_ref(ref):
                continue
            pin = row.pin
            props = {
                "crypto:role": "library",
                "crypto:vulnerable": "true",
                "crypto:advisory": ",".join(a.id for a in row.advisories),
                "crypto:advisoryCount": str(len(row.advisories)),
                "crypto:version": pin.declared,
                "crypto:ecosystem": pin.ecosystem,
                "crypto:dependencyScope": "direct" if pin.direct else "transitive",
                "discovery:source": pin.path,
            }
            if pin.line > 0:
                props["crypto:line"] = str(pin.line)
            if row.upgrade_to:
                props["crypto:fixedVersion"] = row.upgrade_to
            library = _library_row(ctx, pin)
            if library is not None:
                # the code lane's row for the same package (pyca/cryptography for
                # pypi "cryptography"): the report lists the two as one library
                # (review of #491 m6); the BOM keeps the vulnerable pin as its own
                # component, linked to it
                props["crypto:libraryRef"] = library.bom_ref
            ctx.add_component(FrameworkComponent(bom_ref=ref, name=f"{pin.name}@{pin.declared}", properties=props))
            ctx.add_flag(VULNERABLE_CRYPTO_LIBRARY, ref, severity="error", message=_message(row))
