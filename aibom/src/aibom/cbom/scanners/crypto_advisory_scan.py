"""Flag crypto libraries whose resolved version matches the offline advisory file."""

from __future__ import annotations

from aibom.cbom.advisories import VulnerablePin, find_vulnerable, group_by_pin
from aibom.cbom.files import file_walk
from aibom.cbom.gate import VULNERABLE_CRYPTO_LIBRARY
from aibom.cbom.library_versions import _label_of, purl_of
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


# A declared range (``cryptography>=38.0.0``) names no installed version: an advisory
# that only its lower bound falls
# in is not a finding. The library row says so (the version is unverified) and lists
# those advisories; nothing is
# counted, as the SBOM does for a version read from a manifest range (#489).
UNVERIFIED_REASON = (
    "only a version range is declared and no lockfile resolves it: the advisories below match the "
    "range's lower bound, not an installed version"
)


def _unverified(props: dict[str, str], row: VulnerablePin) -> None:
    props["crypto:versionVerified"] = "false"
    props["crypto:unverifiedAdvisories"] = ",".join(a.id for a in row.advisories)
    props["crypto:unverifiedAdvisoryCount"] = str(len(row.advisories))
    props["crypto:versionUnverifiedReason"] = UNVERIFIED_REASON


@cbom_register
class CryptoAdvisoryScanner(Scanner):
    """Direct and lockfile-transitive versions. No network and no install. One row per
    crypto library, carrying every
    advisory its exact version matches. The code lane's row for the package
    (pyca/cryptography for pypi
    "cryptography") is that row: a library is never listed twice (staging QA Q2-09)."""

    name = "crypto_advisory"
    order = 16
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for row in group_by_pin(find_vulnerable(ctx.root, file_walk(ctx))):
            pin = row.pin
            library = _library_row(ctx, pin)
            if library is not None and library.version not in (None, pin.version):
                library = (
                    None  # another version of the package (a lockfile's) is its own row
                )
            if pin.version is None:
                self._range(ctx, row, library)
                continue
            props = {
                "crypto:role": "library",
                "crypto:vulnerable": "true",
                "crypto:advisory": ",".join(a.id for a in row.advisories),
                "crypto:advisoryCount": str(len(row.advisories)),
                "crypto:version": pin.version,
                "crypto:ecosystem": pin.ecosystem,
                "crypto:dependencyScope": "direct" if pin.direct else "transitive",
            }
            if row.upgrade_to:
                props["crypto:fixedVersion"] = row.upgrade_to
            if library is not None:
                library.properties = {**(library.properties or {}), **props}
                if library.version is None:
                    library.version = pin.version
                    library.purl = (
                        library.purl
                        if library.purl and "@" in library.purl
                        else purl_of(pin.ecosystem, pin.name, pin.version)
                    )
                ref = library.bom_ref
            else:
                ref = row.ref
                if ctx.has_ref(ref):
                    continue
                props["discovery:source"] = pin.path
                if pin.line > 0:
                    props["crypto:line"] = str(pin.line)
                ctx.add_component(
                    FrameworkComponent(
                        bom_ref=ref,
                        name=pin.name,
                        version=pin.version,
                        purl=purl_of(pin.ecosystem, pin.name, pin.version),
                        properties=props,
                    )
                )
            ctx.add_flag(VULNERABLE_CRYPTO_LIBRARY, ref, severity="error", message=_message(row))

    @staticmethod
    def _range(ctx: ScanContext, row: VulnerablePin, library) -> None:
        pin = row.pin
        if library is not None:
            props = dict(library.properties or {})
            _unverified(props, row)
            library.properties = props
            return
        ref = row.ref
        if ctx.has_ref(ref):
            return
        props = {
            "crypto:role": "library",
            "crypto:ecosystem": pin.ecosystem,
            "crypto:versionConstraint": pin.declared,
            "crypto:dependencyScope": "direct" if pin.direct else "transitive",
            "discovery:source": pin.path,
        }
        if pin.line > 0:
            props["crypto:line"] = str(pin.line)
        _unverified(props, row)
        ctx.add_component(
            FrameworkComponent(
                bom_ref=ref,
                name=pin.name,
                purl=purl_of(pin.ecosystem, pin.name, None),
                properties=props,
            )
        )
