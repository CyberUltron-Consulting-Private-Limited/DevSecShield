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
    "only a version range is declared and no lockfile resolves it: the advisories "
    "below match the range's lower bound, not an installed version"
)


def _unverified(props: dict[str, str], row: VulnerablePin) -> None:
    props["crypto:versionVerified"] = "false"
    props["crypto:unverifiedAdvisories"] = ",".join(a.id for a in row.advisories)
    props["crypto:unverifiedAdvisoryCount"] = str(len(row.advisories))
    props["crypto:versionUnverifiedReason"] = UNVERIFIED_REASON


@cbom_register
class CryptoAdvisoryScanner(Scanner):
    """Direct and lockfile-transitive versions. No network and no install. An exact
    pin is its own flagged component, linked to the code lane's row for the package.
    A declared range names no installed version: its advisories go on the code lane's
    row as unverified, with no finding and no second component (staging QA Q2-09)."""

    name = "crypto_advisory"
    order = 16
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for row in group_by_pin(find_vulnerable(ctx.root, file_walk(ctx))):
            pin = row.pin
            library = _library_row(ctx, pin)
            if pin.version is None:
                if library is not None and library.version:
                    # a lockfile resolves the package: that version is the installed
                    # one and is judged on its own pin; the range's lower bound says
                    # nothing more
                    continue
                self._range(ctx, row, library)
                continue
            ref = row.ref
            if ctx.has_ref(ref):
                continue
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
            if library is not None:
                # the code lane's row for the same package (pyca/cryptography for
                # pypi "cryptography"): the report lists the two as one library
                # (review of #491 m6); the BOM keeps the vulnerable pin as its own
                # component at the manifest line, linked to it (the D1 lane judges
                # that row: bench/cbom/d1/lane/judge.py judge_libraries)
                props["crypto:libraryRef"] = library.bom_ref
            ctx.add_component(
                FrameworkComponent(
                    bom_ref=ref, name=f"{pin.name}@{pin.declared}", properties=props
                )
            )
            ctx.add_flag(
                VULNERABLE_CRYPTO_LIBRARY, ref, severity="error", message=_message(row)
            )

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
