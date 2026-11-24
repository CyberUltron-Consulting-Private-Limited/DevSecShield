"""Finalize scanner: how many AI library licences the scan resolved.

An unresolved library licence is unknown / partial (``FRAMEWORK_LICENSE_UNKNOWN``,
weight 0), never "no licence". A BOM in which most licences are unknown must say so
in aggregate, the way #489 states an offline SBOM's coverage (``dss:licence_coverage``
"x/n"): review 6037909737 of #498, M7. Two BOM metadata properties:

* ``aibom:licence_coverage`` — ``"<resolved>/<libraries>"``;
* ``aibom:licence_unknown`` — the number of libraries whose licence is unknown,
  present only when it is not zero.

The PDF prints "Library licences resolved: x of n" and the results page shows the
unknown count next to "Unlicensed". Lanes: properties only, never flags or scores.
"""

from __future__ import annotations

from pathlib import Path

from aibom.scan.registry import ScanContext, Scanner, register


@register
class LicenceCoverage(Scanner):
    name = "licence-coverage"
    order = 96  # after every component-producing scanner
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        libraries = [c for c in ctx.components if c.kind == "framework"]
        if not libraries:
            return
        resolved = sum(1 for c in libraries if c.licenses)
        ctx.properties["aibom:licence_coverage"] = f"{resolved}/{len(libraries)}"
        if resolved < len(libraries):
            ctx.properties["aibom:licence_unknown"] = str(len(libraries) - resolved)


__all__ = ["LicenceCoverage"]
