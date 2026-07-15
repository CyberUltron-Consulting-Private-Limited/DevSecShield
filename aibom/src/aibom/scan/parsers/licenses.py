"""Map a free-text license string to a CycloneDX ``licenseChoice`` entry.

Known SPDX identifiers serialize as ``{"license": {"id": ...}}``; anything else
(e.g. ``internal-restricted``) serializes as a named license
``{"license": {"name": ...}}``. Keeps emit/ free of license heuristics.
"""

from __future__ import annotations

# A small, common SPDX id set keyed by lowercase for case-insensitive lookup.
_SPDX_IDS = {
    spdx.lower(): spdx
    for spdx in (
        "Apache-2.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "GPL-2.0-only",
        "GPL-3.0-only",
        "LGPL-2.1-only",
        "LGPL-3.0-only",
        "MPL-2.0",
        "ISC",
        "Unlicense",
        "CC0-1.0",
        "CC-BY-4.0",
        "CC-BY-SA-4.0",
        "CC-BY-NC-4.0",
    )
}


def license_choice(value: str) -> dict:
    """Return a CycloneDX ``licenseChoice`` dict for a license string."""
    canonical = _SPDX_IDS.get(value.strip().lower())
    if canonical:
        return {"license": {"id": canonical}}
    return {"license": {"name": value.strip()}}


__all__ = ["license_choice"]
