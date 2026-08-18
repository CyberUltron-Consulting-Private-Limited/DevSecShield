"""Worker-side SBOM license category mapper (never ``unknown``).

Mirrors ``backend.utilities.dashboard.sbom_license`` for emit-time enrichment.
Kept local so the Celery worker does not need the backend package on PYTHONPATH.
"""

from __future__ import annotations

import re
from typing import Any

LICENSE_NOT_DECLARED = "not_declared"
LICENSE_REF_NOT_DECLARED = "LicenseRef-not-declared"

_CATEGORY_SET = frozenset(
    {
        "permissive",
        "public_domain",
        "weak_copyleft",
        "creative_commons",
        "commercial",
        "strong_copyleft",
        "network_copyleft",
        "source_available",
        LICENSE_NOT_DECLARED,
    }
)

# Offline curated package → SPDX (sync with backend sbom_license / aibom map).
_PACKAGE_SPDX: dict[str, str] = {
    "numpy": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "torch": "BSD-3-Clause",
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "httpx": "BSD-3-Clause",
    "httpcore": "BSD-3-Clause",
    "fastapi": "MIT",
    "starlette": "BSD-3-Clause",
    "uvicorn": "BSD-3-Clause",
    "pydantic": "MIT",
    "pydantic-core": "MIT",
    "click": "BSD-3-Clause",
    "anyio": "MIT",
    "certifi": "MPL-2.0",
    "distro": "Apache-2.0",
    "jiter": "MIT",
    "sniffio": "MIT",
    "flask": "BSD-3-Clause",
    "jinja2": "BSD-3-Clause",
    "werkzeug": "BSD-3-Clause",
    "itsdangerous": "BSD-3-Clause",
    "markupsafe": "BSD-3-Clause",
    "sqlalchemy": "MIT",
    "pytest": "MIT",
    "black": "MIT",
    "redis": "MIT",
    "idna": "BSD-3-Clause",
    "charset-normalizer": "MIT",
    "packaging": "Apache-2.0",
    "setuptools": "MIT",
    "wheel": "MIT",
    "pip": "MIT",
    "pluggy": "MIT",
    "iniconfig": "MIT",
    "colorama": "BSD-3-Clause",
    "pygments": "BSD-2-Clause",
    "six": "MIT",
    "attrs": "MIT",
    "cffi": "MIT",
    "pycparser": "BSD-3-Clause",
    "cryptography": "Apache-2.0",
    "pyopenssl": "Apache-2.0",
    "pyjwt": "MIT",
    "paramiko": "LGPL-2.1-or-later",
    "blinker": "MIT",
    "tqdm": "MPL-2.0",
    "typing-extensions": "PSF-2.0",
    "pyyaml": "MIT",
    "rich": "MIT",
    "tenacity": "Apache-2.0",
    "typer": "MIT",
    "greenlet": "MIT",
    "openai": "Apache-2.0",
    "anthropic": "MIT",
    "langchain": "MIT",
    "transformers": "Apache-2.0",
    "tiktoken": "MIT",
    "numpy": "BSD-3-Clause",
}

_EXTRAS = re.compile(r"\[.*$")
_DASHES = re.compile(r"[-_.]+")
_PKG_FROM_DEP = re.compile(r"^([A-Za-z0-9_.\-]+)")


def normalize_pkg(name: str) -> str:
    return _DASHES.sub("-", _EXTRAS.sub("", (name or "").strip().lower())).strip("-")


def package_from_name(name: str) -> str:
    return normalize_pkg(name)


def resolve_package_spdx(name: str) -> str | None:
    key = normalize_pkg(name)
    return _PACKAGE_SPDX.get(key) if key else None


def spdx_to_license_category(spdx: str) -> str:
    raw = (spdx or "").strip()
    if not raw:
        return LICENSE_NOT_DECLARED
    low = raw.lower()
    if low in ("unknown", "none", "null", "n/a", "unlicensed", LICENSE_NOT_DECLARED):
        return LICENSE_NOT_DECLARED
    if low.startswith("licenseref-not-declared"):
        return LICENSE_NOT_DECLARED
    if low in _CATEGORY_SET:
        return low
    if any(t in low for t in ("0bsd", "unlicense", "cc0", "public-domain", "public domain", "wtfpl")):
        return "public_domain"
    if "agpl" in low:
        return "network_copyleft"
    if re.search(r"(?<![l])gpl", low) or "gpl-" in low or low.startswith("gpl"):
        if "lgpl" not in low:
            return "strong_copyleft"
    if "lgpl" in low or "mpl" in low or "epl" in low:
        return "weak_copyleft"
    if any(t in low for t in ("sspl", "busl", "commons-clause", "elastic", "mongodb", "polyform")):
        return "source_available"
    if low.startswith("cc-") or "creative commons" in low:
        return "creative_commons"
    if any(t in low for t in ("proprietary", "commercial", "licenseref-proprietary")):
        return "commercial"
    if any(
        t in low
        for t in (
            "mit",
            "apache",
            "bsd",
            "isc",
            "psf",
            "python",
            "zlib",
            "boost",
            "openssl",
            "postgresql",
            "mit-cmu",
            "hpnd",
            "x11",
            "afl-",
            "bsl-1",
        )
    ):
        return "permissive"
    return LICENSE_NOT_DECLARED


def resolve_emit_license(name: str, lic_from_cdx: str) -> tuple[str, str]:
    """Return ``(license, license_type)`` for an inventory row."""
    lic = (lic_from_cdx or "").strip()
    if lic and lic.lower() not in ("unknown", "none", "null", "n/a"):
        cat = spdx_to_license_category(lic)
        if cat != LICENSE_NOT_DECLARED:
            return lic, cat
        if lic.lower().startswith("licenseref-"):
            return lic, LICENSE_NOT_DECLARED
    mapped = resolve_package_spdx(name)
    if mapped:
        return mapped, spdx_to_license_category(mapped)
    return LICENSE_REF_NOT_DECLARED, LICENSE_NOT_DECLARED


__all__ = [
    "LICENSE_NOT_DECLARED",
    "LICENSE_REF_NOT_DECLARED",
    "resolve_emit_license",
    "spdx_to_license_category",
]
