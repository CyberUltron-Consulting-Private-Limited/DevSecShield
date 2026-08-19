"""Resolve SBOM license risk categories (never ``unknown``).

Dual-field model (locked):
* ``license`` — raw SPDX / LicenseRef string when known
* ``license_type`` — risk category (``permissive``, …, ``not_declared``)

Read-time remap fixes legacy rows that stored ``unknown`` or raw SPDX in
``license_type``. Emit-time twin lives in the worker SCA merge path.
"""

from __future__ import annotations

import re
from typing import Any

LICENSE_NOT_DECLARED = "not_declared"
LICENSE_REF_NOT_DECLARED = "LicenseRef-not-declared"

# Risk categories shown on the SBOM license chart (unknown removed).
LICENSE_CATEGORIES: tuple[str, ...] = (
    "permissive",
    "public_domain",
    "weak_copyleft",
    "creative_commons",
    "commercial",
    "strong_copyleft",
    "network_copyleft",
    "source_available",
    LICENSE_NOT_DECLARED,
)

_CATEGORY_SET = frozenset(LICENSE_CATEGORIES)

# Curated package → SPDX (subset of aibom license_resolver._LICENSE_MAP; backend
# must not import aibom). Offline-only — no PyPI/GitHub lookups.
_PACKAGE_SPDX: dict[str, str] = {
    "numpy": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "torch": "BSD-3-Clause",
    "torchvision": "BSD-3-Clause",
    "torchaudio": "BSD-2-Clause",
    "tensorflow": "Apache-2.0",
    "scikit-learn": "BSD-3-Clause",
    "sklearn": "BSD-3-Clause",
    "onnx": "Apache-2.0",
    "onnxruntime": "MIT",
    "safetensors": "Apache-2.0",
    "pillow": "MIT-CMU",
    "pydicom": "MIT",
    "transformers": "Apache-2.0",
    "sentence-transformers": "Apache-2.0",
    "huggingface-hub": "Apache-2.0",
    "tokenizers": "Apache-2.0",
    "datasets": "Apache-2.0",
    "accelerate": "Apache-2.0",
    "openai": "Apache-2.0",
    "anthropic": "MIT",
    "cohere": "MIT",
    "mistralai": "Apache-2.0",
    "google-generativeai": "Apache-2.0",
    "langchain": "MIT",
    "langchain-core": "MIT",
    "langchain-community": "MIT",
    "langgraph": "MIT",
    "llama-index": "MIT",
    "crewai": "MIT",
    "autogen": "MIT",
    "haystack-ai": "Apache-2.0",
    "instructor": "MIT",
    "litellm": "MIT",
    "chromadb": "Apache-2.0",
    "qdrant-client": "Apache-2.0",
    "weaviate-client": "BSD-3-Clause",
    "pinecone-client": "Apache-2.0",
    "tiktoken": "MIT",
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "httpx": "BSD-3-Clause",
    "httpcore": "BSD-3-Clause",
    "fastapi": "MIT",
    "starlette": "BSD-3-Clause",
    "uvicorn": "BSD-3-Clause",
    "pydantic": "MIT",
    "pydantic-settings": "MIT",
    "pydantic-core": "MIT",
    "grpcio": "Apache-2.0",
    "protobuf": "BSD-3-Clause",
    "bcrypt": "Apache-2.0",
    "jsonschema": "MIT",
    "kubernetes": "Apache-2.0",
    "mmh3": "MIT",
    "orjson": "Apache-2.0",
    "overrides": "Apache-2.0",
    "pybase64": "BSD-2-Clause",
    "pypika": "Apache-2.0",
    "pyyaml": "MIT",
    "rich": "MIT",
    "tenacity": "Apache-2.0",
    "tqdm": "MPL-2.0",
    "typer": "MIT",
    "typing-extensions": "PSF-2.0",
    "importlib-resources": "Apache-2.0",
    "importlib-metadata": "Apache-2.0",
    "opentelemetry-api": "Apache-2.0",
    "opentelemetry-sdk": "Apache-2.0",
    "opentelemetry-exporter-otlp-proto-grpc": "Apache-2.0",
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
    "alembic": "MIT",
    "pytest": "MIT",
    "pytest-httpbin": "MIT",
    "sphinx": "BSD-2-Clause",
    "black": "MIT",
    "redis": "MIT",
    "celery": "BSD-3-Clause",
    "billiard": "BSD-3-Clause",
    "kombu": "BSD-3-Clause",
    "amqp": "BSD-3-Clause",
    "vine": "BSD-3-Clause",
    "greenlet": "MIT",
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
    "docutils": "BSD-2-Clause",
    "six": "MIT",
    "attrs": "MIT",
    "cffi": "MIT",
    "pycparser": "BSD-3-Clause",
    "cryptography": "Apache-2.0",
    "pyopenssl": "Apache-2.0",
    "pyjwt": "MIT",
    "paramiko": "LGPL-2.1-or-later",
    "nacl": "Apache-2.0",
    "pynacl": "Apache-2.0",
    "blinker": "MIT",
    "azure-core": "MIT",
    "ecdsa": "MIT",
    "nltk": "Apache-2.0",
    "fschat": "Apache-2.0",
    "aiohttp": "Apache-2.0",
    "aiosignal": "Apache-2.0",
    "axios": "MIT",
    "python-multipart": "Apache-2.0",
    "pyasn1": "BSD-2-Clause",
    "next": "MIT",
    "langsmith": "MIT",
}

_EXTRAS = re.compile(r"\[.*$")
_DASHES = re.compile(r"[-_.]+")
_PKG_FROM_DEP = re.compile(r"^([A-Za-z0-9_.\-]+)")


def normalize_pkg(name: str) -> str:
    return _DASHES.sub("-", _EXTRAS.sub("", (name or "").strip().lower())).strip("-")


def package_from_dependency(dep: str) -> str:
    """Extract package name from ``name==ver``, purl, or bare name."""
    raw = (dep or "").strip()
    if not raw:
        return ""
    if raw.startswith("pkg:"):
        # pkg:pypi/requests@2.31.0 → requests
        try:
            path = raw.split("/", 1)[1]
            name = path.split("@", 1)[0]
            return normalize_pkg(name)
        except IndexError:
            return ""
    m = _PKG_FROM_DEP.match(raw.split("==", 1)[0].split("@", 1)[0])
    return normalize_pkg(m.group(1)) if m else ""


def resolve_package_spdx(name: str) -> str | None:
    """Offline curated-map lookup only (never network)."""
    key = normalize_pkg(name)
    if not key:
        return None
    return _PACKAGE_SPDX.get(key)


def spdx_to_license_category(spdx: str) -> str:
    """Map an SPDX id / license name to a risk category.

    Unknown / empty / literal ``unknown`` → ``not_declared``.
    """
    raw = (spdx or "").strip()
    if not raw:
        return LICENSE_NOT_DECLARED
    low = raw.lower()
    if low in ("unknown", "none", "null", "n/a", "unlicensed", LICENSE_NOT_DECLARED):
        return LICENSE_NOT_DECLARED
    if low.startswith("licenseref-not-declared") or low == "licenseref-not-declared":
        return LICENSE_NOT_DECLARED
    # Already a category (legacy vuln LLM emit or remapped row)
    if low in _CATEGORY_SET:
        return low

    # Public domain / CC0 / 0BSD / Unlicense
    if any(
        t in low
        for t in (
            "0bsd",
            "unlicense",
            "cc0",
            "public-domain",
            "public domain",
            "wtfpl",
        )
    ):
        return "public_domain"

    # Network copyleft
    if "agpl" in low:
        return "network_copyleft"

    # Strong copyleft (GPL family, excluding LGPL)
    if re.search(r"(?<![l])gpl", low) or "gpl-" in low or low.startswith("gpl"):
        if "lgpl" not in low:
            return "strong_copyleft"

    # Weak copyleft
    if "lgpl" in low or "mpl" in low or "epl" in low or "cpl" in low:
        return "weak_copyleft"

    # Source-available / restrictive
    if any(
        t in low
        for t in (
            "sspl",
            "busl",
            "commons-clause",
            "elastic",
            "mongodb",
            "prosperity",
            "polyform",
        )
    ):
        return "source_available"

    # Creative Commons (non-CC0)
    if low.startswith("cc-") or "creative commons" in low or "creativecommons" in low:
        return "creative_commons"

    # Commercial / proprietary
    if any(
        t in low
        for t in (
            "proprietary",
            "commercial",
            "all rights reserved",
            "licenseref-proprietary",
        )
    ):
        return "commercial"

    # Permissive common SPDX
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
            "artistic",
            "openssl",
            "postgresql",
            "blueoak",
            "mit-0",
            "mit-cmu",
            "hpnd",
            "x11",
            "afl-",
            "bsl-1",
        )
    ):
        return "permissive"

    # Dual / expression — take strongest signal we recognize
    if " or " in low or " and " in low or " with " in low:
        parts = re.split(r"\s+(?:or|and|with)\s+", low, flags=re.I)
        cats = [spdx_to_license_category(p) for p in parts if p.strip()]
        cats = [c for c in cats if c != LICENSE_NOT_DECLARED]
        if cats:
            # Prefer higher-risk when expression is ambiguous
            for prefer in (
                "network_copyleft",
                "strong_copyleft",
                "source_available",
                "weak_copyleft",
                "commercial",
                "creative_commons",
                "permissive",
                "public_domain",
            ):
                if prefer in cats:
                    return prefer

    return LICENSE_NOT_DECLARED


def _is_empty_or_unknown(val: str) -> bool:
    low = val.strip().lower()
    return (not low) or low in ("unknown", "none", "null", "n/a", "unlicensed")


def resolve_sbom_license_fields(item: dict[str, Any]) -> tuple[str, str]:
    """Return ``(license_spdx_or_ref, license_type_category)`` — never unknown."""
    stored_lic = str(item.get("license") or "").strip()
    stored_type = str(item.get("license_type") or "").strip()
    type_low = stored_type.lower()

    # 1) Concrete SPDX already on ``license``
    if stored_lic and not _is_empty_or_unknown(stored_lic):
        cat = spdx_to_license_category(stored_lic)
        if cat != LICENSE_NOT_DECLARED:
            return stored_lic, cat
        if stored_lic.lower().startswith("licenseref-"):
            return stored_lic, LICENSE_NOT_DECLARED

    # 2) license_type already a risk category (vuln LLM / remapped emit)
    if type_low in _CATEGORY_SET and type_low != LICENSE_NOT_DECLARED:
        return (stored_lic if stored_lic and not _is_empty_or_unknown(stored_lic) else stored_type), type_low
    if type_low == LICENSE_NOT_DECLARED:
        return (
            stored_lic if stored_lic and not _is_empty_or_unknown(stored_lic) else LICENSE_REF_NOT_DECLARED
        ), LICENSE_NOT_DECLARED

    # 3) Raw SPDX mistakenly stored in license_type (Syft MIT/0BSD path)
    if stored_type and not _is_empty_or_unknown(stored_type) and type_low not in _CATEGORY_SET:
        cat = spdx_to_license_category(stored_type)
        if cat != LICENSE_NOT_DECLARED:
            return stored_type, cat

    # 4) Package-name enrichment (curated map only — no network)
    dep = (
        item.get("dependency")
        or item.get("purl")
        or item.get("title")
        or item.get("name")
        or ""
    )
    dep_s = str(dep)
    if dep_s.lower().startswith("inventory:"):
        dep_s = dep_s.split(":", 1)[-1].strip()
    pkg = package_from_dependency(dep_s)
    mapped = resolve_package_spdx(pkg) if pkg else None
    if mapped:
        return mapped, spdx_to_license_category(mapped)

    return LICENSE_REF_NOT_DECLARED, LICENSE_NOT_DECLARED


def resolve_sbom_license_category(item: dict[str, Any]) -> str:
    """Category only — used by dashboard aggregators."""
    return resolve_sbom_license_fields(item)[1]


def resolve_sbom_reachability(item: dict[str, Any]) -> str:
    """Normalize reachability; never emit ``unknown``."""
    raw = str(item.get("reachability") or "").strip().lower().replace(" ", "_")
    if raw in ("reachable", "potentially_reachable", "not_reachable", "not_assessed"):
        return raw
    if raw in ("", "unknown", "none", "null", "n/a"):
        # Inventory rows historically defaulted to not_reachable; bare missing → not_assessed
        if item.get("inventory_only"):
            return "not_reachable"
        return "not_assessed"
    return "not_assessed"


__all__ = [
    "LICENSE_CATEGORIES",
    "LICENSE_NOT_DECLARED",
    "LICENSE_REF_NOT_DECLARED",
    "normalize_pkg",
    "package_from_dependency",
    "resolve_package_spdx",
    "resolve_sbom_license_category",
    "resolve_sbom_license_fields",
    "resolve_sbom_reachability",
    "spdx_to_license_category",
]
