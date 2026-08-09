"""Resolve concrete AI-BOM license labels (never ``unknown``).

Mirrors adapter emit-time fallbacks so legacy persisted scans (license empty /
unknown) remapped at read time match new adapter emissions.
"""

from __future__ import annotations

from typing import Any

# SPDX / LicenseRef labels that count as a declared license for governance.
_DECLARED_PREFIXES = ("licenseref-proprietary",)

# Non-OSS placeholders — concrete chart labels, not "unlicensed library" gaps
# when applied to credentials/artifacts; frameworks should get real SPDX.
LICENSE_NOT_APPLICABLE = "LicenseRef-not-applicable"
LICENSE_NOT_DECLARED = "LicenseRef-not-declared"
LICENSE_PROPRIETARY = "LicenseRef-proprietary"

# Curated package → SPDX (subset of aibom license_resolver._LICENSE_MAP; backend
# must not import aibom). Keep in sync for packages that appear license-less.
_PACKAGE_SPDX: dict[str, str] = {
    "distro": "Apache-2.0",
    "jiter": "MIT",
    "sniffio": "MIT",
    "anyio": "MIT",
    "httpx": "BSD-3-Clause",
    "httpcore": "BSD-3-Clause",
    "pydantic": "MIT",
    "pydantic-core": "MIT",
    "tqdm": "MPL-2.0",
    "typing-extensions": "PSF-2.0",
    "openai": "Apache-2.0",
    "anthropic": "MIT",
    "certifi": "MPL-2.0",
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "numpy": "BSD-3-Clause",
    "torch": "BSD-3-Clause",
    "transformers": "Apache-2.0",
    "tiktoken": "MIT",
}

_FRAMEWORK_TYPES = frozenset({"ml_framework", "ai_framework", "framework"})
_ARTIFACT_SUFFIXES = (".bin", ".safetensors", ".gguf", ".pt", ".pth", ".onnx")
_HOSTED_NEEDLES = (
    "openai api",
    "azure openai",
    "aws bedrock",
    "bedrock",
    "anthropic",
    "vertex",
    "cohere",
    "mistral",
    "ollama",
    "huggingface",
    " api",
)


def _norm_pkg(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def _is_concrete(lic: str) -> bool:
    low = lic.strip().lower()
    return bool(low) and low not in ("unknown", "none", "null", "n/a")


def is_governance_license(lic: str) -> bool:
    """True when license counts toward governance readiness (declared SPDX/proprietary)."""
    if not _is_concrete(lic):
        return False
    low = lic.strip().lower()
    if low in (
        LICENSE_NOT_APPLICABLE.lower(),
        LICENSE_NOT_DECLARED.lower(),
    ):
        return False
    return True


def is_unlicensed_library_gap(lic: str) -> bool:
    """True when a library row still lacks a usable OSS/SPDX license."""
    if not _is_concrete(lic):
        return True
    low = lic.strip().lower()
    return low in (
        LICENSE_NOT_DECLARED.lower(),
        LICENSE_NOT_APPLICABLE.lower(),
    )


def infer_aibom_license(
    *,
    name: str = "",
    kind_or_type: str = "",
    provider: str = "",
) -> str:
    """Infer a concrete license label from inventory fields (never ``unknown``)."""
    name_l = (name or "").lower()
    type_l = (kind_or_type or "").lower()
    text = f"{name_l} {provider}".lower()

    if "credential" in name_l or "secret" in name_l or type_l in (
        "secret",
        "credential",
    ):
        return LICENSE_NOT_APPLICABLE

    if any(name_l.endswith(sfx) for sfx in _ARTIFACT_SUFFIXES):
        return LICENSE_NOT_DECLARED

    if type_l in _FRAMEWORK_TYPES or "framework" in type_l:
        spdx = _PACKAGE_SPDX.get(_norm_pkg(name))
        if spdx:
            return spdx
        return LICENSE_NOT_DECLARED

    # Hosted AI API / cloud external surfaces → proprietary ToS, not OSS.
    if type_l == "external_provider" or any(n in text for n in _HOSTED_NEEDLES):
        # Prefer proprietary for named cloud services; leftover externals → not-declared
        if any(
            n in text
            for n in (
                "openai",
                "bedrock",
                "azure",
                "anthropic",
                "vertex",
                "cohere",
                "mistral",
                "ollama",
                "hugging",
                "api",
            )
        ):
            return LICENSE_PROPRIETARY
        return LICENSE_NOT_DECLARED

    pkg = _PACKAGE_SPDX.get(_norm_pkg(name))
    if pkg:
        return pkg
    return LICENSE_NOT_DECLARED


def resolve_aibom_license(asset: dict[str, Any]) -> str:
    """Return a concrete license for a finding / scan_data row."""
    stored = asset.get("license") or asset.get("license_type") or ""
    stored_s = str(stored).strip()
    if _is_concrete(stored_s):
        return stored_s

    name = (
        asset.get("component_name")
        or asset.get("asset_name")
        or asset.get("title")
        or asset.get("framework")
        or ""
    )
    kind_or_type = (
        asset.get("component_type")
        or asset.get("asset_type")
        or asset.get("kind")
        or ""
    )
    provider = (
        asset.get("source")
        or asset.get("provider")
        or ""
    )
    return infer_aibom_license(
        name=str(name),
        kind_or_type=str(kind_or_type),
        provider=str(provider),
    )
