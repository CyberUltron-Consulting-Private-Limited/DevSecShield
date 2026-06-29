"""Resolve a package's declared license to an SPDX identifier.

Three real sources, in determinism order:

1. **Curated SPDX manifest** (`_LICENSE_MAP`) — the default, deterministic source.
   Hand-verified SPDX ids for common AI/ML + scientific packages. This is what
   the scan path uses, so the emitted BOM is byte-stable across machines
   (CLAUDE.md rule 6) regardless of what happens to be ``pip install``-ed.
2. **``importlib.metadata``** (opt-in, ``allow_metadata=True``) — reads the
   INSTALLED distribution's declared ``License`` / license classifiers. Real,
   offline, but environment-dependent → never used on the deterministic scan path.
3. **PyPI JSON** (opt-in, ``allow_pypi=True``) — network lookup for packages not
   installed locally.

The scan path calls ``resolve_license(name)`` (map only). Live resolution is for
explicit, non-golden use (a future ``aibom emit --resolve-licenses=live``).
``None`` means *genuinely unknown* — the caller flags it, it does not guess.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from email.message import Message
from typing import cast

# Canonical PyPI normalization: lowercase, runs of [-_.] collapse to a single '-'
# (PEP 503), and strip an extras suffix ("uvicorn[standard]" -> "uvicorn").
_EXTRAS = re.compile(r"\[.*$")
_DASHES = re.compile(r"[-_.]+")


def normalize_pkg(name: str) -> str:
    return _DASHES.sub("-", _EXTRAS.sub("", name.strip().lower())).strip("-")


# Hand-verified SPDX ids (the deterministic manifest). Keyed by normalized name.
# Covers: the asserted ground truth (numpy/torch/requests), every example
# fixture dependency (clinical-imaging / no-phi-model / multi-site), the synthetic
# fixture, and chroma's root requirements — so "unlicensed" drops sharply there.
_LICENSE_MAP: dict[str, str] = {
    # ── scientific / ML core ──
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
    # ── HuggingFace / NLP ──
    "transformers": "Apache-2.0",
    "sentence-transformers": "Apache-2.0",
    "huggingface-hub": "Apache-2.0",
    "tokenizers": "Apache-2.0",
    "datasets": "Apache-2.0",
    "accelerate": "Apache-2.0",
    # ── LLM providers / agent frameworks ──
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
    # ── web / infra / utils (chroma + common) ──
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
}

# OSI-classifier substrings -> SPDX, for the importlib.metadata path.
_CLASSIFIER_SPDX: dict[str, str] = {
    "apache software license": "Apache-2.0",
    "mit license": "MIT",
    "mit no attribution": "MIT-0",
    "bsd license": "BSD-3-Clause",
    "isc license": "ISC",
    "mozilla public license 2.0": "MPL-2.0",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu lesser general public license v3": "LGPL-3.0-only",
    "python software foundation license": "PSF-2.0",
}

# Raw "License:" header substrings -> SPDX (importlib.metadata + PyPI fallback).
_RAW_SPDX: dict[str, str] = {
    "apache-2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache license 2": "Apache-2.0",
    "mit": "MIT",
    "bsd-3": "BSD-3-Clause",
    "bsd 3": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd": "BSD-3-Clause",
    "mpl-2": "MPL-2.0",
    "mozilla": "MPL-2.0",
    "isc": "ISC",
    "psf": "PSF-2.0",
    "gpl-3": "GPL-3.0-only",
    "gpl-2": "GPL-2.0-only",
    "lgpl": "LGPL-3.0-only",
}


def _spdx_from_text(text: str | None) -> str | None:
    if not text:
        return None
    low = text.strip().lower()
    # An already-clean SPDX id (PEP 639 License-Expression) — accept as-is.
    if re.fullmatch(r"[A-Za-z0-9.\-+]+", text.strip()) and len(text.strip()) <= 40:
        for spdx in _LICENSE_MAP.values():
            if low == spdx.lower():
                return spdx
    for needle, spdx in _RAW_SPDX.items():
        if needle in low:
            return spdx
    return None


def _from_importlib_metadata(name: str) -> str | None:
    """Resolve from the INSTALLED distribution's metadata. Real, env-dependent."""
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib >=3.8
        return None
    try:
        # PackageMetadata is an email.message.Message at runtime; cast so the
        # .get()/.get_all() accessors type-check (the Protocol omits .get).
        meta = cast("Message", metadata.metadata(name))
    except metadata.PackageNotFoundError:
        return None
    # PEP 639 License-Expression is the cleanest signal when present.
    expr = meta.get("License-Expression")
    if expr and (spdx := _spdx_from_text(expr)):
        return spdx
    for classifier in meta.get_all("Classifier") or []:
        if classifier.lower().startswith("license ::"):
            tail = classifier.split("::")[-1].strip().lower()
            for needle, spdx in _CLASSIFIER_SPDX.items():
                if needle in tail:
                    return spdx
    return _spdx_from_text(meta.get("License"))


def _from_pypi(name: str, timeout: float) -> str | None:
    """Resolve from PyPI's JSON API. Network — opt-in only."""
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, TimeoutError):
        return None
    info = data.get("info", {})
    expr = info.get("license_expression")
    if expr and (spdx := _spdx_from_text(expr)):
        return spdx
    for classifier in info.get("classifiers", []) or []:
        if classifier.lower().startswith("license ::"):
            tail = classifier.split("::")[-1].strip().lower()
            for needle, spdx in _CLASSIFIER_SPDX.items():
                if needle in tail:
                    return spdx
    return _spdx_from_text(info.get("license"))


def resolve_license(
    name: str,
    *,
    allow_metadata: bool = False,
    allow_pypi: bool = False,
    timeout: float = 3.0,
) -> str | None:
    """Resolve ``name`` to an SPDX id, or ``None`` if genuinely unknown.

    The curated manifest is always consulted first (deterministic). The
    environment-dependent sources are tried only when explicitly enabled, so the
    default scan path stays byte-reproducible.
    """
    key = normalize_pkg(name)
    if not key:
        return None
    if key in _LICENSE_MAP:
        return _LICENSE_MAP[key]
    if allow_metadata and (spdx := _from_importlib_metadata(name)):
        return spdx
    if allow_pypi and (spdx := _from_pypi(name, timeout)):
        return spdx
    return None


__all__ = ["resolve_license", "normalize_pkg"]
