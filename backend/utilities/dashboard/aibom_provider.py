"""Resolve concrete AI-BOM ModelProvider labels (never ``unknown``).

Mirrors ``aibom.integrations.devsecshield._provider`` so legacy persisted scans
(source=unknown) remapped at read time match new adapter emissions.
"""

from __future__ import annotations

from typing import Any

# Concrete ModelProvider values emitters/resolvers may return (legacy ``unknown``
# is remapped away). Keep in sync with RabbitMQ/worker/helpers/context/enums.py.
KNOWN_PROVIDERS = frozenset(
    {
        "openai",
        "anthropic",
        "bedrock",
        "vertex",
        "cohere",
        "mistral",
        "huggingface",
        "azure",
        "ollama",
        "google",
        "groq",
        "together",
        "openrouter",
        "deepseek",
        "xai",
        "alibaba",
        "pypi",
        "credential",
        "local",
    }
)

_CLOUD_NEEDLES: tuple[tuple[str, str], ...] = (
    ("anthropic", "anthropic"),
    ("claude", "anthropic"),
    ("bedrock", "bedrock"),
    ("amazon-bedrock", "bedrock"),
    ("aws-bedrock", "bedrock"),
    ("azure", "azure"),
    ("vertex", "vertex"),
    ("cohere", "cohere"),
    ("mistral", "mistral"),
    ("hugging", "huggingface"),
    ("ollama", "ollama"),
    ("openrouter", "openrouter"),
    ("groq", "groq"),
    ("together.xyz", "together"),
    ("together.ai", "together"),
    ("together ai", "together"),
    ("deepseek", "deepseek"),
    ("api.x.ai", "xai"),
    ("xai api", "xai"),
    # Alibaba Cloud (Qwen's publisher, DashScope); a local Qwen weight file names none of these
    ("alibaba", "alibaba"),
    ("dashscope", "alibaba"),
    ("aliyun", "alibaba"),
    ("openai", "openai"),
    ("gemini", "google"),
    ("googleapis", "google"),
    ("google", "google"),
)

# Hosted APIs that scans stored before review of #487 (m7, second review n-a) labelled ``local``: re-derived when read.
_SAAS_ONCE_LOCAL = frozenset({"google", "groq", "together", "openrouter", "deepseek", "xai", "alibaba"})

_FRAMEWORK_TYPES = frozenset({"ml_framework", "ai_framework", "framework"})
_MODEL_TYPES = frozenset(
    {"local_model_file", "huggingface_model", "embedding_model", "model"}
)
_ARTIFACT_SUFFIXES = (".bin", ".safetensors", ".gguf", ".pt", ".pth", ".onnx")


def infer_aibom_provider(
    *,
    name: str = "",
    kind_or_type: str = "",
    location: str = "",
    publisher: str = "",
    extra: str = "",
) -> str:
    """Infer a concrete provider from inventory fields (never ``unknown``)."""
    text = " ".join(
        str(x) for x in (publisher, name, location, extra) if x
    ).lower()
    for needle, value in _CLOUD_NEEDLES:
        if needle in text:
            return value

    name_l = (name or "").lower()
    type_l = (kind_or_type or "").lower()

    if type_l in _FRAMEWORK_TYPES or "framework" in type_l:
        return "pypi"
    if (
        "credential" in name_l
        or "secret" in name_l
        or type_l in ("secret", "credential")
    ):
        return "credential"
    if (
        type_l in _MODEL_TYPES
        or type_l in ("dataset", "prompt", "prompt_asset")
        or any(name_l.endswith(sfx) for sfx in _ARTIFACT_SUFFIXES)
    ):
        return "local"
    return "local"


def is_model_asset(asset: dict[str, Any]) -> bool:
    """A model row: a model component type, or a provider-served model the engine types ``external_provider`` with
    ``component_kind`` "model" (QA round 2, Q2-06). Weight files are ``local_model_file`` (models)."""
    kind = str(asset.get("component_kind") or asset.get("asset_kind") or "").lower()
    ctype = str(asset.get("component_type") or asset.get("asset_type") or "").lower()
    return kind == "model" or ctype in {"local_model_file", "huggingface_model", "embedding_model"}


def resolve_aibom_provider(asset: dict[str, Any]) -> str:
    """Return a concrete provider for a finding / scan_data row.

    Passes through already-concrete ``source``/``provider`` values; remaps empty
    or ``unknown`` using name/type/location.
    """
    stored = (
        asset.get("source")
        or asset.get("provider")
        or ""
    )
    stored_l = str(stored).strip().lower()
    if stored_l in KNOWN_PROVIDERS and stored_l != "local":
        return stored_l

    name = (
        asset.get("component_name")
        or asset.get("asset_name")
        or asset.get("title")
        or ""
    )
    kind_or_type = (
        asset.get("component_type")
        or asset.get("asset_type")
        or asset.get("kind")
        or ""
    )
    location = asset.get("location") or ""
    publisher = asset.get("publisher") or asset.get("framework") or ""
    snippet = asset.get("snippet") or ""
    inferred = infer_aibom_provider(
        name=str(name),
        kind_or_type=str(kind_or_type),
        location=str(location),
        publisher=str(publisher),
        extra=str(snippet),
    )
    if stored_l == "local" and inferred not in _SAAS_ONCE_LOCAL:
        # a stored ``local`` stands, except for the SaaS APIs the adapter labelled ``local`` before it knew them
        return "local"
    return inferred
