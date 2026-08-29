"""AI-BOM Providers chart labels (production: pypi / local / named vendor)."""


_AI_BOM_MODEL_TYPES_FOR_PROVIDER = {
    "local_model_file",
    "huggingface_model",
    "embedding_model",
}
_AI_BOM_FRAMEWORK_TYPES_FOR_PROVIDER = {"ml_framework", "ai_framework"}


def ai_bom_provider_label(asset: dict) -> str:
    """Chart label for one AI-BOM finding's provider.

    Matches production scan 311: torch/langchain → pypi, .pkl weights → local,
    openai/anthropic SDKs keep their vendor name. Empty or ``unknown`` source on
    persisted findings is remapped from ``component_type`` so older scans
    match the same buckets.
    """
    raw = str(asset.get("source") or asset.get("provider") or "").strip()
    if raw and raw.lower() != "unknown":
        return raw
    ctype = str(asset.get("component_type") or "").strip().lower()
    if ctype == "huggingface_model":
        return "huggingface"
    if ctype in _AI_BOM_MODEL_TYPES_FOR_PROVIDER:
        return "local"
    if ctype in _AI_BOM_FRAMEWORK_TYPES_FOR_PROVIDER:
        return "pypi"
    return "unknown"
