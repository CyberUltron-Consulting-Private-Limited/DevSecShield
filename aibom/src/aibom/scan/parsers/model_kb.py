"""Known-model knowledge base — common models -> model-card fields.

Deterministic (no network / no LLM), so the scan path stays byte-reproducible
(CLAUDE.md rule 6). Keyed by a normalized model FAMILY token, so namespaced /
variant ids (``Xenova/all-MiniLM-L6-v2``, ``chroma/all-minilm-l6-v2-f32``) all
resolve to the same card. Models not covered here get an empty card ("—").

Each entry's keys map onto :class:`aibom.model.component.ModelCard`:
``approach_type`` (a ModelCard Literal or omitted), ``task``,
``architecture_family``, ``model_architecture``, ``license`` (SPDX / LicenseRef),
and ``lineage`` (pedigree ancestor names). "proprietary" is a *license*, never an
``approach_type`` (hosted models' training approach is undisclosed -> omitted).
"""

from __future__ import annotations

_PROPRIETARY = "LicenseRef-proprietary"

# Ordered family token -> card fields. First containment match wins, so put
# more-specific tokens before generic ones.
_KB: tuple[tuple[str, dict], ...] = (
    # ── open sentence-embedding models ──
    (
        "all-minilm",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "MiniLM (BERT-family)",
            "license": "Apache-2.0",
            "lineage": ["MiniLM (distillation teacher)"],
        },
    ),
    (
        "all-mpnet",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "MPNet",
            "license": "Apache-2.0",
            "lineage": ["MPNet"],
        },
    ),
    (
        "bge-",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "BGE (BERT-family)",
            "license": "MIT",
            "lineage": [],
        },
    ),
    (
        "e5-",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "E5",
            "license": "MIT",
            "lineage": [],
        },
    ),
    (
        "gte-",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "GTE",
            "license": "Apache-2.0",
            "lineage": [],
        },
    ),
    (
        "nomic-embed",
        {
            "approach_type": "self-supervised",
            "task": "sentence-embedding",
            "architecture_family": "transformer",
            "model_architecture": "Nomic Embed",
            "license": "Apache-2.0",
            "lineage": [],
        },
    ),
    # ── proprietary, hosted ──
    (
        "gpt-4",
        {
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "GPT (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    (
        "gpt-3.5",
        {
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "GPT (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    (
        "text-embedding-",
        {
            "task": "text-embedding",
            "architecture_family": "transformer",
            "model_architecture": "OpenAI Embedding (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    (
        "claude-",
        {
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "Claude (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    (
        "gemini-",
        {
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "Gemini (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    (
        "embed-english",
        {
            "task": "text-embedding",
            "architecture_family": "transformer",
            "model_architecture": "Cohere Embed (proprietary)",
            "license": _PROPRIETARY,
            "lineage": [],
        },
    ),
    # ── open generative ──
    (
        "mixtral",
        {
            "approach_type": "self-supervised",
            "task": "chat/completion",
            "architecture_family": "transformer (sparse MoE)",
            "model_architecture": "Mixtral",
            "license": "Apache-2.0",
            "lineage": ["Mistral"],
        },
    ),
    (
        "mistral",
        {
            "approach_type": "self-supervised",
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "Mistral",
            "license": "Apache-2.0",
            "lineage": [],
        },
    ),
    (
        "llama",
        {
            "approach_type": "self-supervised",
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "LLaMA",
            "license": "LicenseRef-llama-community",
            "lineage": [],
        },
    ),
)


def lookup(name: str) -> dict | None:
    """Return a COPY of the card fields for ``name``, or ``None`` if not in the KB.

    Matching is case-insensitive containment of a family token in the model id's
    final path segment (org prefix stripped).
    """
    if not name:
        return None
    low = name.lower().split("/")[-1]
    for token, fields in _KB:
        if token in low:
            return dict(fields)
    return None


__all__ = ["lookup"]
