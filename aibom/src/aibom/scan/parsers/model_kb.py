"""Known-model knowledge base — common models -> model-card fields.

Deterministic (no network / no LLM), so the scan path stays byte-reproducible
(CLAUDE.md rule 6). Keyed by a normalized model FAMILY token, so namespaced /
variant ids (``Xenova/all-MiniLM-L6-v2``, ``chroma/all-minilm-l6-v2-f32``) all
resolve to the same card. Models not covered here get an empty card ("—").

Each entry's keys map onto :class:`aibom.model.component.ModelCard`:
``approach_type`` (a ModelCard Literal or omitted), ``task``,
``architecture_family``, ``model_architecture``, ``license`` (SPDX / LicenseRef),
``lineage`` (pedigree ancestor names) and ``out_of_scope`` (uses the model's
licence excludes, from the licence's published terms; model-card
``considerations``). "proprietary" is a *license*, never an
``approach_type`` (hosted models' training approach is undisclosed -> omitted).
"""

from __future__ import annotations

import re

from aibom.scan.parsers.model_refs import parse_bedrock_id

# "[<geo>.]<provider>." in front of a Bedrock model id
_BEDROCK_PREFIX = re.compile(r"^(?:(?:us-gov|us|eu|apac|global)\.)?[a-z0-9]+\.")

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
    # ── Mistral families whose licence is not Apache-2.0 (QA round 2, Q2-07) ──
    # Sources: Mistral's model weights page (docs.mistral.ai/getting-started/models/
    # weights): Codestral-22B-v0.1 MNPL, Mistral-Large-Instruct-2407 / -2411 Mistral
    # Research License, Codestral-Mamba-7B Apache 2.0; mistral.ai/news/codestral:
    # "Codestral is a 22B open-weight model licensed under the new Mistral AI
    # Non-Production License" (research and testing; commercial licence on request).
    # docs.mistral.ai lists codestral-latest as the alias of codestral-2508 (code
    # completion, fill-in-the-middle).
    (
        "codestral-mamba",
        {
            "task": "code generation",
            "model_architecture": "Codestral Mamba",
            "license": "Apache-2.0",
            "lineage": [],
        },
    ),
    (
        "codestral",
        {
            "task": "code completion and generation (fill-in-the-middle)",
            "model_architecture": "Codestral",
            "license": "LicenseRef-Mistral-AI-Non-Production-License",
            "lineage": [],
            "out_of_scope": [
                "production / commercial use: the Mistral AI Non-Production License "
                "permits research and testing only; production use needs a commercial "
                "licence from Mistral AI"
            ],
        },
    ),
    *(
        (
            token,
            {
                "task": "chat/completion",
                "architecture_family": "transformer",
                "model_architecture": "Mistral Large",
                "license": "LicenseRef-Mistral-Research-License",
                "lineage": [],
            },
        )
        for token in (
            "mistral-large-2407",
            "mistral-large-instruct-2407",
            "mistral-large-2411",
            "mistral-large-instruct-2411",
        )
    ),
    # other Mistral Large / Medium versions: the licence depends on the version (a
    # hosted premier model, or an open-weight release under its own licence), so it
    # is not stated (the scanner raises the soft MODEL_LICENSE_UNKNOWN for usage)
    (
        "mistral-large",
        {"task": "chat/completion", "model_architecture": "Mistral Large",
         "lineage": []},
    ),
    (
        "mistral-medium",
        {"task": "chat/completion", "model_architecture": "Mistral Medium",
         "lineage": []},
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
    # a Bedrock id: the model part only ("mistral.pixtral-…" is no "mistral" model)
    if parse_bedrock_id(low) is not None:
        low = _BEDROCK_PREFIX.sub("", low)
    for token, fields in _KB:
        if token in low:
            return dict(fields)
    return None


__all__ = ["lookup"]
