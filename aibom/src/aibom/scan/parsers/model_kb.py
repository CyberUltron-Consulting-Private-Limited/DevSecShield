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
    # ── OpenAI Whisper open weights (the Hub checkpoints openai/whisper-tiny …
    # -large-v3-turbo: "license: apache-2.0" on their model cards). The API model
    # ``whisper-1`` matches none of these tokens and keeps OpenAI's terms. ──
    *(
        (
            token,
            {
                "approach_type": "supervised",
                "task": "automatic-speech-recognition",
                "architecture_family": "transformer (encoder-decoder)",
                "model_architecture": "Whisper",
                "license": "Apache-2.0",
                "lineage": [],
            },
        )
        for token in (
            "whisper-tiny",
            "whisper-base",
            "whisper-small",
            "whisper-medium",
            "whisper-large",
        )
    ),
    # ── Google Gemma open weights: the Gemma Terms of Use (ai.google.dev/gemma/terms),
    # not Google's hosted-API terms and not an OSI licence ──
    (
        "gemma",
        {
            "approach_type": "self-supervised",
            "task": "chat/completion",
            "architecture_family": "transformer",
            "model_architecture": "Gemma",
            "license": "LicenseRef-Gemma-Terms-of-Use",
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
    # ── Mistral (QA round 2 Q2-07; review 6037909737 of #498, M6) ──
    # A licence is the licence of the OPEN WEIGHTS, so it is stated only for an
    # open-weight id (a Hugging Face style id with its size / instruct tag). Sources:
    # docs.mistral.ai/getting-started/models/weights (Codestral-22B MNPL; Mistral
    # Large Instruct 2407 / 2411, Ministral 8B, Pixtral Large: Mistral Research
    # License; Mistral 7B, Mixtral, Nemo, Small, Codestral Mamba, Mathstral, Pixtral
    # 12B: Apache 2.0) and mistral.ai/news/codestral. API names (codestral-latest /
    # -2508, mistral-large-latest, mistral-saba-latest …) are used under Mistral's
    # commercial terms (legal.mistral.ai): they carry no weights licence here, and the
    # model-considerations scanner records an API-served Mistral model as provider
    # terms (LicenseRef-proprietary), with no out-of-scope use.
    (
        "codestral-22b",
        {
            "task": "code completion and generation (fill-in-the-middle)",
            "architecture_family": "transformer",
            "model_architecture": "Codestral",
            "license": "LicenseRef-Mistral-AI-Non-Production-License",
            "lineage": [],
            "out_of_scope": [
                "production / commercial use of the open weights: the Mistral AI "
                "Non-Production License permits research and testing only; production "
                "use needs a commercial licence from Mistral AI"
            ],
        },
    ),
    *(
        (
            token,
            {
                "task": task,
                "model_architecture": arch,
                "license": "LicenseRef-Mistral-Research-License",
                "lineage": [],
            },
        )
        for token, task, arch in (
            ("mistral-large-instruct-2407", "chat/completion", "Mistral Large"),
            ("mistral-large-instruct-2411", "chat/completion", "Mistral Large"),
            ("ministral-8b", "chat/completion", "Ministral"),
            ("pixtral-large", "image-text-to-text", "Pixtral"),
        )
    ),
    *(
        (
            token,
            {
                "approach_type": "self-supervised",
                "task": task,
                "architecture_family": family,
                "model_architecture": arch,
                "license": "Apache-2.0",
                "lineage": [],
            },
        )
        for token, task, family, arch in (
            ("codestral-mamba", "code generation", "state space model",
             "Codestral Mamba"),
            ("mathstral", "chat/completion", "transformer", "Mathstral"),
            ("pixtral-12b", "image-text-to-text", "transformer", "Pixtral"),
            ("mixtral-8x", "chat/completion", "transformer (sparse MoE)", "Mixtral"),
            ("mistral-7b", "chat/completion", "transformer", "Mistral"),
            ("mistral-nemo", "chat/completion", "transformer", "Mistral NeMo"),
            ("mistral-small-24b", "chat/completion", "transformer", "Mistral Small"),
            ("mistral-small-3", "chat/completion", "transformer", "Mistral Small"),
        )
    ),
    # any other Mistral id (codestral-latest, mistral-large-latest, mistral-saba …):
    # model card fields only, no licence (API terms, or a version-dependent licence)
    *(
        (token, {"task": task, "model_architecture": arch, "lineage": []})
        for token, task, arch in (
            ("codestral", "code completion and generation (fill-in-the-middle)",
             "Codestral"),
            ("mixtral", "chat/completion", "Mixtral"),
            ("mistral-large", "chat/completion", "Mistral Large"),
            ("mistral-medium", "chat/completion", "Mistral Medium"),
            ("mistral-small", "chat/completion", "Mistral Small"),
            ("mistral", "chat/completion", "Mistral"),
        )
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
