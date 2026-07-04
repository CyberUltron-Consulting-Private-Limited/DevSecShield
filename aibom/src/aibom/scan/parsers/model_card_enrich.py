"""LLM-inferred model-card fields for models NOT in the knowledge base.

Off the deterministic golden path: used only when explicitly enabled (the
model-ref scanner's ``card_llm`` hook). Calls the Bedrock provider
(:mod:`aibom.enrich.bedrock_llm`) with a strict JSON prompt and parses the four
``modelParameters`` fields. The provider is fail-open + LRU-cached, so:

* offline (``AIBOM_LLM_OFFLINE=1``) or any error -> ``{}`` -> the card stays "—";
* a successful call -> validated subset of card fields.

Never raises — a model whose card can't be inferred simply degrades gracefully.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from aibom.enrich.bedrock_llm import enrich as _bedrock_enrich

_SYSTEM = "You are an ML model-metadata expert. Reply with ONLY compact JSON, no prose."
_PROMPT = (
    'For the AI model "{name}", return a JSON object with exactly these keys: '
    '"approach_type" (one of supervised, unsupervised, self-supervised, '
    'semi-supervised, reinforcement-learning, or null), "task" (short, e.g. '
    '"sentence-embedding" or "chat/completion"), "architecture_family" (e.g. '
    '"transformer"), "model_architecture" (e.g. "MiniLM (BERT-family)"). '
    "Use null when unknown. JSON only."
)
_VALID_APPROACH = {
    "supervised",
    "unsupervised",
    "self-supervised",
    "semi-supervised",
    "reinforcement-learning",
}
_STR_FIELDS = ("task", "architecture_family", "model_architecture")


def infer_card(name: str, *, llm: Callable[..., str | None] = _bedrock_enrich) -> dict:
    """Infer card fields for ``name`` via the LLM provider. ``{}`` on offline/error.

    ``llm`` defaults to the Bedrock provider; tests inject a fake. The result is a
    dict of valid :class:`ModelCard` fields (a subset of approach_type/task/
    architecture_family/model_architecture) — never a partial/invalid value.
    """
    raw = llm(_PROMPT.format(name=name), system=_SYSTEM)
    if not raw:
        return {}
    try:
        snippet = raw[raw.index("{") : raw.rindex("}") + 1]
        data = json.loads(snippet)
    except (ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    out: dict = {}
    approach = data.get("approach_type")
    if approach in _VALID_APPROACH:
        out["approach_type"] = approach
    for key in _STR_FIELDS:
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


__all__ = ["infer_card"]
