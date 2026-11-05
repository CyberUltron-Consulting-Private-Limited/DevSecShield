"""Parse a model ``config.json`` into normalized modelParameters fields.

A HuggingFace-style ``config.json`` is the source of the model's architecture
and I/O. We deliberately read only well-known keys and map ``model_type`` to a
human ``architectureFamily``; the model card (not config.json) owns identity,
lineage, metrics and the clinical/regulatory blocks.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aibom.scan.safe_files import read_text

# model_type -> CycloneDX modelCard.modelParameters.architectureFamily phrasing.
_FAMILY_BY_TYPE = {
    "resnet": "convolutional neural network",
    "convnext": "convolutional neural network",
    "efficientnet": "convolutional neural network",
    "vit": "transformer",
    "bert": "transformer",
    "gpt": "transformer",
    "gpt2": "transformer",
    "llama": "transformer",
    "lstm": "recurrent neural network",
    "rnn": "recurrent neural network",
}

# Approach values accepted by the model contract (ModelCard.approach_type).
_VALID_APPROACH = {
    "supervised",
    "unsupervised",
    "reinforcement-learning",
    "semi-supervised",
    "self-supervised",
}


def _clean_architecture(cfg: dict[str, Any]) -> str | None:
    explicit = cfg.get("model_architecture")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    arches = cfg.get("architectures")
    if isinstance(arches, list) and arches and isinstance(arches[0], str):
        return arches[0].strip()
    return None


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int, float))]
    return []


def parse_config(path: Path) -> dict[str, Any]:
    """Return normalized modelParameters fields from ``config.json`` ({} if absent).

    Keys returned (all optional): ``approach_type``, ``task``,
    ``architecture_family``, ``model_architecture``, ``inputs``, ``outputs``.
    """
    text = read_text(path)  # None: absent, a link or not a regular file
    if text is None:
        return {}
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(cfg, dict):
        return {}

    out: dict[str, Any] = {}

    approach = cfg.get("approach")
    if isinstance(approach, str) and approach in _VALID_APPROACH:
        out["approach_type"] = approach

    task = cfg.get("task")
    if isinstance(task, str) and task.strip():
        out["task"] = task.strip()

    arch = _clean_architecture(cfg)
    if arch:
        out["model_architecture"] = arch

    model_type = cfg.get("model_type")
    if isinstance(model_type, str):
        family = _FAMILY_BY_TYPE.get(model_type.lower())
        if family:
            out["architecture_family"] = family

    inputs = _str_list(cfg.get("inputs"))
    if inputs:
        out["inputs"] = inputs
    outputs = _str_list(cfg.get("outputs"))
    if outputs:
        out["outputs"] = outputs

    return out


__all__ = ["parse_config"]
