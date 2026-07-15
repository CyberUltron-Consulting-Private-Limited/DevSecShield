"""Model-card population — KB (deterministic) + Bedrock enrich (mocked) + offline.

aibom/contract/testing: real pipeline for the KB path; mock ONLY the boto3
upstream for the LLM path; offline degrades to "—" with no error.
"""
from __future__ import annotations

import json
import os
import sys
import types

from aibom.scan.parsers import model_card_enrich
from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def test_all_minilm_card_populates_via_kb_no_llm() -> None:
    # No card_llm set -> KB only (deterministic, no network).
    result = scan_repo(_fx("synthetic-ai-app"), level=1)
    minilm = [
        c for c in result.components
        if c.kind == "model" and "minilm" in c.name.lower()
    ]
    assert minilm, "all-MiniLM-L6-v2 reference must be detected"
    card = minilm[0].model_card
    assert card.approach_type == "self-supervised"
    assert card.task == "sentence-embedding"
    assert card.architecture_family == "transformer"
    assert card.model_architecture and "MiniLM" in card.model_architecture
    assert card.pedigree_ancestors, "lineage (pedigree) must be populated"
    assert minilm[0].licenses, "all-MiniLM resolves to Apache-2.0"


def _fake_boto3(payload: dict) -> types.ModuleType:
    mod = types.ModuleType("boto3")

    class _Client:
        def converse(self, **kw):
            return {"output": {"message": {"content": [{"text": json.dumps(payload)}]}}}

    mod.client = lambda *a, **k: _Client()  # type: ignore[attr-defined]
    return mod


def test_unknown_model_card_via_mocked_bedrock(monkeypatch) -> None:
    monkeypatch.delenv("AIBOM_LLM_OFFLINE", raising=False)
    monkeypatch.setitem(
        sys.modules, "boto3",
        _fake_boto3({
            "approach_type": "self-supervised", "task": "image-classification",
            "architecture_family": "transformer", "model_architecture": "MysteryNet",
        }),
    )
    from aibom.enrich import bedrock_llm
    bedrock_llm.cache_clear()

    fields = model_card_enrich.infer_card("totally-unknown-model-xyz-2099")
    assert fields["approach_type"] == "self-supervised"
    assert fields["task"] == "image-classification"
    assert fields["model_architecture"] == "MysteryNet"


def test_offline_degrades_to_dash_without_error(monkeypatch) -> None:
    monkeypatch.setenv("AIBOM_LLM_OFFLINE", "1")
    from aibom.enrich import bedrock_llm
    bedrock_llm.cache_clear()
    # Offline -> no fields -> the card simply stays "—" (empty), no exception.
    assert model_card_enrich.infer_card("totally-unknown-model-xyz-2099") == {}
