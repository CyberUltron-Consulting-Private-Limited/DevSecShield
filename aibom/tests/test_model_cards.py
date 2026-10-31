"""Model-card population — known-model KB only (deterministic, no LLM)."""
from __future__ import annotations

import os

from aibom.scan.parsers.model_kb import lookup
from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def test_all_minilm_card_populates_via_kb_no_llm() -> None:
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


def test_unknown_model_card_stays_empty() -> None:
    """Models outside the KB get no card fields — never an LLM fill-in."""
    assert lookup("totally-unknown-model-xyz-2099") is None
