"""Differential gate: OUR scanner vs the committed reference-tool oracles.

Quantifies detection **recall** (and precision, reported) for three categories —
``provider``, ``framework``, and **model references** — on the same fixtures the
oracles were captured against (``tests/oracles/{trusera,cisco}/<fixture>.json``,
committed in 1de6e27). It is a *tracking gate*: it FAILS now (RED) where the
engine is below threshold and turns GREEN as detection improves.

Category -> oracle choice (deliberate):
  * ``provider`` / ``framework`` -> **Trusera** (CycloneDX). Trusera surfaces
    these as package names, which our requirements parser can match by name.
  * ``model`` -> **Cisco**. Cisco is the ONLY oracle that extracts actual model
    identifiers (``gpt-4o``, ``claude-3-5-sonnet-20241022``, ``all-minilm-...``).
    Trusera types SDK/provider names as ``machine-learning-model`` and extracts
    ZERO real model IDs, so the spec's "models vs Trusera" is ill-defined and is
    corrected here to "models vs Cisco".

Thresholds (recall): providers >= 0.90, frameworks >= 0.90, models >= 0.70.

Expected current state (pre code-AST fix — see aibom/state/realworld-gap):
  * synthetic:   providers/frameworks PASS (requirements.txt-resolvable), models FAIL.
  * trusera-demo: providers/frameworks PASS, models FAIL.
  * chroma:      ALL fail — the engine is requirements.txt-only with no code-AST,
                 so on a real repo (deps in pyproject/package.json + used in code)
                 even provider/framework recall collapses. This is the headline gap.

Scans run the engine IN-PROCESS (``scan_repo``) — synchronous, so there is no
async job to await. If this is ever driven through the platform worker (Celery),
await the terminal job state CONDITION-BASED (poll success/failure, never sleep),
exactly like ``backend/tests/test_ai_bom_e2e.py`` (skill-condition-based-waiting).

The 71 MB ``chroma`` fixture is a gitignored upstream clone (tests/fixtures/CHROMA.md);
chroma cases SKIP when the clone is absent so the synthetic gate still runs in CI.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(_HERE, "fixtures")
ORACLES = os.path.join(_HERE, "oracles")

THRESHOLDS = {"provider": 0.90, "framework": 0.90, "model": 0.70}

# Canonical alias sets — vendor/SDK names that denote a model PROVIDER, and the
# agent/orchestration FRAMEWORKS. Names are matched after normalization.
PROVIDERS = {
    "openai", "anthropic", "cohere", "mistral", "mistralai", "google", "googleai",
    "google-generativeai", "google.generativeai", "generativeai", "vertexai", "vertex",
    "bedrock", "aws-bedrock", "aws bedrock", "azure-openai", "azure openai", "azureopenai",
    "together", "together ai", "togetherai", "ollama", "huggingface", "hugging-face",
    "huggingface-transformers", "transformers", "sentence-transformers", "xenova",
    "replicate", "ai21", "groq", "fireworks", "deepseek", "perplexity", "ai-sdk",
}
FRAMEWORKS = {
    "langchain", "langgraph", "crewai", "llamaindex", "llama-index", "autogen",
    "haystack", "dspy", "semantic-kernel",
}
# Signatures of an actual model IDENTIFIER (not an SDK/provider package name).
MODEL_RE = re.compile(
    r"(gpt-|claude-|gemini-|embed-|text-embedding|minilm|all-mpnet|llama-?\d|"
    r"mistral-\d|embedding-\d|multilingual-\d|-v\d|bge-|e5-|gte-)",
    re.I,
)


def _norm(name: str) -> str:
    if not name:
        return ""
    n = name.strip().lower()
    n = re.sub(r"^@[^/]+/", "", n)   # @chroma-core/openai -> openai ; @ai-sdk/openai -> openai
    n = n.split("/")[-1]            # huggingface/transformers -> transformers
    return n.replace("_", "-").strip()


def _categorize(name: str) -> tuple[str, str]:
    raw = (name or "").strip().lower()
    n = _norm(name)
    if MODEL_RE.search(raw) or MODEL_RE.search(n):
        return "model", raw
    if n in FRAMEWORKS:
        return "framework", n
    if n in PROVIDERS or raw in PROVIDERS:
        return "provider", n
    return "other", n


def _sets(names) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"provider": set(), "framework": set(), "model": set()}
    for nm in names:
        cat, key = _categorize(nm)
        if cat in out:
            out[cat].add(key)
    return out


def _our(fixture: str) -> dict[str, set[str]]:
    path = os.path.join(FIXTURES, fixture)
    if not os.path.isdir(path):
        pytest.skip(f"fixture {fixture!r} not present (see tests/fixtures/CHROMA.md)")
    return _sets(c.name for c in scan_repo(path, level=4).components)


def _trusera(fixture: str) -> dict[str, set[str]]:
    d = json.load(open(os.path.join(ORACLES, "trusera", f"{fixture}.json")))
    return _sets(c.get("name", "") for c in d.get("components", []))


def _cisco(fixture: str) -> dict[str, set[str]]:
    d = json.load(open(os.path.join(ORACLES, "cisco", f"{fixture}.json")))["aibom_analysis"]
    names = [
        it.get("name") or it.get("identifier") or ""
        for src in d["sources"].values()
        for items in src.get("components", {}).values()
        for it in items
    ]
    return _sets(names)


def _oracle(fixture: str, category: str) -> set[str]:
    src = _cisco if category == "model" else _trusera
    return src(fixture)[category]


def _recall(our: set[str], oracle: set[str]) -> float:
    return len(our & oracle) / len(oracle) if oracle else float("nan")


# Full matrix: every (fixture, category) is a tracked gate. Cases below threshold
# are RED by design until the engine improves (records the quantified gap in CI).
_CASES = [
    (fx, cat)
    for fx in ("synthetic", "trusera-demo", "chroma")
    for cat in ("provider", "framework", "model")
]


@pytest.mark.parametrize("fixture,category", _CASES, ids=lambda v: v)
def test_recall_threshold(fixture: str, category: str) -> None:
    ours = _our(fixture)[category]
    oracle = _oracle(fixture, category)
    if not oracle:
        pytest.skip(f"oracle for {fixture}/{category} is empty (nothing to measure)")
    recall = _recall(ours, oracle)
    missed = sorted(oracle - ours)
    assert recall >= THRESHOLDS[category], (
        f"{fixture}/{category}: recall {recall:.2f} < {THRESHOLDS[category]:.2f} "
        f"(ours={len(ours)} oracle={len(oracle)} missed={missed[:8]})"
    )
