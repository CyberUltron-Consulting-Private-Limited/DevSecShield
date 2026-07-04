"""Map scan findings to the OWASP Top 10 for LLM Applications (2025).

Pure, deterministic mapping layer. Given the engine's inventory (components) and
semantic flags, it assigns each finding the OWASP-LLM categories it evidences and
produces an aggregate distribution for the whole scan (``ScanResult.owasp``).

**Taxonomy = the REAL OWASP LLM Top 10 (2025)** — codes ``LLM01``..``LLM10`` with
their 2025 meanings (LLM02 Sensitive Information Disclosure, LLM03 Supply Chain,
LLM08 Vector and Embedding Weaknesses). This is the SOLE / canonical OWASP
mapper: the DevSecShield ``normalize()`` adapter uses it for BOTH the per-finding
``owasp_top_10_llm`` (emitted as full ``LLMxx:2025 - <meaning>`` labels so the
dashboard renders the correct 2025 names regardless of the frontend's legacy
label map) AND the aggregate ``ScanResult.owasp`` distribution. (The earlier
``aibom.scan.owasp`` platform-2023 mapper has been retired.) The mapping table
below is the implementation of record (every row is a comment).

Design rules (mirroring the compliance layer):
* PURE — a category is decided from a component's kind/name/version or a flag
  CODE, never from a score. Same input -> same output.
* CONSERVATIVE — signals with no defensible OWASP-LLM home map to nothing (an
  empty set), never a forced/guessed category.

Category id = the short code ``LLM01``..``LLM10`` (assertable, stable); human
labels live in :data:`OWASP_LLM_LABELS`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aibom.model.component import AIComponent
    from aibom.model.result import Flag, ScanResult

# ── the OWASP LLM Top 10 (2025) ──────────────────────────────────────────────
OWASP_LLM_LABELS: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ── flag CODE -> categories (the finding/flag-type half of the table) ─────────
# FRAMEWORK_NO_LICENSE / MODEL_NO_LICENSE -> LLM03 (a component without a
#   concluded license is an unverifiable supply-chain element).
# UNSANCTIONED_COMPONENT (shadow AI) -> LLM03 (untracked component in the chain).
# MODEL_PHI_AT_INFERENCE -> LLM02 (PHI flowing through inference is sensitive-info
#   exposure). DATASET_NO_DEIDENT -> LLM02 (un-de-identified data = sensitive info).
# DATASET_DECLARED_NOT_FOUND -> LLM04 (a referenced training set that cannot be
#   verified is a data-provenance/poisoning gap).
# EU-AI-Act/graph-collision/file-suffix flags have no defensible OWASP-LLM home.
_FLAG_OWASP: dict[str, frozenset[str]] = {
    "HARDCODED_SECRET": frozenset({"LLM02"}),  # leaked credential -> sensitive-info
    "FRAMEWORK_NO_LICENSE": frozenset({"LLM03"}),
    "MODEL_NO_LICENSE": frozenset({"LLM03"}),
    "MODEL_LICENSE_UNKNOWN": frozenset({"LLM03"}),  # unverifiable model supply chain
    "UNSANCTIONED_COMPONENT": frozenset({"LLM03"}),
    "MODEL_PHI_AT_INFERENCE": frozenset({"LLM02"}),
    "DATASET_NO_DEIDENT": frozenset({"LLM02"}),
    "DATASET_DECLARED_NOT_FOUND": frozenset({"LLM04"}),
    "SERVICE_NO_RATE_LIMIT": frozenset({"LLM10"}),  # endpoint -> unbounded consumption
}

# Kinds that are autonomous agents / tools -> LLM06 (Excessive Agency).
_AGENTIC_KINDS: frozenset[str] = frozenset(
    {
        "agent",
        "tool",
        "mcp_server",
        "mcp_client",
        "plugin",
        "orchestrator",
    }
)

# ── component signals ────────────────────────────────────────────────────────
# Vector stores -> LLM08 (Vector and Embedding Weaknesses).
_VECTOR_STORES: frozenset[str] = frozenset(
    {
        "chromadb",
        "chroma",
        "qdrant-client",
        "qdrant",
        "pinecone-client",
        "pinecone",
        "weaviate-client",
        "weaviate",
        "faiss",
        "faiss-cpu",
        "faiss-gpu",
        "milvus",
        "pymilvus",
        "lancedb",
        "hnswlib",
        "annoy",
        "usearch",
        "pgvector",
        "marqo",
    }
)
# Agent / orchestration frameworks -> LLM06 (Excessive Agency).
_AGENT_FRAMEWORKS: frozenset[str] = frozenset(
    {
        "langchain",
        "langgraph",
        "crewai",
        "autogen",
        "llama-index",
        "llamaindex",
        "haystack",
        "haystack-ai",
        "semantic-kernel",
        "dspy",
        "autogpt",
        "smolagents",
    }
)
# Substrings that mark an embedding model id -> LLM08.
_EMBEDDING_TOKENS: tuple[str, ...] = (
    "embed",
    "embedding",
    "minilm",
    "mpnet",
    "bge-",
    "gte-",
    "e5-",
    "gecko",
    "sentence-transformers",
    "nomic-embed",
    "jina-embed",
)


def _norm(name: str | None) -> str:
    return (name or "").strip().lower().replace("_", "-")


def _is_embedding_model(name: str | None) -> bool:
    low = _norm(name)
    return any(tok in low for tok in _EMBEDDING_TOKENS)


def categories_for_flag(code: str) -> frozenset[str]:
    """OWASP-LLM categories evidenced by a flag CODE (empty if none)."""
    return _FLAG_OWASP.get(code, frozenset())


def categories_for_component(
    comp: AIComponent,
    flags: Iterable[Flag] = (),
) -> set[str]:
    """OWASP-LLM categories for one component, given the flags ON it.

    Combines the component-intrinsic signal (kind / name / pinned-ness) with the
    categories of its flags. PURE — no scores consulted.
    """
    cats: set[str] = set()
    kind = comp.kind
    name = _norm(comp.name)

    if kind == "secret":
        cats.add("LLM02")  # hardcoded key / credential -> sensitive-info disclosure
    elif kind == "framework":
        if name in _VECTOR_STORES:
            cats.add("LLM08")
        if name in _AGENT_FRAMEWORKS:
            cats.add("LLM06")
        if comp.version is None:  # unpinned dependency -> supply-chain risk
            cats.add("LLM03")
    elif kind == "model":
        if _is_embedding_model(comp.name):
            cats.add("LLM08")
    elif kind == "prompt":
        cats.add("LLM01")  # a stored prompt/template is the prompt-injection surface
    elif kind == "service":
        # a model-serving / LLM endpoint is an unbounded-consumption surface
        # (no rate-limit evidenced in the BOM) -> LLM10.
        cats.add("LLM10")
    elif kind in _AGENTIC_KINDS:
        cats.add("LLM06")  # an autonomous agent / tool -> excessive agency

    for flag in flags:
        cats |= categories_for_flag(flag.code)
    return cats


def owasp_distribution(result: ScanResult) -> dict[str, int]:
    """Aggregate {category: number of findings} over the whole scan.

    Each component contributes its category set once (intrinsic + its flags); any
    flag whose target is not a component is folded in so no signal is dropped.
    Returns a dict ordered by OWASP code.
    """
    counts: Counter[str] = Counter()
    component_refs = {c.bom_ref for c in result.components}
    for comp in result.components:
        for cat in categories_for_component(comp, result.flags_for(comp.bom_ref)):
            counts[cat] += 1
    for flag in result.flags:
        if flag.target not in component_refs:
            for cat in categories_for_flag(flag.code):
                counts[cat] += 1
    return {code: counts[code] for code in OWASP_LLM_LABELS if counts[code]}


def annotate(result: ScanResult) -> dict[str, int]:
    """Compute the distribution and store it on ``result.owasp``; return it."""
    dist = owasp_distribution(result)
    result.owasp = dist
    return dist


__all__ = [
    "OWASP_LLM_LABELS",
    "categories_for_flag",
    "categories_for_component",
    "owasp_distribution",
    "annotate",
]
