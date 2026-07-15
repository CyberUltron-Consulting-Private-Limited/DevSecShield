"""Detect AI/ML libraries, frameworks, providers + vector stores that a repo
IMPORTS in code (``import x`` / ``from x import ...``) — including Jupyter
notebook code cells — but does not declare in a manifest.

Manifest scanners (requirements/pyproject) miss import-only usage (an optional
integration, a notebook tutorial, a vendored example). The two reference OSS
AI-BOM tools detect these from code; a CANONICAL import name only counts when it
is in :data:`AI_IMPORTS` (a curated allowlist), so ordinary stdlib/util imports
never become components. Pure, deterministic, offline.
"""

from __future__ import annotations

import json
import re

# top-level import module  ->  canonical component name (matches the OSS naming)
AI_IMPORTS: dict[str, str] = {
    # providers / SDKs
    "openai": "openai", "anthropic": "anthropic", "cohere": "cohere",
    "mistralai": "mistralai", "google": "google-generativeai",  # google.generativeai
    "boto3": "boto3", "ollama": "ollama", "replicate": "replicate",
    "groq": "groq", "together": "together", "voyageai": "voyageai",
    "jinaai": "jina", "huggingface_hub": "huggingface-hub", "cohere_aws": "cohere",
    # agent / LLM frameworks
    "langchain": "langchain", "langchain_core": "langchain",
    "langchain_community": "langchain", "langchain_openai": "langchain",
    "langchain_text_splitters": "langchain", "langgraph": "langgraph",
    "llama_index": "llama-index", "llama_cpp": "llama-cpp-python",
    "crewai": "crewai", "autogen": "autogen", "autogen_core": "autogen",
    "haystack": "haystack", "semantic_kernel": "semantic-kernel", "dspy": "dspy",
    "litellm": "litellm", "instructor": "instructor", "guidance": "guidance",
    "smolagents": "smolagents", "agents": "openai-agents",
    # model libs
    "transformers": "transformers", "sentence_transformers": "sentence-transformers",
    "datasets": "datasets", "tiktoken": "tiktoken", "tokenizers": "tokenizers",
    "torch": "torch", "tensorflow": "tensorflow", "jax": "jax", "trl": "trl",
    "peft": "peft", "accelerate": "accelerate", "vllm": "vllm",
    "diffusers": "diffusers", "onnxruntime": "onnxruntime", "spacy": "spacy",
    "span_marker": "span-marker",
    # vector stores
    "chromadb": "chromadb", "qdrant_client": "qdrant", "pinecone": "pinecone",
    "weaviate": "weaviate", "faiss": "faiss", "pymilvus": "milvus",
    "lancedb": "lancedb", "marqo": "marqo", "pgvector": "pgvector",
    # MCP
    "mcp": "mcp", "fastmcp": "fastmcp",
    # data / finance tools commonly wired into agents
    "yfinance": "yfinance",
}

# `import a.b.c` / `from a.b import x`  -> capture the dotted module path
_IMPORT_RE = re.compile(
    r"^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import|import[ \t]+([A-Za-z_][\w.]*))",
    re.MULTILINE,
)


def _canon_for(module: str) -> str | None:
    """Map a dotted import path to a canonical AI component name, or None."""
    parts = module.split(".")
    # try the 2-part (google.generativeai) then the top-level (openai)
    if len(parts) >= 2 and f"{parts[0]}.{parts[1]}" == "google.generativeai":
        return "google-generativeai"
    return AI_IMPORTS.get(parts[0])


def _notebook_code(text: str) -> str:
    """Concatenate the source of every code cell in a .ipynb document."""
    try:
        nb = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ""
    out: list[str] = []
    for cell in nb.get("cells", []):
        if cell.get("cell_type") == "code":
            src = cell.get("source", "")
            out.append("".join(src) if isinstance(src, list) else str(src))
    return "\n".join(out)


def find_ai_imports(text: str, *, notebook: bool = False) -> set[str]:
    """Canonical AI component names imported in ``text`` (notebook cells if set)."""
    if notebook:
        text = _notebook_code(text)
    found: set[str] = set()
    for m in _IMPORT_RE.finditer(text):
        module = m.group(1) or m.group(2) or ""
        canon = _canon_for(module)
        if canon:
            found.add(canon)
    return found


__all__ = ["AI_IMPORTS", "find_ai_imports"]
