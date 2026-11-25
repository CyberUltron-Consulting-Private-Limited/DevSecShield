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
    # speech and vision model libraries (#498 round 3 audit)
    "pyannote": "pyannote-audio", "whisper": "openai-whisper",
    "faster_whisper": "faster-whisper", "whisperx": "whisperx",
    "ctranslate2": "ctranslate2", "bitsandbytes": "bitsandbytes",
    "ultralytics": "ultralytics", "timm": "timm", "gensim": "gensim",
    "tensorrt": "tensorrt",
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


_JSON_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def read_notebook(text: str) -> str | None:
    """The code cells of a .ipynb document as one Python text, or None when the
    document is not a readable notebook (invalid JSON, or JSON that is not a notebook).

    Defensive (review 6062066749 of #498, M3): a corrupt or half-saved notebook must
    never abort a scan. ``cells`` that is not a list, a top-level list, cells that
    are not objects and ``source`` items that are not strings are skipped. nbformat 3
    (``worksheets[].cells[].input``) is read too."""
    try:
        nb = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(nb, dict):
        return None
    cells: list = []
    if isinstance(nb.get("cells"), list):
        cells = nb["cells"]
    elif isinstance(nb.get("worksheets"), list):  # nbformat 3
        for sheet in nb["worksheets"]:
            if isinstance(sheet, dict) and isinstance(sheet.get("cells"), list):
                cells.extend(sheet["cells"])
    elif "cells" in nb or "worksheets" in nb:
        return None  # a notebook shape we cannot read
    out: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source", cell.get("input", ""))
        if isinstance(src, list):
            out.append("".join(s for s in src if isinstance(s, str)))
        elif isinstance(src, str):
            out.append(src)
    return "\n".join(out)


def notebook_code(text: str) -> str:
    """The code cells of a .ipynb document ("" when it cannot be read)."""
    return read_notebook(text) or ""


def notebook_text(text: str) -> tuple[str, bool]:
    """``(code, readable)``: the code cells, or for an unreadable notebook (a
    truncated save, invalid JSON) its raw text with the JSON string escapes undone,
    so a model or client it names is still seen; ``readable`` False lets the scan
    record a warning (review 6062066749 of #498, m4)."""
    code = read_notebook(text)
    if code is not None:
        return code, True
    # every JSON string literal, decoded (a truncated save still holds its cells'
    # source lines as complete strings)
    parts: list[str] = []
    for m in _JSON_STRING.finditer(text):
        try:
            parts.append(json.loads(f'"{m.group(1)}"'))
        except ValueError:
            continue
    return "\n".join(parts), False


def find_ai_imports(text: str, *, notebook: bool = False) -> set[str]:
    """Canonical AI component names imported in ``text`` (notebook cells if set)."""
    if notebook:
        text = notebook_text(text)[0]
    found: set[str] = set()
    for m in _IMPORT_RE.finditer(text):
        module = m.group(1) or m.group(2) or ""
        canon = _canon_for(module)
        if canon:
            found.add(canon)
    return found


__all__ = [
    "AI_IMPORTS",
    "find_ai_imports",
    "notebook_code",
    "notebook_text",
    "read_notebook",
]
