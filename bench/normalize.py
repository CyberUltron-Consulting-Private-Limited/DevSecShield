#!/usr/bin/env python3
"""bench/normalize.py — bridge three tool vocabularies into one comparable set.

Each tool emits a different schema + a different (and often WRONG) type label, so a
raw set-difference is mostly schema noise. We extract from every tool's output a
canonical set of components keyed by

    CANONICAL KEY = (canonical_name, type_class)

so the diff compares *the same thing*. NOT product code — lives only under bench/.

INPUT SCHEMAS
- Trusera  (CycloneDX): top-level ``components: [{type, name, purl, group}]``.
             type vocabulary is coarse — SDKs/providers/vector stores are ALL
             labelled ``machine-learning-model``; only orchestration libs get
             ``framework``. So we re-derive the class from the NAME, not its label.
- Cisco    (native): ``aibom_analysis.sources[<repo>].components`` is a dict keyed
             by Cisco's own class (``model``/``library``/``framework``/``mcp_server``/
             ``vector_store``/``secret``/``dataset``/…), each a list of
             ``{name, component_type, framework, …}``.
- Ours     (CycloneDX): top-level ``components: [{type, name}]`` with type in
             ``machine-learning-model``/``library``/``application``/``data``.

TYPE-CLASS (the shared vocabulary the diff is computed over)
    model | provider | framework | secret | model_file | vector_store |
    mcp_server | dataset | library

MATCHING RULES (documented; applied in priority order, NAME first because the OSS
labels are unreliable):
 1. name → secret           : looks like a credential (api_key/token/secret/…)
 2. name → model_file       : ends in a model-weight suffix (.safetensors/.gguf/…)
 3. name → vector_store     : a known vector DB (chromadb/qdrant/pinecone/…)
 4. name → provider         : a known model PROVIDER/host (openai/anthropic/aws/…)
 5. name → framework        : a known agent/LLM framework (langchain/llama-index/…)
 6. name → mcp_server       : an MCP server package/path
 7. name → model            : matches a model-id shape (gpt-*/claude-*/*-embed*/…)
 8. else fall back to the tool's own class, mapped through CLASS_ALIASES; an
    unmapped library-ish label becomes ``library``.
Canonicalisation of the NAME: lower-case, drop a ``group/`` or ``vendor/`` prefix,
strip a trailing version/quantisation, collapse separators. So
``BAAI/bge-large-en-v1.5`` and ``bge-large-en-v1.5`` collapse to one key, and
``pkg:pypi/chromadb`` → ``chromadb``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TYPE_CLASSES = {
    "model", "provider", "framework", "secret", "model_file",
    "vector_store", "mcp_server", "dataset", "library",
}

# --- name dictionaries (lower-case, canonicalised) ---------------------------
_VECTOR_STORES = {
    "chromadb", "chroma", "qdrant", "qdrant-client", "pinecone", "pinecone-client",
    "weaviate", "weaviate-client", "faiss", "faiss-cpu", "faiss-gpu", "milvus",
    "pymilvus", "lancedb", "hnswlib", "annoy", "usearch", "pgvector", "marqo",
}
_PROVIDERS = {
    "openai", "anthropic", "cohere", "google", "googleai", "google-vertex-ai",
    "vertexai", "vertex", "mistral", "mistralai", "meta", "huggingface",
    "hugging-face", "huggingface-hub", "hf", "jina", "nomic", "voyageai", "voyage",
    "together", "togetherai", "perplexity", "groq", "fireworks", "replicate",
    "aws", "aws-bedrock", "bedrock", "aws-sagemaker", "sagemaker", "azure",
    "azure-openai", "ollama", "deepseek", "xai", "cloudflare", "morph",
}
_FRAMEWORKS = {
    "langchain", "langchain-core", "langchain-community", "langgraph", "llama-index",
    "llamaindex", "llama_index", "autogen", "pyautogen", "crewai", "haystack",
    "haystack-ai", "semantic-kernel", "dspy", "autogpt", "smolagents",
    "transformers", "sentence-transformers", "litellm", "guidance", "instructor",
    "txtai", "griptape", "langflow",
}
_LIBRARIES = {
    "numpy", "scipy", "pandas", "torch", "pytorch", "tensorflow", "jax", "keras",
    "scikit-learn", "sklearn", "pydantic", "requests", "httpx", "aiohttp", "fastapi",
    "flask", "uvicorn", "tqdm", "pyyaml", "orjson", "grpcio", "onnxruntime",
    "kubernetes", "bcrypt", "jsonschema", "pypdf", "tiktoken", "tokenizers",
    "datasets", "accelerate", "safetensors", "peft", "bitsandbytes", "openai-whisper",
}
_MODEL_FILE_SUFFIX = (".safetensors", ".gguf", ".bin", ".onnx", ".pt", ".pth",
                      ".ckpt", ".h5", ".tflite", ".pb", ".mlmodel", ".gpkg")
_SECRET_HINT = re.compile(r"(api[_-]?key|secret|token|credential|password|passwd)",
                          re.IGNORECASE)
_MCP_HINT = re.compile(r"(^|[-_/])mcp([-_/]|$)|mcp[-_]?server|modelcontextprotocol",
                       re.IGNORECASE)
# model-id shapes (a versioned/sized model name, not a plain package)
_MODEL_ID = re.compile(
    r"^(gpt-|o1|o3|claude-|gemini|text-embedding|embed-|bge-|gte-|e5-|"
    r"all-minilm|all-mpnet|mpnet|nomic-embed|jina-embed|llama-?\d|llama2|llama3|"
    r"mistral-|mixtral|qwen|phi-?\d|falcon|gemma|command-|titan-|nova-|"
    r"stable-?diffusion|whisper|sentence-t5|multilingual-)",
    re.IGNORECASE,
)
_EMBED_TOKEN = re.compile(r"(embed|embedding|minilm|mpnet|bge|gte|e5-|gecko)",
                          re.IGNORECASE)

# tool class label -> our type-class (fallback only)
CLASS_ALIASES = {
    "machine-learning-model": "model", "model": "model", "ml-model": "model",
    "library": "library", "application": "library", "data": "dataset",
    "dataset": "dataset", "framework": "framework", "vector_store": "vector_store",
    "vectorstore": "vector_store", "vector-store": "vector_store",
    "mcp_server": "mcp_server", "mcp-server": "mcp_server", "mcpserver": "mcp_server",
    "secret": "secret", "provider": "provider", "model_file": "model_file",
    "service": "provider", "infra": "library", "prompt": "library",
}


def canon_name(raw: str) -> str:
    """Lower-case; drop purl scheme, a ``group/`` prefix, trailing version/quant."""
    n = (raw or "").strip()
    n = re.sub(r"^pkg:[^/]+/", "", n)          # pkg:pypi/chromadb -> chromadb
    n = n.split("@", 1)[0]                      # name@1.2.3 -> name
    low = n.lower().strip()
    # keep model files whole (the suffix is meaningful), else drop a vendor prefix
    if not low.endswith(_MODEL_FILE_SUFFIX) and "/" in low:
        low = low.rsplit("/", 1)[-1]           # BAAI/bge-large -> bge-large
    low = low.replace("_", "-").strip()
    low = re.sub(r"[:=]+v?\d[\w.\-]*$", "", low)  # trailing version after :/=
    # MCP server package names: collapse the optional "server" token so the
    # distribution name `mcp-server-fetch` (ours, from pyproject) and the OSS
    # short form `mcp-fetch` (Cisco) canonicalise to ONE key.
    low = re.sub(r"^mcp-server-", "mcp-", low)
    low = re.sub(r"-mcp-server$", "-mcp", low)
    # Framework FAMILY collapse: a meta-package and its split distributions are
    # the same framework. OSS report the family name ("langchain"); ours reports
    # the concrete sub-distribution from pyproject ("langchain-core",
    # "llama-index-core"). Collapse to the family so they match ONE key.
    low = _collapse_family(low)
    # provider/library name VARIANTS that denote the same component (OSS display
    # name vs the package name we emit). e.g. cohere-ai≡cohere, mistralai≡mistral,
    # google.generativeai≡google-generativeai, "x endpoint"≡x.
    low = re.sub(r"[ -]endpoint$", "", low)            # "ollama endpoint" -> ollama
    low = _PROVIDER_VARIANT.get(low, low)
    return low


_PROVIDER_VARIANT = {
    "cohere-ai": "cohere", "voyageai": "voyage", "voyage-ai": "voyage",
    "googleai": "google-generativeai", "google-ai": "google-generativeai",
    "google.generativeai": "google-generativeai", "mistralai": "mistral",
    "pyautogen": "autogen", "llamaindex": "llama-index",
    "semantic kernel": "semantic-kernel", "huggingface-hub": "huggingface",
}


# meta-package families: any "<fam>-<sub>" (or "<fam>" itself) → the family root.
_FAMILIES = (
    "langchain", "llama-index", "autogen", "crewai", "haystack", "semantic-kernel",
    "google-cloud", "azure", "opentelemetry", "huggingface",
)
_FAMILY_RE = re.compile(r"^(" + "|".join(re.escape(f) for f in _FAMILIES) + r")(-[a-z0-9.\-]+)?$")


def _collapse_family(low: str) -> str:
    m = _FAMILY_RE.match(low)
    return m.group(1) if m else low


# trailing model VERSION/DATE/SIZE/variant tokens — stripped to get the FAMILY root,
# so a bare/differently-versioned OSS pick (gpt-3.5-turbo, gpt-4o-2024-11-20) matches
# the same family we inventory at finer granularity (gpt-3.5-turbo-16k-0613,
# gpt-4o-2024-08-06). Conservative: only well-formed version/date/size suffixes.
_VERSION_TAIL = re.compile(
    r"(?:[-:](?:"
    r"\d{4}-\d\d-\d\d"               # -2024-11-20
    r"|v?\d+(?:\.\d+)*"              # -v1, -3.5, -0613
    r"|\d+[bk]"                      # -16k, -7b
    r"|mini|nano|preview|latest|instruct|turbo|chat|base|small|large|hd"
    r"|\d{3,4}"                      # -001, -1106
    r"))+$",
    re.IGNORECASE,
)


def model_family_root(name: str) -> str:
    """Strip trailing version/date/size/variant tokens to the model family root."""
    root = canon_name(name)
    prev = None
    while prev != root:                 # peel repeated suffixes (gpt-3.5-turbo-16k-0613)
        prev = root
        root = _VERSION_TAIL.sub("", root)
    return root or canon_name(name)


def classify(name: str, raw_type: str | None) -> str:
    low = canon_name(name)
    raw = (raw_type or "").lower()
    if _SECRET_HINT.search(low) or raw == "secret":
        return "secret"
    if low.endswith(_MODEL_FILE_SUFFIX):
        return "model_file"
    if low in _VECTOR_STORES:
        return "vector_store"
    if low in _PROVIDERS:
        return "provider"
    if _MCP_HINT.search(low) or raw in ("mcp_server", "mcp-server"):
        return "mcp_server"
    if low in _FRAMEWORKS:
        return "framework"
    if low in _LIBRARIES:
        return "library"
    if _MODEL_ID.match(low) or _EMBED_TOKEN.search(low):
        return "model"
    return CLASS_ALIASES.get(raw, "library")


def _add(out: set, name: str, raw_type: str | None) -> None:
    cn = canon_name(name)
    if not cn:
        return
    out.add((cn, classify(name, raw_type)))


def from_cyclonedx(path: Path) -> set:
    """Trusera + Ours both emit CycloneDX components[]."""
    doc = json.loads(Path(path).read_text())
    out: set = set()
    for c in doc.get("components", []):
        nm = c.get("name") or (c.get("purl") or "")
        _add(out, nm, c.get("type"))
    return out


def from_cisco(path: Path) -> set:
    doc = json.loads(Path(path).read_text())
    out: set = set()
    sources = doc.get("aibom_analysis", {}).get("sources", {})
    for s in sources.values():
        comps = s.get("components", {})
        # dict keyed by class -> list, OR a flat list
        groups = comps.values() if isinstance(comps, dict) else [comps]
        for group in groups:
            for c in (group or []):
                _add(out, c.get("name") or c.get("model_name") or "",
                     c.get("component_type") or c.get("type"))
    return out


def normalize(path: Path, tool: str) -> set:
    return from_cisco(path) if tool == "cisco" else from_cyclonedx(path)


if __name__ == "__main__":  # quick CLI: normalize.py <tool> <file>
    tool, file = sys.argv[1], sys.argv[2]
    s = normalize(Path(file), tool)
    for nm, tc in sorted(s):
        print(f"{tc:14} {nm}")
    print(f"--- {len(s)} components ({tool}) ---", file=sys.stderr)
