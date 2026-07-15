"""bench/normalize.py — canonicalize each tool's output into a comparable set.

ISOLATED benchmark code (NOT product code). Reads the three tools' raw outputs for
one repo and emits, per tool, a set of CANONICAL KEYS::

    key = (normalized_name, type_class)

so the diff matrix compares *entities*, not each tool's idiosyncratic schema. The
overwhelming majority of false diffs come from (a) name spelling/version/namespace
noise and (b) each tool typing the same entity differently (Trusera calls the
chromadb library a ``machine-learning-model``; we call it a ``library``; Cisco a
``dependency``). Both are normalized away here.

──────────────────────────────────────────────────────────────────────────────
MATCHING RULES (documented — this is the crux of a fair benchmark)
──────────────────────────────────────────────────────────────────────────────
type_class ∈ {model, provider, framework, secret, model_file, vector_store,
              mcp_server, dataset, library}

1. NAME NORMALIZATION (`norm_name`):
   - lowercase, strip surrounding whitespace
   - drop a leading ``@scope/`` (npm) and any ``pkg:eco/`` purl prefix
   - keep only the last path segment (``huggingface/transformers`` -> ``transformers``)
   - strip a trailing version (``chromadb@0.5.0`` / ``chromadb-0.5.0`` -> ``chromadb``)
   - ``_`` -> ``-``
   - apply ALIASES (``google.generativeai`` -> ``google``, ``mistralai`` -> ``mistral``,
     ``langchain-core`` -> ``langchain``, ``azure-openai`` -> ``azure`` ...) so the
     three tools' different spellings of the same vendor collapse to one key.

2. TYPE-CLASS (`classify`) — NAME-FIRST, tool-type fallback. Applied uniformly to
   every tool's components so the same entity lands in the same class regardless of
   how the tool typed it:
   a. filename with a model-weight extension (.safetensors/.gguf/.bin/.pt/.onnx/
      .h5/.ckpt/.pkl/.pb) -> model_file
   b. normalized name in VECTOR_STORES -> vector_store
   c. normalized name in MCP_SERVERS or name endswith '-mcp'/startswith 'mcp-' -> mcp_server
   d. normalized name in PROVIDERS -> provider
   e. normalized name in FRAMEWORKS -> framework
   f. name matches MODEL_RE (gpt-/claude-/gemini-/all-minilm/llama-N/...) -> model
   g. tool raw-type fallback:
        Cisco:   model->model, model_artifact->model_file, secret->secret,
                 vector_store->vector_store, mcp_server->mcp_server,
                 provider->provider, dataset->dataset, dependency->library
        CycloneDX (Trusera/ours):
                 secret prop / type 'data'+secret:kind -> secret
                 provider:kind prop / type 'application' -> provider
                 dataset prop / type 'data' (dataset) -> dataset
                 type 'machine-learning-model' -> model
                 type 'framework' -> framework
                 type 'library'/'application' -> library
   h. default -> library

3. DEDUPE within each tool's set on the (name, class) key.

The classifier is INTENTIONALLY identical across tools (rules a–f are tool-agnostic
name rules) so a difference in the final sets reflects a difference in *what was
discovered*, not a difference in vocabulary.
"""

from __future__ import annotations

import json
import re
import sys

# ── known-entity name sets (lowercase, post-norm) ────────────────────────────
PROVIDERS = {
    "openai", "anthropic", "cohere", "google", "mistral", "huggingface",
    "bedrock", "aws", "azure", "vertex", "vertexai", "ollama", "together",
    "replicate", "groq", "fireworks", "deepseek", "nvidia", "jina", "nomic",
    "voyage", "perplexity", "xai", "meta", "sentence-transformers",
}
FRAMEWORKS = {
    "langchain", "langgraph", "llamaindex", "llama-index", "crewai", "autogen",
    "haystack", "dspy", "semantic-kernel", "transformers", "torch", "pytorch",
    "tensorflow", "keras", "jax", "scikit-learn", "sklearn", "spacy", "nltk",
    "diffusers", "accelerate", "peft", "trl", "vllm", "monai", "lightning",
    "pytorch-lightning", "fastai", "xgboost", "onnxruntime", "datasets",
    "sentencepiece", "tokenizers", "openai-agents", "pydantic-ai",
}
VECTOR_STORES = {
    "chromadb", "chroma", "pinecone", "weaviate", "qdrant", "qdrant-client",
    "faiss", "faiss-cpu", "faiss-gpu", "milvus", "pymilvus", "lancedb",
    "pgvector", "redis", "elasticsearch", "opensearch", "marqo", "vespa",
}
MCP_SERVERS = {"mcp", "modelcontextprotocol", "fastmcp"}

ALIASES = {
    "google.generativeai": "google", "google-generativeai": "google",
    "google-genai": "google", "googlegenerativeai": "google", "google-ai": "google",
    "google-generative-ai": "google", "vertex-ai": "vertex", "google-vertex": "vertex",
    "mistralai": "mistral", "mistral-ai": "mistral",
    "langchain-core": "langchain", "langchain-community": "langchain",
    "langchain-openai": "langchain", "langchain-anthropic": "langchain",
    "llama-index": "llamaindex", "llama_index": "llamaindex",
    "azure-openai": "azure", "azure-ai-inference": "azure", "azure-ai": "azure",
    "aws-bedrock": "bedrock", "amazon-bedrock": "bedrock", "aws-sagemaker": "sagemaker",
    "amazon-sagemaker": "sagemaker",
    "openai-python": "openai", "openai-api": "openai", "anthropic-sdk": "anthropic",
    "huggingface-hub": "huggingface", "huggingface_hub": "huggingface",
    "huggingface-transformers": "huggingface", "hugging-face": "huggingface", "hf": "huggingface",
    "semantic-kernel-python": "semantic-kernel",
    "pytorch": "torch", "sklearn": "scikit-learn",
    "qdrant-client": "qdrant", "faiss-cpu": "faiss", "faiss-gpu": "faiss",
    "pymilvus": "milvus", "chroma": "chromadb", "pytorch-lightning": "lightning",
    "redis-stack": "redis", "redis-stack-server": "redis",
}

# Generic placeholder names that are never a real entity — OSS tools (esp. Cisco's
# agentic pass) emit these as components (e.g. a dataset literally named "model" or
# "ml-pipeline"). Dropping them is normalization, not hiding a finding ("do NOT
# chase regex noise"). Documented + listed; every drop is reproducible from here.
STOPWORDS = {
    "", "model", "models", "dataset", "datasets", "model-name", "modelname",
    "ml-pipeline", "pipeline", "training-run", "model-artifact", "artifact",
    "unknown", "none", "null", "example", "examples", "test", "tests", "sample",
    "provider", "framework", "library", "secret", "api", "config", "default",
}

MODEL_RE = re.compile(
    r"(gpt-|gpt4|o[1-4]-|claude-|claude\d|gemini-|embed-|text-embedding|"
    r"minilm|mpnet|llama-?\d|mistral-\d|mixtral|embedding-\d|multilingual-\d|"
    r"-v\d|bge-|e5-|gte-|nomic-embed|jina-embed|titan-|cohere-|command-r|"
    r"phi-\d|qwen|deepseek-|whisper|stable-diffusion|sdxl|resnet|bert-|t5-)",
    re.I,
)
_WEIGHT_EXT = (".safetensors", ".gguf", ".bin", ".pt", ".pth", ".onnx", ".h5",
               ".ckpt", ".pkl", ".pb", ".tflite", ".mlmodel")
# Strip ONLY true version/date suffixes — NOT model family tokens. So
# ``chromadb-0.5.0`` -> ``chromadb`` and ``claude-3-5-sonnet-20241022`` ->
# ``claude-3-5-sonnet`` (drops the date), but ``gpt-4o`` / ``all-minilm-l6-v2``
# are preserved (no dot, no 6-digit date).
_SEMVER_TAIL = re.compile(r"-\d+(?:\.\d+)+[\w.\-]*$")   # -0.5.0 / -1.26.4
_DATE_TAIL = re.compile(r"-\d{6,}$")                    # -20241022


def norm_name(raw: str) -> str:
    if not raw:
        return ""
    n = raw.strip().lower()
    n = re.sub(r"^pkg:[a-z]+/", "", n)        # purl prefix
    n = re.sub(r"^@[^/]+/", "", n)            # npm scope
    n = re.sub(r"^(env|secret|os\.environ):", "", n)  # secret indirection prefix
    n = n.split("?")[0].split("#")[0]
    if "/" in n and not n.endswith("/"):
        n = n.split("/")[-1]                  # last path segment
    n = n.split("@")[0]                       # name@version -> name
    n = n.replace("_", "-").strip()
    n = re.sub(r"\s+", "-", n)                # multi-word vendor: "aws bedrock" -> "aws-bedrock"
    n = re.sub(r"^mcp-server-", "mcp-", n)    # ours' pyproject name mcp-server-fetch == Cisco's mcp-fetch
    n = _SEMVER_TAIL.sub("", n)               # trailing -1.2.3
    n = _DATE_TAIL.sub("", n)                 # trailing -20241022
    n = n.strip("()[]{},;:· ")               # strip wrapping punctuation parse-artifacts
    n = ALIASES.get(n, n)
    return "" if n in STOPWORDS else n


def _is_weight_file(raw: str) -> bool:
    return raw.strip().lower().endswith(_WEIGHT_EXT)


def classify(raw_name: str, raw_type: str, props: dict, tool: str) -> str:
    n = norm_name(raw_name)
    rt = (raw_type or "").lower()
    # a. model-weight file
    if _is_weight_file(raw_name) or rt in ("model_artifact", "model-file"):
        return "model_file"
    # b–e. name-first known-entity classes
    if n in VECTOR_STORES:
        return "vector_store"
    if n in MCP_SERVERS or n.endswith("-mcp") or n.startswith("mcp-"):
        return "mcp_server"
    if n in PROVIDERS and not MODEL_RE.search(n):
        return "provider"
    if n in FRAMEWORKS:
        return "framework"
    # f. looks like a concrete model identifier
    if MODEL_RE.search(n) or MODEL_RE.search((raw_name or "").lower()):
        return "model"
    # g. tool raw-type fallback
    pk = {k.lower(): str(v).lower() for k, v in (props or {}).items()}
    if any("secret" in k for k in pk) or rt == "secret":
        return "secret"
    if any("provider" in k for k in pk):
        return "provider"
    if any("dataset" in k for k in pk) or rt == "dataset":
        return "dataset"
    if rt in ("dependency", "library", "application"):
        return "library"
    if rt in ("machine-learning-model", "model"):
        return "model"
    if rt == "framework":
        return "framework"
    if rt == "data":  # CycloneDX 'data' with no secret/dataset hint
        return "dataset"
    return "library"


# ── per-tool extractors -> list[(raw_name, raw_type, props)] ─────────────────
def _cyclonedx_components(path: str):
    d = json.load(open(path))
    for c in d.get("components", []):
        props = {p.get("name"): p.get("value") for p in (c.get("properties") or [])}
        yield c.get("name", ""), c.get("type", ""), props


def _cisco_components(path: str):
    a = json.load(open(path)).get("aibom_analysis", {})
    for src in a.get("sources", {}).values():
        for ctype, items in (src.get("components", {}) or {}).items():
            for it in items:
                name = it.get("name") or it.get("identifier") or ""
                yield name, ctype, it


def canonical_set(tool: str, path: str) -> set[tuple[str, str]]:
    """Return the deduped set of (normalized_name, type_class) for one tool/repo."""
    out: set[tuple[str, str]] = set()
    extractor = _cisco_components if tool == "cisco" else _cyclonedx_components
    for raw_name, raw_type, props in extractor(path):
        n = norm_name(raw_name)
        if not n:
            continue
        out.add((n, classify(raw_name, raw_type, props, tool)))
    return out


if __name__ == "__main__":
    # CLI: normalize.py <tool> <path>  -> prints sorted "class\tname"
    tool, path = sys.argv[1], sys.argv[2]
    for n, cls in sorted(canonical_set(tool, path), key=lambda x: (x[1], x[0])):
        print(f"{cls}\t{n}")
