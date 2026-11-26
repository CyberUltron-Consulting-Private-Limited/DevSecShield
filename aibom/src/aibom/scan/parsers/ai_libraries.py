"""Which declared dependencies are AI/ML libraries (and so belong in an AI BOM).

A manifest lists every dependency of the application: web frameworks, database
drivers, test runners, linters. Only the AI/ML ones are AI components; the rest
are software-supply-chain inventory and belong in the SBOM. Classing every
manifest line as an ``ml_framework`` put pytest, mypy, ruff and sqlalchemy in a
bank's AI BOM and drove its risk score (their "unknown licence" flags) to 100.

:func:`classify` returns one of:

* ``"ai"``    — an AI/ML library: model / training / inference frameworks, LLM
  provider SDKs, agent and RAG frameworks, vector stores, tokenizers, model
  safety / evaluation, and the numerical / imaging data stack models run on;
* ``"dev"``   — a development or test tool (never shipped, never an AI component);
* ``"other"`` — an ordinary runtime dependency (web, database, cache, metrics …).

Deterministic and offline: a curated allow-list plus a few prefix families.
"""

from __future__ import annotations

import re
from typing import Literal

from aibom.scan.parsers.code_imports import AI_IMPORTS

LibraryRole = Literal["ai", "dev", "other"]

_NORM = re.compile(r"[-_.]+")


def _norm(name: str) -> str:
    return _NORM.sub("-", re.sub(r"\[.*$", "", name.strip().lower())).strip("-")


_AI_LIBRARIES = frozenset(
    {
        # model / training / inference frameworks
        "torch", "torchvision", "torchaudio", "pytorch-lightning", "lightning",
        "tensorflow", "keras", "jax", "jaxlib", "flax", "optax", "paddlepaddle",
        "mxnet", "scikit-learn", "sklearn", "xgboost", "lightgbm", "catboost",
        "statsmodels", "onnx", "onnxruntime", "tensorrt", "openvino", "fastai",
        "timm", "ultralytics", "transformers", "diffusers", "accelerate", "peft",
        "trl", "bitsandbytes", "deepspeed", "optimum", "safetensors", "tokenizers",
        "sentence-transformers", "datasets", "evaluate", "huggingface-hub",
        "vllm", "llama-cpp-python", "ctransformers", "mlx", "mlx-lm", "gguf",
        "spacy", "nltk", "gensim", "span-marker", "mlflow", "wandb",
        "tensorboard", "ray", "triton",
        # speech: Whisper runtimes and speaker diarization (#498 round 3 audit:
        # insanely-fast-whisper's pyannote-audio was not an AI library)
        "pyannote-audio", "openai-whisper", "faster-whisper", "whisperx",
        "ctranslate2",
        # numerical / imaging data stack the models run on
        "numpy", "scipy", "pandas", "polars", "pyarrow", "pillow",
        "opencv-python", "opencv-python-headless", "scikit-image", "pydicom",
        "nibabel", "simpleitk", "monai",
        # LLM provider SDKs and gateways
        "openai", "anthropic", "cohere", "mistralai", "google-generativeai",
        "google-genai", "vertexai", "google-cloud-aiplatform", "groq", "together",
        "replicate", "ollama", "litellm", "voyageai", "jina", "fireworks-ai",
        "boto3-bedrock", "amazon-bedrock",
        # agent / RAG / orchestration frameworks
        "langchain", "langgraph", "llama-index", "haystack", "haystack-ai",
        "farm-haystack", "semantic-kernel", "autogen", "pyautogen", "crewai",
        "dspy", "dspy-ai", "guidance", "instructor", "outlines", "smolagents",
        "openai-agents", "pydantic-ai", "agno", "mcp", "fastmcp",
        # vector stores and retrieval
        "chromadb", "faiss", "faiss-cpu", "faiss-gpu", "pinecone",
        "pinecone-client", "qdrant", "qdrant-client", "weaviate",
        "weaviate-client", "pymilvus", "milvus", "lancedb", "marqo", "pgvector",
        "tiktoken", "rank-bm25",
        # model safety / evaluation
        "guardrails-ai", "nemoguardrails", "ragas", "deepeval", "garak",
        "llm-guard", "presidio-analyzer", "presidio-anonymizer",
    }
    | {_norm(v) for v in AI_IMPORTS.values() if v not in ("boto3", "yfinance")}
)
_AI_PREFIXES = (
    "langchain-", "llama-index-", "tensorflow-", "onnxruntime-", "torch-",
    "transformers-", "openai-", "anthropic-", "haystack-", "autogen-",
    "sentence-transformers-", "huggingface-", "nvidia-", "jax-", "pyannote-",
)

_DEV_TOOLS = frozenset(
    {
        "pytest", "mypy", "ruff", "black", "isort", "flake8", "pylint", "pyright",
        "pyflakes", "pycodestyle", "pydocstyle", "autopep8", "yapf", "bandit",
        "safety", "pip-audit", "vulture", "codespell", "coverage", "tox", "nox",
        "pre-commit", "respx", "responses", "requests-mock", "httpretty", "mock",
        "hypothesis", "faker", "factory-boy", "freezegun", "time-machine", "moto",
        "fakeredis", "mongomock", "testcontainers", "locust", "debugpy", "ipdb",
        "ipython", "ipykernel", "sphinx", "mkdocs", "mkdocs-material", "twine",
        "build", "wheel", "setuptools", "pip", "pip-tools", "hatch", "hatchling",
        "poetry", "pdm", "uv", "bump2version", "commitizen", "syrupy",
        "snapshottest", "assertpy", "pyfakefs", "watchdog",
    }
)
_DEV_PREFIXES = (
    "pytest-", "flake8-", "types-", "mypy-", "sphinx-", "mkdocs-", "coverage-",
    "pylint-",
)


# A package the allow-list does not know (a private / internal SDK) is AI when its
# name says so as a whole word: "acme-llm-client", "internal-ml-scorer".
_AI_WORDS = frozenset(
    {"ai", "llm", "llms", "ml", "genai", "gpt", "inference", "embedding", "embeddings",
     "rag", "agent", "agents", "nlp", "transformer", "transformers", "vectorstore",
     "mlops", "chatbot"}
)


def classify(name: str) -> LibraryRole:
    """``ai`` / ``dev`` / ``other`` for a distribution name (PEP 503-normalized)."""
    n = _norm(name)
    if n in _DEV_TOOLS or n.startswith(_DEV_PREFIXES) or n.endswith("-stubs"):
        return "dev"
    if n in _AI_LIBRARIES or n.startswith(_AI_PREFIXES):
        return "ai"
    if _AI_WORDS.intersection(n.split("-")):
        return "ai"
    return "other"


__all__ = ["LibraryRole", "classify"]
