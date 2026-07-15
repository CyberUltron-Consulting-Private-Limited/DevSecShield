"""Synthetic AI application — fully hand-labeled (see expected_assets.json).

Exercises every detector lane: provider SDK imports (openai / anthropic), an
agent framework (langchain), inline model-name string literals, a ChromaDB
vector-store init, a PLANTED FAKE secret, and a model weight file alongside.
"""
import os

import numpy as np  # noqa: F401  (licensed-library presence)
import requests  # noqa: F401
from openai import OpenAI
import anthropic
from langchain.chains import LLMChain  # noqa: F401  (agent framework)
import chromadb

# PLANTED FAKE secret — obvious test dummy, NOT a real credential.
OPENAI_API_KEY = "sk-FAKE-DO-NOT-USE-0000000000000000000000000000"

# Inline model-name references the model-ref scanner must surface.
GEN_MODEL = "gpt-4o"
CLAUDE_MODEL = "claude-3-5-sonnet-20241022"
EMBED_MODEL = "all-MiniLM-L6-v2"

openai_client = OpenAI(api_key=OPENAI_API_KEY)
anthropic_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# Vector store (ChromaDB) — the embedding / vector surface.
chroma_client = chromadb.Client()
collection = chroma_client.create_collection("docs")


def answer(question: str) -> str:
    """Call an LLM (the generation path)."""
    resp = openai_client.chat.completions.create(
        model=GEN_MODEL,
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content
