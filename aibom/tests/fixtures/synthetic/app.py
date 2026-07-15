"""Synthetic labeled AI fixture — the GROUND TRUTH we fully control.

Contains EXACTLY:
  - 2 model references:  gpt-4o, claude-3-5-sonnet-20241022
  - 3 providers:         OpenAI, Anthropic, Cohere
  - 2 agent frameworks:  LangChain, CrewAI
  - 1 vector store:      ChromaDB
  - 1 hardcoded API key  (the OPENAI_API_KEY literal below)
See GROUND_TRUTH.md. Package licenses (numpy=BSD, torch=BSD, requests=Apache)
live in requirements.txt.
"""
import os

import numpy as np
import requests
import torch

# ── providers (3) ────────────────────────────────────────────────────────────
from openai import OpenAI
import anthropic
import cohere

# ── agent frameworks (2) ─────────────────────────────────────────────────────
from langchain.chains import LLMChain
from crewai import Agent, Task, Crew

# ── vector store (1) ─────────────────────────────────────────────────────────
import chromadb

# ── hardcoded API key (1) — a fake literal for secret-detection ──────────────
OPENAI_API_KEY = "sk-proj-aBcD1234EfGh5678IjKl9012MnOp3456QrSt7890UvWxYzaa"

openai_client = OpenAI(api_key=OPENAI_API_KEY)
anthropic_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
cohere_client = cohere.Client(os.environ.get("COHERE_API_KEY"))


# ── model references (2) ─────────────────────────────────────────────────────
def summarize(text: str) -> str:
    resp = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": text}],
    )
    return resp.choices[0].message.content


def analyze(text: str) -> str:
    resp = anthropic_client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=512,
        messages=[{"role": "user", "content": text}],
    )
    return resp.content[0].text


def embed(text: str):
    return cohere_client.embed(texts=[text], model="embed-english-v3.0").embeddings


# ── vector store usage ───────────────────────────────────────────────────────
chroma_client = chromadb.Client()
collection = chroma_client.create_collection(name="documents")


def index(doc_id: str, text: str) -> None:
    collection.add(ids=[doc_id], documents=[text])


# ── agent-framework usage ────────────────────────────────────────────────────
researcher = Agent(role="researcher", goal="research a topic", backstory="expert")
writer_task = Task(description="write a summary", agent=researcher)
crew = Crew(agents=[researcher], tasks=[writer_task])

chain = LLMChain  # langchain reference


def main() -> None:
    arr = np.array([1.0, 2.0, 3.0])
    _ = torch.tensor(arr)
    requests.get("https://example.com/health", timeout=5)
    print(summarize("hello"), analyze("hi"))


if __name__ == "__main__":
    main()
