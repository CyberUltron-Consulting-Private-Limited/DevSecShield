"""Scorer-calibration fixture — deterministically exercises every severity band.

CRITICAL: the planted fake secret. HIGH: the no-license carded model
(MODEL_CARD.md). MEDIUM: the unknown-license library (requirements.txt). LOW:
the licensed library + the vector store (no misconfiguration).
"""
import chromadb  # vector store -> low/info

# PLANTED FAKE secret -> HARDCODED_SECRET -> critical (obvious test dummy).
OPENAI_API_KEY = "sk-FAKE-SCORING-0000000000000000000000000000"

chroma_client = chromadb.Client()
