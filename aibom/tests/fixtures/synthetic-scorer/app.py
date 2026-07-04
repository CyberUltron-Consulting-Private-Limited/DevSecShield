"""Engineered scorer-calibration fixture — one finding per severity band.

The recalibrated scorer stacks per-component flag weights and maps the sum to a
severity band (critical/high/medium/low). This fixture is built so a real scan
yields >=1 finding in EACH band:

  CRITICAL  the planted FAKE secret below   -> HARDCODED_SECRET (14)
  HIGH      the unlicensed model card        -> MODEL_NO_LICENSE (8)   [see MODEL_CARD.md]
  MEDIUM    the unknown-license library      -> FRAMEWORK_NO_LICENSE (5) [see requirements.txt]
  LOW       the chromadb vector store + libs -> no flag (inventory floor)

Not a real app — a deterministic severity-band oracle.
"""

import chromadb  # vector store -> low/info

# ── CRITICAL: a planted FAKE hardcoded credential (obvious test dummy) ────────
OPENAI_API_KEY = "sk-FAKE-DO-NOT-USE-0000000000000000000000000000"

client = chromadb.Client()
collection = client.create_collection("docs")
