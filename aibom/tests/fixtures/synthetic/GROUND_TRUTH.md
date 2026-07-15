# Synthetic fixture — ground truth

A fully-controlled, hand-labeled fixture. The reference-tool oracles
(`tests/oracles/{trusera,cisco}/synthetic.json`) are measured against this.

| Category | Count | Items |
|---|---|---|
| Model references | **2** | `gpt-4o` (OpenAI), `claude-3-5-sonnet-20241022` (Anthropic) |
| Providers | **3** | OpenAI, Anthropic, Cohere |
| Agent frameworks | **2** | LangChain, CrewAI |
| Vector store | **1** | ChromaDB |
| Hardcoded API key | **1** | `OPENAI_API_KEY = "sk-proj-…"` in `app.py` |
| Packages w/ known licenses | **3** | `numpy` = BSD-3-Clause, `torch` = BSD-3-Clause, `requests` = Apache-2.0 |

Notes:
- `cohere.embed(model="embed-english-v3.0")` is an *embedding* model call, not a
  generation model — counted as a provider, not among the 2 generation "model
  references." Tools may or may not surface it as a 3rd model; the oracle records
  whatever each tool reports, and the deltas vs this table are the signal.
- `requirements.txt` also lists the AI deps (openai/anthropic/cohere/langchain/
  crewai/chromadb) so the providers/frameworks/vector-store are resolvable both
  from source imports and from the dependency manifest.
