# OSS false-positive exclusions (triage justification)

The gate is on **true-positive** misses, not raw set difference. 119 of the 187 raw
misses are OSS false positives — Trusera regex noise + Cisco agentic over-generation.
Each is excluded by a documented rule in `fp_exclusions.json` (applied by `diff.py`).
**No exclusion hides a real gap** — genuine misses are in `fix-tasks.md`.

| # | class | rule (regex) | count | why it's a false positive |
|---|-------|--------------|------:|---------------------------|
| 1 | `dataset` | `.*` (all) | 68 | Cisco fabricates "datasets" from tutorial CSV/JSONL files (`ag-news-samples.csv`), training **hyperparameters** (`hyperparameter:batch-size` — not a dataset), experiment trackers (`fl-best-model`), and generic words (`sdk`, `evaluate`). None are governance-relevant corpora. Ours *does* inventory real declared training datasets via the typed graph (`trained_on` edge, e.g. clinical-samd) — it just doesn't list arbitrary tutorial data files. |
| 2 | `secret` | `api-key\|-key$\|-url$\|-id$\|disable-tracing\|embeddings-model` | 20 | env-var / config **key names** (`azure-openai-api-key`, `ngc-api-key`, `qdrant-url`, `cse-id`), not hardcoded credential **literals**. Ours flags only hardcoded values — verified precision advantage (same class as the `ANTHROPIC_API_KEY` env-reference FP on repo0). |
| 3 | `provider` | `api-key\|boto3\|tiktoken\|github-action\|langchain-model\|openai-model\|openai-endpoint\|huggingface-transformers-model\|langchain-google-genai` | ~12 | mis-typed: credential names; `boto3` (AWS SDK lib); `tiktoken` (tokenizer lib); a CI action; LangChain integration **class** names. Real vendors (bedrock/azure/cohere/huggingface/ollama/together + the aws-bedrock* TF resources) are kept. |
| 4 | `framework` | `^crewai$` | ~5 | CrewAI is **mentioned** in docs/comparisons, not a dependency (0 source files in chroma). Real imported frameworks kept. |
| 5 | `mcp_server` | `everything.*server\|server:\|development-guidelines\|docs-langchain\|reference-langchain\|["']` | ~3 | markdown heading / doc-link parse artifacts. Real MCP servers (mcp/mcp-fetch/git/time/fastmcp) kept as true misses. |
| 6 | `model` | `api-key\|\.csv$\|\.jsonl$\|samples$` | ~2 | `cohere-api-key` (credential name), `winemag-data-130k-v2.csv` (data file) mis-typed as models. Real model ids kept. |
| 7 | `model_file` | `qint8\|quint8\|model-o[0-9]\|openvino.*qint8\|avx` | ~8 | quantization / hardware-variant exports of one model (8 `.onnx`/`.bin` variants of all-MiniLM) — OSS over-enumeration. The primary weight files are detected by ours (`model_file_scan`, 14 on hf-model). |
| 8 | `model` | `^ft:\|^openai\.gpt$\|^gpt-4o-20` | ~3 | not base-model ids: `ft:gpt-4o-…` is a user fine-tune INSTANCE id; `openai.gpt` a placeholder; `gpt-4o-2024-11-20` a dated snapshot of `gpt-4o` ours already detects (granularity dup). |
| 9 | `provider` | `^huggingface$\|\.` (contains a dot) | ~7 | `huggingface` standalone duplicates the HF ecosystem ours captures as `transformers`/`sentence-transformers`; dotted names (`aws-bedrockagent-agent.agent-supervisor`) are **Terraform resource addresses**, not providers (ours has `provider:bedrock` via cloud-iac). |
| 10 | `model_file` (exact) | `monai/model.pt` | 1 | Cisco location=`null` → a code string (`torch.save('model.pt')`), not a committed file. Ours inventories only real files. |

**Note on the 25 remaining true-misses:** they are NOT excluded — they are the genuine
code-reference recall gap (FIX-1 in `fix-tasks.md`). The exclusions above are strictly
OSS noise (fabricated datasets, env-var-name "secrets", doc-mention frameworks,
quantization variants, fine-tune-instance ids, Terraform resource addresses).

**Total excluded ≈ 119** (raw 187 → 68 true). Trusera's `machine-learning-model`-for-everything
typing and Cisco's agentic dataset/secret invention are the two dominant noise sources —
exactly the "schema/name mismatch" the normalizer + this triage exist to neutralize.
