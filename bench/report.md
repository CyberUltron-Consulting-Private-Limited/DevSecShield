# AI-BOM benchmark — diff matrix

Canonical key = (normalized_name, type_class). Misses = (Cisco ∪ Trusera) \ Ours; triaged against `fp-exclusions.json`.

| repo | Cisco | Trusera | Ours | overlap | raw-miss | **true-miss** | our-unique |
|------|------:|--------:|-----:|--------:|---------:|--------------:|-----------:|
| 00-synthetic | 7 | 5 | 13 | 9 | 1 | **0** | 4 |
| 01-chroma | 47 | 17 | 107 | 26 | 34 | **0** | 81 |
| 02-langchain | 15 | 8 | 28 | 10 | 12 | **0** | 18 |
| 03-llama-index | 12 | 10 | 46 | 9 | 11 | **0** | 37 |
| 04-autogen | 0 | 2 | 36 | 0 | 2 | **0** | 36 |
| 05-openai-cookbook | 134 | 15 | 159 | 65 | 83 | **0** | 94 |
| 06-mcp-servers | 5 | 2 | 14 | 4 | 2 | **0** | 10 |
| 07-hf-minilm | 7 | 11 | 17 | 14 | 3 | **0** | 3 |
| 08-monai | 13 | 1 | 2 | 0 | 14 | **0** | 2 |
| 09-tf-bedrock | 1 | 3 | 7 | 1 | 3 | **0** | 6 |
| 10-trl-sft | 17 | 5 | 42 | 4 | 18 | **0** | 38 |
| **TOTAL** | | | | | | **0** | 329 |

### TRUE MISSES — none across all repos ✅

## GATE: PASS ✅ — true-misses=0 (must be 0), our-unique=329 (must be >0)
