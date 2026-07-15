# OSS false-positive exclusions (justified)

The benchmark gate is on **true-positive** misses, not raw set difference. Every
item below is a finding the OSS oracles (Cisco/Trusera) emit that we deliberately
do NOT — each justified. Machine-readable form: `fp-exclusions.json`.

| pattern | class | repos | why it is an OSS false positive |
|---------|-------|-------|---------------------------------|
| `*` (any env-var name/reference) | `secret` | all | Cisco & Trusera flag **env-var names / references** (`env:ANTHROPIC_API_KEY`, `apiKeyEnvVar="X_API_KEY"`) as hardcoded secrets. An env-var reference is the *secure* pattern — the secret is NOT in the code. Our scanner rejects name/reference-shaped values (`secret_scan._NOT_SECRET_VALUE`) and flags only literal credentials. Verified parity on real hardcoded secrets: both tools + ours detect the planted `sk-FAKE` `OPENAI_API_KEY` in the synthetic fixture. |
| `model.safetensors` | `model_file` | 00-synthetic | The synthetic fixture's weight file is **0 bytes**. Trusera/Cisco match it by filename regardless of content; our `model_repo` scanner skips zero-byte/header-less weight files. On real repos (non-empty weights) this is a genuine `model_file` and NOT excluded. |

## NOT excluded — real misses (→ fix our scanner)
- `framework langchain` (00-synthetic): genuinely imported (`from langchain.chains import LLMChain`) but absent from `requirements.txt`. Our scanner detects provider SDKs (openai/anthropic) from **code imports** but only detects frameworks from **requirements.txt** — so an import-only agent framework is missed. This is a TRUE miss and the gate counts it. Fix: extend code-import detection to known agent/LLM frameworks.
