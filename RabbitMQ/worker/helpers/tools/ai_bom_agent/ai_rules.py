"""
AI/ML asset detection rules (analogue of crypto_rules.py).

Maps:
- model file extensions -> serialization safety + risk category
- import / dependency patterns -> AI/ML component type + framework + provider
- provider call patterns -> model literal + pinned/unpinned classification
- Hugging Face hub references -> huggingface_model components
- dataset markers -> dataset components
- prompt-asset markers -> prompt_asset components
- AI risk categories -> impact + OWASP Top 10 for LLM + suggested fix

DEEP detection scope across python + javascript/typescript source files,
plus extension-only detection of local model weight files.

IMPORTANT: OWASP / Impact member names below are REAL members of the enums
defined in helpers/context/enums.py (OWASPTop10LLM, Impact). Do not invent.
"""

from helpers.context.enums import (
    AIComponentType,
    AIRiskCategory,
    ModelProvider,
    OWASPTop10LLM,
    Impact,
)

# ---------------------------------------------------------------------------
# Local model weight files — detected by EXTENSION ONLY (no content read).
# ---------------------------------------------------------------------------
# Pickle-based formats execute arbitrary code on load (torch.load / joblib /
# pickle) -> UNSAFE => untrusted deserialization, Critical.
# Partially-safe formats (HDF5/Keras) can carry Lambda layers / custom code.
# Safe formats are pure tensor containers => never flagged as untrusted; the
# residual concern is missing model-card / lineage metadata.
MODEL_FILE_EXTENSIONS: dict[str, dict] = {
    # ----- PICKLE-BASED (UNSAFE: arbitrary code execution on load) -----
    ".pkl": {
        "serialization": "pickle",
        "trusted": False,
        "impact": Impact.CRITICAL.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    ".joblib": {
        "serialization": "joblib-pickle",
        "trusted": False,
        "impact": Impact.CRITICAL.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    ".pt": {
        "serialization": "pytorch-pickle",
        "trusted": False,
        "impact": Impact.CRITICAL.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    ".pth": {
        "serialization": "pytorch-pickle",
        "trusted": False,
        "impact": Impact.CRITICAL.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    ".ckpt": {
        "serialization": "checkpoint-pickle",
        "trusted": False,
        "impact": Impact.CRITICAL.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    # `.bin` is a generic extension (firmware, compiled blobs, arbitrary data),
    # not provably a pickle. Legitimate HF/pytorch weights use `pytorch_model.bin`
    # and ARE still flagged, but we do NOT auto-escalate every bare `.bin` to
    # CRITICAL arbitrary-code-execution. Treat as MEDIUM possible-untrusted
    # (same tier as partially-unsafe HDF5/Keras) to avoid false CRITICALs.
    ".bin": {
        "serialization": "pytorch-bin-pickle",
        "trusted": False,
        "impact": Impact.MEDIUM.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    # ----- PARTIALLY-SAFE (HDF5 / Keras — can embed Lambda/custom code) -----
    ".h5": {
        "serialization": "hdf5",
        "trusted": False,
        "impact": Impact.MEDIUM.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    ".keras": {
        "serialization": "keras-zip",
        "trusted": False,
        "impact": Impact.MEDIUM.value,
        "risk_category": AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value,
    },
    # ----- SAFE FORMATS (pure tensor containers; never untrusted) -----
    ".safetensors": {
        "serialization": "safetensors",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
    ".onnx": {
        "serialization": "onnx",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
    ".gguf": {
        "serialization": "gguf",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
    ".ggml": {
        "serialization": "ggml",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
    ".npz": {
        "serialization": "numpy-npz",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
    ".pb": {
        "serialization": "tensorflow-protobuf",
        "trusted": True,
        "impact": Impact.LOW.value,
        "risk_category": AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value,
    },
}

# ---------------------------------------------------------------------------
# AI/ML library import / dependency patterns (python + js/ts).
# Each entry: regex -> metadata. Patterns are matched case-insensitively.
# `name` is the canonical component name; `framework` is the library; `source`
# is the ModelProvider when the import implies a specific provider, else LOCAL.
# ---------------------------------------------------------------------------
AI_LIBRARY_PATTERNS: list[dict] = [
    # ----- ML frameworks -----
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+torch|from\s+torch|require\(\s*['\"]torch['\"]|['\"]torch['\"])",
        "name": "pytorch",
        "component_type": AIComponentType.ML_FRAMEWORK.value,
        "framework": "pytorch",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+tensorflow|from\s+tensorflow|@tensorflow/tfjs|['\"]@tensorflow/tfjs['\"]|['\"]tensorflow['\"])",
        "name": "tensorflow",
        "component_type": AIComponentType.ML_FRAMEWORK.value,
        "framework": "tensorflow",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+transformers|from\s+transformers|@xenova/transformers|['\"]@xenova/transformers['\"]|['\"]transformers['\"])",
        "name": "transformers",
        "component_type": AIComponentType.ML_FRAMEWORK.value,
        "framework": "transformers",
        "source": ModelProvider.HUGGINGFACE.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+diffusers|from\s+diffusers|['\"]diffusers['\"])",
        "name": "diffusers",
        "component_type": AIComponentType.ML_FRAMEWORK.value,
        "framework": "diffusers",
        "source": ModelProvider.HUGGINGFACE.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+vllm|from\s+vllm|['\"]vllm['\"])",
        "name": "vllm",
        "component_type": AIComponentType.ML_FRAMEWORK.value,
        "framework": "vllm",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+sentence_transformers|from\s+sentence_transformers|sentence-transformers)",
        "name": "sentence-transformers",
        "component_type": AIComponentType.EMBEDDING_MODEL.value,
        "framework": "sentence-transformers",
        "source": ModelProvider.HUGGINGFACE.value,
    },
    # ----- AI / agent frameworks -----
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+langchain|from\s+langchain|@langchain/|['\"]langchain['\"]|['\"]@langchain/[\w-]+['\"])",
        "name": "langchain",
        "component_type": AIComponentType.AI_FRAMEWORK.value,
        "framework": "langchain",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+llama_index|from\s+llama_index|llama-index|['\"]llamaindex['\"])",
        "name": "llama-index",
        "component_type": AIComponentType.AI_FRAMEWORK.value,
        "framework": "llama-index",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+haystack|from\s+haystack|['\"]haystack['\"])",
        "name": "haystack",
        "component_type": AIComponentType.AI_FRAMEWORK.value,
        "framework": "haystack",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+autogen|from\s+autogen|['\"]autogen['\"])",
        "name": "autogen",
        "component_type": AIComponentType.AI_FRAMEWORK.value,
        "framework": "autogen",
        "source": ModelProvider.LOCAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+crewai|from\s+crewai|['\"]crewai['\"])",
        "name": "crewai",
        "component_type": AIComponentType.AI_FRAMEWORK.value,
        "framework": "crewai",
        "source": ModelProvider.LOCAL.value,
    },
    # ----- External provider SDKs -----
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+openai|from\s+openai|require\(\s*['\"]openai['\"]|from\s+['\"]openai['\"]|['\"]openai['\"])",
        "name": "openai-sdk",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "openai-sdk",
        "source": ModelProvider.OPENAI.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+anthropic|from\s+anthropic|@anthropic-ai/sdk|from\s+['\"]@anthropic-ai/sdk['\"]|['\"]anthropic['\"]|['\"]@anthropic-ai/[\w-]+['\"])",
        "name": "anthropic-sdk",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "anthropic-sdk",
        "source": ModelProvider.ANTHROPIC.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+cohere|from\s+cohere|['\"]cohere-ai['\"]|['\"]cohere['\"])",
        "name": "cohere-sdk",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "cohere-sdk",
        "source": ModelProvider.COHERE.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+mistralai|from\s+mistralai|@mistralai/mistralai|['\"]@mistralai/mistralai['\"]|['\"]mistralai['\"])",
        "name": "mistral-sdk",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "mistral-sdk",
        "source": ModelProvider.MISTRAL.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:bedrock-runtime|['\"]bedrock-runtime['\"]|BedrockRuntime|boto3\.client\(\s*['\"]bedrock)",
        "name": "aws-bedrock",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "boto3-bedrock",
        "source": ModelProvider.BEDROCK.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+vertexai|from\s+vertexai|from\s+google\.cloud\s+import\s+aiplatform|google\.cloud\.aiplatform|['\"]@google-cloud/aiplatform['\"])",
        "name": "google-vertex",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "vertexai",
        "source": ModelProvider.VERTEX.value,
    },
    {
        "pattern": r"(?:^|[^\w.])(?:import\s+huggingface_hub|from\s+huggingface_hub|@huggingface/inference|['\"]@huggingface/inference['\"]|['\"]huggingface_hub['\"])",
        "name": "huggingface-hub",
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "huggingface_hub",
        "source": ModelProvider.HUGGINGFACE.value,
    },
]

# ---------------------------------------------------------------------------
# Provider call patterns — capture the model literal and decide pinned vs
# unpinned. Pinned heuristic (computed in source_scanner via is_model_pinned):
#   - trailing date snapshot   -YYYY-MM-DD  or  -YYYYMMDD
#   - HF revision pin          revision="<40-hex-sha>"  or  @<sha>
# Otherwise the reference is treated as unpinned (a floating alias such as
# "gpt-4o", "claude-3-5-sonnet-latest", etc.).
#
# Each entry: regex with a named group `model` capturing the model literal.
# ---------------------------------------------------------------------------
PROVIDER_CALL_PATTERNS: list[dict] = [
    # OpenAI chat.completions / responses
    {
        "pattern": r"(?:chat\.completions\.create|responses\.create|chat\.completions|ChatCompletion\.create)\s*\([^)]*?\bmodel\s*=\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.OPENAI.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "openai-sdk",
    },
    {
        "pattern": r"(?:chat\.completions\.create|responses\.create)\s*\(\s*\{[^}]*?\bmodel\s*:\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.OPENAI.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "openai-sdk",
    },
    # Anthropic messages.create
    {
        "pattern": r"(?:messages\.create|messages\.stream)\s*\([^)]*?\bmodel\s*=\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.ANTHROPIC.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "anthropic-sdk",
    },
    {
        "pattern": r"(?:messages\.create|messages\.stream)\s*\(\s*\{[^}]*?\bmodel\s*:\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.ANTHROPIC.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "anthropic-sdk",
    },
    # AWS Bedrock invoke_model / converse (modelId=...)
    {
        "pattern": r"(?:invoke_model|invoke_model_with_response_stream|converse|converse_stream)\s*\([^)]*?\bmodelId\s*=\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.BEDROCK.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "boto3-bedrock",
    },
    {
        "pattern": r"(?:InvokeModelCommand|ConverseCommand)\s*\(\s*\{[^}]*?\bmodelId\s*:\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.BEDROCK.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "bedrock-sdk",
    },
    # Cohere
    {
        "pattern": r"(?:co\.chat|cohere\.[\w.]+|client\.chat)\s*\([^)]*?\bmodel\s*=\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.COHERE.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "cohere-sdk",
    },
    # Mistral
    {
        "pattern": r"(?:client\.chat\.complete|mistral\.[\w.]+|chat\.complete)\s*\([^)]*?\bmodel\s*=\s*['\"](?P<model>[\w.\-:/]+)['\"]",
        "source": ModelProvider.MISTRAL.value,
        "component_type": AIComponentType.EXTERNAL_PROVIDER.value,
        "framework": "mistral-sdk",
    },
    # Hugging Face transformers from_pretrained / pipeline
    {
        "pattern": r"(?:AutoModel(?:[A-Za-z]*)?|AutoTokenizer|AutoConfig|AutoFeatureExtractor|AutoProcessor)\.from_pretrained\s*\(\s*['\"](?P<model>[\w.\-/]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.HUGGINGFACE_MODEL.value,
        "framework": "transformers",
    },
    {
        "pattern": r"pipeline\s*\([^)]*?\bmodel\s*=\s*['\"](?P<model>[\w.\-/]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.HUGGINGFACE_MODEL.value,
        "framework": "transformers",
    },
]

# ---------------------------------------------------------------------------
# Hugging Face hub references — from_pretrained("org/name") / hub repo-ids.
# These map to huggingface_model components. The captured group `model` is an
# org/name repo id (must contain a single slash).
# ---------------------------------------------------------------------------
HF_PATTERNS: list[dict] = [
    {
        "pattern": r"\.from_pretrained\s*\(\s*['\"](?P<model>[\w.\-]+/[\w.\-]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.HUGGINGFACE_MODEL.value,
        "framework": "transformers",
    },
    {
        "pattern": r"(?:hf_hub_download|snapshot_download|hub_download)\s*\([^)]*?\brepo_id\s*=\s*['\"](?P<model>[\w.\-]+/[\w.\-]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.HUGGINGFACE_MODEL.value,
        "framework": "huggingface_hub",
    },
    {
        "pattern": r"SentenceTransformer\s*\(\s*['\"](?P<model>[\w.\-]+/[\w.\-]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.EMBEDDING_MODEL.value,
        "framework": "sentence-transformers",
    },
]

# ---------------------------------------------------------------------------
# Dataset markers — load_dataset(...), DVC manifests, data manifest filenames.
# ---------------------------------------------------------------------------
DATASET_PATTERNS: list[dict] = [
    {
        "pattern": r"(?:datasets\.)?load_dataset\s*\(\s*['\"](?P<model>[\w.\-/]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.DATASET.value,
        "framework": "datasets",
    },
    {
        "pattern": r"load_dataset_builder\s*\(\s*['\"](?P<model>[\w.\-/]+)['\"]",
        "source": ModelProvider.HUGGINGFACE.value,
        "component_type": AIComponentType.DATASET.value,
        "framework": "datasets",
    },
]

# Dataset-related filenames (matched against basename, case-insensitive).
# NOTE: bare `manifest.json` and `data.yaml` were removed — they are ubiquitous
# non-AI files (PWA/npm/extension manifests, generic config) and produced
# spurious HIGH dataset/privacy findings. Only dataset-SPECIFIC basenames are
# kept; AI datasets typically ship a `data_manifest.json` / `dataset.*` /
# `datacard.md` / DVC file, all of which are retained below.
DATASET_FILE_MARKERS: set[str] = {
    "dvc.yaml",
    "dvc.lock",
    "dataset.yaml",
    "dataset.json",
    "data_manifest.json",
    "datacard.md",
    "dataset_card.md",
}
# Dataset-related file extensions (matched against extension, case-insensitive).
DATASET_FILE_EXTENSIONS: set[str] = {".dvc"}

# ---------------------------------------------------------------------------
# Prompt-asset markers — filename heuristics + content heuristics.
# ---------------------------------------------------------------------------
# Filenames that strongly indicate a prompt asset (basename, lowercased).
# NOTE: these are SUBSTRING-matched against the file stem (source_scanner
# `_is_prompt_path`). The bare singular/plural `agent`/`agents` markers were
# removed because they fire on ubiquitous non-prompt files (user_agent,
# useragent, agent_pool, http_agent, useragents, ...). Genuine `agents/`
# directories are still covered by PROMPT_DIR_MARKERS below. Only strongly
# prompt-indicative `prompt`-based stems are kept.
PROMPT_FILE_NAME_MARKERS: tuple[str, ...] = (
    "system_prompt",
    "systemprompt",
    "prompt",
    "prompts",
)
# Extensions that indicate a prompt asset.
PROMPT_FILE_EXTENSIONS: set[str] = {".prompt"}
# Directory names whose contents are treated as prompt assets.
PROMPT_DIR_MARKERS: set[str] = {"prompts", "agents"}
# Content heuristics — a line/file containing any of these is likely a prompt.
PROMPT_CONTENT_MARKERS: tuple[str, ...] = (
    "you are a",
    "you are an",
    "your task is",
    "act as a",
    "act as an",
    "system prompt",
    "###  instruction",
    "### instruction",
)

# ---------------------------------------------------------------------------
# AI risk category rules -> impact + OWASP Top 10 for LLM + suggested fix.
# OWASP member names are REAL members of OWASPTop10LLM in enums.py:
#   SUPPLY_CHAIN_VULNERABILITIES (LLM05), INSECURE_OUTPUT_HANDLING (LLM02),
#   TRAINING_DATA_POISONING (LLM03), SENSITIVE_INFORMATION_DISCLOSURE (LLM06),
#   MODEL_THEFT (LLM10).
# ---------------------------------------------------------------------------
AI_RISK_RULES: dict[str, dict] = {
    AIRiskCategory.UNTRUSTED_MODEL_DESERIALIZATION.value: {
        "impact": Impact.CRITICAL.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SUPPLY_CHAIN_VULNERABILITIES.name,
            OWASPTop10LLM.INSECURE_OUTPUT_HANDLING.name,
        ],
        "suggested_fix": (
            "Do not load pickle-based model weights (.pkl/.joblib/.pt/.pth/.ckpt/.bin) "
            "from untrusted sources. Migrate to the .safetensors format, verify a "
            "cryptographic checksum/signature before loading, and load inside a "
            "sandboxed, least-privilege environment with no network egress."
        ),
    },
    AIRiskCategory.UNPINNED_MODEL_VERSION.value: {
        "impact": Impact.MEDIUM.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SUPPLY_CHAIN_VULNERABILITIES.name,
        ],
        "suggested_fix": (
            "Pin the model to an immutable version. For hosted providers use a dated "
            "snapshot (e.g. gpt-4o-2024-08-06) instead of a floating alias; for Hugging "
            "Face pin a commit revision (revision='<sha>') rather than the branch HEAD."
        ),
    },
    AIRiskCategory.DEPRECATED_EOL_MODEL.value: {
        "impact": Impact.HIGH.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SUPPLY_CHAIN_VULNERABILITIES.name,
        ],
        "suggested_fix": (
            "Migrate off the deprecated / end-of-life model to a currently supported "
            "version. EOL models stop receiving safety, security, and quality updates "
            "and may be retired without notice, breaking production."
        ),
    },
    AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value: {
        "impact": Impact.LOW.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SUPPLY_CHAIN_VULNERABILITIES.name,
            OWASPTop10LLM.TRAINING_DATA_POISONING.name,
        ],
        "suggested_fix": (
            "Record provenance for every model artifact: source repository, version/SHA, "
            "training-data lineage, intended use, and a linked model card. Track these in "
            "the AI-BOM so supply-chain and licensing risk can be evaluated."
        ),
    },
    AIRiskCategory.LICENSE_COMPLIANCE_GAP.value: {
        "impact": Impact.MEDIUM.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SUPPLY_CHAIN_VULNERABILITIES.name,
        ],
        "suggested_fix": (
            "Identify and record the model/dataset license and verify its terms permit "
            "your usage (commercial use, redistribution, output ownership). Resolve any "
            "restrictive or unknown licenses before shipping to production."
        ),
    },
    AIRiskCategory.DATA_PRIVACY_TRAINING_CONFIG.value: {
        "impact": Impact.HIGH.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.SENSITIVE_INFORMATION_DISCLOSURE.name,
            OWASPTop10LLM.TRAINING_DATA_POISONING.name,
        ],
        "suggested_fix": (
            "Review training / fine-tuning configuration for privacy leakage: disable "
            "provider training-on-your-data flags, scrub PII from datasets, and confirm "
            "data-residency and retention controls meet GDPR/DPDP obligations."
        ),
    },
    AIRiskCategory.MODEL_THEFT_EXPOSURE.value: {
        "impact": Impact.HIGH.value,
        "owasp_top_10_llm": [
            OWASPTop10LLM.MODEL_THEFT.name,
            OWASPTop10LLM.SENSITIVE_INFORMATION_DISCLOSURE.name,
        ],
        "suggested_fix": (
            "Protect proprietary model weights from exfiltration: store artifacts in "
            "access-controlled, encrypted storage; never commit weights to source "
            "control; and apply rate limiting / query monitoring to inference endpoints."
        ),
    },
}

# ---------------------------------------------------------------------------
# Language detection / content-scan targeting.
# ---------------------------------------------------------------------------
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    # Manifest / config formats that can declare AI deps or prompts.
    ".toml": "manifest",
    ".txt": "manifest",
    ".cfg": "manifest",
    ".yaml": "manifest",
    ".yml": "manifest",
    ".json": "manifest",
    ".md": "prompt",
}

# Which detector groups run for each detected "language" bucket. Source files
# get the full import/provider/HF/dataset sweep; manifests get import/HF/dataset
# (dependency + repo-id detection); prompt/markdown files get prompt heuristics.
LANGUAGE_PATTERNS = {
    "python": ["library", "provider", "hf", "dataset", "prompt"],
    "javascript": ["library", "provider", "hf", "dataset", "prompt"],
    "manifest": ["library", "hf", "dataset"],
    "prompt": ["prompt"],
}

# Directories to skip during the content-regex walk.
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build",
}

# Max file size to content-scan (skip very large files). Model weight files are
# detected by extension only and intentionally bypass this cap.
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


# ---------------------------------------------------------------------------
# Component normalization helpers.
# ---------------------------------------------------------------------------
def normalize_component_name(name: str) -> str:
    """Normalize a raw component / model literal into a stable display name."""
    if not name:
        return "unknown"
    return name.strip().strip("'\"").rstrip("/")


def provider_from_model_literal(model: str) -> str:
    """Best-effort ModelProvider value inference from a bare model literal."""
    m = (model or "").lower()
    if m.startswith("claude") or "anthropic" in m:
        return ModelProvider.ANTHROPIC.value
    if m.startswith(("gpt-", "gpt", "o1", "o3", "text-embedding", "text-davinci")):
        return ModelProvider.OPENAI.value
    if m.startswith("command") or "cohere" in m:
        return ModelProvider.COHERE.value
    if m.startswith(("mistral", "mixtral", "open-mistral", "open-mixtral", "ministral")):
        return ModelProvider.MISTRAL.value
    if "anthropic." in m or "amazon." in m or "meta." in m or "bedrock" in m:
        return ModelProvider.BEDROCK.value
    if "/" in m:
        return ModelProvider.HUGGINGFACE.value
    return ModelProvider.UNKNOWN.value


# Components that, when detected as bare libraries (not provider calls), are
# inventory-only and carry the lineage/licensing residual concern rather than a
# deserialization risk. Used by source_scanner to assign a risk_category.
LIBRARY_RISK_CATEGORY = AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value
