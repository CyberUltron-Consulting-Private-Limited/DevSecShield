"""
Source code scanner for AI/ML component detection.
Walks directory, detects language, applies regex rules for imports / provider
calls / Hugging Face references / datasets / prompts, plus an extension-only
pass for local model weight files.
"""

import os
import re
from dataclasses import dataclass
from rich.console import Console

from helpers.tools.ai_bom_agent.ai_rules import (
    LANGUAGE_EXTENSIONS,
    LANGUAGE_PATTERNS,
    AI_LIBRARY_PATTERNS,
    PROVIDER_CALL_PATTERNS,
    HF_PATTERNS,
    DATASET_PATTERNS,
    DATASET_FILE_MARKERS,
    DATASET_FILE_EXTENSIONS,
    PROMPT_FILE_NAME_MARKERS,
    PROMPT_FILE_EXTENSIONS,
    PROMPT_DIR_MARKERS,
    PROMPT_CONTENT_MARKERS,
    MODEL_FILE_EXTENSIONS,
    AI_RISK_RULES,
    LIBRARY_RISK_CATEGORY,
    SKIP_DIRS,
    MAX_FILE_SIZE,
    normalize_component_name,
    provider_from_model_literal,
)
from helpers.context.enums import AIComponentType, AIRiskCategory, ModelProvider

console = Console()


@dataclass
class AIComponentDetection:
    """A single detected AI/ML component usage in source code or on disk."""
    component_name: str
    component_type: str          # AIComponentType value
    framework: str | None = None
    version: str | None = None
    source: str = ModelProvider.UNKNOWN.value   # ModelProvider value
    license: str | None = None
    location: str = ""           # File path (relative)
    snippet: str = ""            # The matched line / evidence
    language: str = ""
    risk_category: str = AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value


# Pinned heuristics: dated snapshot suffix or HF commit revision.
_DATE_SNAPSHOT_RE = re.compile(r"-(?:\d{4}-\d{2}-\d{2}|\d{8})(?:[^\w]|$)")
_HF_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
_HF_AT_SHA_RE = re.compile(r"@[0-9a-f]{7,40}\b")


def is_model_pinned(line: str, model_literal: str) -> bool:
    """Decide whether a provider/model reference is pinned to an immutable version."""
    literal = (model_literal or "")
    # Hosted-provider dated snapshot, e.g. gpt-4o-2024-08-06 / claude-3-5-sonnet-20241022
    if _DATE_SNAPSHOT_RE.search(literal):
        return True
    # HF revision pin via revision="<sha>" or @<sha> on the same line.
    if "revision" in line and (_HF_SHA_RE.search(line) or _HF_AT_SHA_RE.search(line)):
        return True
    if "@" in literal and _HF_AT_SHA_RE.search("@" + literal.split("@", 1)[-1]):
        return True
    return False


def detect_language(filepath: str) -> str | None:
    """Detect content-scan language bucket from file extension or known basename."""
    base = os.path.basename(filepath).lower()
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()

    if ext in PROMPT_FILE_EXTENSIONS:
        return "prompt"
    if base in DATASET_FILE_MARKERS or ext in DATASET_FILE_EXTENSIONS:
        return "manifest"
    return LANGUAGE_EXTENSIONS.get(ext)


def _is_prompt_path(filepath: str, base_dir: str) -> bool:
    """Filename / directory heuristics for prompt assets."""
    rel = os.path.relpath(filepath, base_dir).lower()
    base = os.path.basename(filepath).lower()
    stem, ext = os.path.splitext(base)

    if ext in PROMPT_FILE_EXTENSIONS:
        return True
    parts = set(rel.replace("\\", "/").split("/"))
    if parts & PROMPT_DIR_MARKERS:
        return True
    for marker in PROMPT_FILE_NAME_MARKERS:
        if marker in stem:
            return True
    return False


def _detect_libraries(line: str, relative_path: str, language: str) -> list[AIComponentDetection]:
    out = []
    for rule in AI_LIBRARY_PATTERNS:
        if re.search(rule["pattern"], line, re.IGNORECASE):
            out.append(AIComponentDetection(
                component_name=rule["name"],
                component_type=rule["component_type"],
                framework=rule.get("framework"),
                source=rule.get("source", ModelProvider.LOCAL.value),
                location=relative_path,
                snippet=line[:300],
                language=language,
                risk_category=LIBRARY_RISK_CATEGORY,
            ))
    return out


def _detect_providers(line: str, relative_path: str, language: str) -> list[AIComponentDetection]:
    out = []
    for rule in PROVIDER_CALL_PATTERNS:
        m = re.search(rule["pattern"], line, re.IGNORECASE)
        if not m:
            continue
        model_literal = normalize_component_name(m.group("model"))
        pinned = is_model_pinned(line, model_literal)
        risk = (
            AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value
            if pinned
            else AIRiskCategory.UNPINNED_MODEL_VERSION.value
        )
        out.append(AIComponentDetection(
            component_name=model_literal,
            component_type=rule["component_type"],
            framework=rule.get("framework"),
            source=rule.get("source", ModelProvider.UNKNOWN.value),
            location=relative_path,
            snippet=line[:300],
            language=language,
            risk_category=risk,
        ))
    return out


def _detect_hf(line: str, relative_path: str, language: str) -> list[AIComponentDetection]:
    out = []
    for rule in HF_PATTERNS:
        m = re.search(rule["pattern"], line, re.IGNORECASE)
        if not m:
            continue
        model_literal = normalize_component_name(m.group("model"))
        pinned = is_model_pinned(line, model_literal)
        risk = (
            AIRiskCategory.MISSING_MODEL_CARD_LINEAGE.value
            if pinned
            else AIRiskCategory.UNPINNED_MODEL_VERSION.value
        )
        out.append(AIComponentDetection(
            component_name=model_literal,
            component_type=rule["component_type"],
            framework=rule.get("framework"),
            source=rule.get("source", ModelProvider.HUGGINGFACE.value),
            location=relative_path,
            snippet=line[:300],
            language=language,
            risk_category=risk,
        ))
    return out


def _detect_datasets(line: str, relative_path: str, language: str) -> list[AIComponentDetection]:
    out = []
    for rule in DATASET_PATTERNS:
        m = re.search(rule["pattern"], line, re.IGNORECASE)
        if not m:
            continue
        model_literal = normalize_component_name(m.group("model"))
        out.append(AIComponentDetection(
            component_name=model_literal,
            component_type=rule["component_type"],
            framework=rule.get("framework"),
            source=rule.get("source", ModelProvider.HUGGINGFACE.value),
            location=relative_path,
            snippet=line[:300],
            language=language,
            risk_category=AIRiskCategory.DATA_PRIVACY_TRAINING_CONFIG.value,
        ))
    return out


def _detect_prompt_content(line: str) -> bool:
    low = line.lower()
    return any(marker in low for marker in PROMPT_CONTENT_MARKERS)


def scan_file(filepath: str, base_dir: str) -> list[AIComponentDetection]:
    """Content-scan a single file for AI/ML component usage."""
    detections: list[AIComponentDetection] = []

    language = detect_language(filepath)
    if not language:
        return detections

    groups = LANGUAGE_PATTERNS.get(language, [])
    if not groups:
        return detections

    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return detections
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return detections

    relative_path = os.path.relpath(filepath, base_dir)

    # Dataset manifest filenames are themselves a dataset asset.
    base_lower = os.path.basename(filepath).lower()
    _, ext_lower = os.path.splitext(base_lower)
    if base_lower in DATASET_FILE_MARKERS or ext_lower in DATASET_FILE_EXTENSIONS:
        detections.append(AIComponentDetection(
            component_name=os.path.basename(filepath),
            component_type=AIComponentType.DATASET.value,
            framework="dvc" if ext_lower in DATASET_FILE_EXTENSIONS or "dvc" in base_lower else "manifest",
            source=ModelProvider.LOCAL.value,
            location=relative_path,
            snippet=f"Dataset manifest file: {os.path.basename(filepath)}",
            language=language,
            risk_category=AIRiskCategory.DATA_PRIVACY_TRAINING_CONFIG.value,
        ))

    prompt_path = "prompt" in groups and _is_prompt_path(filepath, base_dir)
    prompt_recorded = False

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        if "library" in groups:
            detections.extend(_detect_libraries(line_stripped, relative_path, language))
        if "provider" in groups:
            detections.extend(_detect_providers(line_stripped, relative_path, language))
        if "hf" in groups:
            detections.extend(_detect_hf(line_stripped, relative_path, language))
        if "dataset" in groups:
            detections.extend(_detect_datasets(line_stripped, relative_path, language))

        if "prompt" in groups and not prompt_recorded:
            if prompt_path or _detect_prompt_content(line_stripped):
                detections.append(AIComponentDetection(
                    component_name=os.path.basename(filepath),
                    component_type=AIComponentType.PROMPT_ASSET.value,
                    framework="prompt",
                    source=ModelProvider.LOCAL.value,
                    location=relative_path,
                    snippet=line_stripped[:300],
                    language=language,
                    risk_category=AIRiskCategory.DATA_PRIVACY_TRAINING_CONFIG.value,
                ))
                prompt_recorded = True

    return detections


def scan_model_file(filepath: str, base_dir: str) -> AIComponentDetection | None:
    """Extension-only detection for a local model weight file (no content read)."""
    _, ext = os.path.splitext(filepath)
    info = MODEL_FILE_EXTENSIONS.get(ext.lower())
    if not info:
        return None

    relative_path = os.path.relpath(filepath, base_dir)
    serialization = info["serialization"]
    trusted = info["trusted"]
    size_note = ""
    try:
        size_bytes = os.path.getsize(filepath)
        size_note = f" ({size_bytes} bytes)"
    except OSError:
        pass

    trust_word = "SAFE" if trusted else "UNSAFE-deserialization"
    return AIComponentDetection(
        component_name=os.path.basename(filepath),
        component_type=AIComponentType.LOCAL_MODEL_FILE.value,
        framework=serialization,
        source=ModelProvider.LOCAL.value,
        location=relative_path,
        snippet=f"Local model weight file [{serialization}, {trust_word}]{size_note}: {os.path.basename(filepath)}",
        language="binary",
        risk_category=info["risk_category"],
    )


def scan_directory(directory: str) -> list[AIComponentDetection]:
    """
    Recursively scan a directory for AI/ML components.

    Two passes over a single deterministic os.walk:
      (a) content-regex pass over scannable source/manifest/prompt files
          (respects MAX_FILE_SIZE + SKIP_DIRS);
      (b) extension-only model-weight pass (no content read, no 2MB cap, and no
          model-dir skipping — weights are large and often live in skipped dirs
          like build/).
    Deduplicated by (component_name, location) and sorted for determinism.
    """
    all_detections: list[AIComponentDetection] = []
    content_files = 0
    model_files = 0

    for root, dirs, files in os.walk(directory):
        # Deterministic traversal. We still descend into SKIP_DIRS for the
        # extension-only model pass, but only content-scan non-skipped paths.
        dirs[:] = sorted(dirs)
        in_skipped = any(part in SKIP_DIRS for part in os.path.relpath(root, directory).split(os.sep))

        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            if os.path.islink(filepath):
                continue

            # (b) Model weight files — always considered, even in skipped dirs.
            model_detection = scan_model_file(filepath, directory)
            if model_detection:
                model_files += 1
                all_detections.append(model_detection)
                continue

            # (a) Content scan — only outside skipped dirs.
            if in_skipped:
                continue
            if detect_language(filepath):
                content_files += 1
                all_detections.extend(scan_file(filepath, directory))

    console.print(
        f"AI-BOM Source Scanner: scanned {content_files} source/manifest files and "
        f"{model_files} model files, found {len(all_detections)} raw detections",
        style="bold cyan",
    )

    # Deduplicate: same component + same file = one detection (keep first).
    seen = set()
    unique_detections: list[AIComponentDetection] = []
    for d in all_detections:
        key = (d.component_name, d.location)
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)

    # Sort for deterministic output order.
    unique_detections.sort(
        key=lambda d: (d.component_name, d.location, d.component_type, d.source)
    )

    console.print(
        f"AI-BOM Source Scanner: {len(unique_detections)} unique AI components after dedup",
        style="bold cyan",
    )
    return unique_detections
