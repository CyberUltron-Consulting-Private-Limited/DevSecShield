"""
Source code scanner for cryptographic usage detection.
Walks directory, detects language, applies regex rules, extracts crypto assets.
"""

import os
import re
from dataclasses import dataclass, field
from rich.console import Console
from helpers.tools.cbom_agent.crypto_rules import (
    LANGUAGE_EXTENSIONS,
    LANGUAGE_PATTERNS,
    WEAK_ALGORITHMS,
    STANDARD_ALGORITHMS,
    ALGORITHM_NORMALIZE,
)

console = Console()

# Max file size to scan (skip very large files)
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", ".svn", "__pycache__", ".tox", ".venv",
    "venv", "env", ".env", "dist", "build", ".next", ".nuxt",
    "target", "vendor", ".cargo", "pkg", "bin", "obj",
}


@dataclass
class CryptoAssetDetection:
    """A single detected cryptographic usage in source code."""
    algorithm_name: str          # Normalized name e.g. "AES-256"
    algorithm_key: str           # Lowercase lookup key e.g. "aes-256"
    algorithm_type: str          # e.g. "symmetric_cipher", "hash"
    crypto_strength: str         # "weak", "moderate", "strong", "quantum_safe"
    key_size: int | None = None
    quantum_safe: bool = False
    location: str = ""           # File path (relative)
    line_number: int = 0
    snippet: str = ""            # The matched line
    language: str = ""
    is_weak: bool = False        # True if in WEAK_ALGORITHMS
    impact: str = "Low"          # Impact level for weak algorithms


def detect_language(filepath: str) -> str | None:
    """Detect language from file extension."""
    _, ext = os.path.splitext(filepath)
    return LANGUAGE_EXTENSIONS.get(ext.lower())


def extract_algorithm_from_match(match_text: str) -> list[str]:
    """
    Extract algorithm names from a regex match.
    Returns lowercase algorithm keys that exist in WEAK_ALGORITHMS or STANDARD_ALGORITHMS.
    """
    algorithms_found = []
    text_lower = match_text.lower()
    
    # Check all known algorithms (iterate in sorted order for determinism)
    all_algos = {**WEAK_ALGORITHMS, **STANDARD_ALGORITHMS}
    for algo_key in sorted(all_algos):
        # Exact substring check (avoid partial matches by checking word boundaries)
        if algo_key in text_lower:
            algorithms_found.append(algo_key)
    
    return algorithms_found


def scan_file(filepath: str, base_dir: str) -> list[CryptoAssetDetection]:
    """Scan a single file for cryptographic usage."""
    detections = []
    
    language = detect_language(filepath)
    if not language:
        return detections
    
    patterns = LANGUAGE_PATTERNS.get(language, [])
    if not patterns:
        return detections
    
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return detections
        
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return detections
    
    relative_path = os.path.relpath(filepath, base_dir)
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    for line_num, line in enumerate(lines, start=1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
            continue
        
        for pattern in compiled_patterns:
            match = pattern.search(line_stripped)
            if match:
                matched_text = match.group(0)
                algo_keys = extract_algorithm_from_match(matched_text)
                
                if not algo_keys:
                    # Generic crypto usage detected but no specific algorithm identified
                    # Still record it as a generic detection
                    algo_keys = _infer_algorithm_from_context(line_stripped, language)
                
                for algo_key in algo_keys:
                    is_weak = algo_key in WEAK_ALGORITHMS
                    algo_info = WEAK_ALGORITHMS.get(algo_key) or STANDARD_ALGORITHMS.get(algo_key, {})
                    
                    normalized_name = ALGORITHM_NORMALIZE.get(algo_key, algo_key.upper())
                    
                    detection = CryptoAssetDetection(
                        algorithm_name=normalized_name,
                        algorithm_key=algo_key,
                        algorithm_type=algo_info.get("type", "hash"),
                        crypto_strength=algo_info.get("strength", "strong"),
                        key_size=algo_info.get("key_size"),
                        quantum_safe=algo_info.get("quantum_safe", False),
                        location=relative_path,
                        line_number=line_num,
                        snippet=line_stripped[:300],  # Truncate long lines
                        language=language,
                        is_weak=is_weak,
                        impact=algo_info.get("impact", "Low") if is_weak else "Low",
                    )
                    detections.append(detection)
                break  # One match per line is sufficient
    
    return detections


def _infer_algorithm_from_context(line: str, language: str) -> list[str]:
    """Try to infer specific algorithms from context clues in the line."""
    line_lower = line.lower()
    inferred = []
    
    # Check for algorithm names mentioned as string literals
    all_algos = {**WEAK_ALGORITHMS, **STANDARD_ALGORITHMS}
    for algo_key in all_algos:
        # Check for quoted algorithm names (common in getInstance calls)
        if f'"{algo_key}"' in line_lower or f"'{algo_key}'" in line_lower:
            inferred.append(algo_key)
    
    # Common string patterns in Java: getInstance("AES/CBC/PKCS5Padding")
    string_match = re.search(r'["\']([A-Za-z0-9_/\-]+)["\']', line)
    if string_match:
        value = string_match.group(1).lower()
        parts = value.split("/")
        for part in parts:
            part_clean = part.strip()
            if part_clean in all_algos:
                if part_clean not in inferred:
                    inferred.append(part_clean)
    
    return inferred


def scan_directory(directory: str) -> list[CryptoAssetDetection]:
    """
    Recursively scan a directory for cryptographic usage across all supported languages.
    Returns deduplicated list of detections.
    """
    all_detections = []
    files_scanned = 0
    
    for root, dirs, files in os.walk(directory):
        # Skip ignored directories and sort for deterministic traversal order
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            language = detect_language(filepath)
            if language:
                files_scanned += 1
                detections = scan_file(filepath, directory)
                all_detections.extend(detections)
    
    console.print(f"CBOM Source Scanner: scanned {files_scanned} files, found {len(all_detections)} crypto usages", style="bold cyan")
    
    # Deduplicate: same algorithm + same file = one detection (keep first occurrence)
    seen = set()
    unique_detections = []
    for d in all_detections:
        key = (d.algorithm_key, d.location)
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)
    
    # Sort for deterministic output order
    unique_detections.sort(key=lambda d: (d.algorithm_key, d.location, d.line_number))

    console.print(f"CBOM Source Scanner: {len(unique_detections)} unique crypto assets after dedup", style="bold cyan")
    return unique_detections
