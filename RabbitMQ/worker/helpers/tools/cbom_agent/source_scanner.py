"""
Source code scanner for cryptographic usage detection.
Walks directory, detects language, applies regex rules, extracts crypto assets.
"""

import os
import re
from dataclasses import dataclass
from rich.console import Console
from helpers.tools.cbom_agent.crypto_rules import (
    LANGUAGE_EXTENSIONS,
    LANGUAGE_PATTERNS,
    WEAK_ALGORITHMS,
    STANDARD_ALGORITHMS,
    ALGORITHM_NORMALIZE,
    LITERAL_ALGO_ALIASES,
    JWT_ALG_MAP,
    GENERIC_API_FALLBACKS,
    GENERIC_LANG_FALLBACK,
    CRYPTO_CONTEXT_HINTS,
    CRYPTO_METHOD_HINTS,
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




_SHA_NUM_RE = re.compile(r"(sha)[-_]?(\d)")
_AES_RSA_TLS_NUM_RE = re.compile(r"(aes|rsa|tls)[-_]?(\d)")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_QUOTE_RE = re.compile(r"""["'`]([^"'`]{1,200})["'`]""")
_IMPORT_RE = re.compile(r"^\s*(import|from|require|require_once|include|include_once|use|using|#include)\b", re.I)

# Short tokens that are also common non-crypto identifiers (des=destination, rsa/aes/tls
# as ad-hoc abbreviations, falcon=web framework). These count as crypto ONLY inside a
# quoted algorithm spec, an import statement, or a dotted module call (rsa. / aes.New).
AMBIGUOUS_TOKENS = {"des", "3des", "rsa", "aes", "dsa", "rc2", "rc4", "tls", "ssl", "md4", "falcon", "aeswrap", "rijndael"}


def _line_has_crypto_context(line_lc: str) -> bool:
    """True if the (lowercased) line carries an independent crypto signal.

    Used to disambiguate AMBIGUOUS_TOKENS on import / dotted-call paths: an
    ambiguous token (e.g. 'falcon', 'rsa', 'aes', 'tls') is only mapped to its
    crypto algorithm when the same line also references a recognized crypto
    module/package (CRYPTO_CONTEXT_HINTS) or a recognized crypto operation in a
    dotted call (CRYPTO_METHOD_HINTS). This stops `import falcon` / `falcon.API()`
    (web framework) from inflating quantum_readiness with a phantom PQC FALCON,
    while preserving real crypto like `from cryptography... import rsa`,
    `import "crypto/aes"`, `aes.NewCipher(...)`, and genuine PQC `falcon` from a
    real PQC library (`from pqcrypto.sign import falcon`).
    """
    if any(h in line_lc for h in CRYPTO_CONTEXT_HINTS):
        return True
    # Method hints must appear as a dotted attribute (`.<hint>`), not anywhere in
    # the line, so `aes.NewCipher` / `rsa.GenerateKey` qualify while `falcon.design_view`
    # (contains 'sign') and bare identifiers like 'assign' do not.
    for h in CRYPTO_METHOD_HINTS:
        if ("." + h) in line_lc:
            return True
    return False


def _alias_keys(tok: str) -> list[str]:
    """Resolve a single normalized token to canonical algorithm key(s)."""
    if tok in JWT_ALG_MAP:
        return list(JWT_ALG_MAP[tok])
    if tok in LITERAL_ALGO_ALIASES:
        return [LITERAL_ALGO_ALIASES[tok]]
    if tok.startswith("hmac") and len(tok) > 4:
        keys = ["hmac"]
        rest = tok[4:]
        if rest in LITERAL_ALGO_ALIASES:
            keys.append(LITERAL_ALGO_ALIASES[rest])
        return keys
    if tok.startswith("pbkdf2"):
        keys = ["pbkdf2"]
        if "hmac" in tok:
            keys.append("hmac")
        return keys
    return []


def _match_tokens(text: str, allow_ambiguous: bool, apply_with: bool) -> list[str]:
    t = text.lower()
    t = _SHA_NUM_RE.sub(r"\1\2", t)            # sha-256 -> sha256
    t = _AES_RSA_TLS_NUM_RE.sub(r"\1\2", t)    # aes-256 -> aes256
    if apply_with:
        t = t.replace("with", " ")              # SHA256withRSA -> sha256 rsa (specs only)
    out: list[str] = []
    for tok in _NON_ALNUM_RE.split(t):
        if not tok:
            continue
        if (not allow_ambiguous) and tok in AMBIGUOUS_TOKENS:
            continue
        for k in _alias_keys(tok):
            if k not in out:
                out.append(k)
    return out


def extract_algorithms_safe(line: str) -> list[str]:
    """
    Precise, context-aware WHOLE-TOKEN algorithm extraction from a code line.
    Avoids false positives (e.g. 'des' as a 'destination' variable, 'falcon' web framework,
    'aesWithPadding' identifier) by:
      - extracting all tokens (incl. ambiguous short names) only from quoted algorithm specs
        (no spaces -> not prose) and import/use statements;
      - extracting only unambiguous tokens from bare code;
      - allowing ambiguous short tokens in bare code only when used as a dotted module call
        (e.g. rsa.GenerateKey, aes.NewCipher).
    Handles compounds: 'SHA256withRSA', 'HmacSHA512', 'AES/GCM/NoPadding', JWT alg ids ('RS256').
    """
    found: list[str] = []

    def add(keys: list[str]):
        for k in keys:
            if k not in found:
                found.append(k)

    # Crypto-context gate: ambiguous tokens (falcon/rsa/aes/des/tls/ssl/...) are
    # only honored on the import and dotted-call paths when the line carries an
    # independent crypto signal. This is what stops `import falcon` / `falcon.API()`
    # (web framework) from being mapped to the PQC FALCON algorithm, while keeping
    # `from cryptography... import rsa`, `import "crypto/aes"`, `aes.NewCipher(...)`,
    # and real PQC `from pqcrypto.sign import falcon`.
    low = line.lower()
    low = _SHA_NUM_RE.sub(r"\1\2", low)
    low = _AES_RSA_TLS_NUM_RE.sub(r"\1\2", low)
    has_crypto_ctx = _line_has_crypto_context(low)

    # 1) Quoted algorithm specs (skip space-containing prose/messages) -> all tokens, with-split.
    for m in _QUOTE_RE.finditer(line):
        s = m.group(1)
        if " " in s.strip():
            continue
        add(_match_tokens(s, allow_ambiguous=True, apply_with=True))

    # 2) Import / require / use statements -> tokens; ambiguous ones only with crypto context.
    if _IMPORT_RE.search(line):
        add(_match_tokens(line, allow_ambiguous=has_crypto_ctx, apply_with=False))

    # 3) Bare code -> unambiguous tokens only.
    add(_match_tokens(line, allow_ambiguous=False, apply_with=False))

    # 4) Bare code -> ambiguous short tokens used as a dotted module call,
    #    but only when the line carries an independent crypto signal.
    if has_crypto_ctx:
        for tok in AMBIGUOUS_TOKENS:
            esc = re.escape(tok)
            if re.search(r"(?<![a-z0-9])" + esc + r"\s*\.", low) or re.search(r"\.\s*" + esc + r"(?![a-z0-9])", low):
                add(_alias_keys(tok))

    return found


def _resolve_detection(algo_key, descriptor, relative_path, line_num, snippet, language):
    """Build a CryptoAssetDetection from either a known algo_key or an explicit descriptor."""
    if descriptor is not None:
        algo_key = descriptor["key"]
        is_weak = algo_key in WEAK_ALGORITHMS
        algo_info = WEAK_ALGORITHMS.get(algo_key) or STANDARD_ALGORITHMS.get(algo_key)
        name = descriptor.get("name") or ALGORITHM_NORMALIZE.get(algo_key, algo_key.upper())
        a_type = descriptor.get("type") or (algo_info or {}).get("type", "symmetric_cipher")
        strength = descriptor.get("strength") or (algo_info or {}).get("strength", "moderate")
        quantum_safe = descriptor.get("quantum_safe", (algo_info or {}).get("quantum_safe", False))
        key_size = (algo_info or {}).get("key_size")
        impact = (algo_info or {}).get("impact", "Low") if is_weak else "Low"
    else:
        is_weak = algo_key in WEAK_ALGORITHMS
        algo_info = WEAK_ALGORITHMS.get(algo_key) or STANDARD_ALGORITHMS.get(algo_key, {})
        name = ALGORITHM_NORMALIZE.get(algo_key, algo_key.upper())
        a_type = algo_info.get("type", "hash")
        strength = algo_info.get("strength", "strong")
        quantum_safe = algo_info.get("quantum_safe", False)
        key_size = algo_info.get("key_size")
        impact = algo_info.get("impact", "Low") if is_weak else "Low"
    return CryptoAssetDetection(
        algorithm_name=name,
        algorithm_key=algo_key,
        algorithm_type=a_type,
        crypto_strength=strength,
        key_size=key_size,
        quantum_safe=quantum_safe,
        location=relative_path,
        line_number=line_num,
        snippet=snippet[:300],
        language=language,
        is_weak=is_weak,
        impact=impact,
    )


def scan_file(filepath: str, base_dir: str) -> list[CryptoAssetDetection]:
    """Scan a single file for cryptographic usage."""
    detections = []

    language = detect_language(filepath)
    if not language:
        return detections

    patterns = LANGUAGE_PATTERNS.get(language, [])
    generic_fallbacks = GENERIC_API_FALLBACKS.get(language, [])
    if not patterns and not generic_fallbacks:
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
    compiled_fallbacks = [(re.compile(p, re.IGNORECASE), desc) for p, desc in generic_fallbacks]
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
    lang_fallback = GENERIC_LANG_FALLBACK.get(language)
    c_style = language in ("java", "javascript", "go", "c", "php", "rust")  # /* */ and //
    hash_style = language in ("python", "ruby", "php")                       # trailing #
    in_block_comment = False

    for line_num, line in enumerate(lines, start=1):
        work = line
        # Strip comments so prose mentioning algorithms ("migrated away from DES") is not scanned.
        if c_style:
            if in_block_comment:
                if "*/" in work:
                    work = work.split("*/", 1)[1]
                    in_block_comment = False
                else:
                    continue
            work = re.sub(r"/\*.*?\*/", " ", work)   # inline /* ... */
            if "/*" in work:
                work = work.split("/*", 1)[0]
                in_block_comment = True
            work = re.sub(r"//.*$", "", work)         # trailing // comment
        if hash_style:
            work = re.sub(r"#.*$", "", work)          # trailing # comment

        line_stripped = work.strip()
        if not line_stripped or line_stripped.startswith("*"):
            continue

        # 1) Precise whole-token extraction over the FULL line (imports, calls, literals, registries).
        algo_keys = extract_algorithms_safe(line_stripped)

        if algo_keys:
            for algo_key in algo_keys:
                detections.append(_resolve_detection(algo_key, None, relative_path, line_num, line_stripped, language))
            continue

        # 2) No concrete algorithm on the line: if it is a generic crypto API CALL whose
        #    algorithm is a runtime value (e.g. Cipher.getInstance(name)), inventory it generically.
        #    (Bare imports are intentionally NOT inventoried to avoid noise.)
        matched_generic = False
        for rx, desc in compiled_fallbacks:
            if rx.search(line_stripped):
                detections.append(_resolve_detection(None, desc, relative_path, line_num, line_stripped, language))
                matched_generic = True
                break
        if matched_generic:
            continue

        # 3) Third-tier fallback: a LANGUAGE_PATTERNS rule matched (crypto is present
        #    on this line) but no concrete algorithm and no generic-API descriptor
        #    applied. Inventory it as an unspecified crypto primitive instead of
        #    silently dropping it. Per-file dedup (algorithm_key + location in
        #    scan_directory) collapses repeats to a single asset per file.
        if lang_fallback is not None:
            for rx in compiled_patterns:
                if rx.search(line_stripped):
                    detections.append(_resolve_detection(None, lang_fallback, relative_path, line_num, line_stripped, language))
                    break

    return detections


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
