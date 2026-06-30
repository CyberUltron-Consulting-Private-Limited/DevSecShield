"""CBOM scanner (C1): crypto **algorithms** + crypto **libraries**.

Reconciled from the worker ``cbom_agent`` (``crypto_rules.py`` /
``source_scanner.py``): it preserves that detection knowledge (the algorithm
strength tables, normalization, multi-language symbols, ambiguous-token gating —
all in :mod:`aibom.cbom.rules`) and ADDS the per-usage **parametrization** the
worker lacked — key size, cipher mode, and curve pulled off the same source line
— so a usage resolves to ``RSA-2048`` vs ``RSA-1024`` and ``AES-GCM`` vs
``AES-ECB`` instead of a flat ``RSA`` / ``AES``.

Emits (lane discipline — EMIT only, never score/flag-weight/serialize):

* one ``crypto_asset`` component per distinct (algorithm, params, file) usage,
  with all crypto detail in ``crypto:`` ``properties`` (assetType=algorithm,
  primitive, keySize, mode, curve, strength, quantumVulnerable);
* one ``framework`` component per detected crypto **library** (declared in
  ``requirements.txt`` or imported), tagged ``crypto:role=library``.

Weak-algorithm FLAGGING is C5; PQC grading is C6; the CycloneDX crypto-asset
serialization is C4. C1 only inventories.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    CRYPTO_IMPORT_MODULES,
    CRYPTO_LIBRARY_PACKAGES,
    LANGUAGE_EXTENSIONS,
    algo_info,
    extract_curve,
    extract_key_size,
    extract_mode,
)
from aibom.model.component import CryptoAssetComponent, FrameworkComponent
from aibom.scan.registry import ScanContext, Scanner

_IGNORE_DIRS = frozenset(
    {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
        "dist", "build", ".next", ".nuxt", "target", "vendor", ".tox",
        ".mypy_cache", ".pytest_cache",
    }
)
_MAX_BYTES = 2_000_000

# --------------------------------------------------------------------------- #
# Concrete crypto-API + literal-name patterns -> canonical algorithm key.
#
# Reconciled from the worker's LANGUAGE_PATTERNS, but each entry names a CONCRETE
# algorithm (not a generic API), so a match resolves directly to an inventoried
# asset. Explicit crypto spellings (pyca ``algorithms.AES``, ``hashlib.sha256``,
# ``rsa.generate_private_key``; Node ``createHash('sha256')``; Java
# ``Cipher.getInstance("AES/GCM/..")``) and parametrized literals (``RSA-2048``,
# ``AES-256``) are detected; bare ambiguous tokens (a lone ``aes`` / ``des``
# identifier) are NOT, to keep precision.
# --------------------------------------------------------------------------- #

_F = re.IGNORECASE
_ALGO_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # --- hashes ---
    ("md5", re.compile(r"\bhashlib\.md5\b|\bMD5\b", _F)),
    ("sha1", re.compile(r"\bhashlib\.sha1\b|\bSHA-?1\b", _F)),
    ("sha256", re.compile(r"\bsha-?256\b", _F)),
    ("sha384", re.compile(r"\bsha-?384\b", _F)),
    ("sha512", re.compile(r"\bsha-?512\b", _F)),
    ("sha3_256", re.compile(r"\bsha3[_-]?256\b", _F)),
    ("blake2b", re.compile(r"\bblake2b\b", _F)),
    ("blake2s", re.compile(r"\bblake2s\b", _F)),
    # --- symmetric ciphers (explicit crypto spellings + parametrized literals) ---
    ("3des", re.compile(r"\bTripleDES\b|\b3DES\b|\bDESede\b|\bMODE_DES3\b", _F)),
    ("des", re.compile(
        r"\balgorithms\.DES\b|\bDES_(?:set_key|ecb|cbc)\b|\bMODE_DES\b", _F)),
    ("rc4", re.compile(r"\bARC4\b|\bRC4\b", _F)),
    ("rc2", re.compile(r"\bRC2\b", _F)),
    ("blowfish", re.compile(r"\bBlowfish\b", _F)),
    ("aes", re.compile(
        r"\balgorithms\.AES\b|\bAESGCM\b|\bAESCCM\b|\bAES-?(?:128|192|256)\b"
        r"|\bAES\b(?=\s*[/(])|getInstance\(\s*['\"]AES", _F)),
    ("chacha20", re.compile(r"\bChaCha20\b", _F)),
    # --- asymmetric / signatures / key agreement ---
    ("rsa", re.compile(
        r"\brsa\.generate_private_key\b|\bRSA\.generate\b|\bRSA-?(?:512|1024|2048|3072|4096)\b"
        r"|\bgenerateKeyPair\(\s*['\"]RSA|\bRSA_generate_key\b", _F)),
    ("ecdsa", re.compile(r"\bECDSA\b|\bec\.derive_private_key\b", _F)),
    ("ed25519", re.compile(r"\bEd25519\b", _F)),
    ("ed448", re.compile(r"\bEd448\b", _F)),
    ("x25519", re.compile(r"\bX25519\b", _F)),
    ("ecdh", re.compile(r"\bECDH\b", _F)),
    ("dh", re.compile(r"\bDiffieHellman\b|\bcreateDiffieHellman\b", _F)),
    ("dsa", re.compile(r"\bDSA\b", _F)),
    # --- KDF / MAC ---
    ("pbkdf2", re.compile(r"\bPBKDF2", _F)),
    ("scrypt", re.compile(r"\bscrypt\b", _F)),
    ("argon2", re.compile(r"\bargon2\b", _F)),
    ("bcrypt", re.compile(r"\bbcrypt\b", _F)),
    ("hkdf", re.compile(r"\bHKDF\b", _F)),
    ("hmac", re.compile(r"\bHMAC\b", _F)),
    # --- PQC ---
    ("kyber", re.compile(r"\bKyber\b|\bML-?KEM\b", _F)),
    ("dilithium", re.compile(r"\bDilithium\b|\bML-?DSA\b", _F)),
    ("sphincs+", re.compile(r"\bSPHINCS\+?\b|\bSLH-?DSA\b", _F)),
)

# Comments / docstrings / prose are never scanned for algorithms — a docstring
# like "STRONG algorithms: RSA-2048, AES-256-GCM, SHA-256" or a comment
# "migrated away from DES" must NOT inventory those algorithms. Triple-quoted
# blocks and C-style /* */ blocks are blanked whole-file (preserving line count);
# trailing # / // comments are stripped per line.
_PY_COMMENT = re.compile(r"#.*$")
_C_LINE_COMMENT = re.compile(r"//.*$")
_TRIPLE_QUOTE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.S)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from|require|use|using|#include|require_once)\b", re.I
)


def _blank(match: re.Match[str]) -> str:
    """Replace a matched span with spaces, preserving newlines (line count)."""
    return re.sub(r"[^\n]", " ", match.group(0))


def _strip_noncode(text: str) -> str:
    """Blank docstrings + block comments so prose is never scanned."""
    text = _TRIPLE_QUOTE.sub(_blank, text)
    text = _BLOCK_COMMENT.sub(_blank, text)
    return text


def _iter_source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix.lower() not in LANGUAGE_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _strip_comment(line: str, lang: str) -> str:
    if lang in ("python", "ruby"):
        return _PY_COMMENT.sub("", line)
    if lang in ("javascript", "java", "go", "c", "rust", "php"):
        return _C_LINE_COMMENT.sub("", line)
    return line


def _refine_key(key: str, key_size: int | None) -> str:
    """Promote a bare ``rsa``/``aes`` to its sized variant when a size is known."""
    if key == "rsa" and key_size in (512, 1024, 2048, 3072, 4096):
        cand = f"rsa-{key_size}"
        if algo_info(cand):
            return cand
    if key == "aes" and key_size in (128, 192, 256):
        cand = f"aes-{key_size}"
        if algo_info(cand):
            return cand
    return key


def _display_name(key: str, explicit_key_size: int | None, mode: str | None) -> str:
    """Build the asset display name. Only a key size found EXPLICITLY on the
    source line is folded into the name (so RSA-2048 vs RSA-1024 separate); a
    table-default size (e.g. 3DES's 168) is NOT, to avoid noisy names."""
    base = ALGORITHM_NORMALIZE.get(key, key.upper())
    if explicit_key_size and not re.search(rf"\b{explicit_key_size}\b", base):
        info = algo_info(key) or {}
        if info.get("primitive") in ("pke", "block-cipher", "stream-cipher"):
            base = f"{base}-{explicit_key_size}"
    if mode and mode.upper() not in base.upper().split("-"):
        return f"{base}-{mode.upper()}"
    return base


class _Asset:
    __slots__ = ("key", "name", "key_size", "mode", "curve", "info", "location")

    def __init__(self, key, name, key_size, mode, curve, info, location):
        self.key = key
        self.name = name
        self.key_size = key_size
        self.mode = mode
        self.curve = curve
        self.info = info
        self.location = location


def _detect_assets(root: Path) -> list[_Asset]:
    """Detect concrete algorithm usages (one per distinct name+file)."""
    seen: dict[tuple[str, str], _Asset] = {}
    for path in _iter_source_files(root):
        lang = LANGUAGE_EXTENSIONS[path.suffix.lower()]
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in _strip_noncode(text).splitlines():
            work = _strip_comment(line, lang).strip()
            if not work or _IMPORT_RE.search(work):
                continue  # imports are LIBRARY signals, handled separately
            explicit_ks = extract_key_size(work)
            mode = extract_mode(work)
            curve = extract_curve(work)
            for key, pat in _ALGO_PATTERNS:
                if not pat.search(work):
                    continue
                refined = _refine_key(key, explicit_ks)
                info = algo_info(refined) or {}
                resolved_ks = explicit_ks or info.get("key_size")
                name = _display_name(refined, explicit_ks, mode)
                ident = (name, rel)
                if ident not in seen:
                    seen[ident] = _Asset(
                        refined, name, resolved_ks, mode, curve, info, rel
                    )
    return sorted(seen.values(), key=lambda a: (a.name, a.location))


def _detect_libraries(root: Path) -> list[tuple[str, str]]:
    """Detect crypto libraries: declared deps + imported modules. -> (label, src)."""
    found: dict[str, str] = {}

    # 1) declared dependencies (requirements.txt / pyproject)
    for req in (*root.rglob("requirements*.txt"), *root.rglob("pyproject.toml")):
        if any(part in _IGNORE_DIRS for part in req.parts):
            continue
        try:
            text = req.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = req.relative_to(root).as_posix()
        for raw in text.splitlines():
            name = re.split(r"[<>=!~;\[\s#]", raw.strip(), maxsplit=1)[0].lower()
            label = CRYPTO_LIBRARY_PACKAGES.get(name)
            if label and label not in found:
                found[label] = rel

    # 2) imported crypto modules in source
    for path in _iter_source_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not _IMPORT_RE.search(line):
                continue
            low = line.lower()
            for module, label in CRYPTO_IMPORT_MODULES.items():
                if re.search(rf"(?<![a-z0-9_]){re.escape(module)}(?![a-z0-9_])", low):
                    found.setdefault(label, rel)
    return sorted(found.items())


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@cbom_register
class CryptoAlgorithmScanner(Scanner):
    name = "crypto_algorithm"
    order = 10
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for label, src in _detect_libraries(ctx.root):
            ref = f"crypto-lib-{_slug(label)}"
            if ctx.has_ref(ref):
                continue
            ctx.add_component(
                FrameworkComponent(
                    bom_ref=ref,
                    name=label,
                    properties={"crypto:role": "library", "discovery:source": src},
                )
            )

        for asset in _detect_assets(ctx.root):
            # The AST scanner (order 8) owns Python algorithm detection with
            # argument binding; defer to any ref it already emitted so the regex
            # pass only adds usages the AST could not see (e.g. an algorithm named
            # in a non-Python file or a string literal). This keeps the emitted
            # inventory duplicate-free *before* the flag/PQC scanners run.
            ast_ref = f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}"
            if ctx.has_ref(ast_ref):
                continue
            props: dict[str, str] = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": asset.info.get("primitive", "unknown"),
                "crypto:strength": asset.info.get("strength", "unknown"),
                "crypto:quantumVulnerable": str(
                    bool(asset.info.get("quantum_vulnerable", False))
                ).lower(),
                "discovery:source": asset.location,
            }
            if asset.key_size:
                props["crypto:keySize"] = str(asset.key_size)
            if asset.mode:
                props["crypto:mode"] = asset.mode
            if asset.curve:
                props["crypto:curve"] = asset.curve
            ctx.add_component(
                CryptoAssetComponent(
                    bom_ref=f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}",
                    name=asset.name,
                    properties=props,
                )
            )


__all__ = ["CryptoAlgorithmScanner"]
