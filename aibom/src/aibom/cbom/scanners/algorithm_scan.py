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

from aibom.cbom.detect import detect_crypto
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    CRYPTO_IMPORT_MODULES,
    CRYPTO_IMPORT_MODULES_BY_LANG,
    CRYPTO_LIBRARY_PACKAGES,
    LANGUAGE_EXTENSIONS,
    algo_info,
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

# Detection of concrete crypto-API usage (receiver+method+arg-role rule model,
# data-flow-lite symbol table, and the literal-token recall lane) lives in the
# clean-room detection module :mod:`aibom.cbom.detect`. This scanner turns the
# facts it returns into ``crypto_asset`` components.

_IMPORT_RE = re.compile(
    r"^\s*(?:import|from|require|use|using|#include|require_once)\b", re.I
)


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
    __slots__ = ("key", "name", "key_size", "mode", "curve", "padding", "info",
                 "location")

    def __init__(self, key, name, key_size, mode, curve, padding, info, location):
        self.key = key
        self.name = name
        self.key_size = key_size
        self.mode = mode
        self.curve = curve
        self.padding = padding
        self.info = info
        self.location = location


def _detect_assets(root: Path) -> list[_Asset]:
    """Detect concrete algorithm usages (one per distinct name+file).

    Detection facts come from the clean-room :func:`detect_crypto` rule engine
    (receiver+method+arg-roles + data-flow-lite symbol table + literal lane); this
    turns each fact into an inventoried asset, folding an explicit key size / mode
    into the display name so RSA-2048 vs RSA-1024 and AES-GCM vs AES-ECB separate.
    """
    seen: dict[tuple[str, str], _Asset] = {}
    for path in _iter_source_files(root):
        lang = LANGUAGE_EXTENSIONS[path.suffix.lower()]
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for det in detect_crypto(text, lang):
            refined = _refine_key(det.key, det.key_size)
            info = algo_info(refined) or {}
            resolved_ks = det.key_size or info.get("key_size")
            name = _display_name(refined, det.key_size, det.mode)
            ident = (name, rel)
            if ident not in seen:
                seen[ident] = _Asset(
                    refined, name, resolved_ks, det.mode, det.curve,
                    det.padding, info, rel
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
        lang = LANGUAGE_EXTENSIONS[path.suffix.lower()]
        # Node's ``crypto`` and C's ``openssl`` roots collide with the Python keys,
        # so JS/C/Rust/.NET files use a language-scoped map; Python/Go/Java (whose
        # roots are distinctive) fall back to the global one (C3).
        modules = CRYPTO_IMPORT_MODULES_BY_LANG.get(lang, CRYPTO_IMPORT_MODULES)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not _IMPORT_RE.search(line):
                continue
            low = line.lower()
            for module, label in modules.items():
                # The lookbehind rejects a preceding "." / "/" so a generic root
                # (e.g. the Python "crypto" key for ``from Crypto import AES``) can
                # NOT match across a package path — ``javax.crypto`` / ``crypto/aes``
                # only match their own explicit multi-segment keys (C2).
                if re.search(rf"(?<![a-z0-9_./]){re.escape(module)}(?![a-z0-9_])", low):
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
            ctx.add_component(
                FrameworkComponent(
                    bom_ref=f"crypto-lib-{_slug(label)}",
                    name=label,
                    properties={"crypto:role": "library", "discovery:source": src},
                )
            )

        for asset in _detect_assets(ctx.root):
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
            if asset.padding:
                props["crypto:padding"] = asset.padding
            ctx.add_component(
                CryptoAssetComponent(
                    bom_ref=f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}",
                    name=asset.name,
                    properties=props,
                )
            )


__all__ = ["CryptoAlgorithmScanner"]
