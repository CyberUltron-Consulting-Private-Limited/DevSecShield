"""CBOM scanner (C6): crypto-material MISUSE emission.

Runs a clean-room source pass (:func:`aibom.cbom.misuse.detect_material_misuse`)
and turns each misuse fact into a ``related-crypto-material`` component whose
``crypto:`` properties record the misuse (``crypto:weakRng`` / ``crypto:staticIv``
/ ``crypto:reused`` / ``crypto:hardcoded`` + ``crypto:generatedBy``). It links
the material to the co-located cipher asset (a ``used_by`` edge) so the CycloneDX
dependency graph reflects "this predictable IV / hardcoded key secures that
cipher".

Lane discipline: this EMITS components + edges only. The pure predicate
:func:`aibom.cbom.weakness.material_misuse_findings` reads the emitted props back
into WEAK_RNG / STATIC_IV / REUSED_NONCE / HARDCODED_KEY flags (raised by the C5
weak-crypto scanner at order 40); the C8 scorer weights them. Order 25 places it
after the algorithm (10) and certificate/material (20) inventory lanes — so the
cipher assets its edges point at already exist — and before the flag phase (40).

By construction it fires ONLY on genuine misuse (a constant-literal or weak-RNG
binding of a crypto-material variable inside a file with a crypto context), so a
strong ``os.urandom``-keyed cipher and a non-crypto ``Math.random()`` raise
nothing.
"""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import LANGUAGE_EXTENSIONS
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

_IGNORE_DIRS = frozenset(
    {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
        "dist", "build", ".next", ".nuxt", "target", "vendor", ".tox",
        ".mypy_cache", ".pytest_cache",
    }
)
_MAX_BYTES = 2_000_000

# Cipher primitives an IV / key secures — used to attach the `used_by` edge.
_CIPHER_PRIMITIVES = frozenset({"block-cipher", "stream-cipher"})


def _slug(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _iter_source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file() or p.suffix.lower() not in LANGUAGE_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


@cbom_register
class CryptoMisuseScanner(Scanner):
    name = "crypto_misuse"
    order = 25
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for path in _iter_source_files(ctx.root):
            rel = path.relative_to(ctx.root).as_posix()
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lang = LANGUAGE_EXTENSIONS[path.suffix.lower()]
            cipher_refs = self._cipher_refs_in(ctx, rel)
            for fact in detect_material_misuse(text, lang):
                self._emit(ctx, fact, rel, cipher_refs)

    @staticmethod
    def _cipher_refs_in(ctx: ScanContext, rel: str) -> list[str]:
        """bom_refs of cipher algorithm assets discovered in the same file."""
        refs = []
        for c in ctx.components:
            if c.kind != "crypto_asset":
                continue
            props = c.properties or {}
            if (
                props.get("crypto:assetType") == "algorithm"
                and props.get("crypto:primitive") in _CIPHER_PRIMITIVES
                and props.get("discovery:source") == rel
            ):
                refs.append(c.bom_ref)
        return sorted(refs)

    def _emit(
        self, ctx: ScanContext, fact, rel: str, cipher_refs: list[str]
    ) -> None:
        var = fact.var or "inline"
        ref = (
            f"crypto-material-misuse-{fact.kind}-{_slug(var)}"
            f"-{_slug(rel)}-l{fact.line}"
        )
        props: dict[str, str] = {
            "crypto:assetType": "related-crypto-material",
            "crypto:materialKind": fact.kind,
            "discovery:source": rel,
        }
        if getattr(fact, "line", None):
            props["crypto:line"] = str(fact.line)
        if fact.weak_rng:
            props["crypto:weakRng"] = "true"
            props["crypto:generatedBy"] = fact.weak_rng
        if fact.hardcoded:
            props["crypto:hardcoded"] = "true"
        if fact.static_iv:
            props["crypto:staticIv"] = "true"
        if fact.reused:
            props["crypto:reused"] = "true"
        name = f"{fact.kind} ({var}, {Path(rel).name})"
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=name, properties=props)
        )
        # Link the misused material to the cipher(s) it secures in this file.
        for cipher_ref in cipher_refs:
            ctx.add_edge(ref, "used_by", cipher_ref)


__all__ = ["CryptoMisuseScanner"]
