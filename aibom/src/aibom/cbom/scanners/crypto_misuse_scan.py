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

from aibom.cbom.files import FileWalk, file_walk
from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.project import project_index
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import source_language
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

# Cipher primitives an IV / key secures — used to attach the `used_by` edge.
_CIPHER_PRIMITIVES = frozenset({"block-cipher", "stream-cipher"})


def _slug(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _iter_source_files(walk: FileWalk) -> list[Path]:
    return walk.files(lambda p: source_language(p) is not None)


@cbom_register
class CryptoMisuseScanner(Scanner):
    name = "crypto_misuse"
    order = 25
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        project = project_index(ctx)
        for path in _iter_source_files(walk):
            rel = walk.rel(path)
            text = walk.read_text(path)
            if text is None:
                continue
            lang = source_language(path)
            cipher_refs = self._cipher_refs_in(ctx, rel)

            def lookup(key: str, file_name: str | None, _rel: str = rel):
                return project.config_value(key, near=_rel, file_name=file_name)

            for fact in detect_material_misuse(text, lang, lookup):
                ref = self._emit(ctx, fact, rel, cipher_refs)
                if fact.derived_with:
                    self._mark_derived(ctx, rel, text, lang, fact, ref)

    @staticmethod
    def _mark_derived(ctx: ScanContext, rel: str, text: str, lang: str, fact, material_ref: str) -> None:
        """The hash a hardcoded key is derived through (``MD5(constant)``) is that key's derivation, not a usage
        of its own: when it is the file's only use of that hash, its row says so (``crypto:derived``) and carries
        no finding; the key row carries the finding."""
        from aibom.cbom.detect import detect_crypto
        from aibom.cbom.rules import ALGORITHM_NORMALIZE

        lines = {d.line_no for d in detect_crypto(text, lang)
                 if ALGORITHM_NORMALIZE.get(d.key, d.key.upper()) == fact.derived_with}
        if lines - {fact.line}:
            return
        for c in ctx.components:
            props = c.properties or {}
            if c.kind == "crypto_asset" and props.get("discovery:source") == rel and \
                    props.get("crypto:assetType") == "algorithm" and c.name == fact.derived_with:
                c.properties = {**props, "crypto:derived": "true", "crypto:derivedFrom": material_ref}

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
    ) -> str:
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
        if getattr(fact, "derived_with", None):
            props["crypto:derivedWith"] = fact.derived_with
        if getattr(fact, "defined_at", None):
            props["crypto:definedAt"] = fact.defined_at
        name = f"{fact.kind} ({var}, {Path(rel).name})"
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=name, properties=props)
        )
        # Link the misused material to the cipher(s) it secures in this file.
        for cipher_ref in cipher_refs:
            ctx.add_edge(ref, "used_by", cipher_ref)
        return ref


__all__ = ["CryptoMisuseScanner"]
