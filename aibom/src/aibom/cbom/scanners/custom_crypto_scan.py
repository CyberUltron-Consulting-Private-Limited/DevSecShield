"""Flag source that embeds well-known cipher or hash constants."""

from __future__ import annotations

from aibom.cbom.custom_crypto import detect_custom_constructions, detect_custom_crypto
from aibom.cbom.files import file_walk
from aibom.cbom.gate import CUSTOM_CRYPTO
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import LANGUAGE_EXTENSIONS
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner


def _slug(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


@cbom_register
class CustomCryptoScanner(Scanner):
    """Private implementations recognized by AES, SHA-256, or MD5 constants."""

    name = "crypto_custom"
    order = 17
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        for path in walk.files(lambda p: p.suffix.lower() in LANGUAGE_EXTENSIONS):
            text = walk.read_text(path)
            if text is None:
                continue
            rel = walk.rel(path)
            found = detect_custom_crypto(text)
            if found is not None:
                kind, display, primitive = found
                self._emit(ctx, rel, kind, display, primitive, None,
                           f"{display} constants appear in {rel} outside a library call "
                           "(CWE-1240). Prefer a maintained cryptographic library.")
            for kind, display, primitive, lines in detect_custom_constructions(text):
                self._emit(ctx, rel, kind, display, primitive, lines,
                           f"{display}: {rel} line {lines[0]} implements its own cipher construction instead "
                           "of calling a library (CWE-327). Use a maintained cryptographic library (AES-GCM).")

    @staticmethod
    def _emit(ctx: ScanContext, rel: str, kind: str, display: str, primitive: str,
              lines: list[int] | None, message: str) -> None:
        ref = f"crypto-custom-{kind}-{_slug(rel)}"
        if ctx.has_ref(ref):
            return
        props = {
            "crypto:assetType": "algorithm",
            "crypto:primitive": primitive,
            "crypto:customImplementation": "true",
            "crypto:source": rel,
            "discovery:source": rel,
        }
        if lines:  # a construction is found at its lines; a constant-recognized one is located later by token
            props["crypto:line"] = str(lines[0])
            props["crypto:occurrences"] = ",".join(str(n) for n in lines[:25])
        ctx.add_component(CryptoAssetComponent(bom_ref=ref, name=display, properties=props))
        ctx.add_flag(CUSTOM_CRYPTO, ref, severity="warning", message=message)
