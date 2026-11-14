"""CBOM scanner (CB-28): .NET, C (OpenSSL) and Terraform line detectors.

The detectors are :mod:`aibom.cbom.lang_misuse`.

Order 26: after the material-misuse lane (25), whose rows on the same line it does not
repeat, and before the flag
phase (40), which raises the findings from the assets emitted here through the existing
predicates: a TLS protocol
asset with its version or cipher list, an RSA algorithm asset with its padding and
operation or key size, and a
related-crypto-material asset for a constant key, a constant IV, a weak iteration count
or RSA exponent 3. Every
asset carries ``crypto:line``, so its finding sits on the line that has the weakness.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.files import file_walk
from aibom.cbom.lang_misuse import (
    C_LANGS,
    DOTNET_LANGS,
    LangFact,
    c_facts,
    dotnet_facts,
    terraform_facts,
)
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import algo_info, source_language
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


@cbom_register
class LangMisuseScanner(Scanner):
    name = "crypto_lang_misuse"
    order = 26
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        taken = {
            (
                p.get("discovery:source"),
                p.get("crypto:line"),
                p.get("crypto:materialKind"),
            )
            for c in ctx.components
            for p in [c.properties or {}]
            if p.get("crypto:assetType") == "related-crypto-material"
        }
        for path in walk.files(
            lambda p: source_language(p) in DOTNET_LANGS | C_LANGS or p.suffix == ".tf"
        ):
            text = walk.read_text(path)
            if text is None:
                continue
            rel = walk.rel(path)
            lang = source_language(path)
            if path.suffix == ".tf":
                facts = terraform_facts(text)
            elif lang in DOTNET_LANGS:
                facts = dotnet_facts(text, lang)
            else:
                facts = c_facts(text, lang or "c")
            for fact in facts:
                asset = self._asset(fact, rel, taken)
                if asset is not None and not ctx.has_ref(asset.bom_ref):
                    ctx.add_component(asset)

    @staticmethod
    def _asset(fact: LangFact, rel: str, taken: set) -> CryptoAssetComponent | None:
        base = {
            "discovery:source": rel,
            "crypto:line": str(fact.line),
            "crypto:detectedBy": "cb28:" + fact.api,
        }
        where = f"{_slug(rel)}-l{fact.line}"
        if fact.what == "protocol":
            weak = fact.detail.startswith("SSL") or fact.detail in ("1.0", "1.1")
            return CryptoAssetComponent(
                bom_ref=f"crypto-protocol-tls-{where}",
                name=f"TLS {fact.detail}",
                properties={
                    **base,
                    "crypto:assetType": "protocol",
                    "crypto:protocolType": "tls",
                    "crypto:protocolVersion": fact.detail,
                    "crypto:strength": "weak" if weak else "strong",
                },
            )
        if fact.what == "cipher_list":
            return CryptoAssetComponent(
                bom_ref=f"crypto-protocol-tls-ciphers-{where}",
                name="TLS cipher list",
                properties={
                    **base,
                    "crypto:assetType": "protocol",
                    "crypto:protocolType": "tls",
                    "crypto:cipherSuite": fact.detail,
                },
            )
        if fact.what in ("rsa_padding", "rsa_key"):
            info = algo_info("rsa") or {}
            props = {
                **base,
                "crypto:assetType": "algorithm",
                "crypto:primitive": str(info.get("primitive") or "pke"),
                "crypto:strength": str(info.get("strength") or "unknown"),
                "crypto:quantumVulnerable": str(
                    bool(info.get("quantum_vulnerable", False))
                ).lower(),
            }
            name = "RSA"
            if fact.what == "rsa_padding":
                props["crypto:padding"] = fact.detail
                props["crypto:operation"] = "encrypt"
            elif fact.key_size:
                props["crypto:keySize"] = str(fact.key_size)
                name = f"RSA-{fact.key_size}"
            return CryptoAssetComponent(
                bom_ref=f"crypto-algo-{_slug(name)}-{where}-cb28",
                name=name,
                properties=props,
            )
        if fact.what == "rsa_exponent":
            if (rel, str(fact.line), "public-key") in taken:
                return None
            return CryptoAssetComponent(
                bom_ref=f"crypto-material-misuse-public-key-e{fact.detail}-{where}",
                name=f"RSA public exponent {fact.detail} ({Path(rel).name})",
                properties={
                    **base,
                    "crypto:assetType": "related-crypto-material",
                    "crypto:materialKind": "public-key",
                    "crypto:publicExponent": fact.detail,
                },
            )
        if fact.what == "material":
            if (rel, str(fact.line), fact.detail) in taken:
                return None
            props = {
                **base,
                "crypto:assetType": "related-crypto-material",
                "crypto:materialKind": fact.detail,
                "crypto:usedBy": fact.api,
            }
            if fact.iterations is not None:
                props["crypto:iterations"] = str(fact.iterations)
                props["crypto:weakIterations"] = "true"
            else:
                props["crypto:hardcoded"] = "true"
                if fact.static_iv:
                    props["crypto:staticIv"] = "true"
            var = fact.var or "inline"
            return CryptoAssetComponent(
                bom_ref=f"crypto-material-misuse-{fact.detail}-{_slug(var)}-{where}",
                name=f"{fact.detail} ({var}, {Path(rel).name})",
                properties=props,
            )
        return None


__all__ = ["LangMisuseScanner"]
