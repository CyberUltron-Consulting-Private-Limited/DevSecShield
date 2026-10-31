"""Weak named groups. A group at or above 224 bits adds no asset."""

from __future__ import annotations

from collections.abc import Iterable

from aibom.cbom.posture.ciphers import classify_groups
from aibom.cbom.posture.defaults import load_registry
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext

_BASIS = frozenset({"curves", "ssl_ecdh_curve"})


def weak_curve_tokens(spec: str) -> tuple[str, ...]:
    """Tokens whose named group is below 224 bits, in written order."""
    registry = load_registry()
    kept: list[str] = []
    seen: set[str] = set()
    for token in spec.replace(",", " ").replace(":", " ").split():
        name = token.strip().strip("'\"")
        if not name or name.casefold() == "auto" or name.casefold() in seen:
            continue
        if not classify_groups(name, registry).weak:
            continue
        seen.add(name.casefold())
        kept.append(name)
    return tuple(kept)


def emit_curves(ctx: ScanContext, facts: Iterable[EncryptionFact]) -> None:
    """One ECDH asset per weak curve, linked from the declaring fact."""
    for fact in facts:
        spec = next(
            (
                item.value
                for item in fact.basis
                if item.name in _BASIS and item.value
            ),
            None,
        )
        if spec is None:
            continue
        for index, token in enumerate(weak_curve_tokens(spec), start=1):
            asset = _asset(fact, token, index)
            if not ctx.has_ref(asset.bom_ref):
                ctx.add_component(asset)
            ctx.add_edge(f"crypto-cfg_{fact.id}", "depends_on", asset.bom_ref)


def _asset(fact: EncryptionFact, token: str, index: int) -> CryptoAssetComponent:
    info = algo_info("ecdh") or {}
    slug = "".join(ch if ch.isalnum() else "-" for ch in token.casefold())
    return CryptoAssetComponent(
        bom_ref=f"crypto-algo-ecdh-{fact.id}-{index}-{slug}",
        name=ALGORITHM_NORMALIZE["ecdh"],
        properties={
            "crypto:assetType": "algorithm",
            "crypto:curve": token,
            "crypto:factId": fact.id,
            "crypto:primitive": str(info.get("primitive") or "key-agree"),
            "crypto:strength": "weak",
            "discovery:source": fact.path,
        },
    )
