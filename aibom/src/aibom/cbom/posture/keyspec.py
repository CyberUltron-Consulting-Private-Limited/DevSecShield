"""Map a declared key specification to one algorithm asset."""

from __future__ import annotations

import json

from aibom.cbom.posture.defaults import read_data_bytes
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.rules import algo_info
from aibom.model.component import CryptoAssetComponent


def _rows() -> dict[str, dict[str, object]]:
    document = json.loads(read_data_bytes("key_specs.json"))
    rows = document.get("rows")
    if not isinstance(rows, list):
        return {}
    found: dict[str, dict[str, object]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            found[row["id"]] = row
    return found


def _basis(fact: EncryptionFact, name: str) -> str | None:
    return next(
        (item.value for item in fact.basis if item.name == name and item.value),
        None,
    )


def material_for_fact(fact: EncryptionFact) -> CryptoAssetComponent | None:
    """One key material asset for each KMS fact."""
    if fact.kind != "kms_key":
        return None
    props = {
        "crypto:assetType": "related-crypto-material",
        "crypto:factId": fact.id,
        "crypto:materialKind": "key",
        "discovery:source": f"{fact.path}:{fact.line}",
    }
    usage = _basis(fact, "key_usage")
    rotation = _basis(fact, "rotation")
    algorithm = {
        "EC": "ECDSA",
        "GOOGLE_SYMMETRIC_ENCRYPTION": "AES",
        "RSA": "RSA",
        "RSA_2048": "RSA",
        "SYMMETRIC_DEFAULT": "AES",
    }.get(_basis(fact, "key_spec") or "")
    if usage:
        props["crypto:keyUsage"] = usage
    if rotation:
        props["crypto:rotation"] = rotation
    if algorithm:
        props["crypto:algorithm"] = algorithm
    return CryptoAssetComponent(
        bom_ref=f"crypto-material-{fact.id}",
        name=f"key ({fact.address})",
        properties=props,
    )


def algorithm_for_fact(fact: EncryptionFact) -> CryptoAssetComponent | None:
    """Return an algorithm asset when ``key_specs.json`` names the fact's spec."""
    spec = _basis(fact, "key_spec")
    if spec is None:
        return None
    row = _rows().get(f"{fact.provider}.{spec}")
    if row is None:
        return None
    algorithm = row.get("algorithm")
    if not isinstance(algorithm, str):
        return None
    info_key = {"EC": "ecdsa", "GOOGLE_SYMMETRIC": "aes"}.get(
        algorithm, algorithm.lower()
    )
    info = algo_info(info_key)
    if info is None:
        return None
    size = row.get("key_size")
    if algorithm == "GOOGLE_SYMMETRIC":
        name = "AES-256"
    elif algorithm == "EC":
        name = "ECDSA"
    else:
        name = f"{algorithm}-{size}" if isinstance(size, int) else algorithm
    props = {
        "crypto:assetType": "algorithm",
        "crypto:factId": fact.id,
        "crypto:primitive": str(info.get("primitive") or "other"),
        "crypto:quantumVulnerable": str(bool(info.get("quantum_vulnerable"))).lower(),
        "crypto:strength": str(info.get("strength") or "unknown"),
        "discovery:source": f"{fact.path}:{fact.line}",
    }
    if algorithm == "EC":
        props["crypto:curve"] = "P-256"
    elif isinstance(size, int):
        props["crypto:keySize"] = str(size)
    return CryptoAssetComponent(
        bom_ref=f"crypto-algo-{fact.id}",
        name=name,
        properties=props,
    )
