"""Encode and decode an Encryption_Fact as string properties."""

from __future__ import annotations

import json
from collections.abc import Mapping

from aibom.cbom.posture.model import (
    BasisEntry,
    EncryptionFact,
    Linkage,
    PathContext,
    fact_id,
)

_PREFIX = "crypto:fact"


def _s(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def encode_fact(fact: EncryptionFact) -> dict[str, str]:
    """Every value is a string. Secrets are not a field of the fact."""
    layers = {key: _s(value) for key, value in fact.layers.items()}
    basis = []
    for item in fact.basis:
        basis.append(
            {
                "name": item.name,
                "value": item.value or "",
                "unknown_reason": item.unknown_reason or "",
            }
        )
    linkage = {
        "system": fact.linkage.system or "",
        "owner": fact.linkage.owner or "",
        "data_classification": fact.linkage.data_classification or "",
        "data_lifetime": fact.linkage.data_lifetime or "",
        "owner_hint": fact.linkage.owner_hint or "",
        "source": fact.linkage.source or "",
    }
    props = {
        f"{_PREFIX}Schema": "1",
        f"{_PREFIX}Id": fact.id,
        f"{_PREFIX}Kind": fact.kind,
        f"{_PREFIX}Provider": fact.provider,
        f"{_PREFIX}NativeType": fact.native_type,
        f"{_PREFIX}Address": fact.address,
        f"{_PREFIX}Path": fact.path,
        f"{_PREFIX}Line": str(fact.line),
        f"{_PREFIX}Format": fact.format,
        f"{_PREFIX}Layers": json.dumps(layers, sort_keys=True),
        f"{_PREFIX}Verdict": fact.verdict,
        f"{_PREFIX}Basis": json.dumps(basis, sort_keys=True),
        f"{_PREFIX}DefaultRow": fact.default_row or "",
        f"{_PREFIX}KeyManagement": fact.key_management,
        f"{_PREFIX}KeyRef": fact.key_ref or "",
        f"{_PREFIX}UnknownReason": fact.unknown_reason or "",
        f"{_PREFIX}PathContext": fact.path_context,
        f"{_PREFIX}Linkage": json.dumps(linkage, sort_keys=True),
        f"{_PREFIX}FindingCodes": json.dumps(list(fact.finding_codes)),
    }
    return dict(props)


def decode_fact(props: Mapping[str, str]) -> EncryptionFact:
    layers = json.loads(props[f"{_PREFIX}Layers"])
    basis_raw = json.loads(props[f"{_PREFIX}Basis"])
    link = json.loads(props[f"{_PREFIX}Linkage"])
    codes = tuple(json.loads(props[f"{_PREFIX}FindingCodes"]))
    context: PathContext = (
        "non_production_hint"
        if props[f"{_PREFIX}PathContext"] == "non_production_hint"
        else "production_like"
    )
    return EncryptionFact(
        id=props[f"{_PREFIX}Id"],
        kind=props[f"{_PREFIX}Kind"],
        provider=props[f"{_PREFIX}Provider"],
        native_type=props[f"{_PREFIX}NativeType"],
        address=props[f"{_PREFIX}Address"],
        path=props[f"{_PREFIX}Path"],
        line=int(props[f"{_PREFIX}Line"]),
        format=props[f"{_PREFIX}Format"],
        layers=layers,
        verdict=props[f"{_PREFIX}Verdict"],
        basis=tuple(
            BasisEntry(
                name=item["name"],
                value=item["value"] or None,
                unknown_reason=item["unknown_reason"] or None,
            )
            for item in basis_raw
        ),
        default_row=props[f"{_PREFIX}DefaultRow"] or None,
        key_management=props[f"{_PREFIX}KeyManagement"],
        key_ref=props[f"{_PREFIX}KeyRef"] or None,
        unknown_reason=props[f"{_PREFIX}UnknownReason"] or None,
        path_context=context,
        linkage=Linkage(
            system=link["system"] or None,
            owner=link["owner"] or None,
            data_classification=link["data_classification"] or None,
            data_lifetime=link["data_lifetime"] or None,
            owner_hint=link["owner_hint"] or None,
            source=link["source"] or None,
        ),
        finding_codes=codes,
    )


def make_fact_id(
    kind: str, provider: str, native_type: str, address: str, path: str
) -> str:
    return fact_id(kind, provider, native_type, address, path)
