"""CBOM certificate harden — .ca-bundle + opaque keystores + chart contract.

Locks detection for ``synthetic-crypto-certs-harden`` (public ISRG Root X1 as
``.ca-bundle``, throwaway PEM key, opaque JKS/PKCS#12 stubs). Pre-harden the
directory scanned to **0** certificates / **0** material (``.ca-bundle`` not in
``_CERT_EXTS``; keystores ignored). Research decision: never password-parse
keystores — inventory as opaque ``credential`` related-crypto-material.
"""

from __future__ import annotations

import os

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-certs-harden")


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _assets(result: ScanResult, asset_type: str) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == asset_type
    ]


def test_ca_bundle_public_cert_detected() -> None:
    certs = _assets(_scan(), "certificate")
    sources = {(c.properties or {}).get("discovery:source") for c in certs}
    assert "isrg-root-x1.ca-bundle" in sources, sources
    isrg = next(
        c
        for c in certs
        if (c.properties or {}).get("discovery:source") == "isrg-root-x1.ca-bundle"
    )
    props = isrg.properties or {}
    assert props.get("crypto:subjectName") == "ISRG Root X1"
    assert (props.get("crypto:notValidAfter") or "").startswith("2035-06-04")


def test_private_key_and_opaque_keystores_inventoried() -> None:
    material = _assets(_scan(), "related-crypto-material")
    by_kind: dict[str, list] = {}
    for c in material:
        kind = (c.properties or {}).get("crypto:materialKind") or "?"
        by_kind.setdefault(kind, []).append(c)

    assert any(
        (c.properties or {}).get("discovery:source") == "server.key"
        for c in by_kind.get("private-key", [])
    ), by_kind

    creds = by_kind.get("credential", [])
    formats = {
        (c.properties or {}).get("crypto:containerFormat") for c in creds
    }
    sources = {(c.properties or {}).get("discovery:source") for c in creds}
    assert "jks" in formats and "pkcs12" in formats, formats
    assert "opaque-truststore.jks" in sources
    assert "opaque-client.p12" in sources or "opaque-client.pfx" in sources
    for c in creds:
        assert (c.properties or {}).get("crypto:parseStatus") == "opaque"
        # Never invent notValidAfter on undecrypted keystores
        assert "crypto:notValidAfter" not in (c.properties or {})


def test_normalize_carries_certificates_and_key_material() -> None:
    run = normalize_crypto(_scan(), duration_of_scan=0.0)
    dist = run["cbom_distributions"]
    assert dist["certificates"], "certificates[] must be non-empty for ISRG Root"
    assert any(
        "isrg" in (r.get("name") or "").lower()
        or (r.get("location") or "").endswith(".ca-bundle")
        for r in dist["certificates"]
    )
    km = dist.get("key_material") or []
    assert km, "key_material[] must surface keys + opaque keystores"
    kinds = {r.get("material_kind") for r in km}
    assert "private-key" in kinds
    assert "credential" in kinds
    opaque = [r for r in km if r.get("parse_status") == "opaque"]
    assert opaque, "opaque keystores must appear in key_material"


def test_material_kinds_remain_cyclonedx_enum() -> None:
    valid = {
        "private-key", "public-key", "secret-key", "key", "ciphertext",
        "signature", "digest", "initialization-vector", "nonce", "seed",
        "salt", "shared-secret", "tag", "additional-data", "password",
        "credential", "token", "other", "unknown",
    }
    for c in _assets(_scan(), "related-crypto-material"):
        kind = (c.properties or {}).get("crypto:materialKind")
        assert kind in valid, kind
