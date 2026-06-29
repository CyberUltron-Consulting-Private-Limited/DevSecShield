"""C2 — CBOM certificate + related-crypto-material scanner.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts the certificate and
related-crypto-material lanes match the oracle (``expected_crypto.json``):

* the self-signed ``cert.pem`` is inventoried with its real validity/expiry,
  subject, signature algorithm and RSA key size — parsed offline by the
  dependency-free :mod:`aibom.cbom.x509` reader;
* the hardcoded private key embedded in ``crypto_app.py`` is inventoried as
  related-crypto-material (kind ``private-key``).

C2 inventories only — weak/expiry FLAGGING is C5/C8, the CycloneDX crypto-asset
serialization is C4. The x509 parser is unit-tested here too (it must never
raise on non-cert bytes).
"""

from __future__ import annotations

import json
import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.x509 import parse_certificate
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _assets_of(result: ScanResult, asset_type: str) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == asset_type
    ]


# --- certificate lane ------------------------------------------------------- #


def test_certificate_is_detected() -> None:
    certs = _assets_of(_scan(), "certificate")
    sources = {(c.properties or {}).get("discovery:source") for c in certs}
    assert "cert.pem" in sources, f"cert.pem not inventoried (got {sources})"
    assert len(certs) == _manifest()["counts"]["certificates"]


def test_certificate_captures_expiry_and_validity() -> None:
    """The story's core requirement: certificate expiry is captured."""
    cert = next(c for c in _assets_of(_scan(), "certificate"))
    props = cert.properties or {}
    assert props.get("crypto:notValidAfter", "").startswith("2027-06-29")
    assert props.get("crypto:notValidBefore", "").startswith("2026-06-29")


def test_certificate_subject_self_signed_and_key_size() -> None:
    expected = _manifest()["certificates"][0]
    cert = next(c for c in _assets_of(_scan(), "certificate"))
    props = cert.properties or {}
    assert props.get("crypto:selfSigned") == "true"
    assert props.get("crypto:subjectName") == "synthetic-crypto-app.test"
    assert props.get("crypto:keySize") == str(expected["key_size"])
    assert props.get("crypto:signatureAlgorithm") == expected["signature_algorithm"]


# --- related-crypto-material lane ------------------------------------------- #


def test_hardcoded_private_key_is_detected() -> None:
    material = _assets_of(_scan(), "related-crypto-material")
    private_keys = [
        c
        for c in material
        if (c.properties or {}).get("crypto:materialKind") == "private-key"
    ]
    sources = {(c.properties or {}).get("discovery:source") for c in private_keys}
    assert "crypto_app.py" in sources, f"hardcoded key not found (got {sources})"
    assert len(material) == _manifest()["counts"]["related_crypto_material"]


def test_material_kinds_are_valid_cyclonedx_enum() -> None:
    valid = {
        "private-key", "public-key", "secret-key", "key", "ciphertext",
        "signature", "digest", "initialization-vector", "nonce", "seed",
        "salt", "shared-secret", "tag", "additional-data", "password",
        "credential", "token", "other", "unknown",
    }
    for c in _assets_of(_scan(), "related-crypto-material"):
        kind = (c.properties or {}).get("crypto:materialKind")
        assert kind in valid, f"invalid materialKind {kind!r}"


# --- the offline x509 reader must be total (never raise) -------------------- #


def test_x509_parser_returns_none_on_garbage() -> None:
    assert parse_certificate(b"") is None
    assert parse_certificate(b"not a certificate at all") is None
    assert parse_certificate(b"\x30\x80\x00") is None  # malformed length


def test_cbom_certificate_scanner_not_in_aibom_registry() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_certificate" for s in SCANNERS)
