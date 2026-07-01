"""C10 — clean-room algorithm/curve -> OID enrichment.

Drives the real CBOM pipeline over the hand-labeled synthetic fixtures, emits
CycloneDX 1.6, and asserts that every algorithm crypto-asset whose parameters
pin it unambiguously carries the canonical ``cryptoProperties.oid`` — and that
an ambiguous asset carries NONE (honest precision, the C9 no-false-precision
rule). The KB itself is unit-tested directly for spec-correct OIDs.

Lane discipline: OID enrichment is an EMIT-time render step. It reads the
``crypto:`` properties the scanners already emit, adds no components, reads no
flags, computes no risk, and stays schema-valid.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.emit.crypto_oid import algorithm_oid
from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx

_HERE = os.path.dirname(os.path.abspath(__file__))
_APP = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
_PQC = os.path.join(_HERE, "fixtures", "synthetic-crypto-pqc")


def _algorithm_oids(bom: dict) -> dict[str, str | None]:
    """name -> cryptoProperties.oid for every algorithm crypto-asset."""
    out: dict[str, str | None] = {}
    for c in bom["components"]:
        cp = c.get("cryptoProperties")
        if cp and cp.get("assetType") == "algorithm":
            out[c["name"]] = cp.get("oid")
    return out


# --------------------------------------------------------------------------- #
# KB unit tests (spec-correct OIDs from the public registries)
# --------------------------------------------------------------------------- #


def test_hash_oids() -> None:
    assert algorithm_oid("SHA-256", "hash") == "2.16.840.1.101.3.4.2.1"
    assert algorithm_oid("SHA-384", "hash") == "2.16.840.1.101.3.4.2.2"
    assert algorithm_oid("SHA-512", "hash") == "2.16.840.1.101.3.4.2.3"
    assert algorithm_oid("SHA-1", "hash") == "1.3.14.3.2.26"
    assert algorithm_oid("MD5", "hash") == "1.2.840.113549.2.5"
    assert algorithm_oid("SHA3-256", "hash") == "2.16.840.1.101.3.4.2.8"


def test_rsa_is_key_size_independent() -> None:
    assert algorithm_oid("RSA-1024", "pke", 1024) == "1.2.840.113549.1.1.1"
    assert algorithm_oid("RSA-2048", "pke", 2048) == "1.2.840.113549.1.1.1"


def test_aes_requires_key_size_and_mode() -> None:
    # Both present -> mode+size-specific OID.
    assert algorithm_oid("AES-128-GCM", "block-cipher", 128, "GCM") == (
        "2.16.840.1.101.3.4.1.6"
    )
    assert algorithm_oid("AES-256-CBC", "block-cipher", 256, "CBC") == (
        "2.16.840.1.101.3.4.1.42"
    )
    assert algorithm_oid("AES-192-ECB", "block-cipher", 192, "ECB") == (
        "2.16.840.1.101.3.4.1.21"
    )
    # Missing key size OR mode -> unresolved (no false precision).
    assert algorithm_oid("AES", "block-cipher", None, "GCM") is None
    assert algorithm_oid("AES-256", "block-cipher", 256, None) is None


def test_legacy_symmetric_oids() -> None:
    assert algorithm_oid("3DES-CBC", "block-cipher", 168, "CBC") == (
        "1.2.840.113549.3.7"
    )
    assert algorithm_oid("RC4", "stream-cipher") == "1.2.840.113549.3.4"
    assert algorithm_oid("DES", "block-cipher", 56, "CBC") == "1.3.14.3.2.7"
    # 3DES with no mode is ambiguous.
    assert algorithm_oid("3DES", "block-cipher", 168, None) is None


def test_curve_oids() -> None:
    assert algorithm_oid("EC", "pke", None, None, "P-256") == "1.2.840.10045.3.1.7"
    assert algorithm_oid("EC", "pke", None, None, "P-384") == "1.3.132.0.34"
    # Edwards keys named without a separate curve token.
    assert algorithm_oid("Ed25519", "signature") == "1.3.101.112"
    assert algorithm_oid("X25519", "key-agree") == "1.3.101.110"


def test_pqc_oids_pure_only() -> None:
    assert algorithm_oid("ML-KEM-768", "kem", None, None, None, "768") == (
        "2.16.840.1.101.3.4.4.2"
    )
    assert algorithm_oid("ML-KEM-1024", "kem", None, None, None, "1024") == (
        "2.16.840.1.101.3.4.4.3"
    )
    assert algorithm_oid("ML-DSA-87", "signature", None, None, None, "87") == (
        "2.16.840.1.101.3.4.3.19"
    )
    # A hybrid construction gets no pure-primitive OID.
    assert (
        algorithm_oid("Hybrid ML-KEM-1024", "key-agree", None, None, None, "1024")
        is None
    )
    # FALCON / SLH-DSA / stateful-hash lack an unambiguous single OID here.
    assert algorithm_oid("FALCON-512", "signature", None, None, None, "512") is None
    assert algorithm_oid("SLH-DSA-256", "signature", None, None, None, "256") is None
    assert algorithm_oid("LMS", "signature") is None


def test_unknown_returns_none() -> None:
    assert algorithm_oid("", "hash") is None
    assert algorithm_oid("Whirlpool", "hash") is None
    assert algorithm_oid(None) is None


# --------------------------------------------------------------------------- #
# End-to-end through the real pipeline + emitter
# --------------------------------------------------------------------------- #


def test_app_fixture_algorithm_oids() -> None:
    bom = emit_cyclonedx(scan_crypto(_APP))
    oids = _algorithm_oids(bom)
    # Unambiguous assets are enriched.
    assert oids["SHA-256"] == "2.16.840.1.101.3.4.2.1"
    assert oids["MD5"] == "1.2.840.113549.2.5"
    assert oids["RC4"] == "1.2.840.113549.3.4"
    assert oids["3DES-CBC"] == "1.2.840.113549.3.7"
    assert oids["RSA-1024"] == "1.2.840.113549.1.1.1"
    assert oids["RSA-2048"] == "1.2.840.113549.1.1.1"
    # AES assets with no key size on the source line stay unresolved.
    assert "oid" not in _algo_cp(bom, "AES")
    assert "oid" not in _algo_cp(bom, "AES-ECB")
    assert "oid" not in _algo_cp(bom, "AES-GCM")


def test_pqc_fixture_algorithm_oids() -> None:
    bom = emit_cyclonedx(scan_crypto(_PQC))
    oids = _algorithm_oids(bom)
    assert oids["ML-KEM-768"] == "2.16.840.1.101.3.4.4.2"
    assert oids["ML-DSA-87"] == "2.16.840.1.101.3.4.3.19"
    assert oids["SHA-384"] == "2.16.840.1.101.3.4.2.2"
    assert oids["RSA-2048"] == "1.2.840.113549.1.1.1"
    # Hybrids + FALCON + stateful-hash + AES-without-mode: no false precision.
    assert oids["Hybrid ML-KEM-768"] is None
    assert oids["Hybrid ML-KEM-1024"] is None
    assert oids["FALCON-512"] is None
    assert oids["SLH-DSA-256"] is None
    assert oids["LMS"] is None
    assert oids["XMSS"] is None
    assert oids["AES-256"] is None  # key size present, mode absent


def test_oid_only_on_algorithm_assets() -> None:
    """Certificates/protocols/material never carry a top-level algorithm OID."""
    bom = emit_cyclonedx(scan_crypto(_APP))
    for c in bom["components"]:
        cp = c.get("cryptoProperties")
        if cp and cp.get("assetType") != "algorithm":
            assert "oid" not in cp


def test_enriched_bom_still_schema_validates() -> None:
    for fx in (_APP, _PQC):
        bom = emit_and_validate(scan_crypto(fx))
        assert validate_cyclonedx(bom) == []


def test_emit_is_deterministic_with_oids() -> None:
    a = emit_cyclonedx(scan_crypto(_PQC))
    b = emit_cyclonedx(scan_crypto(_PQC))
    assert a == b


def _algo_cp(bom: dict, name: str) -> dict:
    for c in bom["components"]:
        if c.get("name") == name and c.get("cryptoProperties"):
            return c["cryptoProperties"]
    raise AssertionError(f"no algorithm asset named {name!r}")
