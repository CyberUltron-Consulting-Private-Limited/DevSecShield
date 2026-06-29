"""C4 — hand-built CycloneDX 1.6 crypto-asset emitter.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture, serializes the resulting
``ScanResult`` through the shared CycloneDX 1.6 emitter, and asserts that:

* every ``crypto_asset`` becomes a CycloneDX ``cryptographic-asset`` component
  carrying a ``cryptoProperties`` block whose ``assetType`` matches the
  scanner's ``crypto:assetType`` — across all four CycloneDX categories
  (algorithm / certificate / protocol / related-crypto-material);
* the crypto detail (primitive, key size, mode, curve, cert validity, protocol
  version + cipher suite, related-material kind) maps onto the EXACT CycloneDX
  1.6 ``cryptoProperties`` field names + enums;
* quantum-vulnerable public-key algorithms carry ``nistQuantumSecurityLevel``;
* the document SCHEMA-VALIDATES (a CBOM that fails validation is a build
  failure, never a warning); and
* the emitter is deterministic (byte-identical output across runs).

Lane discipline: the emitter only RENDERS the ``crypto:`` properties the C1/C2/C3
scanners already emit — it computes no risk and reads no flags.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _bom() -> dict:
    return emit_cyclonedx(scan_crypto(_FX))


def _crypto_components(bom: dict) -> dict[str, dict]:
    """name -> component, for every ``cryptographic-asset`` in the BOM."""
    return {
        c["name"]: c
        for c in bom["components"]
        if c.get("type") == "cryptographic-asset"
    }


def _by_asset_type(bom: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for c in bom["components"]:
        cp = c.get("cryptoProperties")
        if cp:
            out.setdefault(cp["assetType"], []).append(c)
    return out


# --------------------------------------------------------------------------- #
# Schema validity (the build-failure rule)
# --------------------------------------------------------------------------- #


def test_cbom_schema_validates() -> None:
    """The emitted CBOM validates against the bundled CycloneDX 1.6 schema."""
    bom = emit_and_validate(scan_crypto(_FX))  # raises BomValidationError on any error
    assert validate_cyclonedx(bom) == []


def test_it_is_a_cyclonedx_1_6_document() -> None:
    bom = _bom()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")


# --------------------------------------------------------------------------- #
# Every crypto asset becomes a cryptographic-asset component with cryptoProperties
# --------------------------------------------------------------------------- #


def test_every_crypto_asset_emits_cryptoProperties() -> None:
    result = scan_crypto(_FX)
    bom = emit_cyclonedx(result)
    crypto_comps = _crypto_components(bom)

    scanned = [c for c in result.components if c.kind == "crypto_asset"]
    assert len(crypto_comps) == len(scanned)
    for comp in crypto_comps.values():
        cp = comp.get("cryptoProperties")
        assert cp is not None, comp["name"]
        assert cp["assetType"] in {
            "algorithm",
            "certificate",
            "protocol",
            "related-crypto-material",
        }


def test_assetType_matches_the_scanner_property() -> None:
    result = scan_crypto(_FX)
    bom = emit_cyclonedx(result)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    for comp in result.components:
        if comp.kind != "crypto_asset":
            continue
        emitted = by_ref[comp.bom_ref]
        assert (
            emitted["cryptoProperties"]["assetType"]
            == comp.properties["crypto:assetType"]
        )


def test_all_four_categories_present() -> None:
    buckets = _by_asset_type(_bom())
    assert set(buckets) == {
        "algorithm",
        "certificate",
        "protocol",
        "related-crypto-material",
    }


# --------------------------------------------------------------------------- #
# algorithmProperties
# --------------------------------------------------------------------------- #


def test_algorithm_properties_map_primitive_keysize_mode() -> None:
    comps = _crypto_components(_bom())

    rsa = comps["RSA-2048"]["cryptoProperties"]["algorithmProperties"]
    assert rsa["primitive"] == "pke"
    assert rsa["parameterSetIdentifier"] == "2048"

    gcm = comps["AES-GCM"]["cryptoProperties"]["algorithmProperties"]
    assert gcm["mode"] == "gcm"  # CycloneDX enum is lower-case

    ecb = comps["AES-ECB"]["cryptoProperties"]["algorithmProperties"]
    assert ecb["mode"] == "ecb"


def test_quantum_vulnerable_algorithms_carry_nist_quantum_level() -> None:
    comps = _crypto_components(_bom())
    for name in ("RSA-2048", "RSA-1024"):
        algo = comps[name]["cryptoProperties"]["algorithmProperties"]
        # A quantum-vulnerable public-key algorithm has no quantum security.
        assert algo["nistQuantumSecurityLevel"] == 0


def test_primitive_is_a_valid_cyclonedx_enum() -> None:
    valid = {
        "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
        "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other",
        "unknown",
    }
    for comp in _by_asset_type(_bom()).get("algorithm", []):
        prim = comp["cryptoProperties"]["algorithmProperties"].get("primitive")
        if prim is not None:
            assert prim in valid


# --------------------------------------------------------------------------- #
# certificateProperties
# --------------------------------------------------------------------------- #


def test_certificate_properties_carry_subject_and_validity() -> None:
    cert = _crypto_components(_bom())["cert.pem"]["cryptoProperties"]
    assert cert["assetType"] == "certificate"
    certp = cert["certificateProperties"]
    assert certp["subjectName"] == "synthetic-crypto-app.test"
    assert certp["notValidAfter"].startswith("2027-")


# --------------------------------------------------------------------------- #
# relatedCryptoMaterialProperties
# --------------------------------------------------------------------------- #


def test_related_crypto_material_kind() -> None:
    [mat] = _by_asset_type(_bom())["related-crypto-material"]
    relp = mat["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert relp["type"] == "private-key"


# --------------------------------------------------------------------------- #
# protocolProperties
# --------------------------------------------------------------------------- #


def test_protocol_properties_carry_version_and_cipher_suite() -> None:
    [proto] = _by_asset_type(_bom())["protocol"]
    protp = proto["cryptoProperties"]["protocolProperties"]
    assert protp["type"] == "tls"
    assert protp["version"] == "1.0"
    assert protp["cipherSuites"][0]["name"] == "ECDHE-RSA-AES128-SHA"


# --------------------------------------------------------------------------- #
# crypto libraries are NOT crypto-assets; determinism
# --------------------------------------------------------------------------- #


def test_crypto_libraries_emit_as_library_not_crypto_asset() -> None:
    bom = _bom()
    libs = [c for c in bom["components"] if c["name"].endswith("(stdlib)")]
    assert libs  # the fixture imports hashlib/ssl
    for lib in libs:
        assert lib["type"] == "library"
        assert "cryptoProperties" not in lib


def test_emit_is_deterministic() -> None:
    assert emit_cyclonedx(scan_crypto(_FX)) == emit_cyclonedx(scan_crypto(_FX))
