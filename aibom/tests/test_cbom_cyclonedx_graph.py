"""C9 — hand-built CycloneDX 1.6 crypto-asset DEPENDENCY GRAPH hardening.

C4 rendered each crypto asset in isolation; C9 wires the crypto dependency graph
the CycloneDX 1.6 CBOM spec defines and keeps it schema-valid across all four
asset types:

* a ``certificate`` references its signature-algorithm + subject-public-key
  algorithm assets (``signatureAlgorithmRef`` / ``subjectPublicKeyRef``) instead
  of only carrying string properties, plus ``certificateFormat`` / extension;
* a ``protocol`` splits its cipher-suite bag into structured ``cipherSuites[]``
  objects, each linking to the algorithm assets it names via ``algorithms`` +
  the protocol-level ``cryptoRefArray``;
* a ``related-crypto-material`` asset links to the algorithm that generated it
  (``algorithmRef``) and records ``format`` / ``size`` where derivable.

The refs resolve against the algorithm assets already inventoried (no duplicate
component); only when a certificate names an algorithm absent from the source
inventory does the emitter synthesize a minimal dedicated algorithm asset so the
certificate is self-describing (the cbomkit-theia ``certificates``-plugin
behavior, clean-room). The emitter stays pure/deterministic and every document
schema-validates — a CBOM that fails validation is a build failure.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx
from aibom.model.component import CryptoAssetComponent, MetadataComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


# --------------------------------------------------------------------------- #
# Helpers to craft minimal ScanResults (the emitter is a pure function).
# --------------------------------------------------------------------------- #


def _algo(ref: str, name: str, **crypto: str) -> CryptoAssetComponent:
    props = {"crypto:assetType": "algorithm", **crypto}
    return CryptoAssetComponent(bom_ref=ref, name=name, properties=props)


def _result(*components: CryptoAssetComponent) -> ScanResult:
    return ScanResult(
        subject=MetadataComponent(name="crafted"), components=list(components)
    )


def _crypto_by_name(bom: dict) -> dict[str, dict]:
    return {
        c["name"]: c
        for c in bom["components"]
        if c.get("type") == "cryptographic-asset"
    }


def _by_ref(bom: dict) -> dict[str, dict]:
    return {c["bom-ref"]: c for c in bom["components"]}


# --------------------------------------------------------------------------- #
# Certificate -> algorithm dependency graph (refs resolve to existing assets)
# --------------------------------------------------------------------------- #


def test_certificate_refs_point_to_existing_algorithm_assets() -> None:
    sha = _algo("algo-sha256", "SHA-256", **{"crypto:primitive": "hash"})
    rsa = _algo(
        "algo-rsa2048",
        "RSA-2048",
        **{"crypto:primitive": "pke", "crypto:keySize": "2048"},
    )
    cert = CryptoAssetComponent(
        bom_ref="cert-1",
        name="server.pem",
        properties={
            "crypto:assetType": "certificate",
            "crypto:signatureAlgorithm": "sha256WithRSAEncryption",
            "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "2048",
            "discovery:source": "server.pem",
        },
    )
    bom = emit_and_validate(_result(sha, rsa, cert))

    certp = _by_ref(bom)["cert-1"]["cryptoProperties"]["certificateProperties"]
    assert certp["signatureAlgorithmRef"] == "algo-sha256"
    assert certp["subjectPublicKeyRef"] == "algo-rsa2048"
    assert certp["certificateFormat"] == "X.509"
    assert certp["certificateExtension"] == "pem"
    # No synthesis: exactly the three crafted crypto assets are emitted.
    assert len(_crypto_by_name(bom)) == 3


def test_subject_public_key_ref_disambiguates_by_key_size() -> None:
    rsa1024 = _algo(
        "algo-rsa1024", "RSA-1024",
        **{"crypto:primitive": "pke", "crypto:keySize": "1024"},
    )
    rsa2048 = _algo(
        "algo-rsa2048", "RSA-2048",
        **{"crypto:primitive": "pke", "crypto:keySize": "2048"},
    )
    cert = CryptoAssetComponent(
        bom_ref="cert-1",
        name="server.crt",
        properties={
            "crypto:assetType": "certificate",
            "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "2048",
            "discovery:source": "a/server.crt",
        },
    )
    bom = emit_cyclonedx(_result(rsa1024, rsa2048, cert))
    certp = _by_ref(bom)["cert-1"]["cryptoProperties"]["certificateProperties"]
    assert certp["subjectPublicKeyRef"] == "algo-rsa2048"
    assert certp["certificateExtension"] == "crt"


# --------------------------------------------------------------------------- #
# Certificate self-describes: synthesize algorithm assets absent from inventory
# --------------------------------------------------------------------------- #


def test_certificate_synthesizes_missing_algorithm_assets() -> None:
    cert = CryptoAssetComponent(
        bom_ref="cert-1",
        name="leaf.der",
        properties={
            "crypto:assetType": "certificate",
            "crypto:signatureAlgorithm": "sha384WithRSAEncryption",
            "crypto:publicKeyAlgorithm": "rsaEncryption",
            "crypto:keySize": "3072",
            "discovery:source": "leaf.der",
        },
    )
    bom = emit_and_validate(_result(cert))  # must still schema-validate
    by_ref = _by_ref(bom)
    certp = by_ref["cert-1"]["cryptoProperties"]["certificateProperties"]

    sig_ref = certp["signatureAlgorithmRef"]
    key_ref = certp["subjectPublicKeyRef"]
    # Both refs resolve to synthesized cryptographic-asset components.
    assert by_ref[sig_ref]["type"] == "cryptographic-asset"
    assert by_ref[sig_ref]["cryptoProperties"]["assetType"] == "algorithm"
    assert by_ref[sig_ref]["name"] == "SHA-384"
    assert by_ref[key_ref]["name"] == "RSA-3072"
    key_algo = by_ref[key_ref]["cryptoProperties"]["algorithmProperties"]
    assert key_algo["parameterSetIdentifier"] == "3072"


def test_pure_signature_scheme_refs_the_key_algorithm() -> None:
    # Ed25519 signs directly (no separate digest) -> signatureAlgorithmRef falls
    # back to the subject public-key algorithm asset.
    ed = _algo("algo-ed", "Ed25519", **{"crypto:primitive": "signature"})
    cert = CryptoAssetComponent(
        bom_ref="cert-ed",
        name="ed.pem",
        properties={
            "crypto:assetType": "certificate",
            "crypto:signatureAlgorithm": "ed25519",
            "crypto:publicKeyAlgorithm": "ed25519",
            "discovery:source": "ed.pem",
        },
    )
    bom = emit_and_validate(_result(ed, cert))
    certp = _by_ref(bom)["cert-ed"]["cryptoProperties"]["certificateProperties"]
    assert certp["subjectPublicKeyRef"] == "algo-ed"
    assert certp["signatureAlgorithmRef"] == "algo-ed"


# --------------------------------------------------------------------------- #
# Protocol -> cipherSuites[] structured + cryptoRefArray
# --------------------------------------------------------------------------- #


def test_protocol_splits_cipher_suites_into_structured_objects() -> None:
    proto = CryptoAssetComponent(
        bom_ref="proto-1",
        name="TLS 1.2",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:protocolVersion": "1.2",
            "crypto:cipherSuite": (
                "TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256"
            ),
        },
    )
    bom = emit_and_validate(_result(proto))
    protp = _by_ref(bom)["proto-1"]["cryptoProperties"]["protocolProperties"]
    names = [s["name"] for s in protp["cipherSuites"]]
    assert names == ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]


def test_cipher_suite_links_to_unambiguous_algorithm_assets() -> None:
    chacha = _algo("algo-cc", "ChaCha20", **{"crypto:primitive": "stream-cipher"})
    proto = CryptoAssetComponent(
        bom_ref="proto-1",
        name="TLS 1.3",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:cipherSuite": "TLS_CHACHA20_POLY1305_SHA256",
        },
    )
    bom = emit_and_validate(_result(chacha, proto))
    protp = _by_ref(bom)["proto-1"]["cryptoProperties"]["protocolProperties"]
    suite = protp["cipherSuites"][0]
    assert suite["algorithms"] == ["algo-cc"]
    assert protp["cryptoRefArray"] == ["algo-cc"]


def test_cipher_suite_omits_ambiguous_family_refs() -> None:
    # Two AES usages -> the suite's "AES" token is ambiguous -> no false ref.
    aes_gcm = _algo("algo-gcm", "AES-GCM", **{"crypto:mode": "GCM"})
    aes_cbc = _algo("algo-cbc", "AES-CBC", **{"crypto:mode": "CBC"})
    proto = CryptoAssetComponent(
        bom_ref="proto-1",
        name="TLS 1.2",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:cipherSuite": "ECDHE-RSA-AES128-SHA",
        },
    )
    bom = emit_and_validate(_result(aes_gcm, aes_cbc, proto))
    protp = _by_ref(bom)["proto-1"]["cryptoProperties"]["protocolProperties"]
    assert "algorithms" not in protp["cipherSuites"][0]
    assert "cryptoRefArray" not in protp


# --------------------------------------------------------------------------- #
# Related-crypto-material -> algorithmRef / format / size
# --------------------------------------------------------------------------- #


def test_related_material_links_algorithm_and_format() -> None:
    rsa = _algo(
        "algo-rsa", "RSA-2048",
        **{"crypto:primitive": "pke", "crypto:keySize": "2048"},
    )
    mat = CryptoAssetComponent(
        bom_ref="mat-1",
        name="private-key (id_rsa.pem)",
        properties={
            "crypto:assetType": "related-crypto-material",
            "crypto:materialKind": "private-key",
            "crypto:algorithm": "RSA",
            "crypto:keySize": "2048",
            "discovery:source": "keys/id_rsa.pem",
        },
    )
    bom = emit_and_validate(_result(rsa, mat))
    relp = _by_ref(bom)["mat-1"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert relp["type"] == "private-key"
    assert relp["algorithmRef"] == "algo-rsa"
    assert relp["format"] == "PEM"
    assert relp["size"] == 2048


# --------------------------------------------------------------------------- #
# Integration on the FROZEN fixture — refs resolve, zero synthesis, still valid
# --------------------------------------------------------------------------- #


def test_frozen_fixture_cert_wires_into_existing_inventory() -> None:
    result = scan_crypto(_FX)
    bom = emit_and_validate(result)
    by_ref = _by_ref(bom)
    names = {c.bom_ref: c.name for c in result.components if c.kind == "crypto_asset"}

    cert = next(
        c for c in bom["components"]
        if c.get("cryptoProperties", {}).get("assetType") == "certificate"
    )
    certp = cert["cryptoProperties"]["certificateProperties"]
    assert certp["certificateFormat"] == "X.509"
    assert certp["certificateExtension"] == "pem"
    # sig -> the SHA-256 hash asset; pubkey -> the RSA-2048 asset (both source-detected)
    assert names[certp["signatureAlgorithmRef"]] == "SHA-256"
    assert names[certp["subjectPublicKeyRef"]] == "RSA-2048"
    # both refs are real components in the BOM
    assert certp["signatureAlgorithmRef"] in by_ref
    assert certp["subjectPublicKeyRef"] in by_ref


def test_frozen_fixture_emits_no_synthesized_components() -> None:
    result = scan_crypto(_FX)
    bom = emit_cyclonedx(result)
    scanned = [c for c in result.components if c.kind == "crypto_asset"]
    emitted = [c for c in bom["components"] if c.get("type") == "cryptographic-asset"]
    # every crypto asset in the BOM corresponds to a scanned asset (no synthesis)
    assert len(emitted) == len(scanned)


def test_frozen_fixture_still_schema_valid_and_deterministic() -> None:
    assert validate_cyclonedx(emit_cyclonedx(scan_crypto(_FX))) == []
    assert emit_cyclonedx(scan_crypto(_FX)) == emit_cyclonedx(scan_crypto(_FX))
