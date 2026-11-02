"""C3 — JS/TS + C/C++ + Rust + .NET crypto detection through the REGISTERED engine.

The behaviour once pinned against a separate, never-registered scanner module is
asserted here through the real pipeline (:func:`aibom.cbom.pipeline.scan_crypto`)
on the same fixture (``tests/fixtures/synthetic-crypto-native``):

* Node cipher specs carry algorithm + size + mode in one literal, and ONE call is
  ONE asset (``createCipheriv('aes-256-gcm')`` → only AES-256-GCM, never also a
  coarse AES-GCM);
* ``generateKeyPair`` binds ``modulusLength`` / ``namedCurve``; WebCrypto's
  ``{name: "RSA-OAEP"}`` names the padding;
* OpenSSL's ``EVP_aes_128_cbc`` packs size + mode in the function name;
* RustCrypto ``Aes256Gcm`` / ring ``AES_256_GCM`` carry GCM;
* .NET ``aes.Mode = CipherMode.ECB`` binds to the ``Aes.Create()`` it was set on.

These ecosystems are matched by language-scoped literal lanes, not receiver+method
rules, so they carry no ``crypto:detectedBy`` / ``crypto:detectionMethod``. Dropped
from the old file (the deleted module's own contract or behaviour the registered
path legitimately does not reproduce): the provenance / ``detectionContext`` /
``confidence`` properties; curve normalisation to ``SECP*`` names and the
OpenSSL NID / .NET ``nistP*`` / RustCrypto ``p256`` curve bindings; ring's RSA
``PKCS1-v1_5`` padding; the ring-import gate on SCREAMING constants (the engine
matches ``AES_256_GCM`` in any Rust file); RustCrypto ``ed25519_dalek`` /
``p256`` recognised from their ``use`` lines; and the file-wide .NET
``CipherMode`` that turned an unrelated ``TripleDES.Create()`` into 3DES-ECB —
the engine binds the mode to the variable it is set on.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-native")


def _scan(path: str = _FX) -> ScanResult:
    return scan_crypto(path)


def _algos(result: ScanResult, source: str) -> dict[str, dict]:
    """name -> properties for the algorithm assets of one fixture file."""
    return {
        c.name: (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
        and (c.properties or {}).get("discovery:source") == source
    }


# --------------------------------------------------------------------------- #
# JS / TS — Node.js crypto
# --------------------------------------------------------------------------- #


def test_node_cipher_spec_splits_algo_size_mode() -> None:
    """``createCipheriv("aes-256-gcm", …)`` → AES-256-GCM (size + mode)."""
    algos = _algos(_scan(), "crypto_app.js")
    assert "AES-256-GCM" in algos, f"Node algorithms: {sorted(algos)}"
    assert algos["AES-256-GCM"]["crypto:keySize"] == "256"
    assert algos["AES-256-GCM"]["crypto:mode"] == "GCM"


def test_node_des_ede3_and_rc4_specs() -> None:
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["3DES-CBC"]["crypto:mode"] == "CBC"
    assert "RC4" in algos


def test_node_hash_hmac_sign() -> None:
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["SHA-256"]["crypto:primitive"] == "hash"
    assert algos["HMAC"]["crypto:primitive"] == "mac"
    assert "RSA" in algos  # createSign("RSA-SHA256")


def test_node_keypair_modulus_and_curve_bound() -> None:
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["RSA-3072"]["crypto:keySize"] == "3072"
    assert algos["ECDSA"]["crypto:curve"] == "P-384"


def test_node_aes_size_is_not_double_counted() -> None:
    """One ``createCipheriv('aes-256-gcm')`` call is ONE asset: the file must NOT
    carry both AES-256-GCM and the coarse AES-GCM."""
    result = _scan()
    node_js = [
        c.name
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("discovery:source") == "crypto_app.js"
        and c.name.startswith("AES")
    ]
    assert node_js == ["AES-256-GCM"], f"AES assets in crypto_app.js: {node_js}"


# --------------------------------------------------------------------------- #
# JS / TS — WebCrypto
# --------------------------------------------------------------------------- #


def test_webcrypto_name_field_fixes_primitive() -> None:
    algos = _algos(_scan(), "webcrypto.ts")
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"
    assert algos["RSA"]["crypto:padding"] == "oaep"


def test_webcrypto_ecdsa_curve_and_pbkdf2() -> None:
    algos = _algos(_scan(), "webcrypto.ts")
    assert algos["ECDSA"]["crypto:curve"] == "P-256"
    assert algos["PBKDF2"]["crypto:primitive"] == "kdf"
    assert "SHA-512" in algos  # subtle.digest("SHA-512", …)


# --------------------------------------------------------------------------- #
# C / C++ — OpenSSL
# --------------------------------------------------------------------------- #


def test_openssl_evp_cipher_name_encodes_algo_size_mode() -> None:
    algos = _algos(_scan(), "crypto.c")
    assert algos["AES-256-GCM"]["crypto:keySize"] == "256"
    assert algos["AES-128-CBC"]["crypto:mode"] == "CBC"
    assert algos["3DES-CBC"]["crypto:mode"] == "CBC"
    assert algos["ChaCha20-Poly1305"]["crypto:primitive"] == "ae"


def test_openssl_evp_ecb_is_a_weak_mode() -> None:
    """``EVP_aes_128_ecb()`` carries ECB, so the weak-mode flag fires on it."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "ecb.c").write_text(
            "#include <openssl/evp.h>\n"
            "void f(void) { const EVP_CIPHER *c = EVP_aes_128_ecb(); }\n"
        )
        result = scan_crypto(d)
        ecb = [c for c in result.components if c.name == "AES-128-ECB"]
        assert ecb, [c.name for c in result.components]
        assert "WEAK_CIPHER_MODE" in {f.code for f in result.flags_for(ecb[0].bom_ref)}


def test_openssl_rsa_bits() -> None:
    algos = _algos(_scan(), "crypto.c")
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in algos


def test_openssl_evp_and_legacy_digests() -> None:
    algos = _algos(_scan(), "crypto.c")
    for name in ("SHA-256", "MD5", "SHA-1", "HMAC"):
        assert name in algos, name


# --------------------------------------------------------------------------- #
# Rust — RustCrypto + ring
# --------------------------------------------------------------------------- #


def test_rustcrypto_camelcase_types() -> None:
    algos = _algos(_scan(), "rustcrypto_app.rs")
    assert algos["AES-256-GCM"]["crypto:mode"] == "GCM"
    assert "ChaCha20-Poly1305" in algos
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "SHA-256" in algos and "SHA-512" in algos
    assert "HMAC" in algos


def test_ring_screaming_constants() -> None:
    algos = _algos(_scan(), "ring_app.rs")
    assert algos["AES-256-GCM"]["crypto:mode"] == "GCM"
    assert "ChaCha20-Poly1305" in algos
    assert "Ed25519" in algos
    assert "ECDSA" in algos
    assert "RSA" in algos


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography
# --------------------------------------------------------------------------- #


def test_dotnet_rsa_size_and_mode_bound() -> None:
    algos = _algos(_scan(), "CryptoApp.cs")
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in algos
    # ``aes.Mode = CipherMode.ECB`` binds to ``var aes = Aes.Create()``
    assert algos["AES-ECB"]["crypto:mode"] == "ECB"


def test_dotnet_classes_and_kdf() -> None:
    algos = _algos(_scan(), "CryptoApp.cs")
    assert "3DES" in algos  # TripleDES.Create(): its own instance has no Mode set
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"  # new AesGcm(key)
    for name in ("SHA-256", "MD5", "HMAC", "PBKDF2"):
        assert name in algos, name


def test_every_native_asset_has_concrete_primitive() -> None:
    result = _scan()
    algos = [
        c for c in result.components
        if c.kind == "crypto_asset" and (c.properties or {}).get("crypto:assetType") == "algorithm"
    ]
    assert len(algos) >= 30
    for c in algos:
        p = c.properties or {}
        assert p.get("crypto:primitive") not in (None, "", "unknown"), c.name
        assert p["crypto:quantumVulnerable"] in ("true", "false")


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    assert [(c.kind, c.bom_ref) for c in a.components] == [
        (c.kind, c.bom_ref) for c in b.components
    ]
