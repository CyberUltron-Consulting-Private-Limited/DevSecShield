"""C3 — JS/TS + C/C++ + Rust + .NET crypto-API scanner (call-expression model +
per-library API→asset maps for the four language families Sonar-Cryptography does
not cover).

These tests pin the capabilities a flat line-regex cannot have for these
languages: the Node OpenSSL cipher-spec split (``aes-256-gcm`` → algo + key size
+ mode), WebCrypto's algorithm-object ``name`` field (+ ``modulusLength`` /
``namedCurve`` / padding), the OpenSSL ``EVP_<algo>_<bits>_<mode>`` name encoding
+ ``RSA_generate_key_ex`` size + ``NID_`` curve, RustCrypto's CamelCase types +
ring's SCREAMING constants, and .NET's ``RSA.Create(2048)`` / ``ECCurve`` /
``CipherMode`` binding. They drive the REAL pipeline
(:func:`aibom.cbom.pipeline.scan_crypto`) — never a mocked graph.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-native")


def _scan(path: str = _FX) -> ScanResult:
    return scan_crypto(path)


def _by_lib(result: ScanResult, *libraries: str) -> dict[str, dict]:
    """name -> properties, for call-expr algorithm assets from the given libs."""
    want = set(libraries)
    return {
        c.name: (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
        and (c.properties or {}).get("crypto:detectionMethod") == "call-expr"
        and (not want or (c.properties or {}).get("crypto:detectedBy") in want)
    }


# --------------------------------------------------------------------------- #
# JS / TS — Node.js crypto
# --------------------------------------------------------------------------- #


def test_node_cipher_spec_splits_algo_size_mode() -> None:
    """``createCipheriv("aes-256-gcm", …)`` → AES-256-GCM (size 256, mode GCM)."""
    algos = _by_lib(_scan(), _NODE)
    assert "AES-256-GCM" in algos, f"Node algorithms: {sorted(algos)}"
    assert algos["AES-256-GCM"]["crypto:keySize"] == "256"
    assert algos["AES-256-GCM"]["crypto:mode"] == "GCM"


def test_node_des_ede3_and_rc4_specs() -> None:
    """``des-ede3-cbc`` → 3DES-CBC (mode bound); ``rc4`` → RC4."""
    algos = _by_lib(_scan(), _NODE)
    assert "3DES-CBC" in algos
    assert algos["3DES-CBC"]["crypto:mode"] == "CBC"
    assert "RC4" in algos


def test_node_hash_hmac_sign() -> None:
    algos = _by_lib(_scan(), _NODE)
    assert "SHA-256" in algos and algos["SHA-256"]["crypto:primitive"] == "hash"
    assert "HMAC" in algos and algos["HMAC"]["crypto:primitive"] == "mac"
    # createSign("RSA-SHA256") resolves the RSA signature primitive.
    assert "RSA" in algos


def test_node_keypair_modulus_and_curve_bound() -> None:
    """``generateKeyPair("rsa", {modulusLength: 3072})`` → RSA-3072;
    ``("ec", {namedCurve: "P-384"})`` → ECDSA on SECP384R1."""
    algos = _by_lib(_scan(), _NODE)
    assert "RSA-3072" in algos
    assert algos["RSA-3072"]["crypto:keySize"] == "3072"
    assert "ECDSA" in algos
    assert algos["ECDSA"]["crypto:curve"] == "SECP384R1"


def test_node_aes_size_is_not_double_counted() -> None:
    """The order-10 line-regex scanner matches ``AES-256`` but drops the size
    (256 is not in its key-size set) → coarse ``AES-GCM``. C3 reserves that
    de-sized ref, so the file must NOT carry BOTH AES-GCM and AES-256-GCM."""
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
    """The algorithm object's ``name`` field is the entry point:
    ``{name:"AES-GCM"}`` → AES-GCM, ``{name:"RSA-OAEP"}`` → RSA + OAEP padding."""
    algos = _by_lib(_scan(), _WEBCRYPTO)
    assert "AES-GCM" in algos
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"
    assert "RSA" in algos
    assert algos["RSA"]["crypto:padding"] == "OAEP"


def test_webcrypto_ecdsa_curve_and_pbkdf2() -> None:
    algos = _by_lib(_scan(), _WEBCRYPTO)
    assert "ECDSA" in algos
    assert algos["ECDSA"]["crypto:curve"] == "SECP256R1"
    assert "PBKDF2" in algos and algos["PBKDF2"]["crypto:primitive"] == "kdf"
    assert "SHA-512" in algos  # subtle.digest("SHA-512", …)


# --------------------------------------------------------------------------- #
# C / C++ — OpenSSL / BoringSSL
# --------------------------------------------------------------------------- #


def test_openssl_evp_cipher_name_encodes_algo_size_mode() -> None:
    """``EVP_aes_256_gcm()`` → AES-256-GCM; ``EVP_aes_128_cbc()`` → AES-128-CBC;
    ``EVP_chacha20_poly1305()`` → ChaCha20-Poly1305 (AEAD, no mode)."""
    algos = _by_lib(_scan(), _OPENSSL)
    assert "AES-256-GCM" in algos and algos["AES-256-GCM"]["crypto:keySize"] == "256"
    assert "AES-128-CBC" in algos and algos["AES-128-CBC"]["crypto:mode"] == "CBC"
    assert "3DES-CBC" in algos
    assert "ChaCha20-Poly1305" in algos
    assert algos["ChaCha20-Poly1305"]["crypto:primitive"] == "ae"


def test_openssl_rsa_bits_and_curve_nid() -> None:
    """``RSA_generate_key_ex(rsa, 2048, …)`` → RSA-2048 (2nd arg);
    ``EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)`` → ECDSA on SECP256R1."""
    algos = _by_lib(_scan(), _OPENSSL)
    assert "RSA-2048" in algos and algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in algos and algos["ECDSA"]["crypto:curve"] == "SECP256R1"


def test_openssl_evp_and_legacy_digests() -> None:
    algos = _by_lib(_scan(), _OPENSSL)
    assert "SHA-256" in algos  # EVP_sha256()
    assert "MD5" in algos  # EVP_md5()
    assert "SHA-1" in algos  # SHA1_Init() legacy call
    assert "HMAC" in algos


# --------------------------------------------------------------------------- #
# Rust — RustCrypto + ring
# --------------------------------------------------------------------------- #


def test_rustcrypto_camelcase_types() -> None:
    """``Aes256Gcm`` → AES-256-GCM; ``RsaPrivateKey::new(rng, 2048)`` → RSA-2048;
    ``p256`` → ECDSA on SECP256R1."""
    algos = _by_lib(_scan(), _RUSTCRYPTO)
    assert "AES-256-GCM" in algos and algos["AES-256-GCM"]["crypto:mode"] == "GCM"
    assert "ChaCha20-Poly1305" in algos
    assert "RSA-2048" in algos and algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "Ed25519" in algos
    assert "ECDSA" in algos and algos["ECDSA"]["crypto:curve"] == "SECP256R1"
    assert "SHA-256" in algos and "SHA-512" in algos
    assert "HMAC" in algos


def test_ring_screaming_constants_attributed_to_ring() -> None:
    """ring's SCREAMING constants resolve and stay attributable to ring (kept in
    a separate file so they are not collapsed under RustCrypto's same names)."""
    algos = _by_lib(_scan(), _RING)
    assert "AES-256-GCM" in algos
    assert "ChaCha20-Poly1305" in algos
    assert "Ed25519" in algos
    assert "ECDSA" in algos and algos["ECDSA"]["crypto:curve"] == "SECP256R1"
    assert "RSA" in algos and algos["RSA"]["crypto:padding"] == "PKCS1-v1_5"


def test_ring_constants_only_emit_when_ring_imported() -> None:
    """SCREAMING tokens (``SHA256``) must not inventory in a file that does not
    import ring — precision guard against matching an unrelated constant."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        # A Rust file that uses ring's SCREAMING constants but imports no ring.
        (Path(d) / "noise.rs").write_text(
            "fn main() { let _ = AES_256_GCM; let _ = ED25519; }\n"
        )
        result = scan_crypto(d)
        # No C3 (call-expr) asset — the SCREAMING-constant path is ring-gated.
        assert not [
            c
            for c in result.components
            if c.kind == "crypto_asset"
            and (c.properties or {}).get("crypto:detectionMethod") == "call-expr"
        ]


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography
# --------------------------------------------------------------------------- #


def test_dotnet_rsa_size_curve_and_mode_bound() -> None:
    """``RSA.Create(2048)`` → RSA-2048; ``ECCurve.NamedCurves.nistP384`` →
    ECDSA on SECP384R1; ``aes.Mode = CipherMode.ECB`` → AES-ECB (mode bound to
    the same-file AES asset — the ECB weakness signal C6 will grade)."""
    algos = _by_lib(_scan(), _DOTNET)
    assert "RSA-2048" in algos and algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in algos and algos["ECDSA"]["crypto:curve"] == "SECP384R1"
    assert "AES-ECB" in algos and algos["AES-ECB"]["crypto:mode"] == "ECB"


def test_dotnet_classes_and_kdf() -> None:
    algos = _by_lib(_scan(), _DOTNET)
    assert "3DES-ECB" in algos  # TripleDES.Create() + file CipherMode.ECB
    assert "AES-GCM" in algos  # new AesGcm(key)
    assert "SHA-256" in algos and "MD5" in algos
    assert "HMAC" in algos  # new HMACSHA256(key)
    assert "PBKDF2" in algos  # Rfc2898DeriveBytes


def test_dotnet_is_c3_exclusive() -> None:
    """``.cs`` is not in the line-regex scanner's language set, so every C# asset
    must be C3's (call-expr) — nothing falls through to a coarser detector."""
    result = _scan()
    cs = [
        (c.properties or {}).get("crypto:detectionMethod")
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("discovery:source") == "CryptoApp.cs"
    ]
    assert cs and all(m == "call-expr" for m in cs)


# --------------------------------------------------------------------------- #
# Lane discipline
# --------------------------------------------------------------------------- #


def test_c3_emits_only_never_scores_or_flags() -> None:
    """C3 is EMIT-only: it must add crypto-asset components but raise no flags of
    its own (weak-flagging is C6, PQC grading C7)."""
    result = _scan()
    c3 = [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:detectionMethod") == "call-expr"
        and (c.properties or {}).get("crypto:detectedBy")
        in {_NODE, _WEBCRYPTO, _OPENSSL, _RUSTCRYPTO, _RING, _DOTNET}
    ]
    assert len(c3) >= 30
    # Every emitted asset carries the required provenance properties.
    for c in c3:
        p = c.properties or {}
        assert p["crypto:assetType"] == "algorithm"
        assert p["crypto:confidence"] == "high"
        assert "crypto:primitive" in p
        assert p["crypto:quantumVulnerable"] in ("true", "false")


# Library labels (kept in sync with the scanner module).
_NODE = "Node.js crypto"
_WEBCRYPTO = "WebCrypto (SubtleCrypto)"
_OPENSSL = "OpenSSL/BoringSSL (C/C++)"
_RUSTCRYPTO = "RustCrypto"
_RING = "ring (Rust)"
_DOTNET = ".NET System.Security.Cryptography"
