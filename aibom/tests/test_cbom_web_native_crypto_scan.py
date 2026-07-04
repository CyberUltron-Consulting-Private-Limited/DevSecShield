"""C3 — JS/TS + C/C++ + Rust + .NET crypto-API scanner (call-expression model).

These tests pin the capabilities a flat line-regex cannot have for the four
remaining languages of the R2 matrix: Node's ``aes-256-gcm`` literal split into
algorithm + key size + mode, ``generateKeyPair('rsa',{modulusLength})`` /
``('ec',{namedCurve})`` cross-statement option binding, WebCrypto's
``{name:"AES-CBC"}`` field, OpenSSL's ``EVP_aes_256_gcm`` fn-name packing +
``set_rsa_keygen_bits`` + ``EC_KEY_new_by_curve_name(NID_…)``, ring module
constants + RustCrypto types, and .NET's ``CipherMode`` / ``KeySize`` bound to
its AES variable. The tests drive the REAL pipeline
(:func:`aibom.cbom.pipeline.scan_crypto`) — never a mocked graph.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-web-native")

_C3_LIBS = {
    "Node crypto (Node.js)", "WebCrypto API", "OpenSSL (C/C++)",
    "ring (Rust)", "RustCrypto", ".NET System.Security.Cryptography",
}


def _scan(path: str = _FX) -> ScanResult:
    return scan_crypto(path)


def _by_lib(result: ScanResult, *libraries: str) -> dict[str, dict]:
    """name -> properties, for call-expr algorithm assets from the given libs
    (defaults to the full C3 library set)."""
    want = set(libraries) or _C3_LIBS
    return {
        c.name: (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
        and (c.properties or {}).get("crypto:detectionMethod") == "call-expr"
        and (c.properties or {}).get("crypto:detectedBy") in want
    }


# --------------------------------------------------------------------------- #
# JS/TS — Node crypto
# --------------------------------------------------------------------------- #


def test_node_cipheriv_literal_split() -> None:
    """``createCipheriv('aes-256-gcm', …)`` → AES + GCM + keySize 256, with the
    256 in the property only (name stays AES-GCM for ref parity with regex)."""
    algos = _by_lib(_scan(), "Node crypto (Node.js)")
    assert "AES-GCM" in algos, f"Node algorithms: {sorted(algos)}"
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"
    assert algos["AES-GCM"]["crypto:keySize"] == "256"
    assert "3DES-CBC" in algos
    assert algos["3DES-CBC"]["crypto:mode"] == "CBC"


def test_node_keypair_modulus_and_curve_bound() -> None:
    """``generateKeyPair('rsa',{modulusLength:2048})`` → RSA-2048 and
    ``('ec',{namedCurve:'P-384'})`` → ECDSA on SECP384R1 — both bound from the
    options object on a later line."""
    algos = _by_lib(_scan(), "Node crypto (Node.js)")
    assert "RSA-2048" in algos
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert algos["RSA-2048"]["crypto:primitive"] == "pke"
    assert "ECDSA" in algos
    assert algos["ECDSA"]["crypto:curve"] == "SECP384R1"


def test_node_hash_and_mac_roles() -> None:
    algos = _by_lib(_scan(), "Node crypto (Node.js)")
    assert algos["SHA-256"]["crypto:primitive"] == "hash"
    assert "MD5" in algos
    assert algos["HMAC"]["crypto:primitive"] == "mac"


# --------------------------------------------------------------------------- #
# JS/TS — WebCrypto
# --------------------------------------------------------------------------- #


def test_webcrypto_name_field_and_digest_string() -> None:
    """WebCrypto algorithms come from the ``{name:"AES-CBC"}`` field and the
    ``subtle.digest('SHA-512')`` string; PBKDF2 from a deriveBits name."""
    wc = _by_lib(_scan(), "WebCrypto API")
    assert "AES-CBC" in wc, f"WebCrypto algorithms: {sorted(wc)}"
    assert wc["AES-CBC"]["crypto:mode"] == "CBC"
    assert "SHA-512" in wc and wc["SHA-512"]["crypto:primitive"] == "hash"
    assert "PBKDF2" in wc and wc["PBKDF2"]["crypto:primitive"] == "kdf"


# --------------------------------------------------------------------------- #
# C/C++ — OpenSSL EVP
# --------------------------------------------------------------------------- #


def test_openssl_evp_fn_name_packs_algo_size_mode() -> None:
    """``EVP_aes_256_gcm()`` → AES + GCM + keySize 256; ``EVP_des_ede3_cbc()``
    → 3DES-CBC; ``EVP_sha384()`` / ``EVP_md5()`` digests."""
    c = _by_lib(_scan(), "OpenSSL (C/C++)")
    assert "AES-GCM" in c, f"OpenSSL algorithms: {sorted(c)}"
    assert c["AES-GCM"]["crypto:mode"] == "GCM"
    assert c["AES-GCM"]["crypto:keySize"] == "256"
    assert "3DES-CBC" in c
    assert "SHA-384" in c and "MD5" in c


def test_openssl_rsa_bits_and_ec_curve_nid() -> None:
    c = _by_lib(_scan(), "OpenSSL (C/C++)")
    assert "RSA-3072" in c and c["RSA-3072"]["crypto:keySize"] == "3072"
    assert "ECDSA" in c and c["ECDSA"]["crypto:curve"] == "SECP521R1"
    assert "HMAC" in c


# --------------------------------------------------------------------------- #
# Rust — ring + RustCrypto
# --------------------------------------------------------------------------- #


def test_ring_module_constants() -> None:
    r = _by_lib(_scan(), "ring (Rust)")
    assert "AES-GCM" in r, f"ring algorithms: {sorted(r)}"
    assert r["AES-GCM"]["crypto:keySize"] == "128"
    assert "ChaCha20-Poly1305" in r
    assert "SHA-256" in r and "SHA-1" in r
    assert "Ed25519" in r
    assert "ECDSA" in r and r["ECDSA"]["crypto:curve"] == "SECP384R1"
    assert "HMAC" in r and "PBKDF2" in r


def test_rustcrypto_types() -> None:
    """RustCrypto assets live in a separate file so AES-GCM / SHA do not collide
    with ring's on (name, location)."""
    rc = _by_lib(_scan(), "RustCrypto")
    assert "AES-GCM" in rc and rc["AES-GCM"]["crypto:keySize"] == "256"
    assert "SHA-512" in rc
    assert "RSA" in rc and rc["RSA"]["crypto:primitive"] == "pke"
    assert "HMAC" in rc


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography
# --------------------------------------------------------------------------- #


def test_dotnet_aes_mode_and_keysize_bound_across_statements() -> None:
    """``Aes.Create()`` + ``aes.KeySize=256`` + ``aes.Mode=CipherMode.CBC`` →
    AES-CBC keySize 256; ``new AesGcm`` → AES-GCM (inline mode)."""
    net = _by_lib(_scan(), ".NET System.Security.Cryptography")
    assert "AES-CBC" in net, f".NET algorithms: {sorted(net)}"
    assert net["AES-CBC"]["crypto:mode"] == "CBC"
    assert net["AES-CBC"]["crypto:keySize"] == "256"
    assert "AES-GCM" in net and net["AES-GCM"]["crypto:mode"] == "GCM"


def test_dotnet_rsa_arg_ec_curve_and_providers() -> None:
    net = _by_lib(_scan(), ".NET System.Security.Cryptography")
    assert "RSA-2048" in net and net["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in net and net["ECDSA"]["crypto:curve"] == "SECP521R1"
    assert "3DES" in net
    assert "SHA-384" in net and "MD5" in net
    assert "HMAC" in net and "PBKDF2" in net


# --------------------------------------------------------------------------- #
# Provenance, additivity, determinism.
# --------------------------------------------------------------------------- #


def test_every_call_expr_asset_carries_provenance() -> None:
    algos = _by_lib(_scan())
    assert algos, "no C3 call-expr algorithms detected"
    for name, props in algos.items():
        assert props.get("crypto:detectedBy") in _C3_LIBS, name
        assert props.get("crypto:detectionContext"), f"{name} missing context"
        assert props.get("crypto:confidence") == "high", name


def test_quantum_vulnerable_flag_carried() -> None:
    """RSA/ECDSA/Ed25519 carry crypto:quantumVulnerable=true for the C7 grader;
    AES/SHA carry false."""
    algos = _by_lib(_scan())
    assert algos["RSA-2048"]["crypto:quantumVulnerable"] == "true"
    assert algos["AES-GCM"]["crypto:quantumVulnerable"] == "false"
    assert algos["Ed25519"]["crypto:quantumVulnerable"] == "true"


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    refs_a = [(c.kind, c.bom_ref) for c in a.components]
    refs_b = [(c.kind, c.bom_ref) for c in b.components]
    assert refs_a == refs_b


def test_scanner_does_not_leak_into_aibom_pipeline() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_web_native" for s in SCANNERS)


def test_no_false_positives_on_pure_python_fixture() -> None:
    """The C3 scanner emits nothing for a Python-only repo (the shared oracle
    fixture), so it never perturbs the C1 inventory or the differential gate."""
    shared = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    assert not _by_lib(_scan(shared))
