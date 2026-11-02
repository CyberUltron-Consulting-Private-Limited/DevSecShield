"""C3 — JS/TS + C/C++ + Rust + .NET call-argument binding through the REGISTERED engine.

Second fixture (``tests/fixtures/synthetic-crypto-web-native``) for the behaviour a
separate, never-registered module used to own (AGENTS.md: that branch was
rejected; C3 extends ``detect.py``). Asserted through
:func:`aibom.cbom.pipeline.scan_crypto`:

* a Node cipher literal splits into algorithm + size + mode, as ONE asset;
* the ``generateKeyPairSync('rsa', {`` options object binds ``modulusLength`` /
  ``namedCurve`` from the following lines;
* OpenSSL / ring / RustCrypto names carry size + mode;
* .NET ``aes.Mode`` / ``aes.KeySize`` bind across statements to their instance.

Dropped from the old file (the deleted module's own contract): ``detectedBy`` /
``detectionContext`` / ``confidence`` provenance (these ecosystems run on literal
lanes), keeping AES-256 coarse as ``AES-GCM`` for bom-ref parity (the engine names
it ``AES-256-GCM``), and the NID / ``nistP521`` / ring curve normalisations.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-web-native")


def _scan(path: str = _FX) -> ScanResult:
    return scan_crypto(path)


def _algos(result: ScanResult, source: str) -> dict[str, dict]:
    return {
        c.name: (c.properties or {})
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
        and (c.properties or {}).get("discovery:source") == source
    }


# --------------------------------------------------------------------------- #
# Node.js
# --------------------------------------------------------------------------- #


def test_node_cipheriv_literal_split() -> None:
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["AES-256-GCM"]["crypto:mode"] == "GCM", f"Node algorithms: {sorted(algos)}"
    assert algos["AES-256-GCM"]["crypto:keySize"] == "256"
    assert algos["3DES-CBC"]["crypto:mode"] == "CBC"
    assert "AES-GCM" not in algos  # one call, one asset


def test_node_keypair_modulus_and_curve_bound() -> None:
    """``generateKeyPairSync('rsa', {`` with ``modulusLength: 2048`` on a LATER
    line → RSA-2048; ``namedCurve: 'P-384'`` likewise binds to the EC call."""
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert algos["RSA-2048"]["crypto:primitive"] == "pke"
    assert algos["ECDSA"]["crypto:curve"] == "P-384"


def test_node_hash_and_mac_roles() -> None:
    algos = _algos(_scan(), "crypto_app.js")
    assert algos["SHA-256"]["crypto:primitive"] == "hash"
    assert "MD5" in algos
    assert algos["HMAC"]["crypto:primitive"] == "mac"


def test_webcrypto_name_field_and_digest_string() -> None:
    wc = _algos(_scan(), "crypto_app.js")
    assert wc["AES-CBC"]["crypto:mode"] == "CBC"
    assert wc["SHA-512"]["crypto:primitive"] == "hash"
    assert wc["PBKDF2"]["crypto:primitive"] == "kdf"


# --------------------------------------------------------------------------- #
# OpenSSL (C)
# --------------------------------------------------------------------------- #


def test_openssl_evp_fn_name_packs_algo_size_mode() -> None:
    c = _algos(_scan(), "openssl_app.c")
    assert c["AES-256-GCM"]["crypto:mode"] == "GCM", f"OpenSSL algorithms: {sorted(c)}"
    assert c["AES-256-GCM"]["crypto:keySize"] == "256"
    assert c["3DES-CBC"]["crypto:mode"] == "CBC"
    assert "SHA-384" in c and "MD5" in c


def test_openssl_rsa_bits() -> None:
    c = _algos(_scan(), "openssl_app.c")
    assert c["RSA-3072"]["crypto:keySize"] == "3072"
    assert "ECDSA" in c and "HMAC" in c


# --------------------------------------------------------------------------- #
# Rust
# --------------------------------------------------------------------------- #


def test_ring_module_constants() -> None:
    r = _algos(_scan(), "ring_app.rs")
    assert r["AES-128-GCM"]["crypto:keySize"] == "128", f"ring algorithms: {sorted(r)}"
    assert r["AES-128-GCM"]["crypto:mode"] == "GCM"
    assert "ChaCha20-Poly1305" in r
    assert "SHA-256" in r and "SHA-1" in r  # digest::SHA1_FOR_LEGACY_USE_ONLY
    assert "Ed25519" in r and "ECDSA" in r
    assert "HMAC" in r and "PBKDF2" in r


def test_ring_legacy_sha1_is_flagged() -> None:
    result = _scan()
    sha1 = [c for c in result.components
            if c.name == "SHA-1" and (c.properties or {}).get("discovery:source") == "ring_app.rs"]
    assert sha1
    assert result.flags_for(sha1[0].bom_ref)


def test_rustcrypto_types() -> None:
    rc = _algos(_scan(), "rustcrypto_app.rs")
    assert rc["AES-256-GCM"]["crypto:keySize"] == "256"
    assert "SHA-512" in rc
    assert rc["RSA-2048"]["crypto:primitive"] == "pke"
    assert "HMAC" in rc


# --------------------------------------------------------------------------- #
# .NET
# --------------------------------------------------------------------------- #


def test_dotnet_aes_mode_and_keysize_bound_across_statements() -> None:
    net = _algos(_scan(), "CryptoApp.cs")
    assert "AES-256-CBC" in net, f".NET algorithms: {sorted(net)}"
    assert net["AES-256-CBC"]["crypto:mode"] == "CBC"
    assert net["AES-256-CBC"]["crypto:keySize"] == "256"
    assert net["AES-GCM"]["crypto:mode"] == "GCM"


def test_dotnet_rsa_arg_and_providers() -> None:
    net = _algos(_scan(), "CryptoApp.cs")
    assert net["RSA-2048"]["crypto:keySize"] == "2048"
    for name in ("ECDSA", "3DES", "SHA-384", "MD5", "HMAC", "PBKDF2"):
        assert name in net, name


# --------------------------------------------------------------------------- #
# Graph facts carried for the downstream lanes.
# --------------------------------------------------------------------------- #


def test_quantum_vulnerable_flag_carried() -> None:
    result = _scan()
    assert _algos(result, "CryptoApp.cs")["RSA-2048"]["crypto:quantumVulnerable"] == "true"
    assert _algos(result, "crypto_app.js")["AES-256-GCM"]["crypto:quantumVulnerable"] == "false"
    assert _algos(result, "ring_app.rs")["Ed25519"]["crypto:quantumVulnerable"] == "true"


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    assert [(c.kind, c.bom_ref) for c in a.components] == [(c.kind, c.bom_ref) for c in b.components]


def test_no_native_assets_on_pure_python_fixture() -> None:
    shared = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    native = {".js", ".ts", ".c", ".rs", ".cs"}
    sources = {
        os.path.splitext((c.properties or {}).get("discovery:source") or "")[1]
        for c in _scan(shared).components
    }
    assert not sources & native
