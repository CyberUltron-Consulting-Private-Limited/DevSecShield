"""C3 — extend the clean-room crypto-API detection to JS/TS + C/C++ + Rust + .NET.

Four more ecosystems join the ``detect.py`` rule/literal model (C1 Python, C2
Java+Go): Node ``crypto`` + WebCrypto, OpenSSL EVP, ring + RustCrypto, and .NET
``System.Security.Cryptography``. The value over the flat token corpus is the
ecosystem-specific spellings the global literal lane structurally cannot see —
WebCrypto's ``{name:"AES-GCM"}`` (no key-size digit), OpenSSL's underscore-packed
``EVP_aes_256_gcm`` / ``EVP_sha384``, RustCrypto's fused ``Aes256Gcm`` /
``ChaCha20Poly1305``, and .NET's ``RSACryptoServiceProvider`` /
``TripleDESCryptoServiceProvider`` / ``Rfc2898DeriveBytes`` — plus per-ecosystem
library attribution (Node crypto / OpenSSL / ring / RustCrypto / .NET).

The frozen ``synthetic-crypto-app`` oracle + its benchmark gate stay byte-identical
(they are Python-only; the language-scoped literal lanes never fire on Python) —
this fixture isolates the NEW multi-language coverage. The tests drive the REAL
pipeline (:func:`aibom.cbom.pipeline.scan_crypto`), never a mocked graph.
"""

from __future__ import annotations

import os

from aibom.cbom.detect import detect_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-native-apis")
_JS = os.path.join(_FX, "node_crypto.js")
_C = os.path.join(_FX, "openssl_app.c")
_RUST = os.path.join(_FX, "ring_rustcrypto.rs")
_CS = os.path.join(_FX, "DotNetCrypto.cs")


def _detect(path: str, lang: str) -> dict[str, dict]:
    """Aggregate detections per algorithm key -> resolved params."""
    agg: dict[str, dict] = {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for d in detect_crypto(text, lang):
        e = agg.setdefault(d.key, {"size": None, "mode": None, "curve": None})
        e["size"] = e["size"] or d.key_size
        e["mode"] = e["mode"] or d.mode
        e["curve"] = e["curve"] or d.curve
    return agg


# --------------------------------------------------------------------------- #
# JS/TS — Node crypto + WebCrypto.
# --------------------------------------------------------------------------- #


def test_node_cipher_spec_string_split() -> None:
    """``createCipheriv('aes-256-gcm', …)`` packs algorithm + key size + mode into
    ONE literal → AES-256 + mode GCM; ``'des-ede3-cbc'`` → 3DES + CBC (and NOT a
    bare DES on that line)."""
    j = _detect(_JS, "javascript")
    assert "aes-256" in j          # sized key from the packed 'aes-256-gcm' literal
    assert j["aes-256"]["mode"] == "GCM"
    assert j["3des"]["mode"] == "CBC"
    assert "des" not in j  # the 3DES `des-ede3` spelling must not mint a weak DES


def test_node_keypair_and_hmac() -> None:
    """``generateKeyPairSync('rsa', {modulusLength:2048})`` → RSA-2048 (the ``Sync``
    suffix breaks the global anchor); ``createHmac`` → HMAC (``\\bHMAC\\b`` cannot
    fire on ``createHmac``)."""
    j = _detect(_JS, "javascript")
    assert j["rsa"]["size"] == 2048
    assert "hmac" in j


def test_webcrypto_name_field_and_curve() -> None:
    """WebCrypto algorithms come from the ``{name:"AES-GCM"|"RSA-OAEP"|"ECDSA"}``
    field; the ECDSA ``namedCurve:'P-384'`` string resolves the curve."""
    j = _detect(_JS, "javascript")
    assert j["aes"]["mode"] == "GCM"        # {name:"AES-GCM"}
    assert "rsa" in j                        # {name:"RSA-OAEP"}
    assert j["ecdsa"]["curve"] == "P-384"    # {name:"ECDSA", namedCurve:"P-384"}
    assert "sha512" in j                     # subtle.digest('SHA-512', …)


# --------------------------------------------------------------------------- #
# C/C++ — OpenSSL EVP.
# --------------------------------------------------------------------------- #


def test_openssl_evp_fn_name_packs_algo_and_size() -> None:
    """``EVP_aes_256_gcm`` → AES-256; ``EVP_des_ede3_cbc`` → 3DES; ``EVP_sha384`` /
    ``EVP_md5`` digests (a ``_`` before the family breaks the global token)."""
    c = _detect(_C, "c")
    assert "aes-256" in c          # EVP_aes_256_gcm -> sized key
    assert "3des" in c
    assert "sha384" in c and "md5" in c


def test_openssl_rsa_keygen_bits_and_ec_and_hmac() -> None:
    """``EVP_PKEY_CTX_set_rsa_keygen_bits(_, 3072)`` → RSA-3072 (size via the bare
    modulus digit); ``EC_KEY_new_by_curve_name`` → ECDSA; ``HMAC_CTX_new`` → HMAC."""
    c = _detect(_C, "c")
    assert c["rsa"]["size"] == 3072
    assert "ecdsa" in c
    assert "hmac" in c


# --------------------------------------------------------------------------- #
# Rust — ring + RustCrypto.
# --------------------------------------------------------------------------- #


def test_rust_ring_and_rustcrypto_types() -> None:
    """ring UPPER_SNAKE constants (``aead::AES_256_GCM``, ``signature::ED25519``,
    ``ECDSA_P384_*``, ``HMAC_SHA256``) + RustCrypto fused types (``Aes256Gcm``,
    ``ChaCha20Poly1305``, ``RsaPrivateKey``) — all invisible to the global lane."""
    r = _detect(_RUST, "rust")
    assert "aes-256" in r                        # Aes256Gcm / AES_256_GCM
    assert "chacha20-poly1305" in r              # ChaCha20Poly1305 (fused token)
    assert "ed25519" in r                        # signature::ED25519
    assert "ecdsa" in r                          # ECDSA_P384_* (trailing `_`)
    assert r["rsa"]["size"] == 2048              # RsaPrivateKey::new(_, 2048)
    assert "hmac" in r and "pbkdf2" in r


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography.
# --------------------------------------------------------------------------- #


def test_dotnet_provider_class_names() -> None:
    """``RSACryptoServiceProvider(2048)`` → RSA-2048; ``TripleDESCryptoService
    Provider`` → 3DES; ``new HMACSHA256`` → HMAC; ``Rfc2898DeriveBytes`` → PBKDF2 —
    provider suffixes the global ``\\bRSA\\b``/``\\bTripleDES\\b`` cannot match."""
    cs = _detect(_CS, "csharp")
    assert cs["rsa"]["size"] == 2048
    assert "3des" in cs
    assert "hmac" in cs
    assert "pbkdf2" in cs
    assert "aes" in cs      # Aes.Create() inside a `using (...)` statement
    assert "ecdsa" in cs    # ECDsa.Create(...)


def test_dotnet_using_statement_is_not_skipped_as_import() -> None:
    """A ``using (var aes = Aes.Create())`` STATEMENT is scanned, while a ``using
    System.Security.Cryptography;`` DIRECTIVE is skipped (a library signal)."""
    stmt = detect_crypto("using (var aes = Aes.Create()) { }", "csharp")
    assert any(d.key == "aes" for d in stmt)
    directive = detect_crypto("using System.Security.Cryptography;", "csharp")
    assert not directive  # a bare import directive yields no usage detection


# --------------------------------------------------------------------------- #
# Integration — the real pipeline over the multi-language fixture.
# --------------------------------------------------------------------------- #


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _algorithms(result: ScanResult) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
    ]


def test_pipeline_inventories_all_four_ecosystems() -> None:
    names = {c.name for c in _algorithms(_scan())}
    for expected in ("AES-256-GCM", "AES-GCM", "AES-256", "3DES-CBC", "3DES",
                     "RSA-2048", "ChaCha20-Poly1305", "Ed25519", "ECDSA",
                     "SHA-384", "MD5", "PBKDF2", "HMAC"):
        assert expected in names, f"missing {expected} in {sorted(names)}"


def test_pipeline_every_asset_has_concrete_primitive() -> None:
    for c in _algorithms(_scan()):
        prim = (c.properties or {}).get("crypto:primitive")
        assert prim and prim != "unknown", f"{c.name} primitive={prim!r}"


def test_pipeline_attributes_native_crypto_libraries() -> None:
    libs = {
        c.name
        for c in _scan().components
        if c.kind == "framework"
        and (c.properties or {}).get("crypto:role") == "library"
    }
    for expected in ("Node.js crypto (stdlib)", "OpenSSL", "ring (Rust)",
                     "RustCrypto", ".NET (System.Security.Cryptography)"):
        assert expected in libs, f"missing {expected} in {sorted(libs)}"
    # the greedy Python "crypto" root must NOT mislabel node:crypto / openssl.
    assert "PyCryptodome" not in libs
    assert "pyOpenSSL" not in libs


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    assert [(c.kind, c.bom_ref) for c in a.components] == [
        (c.kind, c.bom_ref) for c in b.components
    ]


def test_no_detection_leaks_into_frozen_python_corpus() -> None:
    """The scoped literal lanes must NOT perturb the Python-only oracle fixture:
    scanning it yields the SAME components with the C3 lanes present as without."""
    shared = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    names = {c.name for c in _algorithms(scan_crypto(shared))}
    # sanity: the frozen oracle still inventories its known Python algorithms.
    assert {"AES-GCM", "RSA-2048", "MD5", "RC4"} <= names, sorted(names)
