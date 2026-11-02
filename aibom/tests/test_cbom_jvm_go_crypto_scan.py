"""C2 — Java + Go crypto-API detection through the REGISTERED engine.

The Java/Go call-expression behaviour once lived in a separate, never-registered
scanner module; per the CBOM design rule (C2/C3 extend the ``detect.py`` tables,
not new scanners) it now lives in :mod:`aibom.cbom.detect` and these tests drive
the real pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the same fixture:

* JCA transformation split (algorithm / mode / padding from one literal), the
  ``SHA384withECDSA`` signature name, MAC / KDF entry points, and the RSA "ECB"
  misnomer that is not a mode;
* ``KeyPairGenerator.getInstance("RSA")`` + ``kpg.initialize(2048)`` bound across
  statements;
* Bouncy Castle engines and the block-mode wrapper they are nested in;
* Go ``block := aes.NewCipher(k)`` + ``cipher.NewGCM(block)`` bound through the
  block variable, never across a function boundary;
* call-site provenance (``crypto:detectedBy`` + ``crypto:detectionMethod=call-expr``).

Dropped from the old file (the deleted module's own contract, which the registered
path legitimately does not reproduce): ``crypto:detectionContext`` and
``crypto:confidence`` (the role is ``crypto:primitive``), library labels
``BouncyCastle (Java)`` (now ``Bouncy Castle``), curve normalisation to
``SECP384R1`` (the engine keeps the source spelling ``P384``), and the coarse
``HMAC`` / ``PBKDF2`` names (the engine folds the named hash: ``HMAC-SHA256``,
``PBKDF2-HMAC-SHA256``).
"""

from __future__ import annotations

import os

from aibom.cbom.detect import detect_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-jvm-go")

_JCA = "JCA/JCE (Java)"
_BC = "Bouncy Castle"
_GO = "Go crypto (stdlib)"
_GOX = "golang.org/x/crypto"


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
# Java — JCA/JCE
# --------------------------------------------------------------------------- #


def test_jca_transformation_string_split() -> None:
    """``Cipher.getInstance("AES/GCM/NoPadding")`` → AES + GCM + NoPadding."""
    algos = _algos(_scan(), "CryptoApp.java")
    assert "AES-GCM" in algos, f"JCA algorithms: {sorted(algos)}"
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"
    assert algos["AES-GCM"]["crypto:padding"] == "NoPadding"
    assert algos["DES-CBC"]["crypto:mode"] == "CBC"
    assert algos["DES-CBC"]["crypto:padding"] == "PKCS5Padding"


def test_jca_keypair_size_bound_across_statements() -> None:
    """``KeyPairGenerator.getInstance("RSA")`` + ``kpg.initialize(2048)`` →
    RSA-2048 (the size lives on a different statement, bound via the variable)."""
    algos = _algos(_scan(), "CryptoApp.java")
    assert "RSA-2048" in algos
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert algos["RSA-2048"]["crypto:primitive"] == "pke"
    assert algos["RSA-2048"]["crypto:detectedBy"] == _JCA


def test_jca_generator_size_binds_to_its_own_variable_only() -> None:
    src = (
        "import java.security.KeyPairGenerator;\n"
        "class K {\n"
        "  void a() throws Exception {\n"
        '    KeyPairGenerator big = KeyPairGenerator.getInstance("RSA");\n'
        '    KeyPairGenerator small = KeyPairGenerator.getInstance("DSA");\n'
        "    small.initialize(1024);\n"
        "    big.initialize(4096);\n"
        "  }\n"
        "}\n"
    )
    sized = {(d.key, d.key_size) for d in detect_crypto(src, "java")}
    assert ("rsa", 4096) in sized
    assert ("dsa", 1024) in sized


def test_jca_generator_size_not_bound_after_reassignment() -> None:
    src = (
        "import java.security.KeyPairGenerator;\n"
        "class K {\n"
        "  void a(KeyPairGenerator other) throws Exception {\n"
        '    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
        "    kpg = other;\n"
        "    kpg.initialize(1024);\n"
        "  }\n"
        "}\n"
    )
    rsa = [d for d in detect_crypto(src, "java") if d.key == "rsa"]
    assert rsa and all(d.key_size is None for d in rsa)


def test_jca_key_spec_is_the_key_of_the_cipher_not_a_second_row() -> None:
    src = (
        "import javax.crypto.Cipher;\n"
        "import javax.crypto.spec.SecretKeySpec;\n"
        "class C {\n"
        "  byte[] enc(byte[] p, byte[] key) throws Exception {\n"
        '    SecretKeySpec k = new SecretKeySpec(key, "AES");\n'
        '    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
        "    return c.doFinal(p);\n"
        "  }\n"
        "}\n"
    )
    aes = [(d.line_no, d.mode) for d in detect_crypto(src, "java") if d.key == "aes"]
    assert aes == [(6, "CBC")]
    alone = 'import javax.crypto.spec.SecretKeySpec;\nclass K { Object k(byte[] b) { return new SecretKeySpec(b, "AES"); } }\n'
    assert [d.key for d in detect_crypto(alone, "java")] == ["aes"]


def test_jca_signature_name_resolves_to_algorithm() -> None:
    """``Signature.getInstance("SHA384withECDSA")`` resolves to the ECDSA
    signature algorithm (and its SHA-384 digest), not a bare digest."""
    algos = _algos(_scan(), "CryptoApp.java")
    assert algos["ECDSA"]["crypto:primitive"] == "signature"
    assert algos["SHA-384"]["crypto:primitive"] == "hash"


def test_jca_digest_vs_signature_role_disambiguation() -> None:
    """``MessageDigest.getInstance("SHA-256")`` is a hash."""
    algos = _algos(_scan(), "CryptoApp.java")
    assert algos["SHA-256"]["crypto:primitive"] == "hash"
    assert algos["SHA-256"]["crypto:detectedBy"] == _JCA


def test_jca_mac_and_kdf_entry_points() -> None:
    algos = _algos(_scan(), "CryptoApp.java")
    assert algos["HMAC-SHA256"]["crypto:primitive"] == "mac"
    assert algos["PBKDF2-HMAC-SHA256"]["crypto:primitive"] == "kdf"


def test_jca_rsa_mode_misnomer_not_attached() -> None:
    """``RSA/ECB/OAEP...`` — JCA's "ECB" field is a misnomer for RSA; only the
    OAEP padding is captured, no bogus mode on a pke asset."""
    algos = _algos(_scan(), "CryptoApp.java")
    assert "crypto:mode" not in algos["RSA"]
    assert algos["RSA"]["crypto:padding"].startswith("OAEP")


# --------------------------------------------------------------------------- #
# Java — Bouncy Castle
# --------------------------------------------------------------------------- #


def test_bouncycastle_engine_and_nested_mode_wrapper() -> None:
    """``new CBCBlockCipher(new DESedeEngine())`` → 3DES-CBC; the digest/signer
    engine classes resolve from the class name."""
    bc = _algos(_scan(), "CryptoApp.java")
    assert bc["3DES-CBC"]["crypto:mode"] == "CBC"
    assert bc["3DES-CBC"]["crypto:detectedBy"] == _BC
    assert bc["SHA-1"]["crypto:detectedBy"] == _BC
    assert bc["Ed25519"]["crypto:primitive"] == "signature"


def test_bouncycastle_sic_wrapper_is_ctr() -> None:
    dets = detect_crypto(
        "import org.bouncycastle.crypto.engines.AESEngine;\n"
        "class C { Object m() { return new SICBlockCipher(new AESEngine()); } }\n",
        "java",
    )
    assert any(d.key == "aes" and d.mode == "CTR" for d in dets)


# --------------------------------------------------------------------------- #
# Go — stdlib + x/crypto
# --------------------------------------------------------------------------- #


def test_go_block_mode_variable_binding() -> None:
    """``block := aes.NewCipher(key)`` then ``cipher.NewGCM(block)`` → AES-GCM;
    a second ``block`` (3DES) + ``cipher.NewCBCEncrypter`` → 3DES-CBC."""
    go = _algos(_scan(), "crypto_app.go")
    assert go["AES-GCM"]["crypto:mode"] == "GCM", f"Go algorithms: {sorted(go)}"
    assert go["AES-GCM"]["crypto:detectedBy"] == _GO
    assert go["3DES-CBC"]["crypto:mode"] == "CBC"
    # The ``func aesGCM(`` identifier is not a use of AES: no mode-less AES row.
    assert "AES" not in go


def test_go_mode_never_binds_across_a_function_boundary() -> None:
    src = (
        "package p\n"
        'import ("crypto/aes"; "crypto/cipher")\n'
        "func a(k []byte) {\n"
        "\tblock, _ := aes.NewCipher(k)\n"
        "\t_ = block\n"
        "}\n"
        "func b(block cipher.Block, iv []byte) {\n"
        "\t_ = cipher.NewCBCEncrypter(block, iv)\n"
        "}\n"
    )
    aes = [d for d in detect_crypto(src, "go") if d.key == "aes"]
    assert aes and all(d.mode is None for d in aes)


def test_go_rsa_keysize_and_ecdsa_curve() -> None:
    go = _algos(_scan(), "crypto_app.go")
    assert go["RSA-2048"]["crypto:keySize"] == "2048"
    # the curve is bound from the GenerateKey call, not lost to the earlier
    # ``func ecdsaKey() (*ecdsa.PrivateKey ...`` mention of the same asset
    assert go["ECDSA"]["crypto:curve"] == "P384"
    assert "Ed25519" in go


def test_go_digests_and_mac() -> None:
    go = _algos(_scan(), "crypto_app.go")
    assert go["SHA-256"]["crypto:primitive"] == "hash"
    assert "MD5" in go
    assert go["HMAC"]["crypto:detectedBy"] == _GO


def test_go_x_crypto_constructions() -> None:
    go = _algos(_scan(), "crypto_app.go")
    for name in ("ChaCha20-Poly1305", "bcrypt", "Argon2"):
        assert go[name]["crypto:detectedBy"] == _GOX, name


# --------------------------------------------------------------------------- #
# Provenance, determinism, isolation.
# --------------------------------------------------------------------------- #


def test_every_call_expr_asset_carries_provenance() -> None:
    result = _scan()
    call_expr = [
        c for c in result.components
        if (c.properties or {}).get("crypto:detectionMethod") == "call-expr"
    ]
    assert call_expr, "no call-expr algorithms detected"
    libraries = {(c.properties or {}).get("crypto:detectedBy") for c in call_expr}
    assert {_JCA, _BC, _GO, _GOX} <= libraries


def test_quantum_vulnerable_flag_carried() -> None:
    algos = _algos(_scan(), "CryptoApp.java")
    assert algos["RSA-2048"]["crypto:quantumVulnerable"] == "true"
    assert algos["AES-GCM"]["crypto:quantumVulnerable"] == "false"


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    refs_a = [(c.kind, c.bom_ref) for c in a.components]
    refs_b = [(c.kind, c.bom_ref) for c in b.components]
    assert refs_a == refs_b


def test_no_separate_jvm_go_scanner_is_registered() -> None:
    import aibom.cbom.pipeline  # noqa: F401  (registers the CBOM scanners)
    from aibom.cbom.registry import ordered_cbom_scanners
    from aibom.scan.registry import SCANNERS

    names = {s.name for s in ordered_cbom_scanners()}
    assert "crypto_jvm_go" not in names
    assert not any(s.name.startswith("crypto_") for s in SCANNERS)


def test_no_java_go_provenance_on_pure_python_fixture() -> None:
    shared = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    libs = {
        (c.properties or {}).get("crypto:detectedBy")
        for c in _scan(shared).components
    }
    assert not libs & {_JCA, _BC, _GO, _GOX}
