"""C2 — Java + Go crypto-API scanner (call-expression model + library→asset maps).

These tests pin the capabilities a flat line-regex cannot have for the JVM/Go
languages: JCA transformation-string split (algo/mode/padding from one literal),
the standard ``SHA256withRSA`` signature name → signature algorithm, cross-
statement key-size binding from ``KeyPairGenerator.initialize(int)``, BouncyCastle
engine + nested mode-wrapper resolution, and Go's block→mode variable binding
(``aes.NewCipher`` + ``cipher.NewGCM(block)`` → AES-GCM) plus ``rsa.GenerateKey``
key size and ``ecdsa.GenerateKey(elliptic.P384())`` curve. The tests drive the
REAL pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) — never a mocked graph.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-jvm-go")


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
# Java — JCA/JCE
# --------------------------------------------------------------------------- #


def test_jca_transformation_string_split() -> None:
    """``Cipher.getInstance("AES/GCM/NoPadding")`` → AES + GCM + NoPadding."""
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "AES-GCM" in algos, f"JCA algorithms: {sorted(algos)}"
    assert algos["AES-GCM"]["crypto:mode"] == "GCM"
    assert algos["AES-GCM"]["crypto:padding"] == "NoPadding"
    assert "DES-CBC" in algos
    assert algos["DES-CBC"]["crypto:mode"] == "CBC"


def test_jca_keypair_size_bound_across_statements() -> None:
    """``KeyPairGenerator.getInstance("RSA")`` + ``kpg.initialize(2048)`` →
    RSA-2048 (the size lives on a different statement, bound via the variable)."""
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "RSA-2048" in algos
    assert algos["RSA-2048"]["crypto:keySize"] == "2048"
    assert algos["RSA-2048"]["crypto:primitive"] == "pke"


def test_jca_signature_name_resolves_to_algorithm() -> None:
    """``Signature.getInstance("SHA384withECDSA")`` resolves to the ECDSA
    signature algorithm with the signature primitive role (not a digest)."""
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "ECDSA" in algos
    assert algos["ECDSA"]["crypto:detectionContext"] == "signature"
    assert algos["ECDSA"]["crypto:primitive"] == "signature"


def test_jca_digest_vs_signature_role_disambiguation() -> None:
    """The same SHA-256 token under ``MessageDigest`` is a hash; under
    ``Signature`` it qualifies a signature — the entry point fixes the role."""
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "SHA-256" in algos
    assert algos["SHA-256"]["crypto:detectionContext"] == "digest"
    assert algos["SHA-256"]["crypto:primitive"] == "hash"


def test_jca_mac_and_kdf_entry_points() -> None:
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "HMAC" in algos and algos["HMAC"]["crypto:primitive"] == "mac"
    assert "PBKDF2" in algos and algos["PBKDF2"]["crypto:primitive"] == "kdf"


def test_jca_rsa_mode_misnomer_not_attached() -> None:
    """``RSA/ECB/OAEP...`` — JCA's "ECB" field is a misnomer for RSA; only the
    OAEP padding is captured, no bogus mode on a pke asset."""
    algos = _by_lib(_scan(), "JCA/JCE (Java)")
    assert "RSA" in algos
    assert "crypto:mode" not in algos["RSA"]
    assert algos["RSA"].get("crypto:padding", "").startswith("OAEP")


# --------------------------------------------------------------------------- #
# Java — BouncyCastle
# --------------------------------------------------------------------------- #


def test_bouncycastle_engine_and_nested_mode_wrapper() -> None:
    """``new CBCBlockCipher(new DESedeEngine())`` → 3DES-CBC; the digest/signer
    engine classes resolve from the class name."""
    bc = _by_lib(_scan(), "BouncyCastle (Java)")
    assert "3DES-CBC" in bc, f"BC algorithms: {sorted(bc)}"
    assert bc["3DES-CBC"]["crypto:mode"] == "CBC"
    assert "SHA-1" in bc
    assert "Ed25519" in bc and bc["Ed25519"]["crypto:detectionContext"] == "signature"


# --------------------------------------------------------------------------- #
# Go — stdlib + x/crypto
# --------------------------------------------------------------------------- #


def test_go_block_mode_variable_binding() -> None:
    """``block := aes.NewCipher(key)`` then ``cipher.NewGCM(block)`` → AES-GCM;
    a second ``block`` (3DES) + ``cipher.NewCBCEncrypter`` → 3DES-CBC, with no
    cross-function mode leakage."""
    go = _by_lib(_scan(), "Go crypto (stdlib)")
    assert "AES-GCM" in go, f"Go stdlib algorithms: {sorted(go)}"
    assert go["AES-GCM"]["crypto:mode"] == "GCM"
    assert "3DES-CBC" in go
    assert go["3DES-CBC"]["crypto:mode"] == "CBC"


def test_go_rsa_keysize_and_ecdsa_curve() -> None:
    go = _by_lib(_scan(), "Go crypto (stdlib)")
    assert "RSA-2048" in go and go["RSA-2048"]["crypto:keySize"] == "2048"
    assert "ECDSA" in go and go["ECDSA"]["crypto:curve"] == "SECP384R1"
    assert "Ed25519" in go


def test_go_digests_and_mac() -> None:
    go = _by_lib(_scan(), "Go crypto (stdlib)")
    assert "SHA-256" in go and go["SHA-256"]["crypto:primitive"] == "hash"
    assert "MD5" in go
    assert "HMAC" in go


def test_go_x_crypto_constructions() -> None:
    gox = _by_lib(_scan(), "golang.org/x/crypto")
    assert "ChaCha20-Poly1305" in gox, f"x/crypto algorithms: {sorted(gox)}"
    assert "bcrypt" in gox
    assert "Argon2" in gox


# --------------------------------------------------------------------------- #
# Provenance, additivity, determinism.
# --------------------------------------------------------------------------- #


def test_every_call_expr_asset_carries_provenance() -> None:
    algos = _by_lib(_scan())
    assert algos, "no call-expr algorithms detected"
    for name, props in algos.items():
        assert props.get("crypto:detectedBy"), f"{name} missing crypto:detectedBy"
        assert props.get("crypto:detectionContext"), f"{name} missing context"
        assert props.get("crypto:confidence") == "high", name


def test_quantum_vulnerable_flag_carried() -> None:
    """RSA/ECDSA/Ed25519 carry crypto:quantumVulnerable=true for the C7 grader;
    AES/SHA-256 carry false."""
    algos = _by_lib(_scan())
    assert algos["RSA-2048"]["crypto:quantumVulnerable"] == "true"
    assert algos["AES-GCM"]["crypto:quantumVulnerable"] == "false"


def test_scan_is_deterministic() -> None:
    a, b = _scan(), _scan()
    refs_a = [(c.kind, c.bom_ref) for c in a.components]
    refs_b = [(c.kind, c.bom_ref) for c in b.components]
    assert refs_a == refs_b


def test_scanner_does_not_leak_into_aibom_pipeline() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_jvm_go" for s in SCANNERS)


def test_no_false_positives_on_pure_python_fixture() -> None:
    """The Java/Go scanner emits nothing for a Python-only repo (the shared
    oracle fixture), so it never perturbs the C1 inventory."""
    shared = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
    assert not _by_lib(_scan(shared))
