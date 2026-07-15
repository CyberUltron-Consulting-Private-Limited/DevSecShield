"""C15 — classical security-strength grade + approved-algorithm allowlist.

The classical-adversary peer of the C7 PQC readiness tests. Where C7 grades
``nistQuantumSecurityLevel``, C15 emits ``crypto:securityStrengthBits`` (SP 800-57
Table 2 comparable strength) on every gradeable algorithm asset and owns the
FIPS-140-3 / BSI-TR-02102-1 ``APPROVED_ALGORITHM`` allowlist sets that C8's
frameworks will query.

Lane discipline (asserted below): the scanner EMITS the graph fact, compliance
QUERIES it. Drives the REAL CBOM pipeline over the hand-labeled
``synthetic-crypto-pqc`` (sized, quantum-safe + PQC) and ``synthetic-crypto-app``
(legacy / weak) fixtures — never a mocked ScanResult — plus unit assertions on the
pure grader + allowlist predicate.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.strength import (
    APPROVED_ALGORITHMS,
    canonical_algorithm_family,
    is_approved_algorithm,
    security_strength_bits,
)
from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX_PQC = os.path.join(_HERE, "fixtures", "synthetic-crypto-pqc")
_FX_APP = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _algos(result: ScanResult) -> dict[str, CryptoAssetComponent]:
    return {
        c.name: c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
    }


def _bits(comp: CryptoAssetComponent) -> str | None:
    return (comp.properties or {}).get("crypto:securityStrengthBits")


def _algo(name: str, **props) -> CryptoAssetComponent:
    base = {"crypto:assetType": "algorithm"}
    base.update({f"crypto:{k}": str(v) for k, v in props.items()})
    return CryptoAssetComponent(bom_ref=f"x-{name.lower()}", name=name, properties=base)


# --------------------------------------------------------------------------- #
# Positive strength grading over the pipeline — the whole quantum-safe inventory.
# --------------------------------------------------------------------------- #


def test_symmetric_and_hash_grade_to_table_2_strength() -> None:
    algos = _algos(scan_crypto(_FX_PQC))
    assert _bits(algos["AES-256"]) == "256"   # AES-256 -> 256-bit
    assert _bits(algos["SHA-384"]) == "192"   # SHA-384 collision -> 192-bit


def test_quantum_vulnerable_public_key_grades_by_modulus() -> None:
    # RSA-2048 is quantum security level 0 but classical strength 112 (SP 800-57).
    rsa = _algos(scan_crypto(_FX_PQC))["RSA-2048"]
    assert (rsa.properties or {}).get("crypto:quantumVulnerable") == "true"
    assert (rsa.properties or {}).get("crypto:nistQuantumSecurityLevel") == "0"
    assert _bits(rsa) == "112"  # classical strength is independent of the qsl


def test_pqc_assets_grade_to_their_category_classical_equivalent() -> None:
    algos = _algos(scan_crypto(_FX_PQC))
    assert _bits(algos["ML-KEM-768"]) == "192"    # cat 3 -> AES-192 equivalent
    assert _bits(algos["ML-DSA-87"]) == "256"     # cat 5 -> AES-256 equivalent
    assert _bits(algos["LMS"]) == "128"           # cat 2 -> 128-bit


def test_strength_and_quantum_level_never_disagree() -> None:
    # Every graded quantum-safe asset's classical bits match its NIST-category
    # anchor (cat 1/2 -> 128, 3/4 -> 192, 5 -> 256) — the shared SP 800-57 basis.
    anchor = {"1": 128, "2": 128, "3": 192, "4": 192, "5": 256}
    for comp in _algos(scan_crypto(_FX_PQC)).values():
        props = comp.properties or {}
        level = props.get("crypto:nistQuantumSecurityLevel")
        bits = props.get("crypto:securityStrengthBits")
        if level in anchor and bits is not None:
            assert int(bits) == anchor[level], comp.name


# --------------------------------------------------------------------------- #
# Legacy / weak primitives — a documented comparable strength, not silence.
# --------------------------------------------------------------------------- #


def test_legacy_and_weak_algorithms_carry_a_strength() -> None:
    algos = _algos(scan_crypto(_FX_APP))
    assert _bits(algos["MD5"]) == "64"       # MD5 collision (128/2)
    assert _bits(algos["RC4"]) == "128"      # nominal key; weakness is a flag
    assert _bits(algos["RSA-1024"]) == "80"  # SP 800-57: 1024-bit modulus
    assert _bits(algos["3DES-CBC"]) == "112"  # three-key TDEA meet-in-the-middle


def test_strength_is_a_fact_not_a_verdict() -> None:
    # 3DES grades 112 (>= a 112-bit floor) yet is NOT FIPS/BSI approved — proving
    # the strength number is a comparable-strength FACT; the allowlist + weak-flag
    # (not the number) carry the "disallowed" verdict. C8 ANDs the two.
    tdes = _algos(scan_crypto(_FX_APP))["3DES-CBC"]
    assert _bits(tdes) == "112"
    assert is_approved_algorithm("fips_140_3", tdes) is False
    assert is_approved_algorithm("bsi_tr_02102", tdes) is False


# --------------------------------------------------------------------------- #
# Pure grader unit tests — primitives / sizes the fixtures do not contain.
# --------------------------------------------------------------------------- #


def test_grader_public_key_ladder() -> None:
    assert security_strength_bits(
        _algo("RSA-3072", primitive="pke", quantumVulnerable="true",
              keySize="3072")) == 128
    assert security_strength_bits(
        _algo("RSA-15360", primitive="pke", quantumVulnerable="true",
              keySize="15360")) == 256
    assert security_strength_bits(
        _algo("RSA-512", primitive="pke", quantumVulnerable="true",
              keySize="512")) == 56


def test_grader_ecc_curve_strength() -> None:
    assert security_strength_bits(
        _algo("ECDSA", primitive="signature", quantumVulnerable="true",
              curve="P-256")) == 128
    assert security_strength_bits(
        _algo("ECDSA-P384", primitive="signature", quantumVulnerable="true",
              curve="P-384")) == 192


def test_grader_returns_none_for_unanchored_primitive() -> None:
    # A bare keyed-MAC / KDF has no comparable-strength anchor -> ungraded.
    assert security_strength_bits(
        _algo("HKDF", primitive="kdf", quantumVulnerable="false")) is None
    assert security_strength_bits(
        _algo("HMAC", primitive="mac", quantumVulnerable="false")) is None


def test_grader_ignores_non_algorithm_assets() -> None:
    cert = CryptoAssetComponent(
        bom_ref="x-cert", name="cert.pem",
        properties={"crypto:assetType": "certificate"})
    assert security_strength_bits(cert) is None
    assert canonical_algorithm_family(cert) is None


# --------------------------------------------------------------------------- #
# Canonical family normalization — composites classified before their substrings.
# --------------------------------------------------------------------------- #


def test_family_normalization_precedence() -> None:
    def fam(name: str) -> str | None:
        return canonical_algorithm_family(_algo(name))
    assert fam("AES-256-GCM") == "aes"
    assert fam("3DES-CBC") == "3des"       # not "des"
    assert fam("ML-DSA-87") == "ml-dsa"    # not "dsa"
    assert fam("SLH-DSA-256") == "slh-dsa"  # not "dsa"
    assert fam("ECDSA") == "ecdsa"          # not "dsa"
    assert fam("ECDH") == "ecdh"            # not "dh"
    assert fam("SHA-256") == "sha2"         # not "sha1"
    assert fam("Hybrid ML-KEM-768") == "hybrid"


# --------------------------------------------------------------------------- #
# Approved-algorithm allowlists — the positive inversion of the deny-list.
# --------------------------------------------------------------------------- #


def test_fips_140_3_allowlist_membership() -> None:
    for name in ("AES-256", "SHA-256", "RSA-2048", "ML-KEM-768", "ML-DSA-87"):
        assert is_approved_algorithm("fips_140_3", _algo(name)) is True
    # disallowed / deprecated / non-approved
    for name in ("DES", "3DES-CBC", "RC4", "MD5", "SHA-1", "ChaCha20", "DSA"):
        assert is_approved_algorithm("fips_140_3", _algo(name)) is False


def test_bsi_is_stricter_than_fips_on_symmetric() -> None:
    # BSI approves AES only among symmetric ciphers; ChaCha20 is out (FIPS too).
    chacha = _algo("ChaCha20-Poly1305")
    assert is_approved_algorithm("bsi_tr_02102", chacha) is False
    assert is_approved_algorithm("bsi_tr_02102", _algo("AES-256")) is True


def test_allowlist_out_of_scope_returns_none() -> None:
    # Unknown framework -> no allowlist here (C8 skips, never a fail).
    assert is_approved_algorithm("no_such_framework", _algo("AES-256")) is None
    # Non-classifiable asset -> out of scope.
    assert is_approved_algorithm(
        "fips_140_3",
        CryptoAssetComponent(bom_ref="x", name="cert.pem",
                             properties={"crypto:assetType": "certificate"}),
    ) is None


def test_allowlist_frameworks_are_registered() -> None:
    assert set(APPROVED_ALGORITHMS) == {"fips_140_3", "bsi_tr_02102"}
    # BSI is a strict-or-equal subset shape: it never approves what FIPS forbids
    # on symmetric ciphers (both exclude ChaCha20/3DES); AES is in both.
    assert "aes" in APPROVED_ALGORITHMS["fips_140_3"]
    assert "aes" in APPROVED_ALGORITHMS["bsi_tr_02102"]
    assert "chacha20" not in APPROVED_ALGORITHMS["bsi_tr_02102"]


# --------------------------------------------------------------------------- #
# CycloneDX — the strength renders into classicalSecurityLevel, schema-valid.
# --------------------------------------------------------------------------- #


def test_cyclonedx_renders_classical_security_level() -> None:
    bom = emit_cyclonedx(scan_crypto(_FX_PQC))
    by_name = {
        c["name"]: c for c in bom["components"]
        if c.get("type") == "cryptographic-asset"
    }
    aes = by_name["AES-256"]["cryptoProperties"]["algorithmProperties"]
    assert aes["classicalSecurityLevel"] == 256
    rsa = by_name["RSA-2048"]["cryptoProperties"]["algorithmProperties"]
    # classical strength coexists with the (separate) quantum level 0.
    assert rsa["classicalSecurityLevel"] == 112
    assert rsa["nistQuantumSecurityLevel"] == 0


def test_cyclonedx_is_schema_valid_with_strength() -> None:
    bom = emit_and_validate(scan_crypto(_FX_PQC))
    assert bom["bomFormat"] == "CycloneDX" and bom["components"]


# --------------------------------------------------------------------------- #
# Normalizer carries the strength through to the results-page finding row.
# --------------------------------------------------------------------------- #


def test_normalizer_carries_strength_bits() -> None:
    from aibom.cbom.normalize import normalize_crypto

    run = normalize_crypto(scan_crypto(_FX_PQC), duration_of_scan=0.0)
    by_title = {r["title"]: r for r in run["results"]}
    assert by_title["AES-256"]["security_strength_bits"] == 256
    assert by_title["RSA-2048"]["security_strength_bits"] == 112
