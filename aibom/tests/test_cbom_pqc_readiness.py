"""C7 — PQC readiness: positive ``nistQuantumSecurityLevel`` grading, PQC
parameter-set retention, hybrid detection, stateful-hash signatures, and the
sized migration roadmap.

Extends the C6 PQC lane (:mod:`aibom.cbom.pqc` / ``pqc_scan``) from "grade only
the quantum-vulnerable assets to level 0" to a TOTAL grader over the NIST security
categories: every algorithm asset now carries its category (0 = vulnerable, 1-5 =
quantum-safe), PQC parameter sets survive detection (ML-KEM-768 ≠ ML-KEM-1024),
hybrid KEX is one quantum-safe asset (not a split classical+PQC pair), and each
vulnerable finding names a parameter-sized migration target.

Drives the REAL CBOM pipeline over a hand-labeled ``synthetic-crypto-pqc``
fixture (never a mocked ScanResult) plus unit-level assertions on the pure grader.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.pqc import (
    nist_quantum_level,
    pqc_grade,
    sized_migration_target,
)
from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-pqc")


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _algos(result: ScanResult) -> dict[str, CryptoAssetComponent]:
    return {
        c.name: c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
    }


def _level(comp: CryptoAssetComponent) -> str | None:
    return (comp.properties or {}).get("crypto:nistQuantumSecurityLevel")


def _algo(name: str, **props) -> CryptoAssetComponent:
    base = {"crypto:assetType": "algorithm"}
    base.update({f"crypto:{k}": str(v) for k, v in props.items()})
    return CryptoAssetComponent(bom_ref=f"x-{name.lower()}", name=name, properties=base)


# --------------------------------------------------------------------------- #
# Positive nistQuantumSecurityLevel grading — the whole inventory, by category.
# --------------------------------------------------------------------------- #


def test_every_expected_algorithm_is_inventoried() -> None:
    names = set(_algos(_scan()))
    for expected in (
        "ML-KEM-768", "ML-DSA-87", "SLH-DSA-256", "FALCON-512", "LMS", "XMSS",
        "Hybrid ML-KEM-768", "Hybrid ML-KEM-1024", "AES-256", "SHA-384", "RSA-2048",
    ):
        assert expected in names, f"missing {expected} in {sorted(names)}"


def test_classical_quantum_safe_assets_carry_positive_level() -> None:
    algos = _algos(_scan())
    # The single biggest gap C7 closes: a report can now STATE these are safe.
    assert _level(algos["AES-256"]) == "5"   # Cat 5 anchor
    assert _level(algos["SHA-384"]) == "4"   # Cat 4 (SHA-384 collision anchor)


def test_pqc_parameter_sets_grade_to_their_category() -> None:
    algos = _algos(_scan())
    assert _level(algos["ML-KEM-768"]) == "3"    # FIPS 203, cat 3
    assert _level(algos["ML-DSA-87"]) == "5"     # FIPS 204, cat 5
    assert _level(algos["SLH-DSA-256"]) == "5"   # FIPS 205, cat 5
    assert _level(algos["FALCON-512"]) == "1"    # FN-DSA, cat 1


def test_stateful_hash_signatures_are_quantum_safe() -> None:
    algos = _algos(_scan())
    for name in ("LMS", "XMSS"):
        assert (algos[name].properties or {}).get("crypto:quantumVulnerable") == "false"
        assert _level(algos[name]) == "2"  # SHA-256-anchored (cat 2)


def test_quantum_vulnerable_public_key_is_level_zero() -> None:
    algos = _algos(_scan())
    rsa = algos["RSA-2048"]
    assert (rsa.properties or {}).get("crypto:quantumVulnerable") == "true"
    assert _level(rsa) == "0"


# --------------------------------------------------------------------------- #
# PQC parameter-set retention — the set survives detection.
# --------------------------------------------------------------------------- #


def test_parameter_set_is_retained_not_collapsed() -> None:
    algos = _algos(_scan())
    assert (algos["ML-KEM-768"].properties or {}).get("crypto:parameterSet") == "768"
    assert (algos["ML-DSA-87"].properties or {}).get("crypto:parameterSet") == "87"
    # ML-KEM-768 (cat 3) is distinguishable from a would-be ML-KEM-1024 (cat 5).
    assert _level(algos["ML-KEM-768"]) != _level(_algo(
        "ML-KEM-1024", assetType="algorithm", primitive="kem",
        quantumVulnerable="false", parameterSet="1024"))


def test_kem_primitive_is_distinct_from_pqc_signature() -> None:
    algos = _algos(_scan())
    assert (algos["ML-KEM-768"].properties or {}).get("crypto:primitive") == "kem"
    assert (algos["ML-DSA-87"].properties or {}).get("crypto:primitive") == "signature"


# --------------------------------------------------------------------------- #
# Hybrid detection — one quantum-safe asset, never a split pair.
# --------------------------------------------------------------------------- #


def test_hybrid_kex_is_one_quantum_safe_asset() -> None:
    algos = _algos(_scan())
    hyb = algos["Hybrid ML-KEM-768"]
    props = hyb.properties or {}
    assert props.get("crypto:hybrid") == "true"
    assert props.get("crypto:quantumVulnerable") == "false"  # NOT vulnerable
    assert _level(hyb) == "3"  # graded at its ML-KEM-768 component (cat 3)


def test_hybrid_is_not_split_into_classical_and_pqc_halves() -> None:
    names = set(_algos(_scan()))
    # The fused X25519MLKEM768 must NOT also mint a vulnerable X25519 asset nor a
    # bare CRYSTALS-Kyber — that would double-count and mis-report migration state.
    assert "X25519" not in names
    assert "CRYSTALS-Kyber" not in names


def test_higher_hybrid_grades_higher() -> None:
    algos = _algos(_scan())
    assert _level(algos["Hybrid ML-KEM-1024"]) == "5"


# --------------------------------------------------------------------------- #
# Migration roadmap — sized target + CNSA 2.0 timeline on the vulnerable finding.
# --------------------------------------------------------------------------- #


def test_vulnerable_asset_carries_sized_roadmap() -> None:
    rsa = _algos(_scan())["RSA-2048"]
    props = rsa.properties or {}
    # RSA-2048 ≈ 112-bit classical strength -> ML-KEM-768 / ML-DSA-65.
    assert props.get("crypto:pqcMigrationRoadmap") == (
        "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"
    )
    # The unsized primary target property is unchanged (frozen-oracle-compatible).
    assert props.get("crypto:pqcMigrationTarget") == (
        "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    )


def test_stronger_classical_key_gets_larger_pqc_target() -> None:
    weak = sized_migration_target(_algo("RSA-2048", keySize=2048))
    strong = sized_migration_target(_algo("RSA-15360", keySize=15360))
    assert "ML-KEM-768" in weak and "ML-KEM-1024" in strong


def test_vulnerable_flag_message_cites_both_timelines() -> None:
    grade = pqc_grade(_algo("RSA-2048", primitive="pke",
                            quantumVulnerable="true", keySize="2048"))
    assert grade is not None
    assert "2030" in grade.message and "2035" in grade.message  # NIST
    assert "CNSA 2.0" in grade.message                          # NSA milestones
    assert "ML-KEM" in grade.message


# --------------------------------------------------------------------------- #
# Pure grader unit tests — primitives the fixture does not contain.
# --------------------------------------------------------------------------- #


def test_symmetric_grading_by_key_size() -> None:
    assert nist_quantum_level(
        _algo("AES-128", primitive="block-cipher", quantumVulnerable="false",
              keySize="128")) == 1
    assert nist_quantum_level(
        _algo("AES-192", primitive="block-cipher", quantumVulnerable="false",
              keySize="192")) == 3


def test_chacha20_defaults_to_256_bit_category() -> None:
    assert nist_quantum_level(
        _algo("ChaCha20-Poly1305", primitive="ae",
              quantumVulnerable="false")) == 5


def test_ungradeable_asset_returns_none() -> None:
    # A bare KDF/MAC has no NIST category anchor -> ungraded (property omitted).
    assert nist_quantum_level(
        _algo("HKDF", primitive="kdf", quantumVulnerable="false")) is None
    # An unparameterized PQC detection (new MLKEMEngine(0)) cannot be categorized.
    assert nist_quantum_level(
        _algo("CRYSTALS-Kyber", primitive="kem", quantumVulnerable="false")) is None


def test_non_algorithm_asset_is_not_graded() -> None:
    cert = CryptoAssetComponent(
        bom_ref="x-cert", name="cert.pem",
        properties={"crypto:assetType": "certificate",
                    "crypto:quantumVulnerable": "false"})
    assert nist_quantum_level(cert) is None


# --------------------------------------------------------------------------- #
# CycloneDX — the graded levels + PQC parameter set are schema-valid.
# --------------------------------------------------------------------------- #


def test_cyclonedx_is_schema_valid_with_pqc_assets() -> None:
    # emit_and_validate raises on any schema error (levels 1-5 + parameterSet).
    bom = emit_and_validate(_scan())
    assert bom["bomFormat"] == "CycloneDX" and bom["components"]


def test_pqc_parameter_set_renders_as_parameter_set_identifier() -> None:
    bom = emit_cyclonedx(_scan())
    by_name = {
        c["name"]: c for c in bom["components"]
        if c.get("type") == "cryptographic-asset"
    }
    mlkem = by_name["ML-KEM-768"]["cryptoProperties"]["algorithmProperties"]
    assert mlkem["parameterSetIdentifier"] == "768"
    assert mlkem["nistQuantumSecurityLevel"] == 3
    aes = by_name["AES-256"]["cryptoProperties"]["algorithmProperties"]
    assert aes["nistQuantumSecurityLevel"] == 5
