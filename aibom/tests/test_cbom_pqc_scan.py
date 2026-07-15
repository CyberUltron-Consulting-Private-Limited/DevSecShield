"""C6 — CBOM post-quantum-cryptography (PQC) readiness mapping.

Lane discipline: the C1 scanner INVENTORIES each algorithm asset and records
``crypto:quantumVulnerable``; this scanner GRADES the quantum-vulnerable ones —
enriching the component with ``crypto:nistQuantumSecurityLevel`` + a NIST PQC
``crypto:pqcMigrationTarget`` and raising one ``QUANTUM_VULNERABLE`` ``Flag``
(SARIF ``warning`` == Medium) whose message carries the 2030/2035 timeline. The
C8 scorer (later) WEIGHTS the flag; the C4 emitter passes the level through.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts the oracle's two
quantum-vulnerable RSA assets are graded and the quantum-resistant assets are
not, plus exercises the pure grader on synthetic ECC / DH / strong-symmetric
components the fixture does not contain.
"""

from __future__ import annotations

import json
import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.pqc import PQC_CODES, QUANTUM_VULNERABLE, migration_target, pqc_grade
from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _pqc_refs(result: ScanResult) -> set[str]:
    return {f.target for f in result.flags if f.code in PQC_CODES}


def _by_ref(result: ScanResult) -> dict[str, CryptoAssetComponent]:
    return {c.bom_ref: c for c in result.components if c.kind == "crypto_asset"}


# --------------------------------------------------------------------------- #
# Fixture-level: the two quantum-vulnerable RSA assets are graded; nothing else.
# --------------------------------------------------------------------------- #


def test_only_quantum_vulnerable_assets_are_flagged() -> None:
    result = _scan()
    comps = _by_ref(result)
    flagged = _pqc_refs(result)
    qv_names = {comps[r].name for r in flagged}
    assert qv_names == {"RSA-2048", "RSA-1024"}, qv_names


def test_pqc_flag_count_matches_oracle_quantum_vulnerable_total() -> None:
    manifest = _manifest()
    result = _scan()
    pqc_flags = [f for f in result.flags if f.code in PQC_CODES]
    assert len(pqc_flags) == manifest["counts"]["quantum_vulnerable"] == 2


def test_quantum_resistant_assets_are_not_pqc_flagged() -> None:
    result = _scan()
    comps = _by_ref(result)
    flagged = _pqc_refs(result)
    resistant = {"AES-GCM", "AES-ECB", "AES", "SHA-256", "MD5", "RC4", "3DES-CBC"}
    for ref, comp in comps.items():
        if comp.name in resistant:
            assert ref not in flagged, f"{comp.name} wrongly PQC-flagged"


def test_graded_assets_carry_nist_level_and_migration_target() -> None:
    result = _scan()
    comps = _by_ref(result)
    flagged = _pqc_refs(result)
    assert flagged, "expected quantum-vulnerable assets to be graded"
    for ref in flagged:
        props = comps[ref].properties or {}
        assert props.get("crypto:nistQuantumSecurityLevel") == "0"
        assert props.get("crypto:pqcMigrationTarget") == (
            "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
        )


def test_migration_target_matches_manifest() -> None:
    manifest = _manifest()
    result = _scan()
    comps = _by_ref(result)
    flagged = _pqc_refs(result)
    targets = manifest["pqc_migration_targets"]
    for ref in flagged:
        comp = comps[ref]
        props = comp.properties or {}
        assert props["crypto:pqcMigrationTarget"] == targets[comp.name]


def test_pqc_flags_are_medium_warning_with_timeline_message() -> None:
    result = _scan()
    for f in result.flags:
        if f.code in PQC_CODES:
            assert f.severity == "warning", "PQC finding is SARIF warning (Medium)"
            assert "2030" in f.message and "2035" in f.message, f.message
            assert "ML-KEM (FIPS 203)" in f.message, f.message


def test_pqc_flags_target_existing_components() -> None:
    result = _scan()
    refs = {c.bom_ref for c in result.components}
    for f in result.flags:
        if f.code in PQC_CODES:
            assert f.target in refs, f"orphan PQC flag target {f.target}"


def test_emitted_cyclonedx_carries_nist_quantum_security_level() -> None:
    # The C4 emitter must render the C6-graded level into algorithmProperties.
    result = _scan()
    bom = emit_cyclonedx(result)
    graded = [
        comp
        for comp in bom["components"]
        if comp.get("type") == "cryptographic-asset"
        and comp["name"] in ("RSA-2048", "RSA-1024")
    ]
    assert len(graded) == 2
    for comp in graded:
        algo = comp["cryptoProperties"]["algorithmProperties"]
        assert algo["nistQuantumSecurityLevel"] == 0


# --------------------------------------------------------------------------- #
# Predicate-level: synthetic primitives the fixture does not contain.
# --------------------------------------------------------------------------- #


def _algo(name: str, **props) -> CryptoAssetComponent:
    base = {"crypto:assetType": "algorithm"}
    base.update({f"crypto:{k}": str(v) for k, v in props.items()})
    return CryptoAssetComponent(bom_ref=f"x-{name.lower()}", name=name, properties=base)


def test_signature_primitive_migrates_to_ml_dsa_slh_dsa() -> None:
    grade = pqc_grade(_algo("ECDSA", primitive="signature", quantumVulnerable="true"))
    assert grade is not None
    assert grade.migration_target == "ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)"


def test_key_agreement_primitive_migrates_to_ml_kem() -> None:
    grade = pqc_grade(_algo("ECDH", primitive="key-agree", quantumVulnerable="true"))
    assert grade is not None and grade.migration_target == "ML-KEM (FIPS 203)"


def test_quantum_resistant_algorithm_is_not_graded() -> None:
    assert pqc_grade(
        _algo("AES-256-GCM", primitive="ae", quantumVulnerable="false")
    ) is None


def test_non_algorithm_crypto_asset_is_not_graded() -> None:
    cert = CryptoAssetComponent(
        bom_ref="x-cert",
        name="cert.pem",
        properties={
            "crypto:assetType": "certificate",
            "crypto:quantumVulnerable": "true",
        },
    )
    assert pqc_grade(cert) is None


def test_migration_target_helper_falls_back_for_unknown_primitive() -> None:
    assert migration_target(None) == "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    assert migration_target("pke") == "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"


def test_grade_level_is_zero_for_quantum_vulnerable() -> None:
    grade = pqc_grade(_algo("RSA-3072", primitive="pke", quantumVulnerable="true"))
    assert grade is not None and grade.nist_quantum_security_level == 0
    assert grade.code == QUANTUM_VULNERABLE
