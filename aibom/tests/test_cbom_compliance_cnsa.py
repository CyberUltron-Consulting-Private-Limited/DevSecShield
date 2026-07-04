"""C14 — CNSA 2.0 quantum-readiness compliance framework.

The NSA Commercial National Security Algorithm Suite 2.0 (``cnsa_2_0``) is a
PARAMETER-LEVEL quantum-readiness allowlist for National Security Systems —
stricter than the family-level FIPS/BSI allowlist (C15). It approves AES-256,
SHA-384/512, ML-KEM-1024, ML-DSA-87, and the SP 800-208 stateful-hash signatures
(LMS/XMSS) for firmware/software signing; every under-parameterized (ML-KEM-512/
768, ML-DSA-44/65) or out-of-suite (SLH-DSA, FALCON, SHA-256, AES-128/192)
quantum-safe-capable mechanism is non-compliant. Classical quantum-vulnerable
crypto is the transition state CNSA-3 tracks, not a suite ban.

Driven over the REAL CBOM pipeline (never a mocked ScanResult). Lane discipline
asserted: every check reads the GRAPH — C7's ``nistQuantumSecurityLevel`` +
``crypto:primitive`` + ``crypto:parameterSet`` + ``crypto:hybrid`` and C15's
canonical family — never ``result.flags``.
"""

from __future__ import annotations

import os

from aibom.cbom.compliance import (
    CBOM_FRAMEWORKS,
    cnsa_symmetric_hash_noncompliant,
    cnsa_underparameterized_quantum_safe,
    run_cbom_compliance,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX_APP = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
_FX_PQC = os.path.join(_HERE, "fixtures", "synthetic-crypto-pqc")

_FW = "cnsa_2_0"


def _scan(fx: str) -> ScanResult:
    return scan_crypto(fx)


def _report(fx: str) -> dict:
    return run_cbom_compliance(_scan(fx))


def _verdicts(block: dict) -> dict[str, str]:
    return {r["id"]: r["verdict"] for r in block["requirements"]}


# --------------------------------------------------------------------------- #
# Registration + tri-state shape.
# --------------------------------------------------------------------------- #


def test_cnsa_framework_is_registered() -> None:
    assert _FW in CBOM_FRAMEWORKS
    assert _FW in _report(_FX_APP)


def test_cnsa_has_full_tri_state_shape() -> None:
    block = _report(_FX_APP)[_FW]
    for key in (
        "pass",
        "pass_with_evidence",
        "fail",
        "out_of_scope",
        "not_bom_evidenceable",
        "na",
        "coverage",
        "requirements",
    ):
        assert key in block, f"missing {key}"
    assert block["requirements"]
    for req in block["requirements"]:
        assert req["evidence"], "every verdict carries graph evidence"


def test_cnsa_out_of_scope_without_crypto() -> None:
    # A repo with no crypto -> every CNSA requirement out_of_scope, coverage None.
    empty = ScanResult(subject={"name": "empty"})
    report = run_cbom_compliance(empty)
    v = _verdicts(report[_FW])
    assert set(v.values()) == {"out_of_scope"}


# --------------------------------------------------------------------------- #
# CNSA-1 — symmetric + hash floor (AES-256, SHA-384/512).
# --------------------------------------------------------------------------- #


def test_cnsa1_fails_sub_floor_hash() -> None:
    # App fixture carries SHA-256 (Category 2) — below the CNSA SHA-384/512 floor.
    v = _verdicts(_report(_FX_APP)[_FW])
    assert v["CNSA-1"] == "fail"


def test_cnsa1_passes_aes256_and_sha384() -> None:
    # PQC fixture: AES-256 (Category 5) + SHA-384 (Category 4) meet the floor.
    v = _verdicts(_report(_FX_PQC)[_FW])
    assert v["CNSA-1"] == "pass"


def test_cnsa1_skips_ungraded_symmetric() -> None:
    # An AES with no key size on the source line grades to no level -> honestly
    # skipped, never counted as a fail the inventory cannot substantiate.
    r = _scan(_FX_APP)
    bad_names = {c.name for c in cnsa_symmetric_hash_noncompliant(r)}
    # AES-ECB / AES / AES-GCM are ungraded here -> not flagged by this floor check.
    assert not any(n.startswith("AES") for n in bad_names)
    # SHA-256 (graded Category 2) IS flagged.
    assert "SHA-256" in bad_names


# --------------------------------------------------------------------------- #
# CNSA-2 — quantum-resistant parameter set (the CNSA-specific insight).
# --------------------------------------------------------------------------- #


def test_cnsa2_fails_under_parameterized_pqc() -> None:
    # PQC fixture: ML-KEM-768, SLH-DSA-256, FALCON-512, Hybrid ML-KEM-768 are all
    # quantum-safe but NOT the CNSA 2.0 parameter set -> CNSA-2 fails.
    v = _verdicts(_report(_FX_PQC)[_FW])
    assert v["CNSA-2"] == "fail"


def test_cnsa2_accepts_top_parameter_and_stateful_hash() -> None:
    r = _scan(_FX_PQC)
    under = {c.name for c in cnsa_underparameterized_quantum_safe(r)}
    # CNSA-mandated / SP 800-208 members are NOT in the reject set.
    for approved in ("ML-DSA-87", "LMS", "XMSS", "Hybrid ML-KEM-1024"):
        assert approved not in under, f"{approved} wrongly rejected"
    # Under-parameterized / out-of-suite members ARE rejected.
    for rejected in (
        "ML-KEM-768",
        "SLH-DSA-256",
        "FALCON-512",
        "Hybrid ML-KEM-768",
    ):
        assert rejected in under, f"{rejected} not rejected"


def test_cnsa2_passes_when_no_quantum_safe_adopted() -> None:
    # App fixture has no PQC/hybrid at all -> nothing to parameter-check.
    v = _verdicts(_report(_FX_APP)[_FW])
    assert v["CNSA-2"] == "pass"


def test_cnsa2_judges_hybrid_on_its_mlkem_component() -> None:
    # A hybrid key-agreement is CNSA-approved iff its ML-KEM component is 1024.
    r = _scan(_FX_PQC)
    under = {c.name for c in cnsa_underparameterized_quantum_safe(r)}
    assert "Hybrid ML-KEM-1024" not in under
    assert "Hybrid ML-KEM-768" in under


# --------------------------------------------------------------------------- #
# CNSA-3 — classical quantum-vulnerable crypto is a TRANSITION STATE, not a ban.
# --------------------------------------------------------------------------- #


def test_cnsa3_classical_is_transition_not_ban() -> None:
    # Both fixtures carry quantum-vulnerable RSA WITH a migration target assigned
    # -> CNSA-3 passes (classical use permitted through the transition window).
    assert _verdicts(_report(_FX_APP)[_FW])["CNSA-3"] == "pass"
    assert _verdicts(_report(_FX_PQC)[_FW])["CNSA-3"] == "pass"


# --------------------------------------------------------------------------- #
# CNSA-4 — the NSS transition-timeline milestone is process evidence.
# --------------------------------------------------------------------------- #


def test_cnsa4_timeline_is_not_bom_evidenceable() -> None:
    v = _verdicts(_report(_FX_PQC)[_FW])
    assert v["CNSA-4"] == "not_bom_evidenceable"


# --------------------------------------------------------------------------- #
# Coverage = pass / (pass + fail); NA (CNSA-4) excluded.
# --------------------------------------------------------------------------- #


def test_cnsa_coverage_excludes_na() -> None:
    # App: CNSA-1 fail, CNSA-2 pass, CNSA-3 pass, CNSA-4 NA -> 2/3.
    app = _report(_FX_APP)[_FW]
    assert app["coverage"] == round(2 / 3, 3)
    # PQC: CNSA-1 pass, CNSA-2 fail, CNSA-3 pass, CNSA-4 NA -> 2/3.
    pqc = _report(_FX_PQC)[_FW]
    assert pqc["coverage"] == round(2 / 3, 3)


# --------------------------------------------------------------------------- #
# Lane purity: the CNSA checks read the graph, never flags.
# --------------------------------------------------------------------------- #


def test_cnsa_checks_ignore_flags() -> None:
    # Corrupt every flag; verdicts are computed from graph facts, so they hold.
    r = _scan(_FX_PQC)
    baseline = _verdicts(run_cbom_compliance(r)[_FW])
    r.flags = []
    after = _verdicts(run_cbom_compliance(r)[_FW])
    assert baseline == after
