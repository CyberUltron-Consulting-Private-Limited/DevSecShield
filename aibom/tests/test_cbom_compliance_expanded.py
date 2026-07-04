"""C8 — expanded tri-state CBOM compliance frameworks.

Adds four crypto-regulatory frameworks on top of the C7 lane, driven over the
REAL CBOM pipeline (never a mocked ScanResult):

* **PCI-DSS 4.0.1** (``pci_dss_4``) — "strong cryptography" (≥ 112-bit) for
  stored + transmitted account data;
* **FIPS 140-3** (``fips_140_3``) — the SP 800-140C approved-algorithm allowlist
  (inverting C15's ``is_approved_algorithm``) + the 2048-bit floor;
* **BSI TR-02102-1** (``bsi_tr_02102``) — stricter allowlist + a 120-bit
  effective-strength floor (RSA ≥ 3000 / EC ≥ 250 comparable);
* **NIST SP 1800-38C** (``nist_1800_38c``) — quantum-readiness discovery +
  crypto-agility.

Lane discipline (asserted): every check reads the GRAPH — ``crypto:`` properties
incl. C15's ``securityStrengthBits`` + C7's ``nistQuantumSecurityLevel`` — and
never ``result.flags``. Coverage is ``pass / (pass + fail)``; a no-crypto repo →
every framework ``out_of_scope``.
"""

from __future__ import annotations

import os

import pytest

from aibom.cbom.compliance import (
    CBOM_FRAMEWORKS,
    non_approved_algorithms,
    quantum_safe_mechanisms,
    run_cbom_compliance,
    under_strength,
    undersized_keys,
    weak_algorithms,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX_APP = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
_FX_PQC = os.path.join(_HERE, "fixtures", "synthetic-crypto-pqc")

_NEW_FRAMEWORKS = ("pci_dss_4", "fips_140_3", "bsi_tr_02102", "nist_1800_38c")


def _scan(fx: str) -> ScanResult:
    return scan_crypto(fx)


def _report(fx: str) -> dict:
    return run_cbom_compliance(_scan(fx))


def _verdicts(block: dict) -> dict[str, str]:
    return {r["id"]: r["verdict"] for r in block["requirements"]}


# --------------------------------------------------------------------------- #
# Registration + shape: the four new frameworks are in the CBOM registry and
# every requirement carries the full tri-state shape.
# --------------------------------------------------------------------------- #


def test_four_new_frameworks_are_registered() -> None:
    for fw in _NEW_FRAMEWORKS:
        assert fw in CBOM_FRAMEWORKS
    report = _report(_FX_APP)
    for fw in _NEW_FRAMEWORKS:
        assert fw in report, f"missing framework {fw}"


@pytest.mark.parametrize("fw", _NEW_FRAMEWORKS)
def test_new_framework_has_full_tri_state_shape(fw: str) -> None:
    block = _report(_FX_APP)[fw]
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
        assert key in block, f"{fw} missing {key}"
    assert block["requirements"]
    for req in block["requirements"]:
        assert req["evidence"], "every verdict carries graph evidence"


# --------------------------------------------------------------------------- #
# PCI-DSS 4.0.1 — strong cryptography (≥ 112-bit), no early TLS, no hardcoded keys.
# --------------------------------------------------------------------------- #


def test_pci_fails_the_weak_fixture() -> None:
    v = _verdicts(_report(_FX_APP)["pci_dss_4"])
    assert v["PCI-1"] == "fail"  # MD5(64)/RSA-1024(80) below the 112-bit floor
    assert v["PCI-2"] == "fail"  # TLS 1.0 in use
    assert v["PCI-3"] == "fail"  # a hardcoded private key
    assert v["PCI-4"] == "not_bom_evidenceable"  # key-management lifecycle


def test_pci_passes_the_strong_pqc_fixture() -> None:
    block = _report(_FX_PQC)["pci_dss_4"]
    v = _verdicts(block)
    assert v["PCI-1"] == "pass"  # every algo ≥ 112-bit (RSA-2048 = 112)
    assert v["PCI-2"] == "pass"  # no weak protocols
    assert v["PCI-3"] == "pass"  # no hardcoded keys
    assert block["coverage"] == 1.0


# --------------------------------------------------------------------------- #
# FIPS 140-3 — approved-algorithm allowlist (C15 inversion) + 2048-bit floor.
# --------------------------------------------------------------------------- #


def test_fips_allowlist_rejects_unapproved_algorithms() -> None:
    v = _verdicts(_report(_FX_APP)["fips_140_3"])
    assert v["FIPS-1"] == "fail"  # 3DES / RC4 / MD5 not FIPS-approved
    assert v["FIPS-2"] == "fail"  # RSA-1024 below the 2048-bit floor
    assert v["FIPS-3"] == "fail"  # deprecated algorithms + ECB in use
    assert v["FIPS-4"] == "not_bom_evidenceable"  # CMVP certificate


def test_fips_flags_falcon_as_not_yet_approved_but_not_undersized() -> None:
    # FALCON is not (yet) a FIPS-standardized signature -> allowlist fail; but its
    # 512 parameter set must NOT be read as an undersized RSA modulus.
    block = _report(_FX_PQC)["fips_140_3"]
    v = _verdicts(block)
    assert v["FIPS-1"] == "fail"  # FALCON-512 not on the FIPS allowlist
    assert v["FIPS-2"] == "pass"  # no genuinely undersized asymmetric keys
    assert v["FIPS-3"] == "pass"  # no deprecated algorithms / ECB


# --------------------------------------------------------------------------- #
# BSI TR-02102-1 — stricter allowlist + 120-bit floor (RSA-2048 = 112 fails).
# --------------------------------------------------------------------------- #


def test_bsi_120_bit_floor_is_stricter_than_fips() -> None:
    block = _report(_FX_PQC)["bsi_tr_02102"]
    v = _verdicts(block)
    # RSA-2048 (112-bit) clears the FIPS 2048-bit floor but NOT the BSI 120-bit
    # effective-strength floor — the two frameworks disagree, proving the level
    # parameterization.
    assert v["BSI-2"] == "fail"
    assert _verdicts(_report(_FX_PQC)["fips_140_3"])["FIPS-2"] == "pass"
    assert v["BSI-1"] == "fail"  # FALCON not a BSI-approved mechanism
    assert v["BSI-3"] == "pass"  # no weak algorithms / ECB
    assert v["BSI-4"] == "not_bom_evidenceable"  # key-lifecycle policy


# --------------------------------------------------------------------------- #
# NIST SP 1800-38C — quantum-readiness discovery + crypto-agility.
# --------------------------------------------------------------------------- #


def test_qr_crypto_agility_distinguishes_migrated_from_stuck() -> None:
    # App fixture: quantum-vulnerable RSA, NO PQC/hybrid adopted -> QR-3 fails.
    app = _verdicts(_report(_FX_APP)["nist_1800_38c"])
    assert app["QR-1"] == "pass"  # every primitive identified (discovery)
    assert app["QR-2"] == "pass"  # quantum-vulnerable assets risk-graded
    assert app["QR-3"] == "fail"  # no quantum-safe / hybrid mechanism adopted
    assert app["QR-4"] == "not_bom_evidenceable"  # interop/perf testing
    # PQC fixture: hybrid ML-KEM adopted alongside RSA -> QR-3 passes.
    pqc = _verdicts(_report(_FX_PQC)["nist_1800_38c"])
    assert pqc["QR-3"] == "pass"


# --------------------------------------------------------------------------- #
# Helpers: parameterized floors + PQC-parameter-set regression.
# --------------------------------------------------------------------------- #


def test_undersized_keys_floor_is_parameterized() -> None:
    r = _scan(_FX_PQC)
    # Default 2048 floor: RSA-2048 clears it.
    assert not undersized_keys(r)
    # A 3072 floor now catches RSA-2048.
    caught = {c.name for c in undersized_keys(r, 3072)}
    assert "RSA-2048" in caught


def test_undersized_keys_never_flags_a_pqc_parameter_set() -> None:
    # FALCON-512 / ML-KEM-768 carry a parameter set in keySize, not an IF modulus.
    r = _scan(_FX_PQC)
    for floor in (2048, 3072):
        names = {c.name for c in undersized_keys(r, floor)}
        assert not any(
            n.startswith(("FALCON", "ML-KEM", "ML-DSA", "Hybrid")) for n in names
        ), f"PQC asset false-flagged as undersized at floor {floor}: {names}"


def test_weak_algorithms_does_not_flag_falcon() -> None:
    # Regression: FALCON-512's 512 parameter set must not read as a weak RSA key.
    r = _scan(_FX_PQC)
    weak_names = {c.name for c in weak_algorithms(r)}
    assert not any(n.startswith("FALCON") for n in weak_names), weak_names


def test_under_strength_reads_the_c15_grade() -> None:
    r = _scan(_FX_PQC)
    # 120-bit floor catches RSA-2048 (112-bit) but not AES-256 (256) / ML-KEM-768.
    below = {c.name for c in under_strength(r, 120)}
    assert "RSA-2048" in below
    assert "AES-256" not in below and "ML-KEM-768" not in below


def test_non_approved_algorithms_inverts_the_allowlist() -> None:
    r = _scan(_FX_PQC)
    fips_bad = {c.name for c in non_approved_algorithms(r, "fips_140_3")}
    assert any(n.startswith("FALCON") for n in fips_bad)
    # AES-256 and ML-KEM-768 ARE FIPS-approved -> not in the reject set.
    assert "AES-256" not in fips_bad and "ML-KEM-768" not in fips_bad


def test_quantum_safe_mechanisms_reads_hybrid_and_pqc_families() -> None:
    r = _scan(_FX_PQC)
    names = {c.name for c in quantum_safe_mechanisms(r)}
    assert any(n.startswith("Hybrid") for n in names)
    assert "ML-KEM-768" in names and "ML-DSA-87" in names
    # A classical RSA is not a quantum-safe mechanism.
    assert "RSA-2048" not in names


# --------------------------------------------------------------------------- #
# Applicability + lane purity for the new frameworks specifically.
# --------------------------------------------------------------------------- #


def test_no_crypto_repo_makes_new_frameworks_out_of_scope(tmp_path) -> None:
    (tmp_path / "readme.md").write_text("# nothing cryptographic\n")
    report = run_cbom_compliance(scan_crypto(tmp_path))
    for fw in _NEW_FRAMEWORKS:
        block = report[fw]
        assert block["coverage"] is None
        assert block["fail"] == 0 and block["pass"] == 0
        assert all(r["verdict"] == "out_of_scope" for r in block["requirements"])


def test_new_frameworks_never_read_flags() -> None:
    scanned = _scan(_FX_APP)
    with_flags = run_cbom_compliance(scanned)
    flagless = ScanResult(
        subject=scanned.subject,
        components=scanned.components,
        edges=scanned.edges,
        flags=[],
        properties=scanned.properties,
    )
    without_flags = run_cbom_compliance(flagless)
    for fw in _NEW_FRAMEWORKS:
        assert _verdicts(with_flags[fw]) == _verdicts(without_flags[fw]), (
            f"{fw} verdict changed when flags were cleared — it read a flag"
        )


@pytest.mark.parametrize("fw", _NEW_FRAMEWORKS)
def test_coverage_is_pass_over_pass_plus_fail(fw: str) -> None:
    block = _report(_FX_APP)[fw]
    n_pass = block["pass"] + block["pass_with_evidence"]
    applicable = n_pass + block["fail"]
    if applicable:
        assert block["coverage"] == round(n_pass / applicable, 3)
    else:
        assert block["coverage"] is None
