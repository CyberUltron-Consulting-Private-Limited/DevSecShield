"""C8 — CBOM normalizer carry-through (no flatten).

``normalize_crypto`` shapes a scored + compliance-mapped CBOM ``ScanResult`` into
the DevSecShield run-object, carrying THROUGH the five chart distributions
(algorithm / weak-crypto / PQC readiness / certificate-expiry / protocol-TLS),
the tri-state compliance, and the scores. These tests pin that nothing the
charts (C9) and the contract test (C10) depend on can be flattened away.
"""

from __future__ import annotations

import os

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _run() -> dict:
    return normalize_crypto(scan_crypto(_FX), duration_of_scan=0.0)


# --------------------------------------------------------------------------- #
# Shape + carry-through.
# --------------------------------------------------------------------------- #


def test_run_object_has_locked_keys() -> None:
    run = _run()
    for key in (
        "results",
        "cbom_json",
        "cbom_compliance",
        "cbom_scores",
        "cbom_distributions",
        "duration_of_scan",
    ):
        assert key in run, f"missing {key}"


def test_scores_carried_through_not_flattened() -> None:
    run = _run()
    assert run["cbom_scores"], "scores must be carried through"
    assert "component_severity" in run["cbom_scores"]


def test_compliance_tri_state_carried_through() -> None:
    run = _run()
    comp = run["cbom_compliance"]
    # CBOM frameworks present with their full per-framework breakdown.
    assert "nist_800_57" in comp
    assert "nist_1800_38b" in comp


def test_results_carry_per_asset_severity_and_crypto_fields() -> None:
    run = _run()
    by_title = {f["title"]: f for f in run["results"]}
    # weak asset -> High impact carried per-finding (not flattened to a count)
    assert by_title["MD5"]["impact"] == "High"
    # quantum-vulnerable RSA carries its NIST quantum level + migration target
    rsa = by_title["RSA-2048"]
    assert rsa["quantum_vulnerable"] is True
    assert rsa["nist_quantum_security_level"] == 0
    assert rsa["pqc_migration_target"]
    assert rsa["impact"] == "Medium"


# --------------------------------------------------------------------------- #
# The five chart distributions are all non-empty on the fixture (C9/C10 seam).
# --------------------------------------------------------------------------- #


def test_algorithm_distribution_non_empty() -> None:
    dist = _run()["cbom_distributions"]["algorithms"]
    assert dist  # bucketed by primitive
    assert dist.get("pke") == 2  # RSA-1024 + RSA-2048
    assert dist.get("hash") == 2  # MD5 + SHA-256


def test_weakness_distribution_non_empty() -> None:
    dist = _run()["cbom_distributions"]["weakness"]
    assert dist
    assert dist.get("WEAK_ALGORITHM", 0) >= 3  # MD5, RC4, 3DES, RSA-1024
    assert dist.get("WEAK_PROTOCOL") == 1  # TLS 1.0


def test_pqc_readiness_non_empty() -> None:
    pqc = _run()["cbom_distributions"]["pqc"]
    assert pqc["quantum_vulnerable"] == 2
    assert pqc["quantum_safe"] >= 1
    assert pqc["readiness_pct"] is not None


def test_certificate_expiry_non_empty() -> None:
    certs = _run()["cbom_distributions"]["certificates"]
    assert certs  # at least the fixture cert.pem
    cert = next(c for c in certs if c["name"] == "cert.pem")
    assert cert["not_valid_after"]
    assert cert["expired"] is False  # valid until 2027
    assert cert["self_signed"] is True


def test_protocol_distribution_non_empty() -> None:
    protocols = _run()["cbom_distributions"]["protocols"]
    assert protocols.get("TLS 1.0") == 1


def test_quantum_vulnerable_count_surfaced() -> None:
    assert _run()["quantum_vulnerable_count"] == 2


# --------------------------------------------------------------------------- #
# Determinism: identical ScanResult -> identical run-object.
# --------------------------------------------------------------------------- #


def test_deterministic() -> None:
    result = scan_crypto(_FX)
    a = normalize_crypto(result, duration_of_scan=0.0)
    b = normalize_crypto(result, duration_of_scan=0.0)
    assert a == b
