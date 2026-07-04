"""CBOM CHART-DATA-CONTRACT — prevents the empty-crypto-chart regression (C10).

The CBOM results page renders five charts the engine must feed, all bound to the
``normalize_crypto`` run-object's ``cbom_distributions`` (see
``frontend/components/cbom/CbomCryptoCharts.tsx``):

  * Algorithm distribution   <- distributions.algorithms   (by crypto primitive)
  * Weak-crypto findings      <- distributions.weakness     (by WEAK_*/EXPIRED code)
  * PQC readiness gauge       <- distributions.pqc          (readiness_pct, q-v/safe)
  * Certificate expiry        <- distributions.certificates (per-cert rows)
  * Protocol / TLS            <- distributions.protocols    (by protocol label)

Each chart renders an ``EmptyChart`` placeholder when its backing array is empty,
so this test scans the real synthetic-crypto fixture through the REAL pipeline +
normalizer (no mocks — the CBOM lane touches no network/LLM) and asserts the
EXACT non-empty predicate each chart uses to decide it has data. If a future
change re-flattens or starves any distribution, this fails before it reaches the
UI — the C10 analogue of the AIBOM ``test_chart_data_contract.py`` guard.
"""
from __future__ import annotations

import os

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURE = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _distributions() -> dict:
    """Scan the crypto fixture through the real pipeline + normalizer."""
    run = normalize_crypto(scan_crypto(_FIXTURE), duration_of_scan=0.0)
    return run


def test_run_object_carries_results_and_distributions() -> None:
    run = _distributions()
    assert run["results"], "no crypto-asset findings — every CBOM chart starves"
    assert run.get("cbom_distributions"), "cbom_distributions missing/flattened"


def test_algorithm_distribution_non_empty() -> None:
    """AlgorithmDistribution renders rows from ``Object.entries(algorithms)``."""
    dist = _distributions()["cbom_distributions"]["algorithms"]
    assert dist, "algorithms{} EMPTY -> Algorithm-distribution chart is blank"
    assert all(isinstance(v, int) and v > 0 for v in dist.values())


def test_weakness_distribution_non_empty() -> None:
    """WeakCryptoFindings renders rows from ``Object.entries(weakness)``."""
    dist = _distributions()["cbom_distributions"]["weakness"]
    assert dist, "weakness{} EMPTY -> Weak-crypto-findings chart is blank"
    assert all(isinstance(v, int) and v > 0 for v in dist.values())


def test_pqc_readiness_gauge_has_data() -> None:
    """PqcReadinessGauge shows ``EmptyChart`` when no quantum-relevant algorithms
    exist (quantum_vulnerable + quantum_safe == 0) or readiness_pct is null."""
    pqc = _distributions()["cbom_distributions"]["pqc"]
    graded = pqc["quantum_vulnerable"] + pqc["quantum_safe"]
    assert graded > 0, "no quantum-relevant algorithms -> PQC gauge is blank"
    assert pqc["readiness_pct"] is not None, "readiness_pct null -> gauge blank"
    assert 0.0 <= pqc["readiness_pct"] <= 100.0


def test_certificate_expiry_rows_non_empty() -> None:
    """CertificateExpiry renders when ``certificates[].length > 0``."""
    certs = _distributions()["cbom_distributions"]["certificates"]
    assert certs, "certificates[] EMPTY -> Certificate-expiry chart is blank"
    for row in certs:
        assert "name" in row and "expired" in row and "self_signed" in row


def test_protocol_distribution_non_empty() -> None:
    """ProtocolTls renders rows from ``Object.entries(protocols)``."""
    dist = _distributions()["cbom_distributions"]["protocols"]
    assert dist, "protocols{} EMPTY -> Protocol/TLS chart is blank"
    assert all(isinstance(v, int) and v > 0 for v in dist.values())


def test_no_cbom_chart_can_silently_go_blank() -> None:
    """Consolidated guard: ALL five chart-backing arrays are non-empty at once,
    so the whole CBOM dashboard renders with data on the reference fixture."""
    dist = _distributions()["cbom_distributions"]
    pqc = dist["pqc"]
    assert dist["algorithms"], "algorithms[] blank"
    assert dist["weakness"], "weakness[] blank"
    assert (pqc["quantum_vulnerable"] + pqc["quantum_safe"]) > 0, "pqc gauge blank"
    assert pqc["readiness_pct"] is not None, "pqc readiness_pct blank"
    assert dist["certificates"], "certificates[] blank"
    assert dist["protocols"], "protocols[] blank"
