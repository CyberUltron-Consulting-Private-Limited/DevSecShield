"""I1 — CBOM host adapter: the crypto lane as a DevSecShield peer scanner.

``scan_crypto_to_devsecshield`` is the CBOM peer of
:func:`aibom.integrations.devsecshield.scan_to_devsecshield`: it scans a repo on
disk through the real CBOM pipeline + normalizer and shapes the result into the
exact run-object the DevSecShield worker returns and the platform persists in
``Scan.scan_data`` (then serves through ``GET …/scan/{id}``).

These tests lock the contract that makes CBOM register with the SAME async job
lifecycle as the other scanners:

* the locked run-object fields (``results`` / ``cbom_json`` / ``duration_of_scan``)
  plus the additive ones (``cbom_compliance`` / ``cbom_scores`` /
  ``cbom_distributions``) the new ``CbomCryptoCharts`` bind to;
* each ``results[]`` row ALSO carries the legacy host keys the backend findings
  serializer (``backend/utilities/db/findings.py`` cbom branch) and the dashboard
  cbom branch (``backend/utilities/dashboard/scan.py``) read —
  ``algorithm_name`` / ``algorithm_type`` / ``crypto_strength`` / ``quantum_safe``
  / ``key_size`` / ``suggested_fix`` — so the existing CBOM dashboard + findings
  pages stay populated after the reconcile (additive, nothing discarded).

No mocks: the CBOM lane touches no network/LLM, so this drives the real fixture.
"""
from __future__ import annotations

import os

from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURE = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _run() -> dict:
    return scan_crypto_to_devsecshield(_FIXTURE)


def test_run_object_carries_locked_and_additive_fields() -> None:
    run = _run()
    # locked contract fields (the cbom persist path reads results + cbom_json)
    assert run["results"], "no crypto findings — CBOM scan returns nothing"
    assert isinstance(run["cbom_json"], dict) and run["cbom_json"].get("components")
    assert isinstance(run["duration_of_scan"], float)
    # additive carry-through (charts + compliance + scores + graph) — never flattened
    assert run["cbom_distributions"]["algorithms"]
    assert run["cbom_compliance"], "tri-state compliance dropped"
    assert run["cbom_scores"], "scores dropped"
    # I1: the normalized crypto dependency graph reaches the run-object so the
    # backend scan-metadata branch (and the F1 dependency-graph viz) can read it.
    graph = run["cbom_graph"]
    assert graph["nodes"], "cbom_graph nodes dropped"
    assert graph["edges"], "cbom_graph edges dropped (cert->algorithm links)"
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in graph["edges"])


def test_every_finding_carries_host_dashboard_keys() -> None:
    """Each row must carry the legacy keys the backend findings serializer +
    dashboard cbom branch read, so neither goes blank after the reconcile."""
    required = {
        "title",
        "impact",
        "description",
        "location",
        "algorithm_name",
        "algorithm_type",
        "crypto_strength",
        "quantum_safe",
        "key_size",
        "suggested_fix",
        "compliance_controls",
        "owasp_top_10",
    }
    for row in _run()["results"]:
        missing = required - row.keys()
        assert not missing, f"finding row missing host keys: {missing}"
        assert row["algorithm_name"] == row["title"]
        # impact is one of the dashboard's recognized bands
        assert row["impact"] in {"Critical", "High", "Medium", "Low"}


def test_dashboard_semantics_are_meaningful() -> None:
    """Re-derive the key dashboard aggregates from the rows exactly as
    ``backend/utilities/dashboard/scan.py`` does, and assert they are non-blank
    and crypto-correct on the reference fixture."""
    rows = _run()["results"]
    # weak algorithms surface as crypto_strength == "weak"
    weak = [r for r in rows if r["crypto_strength"] == "weak"]
    assert weak, "no weak crypto surfaced to the dashboard"
    # certificates classify so the cert card counts them
    certs = [r for r in rows if r["algorithm_type"] == "certificate"]
    assert certs, "certificate not classified for the dashboard cert card"
    # quantum readiness: at least one row is quantum-vulnerable (qs is False),
    # and non-algorithm rows are quantum-N/A (qs is None, bucketed 'unknown')
    quantum_vulnerable = [r for r in rows if r["quantum_safe"] is False]
    assert quantum_vulnerable, "no quantum-vulnerable asset for the PQC card"
    for r in rows:
        if r["algorithm_type"] in {"certificate", "protocol", "key"}:
            assert r["quantum_safe"] is None
        else:
            assert isinstance(r["quantum_safe"], bool)


def test_weak_and_quantum_findings_get_a_remediation() -> None:
    rows = _run()["results"]
    for r in rows:
        assert r["suggested_fix"], "every finding needs a remediation string"
    # a quantum-vulnerable row's fix names the PQC migration target
    qv = next(r for r in rows if r["quantum_safe"] is False)
    assert qv["pqc_migration_target"]
    assert "post-quantum" in qv["suggested_fix"].lower()


def test_adapter_is_deterministic() -> None:
    """Identical input -> identical run-object (duration aside)."""
    a, b = _run(), _run()
    for run in (a, b):
        run.pop("duration_of_scan")
    assert a == b


def test_progress_callback_is_invoked_and_reaches_100() -> None:
    seen: list[int] = []
    scan_crypto_to_devsecshield(_FIXTURE, progress=lambda pct, msg: seen.append(pct))
    assert seen, "progress callback never fired"
    assert max(seen) == 100, "progress never reported completion"
