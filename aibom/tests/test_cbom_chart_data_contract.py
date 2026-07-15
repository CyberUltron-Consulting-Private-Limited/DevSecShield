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


# ── F1: asset-type breakdown + crypto dependency-graph (cbom_graph) ──────────
# The F1 results-page adds two graph-fed visualizations bound to the I1
# ``cbom_graph`` {nodes, edges} projection (see CbomCryptoCharts.tsx):
#   * Asset-type distribution  <- graph.nodes grouped by node.asset_type
#                                  (falling back to "library" for kind==framework)
#   * Crypto dependency graph  <- graph.nodes + graph.edges (React Flow)
# These lock the payload so neither graph-fed chart can silently starve.


def test_cbom_graph_present_with_nodes_and_edges() -> None:
    """The dependency-graph viz reads ``cbom_graph`` {nodes, edges}; both must be
    lists and the fixture must carry inventory nodes AND at least one edge."""
    graph = _distributions()["cbom_graph"]
    assert isinstance(graph, dict), "cbom_graph missing/flattened"
    assert isinstance(graph["nodes"], list) and graph["nodes"], "graph nodes blank"
    assert isinstance(graph["edges"], list) and graph["edges"], (
        "graph edges blank -> CryptoDependencyGraph draws no lineage"
    )


def test_cbom_graph_nodes_carry_asset_type_fields() -> None:
    """Each graph node carries the fields the AssetTypeDistribution + node styling
    read (id/label/kind + optional asset_type/weak/quantum_vulnerable)."""
    nodes = _distributions()["cbom_graph"]["nodes"]
    for n in nodes:
        assert n.get("id") and n.get("label") and n.get("kind"), "node field missing"
        assert "asset_type" in n and "weak" in n and "quantum_vulnerable" in n


def test_asset_type_distribution_non_empty_and_multi_type() -> None:
    """AssetTypeDistribution buckets nodes by ``asset_type`` (or "library" for a
    framework node). The fixture must yield >1 distinct asset class so the chart
    is a real breakdown, not a single bar."""
    nodes = _distributions()["cbom_graph"]["nodes"]
    buckets: dict[str, int] = {}
    for n in nodes:
        key = n["asset_type"] or ("library" if n["kind"] == "framework" else "other")
        buckets[key] = buckets.get(key, 0) + 1
    assert buckets, "asset-type breakdown EMPTY -> chart is blank"
    assert len(buckets) > 1, "only one asset class -> breakdown chart is degenerate"
    # the fixture inventories algorithms, a cert, a protocol, key material + libs
    assert "algorithm" in buckets and "certificate" in buckets


def test_cbom_graph_edges_resolve_to_inventory_nodes() -> None:
    """Every edge endpoint resolves to a node id (React Flow drops edges whose
    source/target is absent), and each edge carries a ``rel`` label."""
    graph = _distributions()["cbom_graph"]
    ids = {n["id"] for n in graph["nodes"]}
    for e in graph["edges"]:
        assert e["source"] in ids, f"dangling edge source {e['source']}"
        assert e["target"] in ids, f"dangling edge target {e['target']}"
        assert e.get("rel"), "edge missing rel label"


# ── F2: PQC readiness gauge + quantum-vulnerable list + migration roadmap ─────
# The F2 results-page section binds to the ``distributions.pqc`` payload the C7
# grader carries through (see CbomCryptoCharts.tsx PqcReadinessPanel):
#   * PQC readiness gauge      <- pqc.readiness_pct + quantum_safe/vulnerable/hybrid
#   * Quantum-vulnerable list  <- pqc.migration[] (one row per q-v algorithm)
#   * Migration-roadmap panel  <- pqc.migration[].migration_roadmap (sized target)
# These lock the payload so the PQC panel can never silently starve.


def test_pqc_carries_hybrid_and_nist_level_histogram() -> None:
    """The gauge sub-badges + NIST-level histogram read ``pqc.hybrid`` and
    ``pqc.nist_level_distribution`` (level -> count), both always present."""
    pqc = _distributions()["cbom_distributions"]["pqc"]
    assert "hybrid" in pqc and isinstance(pqc["hybrid"], int)
    hist = pqc["nist_level_distribution"]
    assert isinstance(hist, dict) and hist, "NIST-level histogram blank"
    # level-0 == the two quantum-vulnerable RSA keys on the fixture
    assert int(hist.get("0", 0)) == pqc["quantum_vulnerable"]


def test_pqc_migration_rows_present_for_every_vulnerable_algorithm() -> None:
    """QuantumVulnerableList + MigrationRoadmap render from ``pqc.migration``:
    one row per quantum-vulnerable algorithm, each carrying the fields the panel
    reads (name / primitive / NIST level 0 / sized migration roadmap)."""
    pqc = _distributions()["cbom_distributions"]["pqc"]
    migration = pqc["migration"]
    assert isinstance(migration, list)
    assert len(migration) == pqc["quantum_vulnerable"], (
        "migration rows must cover every quantum-vulnerable algorithm"
    )
    assert migration, "no migration rows -> PQC roadmap panel is blank"
    for row in migration:
        assert row.get("name"), "migration row missing algorithm name"
        assert "primitive" in row and "key_size" in row and "curve" in row
        assert row["nist_quantum_security_level"] == 0, (
            "a quantum-vulnerable algorithm is NIST quantum level 0"
        )
        assert row.get("migration_target"), "migration row missing target family"
        assert row.get("migration_roadmap"), "migration row missing sized roadmap"
        assert row.get("impact"), "migration row missing impact"


def test_pqc_migration_rows_are_deterministically_ordered() -> None:
    """The list renders in a stable order (impact rank, then name) so identical
    input yields identical output (no React key churn / flaky snapshots)."""
    migration = _distributions()["cbom_distributions"]["pqc"]["migration"]
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    keys = [(rank.get(r["impact"], 9), str(r["name"])) for r in migration]
    assert keys == sorted(keys), "migration rows not deterministically ordered"


# ── F3: expanded compliance tri-state matrix ─────────────────────────────────
# The F3 results-page section binds to ``cbom_compliance`` (result.compliance the
# CBOM lane fills via run_cbom_compliance across all 10 frameworks; see
# CbomCryptoCharts.tsx CbomComplianceMatrix). Every framework key MUST carry a
# human label in the FE FRAMEWORK map (below) or the matrix shows a raw snake_key,
# and every framework MUST carry the six tri-state counts + coverage + a
# per-requirement drilldown so no framework row silently starves.

# The 10 CBOM frameworks the aibom lane registers (compliance.CBOM_FRAMEWORKS).
# Kept in lockstep with the FE ``CBOM_FRAMEWORK_LABELS`` map — a new framework
# with no FE label would render its raw snake_case key, which this set forbids.
_EXPECTED_FRAMEWORKS = {
    "nist_1800_38b",
    "nist_800_57",
    "omb_m_23_02",
    "eu_cra",
    "eu_dora",
    "pci_dss_4",
    "fips_140_3",
    "bsi_tr_02102",
    "nist_1800_38c",
    "cnsa_2_0",
    "rbi_free_ai_protection",
}
_VERDICTS = {
    "pass",
    "pass_with_evidence",
    "fail",
    "out_of_scope",
    "not_bom_evidenceable",
    "na",
}


def _compliance() -> dict:
    return _distributions()["cbom_compliance"]


def test_cbom_compliance_present_with_all_frameworks() -> None:
    """The matrix reads every framework in ``cbom_compliance`` (skipping the
    ``disclaimer`` string). The framework key-set must exactly equal the FE's
    labelled set so no framework renders as a raw snake_case key."""
    comp = _compliance()
    assert isinstance(comp, dict) and comp, "cbom_compliance missing/flattened"
    keys = {k for k, v in comp.items() if k != "disclaimer" and isinstance(v, dict)}
    assert keys == _EXPECTED_FRAMEWORKS, (
        f"framework set drifted from the FE label map: {keys ^ _EXPECTED_FRAMEWORKS}"
    )


def test_cbom_compliance_frameworks_carry_tristate_counts() -> None:
    """Each framework carries the six tri-state counts (ints) + a coverage value
    (None or a 0..1 fraction) so the stacked bar + coverage% never NaN."""
    comp = _compliance()
    for key in _EXPECTED_FRAMEWORKS:
        fw = comp[key]
        for state in _VERDICTS:
            assert isinstance(fw.get(state), int) and fw[state] >= 0, (
                f"{key}.{state} not a non-negative int -> bar segment NaN"
            )
        cov = fw["coverage"]
        assert cov is None or (isinstance(cov, (int, float)) and 0.0 <= cov <= 1.0)


def test_cbom_compliance_requirements_drilldown_is_populated() -> None:
    """Clicking a framework bar opens its requirement table — each requirement
    carries id/title/verdict (verdict in the tri-state set) so the drilldown
    can render a verdict badge for every row."""
    comp = _compliance()
    for key in _EXPECTED_FRAMEWORKS:
        reqs = comp[key]["requirements"]
        assert isinstance(reqs, list) and reqs, f"{key} has no requirements to drill"
        for r in reqs:
            assert r.get("id") and r.get("title"), f"{key} requirement missing id/title"
            assert r["verdict"] in _VERDICTS, f"{key}.{r['id']} bad verdict"


def test_cbom_compliance_matrix_is_not_blank_and_is_tri_state() -> None:
    """Consolidated guard: at least one framework has a non-zero stacked bar AND
    at least one carries a real fail AND at least one has a computed coverage, so
    the matrix renders a meaningful tri-state breakdown on the reference fixture
    (a weak repo — every strong-crypto framework should surface failures)."""
    comp = _compliance()
    fws = [comp[k] for k in _EXPECTED_FRAMEWORKS]
    assert any(sum(fw[s] for s in _VERDICTS) > 0 for fw in fws), "every bar blank"
    assert any(fw["fail"] > 0 for fw in fws), "no failures -> tri-state degenerate"
    assert any(fw["coverage"] is not None for fw in fws), "no coverage computed"
