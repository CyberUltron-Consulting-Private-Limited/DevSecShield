"""I1 — CBOM scan-metadata contract (backend passthrough, hermetic).

The results-page renders the C9/F1 CBOM charts + dependency graph from
``scan_metadata`` (the GET-scan ``data`` field carries only the findings list),
so ``backend/utilities/dashboard/scan_metadata.py``'s cbom branch is the single
path that surfaces the reconciled aibom CBOM lane's additive payload —
``cbom_json`` / ``cbom_distributions`` / ``cbom_compliance`` / ``cbom_scores`` /
``cbom_graph`` — from ``Scan.scan_data``.

This pins that passthrough WITHOUT a live server/DB: ``get_scan_metadata`` reads
only ``scan.scan_metadata`` + ``scan.scan_data``, so a duck-typed stub drives the
real branch. The live end-to-end variant is ``test_cbom_e2e.py``. Two cases:

  * a RECONCILED scan (scan_data carries the aibom keys) -> every key surfaces
    verbatim, so no chart/graph starves;
  * a LEGACY worker scan (scan_data lacks them) -> the keys are present-but-None
    (the frontend then falls back to the legacy CbomDashboardCharts), never a
    KeyError.
"""

import os
import sys
import types

# The dashboard code uses absolute ``backend.*`` imports, so the repo root must
# be importable regardless of the pytest working directory (backend/ or root).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.scan_metadata import get_scan_metadata

# The additive keys the reconciled aibom CBOM lane produces and the results page
# reads from scan_metadata (see backend_api.ts CbomScanMetadata).
_ADDITIVE_KEYS = (
    "cbom_json",
    "cbom_distributions",
    "cbom_compliance",
    "cbom_scores",
    "cbom_graph",
)


def _scan(scan_metadata=None, scan_data=None):
    """A duck-typed Scan (get_scan_metadata reads only these two attrs)."""
    return types.SimpleNamespace(
        scan_metadata=scan_metadata or {}, scan_data=scan_data or {}
    )


def _reconciled_scan_data():
    """A minimal but structurally-real reconciled CBOM run-object."""
    return {
        "results": [{"title": "RSA-2048", "impact": "Medium"}],
        "cbom_json": {"bomFormat": "CycloneDX", "components": []},
        "cbom_distributions": {
            "algorithms": {"pke": 1},
            "weakness": {"WEAK_ALGORITHM": 1},
            "pqc": {"quantum_vulnerable": 1, "quantum_safe": 1, "readiness_pct": 50.0},
            "certificates": [{"name": "cert.pem", "expired": False}],
            "protocols": {"TLS 1.0": 1},
        },
        "cbom_compliance": {"nist_800_57": {"coverage": 0.5}},
        "cbom_scores": {"component_severity": {"crypto-algo-rsa-2048": "medium"}},
        "cbom_graph": {
            "nodes": [{"id": "crypto-algo-rsa-2048", "label": "RSA-2048"}],
            "edges": [{"source": "crypto-cert-x", "target": "crypto-algo-rsa-2048", "rel": "subjectPublicKey"}],
        },
        "duration_of_scan": 1.0,
    }


def test_reconciled_scan_surfaces_all_additive_keys() -> None:
    meta = {"repo_url": "https://example.com/repo", "branch": "main"}
    out = get_scan_metadata("cbom", _scan(meta, _reconciled_scan_data()))
    # base metadata still present
    assert out["repo_url"] == "https://example.com/repo"
    assert out["branch"] == "main"
    # every additive key surfaces verbatim (no flatten/drop)
    src = _reconciled_scan_data()
    for key in _ADDITIVE_KEYS:
        assert key in out, f"{key} missing from cbom scan_metadata"
        assert out[key] == src[key], f"{key} altered in passthrough"


def test_graph_is_surfaced_with_nodes_and_edges() -> None:
    """The F1 dependency-graph reads cbom_graph.nodes / cbom_graph.edges."""
    out = get_scan_metadata("cbom", _scan({}, _reconciled_scan_data()))
    graph = out["cbom_graph"]
    assert graph["nodes"] and graph["edges"]
    ids = {n["id"] for n in graph["nodes"]} | {"crypto-cert-x"}
    for e in graph["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_cbom_posture_is_not_surfaced() -> None:
    data = _reconciled_scan_data()
    data["cbom_posture"] = {"schema_version": 1, "facts": [{"id": "fact"}]}
    out = get_scan_metadata("cbom", _scan({}, data))
    assert "cbom_posture" not in out


def test_legacy_scan_keys_present_but_none() -> None:
    """Legacy worker CBOM scan_data lacks the aibom keys: the branch must still
    return them (as None) so the frontend degrades to the legacy charts."""
    out = get_scan_metadata("cbom", _scan({"branch": "main"}, {"results": []}))
    for key in _ADDITIVE_KEYS:
        assert key in out and out[key] is None
