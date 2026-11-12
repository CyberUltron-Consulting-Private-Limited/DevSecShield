"""Hermetic tests for backend bom_graph_view (scan_metadata lazy prune)."""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dashboard.bom_graph_view import (  # noqa: E402
    COMPACT_MAX_NODES,
    compact_cbom_graph,
)
from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402
import types  # noqa: E402


def test_lazy_compact_from_full_graph_in_scan_metadata() -> None:
    nodes = [
        {"id": "c", "label": "cert", "kind": "crypto_asset", "asset_type": "certificate"},
        {"id": "a", "label": "RSA-2048", "kind": "crypto_asset", "asset_type": "algorithm"},
    ]
    for i in range(50):
        nodes.append(
            {
                "id": f"o{i}",
                "label": "secret-key",
                "kind": "crypto_asset",
                "asset_type": "related-crypto-material",
            }
        )
    full = {
        "nodes": nodes,
        "edges": [{"source": "c", "target": "a", "rel": "subjectPublicKey"}],
    }
    scan = types.SimpleNamespace(
        scan_metadata={},
        scan_data={"cbom_graph": full, "results": []},
    )
    out = get_scan_metadata("cbom", scan)
    assert out["cbom_graph"] == full
    compact = out["cbom_graph_compact"]
    assert compact is not None
    assert len(compact["nodes"]) <= COMPACT_MAX_NODES
    assert len(compact["nodes"]) < len(full["nodes"])


def test_compact_helper_direct() -> None:
    g = {
        "nodes": [
            {"id": "1", "label": "x", "kind": "crypto_asset", "asset_type": "algorithm"},
            {"id": "2", "label": "x", "kind": "crypto_asset", "asset_type": "algorithm"},
        ],
        "edges": [],
    }
    view = compact_cbom_graph(g, max_nodes=40)
    assert len(view["nodes"]) == 1
    assert view["nodes"][0].get("cluster") or "Unlinked" in view["nodes"][0]["label"]
