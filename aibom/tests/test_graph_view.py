"""Hermetic tests for BOM graph compact projections (AIBOM + CBOM)."""

from __future__ import annotations

from aibom.graph_view import (
    COMPACT_MAX_NODES,
    EXPANDED_MAX_NODES,
    build_graph_view,
    compact_aibom_graph,
    compact_cbom_graph,
    model_family,
)


def _cbom_noisy() -> dict:
    """Simulate pyjwt-like inventory: few edges, many duplicate orphans."""
    nodes = [
        {"id": "cert-1", "label": "CN=leaf", "kind": "crypto_asset", "asset_type": "certificate"},
        {"id": "rsa", "label": "RSA-2048", "kind": "crypto_asset", "asset_type": "algorithm"},
        {"id": "sha", "label": "SHA-256", "kind": "crypto_asset", "asset_type": "algorithm"},
    ]
    for i in range(37):
        nodes.append(
            {
                "id": f"secret-{i}",
                "label": "secret-key (secret, test_api_jwt.py)",
                "kind": "crypto_asset",
                "asset_type": "related-crypto-material",
                "weak": True,
            }
        )
    for i in range(10):
        nodes.append(
            {
                "id": f"algo-ed-{i}",
                "label": "Ed25519",
                "kind": "crypto_asset",
                "asset_type": "algorithm",
            }
        )
    edges = [
        {"source": "cert-1", "target": "rsa", "rel": "subjectPublicKey"},
        {"source": "cert-1", "target": "sha", "rel": "signatureAlgorithm"},
    ]
    return {"nodes": nodes, "edges": edges}


def _aibom_star() -> dict:
    nodes = [{"id": "lib-openai", "label": "openai", "kind": "framework", "type": "ml_framework"}]
    edges = []
    for i in range(148):
        mid = f"model-{i}"
        fam = "gpt-4" if i % 2 == 0 else "gpt-3.5"
        nodes.append({"id": mid, "label": f"{fam}-{i}", "kind": "model", "type": "model"})
        edges.append({"source": mid, "target": "lib-openai", "rel": "depends_on"})
    for i in range(5):
        nodes.append({"id": f"orphan-lib-{i}", "label": f"unused-{i}", "kind": "framework"})
    return {"nodes": nodes, "edges": edges}


def test_model_family_tokens() -> None:
    assert model_family("gpt-4-0613").startswith("gpt")
    assert model_family("text-embedding-3-small")


def test_cbom_compact_keeps_connected_and_collapses_orphans() -> None:
    raw = _cbom_noisy()
    view = compact_cbom_graph(raw, max_nodes=COMPACT_MAX_NODES)
    ids = {n["id"] for n in view["nodes"]}
    assert "cert-1" in ids and "rsa" in ids and "sha" in ids
    assert len(view["edges"]) == 2
    assert len(view["nodes"]) <= COMPACT_MAX_NODES
    assert len(view["nodes"]) < len(raw["nodes"])
    # Orphan materials should be bucketed, not 37 peers.
    materialish = [
        n
        for n in view["nodes"]
        if "related-crypto-material" in str(n.get("label"))
        or n.get("asset_type") == "related-crypto-material"
        or "orphan" in str(n.get("id"))
    ]
    assert materialish, "expected an Unlinked related-crypto-material cluster"
    assert all(n.get("cluster") or n.get("is_cluster") or "Unlinked" in str(n.get("label")) for n in materialish)


def test_cbom_expanded_allows_duplicate_label_clusters() -> None:
    raw = _cbom_noisy()
    view = compact_cbom_graph(
        raw,
        max_nodes=EXPANDED_MAX_NODES,
        collapse_orphans=False,
        collapse_duplicate_labels=True,
    )
    assert len(view["nodes"]) <= EXPANDED_MAX_NODES
    labels = [n["label"] for n in view["nodes"]]
    assert any("secret-key" in lab and "(" in lab for lab in labels)


def test_aibom_compact_hub_clusters_models() -> None:
    raw = _aibom_star()
    view = compact_aibom_graph(raw, max_nodes=COMPACT_MAX_NODES)
    assert len(view["nodes"]) <= COMPACT_MAX_NODES
    assert len(view["nodes"]) < len(raw["nodes"])
    assert any(
        n.get("kind") == "model" and (n.get("cluster") or "Models" in str(n.get("label")) or "*" in str(n.get("label")))
        for n in view["nodes"]
    )
    # Hub preserved
    assert any(n["id"] == "lib-openai" for n in view["nodes"])
    # Edges still resolve
    ids = {n["id"] for n in view["nodes"]}
    for e in view["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_build_graph_view_meta_and_caps() -> None:
    raw = _cbom_noisy()
    compact = build_graph_view(raw, lane="cbom", max_nodes=COMPACT_MAX_NODES)
    assert compact["meta"]["raw_node_count"] == len(raw["nodes"])
    assert compact["meta"]["view_node_count"] == len(compact["nodes"])
    assert compact["meta"]["view_node_count"] <= COMPACT_MAX_NODES

    araw = _aibom_star()
    av = build_graph_view(araw, lane="aibom", max_nodes=COMPACT_MAX_NODES)
    assert av["meta"]["view_node_count"] <= COMPACT_MAX_NODES
    assert av["meta"]["view_node_count"] < av["meta"]["raw_node_count"]
