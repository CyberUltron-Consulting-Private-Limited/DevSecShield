"""BOM dependency-graph compact projections (AIBOM + CBOM).

Full inventory graphs (``ai_bom_graph`` / ``cbom_graph``) stay intact for
contracts and downloads. These helpers build **additive** compact views that
collapse orphan / duplicate-label noise while preserving every connected edge
endpoint — so lineage remains honest and the Card viewport stays readable.

Flags (keyword args; documented for adapters / FE):

* ``max_nodes`` — hard cap after clustering (default 40 compact / 120 expanded).
* ``collapse_orphans`` — CBOM/AIBOM: bucket degree-0 nodes by asset_type/kind.
* ``collapse_duplicate_labels`` — CBOM: merge same-label orphans into ``Label (N)``.
* ``hub_cluster_models`` — AIBOM: collapse model leaves per ``depends_on`` hub.
* ``family_group_models`` — AIBOM: further group hub clusters by label family
  when still over budget (compact); expanded keeps finer families first.

Deterministic: sorted keys → identical input yields identical output.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

COMPACT_MAX_NODES = 40
EXPANDED_MAX_NODES = 120

_FAMILY_RE = re.compile(
    r"^(?P<root>[A-Za-z][\w]*(?:-[A-Za-z][\w]*)?)",
)


def _as_graph(graph: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(graph, dict):
        return {"nodes": [], "edges": []}
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    return {"nodes": nodes, "edges": edges}


def _connected_ids(edges: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for e in edges:
        src, dst = e.get("source"), e.get("target")
        if isinstance(src, str):
            ids.add(src)
        if isinstance(dst, str):
            ids.add(dst)
    return ids


def _sort_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, list]:
    nodes.sort(key=lambda n: str(n.get("id", "")))
    edges.sort(
        key=lambda e: (
            str(e.get("source", "")),
            str(e.get("rel", "")),
            str(e.get("target", "")),
        )
    )
    return {"nodes": nodes, "edges": edges}


def _cluster_node(
    *,
    cluster_id: str,
    label: str,
    members: list[dict[str, Any]],
    template: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    node = dict(template)
    node["id"] = cluster_id
    node["label"] = label
    node["cluster"] = True
    node["cluster_count"] = len(members)
    node["member_ids"] = [str(m["id"]) for m in members]
    if extra:
        node.update(extra)
    return node


def _model_family(label: str) -> str:
    raw = (label or "").strip()
    if not raw:
        return "model"
    m = _FAMILY_RE.match(raw)
    if not m:
        return raw.lower()
    return m.group("root").lower()


def compact_cbom_graph(
    graph: dict[str, Any] | None,
    *,
    max_nodes: int = COMPACT_MAX_NODES,
    collapse_orphans: bool = True,
    collapse_duplicate_labels: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Prune a CBOM inventory graph into a cluster-friendly compact view.

    Connected nodes (any edge endpoint) are never dropped. Orphans collapse by
    duplicate label, then by ``asset_type`` (or ``kind`` for libraries).
    """
    raw = _as_graph(graph)
    nodes, edges = raw["nodes"], raw["edges"]
    if not nodes:
        return {"nodes": [], "edges": []}

    by_id = {str(n["id"]): n for n in nodes if "id" in n}
    connected = _connected_ids(edges)
    kept: list[dict[str, Any]] = [dict(by_id[i]) for i in sorted(connected) if i in by_id]
    orphans = [dict(n) for n in nodes if str(n.get("id")) not in connected]

    if collapse_duplicate_labels and orphans:
        by_label: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for n in orphans:
            at = str(n.get("asset_type") or n.get("kind") or "other")
            lab = str(n.get("label") or n.get("id"))
            by_label[(at, lab)].append(n)
        orphans = []
        for (at, lab), members in sorted(by_label.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            if len(members) == 1:
                orphans.append(members[0])
            else:
                orphans.append(
                    _cluster_node(
                        cluster_id=f"cluster:dup:{at}:{lab}",
                        label=f"{lab} ({len(members)})",
                        members=members,
                        template=members[0],
                        extra={"asset_type": at if at != "other" else members[0].get("asset_type")},
                    )
                )

    if collapse_orphans and orphans:
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for n in orphans:
            at = str(
                n.get("asset_type")
                or (
                    "library"
                    if n.get("kind") == "framework"
                    else n.get("kind") or "other"
                )
            )
            by_type[at].append(n)
        orphans = []
        for at, members in sorted(by_type.items()):
            count = sum(int(m.get("cluster_count") or 1) for m in members)
            member_ids: list[str] = []
            for m in members:
                member_ids.extend(m.get("member_ids") or [str(m["id"])])
            orphans.append(
                _cluster_node(
                    cluster_id=f"cluster:orphan:{at}",
                    label=f"Unlinked {at} ({count})",
                    members=[{"id": mid} for mid in member_ids],
                    template={
                        "kind": members[0].get("kind", "crypto_asset"),
                        "asset_type": None if at == "library" else at,
                        "weak": any(bool(m.get("weak")) for m in members),
                        "quantum_vulnerable": any(
                            bool(m.get("quantum_vulnerable")) for m in members
                        ),
                        "impact": members[0].get("impact"),
                        "primitive": None,
                    },
                    extra={
                        "asset_type": None if at == "library" else at,
                        "kind": members[0].get("kind", "crypto_asset"),
                    },
                )
            )

    kept.extend(orphans)

    # If still over budget, merge remaining non-connected clusters by type.
    if len(kept) > max_nodes:
        connected_nodes = [n for n in kept if str(n["id"]) in connected]
        extras = [n for n in kept if str(n["id"]) not in connected]
        budget = max(0, max_nodes - len(connected_nodes))
        if budget == 0:
            kept = connected_nodes
        elif len(extras) > budget:
            # coarsen all extras into as few type buckets as needed
            by_type = defaultdict(list)
            for n in extras:
                at = str(n.get("asset_type") or n.get("kind") or "other")
                by_type[at].append(n)
            coarsened: list[dict[str, Any]] = []
            for at, members in sorted(by_type.items()):
                count = sum(int(m.get("cluster_count") or 1) for m in members)
                member_ids: list[str] = []
                for m in members:
                    member_ids.extend(m.get("member_ids") or [str(m["id"])])
                coarsened.append(
                    _cluster_node(
                        cluster_id=f"cluster:coalesce:{at}",
                        label=f"Unlinked {at} ({count})",
                        members=[{"id": mid} for mid in member_ids],
                        template={
                            "kind": members[0].get("kind", "crypto_asset"),
                            "asset_type": None if at in {"library", "framework"} else at,
                            "weak": any(bool(m.get("weak")) for m in members),
                            "quantum_vulnerable": any(
                                bool(m.get("quantum_vulnerable")) for m in members
                            ),
                        },
                    )
                )
            # if still too many type buckets, keep strongest connected only + one overflow
            if len(connected_nodes) + len(coarsened) > max_nodes:
                overflow = coarsened[max(0, max_nodes - len(connected_nodes) - 1) :]
                head = coarsened[: max(0, max_nodes - len(connected_nodes) - (1 if overflow else 0))]
                if overflow:
                    ids = []
                    total = 0
                    for m in overflow:
                        ids.extend(m.get("member_ids") or [str(m["id"])])
                        total += int(m.get("cluster_count") or 1)
                    head.append(
                        _cluster_node(
                            cluster_id="cluster:coalesce:overflow",
                            label=f"Unlinked other ({total})",
                            members=[{"id": i} for i in ids],
                            template={"kind": "crypto_asset", "asset_type": "other"},
                        )
                    )
                coarsened = head
            kept = connected_nodes + coarsened
        else:
            kept = connected_nodes + extras

    # Drop edges that no longer resolve (should not happen for connected set).
    ids = {str(n["id"]) for n in kept}
    kept_edges = [
        e
        for e in edges
        if str(e.get("source")) in ids and str(e.get("target")) in ids
    ]
    return _with_meta(
        raw,
        _sort_graph(kept, kept_edges),
        lane="cbom",
        max_nodes=max_nodes,
    )


def _with_meta(
    raw: dict[str, Any],
    view: dict[str, Any],
    *,
    lane: str,
    max_nodes: int,
) -> dict[str, Any]:
    nodes = list(view.get("nodes") or [])
    edges = list(view.get("edges") or [])
    raw_nodes = list((raw or {}).get("nodes") or [])
    raw_edges = list((raw or {}).get("edges") or [])
    clustered = sum(
        int(n.get("cluster_count") or n.get("clustered_count") or 0)
        for n in nodes
        if n.get("cluster") or n.get("is_cluster")
    )
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "lane": lane,
            "raw_node_count": len(raw_nodes),
            "raw_edge_count": len(raw_edges),
            "view_node_count": len(nodes),
            "view_edge_count": len(edges),
            "clustered_members": clustered,
            "max_nodes": max_nodes,
        },
    }


def compact_aibom_graph(
    graph: dict[str, Any] | None,
    *,
    max_nodes: int = COMPACT_MAX_NODES,
    hub_cluster_models: bool = True,
    family_group_models: bool = True,
    collapse_orphans: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Prune an AIBOM supply-chain graph: hub/family model clusters + orphan buckets."""
    raw = _as_graph(graph)
    nodes, edges = raw["nodes"], raw["edges"]
    if not nodes:
        return {"nodes": [], "edges": []}

    by_id = {str(n["id"]): dict(n) for n in nodes if "id" in n}
    connected = _connected_ids(edges)

    # Model → hub via depends_on (model is typically source).
    model_to_hub: dict[str, str] = {}
    other_edges: list[dict[str, Any]] = []
    for e in edges:
        src, dst, rel = str(e.get("source")), str(e.get("target")), str(e.get("rel") or "")
        src_n, dst_n = by_id.get(src), by_id.get(dst)
        if (
            hub_cluster_models
            and rel == "depends_on"
            and src_n
            and src_n.get("kind") == "model"
        ):
            model_to_hub[src] = dst
        else:
            other_edges.append(e)

    clustered_models = set(model_to_hub)
    kept: list[dict[str, Any]] = []
    new_edges: list[dict[str, Any]] = list(other_edges)

    # Non-model nodes + models not hub-clustered
    for nid, n in sorted(by_id.items()):
        if nid in clustered_models:
            continue
        kept.append(dict(n))

    if hub_cluster_models and model_to_hub:
        by_hub: dict[str, list[str]] = defaultdict(list)
        for mid, hub in model_to_hub.items():
            by_hub[hub].append(mid)

        for hub, mids in sorted(by_hub.items(), key=lambda kv: kv[0]):
            members = [by_id[m] for m in sorted(mids) if m in by_id]
            if not members:
                continue
            hub_label = (by_id.get(hub) or {}).get("label") or hub

            if family_group_models and len(members) > 1:
                by_fam: dict[str, list[dict[str, Any]]] = defaultdict(list)
                for m in members:
                    by_fam[_model_family(str(m.get("label") or ""))].append(m)
                # Prefer family groups when multiple families OR when over budget
                use_families = len(by_fam) > 1 or len(kept) + len(by_hub) > max_nodes
                if use_families and len(by_fam) > 1:
                    for fam, fam_members in sorted(by_fam.items()):
                        cid = f"cluster:models:{hub}:{fam}"
                        kept.append(
                            _cluster_node(
                                cluster_id=cid,
                                label=f"{fam}* → {hub_label} ({len(fam_members)})",
                                members=fam_members,
                                template={
                                    "kind": "model",
                                    "type": fam_members[0].get("type", "model"),
                                },
                            )
                        )
                        new_edges.append(
                            {"source": cid, "target": hub, "rel": "depends_on"}
                        )
                    continue

            cid = f"cluster:models:{hub}"
            kept.append(
                _cluster_node(
                    cluster_id=cid,
                    label=f"Models → {hub_label} ({len(members)})",
                    members=members,
                    template={"kind": "model", "type": members[0].get("type", "model")},
                )
            )
            new_edges.append({"source": cid, "target": hub, "rel": "depends_on"})

    if collapse_orphans:
        connected_after = _connected_ids(new_edges)
        for e in edges:
            for k in ("source", "target"):
                v = e.get(k)
                if isinstance(v, str):
                    connected_after.add(v)
        orphan_ids = {
            str(n["id"])
            for n in kept
            if str(n["id"]) not in connected_after and not n.get("cluster")
        }
        if orphan_ids:
            orphans = [n for n in kept if str(n["id"]) in orphan_ids]
            kept = [n for n in kept if str(n["id"]) not in orphan_ids]
            by_kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for n in orphans:
                by_kind[str(n.get("kind") or "other")].append(n)
            for kind, members in sorted(by_kind.items()):
                kept.append(
                    _cluster_node(
                        cluster_id=f"cluster:orphan:{kind}",
                        label=f"Unlinked {kind} ({len(members)})",
                        members=members,
                        template={"kind": kind, "type": members[0].get("type")},
                    )
                )

    if len(kept) > max_nodes:
        # Prefer keeping hubs / non-cluster nodes with degree, then clusters
        deg: dict[str, int] = defaultdict(int)
        for e in new_edges:
            deg[str(e.get("source"))] += 1
            deg[str(e.get("target"))] += 1
        kept.sort(
            key=lambda n: (
                0 if deg[str(n["id"])] else 1,
                0 if not n.get("cluster") else 1,
                -int(n.get("cluster_count") or 1),
                str(n.get("id")),
            )
        )
        kept = kept[:max_nodes]
        ids = {str(n["id"]) for n in kept}
        new_edges = [
            e
            for e in new_edges
            if str(e.get("source")) in ids and str(e.get("target")) in ids
        ]

    ids = {str(n["id"]) for n in kept}
    new_edges = [
        e
        for e in new_edges
        if str(e.get("source")) in ids and str(e.get("target")) in ids
    ]
    return _with_meta(
        raw,
        _sort_graph(kept, new_edges),
        lane="aibom",
        max_nodes=max_nodes,
    )


def model_family(label: str) -> str:
    """Public alias used by tests / FE docs (``gpt-4-0613`` → ``gpt-4``)."""
    return _model_family(label)


def build_graph_view(
    graph: dict[str, Any] | None,
    *,
    lane: str,
    max_nodes: int = COMPACT_MAX_NODES,
) -> dict[str, Any]:
    """Unified compact projection used by normalize + scan_metadata.

    Returns ``{nodes, edges, meta}``. ``lane`` is ``\"aibom\"`` or ``\"cbom\"``.
    Compact Card uses ``COMPACT_MAX_NODES`` (40); fullscreen Dialog uses
    ``EXPANDED_MAX_NODES`` (120).
    """
    raw_nodes = list((graph or {}).get("nodes") or [])
    raw_edges = list((graph or {}).get("edges") or [])
    if lane == "cbom":
        # Compact: orphan type buckets. Expanded: duplicate-label clusters only.
        view = compact_cbom_graph(
            graph,
            max_nodes=max_nodes,
            collapse_orphans=max_nodes <= COMPACT_MAX_NODES,
            collapse_duplicate_labels=True,
        )
    else:
        view = compact_aibom_graph(
            graph,
            max_nodes=max_nodes,
            hub_cluster_models=True,
            family_group_models=True,
            collapse_orphans=max_nodes <= COMPACT_MAX_NODES,
        )
    # Normalize cluster flag names for FE (accept both styles).
    nodes: list[dict[str, Any]] = []
    clustered_members = 0
    for n in view["nodes"]:
        node = dict(n)
        if node.get("cluster") or node.get("is_cluster"):
            node["is_cluster"] = True
            node["cluster"] = True
            count = int(node.get("cluster_count") or node.get("clustered_count") or 1)
            node["cluster_count"] = count
            node["clustered_count"] = count
            clustered_members += count
        nodes.append(node)
    edges = list(view["edges"])
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "lane": lane,
            "raw_node_count": len(raw_nodes),
            "raw_edge_count": len(raw_edges),
            "view_node_count": len(nodes),
            "view_edge_count": len(edges),
            "clustered_members": clustered_members,
            "max_nodes": max_nodes,
        },
    }


DEFAULT_MAX_NODES = COMPACT_MAX_NODES

__all__ = [
    "COMPACT_MAX_NODES",
    "EXPANDED_MAX_NODES",
    "DEFAULT_MAX_NODES",
    "compact_aibom_graph",
    "compact_cbom_graph",
    "build_graph_view",
    "model_family",
]
