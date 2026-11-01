"""The detailed crypto dependency graph shown on the results page (compact and expanded views).

The inventory graph (``cbom_graph``) has one node per crypto asset or library and the CycloneDX lineage edges
(certificate -> key/signature algorithm, protocol -> cipher-suite algorithms, material -> algorithm) plus
library -> algorithm "provides" edges. For a code scan that is mostly a flat list, so this view adds three
layers that exist only in the picture (never in the CycloneDX inventory or the asset counts):

    folder  --contains-->  asset  <--provides--  library
                             |
                           is a
                             v
                   algorithm family (hash functions, block ciphers, public-key, ...)

It stays readable on big repositories: a node budget is spent on the riskiest assets first (weak, then
quantum-vulnerable, then by impact); the rest are folded into one "+N more" node per family, folders beyond the
budget into "other folders", libraries without a shown asset into one cluster. Parallel edges are merged.
Deterministic: same input, same output.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

FAMILY_LABEL = {
    "hash": "Hash functions", "block-cipher": "Block ciphers", "stream-cipher": "Stream ciphers",
    "ae": "Authenticated encryption", "pke": "Public-key encryption", "signature": "Digital signatures",
    "key-agree": "Key agreement", "kem": "Key encapsulation (KEM)", "kdf": "Key derivation", "mac": "MACs",
    "drbg": "Random generators", "combiner": "Hybrid schemes", "xof": "Extendable-output functions",
    "protocol": "Protocols", "certificate": "Certificates", "related-crypto-material": "Keys and secrets",
    "other": "Other primitives",
}
_IMPACT = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _family(node: dict[str, Any]) -> str:
    at = node.get("asset_type")
    if at in ("protocol", "certificate", "related-crypto-material"):
        return str(at)
    return str(node.get("primitive") or "other") if at == "algorithm" else "other"


def _folder(location: str | None, depth: int = 2) -> str:
    loc = (location or "").split(":", 1)[0].strip("/")
    if "/" not in loc:
        return "(repository root)"
    parts = loc.split("/")[:-1]
    return "/".join(parts[:depth]) + "/"


def _risk_key(n: dict[str, Any]) -> tuple:
    return (0 if n.get("weak") else 1, 0 if n.get("quantum_vulnerable") else 1,
            _IMPACT.get(str(n.get("impact")), 9), str(n.get("label")), str(n.get("id")))


def build_detailed(full: dict[str, Any] | None, *, max_nodes: int = 40, max_folders: int | None = None
                   ) -> dict[str, Any]:
    full = full or {}
    nodes = [dict(n) for n in full.get("nodes") or [] if isinstance(n, dict) and "id" in n]
    edges = [e for e in full.get("edges") or [] if isinstance(e, dict)]
    if not nodes:
        return {"nodes": [], "edges": [], "meta": {"assets": 0, "shown_assets": 0}}
    assets = sorted((n for n in nodes if n.get("kind") == "crypto_asset"), key=_risk_key)
    libs = {n["id"]: n for n in nodes if n.get("kind") != "crypto_asset"}
    provides = defaultdict(set)  # lib id -> asset ids
    for e in edges:
        if e.get("rel") == "provides" and e.get("source") in libs:
            provides[e["source"]].add(e.get("target"))

    families = sorted({_family(n) for n in assets}, key=lambda f: list(FAMILY_LABEL).index(f)
                      if f in FAMILY_LABEL else 99)
    folder_budget = max_folders if max_folders is not None else max(3, min(12, max_nodes // 8))
    folder_counts = Counter(_folder(n.get("location")) for n in assets)
    top_folders = [f for f, _ in sorted(folder_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:folder_budget]]
    lib_budget = max(3, min(16, max_nodes // 6))
    # Spend what is left on assets, riskiest first; keep room for one "+N more" node per family.
    reserved = len(families) * 2 + len(top_folders) + (1 if len(folder_counts) > len(top_folders) else 0) + lib_budget + 1
    asset_budget = max(1, max_nodes - reserved)
    shown = assets[:asset_budget]
    hidden = assets[asset_budget:]
    shown_ids = {n["id"] for n in shown}

    out_nodes: dict[str, dict[str, Any]] = {}
    out_edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def edge(src: str, rel: str, dst: str) -> None:
        if src == dst or src not in out_nodes or dst not in out_nodes:
            return
        key = (src, rel, dst)
        if key in out_edges:
            out_edges[key]["count"] = out_edges[key].get("count", 1) + 1
        else:
            out_edges[key] = {"source": src, "target": dst, "rel": rel}

    for f in families:
        members = [n for n in assets if _family(n) == f]
        out_nodes[f"family:{f}"] = {
            "id": f"family:{f}", "label": f"{FAMILY_LABEL.get(f, f)} ({len(members)})", "kind": "family",
            "asset_type": "family", "weak": any(n.get("weak") for n in members),
            "quantum_vulnerable": any(n.get("quantum_vulnerable") for n in members), "count": len(members)}
    for n in shown:
        out_nodes[n["id"]] = n
        edge(n["id"], "is_a", f"family:{_family(n)}")
    for f in families:
        rest = [n for n in hidden if _family(n) == f]
        if rest:
            cid = f"cluster:more:{f}"
            out_nodes[cid] = {"id": cid, "label": f"+{len(rest)} more", "kind": "crypto_asset",
                              "asset_type": rest[0].get("asset_type"), "cluster": True,
                              "cluster_count": len(rest), "member_ids": [str(m["id"]) for m in rest],
                              "weak": any(m.get("weak") for m in rest),
                              "quantum_vulnerable": any(m.get("quantum_vulnerable") for m in rest)}
            edge(cid, "is_a", f"family:{f}")
    # folders
    for f in top_folders:
        out_nodes[f"folder:{f}"] = {"id": f"folder:{f}", "label": f"{f} ({folder_counts[f]})", "kind": "location",
                                    "asset_type": "location", "count": folder_counts[f]}
    other_folders = [f for f in folder_counts if f not in top_folders]
    if other_folders:
        out_nodes["folder:*"] = {"id": "folder:*", "label": f"other folders ({len(other_folders)})",
                                 "kind": "location", "asset_type": "location", "cluster": True,
                                 "cluster_count": len(other_folders), "member_ids": sorted(other_folders)}
    for n in assets:
        fid = f"folder:{_folder(n.get('location'))}"
        if fid not in out_nodes:
            fid = "folder:*"
        target = n["id"] if n["id"] in shown_ids else f"cluster:more:{_family(n)}"
        edge(fid, "contains", target)
    # libraries: those providing a shown asset first
    ranked = sorted(libs.values(), key=lambda lb: (0 if lb.get("weak") else 1, -len(provides[lb["id"]] & shown_ids),
                                                   str(lb.get("label"))))
    kept_libs = [lb for lb in ranked if lb.get("weak") or provides[lb["id"]] & shown_ids][:lib_budget]
    rest_libs = [lb for lb in ranked if lb not in kept_libs]
    for lb in kept_libs:
        out_nodes[lb["id"]] = lb
    if rest_libs:
        out_nodes["cluster:libraries"] = {"id": "cluster:libraries", "label": f"{len(rest_libs)} more libraries",
                                          "kind": "framework", "asset_type": "library", "cluster": True,
                                          "cluster_count": len(rest_libs),
                                          "member_ids": [str(lb["id"]) for lb in rest_libs],
                                          "weak": any(lb.get("weak") for lb in rest_libs)}
    for lb in kept_libs:  # a vulnerable library hangs off the folder whose manifest / lock file declares it
        if lb.get("weak") and lb.get("location"):
            fid = f"folder:{_folder(lb.get('location'))}"
            if fid not in out_nodes and other_folders:
                fid = "folder:*"
            if fid not in out_nodes:
                fl = _folder(lb.get("location"))
                out_nodes[fid] = {"id": fid, "label": fl, "kind": "location", "asset_type": "location", "count": 0}
            edge(fid, "declares", lb["id"])
    for lid, targets in provides.items():
        src = lid if lid in out_nodes else "cluster:libraries"
        for t in sorted(targets):
            edge(src, "provides", t if t in out_nodes else f"cluster:more:{_family(next((a for a in assets if a['id'] == t), {}))}")
    # original lineage edges between shown nodes (certificate -> key, protocol -> suite, material -> algorithm)
    for e in edges:
        if e.get("rel") != "provides":
            edge(str(e.get("source")), str(e.get("rel")), str(e.get("target")))

    nodes_out = sorted(out_nodes.values(), key=lambda n: str(n["id"]))
    edges_out = sorted(out_edges.values(), key=lambda e: (e["source"], e["rel"], e["target"]))
    return {"nodes": nodes_out, "edges": edges_out,
            "meta": {"assets": len(assets), "shown_assets": len(shown), "folded_assets": len(hidden),
                     "families": len(families), "folders": len(folder_counts), "libraries": len(libs),
                     "max_nodes": max_nodes}}


__all__ = ["build_detailed", "FAMILY_LABEL"]
