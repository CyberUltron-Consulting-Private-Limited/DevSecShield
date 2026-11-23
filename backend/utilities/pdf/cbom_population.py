"""The asset population as the SOW counts it, shared by D1 (Scope Baseline and Asset Population Register) and D14
(Board / IT Strategy Committee Report).

* SOW layer (SOW section 3.1, Table 4) of every source: L1 code, pipelines and images; L2 servers, Kubernetes and
  databases; L3 cloud keys, HSMs, PKI and identity; L4 network, TLS and appliances. A code-scan source is L1; a CBOM
  Sources source takes the layer of its kind (``KIND_LAYER``, one row per ``cbom_sources.kinds.KINDS`` key, pinned
  by a test); a source whose kind is unknown (deleted) takes the layer its assets point to, else "to confirm".
* What each asset is (SOW section 3.2 step 2: algorithm, certificate, key or protocol), plus the two kinds of
  inventory the collectors also record: libraries and encryption settings. Nothing lands in "Other" (audit A-10).
* The reconciliation of the three counts the documents print (audit A-09): asset OCCURRENCES (one per source that
  observed an asset; D1, D14), DISTINCT ASSETS (each estate asset once; the quantum risk register D12 and the
  estate CBOM's ``zs:asset_count``) and BOM COMPONENTS (the estate CBOM D11: one per distinct asset plus the
  certificate part components it references, which are not assets).

Pure: reads the view only; no database, no clock, no network.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    ASSET_CERTIFICATE,
    ASSET_MATERIAL,
    ASSET_PROTOCOL,
    SOURCE_SOURCES,
    AssetAgg,
    SourceAgg,
    TeamCbomView,
)

LAYERS = ("L1", "L2", "L3", "L4")
LAYER_LABELS = {
    "L1": "L1 Code, pipelines and images",
    "L2": "L2 Servers, Kubernetes and databases",
    "L3": "L3 Cloud keys, HSMs, PKI and identity",
    "L4": "L4 Network, TLS and appliances",
}
LAYER_UNKNOWN = "to confirm"
# Product text: SOW Table 4 places each source of the platform (cbom_sources.kinds KINDS) in one layer.
KIND_LAYER = {
    "container_images": "L1",
    "linux_servers": "L2", "windows_servers": "L2", "active_directory": "L2", "host_agent": "L2",
    "awx_hosts": "L2", "salt_hosts": "L2", "ssm_hosts": "L2", "kubernetes": "L2", "database": "L2",
    "aws_account": "L3", "azure_subscription": "L3", "gcp_project": "L3", "oci_tenancy": "L3",
    "key_manager": "L3", "ca_connector": "L3", "idp": "L3", "ct_logs": "L3",
    "network_range": "L4", "appliance": "L4",
}
# a deleted source's kind is unknown: its assets tell (the collector's asset types, cbom_sources.classify)
_NODE_TYPE_LAYER = {
    **{t: "L4" for t in ("tls_endpoint", "ssh_endpoint", "ike_endpoint", "ot_endpoint", "appliance_config",
                         "open_port")},
    **{t: "L3" for t in ("kms_key", "cloud_secret", "cloud_ca", "iam_certificate", "identity_provider", "signing_key",
                         "managed_key", "key_vault", "ca_authority", "ca_template", "load_balancer_tls", "cdn_tls",
                         "api_tls", "storage_encryption", "glue_catalog", "glue_connection")},
    **{t: "L2" for t in ("ssh_host_key", "ssh_server_config", "process_library", "disk_encryption",
                         "os_crypto_policy", "database_tls", "database_config", "database_user_auth", "k8s_cluster",
                         "k8s_tls_secret", "k8s_certificate", "k8s_ingress_tls", "k8s_mesh_policy", "host_secret",
                         "keystore", "db_encryption", "db_login_policy", "db_crypto_policy", "key_store")},
}

KINDS = ("algorithm", "certificate", "key", "protocol", "library", "setting")
KIND_LABELS = {
    "algorithm": "Algorithms",
    "certificate": "Certificates",
    "key": "Keys and secrets",
    "protocol": "Protocols and endpoints",
    "library": "Libraries",
    "setting": "Encryption settings",
}
_LIBRARY_NODES = frozenset({"crypto_library", "process_library"})


def asset_kind(asset: AssetAgg) -> str:
    """What an asset is: its CycloneDX asset type when it has one; else a library or an encryption setting (the
    row's own kind or the collector's asset type), never "other"."""
    by_type = {ASSET_ALGORITHM: "algorithm", ASSET_CERTIFICATE: "certificate", ASSET_MATERIAL: "key",
               ASSET_PROTOCOL: "protocol"}
    if asset.asset_type in by_type:
        return by_type[asset.asset_type]
    row_kind = str(asset.row_kind or "").strip().lower()
    if row_kind == "library" or (asset.node_type or "") in _LIBRARY_NODES:
        return "library"
    if row_kind in ("certificate", "key", "protocol", "algorithm"):
        return row_kind
    return "setting"


def collections_by_key(view: TeamCbomView) -> dict[str, Any]:
    return {c.key: c for c in (getattr(view, "collections", ()) or ())}


def source_layer(source: SourceAgg, view: TeamCbomView, *, _assets: Mapping[str, list] | None = None) -> str | None:
    """The SOW layer of a source (``LAYERS``), None when it cannot be told ("to confirm")."""
    if source.kind != SOURCE_SOURCES:
        return "L1"  # repositories, archives and uploaded CBOM files
    found = collections_by_key(view).get(source.key)
    layer = KIND_LAYER.get(str(getattr(found, "source_kind", "") or ""))
    if layer:
        return layer
    rows = (_assets or {}).get(source.key)
    if rows is None:
        rows = [a for a in view.assets if a.current and a.source_key == source.key]
    votes = Counter(_NODE_TYPE_LAYER[a.node_type] for a in rows if a.node_type in _NODE_TYPE_LAYER)
    return votes.most_common(1)[0][0] if votes else None


def current_assets_by_source(view: TeamCbomView) -> dict[str, list[AssetAgg]]:
    out: dict[str, list[AssetAgg]] = {}
    for asset in view.assets:
        if asset.current:
            out.setdefault(asset.source_key, []).append(asset)
    return out


def layer_rows(view: TeamCbomView) -> list[dict[str, Any]]:
    """One row per layer (L1-L4, then "to confirm" when a source has no layer): sources, assets, assets by kind,
    findings (impact other than Info)."""
    by_source = current_assets_by_source(view)
    rows: dict[str | None, dict[str, Any]] = {}
    for source in view.sources:
        layer = source_layer(source, view, _assets=by_source)
        row = rows.setdefault(layer, {"layer": layer, "sources": 0, "assets": 0, "findings": 0,
                                      "kinds": Counter()})
        row["sources"] += 1
        for asset in by_source.get(source.key, []):
            row["assets"] += 1
            row["kinds"][asset_kind(asset)] += 1
            row["findings"] += asset.impact in ("Critical", "High", "Medium", "Low")
    ordered = [rows[layer] for layer in LAYERS if layer in rows]
    if None in rows:
        ordered.append(rows[None])
    return ordered


def layer_label(layer: str | None) -> str:
    return LAYER_LABELS.get(layer or "", f"Layer {LAYER_UNKNOWN}")


def kind_counts(view: TeamCbomView) -> Counter[str]:
    return Counter(asset_kind(a) for a in view.assets if a.current)


# ------------------------------------------------------------------------------------------------ source metadata
# Product text: the source metadata fields (cbom_sources.kinds._Source, SOW 3.2 step 3 "Correlate" / C5 inputs)
METADATA_COLUMNS = (
    ("owner", "Owner"),
    ("application", "Application"),
    ("data_classification", "Data classification"),
    ("data_lifetime_years", "Data lifetime"),
    ("business_criticality", "Criticality"),
    ("exposure", "Exposure"),
)


def source_metadata(source: SourceAgg, view: TeamCbomView) -> list[str]:
    """The metadata cells of a source, in ``METADATA_COLUMNS`` order: the value the source holds, else "to confirm"
    (a code-scan source holds none: its owner and application are confirmed with the client)."""
    found = collections_by_key(view).get(source.key)
    meta = getattr(found, "metadata", None) or {}
    cells = []
    for key, _label in METADATA_COLUMNS:
        value = meta.get(key) if isinstance(meta, Mapping) else None
        if value in (None, ""):
            cells.append(LAYER_UNKNOWN)
        elif key == "data_lifetime_years":
            cells.append(f"{value} year" + ("" if str(value) == "1" else "s"))
        else:
            cells.append(str(value))
    return cells


# ------------------------------------------------------------------------------------------------ reconciliation
def reconciliation_line(view: TeamCbomView) -> str:
    """How the occurrence count, the distinct-asset count and the BOM component count relate."""
    live = [a for a in view.assets if a.current]
    sources = sum(1 for a in live if a.source_key.startswith("sources:"))
    code = len(live) - sources
    total = int(view.asset_occurrences or len(live))
    line = (f"Population reconciliation: {total} asset occurrence{'' if total == 1 else 's'} (one per source that "
            f"observed the asset: {code} in code scans, {sources} in CBOM Sources collections)")
    register = getattr(view, "register", None)
    summary = (register or {}).get("summary") if isinstance(register, Mapping) else None
    if isinstance(summary, Mapping) and isinstance(summary.get("total"), int):
        distinct = int(summary["total"])
        line += (f"; {distinct} distinct asset{'' if distinct == 1 else 's'} in the quantum risk register (D12), "
                 "where an asset observed by several sources or runs is one asset and code-scan rows are not "
                 "held")
    else:
        line += "; the quantum risk register (D12) was not loaded for this document"
    return line + ("; the estate CBOM (D11) lists one component per distinct asset plus the certificate part "
                   "components (signature algorithm, public key) that certificates reference, which are not assets.")


__all__ = ["KINDS", "KIND_LABELS", "KIND_LAYER", "LAYERS", "LAYER_LABELS", "LAYER_UNKNOWN", "METADATA_COLUMNS",
           "asset_kind", "collections_by_key", "current_assets_by_source", "kind_counts", "layer_label",
           "layer_rows", "reconciliation_line", "source_layer", "source_metadata"]
