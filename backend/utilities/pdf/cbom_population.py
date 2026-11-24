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
    current_collections,
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
def _plural(number: int, singular: str, plural: str | None = None) -> str:
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def reconciliation_counts(view: TeamCbomView) -> dict[str, Any]:
    """The numbers of the reconciliation (SOW audit A-09, review M6), each from the view:

    * ``collected``: the assets of each Sources source's latest collection, as the run's asset list counts them
      (``CollectionAgg.asset_count``: coverage rows excluded, before any de-duplication);
    * ``counted_once``: of those, the observations of a certificate (or another asset) that a second source also
      observed: the certificate is one asset, counted once, from its latest observation (``merge_collections``);
    * ``sources_occurrences`` / ``code_occurrences``: current asset occurrences of Sources collections / code scans
      (a code-scan certificate also observed by a Sources collection is counted from the latter);
    * ``register``: the quantum risk register summary (distinct assets, Q-grade split), None when not loaded."""
    live = [a for a in view.assets if a.current]
    sources = sum(1 for a in live if a.source_key.startswith("sources:"))
    collected = sum(int(getattr(c, "asset_count", 0) or 0) for c in current_collections(view))  # QA2 Q1-01
    register = getattr(view, "register", None)
    summary = (register or {}).get("summary") if isinstance(register, Mapping) else None
    cross = getattr(view, "cross_scope", None) or {}
    return {"collected": collected, "counted_once": max(collected - sources, 0), "sources_occurrences": sources,
            "code_occurrences": len(live) - sources, "occurrences": int(view.asset_occurrences or len(live)),
            "code_certs_superseded": int(cross.get("code_certs_superseded", 0) or 0),
            "register": summary if isinstance(summary, Mapping) and isinstance(summary.get("total"), int) else None}


def grade_split_text(summary: Mapping[str, Any]) -> str:
    """"Q1 Critical 0, Q2 High 3, Q3 Medium 0, Q4 Low 1, Q0 Unknown 5, no grade 1" from a register summary."""
    grades = summary.get("q_grades") if isinstance(summary.get("q_grades"), Mapping) else {}
    names = (("Q1", "Q1 Critical"), ("Q2", "Q2 High"), ("Q3", "Q3 Medium"), ("Q4", "Q4 Low"), ("Q0", "Q0 Unknown"),
             ("none", "no grade (no public-key cryptography)"))
    return ", ".join(f"{label} {int(grades.get(key, 0) or 0)}" for key, label in names)


def reconciliation_steps(view: TeamCbomView) -> list[str]:
    """The reconciliation as arithmetic, one step per line: run assets -> occurrences -> distinct register assets ->
    Q-grade split (SOW audit A-09, review M6)."""
    c = reconciliation_counts(view)
    steps = []
    if current_collections(view):
        n = len(current_collections(view))
        steps.append(
            f"1. The latest collections of the {_plural(n, 'CBOM Sources source')} list {c['collected']} "
            f"asset{'' if c['collected'] == 1 else 's'} (the runs' asset lists). Minus {c['counted_once']} "
            f"observation{'' if c['counted_once'] == 1 else 's'} of an asset another source also observed (a "
            "certificate seen by two sources is one asset, counted once from its latest observation) = "
            f"{c['sources_occurrences']} occurrence{'' if c['sources_occurrences'] == 1 else 's'} in CBOM Sources "
            "collections.")
    code_line = (f"{len(steps) + 1}. Code scans: {_plural(c['code_occurrences'], 'occurrence')}"
                 + (f" (after {_plural(c['code_certs_superseded'], 'certificate')} also observed by a Sources "
                    "collection, counted there)" if c["code_certs_superseded"] else "")
                 + f". Total: {_plural(c['occurrences'], 'asset occurrence')} in this document.")
    steps.append(code_line)
    if c["register"] is not None:
        total = int(c["register"]["total"])
        steps.append(
            f"{len(steps) + 1}. The quantum risk register (D12) holds {_plural(total, 'distinct asset')}: the Sources "
            "occurrences, each estate asset once (an asset observed by several sources or runs is one asset); "
            f"code-scan rows are not held. Grades: {grade_split_text(c['register'])}.")
    else:
        steps.append(f"{len(steps) + 1}. The quantum risk register (D12) was not loaded for this document.")
    steps.append(f"{len(steps) + 1}. The estate CBOM (D11) lists one component per distinct asset plus the "
                 "certificate part components (signature algorithm, public key) that certificates reference, which "
                 "are not assets.")
    return steps


def reconciliation_line(view: TeamCbomView) -> str:
    """How the occurrence count, the distinct-asset count and the BOM component count relate (one paragraph)."""
    c = reconciliation_counts(view)
    line = (f"Population reconciliation: {_plural(c['occurrences'], 'asset occurrence')} "
            f"({c['code_occurrences']} in code scans, {c['sources_occurrences']} in CBOM Sources collections; an "
            "asset that two sources observe is one occurrence in each, except a certificate, which is counted once)")
    if getattr(view, "collections", None) and c["counted_once"]:
        line += (f"; the collections' asset lists hold {c['collected']}, of which {c['counted_once']} "
                 f"{'is' if c['counted_once'] == 1 else 'are'} counted once across sources")
    if c["register"] is not None:
        total = int(c["register"]["total"])
        line += (f"; {_plural(total, 'distinct asset')} in the quantum risk register (D12), where an asset observed "
                 f"by several sources or runs is one asset and code-scan rows are not held "
                 f"({grade_split_text(c['register'])})")
    else:
        line += "; the quantum risk register (D12) was not loaded for this document"
    return line + ("; the estate CBOM (D11) lists one component per distinct asset plus the certificate part "
                   "components (signature algorithm, public key) that certificates reference, which are not assets.")


# ------------------------------------------------------------------------------------------------ PQC targets
# Usage of a quantum-vulnerable asset -> what replaces it (SOW review M5). The names are read from algid's own table
# (test_algid_single_source: post-quantum names come from algid only): the pure FIPS 203 KEM and FIPS 204 signature
# parameter sets of NIST category 3 (the general default), and of category 5 for CNSA 2.0 systems.
USAGE_KEM = "kem"
USAGE_SIGNATURE = "signature"
USAGE_UNKNOWN = "unknown"
USAGE_LABELS = {
    USAGE_KEM: "Key establishment (TLS / SSH / IKE key exchange, key transport, encryption keys)",
    USAGE_SIGNATURE: "Digital signatures (certificates, signing and host keys)",
    USAGE_UNKNOWN: "Usage not recorded (assessor to decide the target)",
}
_USAGE_STANDARD = {USAGE_KEM: "FIPS 203", USAGE_SIGNATURE: "FIPS 204"}
_KEM_PRIMITIVES = frozenset({"kem", "key-agree", "pke", "ke"})


def pq_target(usage: str, category: int = 3) -> str | None:
    """The FIPS 203 (KEM) or FIPS 204 (signature) parameter set of a NIST security category, from algid's table."""
    from backend.utilities.cbom_sources import algid

    standard = _USAGE_STANDARD.get(usage)
    if standard is None:
        return None
    for name, row in sorted(algid._ALGS.items()):
        family, primitive, std, status, parameter_set, nist_category, construction = row[:7]
        if (family == "PQ" and primitive == usage and std == standard and status == "standard"
                and construction == "pure" and nist_category == category and name == parameter_set):
            return name  # the parameter set's own row (not a pre-hash or hybrid variant)
    return None


def asset_usage(asset: AssetAgg) -> str:
    """What a quantum-vulnerable asset is used for: its primitive when recorded, else its kind (a certificate or key
    signs, an endpoint or protocol exchanges keys)."""
    primitive = str(asset.primitive or "").strip().lower()
    if primitive == "signature":
        return USAGE_SIGNATURE
    if primitive in _KEM_PRIMITIVES:
        return USAGE_KEM
    kind = asset_kind(asset)
    if kind in ("certificate", "key"):
        return USAGE_SIGNATURE
    if kind == "protocol":
        return USAGE_KEM
    return USAGE_UNKNOWN


def quantum_vulnerable_assets(view: TeamCbomView) -> list[AssetAgg]:
    """The current assets ``view.pqc_vulnerable`` counts (``_headline``: quantum_vulnerable is True)."""
    return [a for a in view.assets if a.current and a.quantum_vulnerable is True]


def pqc_target_groups(view: TeamCbomView) -> list[dict[str, Any]]:
    """Every current quantum-vulnerable asset grouped by its migration target (usage-based; the scan's recorded
    target for a code-scan algorithm that has one): ``{"target", "usage", "occurrences", "sources", "kinds"}``, most
    occurrences first. The occurrences add up to ``view.pqc_vulnerable``."""
    groups: dict[tuple[str, str], list[AssetAgg]] = {}
    for asset in quantum_vulnerable_assets(view):
        usage = asset_usage(asset)
        recorded = asset.pqc_migration_target if asset.asset_type == ASSET_ALGORITHM else None
        target = recorded or pq_target(usage) or USAGE_LABELS[USAGE_UNKNOWN]
        groups.setdefault((target, usage), []).append(asset)
    rows = [{"target": target, "usage": usage, "occurrences": len(items),
             "sources": len({a.source_key for a in items}), "kinds": Counter(asset_kind(a) for a in items)}
            for (target, usage), items in groups.items()]
    rows.sort(key=lambda r: (-r["occurrences"], r["target"].casefold(), r["usage"]))
    return rows


# ------------------------------------------------------------------------------------------------ asset identity
def asset_identity(asset: AssetAgg) -> tuple[str, ...]:
    """One asset across sources (review M7b): a Sources asset by its identity without the source (two AWS roles over
    one account observe the same parameter), a certificate by its cross-source key, a code row by its own identity."""
    key = getattr(asset, "asset_key", None)
    if key:
        return ("key", str(key))
    return ("own", asset.source_key, asset.asset_type, asset.ident)


__all__ = ["KINDS", "KIND_LABELS", "KIND_LAYER", "LAYERS", "LAYER_LABELS", "LAYER_UNKNOWN", "METADATA_COLUMNS",
           "USAGE_LABELS", "asset_identity", "asset_kind", "asset_usage", "collections_by_key",
           "current_assets_by_source", "grade_split_text", "kind_counts", "layer_label", "layer_rows", "pq_target",
           "pqc_target_groups", "quantum_vulnerable_assets", "reconciliation_counts", "reconciliation_line",
           "reconciliation_steps", "source_layer", "source_metadata"]
