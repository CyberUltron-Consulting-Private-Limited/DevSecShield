import re

from backend.new_models import scan_types , Scan
from backend.utilities.scan.path_patterns import legacy_patterns_to_glob, saved_with_prefix_meaning

# The settings a failed code scan is run again with ("Run again", frontend utils/scanRerun.ts OPTION_KEYS): the
# options utilities/db/metadata.py stores when the scan starts.  Before, only repo_url / branch / zip_file_used came
# back, so "Run again" on a failed SAST scan left the language at "Select language" (lab UI r1 F4).  Allow-listed per
# type; a repository token is never among them (metadata.py never stores one) and _without_secrets drops any key that
# names one, at any depth, in case an older row holds it.
_RERUN_OPTIONS: dict[str, tuple[str, ...]] = {
    "sast": ("repo_type", "app_lang", "exclude_path_arrays"),
    "iac": ("repo_type", "environment", "iac_contexts"),
    "sbom_sca": ("repo_type", "sbom_file_used"),
    "cbom": ("repo_type", "include_vendored", "scan_history"),
    "ai_bom": ("repo_type",),
}
_DAST_AUTH_KEYS = ("login_url", "xpath_of_username_field", "xpath_of_password_field", "username",
                   "xpath_of_submit_button")
_SECRET_WORDS = frozenset({"pat", "token", "tokens", "password", "passwd", "passphrase", "secret", "secrets",
                           "authorization", "credential", "credentials", "cookie", "apikey", "headers"})



def _current_vex(scan_type: str, vex):
    """A stored VEX written by older rules is not served (the page then fetches /vex, which rebuilds it)."""
    from backend.utilities.cbom_sources.vex_semantics import is_current

    return vex if is_current(scan_type, vex) else None

def _secret_key(key) -> bool:
    name = str(key).lower()
    words = set(re.split(r"[^a-z0-9]+", name))
    return bool(words & _SECRET_WORDS) or any(w in name for w in ("api_key", "apikey", "private_key", "access_key"))


def _without_secrets(value):
    if isinstance(value, dict):
        return {k: _without_secrets(v) for k, v in value.items() if not _secret_key(k)}
    if isinstance(value, list):
        return [_without_secrets(v) for v in value]
    return value


def _patterns_in_glob_meaning(scan_type: str, options: dict, meta: dict) -> dict:
    """
    A scan started before #443 stored its path patterns with the old prefix meaning ("k8s" also matched "k8s-prod",
    "test" also "tests"). Its "Run again" options carry the same patterns rewritten as the globs that match the same
    files ("k8s*", "test*"), so a rerun neither skips IaC files nor scans SAST files it skipped before. The form shows
    the rewrite, and "path_patterns_rewritten" (only when a pattern changed) lets the "Run again" notice explain it.
    """
    if not saved_with_prefix_meaning(meta):
        return options
    before = {key: options.get(key) for key in ("exclude_path_arrays", "iac_contexts")}
    if scan_type == "sast" and isinstance(options.get("exclude_path_arrays"), list):
        options["exclude_path_arrays"] = legacy_patterns_to_glob(options["exclude_path_arrays"])
    if scan_type == "iac" and isinstance(options.get("iac_contexts"), list):
        options["iac_contexts"] = [
            {**ctx, "include_path_arrays": legacy_patterns_to_glob(ctx["include_path_arrays"])}
            if isinstance(ctx, dict) and isinstance(ctx.get("include_path_arrays"), list) else ctx
            for ctx in options["iac_contexts"]]
    if any(options.get(key) != value for key, value in before.items()):
        options["path_patterns_rewritten"] = True
    return options


def rerun_options(scan_type: str, meta: dict) -> dict:
    """The stored, non-secret start options of a code scan, for "Run again" (None when the scan never stored one)."""
    options = {key: _without_secrets(meta.get(key)) for key in _RERUN_OPTIONS.get(scan_type, ())
               if not _secret_key(key)}
    return _patterns_in_glob_meaning(scan_type, options, meta)

_CBOM_INPUT_COUNTS = ("components_total", "crypto_assets", "imported", "skipped_not_crypto", "skipped_invalid",
                      "duplicates")


def _cbom_input(raw) -> dict | None:
    """The import report of an uploaded CBOM file (``cbom_input``), reduced to its known fields: counts, truncation,
    spec version and up to 20 short notes. None for code scans (they have no import report)."""
    if not isinstance(raw, dict):
        return None
    out: dict = {k: raw[k] for k in _CBOM_INPUT_COUNTS if isinstance(raw.get(k), int) and not isinstance(raw.get(k), bool)}
    out["truncated"] = raw.get("truncated") is True
    spec = raw.get("spec_version")
    out["spec_version"] = str(spec)[:16] if spec not in (None, "") else None
    out["notes"] = [str(n)[:300] for n in (raw.get("notes") or []) if isinstance(n, str) and n.strip()][:20]
    return out

def get_scan_metadata(scan_type: scan_types, scan: Scan):
    """
    for SAST scans : 
    - repo_url
    - zip_file_used
    - files_scanned
    - total_files
    - code_coverage
    
    for IAC scans : 
    - repo_url
    - zip_file_used
    - dependency_diagram

    """
    if scan_type == "sast":
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch") or ("main" if repo_url else None)  # a zip or an uploaded BOM has no branch

        files_scanned = 0
        total_files = 0
        code_coverage = 0
        if scan.scan_data and isinstance(scan.scan_data, dict) and scan.scan_data.get("metadata"):
            metadata = scan.scan_data["metadata"]
            included = metadata.get("included_documents")
            excluded = metadata.get("excluded_documents")
            included_list = included if isinstance(included, list) else []
            excluded_list = excluded if isinstance(excluded, list) else []
            files_scanned = len(included_list)
            total_files = len(included_list) + len(excluded_list)
            code_coverage = (files_scanned / total_files) * 100 if total_files > 0 else 0

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            **rerun_options("sast", _meta),
            "files_scanned": files_scanned,
            "total_files": total_files,
            "code_coverage": code_coverage,
        }
    
    elif scan_type == "iac": 
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch",None)

        dependency_diagram = None
        if scan.scan_data and isinstance(scan.scan_data, dict) and "dependency_diagram" in scan.scan_data:
            dependency_diagram = scan.scan_data["dependency_diagram"]

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            **rerun_options("iac", _meta),
            "dependency_diagram": dependency_diagram,
        }

    elif scan_type == "sbom_sca":
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch",None)

        sbom_compliance = None
        sbom_json = None
        rbi_csf_rollup = None
        certin_posture = None
        attestations = None
        bom_signature = None
        vex_json = None
        if scan.scan_data and isinstance(scan.scan_data, dict):
            if "sbom_compliance" in scan.scan_data:
                sbom_compliance = scan.scan_data["sbom_compliance"]
            attestations = scan.scan_data.get("attestations")
            bom_signature = scan.scan_data.get("bom_signature")
            vex_json = _current_vex("sbom_sca", scan.scan_data.get("vex_json"))
            from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data, subject_name_for

            sbom_json = bom_dict_from_scan_data(
                "sbom_sca", scan.scan_data, subject_name=subject_name_for(_meta)
            )
        if sbom_compliance:
            from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup
            from backend.utilities.dashboard.certin_posture import build_certin_posture

            rbi_csf_rollup = build_rbi_csf_rollup(sbom_compliance=sbom_compliance)
            certin_posture = build_certin_posture(sbom_compliance=sbom_compliance)

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            **rerun_options("sbom_sca", _meta),
            "sbom_compliance": sbom_compliance,
            "sbom_json": sbom_json,
            "rbi_csf_rollup": rbi_csf_rollup,
            "certin_posture": certin_posture,
            "attestations": attestations,
            "bom_signature": bom_signature,
            "vex_json": vex_json,
        }
    
    elif scan_type == "mcp":
        _meta = scan.scan_metadata or {}
        server_url = _meta.get("server_url") if _meta.get("server_url") else None
        server_mode = _meta.get("server_mode") if _meta.get("server_mode") else None

        # an allow-list: the stored headers (names, masked values, encrypted values: #44) are never returned
        return {
            "server_url": server_url,
            "server_mode": server_mode,
        }
    

    elif scan_type == "llm":
        _meta = scan.scan_metadata or {}
        model_type = _meta.get("model_type") if _meta.get("model_type") else None
        probes = _meta.get("probes") if _meta.get("probes") else None

        return {
            "model_type": model_type,
            "probes": probes,
        }
    
    elif scan_type == "dast":
        _meta = scan.scan_metadata or {}
        _scan_data = scan.scan_data or {}
        target_url = _meta.get("target_url") if _meta.get("target_url") else None
        auth = _meta.get("auth") if _meta.get("auth") else None
        if isinstance(auth, dict):
            # Allow-listed: the login form's address and XPaths and the user name.  The password is never stored
            # (utilities/db/metadata.py) and never returned, whatever an older row holds; "Run again" asks for it.
            auth = {k: auth[k] for k in _DAST_AUTH_KEYS if isinstance(auth.get(k), str)}
        scan_speed = _meta.get("scan_speed") if _meta.get("scan_speed") else None
        urls_included = _scan_data.get("metadata",{}).get("urls_included",[])
        urls_excluded = _scan_data.get("metadata",{}).get("urls_excluded",[])

        return {
            "target_url": target_url,
            "auth": auth,
            "scan_speed": scan_speed,
            "urls_included": urls_included,
            "urls_excluded": urls_excluded,
            # the start options, for "Run again" on a failed DAST scan (frontend utils/dastRerun.ts, X1 M2)
            "max_urls": _meta.get("max_urls"),
            "additional_urls_to_scan": _meta.get("additional_urls_to_scan"),
            "include_url_patterns": _meta.get("include_url_patterns"),
            "exclude_url_patterns": _meta.get("exclude_url_patterns"),
            "profile_id": _meta.get("profile_id"),
            "trigger": _meta.get("trigger"),
        }
    
    elif scan_type == "cbom":
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch") or ("main" if repo_url else None)  # a zip or an uploaded BOM has no branch
        cbom_file_used = bool(_meta.get("cbom_file_used"))
        scan_binaries = bool(_meta.get("scan_binaries"))

        # Extract cbom_json from scan_data (follows IAC dependency_diagram pattern)
        cbom_json = None
        # Additive chart/compliance payload produced by the reconciled aibom CBOM
        # lane (I1). The GET-scan `data` field only carries the findings LIST, and
        # the CbomCryptoCharts (C9) read `cbom_distributions`/`cbom_compliance`
        # from scan_metadata — so surface them here, mirroring the ai_bom branch.
        # Absent on legacy worker CBOM scans (produced before the reconcile), in
        # which case the C9 charts simply don't render and the legacy
        # CbomDashboardCharts take over.
        cbom_distributions = None
        cbom_compliance = None
        cbom_scores = None
        # Normalized crypto dependency graph (nodes + edges) — the peer of the
        # ai_bom branch's ``ai_bom_graph``. The C9 ``cryptoRefArray`` graph is
        # also embedded in ``cbom_json``, but the results-page dependency-graph
        # (F1) reads this pre-joined payload rather than re-walking CycloneDX.
        cbom_graph = None
        cbom_graph_compact = None
        cbom_graph_expanded = None
        if scan.scan_data and isinstance(scan.scan_data, dict):
            if "cbom_json" in scan.scan_data:
                cbom_json = scan.scan_data["cbom_json"]
            if "cbom_distributions" in scan.scan_data:
                cbom_distributions = scan.scan_data["cbom_distributions"]
            if "cbom_compliance" in scan.scan_data:
                cbom_compliance = scan.scan_data["cbom_compliance"]
            if "cbom_scores" in scan.scan_data:
                cbom_scores = scan.scan_data["cbom_scores"]
            if "cbom_graph" in scan.scan_data:
                cbom_graph = scan.scan_data["cbom_graph"]
            if "cbom_graph_compact" in scan.scan_data:
                cbom_graph_compact = scan.scan_data["cbom_graph_compact"]
            if "cbom_graph_expanded" in scan.scan_data:
                cbom_graph_expanded = scan.scan_data["cbom_graph_expanded"]
            if cbom_graph is not None and (
                cbom_graph_compact is None or cbom_graph_expanded is None
            ):
                # Legacy scans: project compact/expanded on read (no worker restart).
                try:
                    from backend.utilities.dashboard.bom_graph_view import (
                        COMPACT_MAX_NODES,
                        EXPANDED_MAX_NODES,
                        compact_cbom_graph,
                    )

                    if cbom_graph_compact is None:
                        cbom_graph_compact = compact_cbom_graph(
                            cbom_graph, max_nodes=COMPACT_MAX_NODES
                        )
                    if cbom_graph_expanded is None:
                        cbom_graph_expanded = compact_cbom_graph(
                            cbom_graph,
                            max_nodes=EXPANDED_MAX_NODES,
                            collapse_orphans=False,
                            collapse_duplicate_labels=True,
                        )
                except Exception:
                    pass

        rbi_csf_rollup = None
        certin_posture = None
        if cbom_compliance:
            from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup
            from backend.utilities.dashboard.certin_posture import build_certin_posture

            rbi_csf_rollup = build_rbi_csf_rollup(cbom_compliance=cbom_compliance)
            certin_posture = build_certin_posture(cbom_compliance=cbom_compliance)

        attestations = None
        bom_signature = None
        vex_json = None
        cbom_input = None
        if scan.scan_data and isinstance(scan.scan_data, dict):
            attestations = scan.scan_data.get("attestations")
            bom_signature = scan.scan_data.get("bom_signature")
            vex_json = scan.scan_data.get("vex_json")
            from backend.utilities.cbom_sources.vex_semantics import is_current

            if not is_current("cbom", vex_json):  # older VEX rules (CB-22): the page fetches /vex, which rebuilds it
                vex_json = None
            cbom_input = _cbom_input(scan.scan_data.get("cbom_input"))
        from backend.utilities.dashboard.cbom_coverage import coverage_report

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            "cbom_file_used": cbom_file_used,
            **rerun_options("cbom", _meta),
            # a code scan: what it left out (archives, images, binaries, firmware ...) from crypto:coverage:* (WP8b)
            "cbom_coverage": None if cbom_file_used else coverage_report(cbom_json),
            # CB-29: the crypto-library advisory data the scan matched (OSV snapshot version, date, stale)
            "advisory_data": (scan.scan_data or {}).get("advisory_data") if isinstance(scan.scan_data, dict) else None,
            # an uploaded CBOM file: what was read, skipped or truncated, and the notes to show the user
            "cbom_input": cbom_input,
            "scan_binaries": scan_binaries,
            "cbom_json": cbom_json,
            "cbom_distributions": cbom_distributions,
            "cbom_compliance": cbom_compliance,
            "cbom_scores": cbom_scores,
            "cbom_graph": cbom_graph,
            "cbom_graph_compact": cbom_graph_compact,
            "cbom_graph_expanded": cbom_graph_expanded,
            "rbi_csf_rollup": rbi_csf_rollup,
            "certin_posture": certin_posture,
            "attestations": attestations,
            "bom_signature": bom_signature,
            "vex_json": vex_json,
        }

    elif scan_type == "ai_bom":
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch") or ("main" if repo_url else None)  # a zip or an uploaded BOM has no branch
        ai_bom_file_used = bool(_meta.get("ai_bom_file_used"))
        scan_binaries = bool(_meta.get("scan_binaries"))

        # Extract ai_bom_json from scan_data (follows IAC dependency_diagram pattern)
        ai_bom_json = None
        ai_bom_compliance = None
        ai_bom_graph = None
        ai_bom_graph_compact = None
        ai_bom_graph_expanded = None
        ai_bom_scores = None
        ai_bom_spdx = None
        ai_bom_sarif = None
        if scan.scan_data and isinstance(scan.scan_data, dict):
            if "ai_bom_json" in scan.scan_data:
                ai_bom_json = scan.scan_data["ai_bom_json"]
            # Additional raw BOM artifacts (downloadable): SPDX 3.0 + SARIF 2.1.0.
            if "ai_bom_spdx" in scan.scan_data:
                ai_bom_spdx = scan.scan_data["ai_bom_spdx"]
            if "ai_bom_sarif" in scan.scan_data:
                ai_bom_sarif = scan.scan_data["ai_bom_sarif"]
            # Advisory healthcare regulatory-readiness mapping (FDA §524B/SaMD/PCCP,
            # EU AI Act Annex IV, GMLP, HIPAA, NIST AI RMF). May be absent on scans
            # produced before the compliance layer was added.
            if "ai_bom_compliance" in scan.scan_data:
                ai_bom_compliance = scan.scan_data["ai_bom_compliance"]
            # Typed inventory graph (trained_on/depends_on/served_by/deployed_at)
            # and the normalized risk scores — additive, surfaced for the AI-BOM
            # dependency-graph, multi-site drift, and risk-heatmap visualizations.
            if "ai_bom_graph" in scan.scan_data:
                ai_bom_graph = scan.scan_data["ai_bom_graph"]
            if "ai_bom_graph_compact" in scan.scan_data:
                ai_bom_graph_compact = scan.scan_data["ai_bom_graph_compact"]
            if "ai_bom_graph_expanded" in scan.scan_data:
                ai_bom_graph_expanded = scan.scan_data["ai_bom_graph_expanded"]
            if ai_bom_graph is not None and (
                ai_bom_graph_compact is None or ai_bom_graph_expanded is None
            ):
                try:
                    from backend.utilities.dashboard.bom_graph_view import (
                        COMPACT_MAX_NODES,
                        EXPANDED_MAX_NODES,
                        compact_aibom_graph,
                    )

                    if ai_bom_graph_compact is None:
                        ai_bom_graph_compact = compact_aibom_graph(
                            ai_bom_graph, max_nodes=COMPACT_MAX_NODES
                        )
                    if ai_bom_graph_expanded is None:
                        ai_bom_graph_expanded = compact_aibom_graph(
                            ai_bom_graph,
                            max_nodes=EXPANDED_MAX_NODES,
                            collapse_orphans=False,
                        )
                except Exception:
                    pass
            if "ai_bom_scores" in scan.scan_data:
                ai_bom_scores = scan.scan_data["ai_bom_scores"]

        rbi_csf_rollup = None
        certin_posture = None
        if ai_bom_compliance:
            from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup
            from backend.utilities.dashboard.certin_posture import build_certin_posture

            rbi_csf_rollup = build_rbi_csf_rollup(ai_bom_compliance=ai_bom_compliance)
            certin_posture = build_certin_posture(ai_bom_compliance=ai_bom_compliance)

        attestations = None
        bom_signature = None
        vex_json = None
        if scan.scan_data and isinstance(scan.scan_data, dict):
            attestations = scan.scan_data.get("attestations")
            bom_signature = scan.scan_data.get("bom_signature")
            vex_json = _current_vex("ai_bom", scan.scan_data.get("vex_json"))

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            "ai_bom_file_used": ai_bom_file_used,
            **rerun_options("ai_bom", _meta),
            "scan_binaries": scan_binaries,
            "ai_bom_json": ai_bom_json,
            "ai_bom_compliance": ai_bom_compliance,
            "ai_bom_graph": ai_bom_graph,
            "ai_bom_graph_compact": ai_bom_graph_compact,
            "ai_bom_graph_expanded": ai_bom_graph_expanded,
            "ai_bom_scores": ai_bom_scores,
            "ai_bom_spdx": ai_bom_spdx,
            "ai_bom_sarif": ai_bom_sarif,
            "rbi_csf_rollup": rbi_csf_rollup,
            "certin_posture": certin_posture,
            "attestations": attestations,
            "bom_signature": bom_signature,
            "vex_json": vex_json,
        }