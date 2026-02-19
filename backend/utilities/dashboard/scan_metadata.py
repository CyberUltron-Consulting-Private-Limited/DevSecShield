from backend.new_models import scan_types , Scan

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
        branch = _meta.get("branch") or "main"

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
            "dependency_diagram": dependency_diagram,
        }

    elif scan_type == "sbom_sca":
        _meta = scan.scan_metadata or {}
        repo_url = _meta.get("repo_url") if _meta.get("repo_url") else None
        zip_file_used = bool(_meta.get("zip_file_used"))
        branch = _meta.get("branch",None)

        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
        }
    
    elif scan_type == "mcp":
        _meta = scan.scan_metadata or {}
        server_url = _meta.get("server_url") if _meta.get("server_url") else None
        server_mode = _meta.get("server_mode") if _meta.get("server_mode") else None

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
        scan_speed = _meta.get("scan_speed") if _meta.get("scan_speed") else None
        urls_included = _scan_data.get("metadata",{}).get("urls_included",[])
        urls_excluded = _scan_data.get("metadata",{}).get("urls_excluded",[])

        return {
            "target_url": target_url,
            "auth": auth,
            "scan_speed": scan_speed,
            "urls_included": urls_included,
            "urls_excluded": urls_excluded,
        }