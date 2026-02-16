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
        repo_url = scan.scan_metadata if ("repo_url" in scan.scan_metadata) and (scan.scan_metadata["repo_url"]) else None
        zip_file_used = scan.scan_metadata if ("zip_file_used" in scan.scan_metadata) and (scan.scan_metadata["zip_file_used"]) else None
        branch = scan.scan_metadata if ("branch" in scan.scan_metadata) and (scan.scan_metadata["branch"]) else "main"
        
        if scan.scan_data == None or scan.scan_data == {}:
            return 
        
        metadata = scan.scan_data["metadata"]
        files_scanned = len(metadata["included_documents"])
        total_files = len(metadata["included_documents"]) + len(metadata["excluded_documents"])
        code_coverage = (files_scanned / total_files) * 100
        
        return {
            "repo_url": repo_url,
            "branch": branch,
            "zip_file_used": zip_file_used,
            "files_scanned": files_scanned,
            "total_files": total_files,
            "code_coverage": code_coverage,
        }
    
    elif scan_type == "iac":

        repo_url = scan.scan_metadata if ("repo_url" in scan.scan_metadata) and (scan.scan_metadata["repo_url"]) else None
        zip_file_used = scan.scan_metadata if ("zip_file_used" in scan.scan_metadata) and (scan.scan_metadata["zip_file_used"]) else None
        
        if scan.scan_data == None or scan.scan_data == {}:
            return 
        
        dependency_diagram = scan.scan_data["dependency_diagram"]
        
        return {
            "repo_url": repo_url,
            "zip_file_used": zip_file_used,
            "dependency_diagram": dependency_diagram,
        }

