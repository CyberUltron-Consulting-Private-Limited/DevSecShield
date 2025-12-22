"""
Parser for SBOM/SCA scan results.
Converts raw SBOM scan JSON into human-readable format.
"""

from typing import Dict, List, Any


def parse_sbom_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse SBOM scan results into a human-readable format.
    
    Args:
        raw_results: Raw SBOM scan results dictionary
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_vulnerabilities": 0,
            "by_severity": {},
            "by_package": {},
            "fixable_count": 0,
            "critical_count": 0
        },
        "vulnerabilities": []
    }
    
    matches = raw_results.get("matches", [])
    parsed["summary"]["total_vulnerabilities"] = len(matches)
    
    # Process each vulnerability match
    for match in matches:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        match_details = match.get("matchDetails", [])
        related_vulns = match.get("relatedVulnerabilities", [])
        
        # Extract vulnerability info
        vuln_id = vulnerability.get("id", "Unknown")
        severity = vulnerability.get("severity", "Unknown")
        description = vulnerability.get("description", "No description")
        fix_state = vulnerability.get("fix", {}).get("state", "unknown")
        fix_versions = vulnerability.get("fix", {}).get("versions", [])
        risk = vulnerability.get("risk", 0.0)
        
        # Extract CVSS score if available
        cvss_scores = vulnerability.get("cvss", [])
        cvss_score = None
        if cvss_scores:
            cvss_score = cvss_scores[0].get("metrics", {}).get("baseScore")
        
        # Extract CVE if available from related vulnerabilities
        cve_id = None
        if related_vulns:
            cve_id = related_vulns[0].get("id")
        
        # Extract artifact info
        package_name = artifact.get("name", "Unknown")
        package_version = artifact.get("version", "Unknown")
        package_type = artifact.get("type", "Unknown")
        locations = artifact.get("locations", [])
        
        # Count by severity
        parsed["summary"]["by_severity"][severity] = parsed["summary"]["by_severity"].get(severity, 0) + 1
        
        # Count by package
        package_key = f"{package_name}@{package_version}"
        parsed["summary"]["by_package"][package_key] = parsed["summary"]["by_package"].get(package_key, 0) + 1
        
        # Count fixable and critical
        if fix_state == "fixed":
            parsed["summary"]["fixable_count"] += 1
        if severity.upper() == "CRITICAL":
            parsed["summary"]["critical_count"] += 1
        
        # Get file path from locations
        file_path = locations[0].get("path", "Unknown") if locations else "Unknown"
        
        # Get suggested fix version from match details
        suggested_version = None
        if match_details:
            fix_info = match_details[0].get("fix", {})
            if fix_info:
                suggested_version = fix_info.get("suggestedVersion")
        
        # Create human-readable vulnerability entry
        parsed_vuln = {
            "vulnerability_id": vuln_id,
            "cve_id": cve_id,
            "severity": severity.upper(),
            "description": description[:200] + "..." if len(description) > 200 else description,
            "package": {
                "name": package_name,
                "version": package_version,
                "type": package_type,
                "file_path": file_path
            },
            "cvss_score": round(cvss_score, 1) if cvss_score else None,
            "risk_score": round(risk, 4),
            "fix_available": fix_state == "fixed",
            "fix_versions": fix_versions,
            "suggested_version": suggested_version
        }
        
        parsed["vulnerabilities"].append(parsed_vuln)
    
    return parsed

