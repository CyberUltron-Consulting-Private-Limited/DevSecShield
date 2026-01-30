from typing import Dict, List, Optional, Any


def parse_sast_results_to_vulnerabilities(sast_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse SAST scan results into a list of human-readable vulnerability descriptions.
    
    Args:
        sast_data: Dictionary containing SAST scan results (from zip_sast_results_testing.json format)
    
    Returns:
        List of dictionaries, each containing human-readable vulnerability information:
        - title: Short title/name of the vulnerability
        - severity: Severity level (ERROR, WARNING, INFO, UNKNOWN)
        - message: Detailed description of the vulnerability
        - file_path: Path to the vulnerable file
        - file_name: Just the filename
        - line_number: Line number where the vulnerability occurs
        - check_id: The check identifier
        - check_name: Simplified check name
        - likelihood: Likelihood rating (if available)
        - impact: Impact rating (if available)
        - confidence: Confidence level (if available)
        - cwe: List of CWE identifiers
        - owasp: List of OWASP categories
        - vulnerability_class: List of vulnerability classes
        - references: List of reference URLs
        - code_snippet: Code snippet where the issue occurs
        - is_ignored: Whether this finding is ignored
        - validation_state: Validation state of the finding
    """
    vulnerabilities = []
    
    # Extract results array
    results = sast_data.get("results", [])
    
    for result in results:
        # Extract basic information
        check_id = result.get("check_id", "Unknown")
        check_name = check_id.split(".")[-1] if "." in check_id else check_id
        
        # Extract location information
        path = result.get("path", "Unknown")
        file_name = path.split("\\")[-1].split("/")[-1] if path else "Unknown"
        start_location = result.get("start", {})
        line_number = start_location.get("line", "?")
        
        # Extract severity (can be in result or extra)
        severity = result.get("severity") or result.get("extra", {}).get("severity", "UNKNOWN")
        
        # Extract message
        extra = result.get("extra", {})
        message = extra.get("message", "No description available")
        
        # Extract metadata
        metadata = extra.get("metadata", {})
        
        # Extract CWE, OWASP, etc.
        cwe_list = metadata.get("cwe", [])
        owasp_list = metadata.get("owasp", [])
        vulnerability_classes = metadata.get("vulnerability_class", [])
        references = metadata.get("references", [])
        
        # Extract risk ratings
        likelihood = metadata.get("likelihood")
        impact = metadata.get("impact")
        confidence = metadata.get("confidence")
        
        # Extract display name or use check name
        display_name = metadata.get("display-name") or check_name
        
        # Extract code snippet
        code_snippet = result.get("snippet") or result.get("lines") or extra.get("lines", "")
        
        # Extract status information
        is_ignored = result.get("is_ignored") or extra.get("is_ignored", False)
        validation_state = result.get("validation_state") or extra.get("validation_state", "NO_VALIDATOR")
        
        # Build vulnerability dictionary
        vulnerability = {
            "title": display_name,
            "severity": severity,
            "message": message,
            "file_path": path,
            "file_name": file_name,
            "line_number": line_number,
            "check_id": check_id,
            "check_name": check_name,
            "likelihood": likelihood,
            "impact": impact,
            "confidence": confidence,
            "cwe": cwe_list,
            "owasp": owasp_list,
            "vulnerability_class": vulnerability_classes,
            "references": references,
            "code_snippet": code_snippet,
            "is_ignored": is_ignored,
            "validation_state": validation_state,
        }
        
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities


def get_vulns(results: dict) -> list:
    """
    Get the vulnerabilities from the results
    
    This is a wrapper function that calls parse_sast_results_to_vulnerabilities
    for backward compatibility.
    """
    return parse_sast_results_to_vulnerabilities(results)
