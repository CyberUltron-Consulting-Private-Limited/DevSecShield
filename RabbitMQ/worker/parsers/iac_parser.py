"""
Parser for IAC scan results.
Converts raw IAC scan JSON into human-readable format.
"""

from typing import Dict, List, Any


def parse_iac_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse IAC scan results into a human-readable format.
    
    Args:
        raw_results: Raw IAC scan results dictionary
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_issues": 0,
            "by_severity": {},
            "by_rule": {},
            "by_resource": {}
        },
        "issues": []
    }
    
    results = raw_results.get("results", [])
    parsed["summary"]["total_issues"] = len(results)
    
    # Process each issue
    for issue in results:
        rule_id = issue.get("rule_id", "Unknown")
        rule_description = issue.get("rule_description", "No description")
        severity = issue.get("severity", "UNKNOWN")
        description = issue.get("description", "No description")
        resource = issue.get("resource", "Unknown")
        impact = issue.get("impact", "No impact description")
        resolution = issue.get("resolution", "No resolution provided")
        location = issue.get("location", {})
        links = issue.get("links", [])
        
        # Count by severity
        parsed["summary"]["by_severity"][severity] = parsed["summary"]["by_severity"].get(severity, 0) + 1
        
        # Count by rule
        parsed["summary"]["by_rule"][rule_id] = parsed["summary"]["by_rule"].get(rule_id, 0) + 1
        
        # Count by resource
        parsed["summary"]["by_resource"][resource] = parsed["summary"]["by_resource"].get(resource, 0) + 1
        
        # Format location
        filename = location.get("filename", "Unknown")
        start_line = location.get("start_line", 0)
        end_line = location.get("end_line", 0)
        
        # Create human-readable issue entry
        parsed_issue = {
            "rule_id": rule_id,
            "rule_description": rule_description,
            "severity": severity,
            "description": description,
            "resource": resource,
            "location": {
                "file": filename,
                "start_line": start_line,
                "end_line": end_line
            },
            "impact": impact,
            "resolution": resolution,
            "documentation_links": links[:3]  # Limit to first 3 links
        }
        
        parsed["issues"].append(parsed_issue)
    
    return parsed

