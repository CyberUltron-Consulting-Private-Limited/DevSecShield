"""
Parser for MCP scan results.
Converts raw MCP scan JSON into human-readable format.
"""

from typing import Dict, List, Any


def parse_mcp_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse MCP scan results into a human-readable format.
    
    Args:
        raw_results: Raw MCP scan results dictionary
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_issues": 0,
            "by_severity": {},
            "by_type": {},
            "by_server": {},
            "error_messages": []
        },
        "issues": []
    }
    
    # Extract final_issues and error_messages
    final_issues = raw_results.get("final_issues", [])
    error_messages = raw_results.get("error_messages", [])
    
    parsed["summary"]["total_issues"] = len(final_issues)
    parsed["summary"]["error_messages"] = error_messages
    
    # Process each issue
    for issue in final_issues:
        issue_code = issue.get("issue_code", "Unknown")
        issue_message = issue.get("issue_message", "No description")
        issue_type = issue.get("issue_type", "unknown")
        server = issue.get("server", "Unknown")
        tool = issue.get("tool", {})
        severity = issue.get("issue_severity", "unknown")
        
        # Count by severity
        parsed["summary"]["by_severity"][severity] = parsed["summary"]["by_severity"].get(severity, 0) + 1
        
        # Count by type
        parsed["summary"]["by_type"][issue_type] = parsed["summary"]["by_type"].get(issue_type, 0) + 1
        
        # Count by server
        parsed["summary"]["by_server"][server] = parsed["summary"]["by_server"].get(server, 0) + 1
        
        # Format tool information
        tool_name = tool.get("name", "Unknown") if tool else "N/A"
        tool_description = tool.get("description", "No description") if tool else "N/A"
        
        # Create human-readable issue entry
        parsed_issue = {
            "code": issue_code,
            "message": issue_message,
            "severity": severity.upper(),
            "type": issue_type.replace("_", " ").title(),
            "server": server,
            "tool": {
                "name": tool_name,
                "description": tool_description
            }
        }
        
        parsed["issues"].append(parsed_issue)
    
    return parsed

