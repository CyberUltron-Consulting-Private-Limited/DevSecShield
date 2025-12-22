"""
Parser for Gitleaks scan results.
Converts raw Gitleaks scan JSON into human-readable format.
"""

from typing import List, Dict, Any


def parse_gitleaks_results(raw_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse Gitleaks scan results into a human-readable format.
    
    Args:
        raw_results: Raw Gitleaks scan results list
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_secrets": len(raw_results),
            "by_rule": {},
            "by_file": {},
            "unique_files": set()
        },
        "secrets": []
    }
    
    # Process each secret finding
    for finding in raw_results:
        rule_id = finding.get("RuleID", "Unknown")
        description = finding.get("Description", "No description")
        file_path = finding.get("File", "Unknown")
        start_line = finding.get("StartLine", 0)
        end_line = finding.get("EndLine", 0)
        match = finding.get("Match", "")
        secret = finding.get("Secret", "")
        entropy = finding.get("Entropy", 0.0)
        snippet = finding.get("snippet", "")
        
        # Count by rule
        parsed["summary"]["by_rule"][rule_id] = parsed["summary"]["by_rule"].get(rule_id, 0) + 1
        
        # Count by file
        parsed["summary"]["by_file"][file_path] = parsed["summary"]["by_file"].get(file_path, 0) + 1
        
        # Track unique files
        parsed["summary"]["unique_files"].add(file_path)
        
        # Mask secret (show only first 4 and last 4 characters)
        masked_secret = mask_secret(secret) if secret else "N/A"
        
        # Create human-readable secret entry
        parsed_secret = {
            "rule_id": rule_id,
            "description": description,
            "file": file_path,
            "location": {
                "start_line": start_line,
                "end_line": end_line
            },
            "secret_preview": masked_secret,
            "entropy": round(entropy, 2),
            "snippet": snippet.strip() if snippet else "No snippet available"
        }
        
        parsed["secrets"].append(parsed_secret)
    
    # Convert set to count
    parsed["summary"]["unique_files"] = len(parsed["summary"]["unique_files"])
    
    return parsed


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """
    Mask a secret, showing only the first and last few characters.
    
    Args:
        secret: The secret string to mask
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Masked secret string
    """
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]

