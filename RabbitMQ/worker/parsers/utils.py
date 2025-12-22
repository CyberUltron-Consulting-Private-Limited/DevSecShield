"""
Utility functions for parsing scan results.
Includes automatic scan type detection and parsing.
"""

from typing import Dict, Any, Union, List
import json

from .mcp_parser import parse_mcp_results
from .discovery_parser import parse_discovery_results
from .llm_parser import parse_llm_results
from .iac_parser import parse_iac_results
from .gitleaks_parser import parse_gitleaks_results
from .sbom_parser import parse_sbom_results
from .sast_parser import parse_sast_results


def detect_scan_type(raw_results: Union[Dict[str, Any], List[Dict[str, Any]]]) -> str:
    """
    Automatically detect the scan type from raw results.
    
    Args:
        raw_results: Raw scan results (dict or list)
        
    Returns:
        Scan type string: 'mcp', 'discovery', 'llm', 'iac', 'gitleaks', 'sbom', 'sast', or 'unknown'
    """
    if isinstance(raw_results, list):
        # Check if it's discovery results (list of agents)
        if raw_results and isinstance(raw_results[0], dict):
            if "id" in raw_results[0] and "file_path" in raw_results[0] and "role" in raw_results[0]:
                return "discovery"
            # Check if it's gitleaks results (list of findings)
            if "RuleID" in raw_results[0] and "File" in raw_results[0] and "Secret" in raw_results[0]:
                return "gitleaks"
    
    if isinstance(raw_results, dict):
        # Check for MCP results
        if "final_issues" in raw_results and "error_messages" in raw_results:
            return "mcp"
        
        # Check for LLM results
        if "status" in raw_results and "model_name" in raw_results and "total_tests" in raw_results:
            return "llm"
        
        # Check for IAC results
        if "results" in raw_results:
            results = raw_results["results"]
            if results and isinstance(results[0], dict):
                if "rule_id" in results[0] and "severity" in results[0] and "resource" in results[0]:
                    return "iac"
                # Check if it's SAST results (has check_id, path, start, and extra fields)
                if "check_id" in results[0] and "path" in results[0] and "start" in results[0] and "extra" in results[0]:
                    return "sast"
        
        # Check for SBOM results
        if "matches" in raw_results and "source" in raw_results:
            return "sbom"
    
    return "unknown"


def parse_scan_results(raw_results: Union[Dict[str, Any], List[Dict[str, Any]], str], scan_type: str = None) -> Dict[str, Any]:
    """
    Parse scan results automatically or with specified scan type.
    
    Args:
        raw_results: Raw scan results (dict, list, or JSON string)
        scan_type: Optional scan type override ('mcp', 'discovery', 'llm', 'iac', 'gitleaks', 'sbom', 'sast')
                  If not provided, will auto-detect
        
    Returns:
        Dictionary with parsed, human-readable results
        
    Raises:
        ValueError: If scan type cannot be determined or is unsupported
    """
    # Convert JSON string to dict/list if needed
    if isinstance(raw_results, str):
        try:
            raw_results = json.loads(raw_results)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string: {e}")
    
    # Auto-detect scan type if not provided
    if scan_type is None:
        scan_type = detect_scan_type(raw_results)
    
    if scan_type == "unknown":
        raise ValueError("Could not determine scan type. Please specify scan_type parameter.")
    
    # Parse based on scan type
    parsers = {
        "mcp": parse_mcp_results,
        "discovery": parse_discovery_results,
        "llm": parse_llm_results,
        "iac": parse_iac_results,
        "gitleaks": parse_gitleaks_results,
        "sbom": parse_sbom_results,
        "sast": parse_sast_results
    }
    
    if scan_type not in parsers:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    
    parser_func = parsers[scan_type]
    return parser_func(raw_results)

