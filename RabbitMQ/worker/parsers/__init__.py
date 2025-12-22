"""
Parser functions for converting raw scan results into human-readable formats.
"""

from .mcp_parser import parse_mcp_results
from .discovery_parser import parse_discovery_results
from .llm_parser import parse_llm_results
from .iac_parser import parse_iac_results
from .gitleaks_parser import parse_gitleaks_results
from .sbom_parser import parse_sbom_results
from .sast_parser import parse_sast_results
from .utils import detect_scan_type, parse_scan_results

__all__ = [
    "parse_mcp_results",
    "parse_discovery_results",
    "parse_llm_results",
    "parse_iac_results",
    "parse_gitleaks_results",
    "parse_sbom_results",
    "parse_sast_results",
    "detect_scan_type",
    "parse_scan_results",
]

