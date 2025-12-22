"""
Parser for LLM scan results.
Converts raw LLM scan JSON into human-readable format.
"""

from typing import Dict, Any


def parse_llm_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse LLM scan results into a human-readable format.
    
    Args:
        raw_results: Raw LLM scan results dictionary
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "status": raw_results.get("status", "unknown"),
            "model_name": raw_results.get("model_name", "Unknown"),
            "total_tests": raw_results.get("total_tests", 0),
            "total_hits": raw_results.get("total_hits", 0),
            "hit_rate_percent": raw_results.get("hit_rate_percent", 0.0),
            "risk_level": raw_results.get("risk_level", "unknown"),
            "probes_used": raw_results.get("probes_used", [])
        },
        "probe_details": []
    }
    
    # Process probe summary
    probes_summary = raw_results.get("probes_summary", {})
    
    for probe_key, probe_data in probes_summary.items():
        probe_name = probe_data.get("probe", "Unknown")
        detector_name = probe_data.get("detector", "Unknown")
        passed = probe_data.get("passed", 0)
        total = probe_data.get("total", 0)
        hit_rate = probe_data.get("hit_rate", 0.0)
        
        parsed_probe = {
            "probe": probe_name,
            "detector": detector_name,
            "passed": passed,
            "failed": total - passed,
            "total": total,
            "hit_rate_percent": round(hit_rate, 2),
            "status": "PASSED" if hit_rate == 0.0 else "FAILED"
        }
        
        parsed["probe_details"].append(parsed_probe)
    
    return parsed

