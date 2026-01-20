"""
Guardrails API Client

Helper functions for interacting with the Guardrails API.
This module handles all API communication details.
"""

import time
import requests
from typing import Optional, Dict, Any

# Configuration
BASE_URL = "https://devsecshieldapi.zeroshield.ai"


def start_guardrails_scan(api_key: str, input_prompt: str) -> Optional[str]:
    """
    Start a Guardrails scan for the given prompt.
    
    Args:
        api_key: The Guardrails API key
        input_prompt: The prompt to scan
        
    Returns:
        The scan ID if successful, None otherwise
    """
    print("🔒 Starting Guardrails scan...")
    url = f"{BASE_URL}/public/guardrails/start_scan"
    headers = {
        "gr-api-key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "input_prompt": input_prompt
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        result = response.json()
        scan_id = result.get("result_id")
        if scan_id:
            print(f"   ✓ Scan started. Scan ID: {scan_id}")
        return scan_id
    except requests.exceptions.RequestException as e:
        print(f"❌ Error starting Guardrails scan: {e}")
        return None


def get_guardrails_scan_status(api_key: str, scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Get the status and results of a Guardrails scan.
    
    Args:
        api_key: The Guardrails API key
        scan_id: The scan ID returned from start_scan
        
    Returns:
        Dictionary with status and results, None if error
    """
    url = f"{BASE_URL}/public/guardrails/{scan_id}"
    headers = {
        "gr-api-key": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting Guardrails scan status: {e}")
        return None


def wait_for_scan_completion(api_key: str, scan_id: str, max_wait_time: int = 60) -> Optional[Dict[str, Any]]:
    """
    Poll the Guardrails API until the scan completes.
    
    Args:
        api_key: The Guardrails API key
        scan_id: The scan ID to check
        max_wait_time: Maximum time to wait in seconds
        
    Returns:
        The scan results if successful, None otherwise
    """
    print("⏳ Waiting for scan to complete...")
    start_time = time.time()
    poll_interval = 2  # Poll every 2 seconds
    
    while time.time() - start_time < max_wait_time:
        result = get_guardrails_scan_status(api_key, scan_id)
        
        if result is None:
            return None
            
        status = result.get("status", "").lower()
        print(f"   Status: {status}")
        
        if status == "success":
            print("   ✓ Scan completed successfully!")
            return result
        elif status == "failed":
            print("   ✗ Scan failed")
            return result
        elif status in ["pending", "started"]:
            time.sleep(poll_interval)
        else:
            time.sleep(poll_interval)
    
    print("   ⚠ Timeout: Scan did not complete within the time limit")
    return None


def start_guardrails_scan_and_wait_for_results(api_key: str, input_prompt: str, max_wait_time: int = 60) -> Optional[Dict[str, Any]]:
    """
    Start a Guardrails scan and wait for results.
    
    Args:
        api_key: The Guardrails API key
        input_prompt: The prompt to scan
        max_wait_time: Maximum time to wait for scan completion
        
    Returns:
        Dictionary with scan results, None if error
    """
    scan_id = start_guardrails_scan(api_key, input_prompt)
    if not scan_id:
        return None
    
    return wait_for_scan_completion(api_key, scan_id, max_wait_time)


def passed_check(scan_results: Optional[Dict[str, Any]]) -> bool:
    """
    Check if the Guardrails scan passed.
    Cycles through all risk scores that are not -1 and fails if any score > 0.5.
    Prints scan results and decision.
    
    Args:
        scan_results: The scan results dictionary
        
    Returns:
        True if the scan passed, False otherwise
    """
    print("\n" + "=" * 70)
    print("  Guardrails Scan Results")
    print("=" * 70)
    
    if not scan_results:
        print("❌ DECISION: REJECT (No scan results)")
        return False
    
    results = scan_results.get("results")
    if not results or not isinstance(results, dict):
        print("❌ DECISION: REJECT (Invalid scan results)")
        return False
    
    # Known scanner patterns (handle both cases)
    scanner_patterns = ["anonymize", "toxicity", "tokenlimit", "promptinjection", "regex", "code", "secrets"]
    
    risk_scores = []
    
    # Extract and display risk scores
    for key in results.keys():
        if key.lower() in [p.lower() for p in scanner_patterns]:
            scanner_data = results.get(key)
            if scanner_data and isinstance(scanner_data, dict):
                score = scanner_data.get("score")
                valid = scanner_data.get("valid")
                # Include all scores for display
                if score is not None and isinstance(score, (int, float)):
                    risk_scores.append({
                        "scanner": key,
                        "score": float(score),
                        "valid": valid
                    })
    
    # Display risk scores
    if risk_scores:
        print("\n📊 Risk Scores:")
        print("-" * 70)
        print(f"   {'Scanner':<22s} | {'Score':>10s} | {'Risk Level':<12s} | {'Status':<8s}")
        print("-" * 70)
        for risk_info in risk_scores:
            scanner_display = risk_info["scanner"].replace("_", " ").title()
            score = risk_info["score"]
            valid = risk_info["valid"]
            status_text = "PASS" if valid else "FAIL"
            
            # Handle -1 score (scanner active but didn't flag anything)
            if score == -1:
                score_percentage = "N/A"
                risk_level = "✅ CLEAR"
                status_icon = "✅"
            else:
                # Format score - handle both 0-1 scale and 0-100 scale
                if score <= 1.0:
                    score_percentage = f"{score * 100:.1f}%"
                else:
                    score_percentage = f"{score:.1f}"
                
                # Interpret score (0-1 scale typically, where higher = more risky)
                normalized_score = score if score <= 1.0 else score / 100.0
                if normalized_score >= 0.8:
                    risk_level = "🔴 HIGH"
                elif normalized_score >= 0.5:
                    risk_level = "🟡 MEDIUM"
                elif normalized_score >= 0.2:
                    risk_level = "🟠 LOW"
                else:
                    risk_level = "🟢 VERY LOW"
                
                status_icon = "✅" if valid else "❌"
            
            print(f"   {scanner_display:<22s} | {score_percentage:>10s} | {risk_level:<12s} | {status_icon} {status_text}")
    
    # Check if any score > 0.5 (fail condition)
    check_passed = True
    for risk_info in risk_scores:
        score = risk_info["score"]
        # Check only scores that are not -1
        if score != -1 and float(score) > 0.5:
            check_passed = False
            break
    
    # Display decision
    print("\n" + "=" * 70)
    if check_passed:
        print("  ✅ DECISION: ACCEPT")
    else:
        print("  ❌ DECISION: REJECT (Risk score exceeds threshold)")
    print("=" * 70 + "\n")
    
    return check_passed


def get_sanitized_prompt(scan_results: Optional[Dict[str, Any]], original_prompt: str) -> str:
    """
    Get the sanitized prompt from scan results.
    
    Args:
        scan_results: The scan results dictionary
        original_prompt: The original prompt
        
    Returns:
        The sanitized prompt, or original if not available
    """
    if not scan_results:
        return original_prompt
    
    results = scan_results.get("results")
    if not results:
        return original_prompt
    
    return results.get("sanitized_prompt", original_prompt)
