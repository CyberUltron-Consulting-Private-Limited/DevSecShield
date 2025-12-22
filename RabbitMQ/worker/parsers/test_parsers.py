"""
Test script to verify all parsers work correctly with testing JSON files.
"""

import json
import sys
from pathlib import Path

# Add parent directory to path to import parsers
sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers import (
    parse_mcp_results,
    parse_discovery_results,
    parse_llm_results,
    parse_iac_results,
    parse_gitleaks_results,
    parse_sbom_results,
    parse_sast_results,
    parse_scan_results,
    detect_scan_type
)


def test_parser(parser_func, file_path, scan_type_name):
    """Test a parser function with a test file."""
    print(f"\n{'='*60}")
    print(f"Testing {scan_type_name} Parser")
    print(f"{'='*60}")
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_results = json.load(f)
        
        # Test auto-detection
        detected_type = detect_scan_type(raw_results)
        print(f"Auto-detected type: {detected_type}")
        
        # Test parsing
        parsed_results = parser_func(raw_results)
        
        # Print summary
        if "summary" in parsed_results:
            print("\nSummary:")
            summary = parsed_results["summary"]
            for key, value in summary.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for k, v in value.items():
                        print(f"    {k}: {v}")
                elif isinstance(value, (list, set)):
                    if isinstance(value, set):
                        print(f"  {key}: {len(value)}")
                    else:
                        print(f"  {key}: {len(value)} items")
                else:
                    print(f"  {key}: {value}")
        
        # Print first few items
        items_key = None
        for key in ["issues", "agents", "secrets", "vulnerabilities", "probe_details"]:
            if key in parsed_results:
                items_key = key
                break
        
        if items_key and parsed_results[items_key]:
            print(f"\nFirst {min(2, len(parsed_results[items_key]))} {items_key}:")
            for i, item in enumerate(parsed_results[items_key][:2]):
                print(f"\n  Item {i+1}:")
                for key, value in item.items():
                    if isinstance(value, dict):
                        print(f"    {key}:")
                        for k, v in value.items():
                            print(f"      {k}: {v}")
                    elif isinstance(value, list):
                        print(f"    {key}: {len(value)} items")
                    else:
                        print(f"    {key}: {str(value)[:100]}{'...' if len(str(value)) > 100 else ''}")
        
        print(f"\n✅ {scan_type_name} parser test PASSED")
        return True
        
    except FileNotFoundError:
        print(f"⚠️  Test file not found: {file_path}")
        return False
    except Exception as e:
        print(f"❌ {scan_type_name} parser test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all parser tests."""
    base_dir = Path(__file__).parent.parent
    
    tests = [
        (parse_mcp_results, base_dir / "mcp_results_testing.json", "MCP"),
        (parse_discovery_results, base_dir / "discovery_results_testing.json", "Discovery"),
        (parse_llm_results, base_dir / "llm_results_testing.json", "LLM"),
        (parse_iac_results, base_dir / "iac_results_testing.json", "IAC"),
        (parse_gitleaks_results, base_dir / "gitleaks_results_testing.json", "Gitleaks"),
        (parse_sbom_results, base_dir / "sbom_results_testing.json", "SBOM"),
    ]
    
    passed = 0
    total = len(tests)
    
    for parser_func, file_path, scan_type in tests:
        if test_parser(parser_func, file_path, scan_type):
            passed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{total} passed")
    print(f"{'='*60}")
    
    # Test auto-parsing
    print(f"\n{'='*60}")
    print("Testing Auto-Parse Function")
    print(f"{'='*60}")
    
    try:
        with open(base_dir / "mcp_results_testing.json", "r", encoding="utf-8") as f:
            raw_results = json.load(f)
        
        parsed = parse_scan_results(raw_results)
        print("✅ Auto-parse test PASSED")
        print(f"   Detected type: {detect_scan_type(raw_results)}")
        print(f"   Summary keys: {list(parsed.get('summary', {}).keys())}")
    except Exception as e:
        print(f"❌ Auto-parse test FAILED: {e}")


if __name__ == "__main__":
    main()

