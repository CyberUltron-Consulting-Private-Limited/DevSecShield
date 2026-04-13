from backend.new_models import scan_types

def create_sast_output_string(results: list[dict]) -> str:
    """
    Create a sast output from the results
    """
    output="Summary of Vulnerabilities found in the code:"
    for item in results:
        logical_component = item.get("logical_component")
        vulnerabilities = []
        for vulnerability in item.get("vulnerabilities",[]):
            title = vulnerability.get("title")
            description = vulnerability.get("description")
            impact = vulnerability.get("impact")
            owasp_top_10 = vulnerability.get("owasp_top_10")
            compliance_controls = vulnerability.get("compliance_controls")
            suggested_fix = vulnerability.get("suggested_fix")
            location = vulnerability.get("location")
            snippet = vulnerability.get("snippet")
            cves = vulnerability.get("cves")
            vulnerabilities.append(f"Title: {title}\nDescription: {description}\nImpact: {impact}\nOWASP Top 10: {owasp_top_10}\nCompliance Controls: {compliance_controls}\nSuggested Fix: {suggested_fix}\nLocation: {location}\nSnippet: {snippet}\nCVEs: {cves}")
        output += f"\nLogical Component: {logical_component}"
        vulns = "\n".join(vulnerabilities)
        output += f"\nVulnerabilities: {vulns}"
        output += "======="*20
    return output


def create_cbom_output_string(results: list[dict]) -> str:
    """
    Create a cbom output from the results for Jira ticket
    """
    output = "Summary of Cryptographic Assets found in the code:"
    for item in results:
        logical_component = item.get("logical_component")
        vulnerabilities = []
        for vulnerability in item.get("vulnerabilities", []):
            title = vulnerability.get("title")
            description = vulnerability.get("description")
            impact = vulnerability.get("impact")
            algorithm_name = vulnerability.get("algorithm_name")
            algorithm_type = vulnerability.get("algorithm_type")
            crypto_strength = vulnerability.get("crypto_strength")
            key_size = vulnerability.get("key_size")
            quantum_safe = vulnerability.get("quantum_safe")
            location = vulnerability.get("location")
            snippet = vulnerability.get("snippet")
            suggested_fix = vulnerability.get("suggested_fix")
            owasp_top_10 = vulnerability.get("owasp_top_10")
            compliance_controls = vulnerability.get("compliance_controls")
            cves = vulnerability.get("cves")
            vulnerabilities.append(
                f"Title: {title}\nAlgorithm: {algorithm_name} ({algorithm_type})\n"
                f"Strength: {crypto_strength}\nKey Size: {key_size}\n"
                f"Quantum Safe: {quantum_safe}\nDescription: {description}\n"
                f"Impact: {impact}\nOWASP Top 10: {owasp_top_10}\n"
                f"Compliance Controls: {compliance_controls}\n"
                f"Suggested Fix: {suggested_fix}\nLocation: {location}\n"
                f"Snippet: {snippet}\nCVEs: {cves}"
            )
        output += f"\nLogical Component: {logical_component}"
        vulns = "\n".join(vulnerabilities)
        output += f"\nVulnerabilities: {vulns}"
        output += "=======" * 20
    return output


def create_output_string_for_results(scan_type: scan_types , results: list[dict]) -> str:
    if scan_type == "sast":
        return create_sast_output_string(results)
    elif scan_type == "cbom":
        return create_cbom_output_string(results)
    else:
        raise ValueError(f"Unsupported scan type: {scan_type}")