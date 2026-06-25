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
    Create a cbom output from the results for Jira ticket.

    The CBOM worker result is a flat list of cryptographic-asset finding dicts
    (each produced from a CryptographicAssetVulnerability), with keys:
    title, description, impact, algorithm_name, algorithm_type, crypto_strength,
    key_size, quantum_safe, location, snippet, suggested_fix, owasp_top_10,
    compliance_controls. There is no logical_component grouping and no nested
    vulnerabilities list (unlike SAST).
    """
    # The caller may hand us either the inner list of findings or the full
    # worker result dict ( { "results": [ ... ], "cbom_json": ..., ... } ).
    # Normalize to the list of finding dicts so iteration is always correct.
    if isinstance(results, dict):
        findings = results.get("results", [])
    else:
        findings = results or []

    output = "Summary of Cryptographic Assets found in the code:"
    for finding in findings:
        title = finding.get("title")
        description = finding.get("description")
        impact = finding.get("impact")
        algorithm_name = finding.get("algorithm_name")
        algorithm_type = finding.get("algorithm_type")
        crypto_strength = finding.get("crypto_strength")
        key_size = finding.get("key_size")
        quantum_safe = finding.get("quantum_safe")
        location = finding.get("location")
        snippet = finding.get("snippet")
        suggested_fix = finding.get("suggested_fix")
        owasp_top_10 = finding.get("owasp_top_10")
        compliance_controls = finding.get("compliance_controls")
        output += (
            f"\nTitle: {title}\nAlgorithm: {algorithm_name} ({algorithm_type})\n"
            f"Strength: {crypto_strength}\nKey Size: {key_size}\n"
            f"Quantum Safe: {quantum_safe}\nDescription: {description}\n"
            f"Impact: {impact}\nOWASP Top 10: {owasp_top_10}\n"
            f"Compliance Controls: {compliance_controls}\n"
            f"Suggested Fix: {suggested_fix}\nLocation: {location}\n"
            f"Snippet: {snippet}"
        )
        output += "=======" * 20
    return output


def create_ai_bom_output_string(results: list[dict]) -> str:
    """
    Create an ai_bom output from the results for Jira ticket.

    The AI-BOM worker result is a flat list of AI/ML component finding dicts
    (each produced from an AIComponentVulnerability via parse_vuln), with keys:
    title, description, impact, component_name, component_type, framework,
    version, source, license, risk_category, location, snippet, suggested_fix,
    owasp_top_10, owasp_top_10_llm, compliance_controls. There is no
    logical_component grouping and no nested vulnerabilities list (unlike SAST).
    parse_vuln serializes owasp_top_10 / owasp_top_10_llm / compliance_controls
    as { enum_name: enum_value } dicts, so render the human-readable values.
    """
    # The caller may hand us either the inner list of findings or the full
    # worker result dict ( { "results": [ ... ], "ai_bom_json": ..., ... } ).
    # Normalize to the list of finding dicts so iteration is always correct.
    if isinstance(results, dict):
        findings = results.get("results", [])
    else:
        findings = results or []

    def _values(field) -> str:
        # owasp_top_10 / owasp_top_10_llm / compliance_controls are serialized
        # as { enum_name: human_readable_value }. Show the values.
        if isinstance(field, dict):
            return ", ".join(str(v) for v in field.values() if v)
        if isinstance(field, (list, tuple)):
            return ", ".join(str(v) for v in field if v)
        return str(field) if field else ""

    output = "Summary of AI Assets found in the code:"
    for finding in findings:
        title = finding.get("title")
        description = finding.get("description")
        impact = finding.get("impact")
        # Tolerate both stored (component_name/source/license) and frontend
        # (asset_name/provider/license_type) field names.
        component_name = finding.get("component_name") or finding.get("asset_name")
        component_type = finding.get("component_type") or finding.get("asset_type")
        framework = finding.get("framework")
        version = finding.get("version")
        source = finding.get("source") or finding.get("provider")
        license = finding.get("license") or finding.get("license_type")
        risk_category = finding.get("risk_category")
        location = finding.get("location")
        snippet = finding.get("snippet")
        suggested_fix = finding.get("suggested_fix")
        owasp_top_10 = _values(finding.get("owasp_top_10"))
        owasp_top_10_llm = _values(finding.get("owasp_top_10_llm"))
        compliance_controls = _values(finding.get("compliance_controls"))
        output += (
            f"\nTitle: {title}\nComponent: {component_name} ({component_type})\n"
            f"Framework: {framework}\nVersion: {version}\n"
            f"Source: {source}\nLicense: {license}\n"
            f"Risk Category: {risk_category}\nDescription: {description}\n"
            f"Impact: {impact}\nOWASP Top 10: {owasp_top_10}\n"
            f"OWASP Top 10 LLM: {owasp_top_10_llm}\n"
            f"Compliance Controls: {compliance_controls}\n"
            f"Suggested Fix: {suggested_fix}\nLocation: {location}\n"
            f"Snippet: {snippet}"
        )
        output += "=======" * 20
    return output


def create_output_string_for_results(scan_type: scan_types , results: list[dict]) -> str:
    if scan_type == "sast":
        return create_sast_output_string(results)
    elif scan_type == "cbom":
        return create_cbom_output_string(results)
    elif scan_type == "ai_bom":
        return create_ai_bom_output_string(results)
    else:
        raise ValueError(f"Unsupported scan type: {scan_type}")