from backend.get_db import get_mongo_client_db
from backend.mongo_models import ScanFindings
from backend.new_models import scan_types



def get_findings_for_scan_id(scan_id: int) -> list[dict]:
    
    mongo_db = get_mongo_client_db()
    findings_collection = mongo_db["scan_findings"]

    findings = findings_collection.find({"scan_id": scan_id})

    findings_list = []
    for finding in findings:
        findings_list.append(finding)
    
    return findings_list

risk_score_map = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def get_findings_for_scan_type(scan_type: scan_types , scan_id: int) -> list[dict]:
    findings = []
    if scan_type == "sast":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "risk_score": risk_score_map[finding["finding_data"]["impact"].lower()],
                "status": finding["finding_status"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "owasp_top_10": finding["finding_data"]["owasp_top_10"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "location": finding["finding_data"]["location"],
                "snippet": finding["finding_data"]["snippet"],
                "cves": finding["finding_data"]["cves"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "iac":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "risk_score": risk_score_map[finding["finding_data"]["impact"].lower()],
                "status": finding["finding_status"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "owasp_top_10": finding["finding_data"]["owasp_top_10"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "location": finding["finding_data"]["location"],
                "snippet": finding["finding_data"]["snippet"],
                "cves": finding["finding_data"]["cves"],
                "category": finding["finding_data"]["category"],
                "resource": finding["finding_data"]["resource"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "sbom_sca":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "risk_score": risk_score_map[finding["finding_data"]["impact"].lower()],
                "status": finding["finding_status"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "owasp_top_10": finding["finding_data"]["owasp_top_10"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "cves": finding["finding_data"]["cves"],
                "dependency": finding["finding_data"]["dependency"],
                "reachability": finding["finding_data"]["reachability"],
                "dependency_type": finding["finding_data"]["dependency_type"],
                "license_type": finding["finding_data"]["license_type"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "mcp":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "risk_score": risk_score_map[finding["finding_data"]["impact"].lower()],
                "status": finding["finding_status"],
                "owasp_top_10": finding["finding_data"]["owasp_top_10"],
                "owasp_top_10_llm": finding["finding_data"]["owasp_top_10_llm"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "type": finding["finding_data"]["type"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "llm":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "status": finding["finding_status"],
                "vulnerability_predictions": finding["finding_data"]["vulnerability_predictions"],
                "owasp_top_10_llm": finding["finding_data"]["owasp_top_10_llm"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "dast":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            findings.append({
                "id": str(finding["_id"]),
                "title": finding["finding_data"]["title"],
                "url": finding["finding_data"].get("url","-"),
                "description": finding["finding_data"]["description"],
                "impact": finding["finding_data"]["impact"],
                "risk_score": risk_score_map[finding["finding_data"]["impact"].lower()],
                "status": finding["finding_status"],
                "compliance_controls": finding["finding_data"]["compliance_controls"],
                "owasp_top_10": finding["finding_data"]["owasp_top_10"],
                "suggested_fix": finding["finding_data"]["suggested_fix"],
                "category": finding["finding_data"]["category"],
                "confidence": finding["finding_data"]["confidence"],
                "remediation": finding.get("remediation", None),
            })
    
    elif scan_type == "cbom":
        findings_fetched = get_findings_for_scan_id(scan_id=scan_id)
        for finding in findings_fetched:
            fd = finding.get("finding_data", {})
            findings.append({
                "id": str(finding["_id"]),
                "title": fd.get("title", ""),
                "description": fd.get("description", ""),
                "impact": fd.get("impact", "low"),
                "risk_score": risk_score_map[fd.get("impact", "low").lower()],
                "status": finding.get("finding_status", "open"),
                "compliance_controls": fd.get("compliance_controls", []),
                "owasp_top_10": fd.get("owasp_top_10", []),
                "suggested_fix": fd.get("suggested_fix", ""),
                "algorithm_name": fd.get("algorithm_name", ""),
                "algorithm_type": fd.get("algorithm_type", ""),
                "crypto_strength": fd.get("crypto_strength", ""),
                "key_size": fd.get("key_size"),
                "quantum_safe": fd.get("quantum_safe", False),
                "location": fd.get("location", ""),
                "snippet": fd.get("snippet", ""),
                "remediation": finding.get("remediation", None),
            })

    return findings