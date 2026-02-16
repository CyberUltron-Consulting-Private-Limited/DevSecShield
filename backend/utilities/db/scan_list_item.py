from backend.new_models import Scan

def return_sast_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low  = 0,0,0,0
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        for item in scan.scan_data["results"]:
            for vulnerability in item["vulnerabilities"]:
                if vulnerability["impact"].lower() == "critical":
                    total_critical += 1
                elif vulnerability["impact"].lower() == "high":
                    total_high += 1
                elif vulnerability["impact"].lower() == "medium":
                    total_medium += 1
                elif vulnerability["impact"].lower() == "low":
                    total_low += 1

    risk_data = {
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
    }

    _scan_data = scan.scan_data or {}
    _metadata = _scan_data.get("metadata") or {}
    included_docs = _metadata.get("included_documents")
    excluded_docs = _metadata.get("excluded_documents")
    included_count = len(included_docs) if isinstance(included_docs, list) else 0
    excluded_count = len(excluded_docs) if isinstance(excluded_docs, list) else 0
    total_files = included_count + excluded_count
    code_coverage = (included_count / total_files) * 100 if total_files > 0 else 0

    _meta = scan.scan_metadata or {}
    scan_type = _meta.get("repo_type")  # github, gitlab, bitbucket
    if _meta.get("zip_file_used"):
        scan_type = "zip_file"

    duration = _scan_data.get("duration_of_scan") if isinstance(_scan_data, dict) else None
    branch = _meta.get("branch")

    critical_vulnerabilities = []
    results = _scan_data.get("results") or []
    for item in results:
        if not isinstance(item, dict):
            continue
        for vulnerability in item.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            imp = (vulnerability.get("impact") or "").lower()
            if imp == "critical" or imp == "high":
                critical_vulnerabilities.append({
                    "title": vulnerability.get("title"),
                    "impact": vulnerability.get("impact"),
                    "description": vulnerability.get("description"),
                    "policy_violation": len(vulnerability.get("compliance_controls") or []),
                })

        

    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": f"{scan.owner_user.first_name} {scan.owner_user.last_name}",


        "info": scan.info, # sometimes maybe None or sometimes may be { "current" : 20 } where 20 is the progress percentage
        'risk_data': risk_data,
        "repo_url": scan.scan_metadata["repo_url"] if scan.scan_metadata and "repo_url" in scan.scan_metadata else None,
        "branch": scan.scan_metadata["branch"] if scan.scan_metadata and "branch" in scan.scan_metadata else None,
        "app_lang": scan.scan_metadata["app_lang"] if scan.scan_metadata and "app_lang" in scan.scan_metadata else None,
        "risk_score": total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1,
        "code_coverage": code_coverage,
        "scan_type": scan_type,

        "duration": duration,
        "branch" : branch,
        "top_vulnerabilities" : critical_vulnerabilities, 

    }



def return_iac_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low , average_risk_score  = 0,0,0,0,0
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        for vulnerability in scan.scan_data["results"]:
            if vulnerability["impact"].lower() == "critical":
                total_critical += 1
            elif vulnerability["impact"].lower() == "high":
                total_high += 1
            elif vulnerability["impact"].lower() == "medium":
                total_medium += 1
            elif vulnerability["impact"].lower() == "low":
                total_low += 1

    risk_data = {
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
    }


    # calculating average risk score
    if sum([total_critical, total_high, total_medium, total_low]) > 0:
        average_risk_score = total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1 / (total_critical + total_high + total_medium + total_low)
        
    # calculating coverage % 
    scan_run_metadata = scan.scan_metadata.get("metadata",None)
    if not scan_run_metadata :
        coverage_percentage = 0
    else:
        files_scanned = scan_run_metadata.get("included_files",0)
        total_files = scan_run_metadata.get("excluded_files",0) + scan_run_metadata.get("included_files",0)
        coverage_percentage = (files_scanned / total_files) * 100 if total_files > 0 else 0

    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": f"{scan.owner_user.first_name} {scan.owner_user.last_name}",


        "info": scan.info, # sometimes maybe None or sometimes may be { "current" : 20 } where 20 is the progress percentage
        'risk_data': risk_data,
        "repo_url": scan.scan_metadata["repo_url"] if scan.scan_metadata and "repo_url" in scan.scan_metadata else None,
        "zip_file_used": scan.scan_metadata["zip_file_used"] if scan.scan_metadata and "zip_file_used" in scan.scan_metadata else None,
        "branch": scan.scan_metadata["branch"] if scan.scan_metadata and "branch" in scan.scan_metadata else None,
        "cloud_provider" : [ iac_context["mode"] for iac_context in scan.scan_metadata["iac_contexts"] ] if scan.scan_metadata and "iac_contexts" in scan.scan_metadata else [] , 
        "average_risk_score" : average_risk_score,
        "coverage_percentage" : coverage_percentage,
        "environment" : scan.scan_metadata["environment"] if scan.scan_metadata and "environment" in scan.scan_metadata else None,
    }