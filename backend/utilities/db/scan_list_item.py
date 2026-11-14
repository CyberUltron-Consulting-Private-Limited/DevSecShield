from backend.new_models import Scan


def owner_full_name(user) -> str | None:
    """"First Last" of a scan's owner; a missing part is left out ("alice", never "alice None"); None when both are."""
    return " ".join(p for p in (getattr(user, "first_name", None), getattr(user, "last_name", None)) if p) or None

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
        "owner_user_full_name": owner_full_name(scan.owner_user),


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
        average_risk_score = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / (total_critical + total_high + total_medium + total_low)
        
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
        "owner_user_full_name": owner_full_name(scan.owner_user),


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





def return_sbom_sca_list_item(scan : Scan) -> dict:
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
        average_risk_score = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / (total_critical + total_high + total_medium + total_low)
        
 
    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),


        "info": scan.info, # sometimes maybe None or sometimes may be { "current" : 20 } where 20 is the progress percentage
        'risk_data': risk_data,
        "repo_url": scan.scan_metadata["repo_url"] if scan.scan_metadata and "repo_url" in scan.scan_metadata else None,
        "zip_file_used": scan.scan_metadata["zip_file_used"] if scan.scan_metadata and "zip_file_used" in scan.scan_metadata else None,
        "branch": scan.scan_metadata["branch"] if scan.scan_metadata and "branch" in scan.scan_metadata else None, 
        "average_risk_score" : average_risk_score,
    }




def return_mcp_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low , average_risk_score  = 0,0,0,0,0
    total_tools , total_prompts , total_resources = 0,0,0
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        for tool in scan.scan_data["results"]["tools"]:
            total_tools += 1
            for vulnerability in tool["vulnerabilities"]:
                if vulnerability["impact"].lower() == "critical":
                    total_critical += 1
                elif vulnerability["impact"].lower() == "high":
                    total_high += 1
                elif vulnerability["impact"].lower() == "medium":
                    total_medium += 1
                elif vulnerability["impact"].lower() == "low":
                    total_low += 1
        for prompt in scan.scan_data["results"]["prompts"] and "results" in scan.scan_data and scan.scan_status == "success":
            total_prompts += 1
            for vulnerability in prompt["vulnerabilities"]:
                if vulnerability["impact"].lower() == "critical":
                    total_critical += 1
                elif vulnerability["impact"].lower() == "high":
                    total_high += 1
                elif vulnerability["impact"].lower() == "medium":
                    total_medium += 1
                elif vulnerability["impact"].lower() == "low":
                    total_low += 1
        for resource in scan.scan_data["results"]["resources"] and "results" in scan.scan_data and scan.scan_status == "success":
            total_resources += 1
            for vulnerability in resource["vulnerabilities"]:
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

    # calculating risky resources
    risky_resources = 0 
    if "results" in scan.scan_data and scan.scan_status == "success":
        for tool in scan.scan_data["results"]["tools"]:
            if tool["tool_risk_level"].lower() == "high" or tool["tool_risk_level"].lower() == "critical":
                risky_resources += 1
        for prompt in scan.scan_data["results"]["prompts"]:
            if prompt["prompt_risk_level"].lower() == "high" or prompt["prompt_risk_level"].lower() == "critical":
                risky_resources += 1
        for resource in scan.scan_data["results"]["resources"]:
            if resource["resource_risk_level"].lower() == "high" or resource["resource_risk_level"].lower() == "critical":
                risky_resources += 1


    # calculating average risk score
    if sum([total_critical, total_high, total_medium, total_low]) > 0:
        average_risk_score = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / (total_critical + total_high + total_medium + total_low)
        
 
    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),


        "info": scan.info, # sometimes maybe None or sometimes may be { "current" : 20 } where 20 is the progress percentage
        'risk_data': risk_data,
        "server" : scan.scan_metadata["server_url"].split(".")[-2].replace("https://","").replace("http://","") if scan.scan_metadata and "server_url" in scan.scan_metadata else None,
        "average_risk_score" : average_risk_score,
        "discovery_metrics" : {
            "total_tools" : total_tools,
            "total_prompts" : total_prompts,
            "total_resources" : total_resources,
        },
        "risky_assets" : risky_resources,
    }





def return_llm_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low , average_risk_score  = 0,0,0,0,0
    vulns: list = []
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        results = scan.scan_data.get("results") or {}
        vulns = results.get("vulnerabilities") or []
        for vulnerability in vulns:
            if isinstance(vulnerability, dict):
                imp = (vulnerability.get("impact") or "").lower()
                if imp == "critical":
                    total_critical += 1
                elif imp == "high":
                    total_high += 1
                elif imp == "medium":
                    total_medium += 1
                elif imp == "low":
                    total_low += 1

    risk_data = {
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
    }

    results_safe = (scan.scan_data or {}).get("results") or {}
    model_vulnerabilities = results_safe.get("model_vulnerabilities") or {}
    """
    model_vulnerabilities will look like this :
        {
            "jailbreak_resistance_score": 10,
            "injection_resistance_score": 10,
            "hallucination_resistance_score": 10,
            "bias_resistance_score": 10,
            "content_safety_score": 10,
            "data_privacy_score": 10,
        }
    """

    # calculating average risk score (0-10 scale, same as IAC)
    total = total_critical + total_high + total_medium + total_low
    if total > 0:
        weighted = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / total
        average_risk_score = min(10.0, max(0.0, (weighted / 4) * 10))
    else:
        average_risk_score = 0.0

    mitre_atlas_tactics = 0
    if vulns:
        tactics = set()
        for v in vulns:
            if isinstance(v, dict):
                t = v.get("mitre_atlas_tactic")
                if t is not None:
                    tactics.add(str(t))
        mitre_atlas_tactics = len(tactics)

    scan_meta = scan.scan_metadata or {}
    data_meta = (scan.scan_data or {}).get("metadata") or {}
    model_name = scan_meta.get("model_name") or data_meta.get("model_name")

    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),

        "info": scan.info,
        "risk_data": risk_data,
        "average_risk_score": round(average_risk_score * 10) / 10 if total > 0 else 0.0,
        "model_type": scan_meta.get("model_type"),
        "model_name": model_name,
        "attack_iterations": scan_meta.get("generations"),
        "total_attacks_performed": len(scan_meta.get("probes") or []),

        "model_vulnerabilities": model_vulnerabilities,
        "total_mitre_atlas_tactics": mitre_atlas_tactics,
    
    }



def return_dast_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low , average_risk_score , urls_scanned =  0,0,0,0,0,0
    urls_not_scanned = 0
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
        
        if "metadata" in scan.scan_data and scan.scan_data["metadata"] != {} and "urls_scanned" in scan.scan_data["metadata"]:
            urls_scanned = len(scan.scan_data["metadata"]["urls_included"])
            urls_not_scanned = len(scan.scan_data["metadata"]["urls_excluded"])

    risk_data = {
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
    }


    # calculating average risk score
    if sum([total_critical, total_high, total_medium, total_low]) > 0:
        average_risk_score = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / (total_critical + total_high + total_medium + total_low)
        
 
    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),


        "info": scan.info, # sometimes maybe None or sometimes may be { "current" : 20 } where 20 is the progress percentage
        'risk_data': risk_data,
        "target_url": scan.scan_metadata["target_url"] if scan.scan_metadata and "target_url" in scan.scan_metadata else None,
        "average_risk_score" : average_risk_score,
        "urls_scanned": urls_scanned,
        "coverage_percentage": (urls_scanned / (urls_scanned + urls_not_scanned)) * 100 if urls_scanned + urls_not_scanned > 0 else 0,
    }



def return_cbom_list_item(scan : Scan) -> dict:
    # the same counts as the scan's dashboard and PDF (cbom_metrics): findings only, inventory is informational
    from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows

    rows = []
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        rows = scan.scan_data["results"] or []
    summary = summarize_code_rows(rows)
    risk_data = {
        "total_critical": summary.severity["critical"],
        "total_high": summary.severity["high"],
        "total_medium": summary.severity["medium"],
        "total_low": summary.severity["low"],
        "total_informational": summary.informational,
    }
    # app-wide 0-10 CBOM scale (critical=9, high=7, medium=5, low=2), over findings only
    average_risk_score = summary.average_risk
    total_weak = summary.weak
    total_quantum_vulnerable = summary.quantum["quantum_vulnerable"]

    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),


        "info": scan.info,
        'risk_data': risk_data,
        "repo_url": scan.scan_metadata["repo_url"] if scan.scan_metadata and "repo_url" in scan.scan_metadata else None,
        "zip_file_used": scan.scan_metadata["zip_file_used"] if scan.scan_metadata and "zip_file_used" in scan.scan_metadata else None,
        "cbom_file_used": scan.scan_metadata.get("cbom_file_used", False) if scan.scan_metadata else False,
        "branch": scan.scan_metadata["branch"] if scan.scan_metadata and "branch" in scan.scan_metadata else None,
        "average_risk_score" : average_risk_score,
        "total_weak_algorithms": total_weak,
        "total_quantum_vulnerable": total_quantum_vulnerable,
        "scan_binaries": scan.scan_metadata.get("scan_binaries", False) if scan.scan_metadata else False,
    }




def return_ai_bom_list_item(scan : Scan) -> dict:
    total_critical , total_high , total_medium , total_low , average_risk_score  = 0,0,0,0,0
    total_high_risk_assets , total_models = 0, 0
    model_component_types = {"local_model_file", "huggingface_model", "embedding_model"}
    if scan.scan_data and scan.scan_data != {} and "results" in scan.scan_data and scan.scan_status == "success":
        for asset in scan.scan_data["results"]:
            impact = (asset.get("impact") or "").lower()
            if impact == "critical":
                total_critical += 1
            elif impact == "high":
                total_high += 1
            elif impact == "medium":
                total_medium += 1
            elif impact == "low":
                total_low += 1

            # Count high risk assets (Critical / High impact)
            if impact in ("critical", "high"):
                total_high_risk_assets += 1

            # Count models by component_type
            component_type = (asset.get("component_type") or "").lower()
            if component_type in model_component_types:
                total_models += 1

    risk_data = {
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
        "total_high_risk_assets": total_high_risk_assets,
        "total_models": total_models,
    }


    # calculating average risk score (normalized 0-10 scale, same as the
    # single-scan AI-BOM dashboard and cbom)
    total_findings = total_critical + total_high + total_medium + total_low
    if total_findings > 0:
        weighted = (total_critical * 4 + total_high * 3 + total_medium * 2 + total_low * 1) / total_findings
        average_risk_score = min(10.0, max(0.0, (weighted / 4) * 10))


    return {
        "id": scan.id,
        "title": scan.title,
        "created_at": scan.created_at,
        "last_updated": scan.last_updated,
        "scan_status": scan.scan_status.lower(),

        "estimated_credits": scan.credit_consumed,
        "owner_user_email": scan.owner_user.email,
        "owner_user_full_name": owner_full_name(scan.owner_user),


        "info": scan.info,
        'risk_data': risk_data,
        "repo_url": scan.scan_metadata["repo_url"] if scan.scan_metadata and "repo_url" in scan.scan_metadata else None,
        "zip_file_used": scan.scan_metadata["zip_file_used"] if scan.scan_metadata and "zip_file_used" in scan.scan_metadata else None,
        "ai_bom_file_used": scan.scan_metadata.get("ai_bom_file_used", False) if scan.scan_metadata else False,
        "branch": scan.scan_metadata["branch"] if scan.scan_metadata and "branch" in scan.scan_metadata else None,
        "average_risk_score" : average_risk_score,
        "scan_binaries": scan.scan_metadata.get("scan_binaries", False) if scan.scan_metadata else False,
    }