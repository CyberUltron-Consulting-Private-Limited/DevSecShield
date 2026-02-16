from backend.new_models import Scan, scan_types
from datetime import datetime , timezone
from rich.console import Console
from fastapi import HTTPException , status
from backend.utilities.db.findings import get_findings_for_scan_id
from backend.utilities.dashboard.remediation_metrics import get_remediation_metrics
from backend.utilities.dashboard.finding_metrics import get_issue_status_metrics, get_mttr_per_day

console = Console()

# OWASP short label: split enum-style value by " - " (see RabbitMQ/worker/helpers/context/enums.py OWASPTop10).
# e.g. "A01:2021 - Broken Access Control" -> "Broken Access Control"
def _short_label_owasp(key: str) -> str:
    if not key or not isinstance(key, str):
        return ""
    key = key.strip()
    if " - " in key:
        return key.split(" - ", 1)[1].strip() or key
    return key[:20] if len(key) > 20 else key

LANG_DISPLAY = {
    "python": "Python",
    "javascript": "JavaScript",
    "java": "Java",
    "typescript": "TypeScript",
    "php": "PHP",
    "c": "C",
    "ruby": "Ruby",
    "rust": "Rust",
    "swift": "Swift",
    "csharp": "C#",
    "kotlin": "Kotlin",
}


def _sast_results(scan: Scan) -> list:
    """Normalize SAST scan_data to list of components (support list or {"results": [...]})."""
    if not scan.scan_data or scan.scan_data == {}:
        return []
    if isinstance(scan.scan_data, dict):
        return scan.scan_data.get("results", []) or []
    return scan.scan_data if isinstance(scan.scan_data, list) else []


def _extract_standard(s: str) -> str:
    parts = (s or "").split(" - ")
    return (parts[0] or s or "").strip()


def _display_lang(meta: dict | None) -> str:
    if not meta:
        return "Unknown"
    app_lang = (meta.get("app_lang") or "unknown").lower()
    return LANG_DISPLAY.get(app_lang, app_lang.capitalize() if app_lang else "Unknown")


def generate_dashboard_data_for_scan_list(scans: list[Scan], scan_type: scan_types) -> dict:
    """
    Generate dashboard data for a list of SAST scans.
    Arguments :
    - scans : list[Scan]
    Returns :
    - dict
    """
    try:
        if scan_type == "sast":
            return generate_sast_dashboard_data(scans=scans)
        if scan_type == "iac":
            return generate_iac_dashboard_data(scans=scans)
    except Exception as e:
        console.print(f"Error in generating dashboard data for scan list: {e}", style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating dashboard data for scan list, please try again later")


def _iac_results(scan: Scan) -> list:
    """Get IAC results list from scan.scan_data (dict with 'results' key)."""
    if not scan.scan_data or not isinstance(scan.scan_data, dict):
        return []
    return scan.scan_data.get("results", []) or []


def generate_iac_dashboard_data(scans: list[Scan]) -> dict:
    """
    Should generate the following data : 

    1. card data : 
        - total scans 
        - total issues 
        - total critical issues 
        - Avg MTTR ( avg time to remediate )
        - coverage percentage
        - total number of policy violations 
        - Average risk score 

    2. Severity distribution ( pie chart ) : 
        {
            critical : 0,
            high : 2,
            medium : 5,
            low : 1,
        }
    
    3. Issues over time ( area - line chart ) : 
        {
            "2026-01-01" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
            "2026-01-02" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
            "2026-01-03" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
        }
    
    4. Security posture overview ( issues per category radar chart ) :
        {
            Network Security : 10,
            Data Protection : 20,
            Access Control : 30,
            Logging and Monitoring : 40,
            Secret Management : 50,
            Audit and Compliance : 60,
        }
    
    5. Compliance framework Coverage ( cards with percentages ) :
        note : get complaince framework from compliance controls values by splitting the value by " - " and taking the first part
        {
            "PCI DSS" : 80,
            "ISO 27001" : 70,
            "ISO 27002" : 60,
            "ISO 27003" : 50,
            "ISO 27004" : 40,
        }
    
    6. Remediation Pipeline ( horizontal progress bars ) : 
        {
            "total_issues" : 100,
            "fixed" : 20,
            "in_progress" : 30,
            "not_started" : 50,
            "ignored" : 0,
        }
    
    7. Mean time to remediate per day ( area - line chart ) :
        {
            "2026-01-01" : [ 10, 20, 30 ], # where [ days , hours , minutes ]
            "2026-01-02" : [ 10, 20, 30 ],
            "2026-01-03" : [ 10, 20, 30 ],
        }
    
    8. Resources by provider ( bar chart ) : 
        note : calculated using iac contexts "terraform","k8s","pulumi","ansible","helm","aws_cloudformation","aws_cdk
        
        {
            "aws_cloudformation" : 10,
            "aws_cdk" : 20,
            "ansible" : 30,
            "helm" : 40,
            "terraform" : 50,
            "pulumi" : 60,
            "k8s" : 70,
        }
    
    10. environment x cloud resource heatmap : 
        ( calculates number of resources by provider for each environment )
        {
            "production" : {
                "aws_cloudformation" : 10,
                "aws_cdk" : 20,
                "ansible" : 30,
                "helm" : 40,
                "terraform" : 50,
                "pulumi" : 60,
                "k8s" : 70,
            },
            "staging" : {
                "aws_cloudformation" : 10,
                "aws_cdk" : 20,
                "ansible" : 30,
                "helm" : 40,
                "terraform" : 50,
                "pulumi" : 60,
                "k8s" : 70,
            },
            "development" : {
                "aws_cloudformation" : 10,
                "aws_cdk" : 20,
                "ansible" : 30,
                "helm" : 40,
                "terraform" : 50,
                "pulumi" : 60,
                "k8s" : 70,
            },
        }
    

    """
    iac_scans = [s for s in scans if s.scan_type == "iac"]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    issues_over_time: dict[str, dict[str, int]] = {}
    category_counts: dict[str, int] = {}
    framework_violations: dict[str, int] = {}
    resources_by_provider: dict[str, int] = {}
    environment_counts: dict[str, int] = {}
    environment_cloud_resource_heatmap: dict[str, dict[str, int]] = {}
    all_heatmap_modes: set[str] = set()  # all IAC modes seen in any scan (for defaulting missing to 0)
    total_issues = 0
    total_policy_violations = 0
    coverage_pct_sum = 0.0
    coverage_pct_count = 0
    risk_score_weighted_sum = 0.0
    risk_score_count = 0

    all_findings: list = []
    for scan in iac_scans:
        all_findings.extend(get_findings_for_scan_id(scan_id=scan.id))

    for scan in iac_scans:
        if scan.scan_status != "success":
            continue
        results = _iac_results(scan)
        if not results:
            continue

        meta = scan.scan_metadata or {}
        date_key = str(scan.created_at.date()) if scan.created_at else ""

        temp = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in results:
            imp = (item.get("impact") or "medium").lower()
            if imp == "critical":
                temp["critical"] += 1
            elif imp == "high":
                temp["high"] += 1
            elif imp == "medium":
                temp["medium"] += 1
            elif imp == "low":
                temp["low"] += 1
        for k in ("critical", "high", "medium", "low"):
            severity_counts[k] += temp[k]

        total_issues += len(results)

        if date_key:
            if date_key not in issues_over_time:
                issues_over_time[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for k in ("critical", "high", "medium", "low"):
                issues_over_time[date_key][k] += temp[k]

        for item in results:
            cat = (item.get("category") or "Other").strip()
            if cat:
                category_counts[cat] = category_counts.get(cat, 0) + 1

        for item in results:
            cc = item.get("compliance_controls")
            if isinstance(cc, dict):
                for val in cc.values():
                    std = _extract_standard(str(val) if val is not None else "")
                    if std:
                        framework_violations[std] = framework_violations.get(std, 0) + 1
                        total_policy_violations += 1
            elif isinstance(cc, list):
                for c in cc:
                    s = c.get("value", c) if isinstance(c, dict) else c
                    std = _extract_standard(str(s) if s is not None else "")
                    if std:
                        framework_violations[std] = framework_violations.get(std, 0) + 1
                        total_policy_violations += 1

        if isinstance(scan.scan_data, dict):
            md = scan.scan_data.get("metadata") or {}
            inc = md.get("included_documents") or []
            exc = md.get("excluded_documents") or []
            inc = list(inc) if isinstance(inc, (list, tuple)) else []
            exc = list(exc) if isinstance(exc, (list, tuple)) else []
            total_docs = len(inc) + len(exc)
            if total_docs > 0:
                coverage_pct_sum += (len(inc) / total_docs) * 100
                coverage_pct_count += 1

        c, h, m, l = temp["critical"], temp["high"], temp["medium"], temp["low"]
        n = c + h + m + l
        if n > 0:
            weighted = (c * 4 + h * 3 + m * 2 + l * 1) / n
            score = min(10.0, max(0.0, (weighted / 4) * 10))
            risk_score_weighted_sum += score * n
            risk_score_count += n

        iac_contexts = meta.get("iac_contexts") or []
        for ctx in iac_contexts:
            if isinstance(ctx, dict):
                mode = (ctx.get("mode") or "terraform").lower()
            else:
                mode = getattr(ctx, "mode", "terraform")
            mode_display = mode.replace("_", " ").title()
            if mode == "k8s":
                mode_display = "Kubernetes"
            resources_by_provider[mode_display] = resources_by_provider.get(mode_display, 0) + 1
        if not iac_contexts and results:
            resources_by_provider["Terraform"] = resources_by_provider.get("Terraform", 0) + 1

        env = (meta.get("environment") or "development").lower()
        environment_counts[env] = environment_counts.get(env, 0) + 1

        # Environment x cloud resource heatmap: count (environment, mode) from iac_contexts
        iac_contexts_list = meta.get("iac_contexts") or []
        if not iac_contexts_list and results:
            iac_contexts_list = [{"mode": "terraform"}]
        if env not in environment_cloud_resource_heatmap:
            environment_cloud_resource_heatmap[env] = {}
        for ctx in iac_contexts_list:
            if isinstance(ctx, dict):
                mode = (ctx.get("mode") or "terraform").lower().strip()
            else:
                mode = (getattr(ctx, "mode", "terraform") or "terraform").lower().strip()
            if mode:
                all_heatmap_modes.add(mode)
                environment_cloud_resource_heatmap[env][mode] = environment_cloud_resource_heatmap[env].get(mode, 0) + 1

    # Default any missing (env, mode) to 0 so every environment has every seen mode
    for env in environment_cloud_resource_heatmap:
        for mode in all_heatmap_modes:
            environment_cloud_resource_heatmap[env].setdefault(mode, 0)

    remediation = get_remediation_metrics(all_findings) if all_findings else {}
    mttr = remediation.get("mean_time_to_remediate", [0, 0, 0])
    if isinstance(mttr, list) and len(mttr) >= 3:
        avg_mttr_days = mttr[0] + mttr[1] / 24 + mttr[2] / (24 * 60)
    else:
        avg_mttr_days = 0.0
    coverage_pct = round(coverage_pct_sum / coverage_pct_count, 1) if coverage_pct_count > 0 else 0.0
    average_risk_score = round(risk_score_weighted_sum / risk_score_count, 1) if risk_score_count > 0 else 0.0
    total_critical = severity_counts["critical"]

    card_data = {
        "total_scans": len([s for s in iac_scans if s.scan_status == "success"]),
        "total_issues": total_issues,
        "total_critical_issues": total_critical,
        "avg_mttr_days": round(avg_mttr_days, 2),
        "coverage_percentage": coverage_pct,
        "total_policy_violations": total_policy_violations,
        "average_risk_score": average_risk_score,
    }

    severity_distribution = {
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
    }

    issues_over_time = dict(sorted(issues_over_time.items()))

    # Security posture: always include all 6 IAC categories with default 0, then any extras from data
    SECURITY_POSTURE_CATEGORIES = [
        "Network Security",
        "Data Protection",
        "Access Control",
        "Logging and Monitoring",
        "Secret Management",
        "Audit and Compliance",
    ]
    security_posture_overview = {c: category_counts.get(c, 0) for c in SECURITY_POSTURE_CATEGORIES}
    for k, v in category_counts.items():
        if k not in security_posture_overview:
            security_posture_overview[k] = v
    security_posture_overview = dict(sorted(security_posture_overview.items(), key=lambda x: (-x[1], x[0])))

    total_findings_for_pct = total_issues if total_issues > 0 else 1
    compliance_framework_counts = dict(sorted(framework_violations.items(), key=lambda x: -x[1]))
    compliance_framework_coverage = {
        k: round((v / total_findings_for_pct) * 100, 1)
        for k, v in compliance_framework_counts.items()
    }

    status_metrics = get_issue_status_metrics(all_findings) if all_findings else {"fixed": 0, "ignored": 0, "in_progress": 0, "not_started": 0}
    remediation_pipeline = {
        "total_issues": total_issues,
        "fixed": status_metrics.get("fixed", 0),
        "in_progress": status_metrics.get("in_progress", 0),
        "not_started": status_metrics.get("not_started", 0),
        "ignored": status_metrics.get("ignored", 0),
    }

    mttr_per_day = get_mttr_per_day(all_findings) if all_findings else {}
    mttr_per_day = dict(sorted(mttr_per_day.items()))
    environment = dict(sorted(environment_counts.items(), key=lambda x: -x[1]))

    # Sort heatmap envs and modes for stable output
    environment_cloud_resource_heatmap = {
        env: dict(sorted(modes.items(), key=lambda x: -x[1]))
        for env, modes in sorted(environment_cloud_resource_heatmap.items())
    }

    return {
        "card_data": card_data,
        "severity_distribution": severity_distribution,
        "issues_over_time": issues_over_time,
        "security_posture_overview": security_posture_overview,
        "compliance_framework_coverage": compliance_framework_coverage,
        "compliance_framework_counts": compliance_framework_counts,
        "remediation_pipeline": remediation_pipeline,
        "mttr_per_day": mttr_per_day,
        "resources_by_provider": resources_by_provider,
        "environment": environment,
        "environment_cloud_resource_heatmap": environment_cloud_resource_heatmap,
        "remediation_metrics": remediation,
    }


def generate_sast_dashboard_data(scans: list[Scan]) -> dict:
    """
    """
    pending_scans , started_scans , success_scans , failure_scans , not_started_scans , scans_created_today , scans_updated_today = 0 , 0 , 0 , 0 , 0 , 0 , 0
    repos_scanned: list[str] = []
    zip_files_scanned: int = 0
    scans_per_day: dict = {}
    risks_per_day: dict = {}
    owasp_map: dict[str, int] = {}
    standards: dict[str, int] = {}
    by_language_map: dict[str, int] = {}
    top_repos_candidates: list[dict] = []

    for scan in scans:
        if scan.scan_status == "pending":
            pending_scans += 1
        elif scan.scan_status == "started":
            started_scans += 1
        elif scan.scan_status == "success":
            success_scans += 1
        elif scan.scan_status == "failure":
            failure_scans += 1
        elif scan.scan_status == "NOT_STARTED" or scan.scan_status == "not_started":
            not_started_scans += 1
        if scan.created_at and scan.created_at.date() == datetime.now(timezone.utc).date():
            scans_created_today += 1
        if scan.last_updated and scan.last_updated.date() == datetime.now(timezone.utc).date():
            scans_updated_today += 1

        meta = scan.scan_metadata or {}
        date_key = str(scan.created_at.date()) if scan.created_at else ""

        results = _sast_results(scan) if scan.scan_type == "sast" else []
        has_sast_results = scan.scan_type == "sast" and scan.scan_status == "success" and bool(results)

        if has_sast_results and meta.get("repo_url"):
            repos_scanned.append(meta["repo_url"])
        if has_sast_results and meta.get("zip_file_used"):
            zip_files_scanned += 1

        # risks per day (string keys) and per-scan risk for top_repos
        if scan.scan_type == "sast" and has_sast_results:
            temp = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for item in results:
                vulns = item.get("vulnerabilities") or []
                for v in vulns:
                    imp = (v.get("impact") or "").lower()
                    if imp == "critical":
                        temp["critical"] += 1
                    elif imp == "high":
                        temp["high"] += 1
                    elif imp == "medium":
                        temp["medium"] += 1
                    elif imp == "low":
                        temp["low"] += 1
            if date_key:
                if date_key not in risks_per_day:
                    risks_per_day[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for k in ("critical", "high", "medium", "low"):
                    risks_per_day[date_key][k] += temp[k]

            # OWASP by category
            for item in results:
                for v in item.get("vulnerabilities") or []:
                    owasp = v.get("owasp_top_10")
                    if isinstance(owasp, list):
                        for o in owasp:
                            k = o.get("value", o) if isinstance(o, dict) else o
                            k = str(k) if k is not None else ""
                            if k:
                                label = _short_label_owasp(k)
                                if label:
                                    owasp_map[label] = owasp_map.get(label, 0) + 1
                    elif isinstance(owasp, dict):
                        for val in owasp.values():
                            s = str(val) if val is not None else ""
                            if s:
                                label = _short_label_owasp(s)
                                if label:
                                    owasp_map[label] = owasp_map.get(label, 0) + 1

            # policy compliance
            for item in results:
                for v in item.get("vulnerabilities") or []:
                    cc = v.get("compliance_controls")
                    if isinstance(cc, list):
                        for c in cc:
                            s = c.get("value", c) if isinstance(c, dict) else c
                            s = str(s) if s is not None else ""
                            std = _extract_standard(s)
                            if std:
                                standards[std] = standards.get(std, 0) + 1
                    elif isinstance(cc, dict):
                        for val in cc.values():
                            s = str(val) if val is not None else ""
                            std = _extract_standard(s)
                            if std:
                                standards[std] = standards.get(std, 0) + 1

            # by_language: vuln count per scan per language
            display_lang = _display_lang(meta)
            total_vulns = sum(len(item.get("vulnerabilities") or []) for item in results)
            if total_vulns > 0:
                by_language_map[display_lang] = by_language_map.get(display_lang, 0) + total_vulns

            # top_repos_by_risk: per-scan risk score
            c, h, m, l = temp["critical"], temp["high"], temp["medium"], temp["low"]
            total_issues = c + h + m + l
            weighted = (c * 4 + h * 3 + m * 2 + l * 1) / total_issues if total_issues > 0 else 0
            score = min(10.0, max(0.0, (weighted / 4) * 10))
            risk_score = round(score * 10) / 10
            repo_url = meta.get("repo_url")
            repo_name = (repo_url.split("/")[-1] if repo_url else None) or scan.title or "Unknown"
            top_repos_candidates.append({
                "name": repo_name,
                "repo_url": repo_url,
                "zip_file_used": bool(meta.get("zip_file_used")),
                "issues": total_issues,
                "risk_score": risk_score,
                "trend": "—",
                "language": display_lang,
            })

        if (scan.scan_type == "sbom_sca" or scan.scan_type == "iac") and scan.scan_data and scan.scan_data != {} and isinstance(scan.scan_data, list) and scan.scan_status == "success":
            temp = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for item in scan.scan_data:
                imp = (item.get("impact") or "").lower()
                if imp == "critical":
                    temp["critical"] += 1
                elif imp == "high":
                    temp["high"] += 1
                elif imp == "medium":
                    temp["medium"] += 1
                elif imp == "low":
                    temp["low"] += 1
            if date_key:
                if date_key not in risks_per_day:
                    risks_per_day[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for k in ("critical", "high", "medium", "low"):
                    risks_per_day[date_key][k] += temp[k]

        # scans per day (string keys)
        if date_key:
            scans_per_day[date_key] = scans_per_day.get(date_key, 0) + 1

    # risk_totals
    critical_t = sum(d.get("critical", 0) for d in risks_per_day.values())
    high_t = sum(d.get("high", 0) for d in risks_per_day.values())
    medium_t = sum(d.get("medium", 0) for d in risks_per_day.values())
    low_t = sum(d.get("low", 0) for d in risks_per_day.values())
    risk_totals = [
        {"severity": "Critical", "count": critical_t},
        {"severity": "High", "count": high_t},
        {"severity": "Medium", "count": medium_t},
        {"severity": "Low", "count": low_t},
    ]

    total_issues = critical_t + high_t + medium_t + low_t
    weighted = (critical_t * 4 + high_t * 3 + medium_t * 2 + low_t * 1) / total_issues if total_issues > 0 else 0
    average_risk_score = round(min(10, max(0, (weighted / 4) * 10)) * 10) / 10

    # owasp_by_category top 8
    owasp_by_category = [
        {"category": k, "count": v}
        for k, v in sorted(owasp_map.items(), key=lambda x: -x[1])[:8]
    ]

    # policy_compliance top 8
    total_std = sum(standards.values())
    policy_compliance = [
        {
            "name": k,
            "violations": v,
            "compliance": round((v / total_std) * 1000) / 10 if total_std > 0 else 0,
        }
        for k, v in sorted(standards.items(), key=lambda x: -x[1])[:8]
    ]
    overall_compliance_score = 0
    if policy_compliance:
        overall_compliance_score = round((sum(p["compliance"] for p in policy_compliance) / len(policy_compliance)) * 10) / 10

    # by_language top 8
    by_language = [
        {"language": k, "count": v}
        for k, v in sorted(by_language_map.items(), key=lambda x: -x[1])[:8]
        if v > 0
    ]

    # top_repos_by_risk top 5
    top_repos_by_risk = sorted(top_repos_candidates, key=lambda x: -x["risk_score"])[:5]

    card_data = {
        "pending_scans": pending_scans,
        "started_scans": started_scans,
        "success_scans": success_scans,
        "failure_scans": failure_scans,
        "not_started_scans": not_started_scans,
        "scans_created_today": scans_created_today,
        "scans_updated_today": scans_updated_today
    }

    findings = []
    for scan in scans:
        findings.extend(get_findings_for_scan_id(scan_id=scan.id))
    remediation_metrics = get_remediation_metrics(findings=findings)

    return {
        "card_data": card_data,
        "repos_scanned": list(set(repos_scanned)),
        "zip_files_scanned": zip_files_scanned,
        "scans_per_day": scans_per_day,
        "risks_per_day": risks_per_day,
        "risk_totals": risk_totals,
        "average_risk_score": average_risk_score,
        "total_issues": total_issues,
        "critical_count": critical_t,
        "owasp_by_category": owasp_by_category,
        "policy_compliance": policy_compliance,
        "overall_compliance_score": overall_compliance_score,
        "by_language": by_language,
        "top_repos_by_risk": top_repos_by_risk,
        "remediation_metrics": remediation_metrics,
    }