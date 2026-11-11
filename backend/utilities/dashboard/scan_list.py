from typing import Any

from backend.new_models import Scan, scan_types
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from rich.console import Console
from fastapi import HTTPException , status
from backend.utilities.db.findings import get_findings_for_scan_id
from backend.utilities.dashboard.remediation_metrics import get_remediation_metrics
from backend.utilities.dashboard.finding_metrics import get_issue_status_metrics, get_mttr_per_day
from backend.utilities.dashboard.sbom_license import (
    LICENSE_CATEGORIES,
    resolve_sbom_license_category,
    resolve_sbom_reachability,
)

console = Console()


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetime to UTC-aware. Handles naive datetimes by assuming UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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


# DAST list dashboard: OWASP Top 10 2021, categories (5 for bar chart, 12 for radial), compliance, confidence
OWASP_DAST_KEYS = (
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery (SSRF)",
)
DAST_CATEGORIES_FIVE = (
    "injection",
    "xss_and_client_side",
    "authentication",
    "authorization",
    "session_and_state",
)
DAST_CATEGORIES_ALL = (
    "injection",
    "xss_and_client_side",
    "authentication",
    "authorization",
    "session_and_state",
    "file_and_resource",
    "server_side_execution",
    "information_disclosure",
    "crypto_and_transport",
    "security_headers_and_hardening",
    "api_security",
    "denial_of_service",
)
DAST_COMPLIANCE_STANDARDS = ("PCI DSS", "ISO 27001", "ISO 27002", "ISO 27003", "ISO 27004")
DAST_CONFIDENCE_KEYS = ("high", "medium", "low")
DAST_RISK_SCORE_FOR_IMPACT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}


def _display_lang(meta: dict | None) -> str:
    if not meta:
        return "Unknown"
    app_lang = (meta.get("app_lang") or "unknown").lower()
    return LANG_DISPLAY.get(app_lang, app_lang.capitalize() if app_lang else "Unknown")


def generate_dashboard_data_for_scan_list(scans: list[Scan], scan_type: scan_types, sources: Any = None) -> dict:
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
        elif scan_type == "iac":
            return generate_iac_dashboard_data(scans=scans)
        elif scan_type == "sbom_sca":
            return generate_sbom_sca_dashboard_data(scans=scans)
        elif scan_type == "mcp":
            return generate_mcp_dashboard_data(scans=scans)
        elif scan_type == "llm":
            return generate_llm_dashboard_data(scans=scans)
        elif scan_type == "dast":
            return generate_dast_dashboard_data(scans=scans)
        elif scan_type == "cbom":
            return generate_cbom_dashboard_data(scans=scans, sources=sources)
        elif scan_type == "ai_bom":
            return generate_ai_bom_dashboard_data(scans=scans)
    except Exception as e:
        console.print(f"Error in generating dashboard data for scan list: {e}", style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating dashboard data for scan list, please try again later")


def _iac_results(scan: Scan) -> list:
    """Get IAC results list from scan.scan_data (dict with 'results' key)."""
    if not scan.scan_data or not isinstance(scan.scan_data, dict):
        return []
    return scan.scan_data.get("results", []) or []


def _sbom_results(scan: Scan) -> list:
    """Get SBOM/SCA results list from scan.scan_data (dict with 'results' key)."""
    if not scan.scan_data or not isinstance(scan.scan_data, dict):
        return []
    return scan.scan_data.get("results", []) or []


def _mcp_cleaned_server_url(scan: Scan) -> str:
    """Return a short label for MCP scan (from scan_metadata.server_url)."""
    meta = scan.scan_metadata or {}
    url = meta.get("server_url") or ""
    if not url:
        return f"scan_{scan.id}"
    url = url.replace("https://", "").replace("http://", "").strip()
    parts = url.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return url[:30] if len(url) > 30 else url or f"scan_{scan.id}"


def _dast_owasp_values(cc) -> list:
    """Extract OWASP values from finding_data owasp_top_10 (dict or list)."""
    if isinstance(cc, dict):
        return list(cc.values()) if cc else []
    if isinstance(cc, list):
        return [x.get("value", x) if isinstance(x, dict) else x for x in cc]
    return []


def _dast_compliance_values(cc) -> list:
    """Extract compliance values from finding_data compliance_controls (dict or list)."""
    if isinstance(cc, dict):
        return list(cc.values()) if cc else []
    if isinstance(cc, list):
        return [x.get("value", x) if isinstance(x, dict) else x for x in cc]
    return []


def generate_dast_dashboard_data(scans: list[Scan]) -> dict:
    """
    Should generate the following data :
    1. Card data :
        - total scans
        - total critical issues
        - total high issues
        - total medium issues
        - total low issues
        - average risk score

    2. Severity distribution ( pie chart ) :
        { critical, high, medium, low } with counts

    3. Issues over time ( area - line chart ) : date -> { critical, high, medium, low }

    4. Security posture overview ( issues per category radial chart ) : 12 categories

    5. Owasp top 10 issues ( bar chart ) : all 10 keys, default 0

    6. Average Risk score per category ( bar chart ) : 5 categories

    7. Average Risk score per confidence ( pie chart ) : high, medium, low

    8. Compliance violations ( bar chart ) : PCI DSS, ISO 27001-27004
    """
    dast_scans = [s for s in scans if s.scan_type == "dast"]
    success_dast = [s for s in dast_scans if s.scan_status == "success"]
    all_findings: list = []
    for scan in dast_scans:
        all_findings.extend(get_findings_for_scan_id(scan_id=scan.id))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    issues_over_time: dict[str, dict[str, int]] = {}
    category_counts: dict[str, int] = defaultdict(int)
    owasp_counts: dict[str, int] = defaultdict(int)
    risk_sum_per_category: dict[str, float] = defaultdict(float)
    risk_count_per_category: dict[str, int] = defaultdict(int)
    risk_sum_per_confidence: dict[str, float] = defaultdict(float)
    risk_count_per_confidence: dict[str, int] = defaultdict(int)
    compliance_violations: dict[str, int] = defaultdict(int)
    risk_score_total = 0.0
    risk_score_n = 0

    # Per-scan: build issues_over_time by scan date
    for scan in dast_scans:
        if scan.scan_status != "success":
            continue
        scan_findings = get_findings_for_scan_id(scan.id)
        date_key = str(scan.created_at.date()) if scan.created_at else ""
        if not date_key:
            continue
        if date_key not in issues_over_time:
            issues_over_time[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in scan_findings:
            fd = finding.get("finding_data") or {}
            imp = (fd.get("impact") or "low").lower().strip()
            if imp not in issues_over_time[date_key]:
                imp = "low"
            issues_over_time[date_key][imp] = issues_over_time[date_key].get(imp, 0) + 1

    # Aggregate over all findings
    for finding in all_findings:
        fd = finding.get("finding_data") or {}
        imp = (fd.get("impact") or "low").lower().strip()
        if imp not in severity_counts:
            imp = "low"
        severity_counts[imp] = severity_counts.get(imp, 0) + 1
        score = DAST_RISK_SCORE_FOR_IMPACT.get(imp, 2.5)
        risk_score_total += score
        risk_score_n += 1

        for std_val in _dast_compliance_values(fd.get("compliance_controls")):
            std = _extract_standard(str(std_val) if std_val is not None else "")
            if std and std in DAST_COMPLIANCE_STANDARDS:
                compliance_violations[std] += 1

        for owasp_val in _dast_owasp_values(fd.get("owasp_top_10")):
            s = (owasp_val if isinstance(owasp_val, str) else str(owasp_val)).strip()
            if s in OWASP_DAST_KEYS:
                owasp_counts[s] += 1

        cat = (fd.get("category") or "").strip().lower().replace(" ", "_")
        if cat and cat in DAST_CATEGORIES_ALL:
            category_counts[cat] += 1
        if cat in DAST_CATEGORIES_FIVE:
            risk_sum_per_category[cat] += score
            risk_count_per_category[cat] += 1

        conf = (fd.get("confidence") or "low").lower().strip()
        if conf not in DAST_CONFIDENCE_KEYS:
            conf = "low"
        risk_sum_per_confidence[conf] += score
        risk_count_per_confidence[conf] += 1

    total_critical = severity_counts.get("critical", 0)
    total_high = severity_counts.get("high", 0)
    total_medium = severity_counts.get("medium", 0)
    total_low = severity_counts.get("low", 0)
    average_risk_score = round(risk_score_total / risk_score_n, 1) if risk_score_n > 0 else 0.0

    card_data = {
        "total_scans": len(success_dast),
        "total_critical_issues": total_critical,
        "total_high_issues": total_high,
        "total_medium_issues": total_medium,
        "total_low_issues": total_low,
        "average_risk_score": average_risk_score,
    }
    SEVERITY_KEYS = ("critical", "high", "medium", "low")
    severity_distribution = {k: severity_counts.get(k, 0) for k in SEVERITY_KEYS}
    issues_over_time = dict(sorted(issues_over_time.items()))
    security_posture_overview = {c: category_counts.get(c, 0) for c in DAST_CATEGORIES_ALL}
    owasp_top_10_issues = {k: owasp_counts.get(k, 0) for k in OWASP_DAST_KEYS}
    average_risk_score_per_category = {
        c: round(risk_sum_per_category[c] / risk_count_per_category[c], 1) if risk_count_per_category[c] > 0 else 0.0
        for c in DAST_CATEGORIES_FIVE
    }
    average_risk_score_per_confidence = {
        k: round(risk_sum_per_confidence[k] / risk_count_per_confidence[k], 1) if risk_count_per_confidence[k] > 0 else 0.0
        for k in DAST_CONFIDENCE_KEYS
    }
    compliance_violations_out = {std: compliance_violations.get(std, 0) for std in DAST_COMPLIANCE_STANDARDS}

    return {
        "card_data": card_data,
        "severity_distribution": severity_distribution,
        "issues_over_time": issues_over_time,
        "security_posture_overview": security_posture_overview,
        "owasp_top_10_issues": owasp_top_10_issues,
        "average_risk_score_per_category": average_risk_score_per_category,
        "average_risk_score_per_confidence": average_risk_score_per_confidence,
        "compliance_violations": compliance_violations_out,
    } 


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


def generate_sbom_sca_dashboard_data(scans: list[Scan]) -> dict:
    """
    1. Remediation Actions required ( card with progress bars and icons ) :
        {
            "total_findings" : total_findings,
            "total_fixed" : total_fixed,
            "total_in_progress" : total_in_progress,
            "total_not_started" : total_not_started,
            "total_ignored" : total_ignored,
        }
    2. severity distribution ( radar chart ) :
        {
            "critical" : total_critical_issues,
            "high" : total_high_issues,
            "medium" : total_medium_issues,
            "low" : total_low_issues,
        }
    3. Reachability Age ( how long a certail finding remained in not_reachable or potentially_reachable status ) ( Bar chart )
        {
            "not_reachable" : total_not_reachable_issues,
            "potentially_reachable" : total_potentially_reachable_issues,
            "reachable" : total_reachable_issues,
            "unknown" : total_unknown_issues,
        }
    4. Vulnerability Trends over time ( area - line chart ) : 
        {
            "2026-01-01" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
            "2026-01-02" : { "critical" : 15, "high" : 25, "medium" : 35, "low" : 45 },
            "2026-01-03" : { "critical" : 20, "high" : 30, "medium" : 40, "low" : 50 },
        }
    5. Licenses Distribution ( card with progress bars and icons ):
        {
            "permissive" : total_permissive_licenses,
            "public_domain" : total_public_domain_licenses,
            "weak_copyleft" : total_weak_copyleft_licenses,
            "creative_commons" : total_creative_commons_licenses,
            "commercial" : total_commercial_licenses,
        }
    6. Top Vulnerabilities by Risk Score ( Card with a list of components ):
        ( sorted by impact in descending order )
        [
            {
                "dependency" : dependency_name,
                "reachability" : reachability,
                "dependency_type" : dependency_type,
                "license_type" : license_type,
                "impact" : impact, 
            },
        ]
    7. Card Data : 
        - total vulnerabilities
        - total critical vulnerabilities
        - total policy violations
        - total license risks ( total high and medium risk licenses )
        - total high risk licenses 
        note : Risk level splitup for licenses : 
                Low risk ---> permissive , public_domain , not_declared
                Medium risk ---> weak_copyleft , creative_commons , commercial
                High risk ---> strong_copyleft , network_copyleft , source_available
        - average risk score ( based on weighted average of impact class of all vulnerabilities )
        - total reachable issues 
    
    8. Average risk score per reachability level : ( radar chart )
        note : calculate average risk score for each reachability level by weighted average of impact class of all vulnerabilities for that reachability level
        {
            "reachable" : average_risk_score_reachable,
            "potentially_reachable" : average_risk_score_potentially_reachable,
            "not_reachable" : average_risk_score_not_reachable,
            "not_assessed" : average_risk_score_not_assessed,
        }
    9. Policy Compliance Data : ( Card with a list of progress bars and icons )
        {
            "PCI DSS" : total_pci_dss_issues,
            "ISO 27001" : total_iso_27001_issues,
            "ISO 27002" : total_iso_27002_issues,
            "ISO 27003" : total_iso_27003_issues,
            "ISO 27004" : total_iso_27004_issues,
        }
    
    """
    sbom_scans = [s for s in scans if s.scan_type == "sbom_sca"]
    all_results: list[dict] = []
    all_findings: list = []
    for scan in sbom_scans:
        if scan.scan_status == "success":
            all_results.extend(_sbom_results(scan))
        all_findings.extend(get_findings_for_scan_id(scan.id))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    reachability_counts: dict[str, int] = defaultdict(int)
    vulnerability_trends_over_time: dict[str, dict[str, int]] = {}
    license_counts: dict[str, int] = defaultdict(int)
    policy_compliance_counts: dict[str, int] = defaultdict(int)
    total_policy_violations = 0
    risk_score_weighted_sum = 0.0
    risk_score_count = 0
    total_reachable = 0
    reachability_risk_sum: dict[str, float] = defaultdict(float)
    reachability_risk_count: dict[str, int] = defaultdict(int)
    impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    license_high_risk = {"strong_copyleft", "network_copyleft", "source_available"}
    license_medium_risk = {"weak_copyleft", "creative_commons", "commercial"}
    # All license categories for distribution (all shown with default 0)
    license_all_categories = list(LICENSE_CATEGORIES)

    for scan in sbom_scans:
        if scan.scan_status != "success":
            continue
        results = _sbom_results(scan)
        if not results:
            continue
        date_key = str(scan.created_at.date()) if scan.created_at else ""
        temp_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in results:
            imp = (item.get("impact") or "low").lower().strip()
            if imp == "critical":
                temp_sev["critical"] += 1
            elif imp == "high":
                temp_sev["high"] += 1
            elif imp == "medium":
                temp_sev["medium"] += 1
            elif imp == "low":
                temp_sev["low"] += 1
            severity_counts[imp] = severity_counts.get(imp, 0) + 1
            reach = resolve_sbom_reachability(item)
            reachability_counts[reach] += 1
            if reach == "reachable":
                total_reachable += 1
            lic = resolve_sbom_license_category(item)
            license_counts[lic] += 1
            cc = item.get("compliance_controls")
            if isinstance(cc, dict):
                total_policy_violations += len(cc)
                for val in cc.values():
                    std = _extract_standard(str(val) if val is not None else "")
                    if std:
                        policy_compliance_counts[std] += 1
            elif isinstance(cc, list):
                total_policy_violations += len(cc)
                for c in cc:
                    s = c.get("value", c) if isinstance(c, dict) else c
                    std = _extract_standard(str(s) if s is not None else "")
                    if std:
                        policy_compliance_counts[std] += 1
            w = impact_order.get(imp, 1)
            risk_score_weighted_sum += (w / 4) * 10
            risk_score_count += 1
            reachability_risk_sum[reach] += (w / 4) * 10
            reachability_risk_count[reach] += 1
        if date_key:
            if date_key not in vulnerability_trends_over_time:
                vulnerability_trends_over_time[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for k in ("critical", "high", "medium", "low"):
                vulnerability_trends_over_time[date_key][k] = vulnerability_trends_over_time[date_key].get(k, 0) + temp_sev[k]

    status_metrics = get_issue_status_metrics(all_findings) if all_findings else {"fixed": 0, "in_progress": 0, "not_started": 0, "ignored": 0}
    remediation_actions_required = {
        "total_findings": len(all_findings),
        "total_fixed": status_metrics.get("fixed", 0),
        "total_in_progress": status_metrics.get("in_progress", 0),
        "total_not_started": status_metrics.get("not_started", 0),
        "total_ignored": status_metrics.get("ignored", 0),
    }
    severity_distribution = {
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
    }
    other_reach = sum(
        v
        for k, v in reachability_counts.items()
        if k not in ("not_reachable", "potentially_reachable", "reachable", "not_assessed", "unknown")
    )
    reachability_distribution = {
        "not_reachable": reachability_counts.get("not_reachable", 0),
        "potentially_reachable": reachability_counts.get("potentially_reachable", 0),
        "reachable": reachability_counts.get("reachable", 0),
        "not_assessed": reachability_counts.get("not_assessed", 0)
        + reachability_counts.get("unknown", 0)
        + other_reach,
    }
    vulnerability_trends_over_time = dict(sorted(vulnerability_trends_over_time.items()))
    licenses_distribution = {k: license_counts.get(k, 0) for k in license_all_categories}

    top_vulnerabilities_by_risk_score = []
    for item in all_results:
        top_vulnerabilities_by_risk_score.append({
            "dependency": item.get("dependency") or item.get("title") or "—",
            "reachability": resolve_sbom_reachability(item),
            "dependency_type": item.get("dependency_type") or "—",
            "license_type": resolve_sbom_license_category(item),
            "impact": item.get("impact") or "low",
        })
    top_vulnerabilities_by_risk_score.sort(
        key=lambda x: (impact_order.get((x.get("impact") or "low").lower(), 0),),
        reverse=True,
    )

    total_high_license = sum(license_counts.get(k, 0) for k in license_high_risk)
    total_medium_license = sum(license_counts.get(k, 0) for k in license_medium_risk)
    total_license_risks = total_high_license + total_medium_license
    average_risk_score = round(risk_score_weighted_sum / risk_score_count, 1) if risk_score_count > 0 else 0.0
    card_data = {
        "total_vulnerabilities": len(all_results),
        "total_critical_vulnerabilities": severity_counts["critical"],
        "total_policy_violations": total_policy_violations,
        "total_license_risks": total_license_risks,
        "total_high_risk_licenses": total_high_license,
        "average_risk_score": average_risk_score,
        "total_reachable_issues": total_reachable,
    }
    average_risk_score_per_reachability_level = {}
    for r in ["reachable", "potentially_reachable", "not_reachable", "not_assessed"]:
        cnt = reachability_risk_count.get(r, 0)
        total = reachability_risk_sum.get(r, 0.0)
        if r == "not_assessed":
            cnt += reachability_risk_count.get("unknown", 0)
            total += reachability_risk_sum.get("unknown", 0.0)
        if cnt > 0:
            average_risk_score_per_reachability_level[r] = round(total / cnt, 1)
        else:
            average_risk_score_per_reachability_level[r] = 0.0

    policy_compliance_data = {
        "PCI DSS": policy_compliance_counts.get("PCI DSS", 0),
        "ISO 27001": policy_compliance_counts.get("ISO 27001", 0),
        "ISO 27002": policy_compliance_counts.get("ISO 27002", 0),
        "ISO 27003": policy_compliance_counts.get("ISO 27003", 0),
        "ISO 27004": policy_compliance_counts.get("ISO 27004", 0),
    }

    return {
        "remediation_actions_required": remediation_actions_required,
        "severity_distribution": severity_distribution,
        "reachability_distribution": reachability_distribution,
        "vulnerability_trends_over_time": vulnerability_trends_over_time,
        "licenses_distribution": licenses_distribution,
        "top_vulnerabilities_by_risk_score": top_vulnerabilities_by_risk_score,
        "card_data": card_data,
        "average_risk_score_per_reachability_level": average_risk_score_per_reachability_level,
        "policy_compliance_data": policy_compliance_data,
    }


def generate_mcp_dashboard_data(scans: list[Scan]) -> dict:
    """
    Need to calculate the following metrics : 
    1. Card Data :
        - total scans 
        - total critical issues 
        - average risk score ( based on weighted average of impact class of all vulnerabilities )
        - total active scans ( total count of "started" scan_status scans )
        - total resolved issues ( total count of "fixed" findings across all mcp scans in the past 7 days )
    
    2. Scan status distribution ( pie chart ) :
        {
            "not_started" : total_not_started_scans,
            "started" : total_started_scans,
            "success" : total_success_scans,
            "failure" : total_failure_scans,
        }
    
    3. Risk score trend ( average risk score per scan ) ( area - line chart )
        note : calculate average risk score for each scan by weighted average of impact class of all vulnerabilities for that scan
        {
            "server_url_cleaned_of_mcp_scan_1" : average_risk_score_per_scan,
            "server_url_cleaned_of_mcp_scan_2" : average_risk_score_per_scan,
            "server_url_cleaned_of_mcp_scan_3" : average_risk_score_per_scan,
        } 
    4. Risks over time ( area - line chart ) :
        {
            "2026-01-01" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
            "2026-01-02" : { "critical" : 15, "high" : 25, "medium" : 35, "low" : 45 },
            "2026-01-03" : { "critical" : 20, "high" : 30, "medium" : 40, "low" : 50 },
        }
    5. Severity distribution ( bar chart ) :
        {
            "critical" : total_critical_issues,
            "high" : total_high_issues,
            "medium" : total_medium_issues,
            "low" : total_low_issues,
        }
    6. Environment risk analysis ( bar chart ) :
        {
            "development" : total_development_issues,
            "production" : total_production_issues,
            "staging" : total_staging_issues,
        }
    7. Compliance framework distribution ( pie chart ) :
        {
            "PCI DSS" : total_pci_dss_issues,
            "ISO 27001" : total_iso_27001_issues,
            "ISO 27002" : total_iso_27002_issues,
            "ISO 27003" : total_iso_27003_issues,
            "ISO 27004" : total_iso_27004_issues,
        }
    8. Remediation status Tracking ( bar chart ) :
        {
            "not_started" : total_not_started_issues,
            "in_progress" : total_in_progress_issues,
            "fixed" : total_fixed_issues,
            "ignored" : total_ignored_issues,
        }
    9. Asset Category Vulnerabilities ( bar chart ) : 
        note : calculate this from the tool_category field of tools or prompt_category field of prompts or resource_category field of resources
        {
            "web" : total_web_issues,
            "file_system" : total_file_system_issues,
            "code_execution" : total_code_execution_issues,
            "database" : total_database_issues,
            "search" : total_search_issues,
            "vector_store" : total_vector_store_issues,
            "document_store" : total_document_store_issues,
        }
    10 . Scan duration trends ( bar chart ) :
        {
            "server_url_cleaned_of_mcp_scan_1" : scan_duration_per_scan,
            "server_url_cleaned_of_mcp_scan_2" : scan_duration_per_scan,
            "server_url_cleaned_of_mcp_scan_3" : scan_duration_per_scan,
        }
    11. Security Posture overview ( radar chart ) ( risk score per category ) ( show all categories and default to 0 if no data is available ) :
        {
            "web" : risk_score_web,
            "file_system" : risk_score_file_system,
            "code_execution" : risk_score_code_execution,
            "database" : risk_score_database,
            "search" : risk_score_search,
            "vector_store" : risk_score_vector_store,
            "document_store" : risk_score_document_store,
        }
    12. Mean time to remediate per day ( area - line chart ) :
        {
            "2026-01-01" : [ 10, 20, 30 ], # where [ days , hours , minutes ]
            "2026-01-02" : [ 10, 20, 30 ],
            "2026-01-03" : [ 10, 20, 30 ],
        }
    13. Scan effecttiveness trend ( bar chart with multiple bars ) : 
        note : calculate false positive count by finding count of "ignored" status findings across all mcp scan
        {
            "2026-01-01" : { "false_positive" : 10, "total_findings" : 100 },
            "2026-01-02" : { "false_positive" : 15, "total_findings" : 105 },
            "2026-01-03" : { "false_positive" : 20, "total_findings" : 110 },
        }
    14. Compliance Framework Score trend ( area - line chart ) :
        {
            "2026-01-01" : { "PCI DSS" : 80, "ISO 27001" : 85, "ISO 27002" : 90 },
            "2026-01-02" : { "PCI DSS" : 85, "ISO 27001" : 90, "ISO 27002" : 95 },
            "2026-01-03" : { "PCI DSS" : 90, "ISO 27001" : 95, "ISO 27002" : 100 },
        }
    15. Vulnerability age distribution ( bar chart ) :
        note : calculate this for the findings that have "fixed" or "ignored" status and use the "created_at" field + "fixed_at" / "ignored_at" field to calculate the age of the finding
        {
            "0-30 days" : total_0_30_days_issues,
            "30-60 days" : total_30_60_days_issues,
            "60-90 days" : total_60_90_days_issues,
            "90-120 days" : total_90_120_days_issues,
            "120-150 days" : total_120_150_days_issues,
            "150-180 days" : total_150_180_days_issues,
            "180-210 days" : total_180_210_days_issues,
        }
            
    """
    mcp_scans = [s for s in scans if s.scan_type == "mcp"]
    all_mcp_findings: list = []
    for scan in mcp_scans:
        all_mcp_findings.extend(get_findings_for_scan_id(scan.id))

    now_utc = datetime.now(timezone.utc)
    seven_days_ago = now_utc - timedelta(days=7)
    total_resolved_past_7_days = sum(
        1 for f in all_mcp_findings
        if f.get("finding_status") == "fixed" and f.get("fixed_at") and _ensure_utc(f["fixed_at"]) >= seven_days_ago
    )

    scan_status_distribution = {"not_started": 0, "started": 0, "success": 0, "failure": 0}
    risk_score_trend: dict[str, float] = {}
    risks_over_time: dict[str, dict[str, int]] = {}
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    environment_risk_analysis = {"development": 0, "production": 0, "staging": 0}
    compliance_framework_distribution: dict[str, int] = defaultdict(int)
    asset_category_vulnerabilities = {
        "web": 0, "file_system": 0, "code_execution": 0, "database": 0,
        "search": 0, "vector_store": 0, "document_store": 0,
    }
    scan_duration_trends: dict[str, float] = {}
    security_posture_overview = {
        "web": 0.0, "file_system": 0.0, "code_execution": 0.0, "database": 0.0,
        "search": 0.0, "vector_store": 0.0, "document_store": 0.0,
    }
    category_risk_sum: dict[str, float] = defaultdict(float)
    category_risk_count: dict[str, int] = defaultdict(int)
    compliance_by_date: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    scan_id_to_date: dict[int, str] = {}
    impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    total_critical = 0
    total_vulns = 0
    risk_score_weighted_sum = 0.0

    def _mcp_vulns(scan: Scan) -> list[tuple[dict, str]]:
        out: list[tuple[dict, str]] = []
        results = (scan.scan_data or {}).get("results") or {}
        for tool in results.get("tools") or []:
            cat = (tool.get("tool_category") or "web").lower().strip().replace(" ", "_")
            for v in tool.get("vulnerabilities") or []:
                out.append((v, cat))
        for prompt in results.get("prompts") or []:
            cat = (prompt.get("prompt_category") or "web").lower().strip().replace(" ", "_")
            for v in prompt.get("vulnerabilities") or []:
                out.append((v, cat))
        for resource in results.get("resources") or []:
            cat = (resource.get("resource_category") or "web").lower().strip().replace(" ", "_")
            for v in resource.get("vulnerabilities") or []:
                out.append((v, cat))
        return out

    for scan in mcp_scans:
        status = (scan.scan_status or "not_started").lower()
        if status == "started":
            scan_status_distribution["started"] += 1
        elif status == "success":
            scan_status_distribution["success"] += 1
        elif status == "failure":
            scan_status_distribution["failure"] += 1
        else:
            scan_status_distribution["not_started"] += 1

        vulns_with_cat = _mcp_vulns(scan)
        if not vulns_with_cat:
            continue
        date_key = str(scan.created_at.date()) if scan.created_at else ""
        server_label = _mcp_cleaned_server_url(scan)
        temp_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        scan_risk_sum = 0.0
        for v, cat in vulns_with_cat:
            imp = (v.get("impact") or "low").lower().strip()
            if imp == "critical":
                temp_sev["critical"] += 1
            elif imp == "high":
                temp_sev["high"] += 1
            elif imp == "medium":
                temp_sev["medium"] += 1
            elif imp == "low":
                temp_sev["low"] += 1
            severity_distribution[imp] = severity_distribution.get(imp, 0) + 1
            w = impact_order.get(imp, 1)
            scan_risk_sum += (w / 4) * 10
            risk_score_weighted_sum += (w / 4) * 10
            total_vulns += 1
            if imp == "critical":
                total_critical += 1
            env = (scan.scan_metadata or {}).get("environment") or "development"
            env = str(env).lower().strip()
            if env in environment_risk_analysis:
                environment_risk_analysis[env] += 1
            cc = v.get("compliance_controls")
            if isinstance(cc, dict):
                for _k, val in cc.items():
                    std = _extract_standard(str(val) if val is not None else "")
                    if std:
                        compliance_framework_distribution[std] += 1
                        if date_key:
                            compliance_by_date[date_key][std] += 1
            elif isinstance(cc, list):
                for c in cc:
                    s = c.get("value", c) if isinstance(c, dict) else c
                    std = _extract_standard(str(s) if s is not None else "")
                    if std:
                        compliance_framework_distribution[std] += 1
                        if date_key:
                            compliance_by_date[date_key][std] += 1
            if cat in asset_category_vulnerabilities:
                asset_category_vulnerabilities[cat] += 1
            category_risk_sum[cat] += (w / 4) * 10
            category_risk_count[cat] += 1
        if vulns_with_cat:
            risk_score_trend[server_label] = round(scan_risk_sum / len(vulns_with_cat), 1)
        if date_key:
            if date_key not in risks_over_time:
                risks_over_time[date_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for k in ("critical", "high", "medium", "low"):
                risks_over_time[date_key][k] = risks_over_time[date_key].get(k, 0) + temp_sev[k]
        dur = (scan.scan_data or {}).get("duration_of_scan")
        if dur is not None:
            scan_duration_trends[server_label] = float(dur)
        if date_key:
            scan_id_to_date[scan.id] = date_key

    for cat in security_posture_overview:
        cnt = category_risk_count.get(cat, 0)
        if cnt > 0:
            security_posture_overview[cat] = round(category_risk_sum[cat] / cnt, 1)

    average_risk_score = round(risk_score_weighted_sum / total_vulns, 1) if total_vulns > 0 else 0.0
    total_active_scans = scan_status_distribution["started"]
    card_data = {
        "total_scans": len(mcp_scans),
        "total_critical_issues": total_critical,
        "average_risk_score": average_risk_score,
        "total_active_scans": total_active_scans,
        "total_resolved_issues": total_resolved_past_7_days,
    }
    risks_over_time = dict(sorted(risks_over_time.items()))
    remediation_status_tracking = get_issue_status_metrics(all_mcp_findings) if all_mcp_findings else {"not_started": 0, "in_progress": 0, "fixed": 0, "ignored": 0}
    mttr_per_day = get_mttr_per_day(all_mcp_findings) if all_mcp_findings else {}
    mttr_per_day = dict(sorted(mttr_per_day.items()))

    compliance_framework_score_trend: dict[str, dict[str, float]] = {}
    for date_key in sorted(compliance_by_date.keys()):
        by_fw = compliance_by_date[date_key]
        total_fw = sum(by_fw.values())
        compliance_framework_score_trend[date_key] = {}
        for fw, count in by_fw.items():
            compliance_framework_score_trend[date_key][fw] = round(100 - (count / total_fw * 100), 1) if total_fw > 0 else 100.0

    scan_effectiveness_trend = defaultdict(lambda: {"false_positive": 0, "total_findings": 0})
    for f in all_mcp_findings:
        sid = f.get("scan_id")
        if sid is None:
            continue
        date_key = scan_id_to_date.get(sid)
        if not date_key:
            continue
        scan_effectiveness_trend[date_key]["total_findings"] += 1
        if f.get("finding_status") == "ignored":
            scan_effectiveness_trend[date_key]["false_positive"] += 1
    scan_effectiveness_trend = dict(sorted(scan_effectiveness_trend.items()))

    age_buckets = [
        "0-30 days", "30-60 days", "60-90 days", "90-120 days",
        "120-150 days", "150-180 days", "180-210 days",
    ]
    bucket_limits = [(0, 30), (30, 60), (60, 90), (90, 120), (120, 150), (150, 180), (180, 210)]
    vulnerability_age_distribution = {b: 0 for b in age_buckets}
    for f in all_mcp_findings:
        status = f.get("finding_status")
        if status not in ("fixed", "ignored"):
            continue
        resolved_at = _ensure_utc(f.get("fixed_at") or f.get("ignored_at"))
        created_at = _ensure_utc(f.get("created_at"))
        if not resolved_at or not created_at:
            continue
        delta = resolved_at - created_at
        days = delta.days
        for i, (lo, hi) in enumerate(bucket_limits):
            if lo <= days < hi:
                vulnerability_age_distribution[age_buckets[i]] += 1
                break

    return {
        "card_data": card_data,
        "scan_status_distribution": scan_status_distribution,
        "risk_score_trend": risk_score_trend,
        "risks_over_time": risks_over_time,
        "severity_distribution": severity_distribution,
        "environment_risk_analysis": environment_risk_analysis,
        "compliance_framework_distribution": dict(compliance_framework_distribution),
        "remediation_status_tracking": remediation_status_tracking,
        "asset_category_vulnerabilities": asset_category_vulnerabilities,
        "scan_duration_trends": scan_duration_trends,
        "security_posture_overview": security_posture_overview,
        "mttr_per_day": mttr_per_day,
        "scan_effectiveness_trend": scan_effectiveness_trend,
        "compliance_framework_score_trend": compliance_framework_score_trend,
        "vulnerability_age_distribution": vulnerability_age_distribution,
    }


def generate_llm_dashboard_data(scans: list[Scan]) -> dict:
    """
    Need to calculate the following metrics : 
    1. Card Data :
        - total scans 
        - average risk score ( based on weighted average of impact class of all vulnerabilities )
        - total critical vulnerabilities
        - total vulnerabilities 
        - owasp compliance score ( x out of 10 , calculate across all llm scans )
        - passed rate ( total passed tests across all llm scans , get this from the metadata field of the scan.scan_data .)
    
    2. Risk Level Distribution ( pie chart ) :
        {
            "critical" : total_critical_issues,
            "high" : total_high_issues,
            "medium" : total_medium_issues,
            "low" : total_low_issues,
        }
    3. Attack Vector Test Results ( no of tests passed and failed per probe , across all llm scans ) ( bar chart )
        note : get this from the metadata field of the scan.scan_data . that has the test results for each probe.
        {
            "probe_name_1" : { "passed" : total_passed_tests, "failed" : total_failed_tests },
            "probe_name_2" : { "passed" : total_passed_tests, "failed" : total_failed_tests },
            "probe_name_3" : { "passed" : total_passed_tests, "failed" : total_failed_tests },
        }
    4. Model Risk comparison ( area - line chart ) 
        note : calculate the average risk score for each model by weighted average of impact class of all vulnerabilities for that model
        {
            "model_name_1" : average_risk_score_model_1,
            "model_name_2" : average_risk_score_model_2,
            "model_name_3" : average_risk_score_model_3,
        }
    5. AI Security Posture overview ( radar chart ) 
        {
            "jailbreak resistance" : average_jailbreak_resistance_score_across_all_llm_scans,
            "injection resistance" : average_injection_resistance_score_across_all_llm_scans,
            "hallucination resistance" : average_hallucination_resistance_score_across_all_llm_scans,
            "bias resistance" : average_bias_resistance_score_across_all_llm_scans,
            "content safety" : average_content_safety_score_across_all_llm_scans,
            "data privacy" : average_data_privacy_score_across_all_llm_scans,
        }
    6. OWASP Top 10 LLM Metrics ( pie chart)
        note : default to 0 for each category if no data is available
        {
            "LLM01:2025 - Prompt Injection" : total_prompt_injection_issues,
            "LLM02:2025 - Insecure Output Handling" : total_insecure_output_handling_issues,
            "LLM03:2025 - Training Data Poisoning" : total_training_data_poisoning_issues,
            "LLM04:2025 - Model Denial of Service" : total_model_denial_of_service_issues,
            "LLM05:2025 - Supply Chain Vulnerabilities" : total_supply_chain_vulnerabilities_issues,
            "LLM06:2025 - Sensitive Information Disclosure" : total_sensitive_information_disclosure_issues,
            "LLM07:2025 - Insecure Plugin Design" : total_insecure_plugin_design_issues,
            "LLM08:2025 - Excessive Agency" : total_excessive_agency_issues,
            "LLM09:2025 - Overreliance" : total_overreliance_issues,
            "LLM10:2025 - Model Theft" : total_model_theft_issues,
        } 
    """
    llm_scans = [s for s in scans if s.scan_type == "llm"]
    pending_scans = started_scans = success_scans = failure_scans = not_started_scans = scans_created_today = scans_updated_today = 0
    scans_per_day: dict[str, int] = {}
    for scan in llm_scans:
        if scan.scan_status == "pending":
            pending_scans += 1
        elif scan.scan_status == "started":
            started_scans += 1
        elif scan.scan_status == "success":
            success_scans += 1
        elif scan.scan_status == "failure":
            failure_scans += 1
        elif scan.scan_status in ("NOT_STARTED", "not_started"):
            not_started_scans += 1
        if scan.created_at and scan.created_at.date() == datetime.now(timezone.utc).date():
            scans_created_today += 1
        if scan.last_updated and scan.last_updated.date() == datetime.now(timezone.utc).date():
            scans_updated_today += 1
        if scan.created_at:
            date_key = str(scan.created_at.date())
            scans_per_day[date_key] = scans_per_day.get(date_key, 0) + 1

    all_vulns: list[dict] = []
    risk_level_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    model_risk_comparison: dict[str, float] = defaultdict(float)
    model_risk_count: dict[str, int] = defaultdict(int)
    attack_vector_test_results: dict[str, dict[str, int]] = defaultdict(lambda: {"passed": 0, "failed": 0})
    posture_scores: dict[str, list[float]] = defaultdict(list)
    owasp_llm_counts: dict[str, int] = defaultdict(int)
    total_tests_sum = 0
    total_hits_sum = 0

    OWASP_LLM_KEYS = [
        "LLM01:2025 - Prompt Injection",
        "LLM02:2025 - Insecure Output Handling",
        "LLM03:2025 - Training Data Poisoning",
        "LLM04:2025 - Model Denial of Service",
        "LLM05:2025 - Supply Chain Vulnerabilities",
        "LLM06:2025 - Sensitive Information Disclosure",
        "LLM07:2025 - Insecure Plugin Design",
        "LLM08:2025 - Excessive Agency",
        "LLM09:2025 - Overreliance",
        "LLM10:2025 - Model Theft",
    ]
    POSTURE_KEY_MAP = {
        "jailbreak_resistance_score": "jailbreak resistance",
        "injection_resistance_score": "injection resistance",
        "hallucination_resistance_score": "hallucination resistance",
        "bias_resistance_score": "bias resistance",
        "content_safety_score": "content safety",
        "data_privacy_score": "data privacy",
    }

    for scan in llm_scans:
        if scan.scan_status != "success":
            continue
        data = scan.scan_data or {}
        results = data.get("results") or {}
        vulns = results.get("vulnerabilities") or []
        all_vulns.extend(vulns)
        meta = data.get("metadata") or {}
        scan_meta = scan.scan_metadata or {}
        model_name = scan_meta.get("model_name") or meta.get("model_name") or "unknown"

        for v in vulns:
            imp = (v.get("impact") or "low").lower().strip()
            if imp in risk_level_distribution:
                risk_level_distribution[imp] += 1
            owasp_llm = v.get("owasp_top_10_llm")
            if isinstance(owasp_llm, dict):
                for key in owasp_llm:
                    owasp_llm_counts[key] += 1
            elif isinstance(owasp_llm, list):
                for item in owasp_llm:
                    if isinstance(item, dict):
                        for key in item:
                            owasp_llm_counts[key] += 1
                    else:
                        owasp_llm_counts[str(item)] += 1

        if vulns:
            c = sum(1 for v in vulns if (v.get("impact") or "").lower() == "critical")
            h = sum(1 for v in vulns if (v.get("impact") or "").lower() == "high")
            m = sum(1 for v in vulns if (v.get("impact") or "").lower() == "medium")
            l = sum(1 for v in vulns if (v.get("impact") or "").lower() == "low")
            n = c + h + m + l
            if n > 0:
                w = (c * 4 + h * 3 + m * 2 + l * 1) / n
                score = (w / 4) * 10
                model_risk_comparison[model_name] += score * n
                model_risk_count[model_name] += n

        probes_summary = meta.get("probes_summary") or {}
        for _probe_key, probe_data in probes_summary.items():
            if not isinstance(probe_data, dict):
                continue
            probe_name = probe_data.get("probe") or _probe_key
            passed = probe_data.get("passed") or 0
            total = probe_data.get("total") or 0
            failed = total - passed
            attack_vector_test_results[probe_name]["passed"] += passed
            attack_vector_test_results[probe_name]["failed"] += failed

        total_tests = meta.get("total_tests") or 0
        total_hits = meta.get("total_hits") or 0
        total_tests_sum += total_tests
        total_hits_sum += total_hits

        model_vulns = results.get("model_vulnerabilities") or {}
        for key, label in POSTURE_KEY_MAP.items():
            val = model_vulns.get(key)
            if val is not None:
                try:
                    posture_scores[label].append(float(val))
                except (TypeError, ValueError):
                    pass

    total_critical = risk_level_distribution["critical"]
    total_vulns = len(all_vulns)
    risk_score_weighted_sum = 0.0
    risk_score_count = 0
    for v in all_vulns:
        imp = (v.get("impact") or "low").lower().strip()
        w = impact_order.get(imp, 1)
        risk_score_weighted_sum += (w / 4) * 10
        risk_score_count += 1
    average_risk_score = round(risk_score_weighted_sum / risk_score_count, 1) if risk_score_count > 0 else 0.0

    owasp_categories_with_issues = sum(1 for k in OWASP_LLM_KEYS if owasp_llm_counts.get(k, 0) > 0)
    owasp_compliance_score = round(10 - min(10, owasp_categories_with_issues), 1)
    if owasp_compliance_score < 0:
        owasp_compliance_score = 0.0

    passed_rate = 0.0
    if total_tests_sum > 0:
        passed_rate = round((total_tests_sum - total_hits_sum) / total_tests_sum * 100, 1)

    card_data = {
        "total_scans": success_scans,
        "average_risk_score": average_risk_score,
        "total_critical_vulnerabilities": total_critical,
        "total_vulnerabilities": total_vulns,
        "owasp_compliance_score": owasp_compliance_score,
        "passed_rate": passed_rate,
        "pending_scans": pending_scans,
        "started_scans": started_scans,
        "success_scans": success_scans,
        "failure_scans": failure_scans,
        "not_started_scans": not_started_scans,
        "scans_created_today": scans_created_today,
        "scans_updated_today": scans_updated_today,
    }

    for model_name in model_risk_count:
        n = model_risk_count[model_name]
        if n > 0:
            model_risk_comparison[model_name] = round(model_risk_comparison[model_name] / n, 1)
    model_risk_comparison = dict(model_risk_comparison)

    ai_security_posture_overview = {}
    for label in POSTURE_KEY_MAP.values():
        vals = posture_scores.get(label, [])
        if vals:
            ai_security_posture_overview[label] = round(sum(vals) / len(vals), 1)
        else:
            ai_security_posture_overview[label] = 0.0

    # Ensure all OWASP LLM categories are present as keys with default 0 (frontend needs this)
    owasp_top_10_llm_metrics = dict.fromkeys(OWASP_LLM_KEYS, 0)
    for k, v in owasp_llm_counts.items():
        owasp_top_10_llm_metrics[k] = v

    return {
        "card_data": card_data,
        "risk_level_distribution": risk_level_distribution,
        "attack_vector_test_results": dict(attack_vector_test_results),
        "model_risk_comparison": model_risk_comparison,
        "ai_security_posture_overview": ai_security_posture_overview,
        "owasp_top_10_llm_metrics": owasp_top_10_llm_metrics,
        "scans_per_day": scans_per_day,
    }


from backend.utilities.dashboard.aibom_license import (
    is_governance_license,
    is_unlicensed_library_gap,
    resolve_aibom_license,
)
from backend.utilities.dashboard.aibom_provider import resolve_aibom_provider
from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

CBOM_RISK_SCORE_FOR_IMPACT = {"critical": 9, "high": 7, "medium": 5, "low": 2}


def _cbom_results(scan: Scan) -> list:
    """Get CBOM results list from scan.scan_data."""
    if not scan.scan_data or not isinstance(scan.scan_data, dict):
        return []
    return scan.scan_data.get("results", []) or []


def generate_cbom_dashboard_data(scans: list[Scan], sources: Any = None) -> dict:
    """Aggregate CBOM dashboard data across all scans for the scan-list page (same rules as one scan: cbom_metrics).

    ``sources`` (``collections_view.SourcesResult``) adds each CBOM Sources source's latest completed collection: its
    rows are counted by the same rules, and an asset seen by both a code scan and a Sources collection is counted
    once, from the latest observation (``collections_view.resolve``)."""
    from backend.utilities.cbom_sources.cbom_metrics import CodeRowSummary
    from backend.utilities.cbom_sources.collections_view import (
        ORIGIN_CODE, REMEDIATION_BUCKET, SourcesResult, code_cert_identities, code_row_identity, resolve)

    sources = sources if isinstance(sources, SourcesResult) else SourcesResult()
    summary = CodeRowSummary()
    compliance_controls_metrics: dict[str, int] = defaultdict(int)

    cert_ids: dict[int, dict[str, str]] = {}
    code_observations = []
    for scan in scans:
        if scan.scan_status != "success":
            continue
        cert_ids[scan.id] = code_cert_identities(scan.scan_data)
        for row in _cbom_results(scan):
            ident = code_row_identity(row, cert_ids[scan.id])
            if ident:
                code_observations.append((scan.id, scan.created_at, ident))
    resolution = resolve(code_observations, sources.rows)

    for scan in scans:
        if scan.scan_status != "success":
            continue
        results = [row for row in _cbom_results(scan)
                   if resolution.code_kept(scan.id, code_row_identity(row, cert_ids.get(scan.id, {})))]
        if not results:
            continue
        summary.add_rows(results, origin={"kind": ORIGIN_CODE, "scan_id": scan.id, "scan_title": scan.title})

        # Framework FAIL counts from cbom_compliance (mirrors single-scan CBOM dashboard)
        _cbom_compliance = (
            scan.scan_data.get("cbom_compliance")
            if isinstance(scan.scan_data, dict)
            else None
        )
        if isinstance(_cbom_compliance, dict):
            for _fw_key, _fw in _cbom_compliance.items():
                if _fw_key == "disclaimer" or not isinstance(_fw, dict):
                    continue
                _fail = _fw.get("fail") or 0
                if _fail:
                    _label = _fw.get("title") or _fw_key
                    compliance_controls_metrics[_label] += int(_fail)

    summary.add_rows([item.row for item in resolution.sources_rows])
    for label, count in summary.compliance.items():
        compliance_controls_metrics[label] += count
    readiness = summary.readiness_pct

    # Aggregate remediation across all successful scans (finding rows only)
    total_fixed = 0
    total_in_progress = 0
    total_not_started = 0
    total_ignored = 0
    all_findings_count = 0
    for scan in scans:
        if scan.scan_status != "success":
            continue
        findings = get_findings_for_scan_id(scan_id=scan.id, scan_type="cbom")
        all_findings_count += len(findings)
        metrics = get_issue_status_metrics(findings)
        total_fixed += metrics.get("fixed", 0)
        total_in_progress += metrics.get("in_progress", 0)
        total_not_started += metrics.get("not_started", 0)
        total_ignored += metrics.get("ignored", 0)
    # Sources findings: their status is the remediation plan's (Sources pages, waves); open counts as not started.
    # A Sources finding on an asset a code scan also found is that code finding (counted once, with its status).
    sources_findings = 0
    for item in resolution.new_findings():
        sources_findings += 1
        bucket = REMEDIATION_BUCKET.get(str(item.row.get("remediation_status") or "open"), "not_started")
        total_fixed += bucket == "fixed"
        total_in_progress += bucket == "in_progress"
        total_not_started += bucket == "not_started"
        total_ignored += bucket == "ignored"
    all_findings_count += sources_findings

    return {
        "sources": {
            "collections": len(sources.collections),
            "assets": len(resolution.sources_rows),
            "deduplicated": len(sources.rows) - len(resolution.sources_rows) + len(resolution.dropped_code),
        },
        "card_data": {
            "total_crypto_assets": summary.crypto_assets,
            "total_crypto_vulnerabilities": summary.findings,
            "total_informational": summary.informational,
            "total_weak_algorithms": summary.weak,
            "total_quantum_vulnerable": summary.quantum["quantum_vulnerable"],
            "total_certificates": summary.certificates,
            "total_keys": summary.keys,
            "quantum_readiness_score": 0.0 if readiness is None else readiness,
            "quantum_readiness_judged": readiness is not None,
            "average_risk_score": summary.average_risk,
        },
        "severity_distribution": summary.severity_distribution(),
        "algorithm_type_distribution": dict(summary.algorithm_types),
        "strength_distribution": dict(summary.strengths),
        "quantum_readiness": dict(summary.quantum),
        "owasp_top_10_issues": dict(summary.owasp),
        "compliance_controls": dict(compliance_controls_metrics),
        "top_risks": summary.top(10),
        "remediation_actions_required": {
            "total_findings": all_findings_count,
            "total_fixed": total_fixed,
            "total_in_progress": total_in_progress,
            "total_not_started": total_not_started,
            "total_ignored": total_ignored,
        },
    }


AI_BOM_RISK_SCORE_FOR_IMPACT = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}
AI_BOM_MODEL_COMPONENT_TYPES = {"local_model_file", "huggingface_model", "embedding_model"}


def _ai_bom_results(scan: Scan) -> list:
    """Get AI-BOM results list from scan.scan_data."""
    if not scan.scan_data or not isinstance(scan.scan_data, dict):
        return []
    return scan.scan_data.get("results", []) or []


def generate_ai_bom_dashboard_data(scans: list[Scan]) -> dict:
    """Aggregate AI-BOM dashboard data across all scans for the scan-list page."""
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    asset_type_distribution: dict[str, int] = defaultdict(int)
    provider_distribution: dict[str, int] = defaultdict(int)
    license_distribution: dict[str, int] = defaultdict(int)
    risk_category_distribution: dict[str, int] = defaultdict(int)
    owasp_top_10_llm_issues: dict[str, int] = defaultdict(int)
    compliance_controls: dict[str, int] = defaultdict(int)
    top_risks_entries: list[dict] = []

    total_ai_assets = 0
    # Distinct entity sets (count UNIQUE entities, not detection rows).
    # e.g. an OpenAI SDK imported in 4 files is ONE external provider, not 4.
    # Sets span ALL scans so the aggregate dashboard de-dupes across scans too.
    distinct_external_providers: set = set()
    distinct_models: set = set()
    distinct_datasets: set = set()
    total_high_risk_assets = 0
    total_unlicensed_assets = 0
    assets_with_license_and_card = 0

    for scan in scans:
        if scan.scan_status != "success":
            continue
        results = _ai_bom_results(scan)
        if not results:
            continue

        total_ai_assets += len(results)

        for asset in results:
            impact = asset.get("impact", "Low")
            impact_lower = (impact or "low").lower()
            if impact_lower in severity_distribution:
                severity_distribution[impact_lower] += 1

            component_type = (asset.get("component_type") or "unknown").lower()
            asset_type_distribution[component_type] += 1

            provider = resolve_aibom_provider(asset)
            provider_distribution[provider] += 1

            license_type = resolve_aibom_license(asset)
            license_distribution[license_type] += 1

            risk_category = asset.get("risk_category") or "unknown"
            risk_category_distribution[risk_category] += 1

            # Distinct entity counts.
            # asset_name comes from the worker field 'component_name'; provider
            # from 'source' (ModelProvider value, e.g. openai/anthropic).
            asset_name = asset.get("component_name") or asset.get("title") or "Unknown"
            if component_type in AI_BOM_MODEL_COMPONENT_TYPES:
                # distinct model by (provider, asset_name)
                distinct_models.add((provider, asset_name))
            if component_type == "external_provider":
                # distinct provider among external_provider findings
                distinct_external_providers.add(provider)
            if component_type == "dataset":
                # distinct dataset by asset_name
                distinct_datasets.add(asset_name)

            # high-risk assets (Critical / High impact)
            if impact_lower in ("critical", "high"):
                total_high_risk_assets += 1

            # unlicensed assets = libraries still lacking a usable SPDX license
            if (
                component_type not in AI_BOM_MODEL_COMPONENT_TYPES
                and component_type != "external_provider"
                and is_unlicensed_library_gap(license_type)
            ):
                total_unlicensed_assets += 1

            # governance readiness: assets with both declared license and model card
            has_license = is_governance_license(license_type)
            has_card = bool(asset.get("model_card") or asset.get("card"))
            if has_license and has_card:
                assets_with_license_and_card += 1

            # owasp top 10 llm — aggregate by short LLM0x code (key)
            owasp_llm = asset.get("owasp_top_10_llm") or {}
            if isinstance(owasp_llm, dict):
                for key in owasp_llm:
                    owasp_top_10_llm_issues[str(key)] += 1
            elif isinstance(owasp_llm, list):
                for value in owasp_llm:
                    owasp_top_10_llm_issues[str(value)] += 1

            # compliance controls
            cc = asset.get("compliance_controls") or {}
            if isinstance(cc, dict):
                for _k, value in cc.items():
                    compliance_controls[value] += 1
            elif isinstance(cc, list):
                for value in cc:
                    compliance_controls[str(value)] += 1

            top_risks_entries.append({
                "asset_name": asset.get("component_name", asset.get("title", "Unknown")),
                "asset_type": component_type,
                "provider": provider,
                "license_type": license_type,
                "impact": impact,
            })

        # Framework FAIL counts from ai_bom_compliance (mirrors single-scan dashboard)
        _ai_bom_compliance = (
            scan.scan_data.get("ai_bom_compliance")
            if isinstance(scan.scan_data, dict)
            else None
        )
        if isinstance(_ai_bom_compliance, dict):
            for _fw_key, _fw in _ai_bom_compliance.items():
                if _fw_key == "disclaimer" or not isinstance(_fw, dict):
                    continue
                _fail = _fw.get("fail") or 0
                if _fail:
                    _label = _fw.get("title") or _fw_key
                    compliance_controls[_label] += int(_fail)

    impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # Materialize distinct entity counts.
    total_models = len(distinct_models)
    total_datasets = len(distinct_datasets)
    total_external_providers = len(distinct_external_providers)

    # governance readiness score
    governance_readiness_score = 0.0
    if total_ai_assets > 0:
        governance_readiness_score = round((assets_with_license_and_card / total_ai_assets) * 100, 1)

    # Average risk score (normalized 0-10 scale, same as cbom)
    total_findings = sum(severity_distribution.values())
    if total_findings > 0:
        weighted = (severity_distribution["critical"] * 4 + severity_distribution["high"] * 3 + severity_distribution["medium"] * 2 + severity_distribution["low"] * 1) / total_findings
        average_risk_score = min(10.0, max(0.0, (weighted / 4) * 10))
    else:
        average_risk_score = 0.0

    top_risks_list = sorted(
        top_risks_entries,
        key=lambda x: impact_order.get((x.get("impact") or "low").lower(), 0),
        reverse=True,
    )[:10]

    # Aggregate remediation across all successful scans
    all_findings: list = []
    total_fixed = 0
    total_in_progress = 0
    total_not_started = 0
    total_ignored = 0
    all_findings_count = 0
    for scan in scans:
        if scan.scan_status != "success":
            continue
        findings = get_findings_for_scan_id(scan_id=scan.id)
        all_findings.extend(findings)
        all_findings_count += len(findings)
        metrics = get_issue_status_metrics(findings)
        total_fixed += metrics.get("fixed", 0)
        total_in_progress += metrics.get("in_progress", 0)
        total_not_started += metrics.get("not_started", 0)
        total_ignored += metrics.get("ignored", 0)

    remediation_metrics = get_remediation_metrics(all_findings) if all_findings else {}

    return {
        "card_data": {
            "total_ai_assets": total_ai_assets,
            "total_models": total_models,
            "total_datasets": total_datasets,
            "total_external_providers": total_external_providers,
            "total_high_risk_assets": total_high_risk_assets,
            "total_unlicensed_assets": total_unlicensed_assets,
            "governance_readiness_score": governance_readiness_score,
            "average_risk_score": round(average_risk_score * 10) / 10,
        },
        "remediation_metrics": remediation_metrics,
        "remediation_actions_required": {
            "total_findings": all_findings_count,
            "total_fixed": total_fixed,
            "total_in_progress": total_in_progress,
            "total_not_started": total_not_started,
            "total_ignored": total_ignored,
        },
        "severity_distribution": severity_distribution,
        "asset_type_distribution": dict(asset_type_distribution),
        "provider_distribution": dict(provider_distribution),
        "license_distribution": dict(license_distribution),
        "risk_category_distribution": dict(risk_category_distribution),
        "owasp_top_10_llm_issues": dict(owasp_top_10_llm_issues),
        "compliance_controls": dict(compliance_controls),
        "top_risks": top_risks_list,
    }