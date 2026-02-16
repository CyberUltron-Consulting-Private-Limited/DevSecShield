# Dashboard data specs

This document describes the **dashboard data** produced by `backend/utilities/dashboard/scan.py` via `generate_scan_dashboard()` for SAST and IAC scans.

---

## SAST scan dashboard data

**Input:** Scan results are taken from `scan.scan_data["results"]` or from the `scan_results` argument. Each item in `results` is an object that has a `vulnerabilities` array. Each vulnerability has: `owasp_top_10`, `compliance_controls`, `impact`, `cves`, `title`.

**Output:** A single dictionary with the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `owasp_top_10_metrics` | `dict[str, int]` | Count per OWASP Top 10 category (values from `vulnerability["owasp_top_10"]`). |
| `compliance_controls_metrics` | `dict[str, int]` | Count per compliance control (values from `vulnerability["compliance_controls"]`). |
| `risk_metrics` | `dict[str, int]` | Count per impact: `"Low"`, `"Medium"`, `"High"`, `"Critical"`. |
| `cves_per_vulnerability` | `dict[str, int]` | Count per CVE ID (values from `vulnerability["cves"]`). |
| `remediation_metrics` | `dict` | From `get_remediation_metrics(findings)`: `mean_time_to_remediate`, `critical_issues_fixed`, `remediation_velocity`. |
| `policy_violations` | `dict[str, int]` | Count per compliance standard (prefix before `" - "` in each compliance control value). |
| `risk_scores_per_finding` | `dict[str, float]` | Risk score per finding title (Critical=10, High=7.5, Medium=5, Low=2.5). |

---

## IAC scan dashboard data

**Input:** Scan results are taken from `scan.scan_data["results"]` or from the `scan_results` argument. For IAC, `results` is a **flat list of vulnerabilities**. Each vulnerability has: `owasp_top_10`, `compliance_controls`, `impact`, `cves`, `category`.

**Output:** A single dictionary with the following keys:

| Key | Type | Description |
|-----|------|-------------|
| `owasp_top_10_metrics` | `dict[str, int]` | Count per OWASP Top 10 **key** (keys from `vulnerability["owasp_top_10"]`). |
| `compliance_controls_metrics` | `dict[str, int]` | Count per compliance control **key** (keys from `vulnerability["compliance_controls"]`). |
| `risk_metrics` | `dict[str, int]` | Count per impact: `"Low"`, `"Medium"`, `"High"`, `"Critical"`. |
| `cves_per_vulnerability` | `dict[str, int]` | Count per CVE **key** (keys from `vulnerability["cves"]`). |
| `issue_status_metrics` | `dict[str, int]` | From `get_issue_status_metrics(findings)`: counts for `"fixed"`, `"ignored"`, `"in_progress"`, `"not_started"`. |
| `issue_address_metrics` | `dict[str, list[int]]` | From `get_issue_address_metrics(findings)`: per finding title, `[days, hours, minutes]` (time-to-address). |
| `issues_by_category` | `dict[str, int]` | Count of issues per `vulnerability["category"]`. |
| `issues_by_severity` | `dict[str, int]` | Count per impact (same as risk_metrics for IAC). |
| `average_risk_score_per_category` | `dict[str, float]` | Mean risk score per category (Critical=10, High=7.5, Medium=5, Low=2.5). |

---

## Notes

- **SAST** iterates over `item["vulnerabilities"]` for each `item` in `results`; **IAC** iterates over `results` as a direct list of vulnerabilities.
- **SAST** uses OWASP/compliance **values** for metrics; **IAC** uses **keys** for `owasp_top_10_metrics` and `compliance_controls_metrics`.
- **Remediation** metrics are only in the SAST dashboard; **issue status** and **issue address** metrics are only in the IAC dashboard.
- **IAC** adds category-based metrics: `issues_by_category` and `average_risk_score_per_category`; **SAST** adds `risk_scores_per_finding` and `policy_violations`.
