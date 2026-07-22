"""Normalize analyzer JSON reports into DevSecShield finding dicts.

User-facing payloads never mention the underlying analyzer product name.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from helpers.tools.mobile_agent.sanitize import (
    normalize_mstg_reference,
    sanitize_finding_fields,
)

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "warning": "Medium",
    "medium": "Medium",
    "info": "Low",
    "low": "Low",
    "good": "Low",
    "secure": "Low",
    "hotspot": "Medium",
}

# MobSF section keys that are metadata, not vulnerability rules.
_SKIP_RULE_KEYS = frozenset(
    {
        "summary",
        "manifest_summary",
        "manifest_findings",
        "findings",
        "statistics",
        "metadata",
    }
)

# Binary hardening checks we skip when marked benign.
_BENIGN_SEVERITIES = frozenset({"info", "secure", "good", "low", ""})

_OWASP_MOBILE_LABELS = {
    "m1": "M1 - Improper Platform Usage",
    "m2": "M2 - Insecure Data Storage",
    "m3": "M3 - Insecure Communication",
    "m4": "M4 - Insecure Authentication",
    "m5": "M5 - Insufficient Cryptography",
    "m6": "M6 - Insecure Authorization",
    "m7": "M7 - Client Code Quality",
    "m8": "M8 - Code Tampering",
    "m9": "M9 - Reverse Engineering",
    "m10": "M10 - Extraneous Functionality",
}


def _impact(raw: Any) -> str:
    if raw is None:
        return "Medium"
    key = str(raw).strip().lower()
    return _SEVERITY_MAP.get(key, "Medium")


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _clean_description(title: str, description: str) -> str:
    desc = (description or "").strip()
    title = (title or "").strip()
    if not desc or desc == title:
        return ""
    return desc


def _compliance_from_metadata(meta: Any) -> tuple[dict[str, str], dict[str, str]]:
    """Map MobSF rule metadata to DevSecShield compliance / OWASP fields."""
    data = _as_dict(meta)
    compliance: dict[str, str] = {}
    owasp: dict[str, str] = {}

    masvs = data.get("masvs")
    if masvs:
        compliance[f"MASVS_{masvs}"] = f"MASVS - {masvs}"

    cwe = data.get("cwe")
    if cwe:
        cwe_str = str(cwe).strip()
        key = cwe_str.upper().replace(" ", "_")
        compliance[key] = cwe_str if cwe_str.upper().startswith("CWE") else f"CWE - {cwe_str}"

    cvss = data.get("cvss")
    if cvss is not None and str(cvss).strip() != "":
        compliance["CVSS"] = f"CVSS {cvss}"

    ref = data.get("ref")
    if ref:
        url = normalize_mstg_reference(str(ref))
        compliance["OWASP_MSTG"] = url

    owasp_mobile = data.get("owasp-mobile") or data.get("owasp_mobile")
    if owasp_mobile and str(owasp_mobile).strip():
        om = str(owasp_mobile).strip().lower()
        owasp[om.upper()] = _OWASP_MOBILE_LABELS.get(om, f"OWASP Mobile - {om.upper()}")

    return compliance, owasp


def _finding(
    title: str,
    description: str,
    impact: str,
    suggested_fix: str = "",
    category: str = "general",
    rule_id: str | None = None,
    file_path: str | None = None,
    owasp_top_10: dict[str, str] | None = None,
    compliance_controls: dict[str, str] | None = None,
) -> dict[str, Any]:
    title = title[:500]
    finding = {
        "title": title,
        "description": _clean_description(title, description),
        "impact": impact,
        "owasp_top_10": owasp_top_10 or {},
        "compliance_controls": compliance_controls or {},
        "suggested_fix": (suggested_fix or "").strip(),
        "category": category,
        "rule_id": rule_id,
        "file_path": file_path or "",
        "location": file_path or "",
    }
    return sanitize_finding_fields(finding)


def _from_code_findings(section: Any, category: str) -> list[dict[str, Any]]:
    """Handle { findings: { rule_id: {metadata, files, ...} } } sections."""
    out: list[dict[str, Any]] = []
    data = _as_dict(section)
    findings = data.get("findings")
    if not isinstance(findings, dict):
        return out

    for rule_id, item in findings.items():
        if rule_id in _SKIP_RULE_KEYS:
            continue
        item = _as_dict(item)
        meta = _as_dict(item.get("metadata"))
        title = meta.get("description") or meta.get("title") or item.get("title") or str(rule_id)
        desc = meta.get("description") or item.get("description") or title
        severity = meta.get("severity") or item.get("severity") or item.get("level") or "warning"
        files = item.get("files") or item.get("file") or []
        file_path = None
        if isinstance(files, dict):
            file_path = next(iter(files.keys()), None)
        elif isinstance(files, list) and files:
            first = files[0]
            file_path = first if isinstance(first, str) else _as_dict(first).get("file_path")
        elif isinstance(files, str):
            file_path = files
        compliance, owasp = _compliance_from_metadata(meta)
        out.append(
            _finding(
                title=str(title),
                description=str(desc),
                impact=_impact(severity),
                suggested_fix=str(meta.get("remediation") or item.get("remediation") or ""),
                category=category,
                rule_id=str(rule_id),
                file_path=str(file_path) if file_path else None,
                owasp_top_10=owasp,
                compliance_controls=compliance,
            )
        )
    return out


def _from_manifest(manifest: Any) -> list[dict[str, Any]]:
    """MobSF manifest_analysis: { manifest_findings: [...], manifest_summary: {...} }."""
    out: list[dict[str, Any]] = []
    data = _as_dict(manifest)
    items = data.get("manifest_findings")
    if not isinstance(items, list):
        return out

    for item in items:
        item = _as_dict(item)
        title = item.get("title") or item.get("rule") or "Manifest issue"
        desc = item.get("description") or title
        out.append(
            _finding(
                title=str(title),
                description=str(desc),
                impact=_impact(item.get("severity")),
                suggested_fix=str(item.get("remediation") or ""),
                category="manifest",
                rule_id=str(item.get("rule") or "") or None,
            )
        )
    return out


def _from_binary_list(binaries: Any) -> list[dict[str, Any]]:
    """MobSF binary_analysis is a list of native libs with hardening checks (nx, pie, ...)."""
    if not isinstance(binaries, list):
        return out if (out := []) else []

    out: list[dict[str, Any]] = []
    for binary in binaries:
        binary = _as_dict(binary)
        lib_path = str(binary.get("name") or "native library")
        lib_name = Path(lib_path).name

        for check_name, check in binary.items():
            if check_name == "name" or not isinstance(check, dict):
                continue
            severity = str(check.get("severity") or "").lower()
            if severity in _BENIGN_SEVERITIES:
                continue
            desc = str(check.get("description") or "").strip()
            if not desc:
                continue
            label = check_name.replace("_", " ").title()
            out.append(
                _finding(
                    title=f"{label} - {lib_name}",
                    description=desc,
                    impact=_impact(severity),
                    category="binary",
                    rule_id=f"{lib_name}:{check_name}",
                    file_path=lib_path,
                )
            )
    return out


def _from_permissions(permissions: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    perms = _as_dict(permissions)
    for name, info in perms.items():
        info = _as_dict(info) if not isinstance(info, str) else {"description": info}
        status = str(info.get("status") or info.get("level") or "").lower()
        if status in ("normal", "unknown", ""):
            if status == "normal":
                continue
        impact = "High" if status in ("dangerous", "high", "critical") else "Medium"
        if status in ("dangerous", "high", "critical", "warning", "signature"):
            out.append(
                _finding(
                    title=f"Permission: {name}",
                    description=str(info.get("description") or f"App requests permission {name}"),
                    impact=impact if status != "signature" else "Low",
                    suggested_fix="Confirm this permission is required; remove if unused and document justification.",
                    category="permissions",
                    rule_id=str(name),
                )
            )
    return out


def _from_certificate(cert: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _as_dict(cert)
    findings = data.get("certificate_findings") or data.get("findings") or []
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                severity, title = item[0], item[1]
                desc = item[2] if len(item) > 2 else title
                out.append(
                    _finding(
                        title=str(title),
                        description=str(desc),
                        impact=_impact(severity),
                        category="certificate",
                    )
                )
            elif isinstance(item, dict):
                out.append(
                    _finding(
                        title=str(item.get("title") or "Certificate issue"),
                        description=str(item.get("description") or ""),
                        impact=_impact(item.get("severity")),
                        category="certificate",
                    )
                )
    return out


def _from_network_security(ns: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _as_dict(ns)
    for key in ("network_findings", "findings", "cleartext"):
        section = data.get(key)
        if isinstance(section, list):
            for item in section:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    out.append(
                        _finding(
                            title=str(item[1]),
                            description=str(item[2] if len(item) > 2 else item[1]),
                            impact=_impact(item[0]),
                            category="network_security",
                        )
                    )
                elif isinstance(item, dict):
                    out.append(
                        _finding(
                            title=str(item.get("title") or "Network security issue"),
                            description=str(item.get("description") or ""),
                            impact=_impact(item.get("severity")),
                            category="network_security",
                        )
                    )
    nested = data.get("findings")
    if isinstance(nested, dict):
        out.extend(_from_code_findings({"findings": nested}, "network_security"))
    return out


def _from_urls(urls: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(urls, list):
        return out
    for item in urls:
        item = _as_dict(item)
        path = str(item.get("path") or item.get("file") or "")
        for url in item.get("urls") or []:
            out.append(
                _finding(
                    title=f"URL in source: {url}",
                    description=f"Hardcoded or referenced URL found in application source.",
                    impact="Low",
                    category="network",
                    file_path=path or None,
                )
            )
    return out


def _from_emails(emails: Any) -> list[dict[str, Any]]:
    """MobSF extracts email strings from decompiled source — lightweight PII signal."""
    out: list[dict[str, Any]] = []
    if not isinstance(emails, list):
        return out
    for email in emails[:100]:
        if isinstance(email, str) and email.strip():
            out.append(
                _finding(
                    title=f"Email address found: {email}",
                    description="Email string extracted from app resources or source code. Review for unintended PII exposure.",
                    impact="Medium",
                    suggested_fix="Remove hardcoded emails from production builds or ensure they are not sensitive.",
                    category="pii",
                    rule_id=email,
                )
            )
        elif isinstance(email, dict):
            addr = email.get("email") or email.get("value") or email.get("address")
            path = email.get("path") or email.get("file")
            if addr:
                out.append(
                    _finding(
                        title=f"Email address found: {addr}",
                        description="Email string extracted from app resources or source code.",
                        impact="Medium",
                        category="pii",
                        file_path=str(path) if path else None,
                        rule_id=str(addr),
                    )
                )
    return out


def _from_domains(domains: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _as_dict(domains)
    for domain, info in list(data.items())[:50]:
        info = _as_dict(info)
        bad = str(info.get("bad") or "").lower()
        impact = "High" if bad in ("yes", "true", "1") else "Low"
        geo = _as_dict(info.get("geolocation"))
        desc_parts = [f"Domain referenced in app: {domain}"]
        if geo.get("country_long"):
            desc_parts.append(f"Geolocation: {geo.get('country_long')}")
        if info.get("ofac"):
            desc_parts.append("OFAC sanctioned region flagged.")
        out.append(
            _finding(
                title=f"Domain: {domain}",
                description=". ".join(desc_parts),
                impact=impact,
                category="network",
                rule_id=str(domain),
            )
        )
    return out


def _from_trackers(trackers: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    data = _as_dict(trackers)
    detected = data.get("detected_trackers") or 0
    if detected and int(detected) > 0:
        out.append(
            _finding(
                title=f"Third-party trackers detected ({detected})",
                description="The app includes libraries associated with user tracking.",
                impact="Medium",
                category="privacy",
            )
        )
    for item in data.get("trackers") or []:
        item = _as_dict(item) if isinstance(item, dict) else {"name": str(item)}
        name = item.get("name") or item.get("title") or "Tracker"
        out.append(
            _finding(
                title=f"Tracker: {name}",
                description=str(item.get("description") or "Third-party tracker library detected."),
                impact="Medium",
                category="privacy",
                rule_id=str(name),
            )
        )
    return out


def extract_summary(report: dict[str, Any]) -> dict[str, Any]:
    """App identity + security score for dashboards (no tool branding)."""
    app_name = (
        report.get("app_name")
        or report.get("title")
        or report.get("bundle_name")
        or report.get("file_name")
    )
    package = report.get("package_name") or report.get("bundle_id") or report.get("id")
    version = report.get("version_name") or report.get("app_version") or report.get("version")
    platform = "ios" if report.get("bundle_id") or report.get("platform") == "ios" else "android"
    if str(report.get("file_name") or "").lower().endswith(".ipa"):
        platform = "ios"

    score = report.get("security_score")
    if score is None and isinstance(report.get("appsec"), dict):
        score = report["appsec"].get("security_score")

    return {
        "app_name": app_name,
        "package_name": package,
        "version_name": version,
        "platform": platform,
        "security_score": score,
        "file_name": report.get("file_name"),
        "md5": report.get("md5") or report.get("hash"),
    }


def normalize_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a full static analysis JSON report into finding rows."""
    if not isinstance(report, dict):
        return []

    findings: list[dict[str, Any]] = []

    findings.extend(_from_code_findings(report.get("code_analysis"), "code_analysis"))
    findings.extend(_from_manifest(report.get("manifest_analysis")))
    findings.extend(_from_binary_list(report.get("binary_analysis")))
    findings.extend(_from_code_findings(report.get("niap_analysis"), "niap"))
    findings.extend(_from_permissions(report.get("permissions")))
    findings.extend(_from_certificate(report.get("certificate_analysis")))
    findings.extend(_from_network_security(report.get("network_security")))
    findings.extend(_from_urls(report.get("urls")))
    findings.extend(_from_emails(report.get("emails")))
    findings.extend(_from_domains(report.get("domains")))
    findings.extend(_from_trackers(report.get("trackers")))

    for key, category in (("secrets", "secrets"), ("firebase_urls", "secrets")):
        value = report.get(key)
        if isinstance(value, list) and value:
            for item in value[:50]:
                if isinstance(item, str):
                    title = "Hardcoded secret detected"
                    desc = item
                elif isinstance(item, dict):
                    title = str(item.get("name") or item.get("title") or "Hardcoded secret detected")
                    desc = str(item.get("description") or item.get("url") or item)
                else:
                    continue
                findings.append(
                    _finding(
                        title=title,
                        description=desc if isinstance(desc, str) else str(desc),
                        impact="High" if category == "secrets" else "Medium",
                        category=category,
                    )
                )

    appsec = _as_dict(report.get("appsec"))
    for bucket, impact in (("high", "High"), ("warning", "Medium"), ("hotspot", "Medium")):
        for item in appsec.get(bucket) or []:
            item = _as_dict(item) if not isinstance(item, str) else {"title": item}
            title = str(item.get("title") or item.get("name") or bucket)
            if any(f["title"] == title for f in findings):
                continue
            findings.append(
                _finding(
                    title=title,
                    description=str(item.get("description") or title),
                    impact=impact,
                    suggested_fix=str(item.get("section") or ""),
                    category="appsec",
                )
            )

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (f["title"], f.get("category") or "", f.get("file_path") or f.get("location") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
