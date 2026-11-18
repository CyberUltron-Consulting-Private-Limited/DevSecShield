"""
SBOM/SCA Scan Results PDF Generator
Human-readable enterprise report with tabular summary and detailed findings.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, TableStyle

from backend.utilities.dashboard.risk_scale import average_risk_of
from backend.utilities.dashboard.sbom_rows import is_inventory_row
from backend.utilities.pdf.report_branding import (
    COLOR_WHITE,
    append_bom_compliance_sections,
    append_executive_summary,
    append_findings_catalog,
    build_finding_section,
    count_label,
    escape_html,
    finding_location,
    format_scan_duration,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_entries,
    mapping_rows,
    panel_wrap,
    relative_scan_path,
    severity_color,
    split_scan_payload,
    styled_data_table,
)

_INVENTORY_FIX_PLACEHOLDERS = {
    "",
    "n/a",
    "n/a — inventory row",
    "n/a - inventory row",
}
_INVENTORY_REMEDIATION = (
    "No CVE recorded for this component. Track the package and upgrade "
    "if a vulnerability is later identified."
)


_UNKNOWN_LICENSES = {"", "noassertion", "none", "unknown", "n/a", "licenseref-not-declared", "not_declared"}
_PACKAGE_ROWS_PER_PANEL = 30


def get_severity_color(severity: str):
    return severity_color(severity)


def _as_mapping(val: Any) -> Any:
    if isinstance(val, dict) or isinstance(val, list):
        return val
    return {}


def _license_label(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, list):
        parts: List[str] = []
        for item in val:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
            elif isinstance(item, dict):
                name = item.get("name") or item.get("id") or item.get("value") or ""
                if str(name).strip():
                    parts.append(str(name).strip())
            elif item:
                parts.append(str(item).strip())
        return ", ".join(parts)
    return str(val).strip()


def _package_label(item: Dict[str, Any]) -> str:
    dep = item.get("dependency")
    if isinstance(dep, str) and dep.strip():
        return dep.strip()
    deps = item.get("dependencies") or []
    if isinstance(deps, list) and deps:
        first = deps[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
        if first:
            return str(first)
    return ""


def _short_finding_title(item: Dict[str, Any]) -> str:
    title = str(item.get("title") or "").strip() or "Untitled"
    if "/" not in title and "\\" not in title:
        return title
    dep = _package_label(item)
    pkg = dep.split("==")[0].split("@")[0] if dep else ""
    if pkg:
        return f"Inventory: {pkg}"
    cleaned = relative_scan_path(title)
    base = cleaned.rsplit("/", 1)[-1] if cleaned else "component"
    return f"Lockfile: {base}"


def _sbom_remediation(item: Dict[str, Any]) -> str:
    suggested = str(item.get("suggested_fix") or "").strip()
    license_val = _license_label(item.get("license"))
    cves = item.get("cves") or {}
    has_cves = bool(mapping_entries(cves))
    inventory_only = bool(item.get("inventory_only"))
    is_placeholder = suggested.lower() in _INVENTORY_FIX_PLACEHOLDERS
    if inventory_only or (is_placeholder and not has_cves):
        text = _INVENTORY_REMEDIATION
        if license_val:
            text += f" License: {license_val}."
        return text
    return suggested


def _package_line(item: Dict[str, Any]) -> tuple[str, str, str, str]:
    """(name, version, ecosystem, licence) of an inventory row; its dependency is ``name==version`` (merge_inventory)
    and the ecosystem is its purl's type (``pkg:npm/...``: npm)."""
    dep = str(item.get("dependency") or "").strip()
    name, sep, version = dep.rpartition("==")
    if not sep:
        name, version = dep, ""
    name = name.strip() or str(item.get("title") or "").replace("Inventory:", "", 1).strip()
    purl = str(item.get("purl") or "").strip()
    ecosystem = purl[4:].split("/", 1)[0].lower() if purl.lower().startswith("pkg:") else ""
    licence = _license_label(item.get("license"))
    if licence.lower() in _UNKNOWN_LICENSES:
        licence = ""
    return name, version.strip(), ecosystem, licence


def _append_package_panels(
    story: List[Any], *, title: str, intro: str, headers: List[str], lines: List[List[str]], styles: Dict[str, Any]
) -> None:
    """One compact table, a line per package, split into panels that fit a page (as the findings catalog)."""
    story.append(Paragraph(escape_html(title), styles["title"]))
    story.append(Paragraph(escape_html(intro), styles["muted"]))
    story.append(Spacer(1, 0.1 * inch))
    widths = [2.9 * inch, 1.3 * inch, 0.9 * inch, 1.9 * inch]
    for offset in range(0, len(lines), _PACKAGE_ROWS_PER_PANEL):
        chunk = lines[offset : offset + _PACKAGE_ROWS_PER_PANEL]
        cells = [
            [Paragraph(escape_html(c or "—"), styles["mono_cell" if i < 2 else "table_cell"]) for i, c in enumerate(row)]
            for row in chunk
        ]
        end = offset + len(chunk)
        meta = f"{len(lines)} packages" if offset == 0 else f"{offset + 1}–{end} of {len(lines)}"
        heading = title if offset == 0 else f"{title} (cont.)"
        table = styled_data_table(headers, cells, styles=styles, col_widths=widths)
        table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0, COLOR_WHITE)]))  # the panel draws the box
        story.append(panel_wrap(heading, meta, table, styles=styles))
        story.append(Spacer(1, 0.08 * inch))


def _append_inventory_sections(story: List[Any], inventory: List[Dict[str, Any]], styles: Dict[str, Any]) -> None:
    """#46: the inventoried packages are the bill of materials, not vulnerabilities. Those with no known vulnerability
    are listed one line each; an inventory row Grype matched to CVE ids (parser.apply_grype_cves) is not "no known
    vulnerability", so it is listed with its CVE ids instead. Neither is counted in the totals above."""
    clean: set[tuple[str, str, str, str]] = set()
    with_cves: dict[tuple[str, str, str], set[str]] = {}
    for item in inventory:
        name, version, ecosystem, licence = _package_line(item)
        if not name:
            continue
        cve_ids = {str(k or v) for k, v in mapping_entries(item.get("cves") or {}) if (k or v)}
        if cve_ids:
            with_cves.setdefault((name, version, ecosystem), set()).update(cve_ids)
        else:
            clean.add((name, version, ecosystem, licence))
    if not clean and not with_cves:
        return
    story.append(PageBreak())
    if clean:
        _append_package_panels(
            story,
            title="Packages with no known vulnerability",
            intro="The other packages in this scan's bill of materials. No known vulnerability matches them, so they "
            "are not counted as vulnerabilities in this report.",
            headers=["Package", "Version", "Ecosystem", "Licence"],
            lines=[list(t) for t in sorted(clean, key=lambda t: (t[0].lower(), t[1], t[2], t[3]))],
            styles=styles,
        )
    if with_cves:
        _append_package_panels(
            story,
            title="Inventoried packages with CVE ids from Grype",
            intro="Grype matched these inventoried packages to CVE ids. Where the analysis described the vulnerability "
            "it is in Detailed Findings; these rows are not counted again.",
            headers=["Package", "Version", "Ecosystem", "CVE ids"],
            lines=[[*key, ", ".join(sorted(ids)[:8])]
                   for key, ids in sorted(with_cves.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1], kv[0][2]))],
            styles=styles,
        )


def _normalize_sbom_results(scan_results: Union[dict, list]) -> List[Dict[str, Any]]:
    """
    Normalize scan results to a list of vulnerability dicts with a unified shape.
    - Agent format: scan_results is a list of items with title, description, impact,
      owasp_top_10, compliance_controls, suggested_fix, dependencies, cves.
    - Export-route format: full scan_data dict with a ``results`` list (same shape as agent).
    - Legacy format: scan_results is a dict with "matches"; each match has vulnerability + artifact.
    Returns list of dicts with keys: title, description, impact, suggested_fix, dependencies,
    cves, owasp_top_10, compliance_controls (and optionally package_name, package_version for legacy).
    """
    out: List[Dict[str, Any]] = []
    # Export route for BOM types passes the full scan_data dict so RBI/CERT-In
    # appendix helpers can read compliance keys; findings live under "results".
    if isinstance(scan_results, dict) and "results" in scan_results and "matches" not in scan_results:
        scan_results = scan_results.get("results") or []
    if isinstance(scan_results, list):
        for item in scan_results:
            if not isinstance(item, dict):
                continue
            dependency = _package_label(item)
            deps = item.get("dependencies") or []
            if not isinstance(deps, list):
                deps = [deps] if deps else []
            if dependency and dependency not in deps:
                deps = [dependency, *[d for d in deps if d != dependency]]
            out.append(
                {
                    "title": _short_finding_title({**item, "dependency": dependency}),
                    "description": item.get("description") or "",
                    "impact": item.get("impact") or "Unknown",
                    "owasp_top_10": _as_mapping(item.get("owasp_top_10")),
                    "compliance_controls": _as_mapping(item.get("compliance_controls")),
                    "suggested_fix": item.get("suggested_fix") or "",
                    "dependency": dependency,
                    "dependencies": deps,
                    "cves": _as_mapping(item.get("cves")),
                    "location": item.get("location"),
                    "snippet": item.get("snippet") or "",
                    "purl": item.get("purl") or "",
                    "license": _license_label(item.get("license") or item.get("licenses")),
                    "inventory_only": bool(item.get("inventory_only")),
                    "_raw": item,
                }
            )
        return out

    matches = (scan_results or {}).get("matches", []) if isinstance(scan_results, dict) else []
    for match in matches:
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        fix = vuln.get("fix", {}) or {}
        fix_state = fix.get("state", "unknown")
        fix_versions = fix.get("versions", []) or []
        suggested_fix = f"Fix status: {fix_state}"
        if fix_versions:
            suggested_fix += f". Fixed in: {', '.join(fix_versions[:3])}"
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        dependency = f"{name}@{version}" if name else ""
        cves = _as_mapping(vuln.get("cves"))
        out.append(
            {
                "title": vuln.get("id", "Unknown"),
                "description": vuln.get("description", "No description available"),
                "impact": vuln.get("severity", "UNKNOWN"),
                "owasp_top_10": _as_mapping(vuln.get("owasp_top_10")),
                "compliance_controls": _as_mapping(vuln.get("compliance_controls")),
                "suggested_fix": suggested_fix,
                "dependency": dependency,
                "dependencies": [dependency] if dependency else [],
                "cves": cves,
                "location": artifact.get("locations") or artifact.get("location"),
                "snippet": "",
                "purl": artifact.get("purl") or "",
                "license": _license_label(artifact.get("licenses") or artifact.get("license")),
                "inventory_only": False,
                "_raw": match,
            }
        )
    return out


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None) -> str:
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sbom_sca_scan_report_{timestamp}.pdf"

    inner, duration, raw = split_scan_payload(scan_results)
    rows = _normalize_sbom_results(inner)
    # #46: the inventoried packages are the bill of materials, listed after the findings; only vulnerabilities count
    vulnerabilities = [v for v in rows if not is_inventory_row(v)]
    inventory = [v for v in rows if is_inventory_row(v)]
    total = len(vulnerabilities)
    by_severity: Dict[str, int] = {}
    unique_packages: set = set()
    fixable_count = 0

    for v in vulnerabilities:
        impact = count_label(v.get("impact") or "Unknown")
        by_severity[impact] = by_severity.get(impact, 0) + 1
        dep = v.get("dependency") or ""
        if dep:
            unique_packages.add(dep)
        suggested = (v.get("suggested_fix") or "").lower()
        if suggested not in _INVENTORY_FIX_PLACEHOLDERS and (
            "upgrade" in suggested or "fixed" in suggested or "update" in suggested
        ):
            fixable_count += 1

    # the app's one 0-10 scale (#35): the same number as the dashboards' Avg risk score card
    avg_risk = average_risk_of(v.get("impact") for v in vulnerabilities)
    styles = get_report_styles()
    scan_time = format_scan_duration(duration)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=56,
        bottomMargin=52,
    )
    story: List[Any] = []

    overview = [
        ("Scan type", "SBOM / Software Composition Analysis (SCA)"),
        ("Total vulnerabilities", str(total)),
        ("Packages affected", str(len(unique_packages))),
        ("Likely fixable via upgrade/update", str(fixable_count)),
        ("Average risk score (0–10)", f"{avg_risk:.1f}" if avg_risk is not None else "N/A"),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="sbom_sca",
        overview_rows=overview,
        severity_counts=by_severity,
        styles=styles,
        project_name="SBOM / SCA Dependencies",
        scan_time=scan_time,
        meta_chips=[
            ("Scan type", "SBOM / SCA"),
            ("Packages affected", str(len(unique_packages))),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Fixable", str(fixable_count)),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, v in enumerate(vulnerabilities, 1):
        title = v.get("title") or "Untitled"
        impact = (v.get("impact") or "Unknown").strip()
        location = finding_location(v)
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(title), styles["table_cell"]),
                Paragraph(escape_html(location), styles["mono_cell"]),
            ]
        )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card shows where the package was found, description, and remediation. "
            "Package and CVE values use monospace.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total == 0:
        story.append(Paragraph("No vulnerabilities were identified in this scan.", styles["body"]))
    else:
        for idx, v in enumerate(vulnerabilities, 1):
            title = v.get("title") or "Untitled"
            impact = (v.get("impact") or "Unknown").strip()
            loc = finding_location(v)
            dependency = v.get("dependency") or ""
            purl = str(v.get("purl") or "").strip()
            license_val = _license_label(v.get("license"))
            cves = v.get("cves") or {}

            detail_rows = [("Severity", impact), ("Where it was found", loc)]
            if dependency:
                detail_rows.append(("Affected package", dependency))
            if purl:
                detail_rows.append(("PURL", purl))
            if license_val:
                detail_rows.append(("License", license_val))
            cve_ids = [k or v for k, v in mapping_entries(cves)]
            if cve_ids:
                detail_rows.append(("CVE IDs", ", ".join(cve_ids[:8])))

            standards: List[List[str]] = []
            standards.extend(mapping_rows(v.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(v.get("compliance_controls"), label="Compliance"))
            standards.extend(mapping_rows(cves, label="CVE detail", limit=5))

            story.append(
                build_finding_section(
                    index=idx,
                    title=title,
                    severity=impact,
                    detail_rows=detail_rows,
                    description=v.get("description") or "",
                    evidence=str(v.get("snippet") or ""),
                    recommended_fix=_sbom_remediation(v),
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    _append_inventory_sections(story, inventory, styles)

    appendix_payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
    append_bom_compliance_sections(story, appendix_payload, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("sbom_sca"),
        onLaterPages=make_footer_callback("sbom_sca"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="sbom_sca")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="sbom_sca")


if __name__ == "__main__":
    test_file_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "RabbitMQ",
            "worker",
            "archive",
            "worker_sbom_agent_results_testing.json",
        )
    )
    with open(test_file_path, "r", encoding="utf-8") as f:
        scan_results = json.load(f)
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    print(generate_pdf(scan_results, os.path.join(out_dir, "SBOM_SCA_Enterprise_Report.pdf")))
