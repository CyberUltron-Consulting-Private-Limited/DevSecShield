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

from backend.utilities.dashboard.risk_scale import (
    POSTURE_KEY,
    STATUS_KEY,
    UNVERIFIED_KEY,
    posture_field,
    unverified_note,
)
from backend.utilities.dashboard.sbom_rows import (
    is_incomplete,
    is_inventory_row,
    is_unverified_version,
    unverified_counts,
)
from backend.utilities.pdf.report_context import ReportContext, details_note, join_parts
from backend.utilities.pdf.report_branding import (
    report_generated,
    append_report_masthead,
    COLOR_WHITE,
    append_bom_compliance_sections,
    append_executive_summary,
    compute_posture_risk_score,
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
    return name, version_label(version.strip(), item.get("version_guessed_from")), ecosystem, licence


def version_label(version: str, guessed_from: Any = None) -> str:
    """A version guessed from a manifest range reads "≥ 10.0 (range >=10.0,<11)", never as a pin (review B2)."""
    if not guessed_from or not version:
        return version
    constraint = str(guessed_from).strip()
    return f"≥ {version} (range {constraint})" if constraint and constraint != "range" else f"≥ {version} (range)"


# The height a package panel may fill: a panel is one flowable, so it must fit on a page whole (frame 672 pt, less
# the panel's title bar and the table header).
_PANEL_BUDGET_PT = 560.0
_CELL_PADDING_PT = 12.0


def _package_chunks(cells: List[List[Any]], widths: List[float]) -> List[tuple]:
    """(offset, rows) panels of at most _PACKAGE_ROWS_PER_PANEL rows whose measured height fits a page: long package
    names (@babel/plugin-transform-react-jsx-source) wrap, and 30 two-line rows (758 pt) overflowed the 672 pt frame,
    so the whole PDF export failed for a repository like ninedter/pcap-hunter."""
    out: List[tuple] = []
    start, height = 0, 0.0
    for i, row in enumerate(cells):
        h = max(cell.wrap(w - _CELL_PADDING_PT, 10_000)[1] for cell, w in zip(row, widths)) + _CELL_PADDING_PT
        if i > start and (i - start >= _PACKAGE_ROWS_PER_PANEL or height + h > _PANEL_BUDGET_PT):
            out.append((start, cells[start:i]))
            start, height = i, 0.0
        height += h
    if start < len(cells):
        out.append((start, cells[start:]))
    return out


def _append_package_panels(
    story: List[Any], *, title: str, intro: str, headers: List[str], lines: List[List[str]], styles: Dict[str, Any]
) -> None:
    """One compact table, a line per package, split into panels that fit a page (as the findings catalog)."""
    story.append(Paragraph(escape_html(title), styles["title"]))
    story.append(Paragraph(escape_html(intro), styles["muted"]))
    story.append(Spacer(1, 0.1 * inch))
    widths = [2.9 * inch, 1.3 * inch, 0.9 * inch, 1.9 * inch]
    all_cells = [
        [Paragraph(escape_html(c or "—"), styles["mono_cell" if i < 2 else "table_cell"]) for i, c in enumerate(row)]
        for row in lines
    ]
    for offset, cells in _package_chunks(all_cells, widths):
        chunk = cells
        end = offset + len(chunk)
        meta = f"{len(lines)} packages" if offset == 0 else f"{offset + 1}–{end} of {len(lines)}"
        heading = title if offset == 0 else f"{title} (cont.)"
        table = styled_data_table(headers, cells, styles=styles, col_widths=widths)
        table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0, COLOR_WHITE)]))  # the panel draws the box
        story.append(panel_wrap(heading, meta, table, styles=styles))
        story.append(Spacer(1, 0.08 * inch))


def _bom_licences(bom: Optional[Dict[str, Any]]) -> Dict[tuple, str]:
    """(name, version) -> licence of the downloaded SBOM (registry-resolved there; the rows may say not declared)."""
    out: Dict[tuple, str] = {}
    for comp in (bom or {}).get("components") or []:
        if not isinstance(comp, dict):
            continue
        for item in comp.get("licenses") or []:
            lic = item.get("license") if isinstance(item, dict) and isinstance(item.get("license"), dict) else {}
            token = str(lic.get("id") or lic.get("name") or (item or {}).get("expression") or "").strip()
            if token and token.lower() not in _UNKNOWN_LICENSES:
                out[(str(comp.get("name") or "").strip().lower(), str(comp.get("version") or "").strip())] = token
                break
    return out


def _append_inventory_sections(story: List[Any], inventory: List[Dict[str, Any]], styles: Dict[str, Any],
                               bom_licences: Optional[Dict[tuple, str]] = None) -> None:
    """#46: the inventoried packages are the bill of materials, not vulnerabilities. Those with no known vulnerability
    are listed one line each; an inventory row Grype matched to CVE ids (parser.apply_grype_cves) is not "no known
    vulnerability", so it is listed with its CVE ids instead. Neither is counted in the totals above."""
    clean: set[tuple[str, str, str, str]] = set()
    with_cves: dict[tuple[str, str, str], set[str]] = {}
    for item in inventory:
        name, version, ecosystem, licence = _package_line(item)
        if not name or (name.startswith("/") and not item.get("purl")):  # a file path is not a package (G-D4-6)
            continue
        raw_version = str(item.get("dependency") or "").rpartition("==")[2].strip()
        licence = licence or (bom_licences or {}).get((name.lower(), raw_version), "")
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


_FRAMEWORK_LABELS = (
    ("ntia_minimum_elements", "NTIA minimum elements"),
    ("cert_in_sbom", "CERT-In SBOM (TG v2.0, Table 5)"),
    ("sebi_cscrf_sbom", "SEBI CSCRF (SBOM)"),
    ("rbi_free_ai_supply", "RBI FREE-AI (supply chain)"),
    ("nist_ssdf", "NIST SSDF (SP 800-218)"),
)
_STATUS_LABEL = {"pass": "Pass", "partial": "Partial", "missing": "Missing"}


# the export routes put the scan's subject name here (certin_attest.subject_name_for(scan.scan_metadata)), so the
# PDF's SBOM is the very document ``/bom`` serves (review 6028132826 M6 / m1)
SUBJECT_NAME_KEY = "sbom_subject_name"


def _downloaded_bom(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The scan's SBOM as ``/bom`` serves it. ``/export`` and the evidence pack name the scan in the data
    (``served_bom.SCAN_IDENTITY_KEY``), and the page calls the routes' own builder, ``served_bom.served_bom``: the same
    serial, subject and server-stamped ``zs:`` properties, so the SHA-256 printed is the served document's (review
    6032108510 M-3). Data that names no scan (a PDF of an unsaved result) gets the stored document with its subject."""
    if not isinstance(raw, dict) or not isinstance(raw.get("sbom_json"), dict):
        return None
    try:
        from backend.utilities.compliance import served_bom
        from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data

        served = served_bom.served_bom_for_pdf(raw, "sbom_sca")
        if served is not False:
            return served if isinstance(served, dict) else None
        subject = raw.get(SUBJECT_NAME_KEY)
        return bom_dict_from_scan_data("sbom_sca", raw, subject_name=subject if isinstance(subject, str) else None)
    except Exception:
        return None


def bom_sha256(bom: Dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON (sorted keys, compact, no embedded JSF signature) of the SBOM: the digest a
    ``bom_signature.json`` names (``served_bom.bom_sha256``)."""
    from backend.utilities.compliance.served_bom import bom_sha256 as served_sha256

    return served_sha256(bom)


def _meta_prop(bom: Dict[str, Any], name: str) -> str:
    for prop in (bom.get("metadata") or {}).get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return str(prop.get("value") or "")
    return ""


def _framework_results(raw: Dict[str, Any], bom: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Framework results computed from the downloaded SBOM's fields (aibom.sbom.compliance), with the scan's
    attestations; the stored result when the engine is not importable."""
    stored = raw.get("sbom_compliance") if isinstance(raw.get("sbom_compliance"), dict) else {}
    if bom is None:
        return stored
    try:
        from backend.utilities.cbom_sources.run_parity import engine
        from backend.utilities.compliance.certin_attest import evidence_map_from_attestations

        engine()  # puts the aibom engine on the path (image: /opt/aibom/src; checkout: aibom/src)
        from aibom.sbom.compliance import run_sbom_compliance

        rows = raw.get("results") if isinstance(raw.get("results"), list) else []
        evidence = evidence_map_from_attestations(raw.get("attestations") or {})
        return run_sbom_compliance(rows, evidence=evidence, sbom_json=bom)
    except Exception:
        return stored


def _append_sbom_elements_section(story: List[Any], raw: Dict[str, Any], styles: Dict[str, Any]) -> None:
    """FIX-C1 (SOW D4): NTIA minimum elements / CERT-In fields counted in the CycloneDX file, then the SBOM
    frameworks' results (NTIA, CERT-In, SEBI CSCRF, RBI FREE-AI, NIST SSDF) computed from those same fields."""
    from backend.utilities.compliance.sbom_minimum_elements import minimum_elements

    bom = _downloaded_bom(raw)
    if bom is None:
        return
    report = minimum_elements(bom)
    story.append(PageBreak())
    story.append(Paragraph("SBOM minimum elements (NTIA / CERT-In)", styles["title"]))
    story.append(Paragraph(escape_html(
        f"Counted in the CycloneDX {report['spec_version']} file this scan downloads "
        f"({report['components']} components, {report['vulnerabilities']} linked vulnerabilities). Present: "
        "components (or document fields) carrying the element. Hashes are listed when the package source "
        "publishes one; a version guessed from a range gets none."), styles["muted"]))
    facts = [f"SBOM file: serial {bom.get('serialNumber') or '—'}, SHA-256 (canonical JSON) {bom_sha256(bom)}"]
    graph = _meta_prop(bom, "dss:dependency_graph")
    if graph and graph != "declared":
        facts.append(f"Dependency graph: {graph} — only edges the inventory tools declared are listed; the "
                     "relationships of the other components are unknown (CycloneDX compositions: incomplete).")
    db_built = _meta_prop(bom, "dss:grype_db_built")
    if db_built:
        facts.append(f"Vulnerability database: Grype database built {db_built}.")
    # licence and hash coverage counted in this file (review 6032108510 M-1), and where they came from
    present = {r["element"]: r for r in report["rows"]}
    lic, sha = present.get("Licence"), present.get("Hash / checksum (when known)")
    if lic and sha and report["components"]:
        registry = _meta_prop(bom, "dss:registry")
        facts.append(f"Licence coverage: {lic['present']}/{lic['total']} components; hash coverage: "
                     f"{sha['present']}/{sha['total']}" + (f"; package registries: {registry}." if registry else ".")
                     + (" Licence-risk checks report the components without a licence as not assessed."
                        if lic["present"] < lic["total"] else ""))
    note = _meta_prop(bom, "dss:coverage_note")
    if note:
        facts.append(f"Coverage: {note}.")
    for fact in facts:
        story.append(Paragraph(escape_html(fact), styles["muted"]))
    story.append(Spacer(1, 0.1 * inch))
    lines = [[r["element"], r["ntia"], r["cert_in"], f"{r['present']}/{r['total']}", _STATUS_LABEL[r["status"]]]
             for r in report["rows"]]
    cells = [[Paragraph(escape_html(c), styles["table_cell"]) for c in row] for row in lines]
    story.append(styled_data_table(["Element", "NTIA", "CERT-In field", "Present", "Status"], cells, styles=styles,
                                   col_widths=[2.6 * inch, 0.7 * inch, 1.9 * inch, 0.8 * inch, 0.9 * inch]))
    results = _framework_results(raw, bom)
    # the frameworks that bind the team, as the SBOM page shows them (bom_applicability; every one without a profile)
    from backend.utilities.compliance.bom_applicability import pdf_view

    view = pdf_view("sbom_sca", raw, results)
    binding = set(view["binding"]) if view else None
    fw_lines = []
    for key, label in _FRAMEWORK_LABELS:
        block = results.get(key) if isinstance(results, dict) else None
        if not isinstance(block, dict) or (binding is not None and key not in binding):
            continue
        cov = block.get("coverage")
        fw_lines.append([label, str(int(block.get("pass", 0)) + int(block.get("pass_with_evidence", 0) or 0)),
                         str(block.get("fail", 0)), str(block.get("not_bom_evidenceable", 0)),
                         "n/a" if cov is None else f"{round(float(cov) * 100)}%"])
    if fw_lines:
        story.append(Spacer(1, 0.18 * inch))
        story.append(Paragraph("SBOM compliance checks", styles["heading"]))
        story.append(Paragraph(escape_html(
            "Each requirement is checked against the fields above (advisory mapping, not a certification). "
            "Not evidenceable: the SBOM cannot show it (process evidence, or a field the sources do not publish)."),
            styles["muted"]))
        if view and view.get("not_applicable"):
            story.append(Paragraph(escape_html(
                f"Frameworks shown for this team's regulatory profile ({view['basis']}). Not applicable to it: "
                + ", ".join(n["label"] for n in view["not_applicable"]) + "."), styles["muted"]))
        story.append(Spacer(1, 0.08 * inch))
        fw_cells = [[Paragraph(escape_html(c), styles["table_cell"]) for c in row] for row in fw_lines]
        story.append(styled_data_table(["Framework", "Pass", "Fail", "Not evidenceable", "Coverage"], fw_cells,
                                       styles=styles,
                                       col_widths=[2.8 * inch, 0.7 * inch, 0.7 * inch, 1.4 * inch, 1.0 * inch]))


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
        for position, item in enumerate(scan_results):
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
                    "version_guessed_from": item.get("version_guessed_from") or None,
                    "_raw": item,
                    "_pos": position,  # index of the stored finding row (finding_rows.mongo_rows)
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


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None, *, ctx: Optional[ReportContext] = None) -> str:
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sbom_sca_scan_report_{timestamp}.pdf"

    inner, duration, raw = split_scan_payload(scan_results)
    rows = _normalize_sbom_results(inner)
    # #46: the inventoried packages are the bill of materials, listed after the findings; only vulnerabilities count
    vulnerabilities = [v for v in rows if not is_inventory_row(v)]
    inventory = [v for v in rows if is_inventory_row(v)]
    # a match on a version guessed from a range is listed but not counted (review 6028132826 M2), as on the dashboard
    counted = [v for v in vulnerabilities if not is_unverified_version(v)]
    unverified = len(vulnerabilities) - len(counted)
    total = len(counted)
    ctx = ctx or ReportContext()
    shown = ctx.select(vulnerabilities, lambda v: count_label(v.get("impact") or "Unknown"),
                       lambda _i, v: v.get("_pos"))
    by_severity: Dict[str, int] = {}
    unique_packages: set = set()
    fixable_count = 0

    for v in counted:
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

    # the one 0-100 risk score (risk_scale.posture): the number, grade and words of the headline, the list row and the
    # dashboard tile (it replaces the 0-10 average this row printed)
    # the rows this report reads, with the stored SBOM when the payload carries it: the same score, status and
    # unverified note as the list row and the results card (risk_scale.posture_field)
    data = {**(raw if isinstance(raw, dict) else {}), "results": rows}
    risk_field = posture_field(by_severity, incomplete=is_incomplete(data), unverified=unverified_counts(data))
    risk, risk_status = risk_field[POSTURE_KEY], risk_field[STATUS_KEY]
    risk_note = unverified_note(risk_field.get(UNVERIFIED_KEY))
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
        ("Unverified version (not counted)", str(unverified)),
        ("Packages affected", str(len(unique_packages))),
        ("Likely fixable via upgrade/update", str(fixable_count)),
        ("Risk score", "Incomplete scan (no package inventoried)" if risk is None
         else f"{risk['score']} / 100 · grade {risk['grade']} · {risk['label']}"
              + (" (unverified: worst case of guessed-version matches)" if risk_status == "unverified" else "")
              + (f" · {risk_note}" if risk_note else "")),
        ("Report generated", report_generated(long=True)),
    ]
    summary: List[Any] = []
    if not ctx.has("summary"):
        append_report_masthead(summary, report_key="sbom_sca", project_name="SBOM / SCA Dependencies", styles=styles, ctx=ctx)
    else:
      append_executive_summary(
        summary,
        report_key="sbom_sca",
        overview_rows=overview,
        severity_counts=by_severity,
        styles=styles,
        project_name="SBOM / SCA Dependencies",
        scan_time=scan_time,
        # one headline formula for every BOM PDF: the engine's posture score with its worst-severity cap (the AI BOM
        # and the CBOM use it too; staging QA Q2-01), not the uncapped compute_risk_score
        risk_score_fn=compute_posture_risk_score,
        meta_chips=[
            # the strip holds 4 chips: a scan with matches on range-guessed versions says so first (review M2)
            ("Unverified version", f"{unverified} not counted") if unverified else ("Scan type", "SBOM / SCA"),
            ("Packages affected", str(len(unique_packages))),
            ("Report generated", report_generated()),
            ("Fixable", str(fixable_count)),
        ],
        ctx=ctx,
        unverified=unverified,  # review 6032108510 m2: the headline agrees with the catalogue
        # no package inventoried: "incomplete", never grade A; only guessed-version matches: their worst case,
        # marked unverified (risk_scale statuses)
        risk_override=(("—", "—", "Incomplete scan") if risk is None else
                       (risk["score"], risk["grade"], f"{risk['label']} (unverified)") if risk_status == "unverified"
                       else None),
      )

    catalog_part: List[Any] = []
    catalog: List[List[Any]] = []
    shown_unverified = 0
    for idx, v in shown if ctx.has("catalog") else ():
        title = v.get("title") or "Untitled"
        if is_unverified_version(v):
            shown_unverified += 1
            if "unverified" not in title.lower():  # scans stored before the worker labelled it
                title += " - unverified version"
            title += " (not counted)"
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
    if ctx.has("catalog"):
        append_findings_catalog(catalog_part, catalog_rows=catalog, styles=styles, ctx=ctx, unverified=shown_unverified)

    details: List[Any] = []
    if ctx.has("details"):
        details.append(Paragraph("Detailed Findings", styles["title"]))
        details.append(
            Paragraph(
                details_note(ctx, "Each card shows where the package was found, description, and remediation. "
                             "Package and CVE values use monospace."),
                styles["muted"],
            )
        )
        details.append(Spacer(1, 0.1 * inch))

    if not ctx.has("details"):
        pass
    elif not shown:
        details.append(Paragraph(escape_html(ctx.empty_text("No vulnerabilities were identified in this scan.")), styles["body"]))
    else:
        for idx, v in shown:
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
            if v.get("version_guessed_from"):
                detail_rows.append(("Version", "unverified: guessed from the manifest range "
                                    f"{v.get('version_guessed_from')} (its lower bound); not counted in the totals"))
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

            details.append(
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
                    ctx=ctx,
                )
            )

    join_parts(story, [summary, catalog_part, details], PageBreak)
    # Both appendices keep today's flow: the inventory opens with its own page break and the
    # compliance appendix follows on the same page.
    if ctx.has("inventory"):
        _append_inventory_sections(story, inventory, styles, _bom_licences(_downloaded_bom(raw or {})))

    if ctx.has("compliance"):
        appendix_payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
        _append_sbom_elements_section(story, appendix_payload, styles)
        append_bom_compliance_sections(story, appendix_payload, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("sbom_sca", ctx),
        onLaterPages=make_footer_callback("sbom_sca", ctx),
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
