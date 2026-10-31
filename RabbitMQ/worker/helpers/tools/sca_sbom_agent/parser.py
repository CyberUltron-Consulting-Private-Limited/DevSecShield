"""Parser for Grype SBOM scan results. Converts match/finding dicts into readable strings."""

from __future__ import annotations

import re


def _get_cves(related: list[dict] | None) -> list[str]:
    """Extract CVE IDs from relatedVulnerabilities."""
    if not isinstance(related, list):
        return []
    return [r["id"] for r in related if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"].startswith("CVE-")]


def _get_cvss_score(cvss_list: list[dict] | None) -> str | None:
    """Get primary or first CVSS base score and vector."""
    if not isinstance(cvss_list, list):
        return None
    for entry in cvss_list:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        if not isinstance(metrics, dict) or "baseScore" not in metrics:
            continue
        vector = entry.get("vector") or ""
        vec_str = f" ({vector})" if vector else ""
        return f"{metrics['baseScore']}{vec_str}"
    return None


def _get_cwes(cwes_list: list[dict] | None) -> list[str]:
    """Extract unique CWE IDs."""
    if not isinstance(cwes_list, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for c in cwes_list:
        if not isinstance(c, dict):
            continue
        cwe = c.get("cwe")
        if cwe is not None and isinstance(cwe, str) and cwe not in seen:
            seen.add(cwe)
            out.append(cwe)
    return out


def _get_locations(artifact: dict | None) -> list[str]:
    """Extract location paths from artifact."""
    if not isinstance(artifact, dict):
        return []
    locs = artifact.get("locations")
    if not isinstance(locs, list):
        return []
    paths: list[str] = []
    for loc in locs:
        if not isinstance(loc, dict):
            continue
        p = loc.get("path") or loc.get("accessPath")
        if p is not None:
            paths.append(str(p))
    return paths


def _match_to_string(match: dict, index: int) -> str:
    """Convert a single match/finding dict into a readable string."""
    if not isinstance(match, dict):
        return ""

    vuln = match.get("vulnerability")
    artifact = match.get("artifact")
    related = match.get("relatedVulnerabilities")
    vuln = vuln if isinstance(vuln, dict) else {}
    artifact = artifact if isinstance(artifact, dict) else {}

    vuln_id = vuln.get("id")
    severity = vuln.get("severity")
    description = vuln.get("description")
    vuln_id = vuln_id if isinstance(vuln_id, str) and vuln_id else "Unknown"
    severity = severity if isinstance(severity, str) and severity else "Unknown"
    description = description if isinstance(description, str) and description else "No description."

    cvss = _get_cvss_score(vuln.get("cvss"))
    cwes = _get_cwes(vuln.get("cwes"))

    fix = vuln.get("fix")
    fix = fix if isinstance(fix, dict) else {}
    fix_state = fix.get("state")
    fix_state = fix_state if isinstance(fix_state, str) else "unknown"
    fix_versions = fix.get("versions")
    fix_versions = fix_versions if isinstance(fix_versions, list) else []

    pkg_name = artifact.get("name")
    pkg_version = artifact.get("version")
    pkg_type = artifact.get("type")
    purl = artifact.get("purl")
    pkg_name = pkg_name if isinstance(pkg_name, str) and pkg_name else "Unknown"
    pkg_version = pkg_version if isinstance(pkg_version, str) and pkg_version else "Unknown"
    pkg_type = pkg_type if isinstance(pkg_type, str) and pkg_type else "unknown"
    purl = purl if isinstance(purl, str) and purl else ""

    locations = _get_locations(artifact)
    cves = _get_cves(related)

    lines: list[str] = [
        f"[Finding {index}]",
        f"Vulnerability: {vuln_id}",
        f"Severity: {severity}",
        f"Description: {description}",
        f"Package: {pkg_name}@{pkg_version} ({pkg_type})",
    ]
    if purl:
        lines.append(f"PURL: {purl}")
    if cves:
        lines.append(f"CVE(s): {', '.join(cves)}")
    if cvss:
        lines.append(f"CVSS: {cvss}")
    if cwes:
        lines.append(f"CWE(s): {', '.join(cwes)}")
    lines.append(f"Fix state: {fix_state}")
    if fix_versions:
        lines.append(f"Fix version(s): {', '.join(str(v) for v in fix_versions)}")
    if locations:
        lines.append(f"Location(s): {', '.join(locations)}")

    return "\n".join(lines)


def parse_sbom_results_to_strings(results: dict) -> list[str]:
    """
    Parse Grype SBOM results (as a Python dict) into a list of strings.

    Each string represents one match/finding with vulnerability id, severity,
    description, package, CVSS, CWE(s), fix state, and locations.

    Missing keys, wrong types, or malformed entries are handled safely;
    invalid matches are skipped or yield placeholder values (e.g. "Unknown").

    Args:
        results: Grype JSON output as a dict (must contain a "matches" key).

    Returns:
        List of strings, one per match/finding.
    """
    if not isinstance(results, dict):
        return []
    matches = results.get("matches")
    if not isinstance(matches, list):
        return []

    out: list[str] = []
    for i, m in enumerate(matches):
        s = _match_to_string(m, i + 1)
        if s:
            out.append(s)
    return out


_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _cve_records(match: dict) -> list[tuple[str, str]]:
    """CVE id plus a short description from a Grype match."""
    vuln = match.get("vulnerability")
    vuln = vuln if isinstance(vuln, dict) else {}
    related = match.get("relatedVulnerabilities")
    candidates: list[dict] = []
    if vuln:
        candidates.append(vuln)
    if isinstance(related, list):
        candidates.extend(item for item in related if isinstance(item, dict))
    seen: set[str] = set()
    records: list[tuple[str, str]] = []
    fallback = str(vuln.get("description") or "").strip()
    for item in candidates:
        found = _CVE_ID.search(str(item.get("id") or ""))
        if not found:
            continue
        cve = found.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        desc = str(item.get("description") or fallback or cve).strip()
        records.append((cve, desc[:400] or cve))
    return records


def grype_package_cves(document: dict | None) -> dict[str, dict[str, str]]:
    """Index Grype CVE ids by purl and by ``name@version``.

    A bare package name is indexed only when every match for that name shares
    one version, so a lookup cannot mix CVEs from other releases.
    """
    if not isinstance(document, dict):
        return {}
    matches = document.get("matches")
    if not isinstance(matches, list):
        return {}
    index: dict[str, dict[str, str]] = {}
    versions_for_name: dict[str, set[str]] = {}
    for match in matches:
        if not isinstance(match, dict):
            continue
        artifact = match.get("artifact")
        artifact = artifact if isinstance(artifact, dict) else {}
        name = str(artifact.get("name") or "").strip()
        version = str(artifact.get("version") or "").strip()
        purl = artifact.get("purl")
        purl = purl.strip() if isinstance(purl, str) else ""
        records = _cve_records(match)
        if not records:
            continue
        keys: list[str] = []
        if name and version:
            keys.append(f"{name.lower()}@{version}")
            keys.append(f"{name.lower()}=={version}")
            versions_for_name.setdefault(name.lower(), set()).add(version)
        if purl:
            keys.append(purl.lower())
        for key in keys:
            bucket = index.setdefault(key, {})
            for cve, desc in records:
                bucket.setdefault(cve, desc)
    for name, versions in versions_for_name.items():
        if len(versions) == 1:
            only = next(iter(versions))
            exact = index.get(f"{name}@{only}")
            if exact:
                index.setdefault(name, dict(exact))
    return index


def _row_has_cve_id(cves: object) -> bool:
    if isinstance(cves, dict):
        return any(_CVE_ID.search(str(key)) for key in cves)
    if isinstance(cves, list):
        return any(_CVE_ID.search(str(item)) for item in cves)
    return False


def _row_lookup_keys(row: dict) -> list[str]:
    keys: list[str] = []
    purl = row.get("purl")
    if isinstance(purl, str) and purl.strip():
        keys.append(purl.strip().lower())
    raw = str(row.get("dependency") or "").strip()
    if raw.startswith("@") and raw.count("@") >= 2:
        name, _, version = raw.rpartition("@")
    elif "==" in raw:
        name, _, version = raw.partition("==")
    elif "@" in raw:
        name, _, version = raw.partition("@")
    else:
        name, version = raw, ""
    name = name.strip().lower()
    version = version.strip()
    if name and version:
        keys.append(f"{name}@{version}")
        keys.append(f"{name}=={version}")
    if name:
        keys.append(name)
    return keys


def apply_grype_cves(rows: list[dict], document: dict | None) -> None:
    """Copy Grype CVE ids onto finding rows the map-reduce left empty.

    The structured LLM field only accepts a recent-NVD allowlist, so package
    CVEs that Grype already identified are dropped. The bill-of-materials table
    reads those ids, not the prose description.
    """
    index = grype_package_cves(document)
    if not index:
        return
    for row in rows:
        if not isinstance(row, dict) or _row_has_cve_id(row.get("cves")):
            continue
        found: dict[str, str] | None = None
        for key in _row_lookup_keys(row):
            bucket = index.get(key)
            if not bucket:
                continue
            found = bucket
            if "@" in key or "==" in key or key.startswith("pkg:"):
                break
        if found:
            row["cves"] = dict(found)
