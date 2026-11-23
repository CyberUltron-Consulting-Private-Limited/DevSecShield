"""Deterministic SBOM vulnerability findings from Grype JSON (SOW D4, audit G-X-2).

Every finding row comes from a Grype match: one row per (advisory id, package, version). The same Grype document
always gives the same rows in the same order, so a scan's vulnerability list never depends on an LLM. The LLM
map-reduce in ``main.py`` is optional enrichment on top of these rows and can never add or drop a finding.

Standard library only (no worker package imports), so it is unit-testable on its own.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# The worker's Impact enum is Low / Medium / High / Critical (helpers/context/enums.py).
_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "negligible": "Low",
}
_IMPACT_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_OWASP_A06 = {"VULNERABLE_AND_OUTDATED_COMPONENTS": "A06:2021 - Vulnerable and Outdated Components"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_DESC_LIMIT = 1200


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def impact_from_cvss(score: float | None) -> str | None:
    """CVSS v3 qualitative rating (FIRST CVSS v3.1 spec, section 5) for a base score."""
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return None


def _best_cvss(entries: Iterable[Any]) -> tuple[float | None, str, str]:
    """(base score, vector, version) of the highest CVSS entry; a primary (NVD) entry wins a tie."""
    best: tuple[float | None, str, str] = (None, "", "")
    for entry in entries:
        entry = _dict(entry)
        metrics = _dict(entry.get("metrics"))
        try:
            score = float(metrics.get("baseScore"))
        except (TypeError, ValueError):
            continue
        if best[0] is None or score > best[0]:
            best = (score, _str(entry.get("vector")), _str(entry.get("version")))
    return best


def _cwes(vuln: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in _list(vuln.get("cwes")):
        cwe = _str(_dict(item).get("cwe"))
        if cwe and cwe not in out:
            out.append(cwe)
    return out


def _locations(artifact: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for loc in _list(artifact.get("locations")):
        path = _str(_dict(loc).get("path")) or _str(_dict(loc).get("accessPath"))
        if path and path not in out:
            out.append(path)
    return out


def _epss(vuln: dict[str, Any]) -> float | None:
    for item in _list(vuln.get("epss")):
        try:
            return float(_dict(item).get("epss"))
        except (TypeError, ValueError):
            continue
    return None


def _kev(vuln: dict[str, Any]) -> bool:
    return bool(_list(vuln.get("knownExploited")))


def _aliases(match: dict[str, Any], primary: str) -> list[str]:
    """Other advisory ids for the same issue (CVE ids from relatedVulnerabilities first)."""
    ids: list[str] = []
    for rel in _list(match.get("relatedVulnerabilities")):
        rid = _str(_dict(rel).get("id"))
        if rid and rid != primary and rid not in ids:
            ids.append(rid)
    return sorted(ids, key=lambda i: (not _CVE.match(i), i))


def _description(vuln: dict[str, Any], match: dict[str, Any]) -> str:
    text = _str(vuln.get("description"))
    if not text:
        for rel in _list(match.get("relatedVulnerabilities")):
            text = _str(_dict(rel).get("description"))
            if text:
                break
    return text[:_DESC_LIMIT]


def _suggested_fix(name: str, version: str, fix_state: str, fix_versions: list[str], guessed: bool) -> str:
    if fix_versions:
        target = ", ".join(fix_versions[:3])
        text = f"Upgrade {name} from {version} to {target} or later."
    elif fix_state == "wont-fix":
        text = (f"The maintainers will not fix this in {name}; replace the package or apply a compensating control "
                "and record the exception.")
    else:
        text = (f"No fixed release of {name} is published yet; track the advisory, apply the vendor workaround if "
                "any, or record the exception.")
    if guessed:
        text += (" The version was read from a version range in the manifest (its lower bound); confirm the version "
                 "you install, pin it, and rescan.")
    return text


def _component_key(name: str, version: str) -> str:
    return f"{re.sub(r'[-_.]+', '-', name.strip().lower())}@{version.strip()}"


def finding_rows(
    document: dict[str, Any] | None,
    *,
    licenses: dict[str, tuple[str, str]] | None = None,
    guessed_versions: dict[str, str] | None = None,
    direct: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Finding rows for every Grype match, sorted by (severity desc, package, advisory id).

    ``licenses`` maps ``purl`` or ``name@version`` to ``(spdx_or_label, license_type)`` from the inventory;
    ``guessed_versions`` maps ``purl`` to the manifest's version constraint where the version was guessed from a
    range; ``direct`` holds the purls the subject depends on directly (None: not known, rows say "direct").
    """
    if not isinstance(document, dict):
        return []
    licenses = licenses or {}
    guessed_versions = guessed_versions or {}
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, Any]] = []
    for raw in _list(document.get("matches")):
        match = _dict(raw)
        vuln = _dict(match.get("vulnerability"))
        artifact = _dict(match.get("artifact"))
        vid = _str(vuln.get("id"))
        name = _str(artifact.get("name"))
        version = _str(artifact.get("version"))
        if not vid or not name:
            continue
        key = (vid, name.lower(), version)
        if key in seen:  # grype can report one advisory twice for one package (two matchers)
            continue
        seen.add(key)
        purl = _str(artifact.get("purl")).split("?", 1)[0]
        aliases = _aliases(match, vid)
        cves = [i for i in [vid, *aliases] if _CVE.match(i)]
        # the advisory's own CVSS (it is what grype's severity comes from); a related record's only when it has none
        score, vector, cvss_version = _best_cvss(_list(vuln.get("cvss")))
        if score is None:
            score, vector, cvss_version = _best_cvss(
                c for r in _list(match.get("relatedVulnerabilities")) for c in _list(_dict(r).get("cvss")))
        grype_severity = _str(vuln.get("severity"))
        impact = _SEVERITY.get(grype_severity.lower()) or impact_from_cvss(score) or "Medium"
        fix = _dict(vuln.get("fix"))
        fix_state = _str(fix.get("state")) or "unknown"
        fix_versions = [str(v) for v in _list(fix.get("versions")) if str(v).strip()]
        description = _description(vuln, match)
        constraint = guessed_versions.get(purl) or guessed_versions.get(_component_key(name, version))
        lic, lic_type = licenses.get(purl) or licenses.get(_component_key(name, version)) or ("LicenseRef-not-declared", "not_declared")
        ids_text = {i: (description or i)[:400] for i in [vid, *aliases]}
        row: dict[str, Any] = {
            "title": f"{vid} in {name} {version}".strip(),
            "description": description or f"{vid} affects {name} {version}.",
            "impact": impact,
            "dependency": f"{name}=={version}" if version else name,
            "purl": purl or None,
            "reachability": "not_assessed",
            "dependency_type": "direct" if direct is None or (purl and purl in direct) else "transitive",
            "license": lic or "LicenseRef-not-declared",
            "license_type": lic_type or "not_declared",
            "cves": ids_text,
            "owasp_top_10": dict(_OWASP_A06),
            "compliance_controls": {},
            "suggested_fix": _suggested_fix(name, version, fix_state, fix_versions, bool(constraint)),
            "vuln_id": vid,
            "vuln_aliases": aliases,
            "cve_ids": cves,
            "vuln_source": _str(vuln.get("namespace")),
            "vuln_url": _str(vuln.get("dataSource")),
            "grype_severity": grype_severity or "Unknown",
            "fix_state": fix_state,
            "fix_versions": fix_versions,
            "location": ", ".join(_locations(artifact)[:3]),
            "detected_by": "grype",
            "vuln_assessed": True,
            "inventory_only": False,
        }
        if score is not None:
            row["cvss_score"] = score
            row["cvss_vector"] = vector
            row["cvss_version"] = cvss_version
        cwes = _cwes(vuln)
        if cwes:
            row["cwes"] = cwes
        epss = _epss(vuln)
        if epss is not None:
            row["epss"] = epss
        if _kev(vuln):
            row["known_exploited"] = True
        if constraint:
            row["version_guessed_from"] = constraint
        rows.append({k: v for k, v in row.items() if v is not None})
    rows.sort(key=lambda r: (-_IMPACT_ORDER.get(r["impact"], 0), r["dependency"].lower(), r["vuln_id"]))
    return rows


def merge_llm_enrichment(rows: list[dict[str, Any]], enriched: list[dict[str, Any]]) -> int:
    """Copy LLM mappings onto deterministic rows of the same package; never adds, drops or re-rates a row.

    Fills only empty ``compliance_controls`` and adds OWASP keys; the LLM's prose goes to ``llm_summary``.
    Returns the number of rows that took something.
    """
    by_pkg: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        pkg = re.split(r"==|@", str(row.get("dependency") or ""), maxsplit=1)[0].strip().lower()
        if pkg:
            by_pkg.setdefault(re.sub(r"[-_.]+", "-", pkg), []).append(row)
    touched = 0
    for item in enriched or []:
        if not isinstance(item, dict):
            continue
        pkg = re.split(r"==|@|\s", str(item.get("dependency") or "").strip(), maxsplit=1)[0].lower()
        targets = by_pkg.get(re.sub(r"[-_.]+", "-", pkg)) or []
        for row in targets:
            took = False
            controls = item.get("compliance_controls")
            if isinstance(controls, dict) and controls and not row.get("compliance_controls"):
                row["compliance_controls"] = dict(controls)
                took = True
            owasp = item.get("owasp_top_10")
            if isinstance(owasp, dict):
                for k, v in owasp.items():
                    if k not in row["owasp_top_10"]:
                        row["owasp_top_10"][k] = v
                        took = True
            summary = _str(item.get("description"))
            if summary and not row.get("llm_summary"):
                row["llm_summary"] = summary[:_DESC_LIMIT]
                took = True
            touched += int(took)
    return touched


__all__ = ["finding_rows", "impact_from_cvss", "merge_llm_enrichment"]
