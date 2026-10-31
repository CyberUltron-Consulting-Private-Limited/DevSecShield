"""CERT-In VEX emit — CycloneDX 1.6-compatible vulnerabilities (F5).

Default analysis state is ``not_affected`` unless proven otherwise.
Proven affected: SBOM finding rows with non-empty CVE ids.
CBOM code scans: a weakness seen in the code (finding code) or a CVE matched from that evidence is ``in_triage``
(the use is real, whether it protects anything exploitable needs a person); only assets with no finding are
``not_affected``. A CBOM asset that names a CVE is never reported as not affected.
"""

from __future__ import annotations

from typing import Any

__all__ = ["build_vex"]

_HIGH_IMPACT = frozenset({"Critical", "critical", "High", "high"})


def _cve_ids_from_finding(row: dict[str, Any]) -> list[str]:
    cves = row.get("cves")
    out: list[str] = []
    if isinstance(cves, dict):
        for k in cves:
            s = str(k).strip()
            if s:
                out.append(s)
    elif isinstance(cves, list):
        for item in cves:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                cid = item.get("id") or item.get("cve")
                if cid and str(cid).strip():
                    out.append(str(cid).strip())
    return out


def _dep_ref(row: dict[str, Any], index: int) -> str:
    dep = str(row.get("dependency") or row.get("package_name") or "").strip()
    if dep:
        return dep.split("@")[0].split("==")[0].strip() or f"component-{index}"
    return f"component-{index}"


def _vuln_entry(
    *,
    vuln_id: str,
    state: str,
    affects_ref: str | None,
    detail: str,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": vuln_id,
        "source": {"name": "DevSecShield CERT-In VEX", "url": ""},
        "analysis": {
            "state": state,
            "detail": detail,
        },
    }
    if affects_ref:
        entry["affects"] = [{"ref": affects_ref}]
    return entry


CBOM_VEX_RULES = "2"


def _cbom_vulnerabilities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per finding code and per CVE across the scan, listing the assets (bom-refs) they affect."""
    by_code: dict[str, list[str]] = {}
    by_cve: dict[str, list[str]] = {}
    clean: list[str] = []
    for i, row in enumerate(findings):
        if not isinstance(row, dict):
            continue
        ref = str(row.get("bom_ref") or row.get("bom-ref") or f"component-{i}")
        codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str)]
        for code in codes:
            by_code.setdefault(code, []).append(ref)
        for cid in _cve_ids_from_finding(row):
            by_cve.setdefault(cid, []).append(ref)
        if not codes and not _cve_ids_from_finding(row):
            clean.append(ref)
    out: list[dict[str, Any]] = []
    for code, refs in sorted(by_code.items()):
        entry = _vuln_entry(vuln_id=f"ZS-CBOM-{code}", state="in_triage", affects_ref=None,
                            detail="Seen in the source code or configuration; confirm whether it protects data that "
                                   "matters, then fix or record the exception.")
        entry["affects"] = [{"ref": r} for r in dict.fromkeys(refs)]
        out.append(entry)
    for cid, refs in sorted(by_cve.items()):
        entry = _vuln_entry(vuln_id=cid, state="in_triage", affects_ref=None,
                            detail="Matched from the algorithm or protocol the code uses; a match is not proof of "
                                   "exposure.")
        entry["source"] = {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cid}"}
        entry["affects"] = [{"ref": r} for r in dict.fromkeys(refs)]
        out.append(entry)
    for ref in dict.fromkeys(clean):
        out.append(_vuln_entry(vuln_id=f"not-affected:{ref}", state="not_affected", affects_ref=ref,
                               detail="No weakness or CVE found for this asset (CERT-In F5)"))
    return out


def build_vex(
    *,
    bom: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    scan_type: str = "sbom_sca",
) -> dict[str, Any]:
    """Build a CycloneDX-shaped VEX document (vulnerabilities list + metadata).

    - SBOM with CVE-bearing findings → those CVEs are ``affected`` (or
      ``exploitable`` when impact is Critical/High).
    - Components / findings without CVEs → ``not_affected`` stubs when we have
      an inventory; empty inventory → empty vulnerabilities (honest).
    - CBOM/AIBOM (no CVE inventory) → ``not_affected`` per component bom-ref
      when ``bom.components`` present; never invent CVEs from crypto flags.
    """
    vulnerabilities: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    if scan_type == "cbom" and findings:
        vulnerabilities = _cbom_vulnerabilities(findings)
    elif findings:
        for i, row in enumerate(findings):
            if not isinstance(row, dict):
                continue
            cves = _cve_ids_from_finding(row)
            ref = _dep_ref(row, i)
            impact = str(row.get("impact") or "")
            if cves:
                state = "exploitable" if impact in _HIGH_IMPACT else "affected"
                for cid in cves:
                    if cid in seen_cves:
                        continue
                    seen_cves.add(cid)
                    vulnerabilities.append(
                        _vuln_entry(
                            vuln_id=cid,
                            state=state,
                            affects_ref=ref,
                            detail=(
                                "Proven by SBOM/SCA CVE linkage "
                                f"(impact={impact or 'unknown'})"
                            ),
                        )
                    )
            else:
                # No CVE → default not_affected for this inventoried dependency.
                vulnerabilities.append(
                    _vuln_entry(
                        vuln_id=f"not-affected:{ref}",
                        state="not_affected",
                        affects_ref=ref,
                        detail="No CVE linkage; default not_affected (CERT-In F5)",
                    )
                )

    elif isinstance(bom, dict):
        comps = bom.get("components")
        if isinstance(comps, list):
            for i, comp in enumerate(comps):
                if not isinstance(comp, dict):
                    continue
                ref = str(comp.get("bom-ref") or comp.get("name") or f"component-{i}")
                vulnerabilities.append(
                    _vuln_entry(
                        vuln_id=f"not-affected:{ref}",
                        state="not_affected",
                        affects_ref=ref,
                        detail=(
                            f"No CVE inventory for {scan_type}; "
                            "default not_affected (CERT-In F5)"
                        ),
                    )
                )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "DevSecShield CERT-In VEX",
                        "version": "1.0",
                    }
                ]
            },
            "properties": [
                {"name": "zs:vex_rules", "value": CBOM_VEX_RULES},
                {
                    "name": "certin:disclaimer",
                    "value": (
                        "Advisory VEX alignment to CERT-In TG v2.0; "
                        "default not_affected unless proven. "
                        "Does not constitute CERT-In certification."
                    ),
                }
            ],
        },
        "vulnerabilities": vulnerabilities,
    }
