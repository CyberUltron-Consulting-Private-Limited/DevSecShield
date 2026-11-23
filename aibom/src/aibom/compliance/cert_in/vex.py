"""CERT-In VEX emit — CycloneDX 1.6 VEX (F5).

SBOM and AI BOM (FIX-C1, SOW D4, audit G-D4-3): a statement only for a vulnerability
that exists, i.e. one with an advisory id (CVE, GHSA, PYSEC, GO, RUSTSEC, OSV) that a
scanner matched to a component. Each statement names the id, the affected component (a
BOM-Link into the SBOM when it has a serial number), its state, and the response /
detail the CycloneDX VEX and CISA "minimum requirements for VEX" ask for. A match is
``in_triage`` (CISA: under investigation): the version is in the advisory's range but
nobody has assessed whether the code is exploitable. ``not_affected`` is never asserted
without an id and a justification, so a component with no known vulnerability gets no
statement at all (it used to get a blanket ``not_affected`` with a made-up
``not-affected:<ref>`` id).

CBOM code scans: a weakness seen in the code (finding code) or a CVE matched from that
evidence is ``in_triage`` (the use is real, whether it protects anything exploitable
needs a person); only assets with no finding are ``not_affected``. A CBOM asset that
names a CVE is never reported as not affected.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

__all__ = ["SBOM_VEX_RULES", "build_vex", "is_current"]

# Stored SBOM / AI BOM VEX documents written by older rules (no or another value) are
# rebuilt (routers/certin.py).
SBOM_VEX_RULES = "sbom-2"
# Any OSV-schema advisory id Grype or an OSV source reports (review 6028132826 m3):
# CVE, GHSA, PYSEC, GO, RUSTSEC, OSV, GMS, CGA, DLA, DSA, ALSA, RHSA, MAL, USN, SUSE-SU,
# BIT ...: a letter-and-digit prefix, then dash-separated parts, at least one digit;
# ':' may appear inside (ALSA-2023:1234, SUSE-SU-2023:0001-1).
_ADVISORY = re.compile(
    r"^(?=.*\d)[A-Za-z][A-Za-z0-9]{1,15}(?:-[A-Za-z0-9][A-Za-z0-9.:_]*){1,6}$"
)
_UPPER_PREFIXES = frozenset({"CVE", "PYSEC", "GO", "RUSTSEC", "OSV"})
_UUID = re.compile(
    r"^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
    re.I,
)
_SEVERITIES = frozenset(
    {"critical", "high", "medium", "low", "info", "none", "unknown"}
)
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")

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
    """One entry per finding code and per CVE across the scan, listing the assets
    (bom-refs) they affect.
    """
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
        entry = _vuln_entry(
            vuln_id=f"ZS-CBOM-{code}",
            state="in_triage",
            affects_ref=None,
            detail="Seen in the source code or configuration; confirm whether it protects data that "
            "matters, then fix or record the exception.",
        )
        entry["affects"] = [{"ref": r} for r in dict.fromkeys(refs)]
        out.append(entry)
    for cid, refs in sorted(by_cve.items()):
        entry = _vuln_entry(
            vuln_id=cid,
            state="in_triage",
            affects_ref=None,
            detail="Matched from the algorithm or protocol the code uses; a match is not proof of "
            "exposure.",
        )
        entry["source"] = {
            "name": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        }
        entry["affects"] = [{"ref": r} for r in dict.fromkeys(refs)]
        out.append(entry)
    for ref in dict.fromkeys(clean):
        out.append(
            _vuln_entry(
                vuln_id=f"not-affected:{ref}",
                state="not_affected",
                affects_ref=ref,
                detail="No weakness or CVE found for this asset (CERT-In F5)",
            )
        )
    return out


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _product_version() -> str:
    """DevSecShield build (``DSS_BUILD_VERSION``, else the short ``DSS_BUILD_SHA``;
    backend/utilities/build_info).
    """
    version = (os.environ.get("DSS_BUILD_VERSION") or "").strip()
    if _VERSION.match(version):
        return version
    sha = (os.environ.get("DSS_BUILD_SHA") or "").strip().lower()
    return sha[:12] if re.fullmatch(r"[0-9a-f]{40}", sha) else "unknown"


def normalise_advisory_id(raw: Any) -> str | None:
    text = str(raw or "").strip()
    if len(text) > 80 or not _ADVISORY.match(text):
        return None
    head, _, body = text.partition("-")
    if head.upper() == "GHSA":
        return f"GHSA-{body.lower()}"
    return text.upper() if head.upper() in _UPPER_PREFIXES else text


def _bom_link(bom: dict[str, Any] | None, ref: str) -> str:
    """``urn:cdx:<serial>/<version>#<bom-ref>`` (CycloneDX BOM-Link) when the SBOM has a
    UUID serial, else the ref.
    """
    if not isinstance(bom, dict):
        return ref
    m = _UUID.match(str(bom.get("serialNumber") or ""))
    version = (
        bom.get("version")
        if isinstance(bom.get("version"), int) and bom.get("version") > 0
        else 1
    )
    return f"urn:cdx:{m.group(1).lower()}/{version}#{quote(ref, safe='')}" if m else ref


def _source_for(vid: str) -> dict[str, str]:
    if vid.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"}
    if vid.startswith("GHSA-"):
        return {
            "name": "GitHub Advisory Database",
            "url": f"https://github.com/advisories/{vid}",
        }
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"}


def _fix_of(vuln: dict[str, Any]) -> tuple[bool, str]:
    """(fixed version published, recommendation text) of the SBOM vulnerability."""
    text = str(vuln.get("recommendation") or "").strip()
    fixed = False
    for prop in vuln.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "dss:fix_state":
            fixed = str(prop.get("value") or "") == "fixed"
    return fixed, text


def _statements_from_bom(
    bom: dict[str, Any], first_issued: str, now: str
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    names = {
        str(c.get("bom-ref")): c
        for c in bom.get("components") or []
        if isinstance(c, dict)
    }
    for vuln in bom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        vid = normalise_advisory_id(vuln.get("id"))
        refs = [
            str(a.get("ref"))
            for a in vuln.get("affects") or []
            if isinstance(a, dict) and a.get("ref")
        ]
        if not vid or not refs:
            # no id or nothing affected: no statement (never a blanket not_affected)
            continue
        fixed, recommendation = _fix_of(vuln)
        props = {
            str(p.get("name")): str(p.get("value") or "")
            for p in vuln.get("properties") or []
            if isinstance(p, dict)
        }
        guessed = "dss:version_guessed_from" in props
        scanner = (
            "Grype"
            if props.get("dss:detected_by") == "grype"
            else "the SBOM scan's advisory lookup"
        )
        comps = ", ".join(
            " ".join(
                x
                for x in (
                    names.get(r, {}).get("name") or r,
                    names.get(r, {}).get("version"),
                )
                if x
            )
            for r in refs
        )
        detail = (
            f"{comps}: the version is in the advisory's affected range (matched by "
            f"{scanner}). Exploitability has not been assessed; "
            "triage it to exploitable, resolved, or not_affected with a justification."
        )
        if guessed:
            detail += (
                " The version was read from a version range in the manifest (its lower"
                " bound): pin and rescan."
            )
        entry: dict[str, Any] = {
            "id": vid,
            "source": vuln.get("source")
            if isinstance(vuln.get("source"), dict)
            else _source_for(vid),
            "affects": [],
            "analysis": {
                "state": "in_triage",
                "detail": detail,
                "firstIssued": first_issued,
                "lastUpdated": now,
            },
        }
        for ref in refs:
            comp = names.get(ref) or {}
            aff: dict[str, Any] = {"ref": _bom_link(bom, ref)}
            if comp.get("version"):
                aff["versions"] = [
                    {"version": str(comp["version"]), "status": "affected"}
                ]
            entry["affects"].append(aff)
        if fixed:
            entry["analysis"]["response"] = ["update"]
        if recommendation:
            entry["recommendation"] = recommendation
        for key in ("references", "ratings", "cwes", "description"):
            if vuln.get(key):
                entry[key] = json.loads(json.dumps(vuln[key]))
        out.append(entry)
    return out


def _statements_from_findings(
    findings: list[dict[str, Any]],
    bom: dict[str, Any] | None,
    first_issued: str,
    now: str,
) -> list[dict[str, Any]]:
    """Rows of a scan whose SBOM has no ``vulnerabilities`` (older scans): the ids
    the rows actually name.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(findings):
        if not isinstance(row, dict) or row.get("inventory_only"):
            continue
        ids = (
            [normalise_advisory_id(row.get("vuln_id"))]
            if row.get("vuln_id")
            else [normalise_advisory_id(c) for c in _cve_ids_from_finding(row)]
        )
        ref = str(row.get("purl") or "").split("?", 1)[0] or _dep_ref(row, i)
        impact = str(row.get("impact") or "").lower()
        for vid in (v for v in ids if v):
            entry = by_id.setdefault(
                vid,
                {
                    "id": vid,
                    "source": _source_for(vid),
                    "affects": [],
                    "analysis": {
                        "state": "in_triage",
                        "detail": (
                            "Named by the SBOM scan for this package; exploitability "
                            "has not been assessed."
                        ),
                        "firstIssued": first_issued,
                        "lastUpdated": now,
                    },
                },
            )
            if impact in _SEVERITIES:
                entry.setdefault("ratings", [{"severity": impact, "method": "other"}])
            link = {"ref": _bom_link(bom, ref)}
            if link not in entry["affects"]:
                entry["affects"].append(link)
            fix = str(row.get("suggested_fix") or "").strip()
            if fix and "recommendation" not in entry:
                entry["recommendation"] = fix
    return [by_id[k] for k in sorted(by_id)]


def is_current(vex: Any) -> bool:
    props = (
        ((vex.get("metadata") or {}).get("properties") or [])
        if isinstance(vex, dict)
        else []
    )
    return any(
        isinstance(p, dict)
        and p.get("name") == "zs:vex_rules"
        and p.get("value") == SBOM_VEX_RULES
        for p in props
    )


def _sbom_vex(
    bom: dict[str, Any] | None, findings: list[dict[str, Any]] | None, scan_type: str
) -> dict[str, Any]:
    now = _now()
    meta_in = (
        (bom or {}).get("metadata")
        if isinstance((bom or {}).get("metadata"), dict)
        else {}
    )
    first_issued = str(meta_in.get("timestamp") or now)
    if (
        isinstance(bom, dict)
        and isinstance(bom.get("vulnerabilities"), list)
        and bom["vulnerabilities"]
    ):
        statements = _statements_from_bom(bom, first_issued, now)
    else:
        statements = _statements_from_findings(findings or [], bom, first_issued, now)
    metadata: dict[str, Any] = {
        "timestamp": now,
        "authors": [{"name": "DevSecShield"}],
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "DevSecShield",
                    "version": _product_version(),
                    "publisher": "DevSecShield",
                }
            ]
        },
        "properties": [
            {"name": "zs:vex_rules", "value": SBOM_VEX_RULES},
            {"name": "zs:vex_scope", "value": scan_type},
            {
                "name": "certin:disclaimer",
                "value": (
                    "Advisory VEX alignment to CERT-In TG v2.0 and the CISA minimum "
                    "requirements for VEX: a statement for each matched advisory, none "
                    "for components with no known vulnerability. Does not constitute "
                    "CERT-In certification."
                ),
            },
        ],
    }
    subject = meta_in.get("component")
    if isinstance(subject, dict) and subject.get("name"):
        metadata["component"] = {
            k: subject[k]
            for k in ("type", "name", "version", "purl", "bom-ref")
            if subject.get(k)
        }
        metadata["component"].setdefault("type", "application")
    serial = str((bom or {}).get("serialNumber") or "")
    seed = (
        f"{serial}|{SBOM_VEX_RULES}|{json.dumps(sorted(s['id'] for s in statements))}"
    )
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": metadata,
        "vulnerabilities": statements,
    }


def build_vex(
    *,
    bom: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    scan_type: str = "sbom_sca",
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 VEX document.

    - SBOM / AI BOM: one statement per advisory id matched to a component
      (``bom.vulnerabilities``, else the finding rows' ids); nothing for components with
      no known vulnerability.
    - CBOM (direct callers only; the API builds CBOM VEX with
      ``cbom_sources.vex_semantics``): unchanged rules.
    """
    if scan_type != "cbom":
        return _sbom_vex(bom, findings, scan_type)

    vulnerabilities: list[dict[str, Any]] = []
    if findings:
        vulnerabilities = _cbom_vulnerabilities(findings)
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
                },
            ],
        },
        "vulnerabilities": vulnerabilities,
    }
