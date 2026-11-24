"""CERT-In VEX emit: a CycloneDX 1.6 VEX of the scan's real vulnerabilities (F5).

A VEX statement is about a vulnerability: it names one (a CVE / GHSA / OSV id), the
components it affects and an
analysis state. Rules (CycloneDX VEX, CISA "Minimum Requirements for VEX"):

* Only real vulnerability ids are emitted. A component with no known vulnerability gets
NO statement: the earlier
  ``not-affected:<component>`` stubs asserted "not affected" with a made-up id
  and no justification for every
  component of every SBOM / AI BOM, which is false assurance.
* A matched vulnerability is ``in_triage`` (the match is real; whether it is exploitable
here needs a person), unless
  the scan row carries an analysis of its own.
* ``not_affected`` is emitted only with a CycloneDX ``justification`` (e.g.
``code_not_reachable``); a row claiming
  not affected without one stays ``in_triage``.
* CBOM code scans: a weakness seen in the code (finding code) or a CVE matched from that
evidence is ``in_triage``
  (the backend builds CBOM code-scan VEX with ``cbom_sources/vex_semantics``; this
  branch is the fallback).
* AI BOM: the vulnerabilities the AI BOM itself records (``bom.vulnerabilities``) and
any finding row with a CVE.
* SBOM (FIX-C1, SOW D4): the SBOM's own ``vulnerabilities`` (one per Grype advisory) are
  the statements, each pointing at the component with a CycloneDX BOM-Link into ``/bom``
  (``urn:cdx:<serial>/<version>#<bom-ref>``) with the affected version, the scanner's
  detail (a version guessed from a manifest range says so), ``response: update`` when a
  fixed release exists, and first-issued / last-updated times. Ids are any OSV-style
  advisory id (CVE, GHSA, PYSEC, GO, RUSTSEC, OSV, GMS, CGA, ALSA, MAL, ...).

stdlib only (the backend loads this file without the aibom package).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import uuid
from typing import Any
from urllib.parse import quote

__all__ = [
    "build_vex",
    "VEX_RULES",
    "SBOM_VEX_RULES",
    "is_current",
    "normalise_advisory_id",
]

# : Version of these rules, stamped as ``zs:vex_rules``. A stored VEX written by older
# rules is rebuilt. certin-4: certin-3 (#487) plus the SBOM BOM-Link statements (#489).
VEX_RULES = "certin-4"
SBOM_VEX_RULES = VEX_RULES
# the CBOM fallback branch keeps its rule id (cbom_sources.vex_semantics owns CBOM VEX)
CBOM_VEX_RULES = "2"

_STATES = frozenset(
    {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
)
_JUSTIFICATIONS = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    }
)
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "none",
}
_VEX_NS = uuid.UUID("0f4d6c52-7a3e-4b8f-9d21-5c6e7f8a9b0c")
# Any OSV-schema advisory id Grype or an OSV source reports (review 6028132826 m3):
# CVE, GHSA, PYSEC, GO, RUSTSEC, OSV, GMS, CGA, DLA, DSA, ALSA, RHSA, MAL, USN, SUSE-SU,
# BIT ...: a letter-and-digit prefix, then dash-separated parts, at least one digit;
# ':' may appear inside (ALSA-2023:1234, SUSE-SU-2023:0001-1). A GHSA id is three groups
# of four from GitHub's alphabet, which may hold no digit at all (review 6032108510 m1).
_ADVISORY = re.compile(
    r"^(?=.*\d)[A-Za-z][A-Za-z0-9]{1,15}(?:-[A-Za-z0-9][A-Za-z0-9.:_]*){1,6}$"
)
_GHSA = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$", re.I)
_UPPER_PREFIXES = frozenset({"CVE", "PYSEC", "GO", "RUSTSEC", "OSV"})
_UUID = re.compile(
    r"^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}"
    r"-[0-9a-f]{12})$",
    re.I,
)


def normalise_advisory_id(raw: Any) -> str | None:
    """The advisory id in its canonical form (GHSA body lower-case, CVE / PYSEC / GO /
    RUSTSEC / OSV upper-case, others as given), or None for text that is not one."""
    text = str(raw or "").strip()
    if len(text) > 80 or not (_ADVISORY.match(text) or _GHSA.match(text)):
        return None
    head, _, body = text.partition("-")
    if head.upper() == "GHSA":
        return f"GHSA-{body.lower()}"
    return text.upper() if head.upper() in _UPPER_PREFIXES else text


def _bom_link(bom: dict[str, Any] | None, ref: str) -> str:
    """``urn:cdx:<serial>/<version>#<bom-ref>`` (CycloneDX BOM-Link) when the SBOM has a
    UUID serial, else the ref."""
    if not isinstance(bom, dict):
        return ref
    m = _UUID.match(str(bom.get("serialNumber") or ""))
    version = bom.get("version")
    version = version if isinstance(version, int) and version > 0 else 1
    return f"urn:cdx:{m.group(1).lower()}/{version}#{quote(ref, safe='')}" if m else ref


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
    for key in ("cve", "cve_id", "vulnerability_id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip() and value.strip() not in out:
            out.append(value.strip())
    return out


def _source(vuln_id: str) -> dict[str, str]:
    up = vuln_id.upper()
    if up.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"}
    if up.startswith("GHSA-"):
        return {"name": "GitHub", "url": f"https://github.com/advisories/{vuln_id}"}
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"}


def _component_refs(bom: dict[str, Any] | None) -> dict[str, str]:
    """name / name@version / purl (lower-case) -> bom-ref, so a statement points
    at the BOM's own component."""
    out: dict[str, str] = {}
    for comp in (bom or {}).get("components") or []:
        if not isinstance(comp, dict) or not comp.get("bom-ref"):
            continue
        ref = str(comp["bom-ref"])
        name = str(comp.get("name") or "").strip().lower()
        if comp.get("purl"):
            out.setdefault(str(comp["purl"]).lower(), ref)
        if name:
            if comp.get("version"):
                out.setdefault(f"{name}@{str(comp['version']).lower()}", ref)
            out.setdefault(name, ref)
    return out


def _affects_ref(row: dict[str, Any], index: int, refs: dict[str, str]) -> str:
    for key in ("bom_ref", "bom-ref"):
        if row.get(key):
            return str(row[key])
    if row.get("purl") and str(row["purl"]).lower() in refs:
        return refs[str(row["purl"]).lower()]
    dep = str(
        row.get("dependency")
        or row.get("package_name")
        or row.get("component_name")
        or ""
    ).strip()
    name = dep.split("@")[0].split("==")[0].strip()
    version = (
        str(row.get("version") or row.get("installed_version") or "").strip().lower()
    )
    for key in (f"{name.lower()}@{version}", name.lower()):
        if key in refs:
            return refs[key]
    return name or row.get("purl") or f"component-{index}"


def _analysis(row: dict[str, Any], detail: str) -> dict[str, Any]:
    """The row's own analysis when it states a valid one; else in_triage.
    not_affected needs a justification."""
    state = str(row.get("vex_state") or row.get("analysis_state") or "").strip().lower()
    justification = (
        str(row.get("vex_justification") or row.get("justification") or "")
        .strip()
        .lower()
    )
    if state == "not_affected" and justification not in _JUSTIFICATIONS:
        state = ""
    if state not in _STATES:
        return {"state": "in_triage", "detail": detail}
    out: dict[str, Any] = {
        "state": state,
        "detail": str(row.get("vex_detail") or detail),
    }
    if state == "not_affected":
        out["justification"] = justification
    return out


def _entry(
    vuln_id: str, analysis: dict[str, Any], refs: list[str], impact: str | None
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": vuln_id,
        "source": _source(vuln_id),
        "analysis": analysis,
        "affects": [{"ref": r} for r in dict.fromkeys(refs)],
    }
    severity = _SEVERITY.get(str(impact or "").strip().lower())
    if severity:
        entry["ratings"] = [
            {
                "source": {"name": "DevSecShield"},
                "severity": severity,
                "method": "other",
            }
        ]
    return entry


def _finding_vulnerabilities(
    findings: list[dict[str, Any]],
    bom: dict[str, Any] | None,
    *,
    advisories_only: bool = True,
) -> list[dict[str, Any]]:
    """One statement per id across the finding rows. An SBOM scan
    (``advisories_only``) keeps advisory ids only, in canonical form, and skips
    inventory rows; an AI BOM keeps every id its findings carry as given (#487),
    e.g. ``AI-SUPPLY-CHAIN``."""
    refs = _component_refs(bom)
    by_id: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(findings):
        if not isinstance(row, dict):
            continue
        if advisories_only and row.get("inventory_only"):
            continue
        if advisories_only:
            raw = [row["vuln_id"]] if row.get("vuln_id") else _cve_ids_from_finding(row)
            ids = [v for v in (normalise_advisory_id(r) for r in raw) if v]
        else:
            ids = _cve_ids_from_finding(row)
        if not ids:
            continue
        ref = _affects_ref(row, i, refs)
        detail = (
            "Matched to this component's name and version from the bill of "
            "materials; confirm whether the "
            "vulnerable code is used before closing it."
        )
        for vid in ids:
            if vid in by_id:
                by_id[vid]["affects"].append({"ref": ref})
                continue
            by_id[vid] = _entry(vid, _analysis(row, detail), [ref], row.get("impact"))
    for entry in by_id.values():
        entry["affects"] = [
            dict(t) for t in dict.fromkeys(tuple(a.items()) for a in entry["affects"])
        ]
    return [by_id[k] for k in sorted(by_id)]


def _bom_vulnerabilities(bom: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Vulnerabilities the BOM itself records (an AI BOM / SBOM with matched
    advisories), restated as VEX."""
    out: list[dict[str, Any]] = []
    for v in (bom or {}).get("vulnerabilities") or []:
        if not isinstance(v, dict) or not str(v.get("id") or "").strip():
            continue
        refs = [
            str(a.get("ref"))
            for a in v.get("affects") or []
            if isinstance(a, dict) and a.get("ref")
        ]
        if not refs:
            continue
        analysis = v.get("analysis") if isinstance(v.get("analysis"), dict) else {}
        row = {
            "vex_state": analysis.get("state"),
            "vex_justification": analysis.get("justification"),
            "vex_detail": analysis.get("detail"),
        }
        entry = _entry(
            str(v["id"]).strip(),
            _analysis(
                row,
                "Recorded in the bill of materials; confirm whether "
                "it is exploitable here.",
            ),
            refs,
            None,
        )
        if v.get("ratings"):
            entry["ratings"] = v["ratings"]
        out.append(entry)
    return out


_PEP440_OPS = ("===", "~=", "==", "!=", ">=", "<=", ">", "<")


def _release(version: str) -> tuple[int, ...] | None:
    parts = version.split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


def _vers_range(comp: dict[str, Any], constraint: str) -> str | None:
    """A PEP 440 requirement range as a ``vers`` range (``>=10.0,<13.0`` ->
    ``vers:pypi/>=10.0|<13.0``), or None when it cannot be written as one."""
    purl = str(comp.get("purl") or "")
    eco = purl[4:].split("/", 1)[0].lower() if purl.startswith("pkg:") else ""
    spec = str(constraint or "").split(";", 1)[0].replace(" ", "")
    if eco != "pypi" or not spec:
        return None
    out: list[tuple[str, str]] = []
    for part in spec.split(","):
        op = next((o for o in _PEP440_OPS if part.startswith(o)), "")
        ver = part[len(op) :]
        if not op or not ver or op == "===":
            return None
        if op in {"==", "~="} or ver.endswith(".*"):
            base = ver[:-2] if ver.endswith(".*") else ver
            rel = _release(base)
            if op == "!=" or rel is None or (op == "~=" and len(rel) < 2):
                return None
            if op == "==" and not ver.endswith(".*"):
                out.append(("", ver))
                continue
            top = rel[:-1] if op == "~=" else rel
            upper = ".".join(str(x) for x in (*top[:-1], top[-1] + 1))
            out += [(">=", base), ("<", upper)]
        else:
            out.append((op, ver))
    if not out:
        return None
    keys = [_release(v) for _, v in out]
    if all(k is not None for k in keys):
        out = [c for _, c in sorted(zip(keys, out, strict=True))]
    return "vers:pypi/" + "|".join(f"{op}{quote(v, safe='.')}" for op, v in out)


def _sbom_bom_vulnerabilities(
    bom: dict[str, Any], first_issued: str, now: str
) -> list[dict[str, Any]]:
    """An SBOM's own vulnerabilities (one per Grype advisory, sbom_cyclonedx.py) as VEX
    statements with BOM-Links into ``/bom`` (FIX-C1, SOW D4)."""
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
            continue  # no id or nothing affected: no statement
        props = {
            str(p.get("name")): str(p.get("value") or "")
            for p in vuln.get("properties") or []
            if isinstance(p, dict)
        }
        scanner = (
            "Grype"
            if props.get("dss:detected_by") == "grype"
            else "the SBOM scan's advisory lookup"
        )
        comps = ", ".join(
            " ".join(
                str(x)
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
            f"{scanner}). Exploitability has not been assessed; triage it to "
            "exploitable, resolved, or not_affected with a justification."
        )
        if "dss:version_guessed_from" in props:
            detail += (
                " The version was read from a version range in the manifest (its "
                "lower bound): pin and rescan."
            )
        given = vuln.get("analysis") if isinstance(vuln.get("analysis"), dict) else {}
        analysis = _analysis(
            {
                "vex_state": given.get("state"),
                "vex_justification": given.get("justification"),
                "vex_detail": given.get("detail"),
            },
            detail,
        )
        analysis["firstIssued"] = first_issued
        analysis["lastUpdated"] = now
        if props.get("dss:fix_state") == "fixed":
            analysis["response"] = ["update"]
        entry: dict[str, Any] = {
            "id": vid,
            "source": vuln.get("source")
            if isinstance(vuln.get("source"), dict)
            else _source(vid),
            "analysis": analysis,
            "affects": [],
        }
        for ref in refs:
            comp = names.get(ref) or {}
            aff: dict[str, Any] = {"ref": _bom_link(bom, ref)}
            if "dss:version_guessed_from" in props:
                # the installed version is not known, only the manifest's range
                # (review 6032108510 m3): state the range, status unknown
                vers = _vers_range(comp, props["dss:version_guessed_from"])
                if vers:
                    aff["versions"] = [{"range": vers, "status": "unknown"}]
                elif comp.get("version"):
                    aff["versions"] = [
                        {"version": str(comp["version"]), "status": "unknown"}
                    ]
            elif comp.get("version"):
                aff["versions"] = [
                    {"version": str(comp["version"]), "status": "affected"}
                ]
            entry["affects"].append(aff)
        if vuln.get("recommendation"):
            entry["recommendation"] = str(vuln["recommendation"])
        for key in ("references", "ratings", "cwes", "description"):
            if vuln.get(key):
                entry[key] = json.loads(json.dumps(vuln[key]))
        out.append(entry)
    return out


def _cbom_vulnerabilities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per finding code and per CVE across the scan, listing the
    assets (bom-refs) they affect."""
    by_code: dict[str, list[str]] = {}
    by_cve: dict[str, list[str]] = {}
    for i, row in enumerate(findings):
        if not isinstance(row, dict):
            continue
        ref = str(row.get("bom_ref") or row.get("bom-ref") or f"component-{i}")
        for code in [c for c in row.get("finding_codes") or [] if isinstance(c, str)]:
            by_code.setdefault(code, []).append(ref)
        for cid in _cve_ids_from_finding(row):
            by_cve.setdefault(cid, []).append(ref)
    out: list[dict[str, Any]] = []
    for code, refs in sorted(by_code.items()):
        entry = _entry(
            f"ZS-CBOM-{code}",
            {
                "state": "in_triage",
                "detail": (
                    "Seen in the source code or configuration; confirm whether it "
                    "protects data that matters, then fix or "
                    "record the exception."
                ),
            },
            refs,
            None,
        )
        entry["source"] = {"name": "DevSecShield CBOM rules"}
        out.append(entry)
    for cid, refs in sorted(by_cve.items()):
        out.append(
            _entry(
                cid,
                {
                    "state": "in_triage",
                    "detail": (
                        "Matched from the algorithm or protocol the code uses; a "
                        "match is not proof of exposure."
                    ),
                },
                refs,
                None,
            )
        )
    return out


def _iso_now() -> str:
    return (
        _dt.datetime.now(_dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_vex(
    *,
    bom: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    scan_type: str = "sbom_sca",
    now: str | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 VEX document of the scan's real vulnerabilities (see
    the module docstring).

    No vulnerability -> an empty ``vulnerabilities`` list (honest: nothing to state),
    never per-component stubs.
    """
    if scan_type == "cbom":
        vulnerabilities = _cbom_vulnerabilities(findings or [])
        rules = CBOM_VEX_RULES
    else:
        stamp = now or _iso_now()
        meta_in = (bom or {}).get("metadata")
        first_issued = str(
            (meta_in.get("timestamp") if isinstance(meta_in, dict) else None) or stamp
        )
        # an SBOM's own Grype statements (with BOM-Links) are authoritative for their
        # ids; an AI BOM's recorded ones are merged with its findings' affects, as
        # #487 does (review 6032108510 m1)
        sbom = scan_type == "sbom_sca" and isinstance(bom, dict)
        own = (
            _sbom_bom_vulnerabilities(bom, first_issued, stamp)
            if sbom
            else _bom_vulnerabilities(bom)
        )
        authoritative = {e["id"] for e in own} if sbom else set()
        merged: dict[str, dict[str, Any]] = {e["id"]: e for e in own}
        for entry in _finding_vulnerabilities(
            findings or [], bom, advisories_only=scan_type == "sbom_sca"
        ):
            if entry["id"] in authoritative:
                continue
            if entry["id"] in merged:
                merged[entry["id"]]["affects"] += [
                    a
                    for a in entry["affects"]
                    if a not in merged[entry["id"]]["affects"]
                ]
            else:
                merged[entry["id"]] = entry
        vulnerabilities = [merged[k] for k in sorted(merged)]
        rules = VEX_RULES
    digest = hashlib.sha256(
        json.dumps(vulnerabilities, sort_keys=True).encode()
    ).hexdigest()
    subject = (bom or {}).get("serialNumber") or ""
    states: dict[str, int] = {}
    for v in vulnerabilities:
        states[v["analysis"]["state"]] = states.get(v["analysis"]["state"], 0) + 1
    seed = f"{scan_type}:{subject}:{rules}:{digest}"
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_VEX_NS, seed)}",
        "version": 1,
        "metadata": {
            "timestamp": now or _iso_now(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "DevSecShield CERT-In VEX",
                        "version": rules,
                    }
                ]
            },
            "properties": [
                {"name": "zs:vex_rules", "value": rules},
                *[
                    {"name": f"zs:entries_{state}", "value": str(n)}
                    for state, n in sorted(states.items())
                ],
                {
                    "name": "certin:disclaimer",
                    "value": (
                        "Advisory VEX alignment to CERT-In TG v2.0. Lists only real "
                        "vulnerability identifiers matched for this scan; matched "
                        "vulnerabilities are in triage until analysed, and "
                        "not_affected is stated only with a justification. "
                        "Components without a known vulnerability carry no "
                        "statement. Does not constitute CERT-In certification."
                    ),
                },
            ],
        },
        "vulnerabilities": vulnerabilities,
    }
    if scan_type != "cbom":
        # the VEX's own provenance and subject (CISA minimum elements: author, tool,
        # product): DevSecShield with its build version, and the BOM's subject
        doc["metadata"]["authors"] = [{"name": "DevSecShield"}]
        doc["metadata"]["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": "DevSecShield",
                    "version": _product_version(),
                    "publisher": "DevSecShield",
                    "description": f"CERT-In VEX rules {rules}",
                }
            ]
        }
        meta_in = (bom or {}).get("metadata")
        subject = meta_in.get("component") if isinstance(meta_in, dict) else None
        if isinstance(subject, dict) and subject.get("name"):
            component = {
                k: subject[k]
                for k in ("type", "name", "version", "purl", "bom-ref")
                if subject.get(k)
            }
            component.setdefault("type", "application")
            doc["metadata"]["component"] = component
    return doc


def _product_version() -> str:
    """DevSecShield build (``DSS_BUILD_VERSION``, else the short ``DSS_BUILD_SHA``)."""
    version = (os.environ.get("DSS_BUILD_VERSION") or "").strip()
    if re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}", version):
        return version
    sha = (os.environ.get("DSS_BUILD_SHA") or "").strip().lower()
    return sha[:12] if re.fullmatch(r"[0-9a-f]{40}", sha) else "unknown"


def is_current(*args: Any) -> bool:
    """``is_current(scan_type, vex)`` (or ``is_current(vex)`` for an SBOM / AI BOM VEX):
    a stored VEX written by older rules (per-component not_affected stubs, certin-3
    without the SBOM BOM-Links) is rebuilt."""
    scan_type, vex = (args[0], args[1]) if len(args) == 2 else ("sbom_sca", args[0])
    props = (
        ((vex.get("metadata") or {}).get("properties") or [])
        if isinstance(vex, dict)
        else []
    )
    want = CBOM_VEX_RULES if scan_type == "cbom" else VEX_RULES
    return any(
        isinstance(p, dict)
        and p.get("name") == "zs:vex_rules"
        and p.get("value") == want
        for p in props
    )
