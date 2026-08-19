"""Industry CycloneDX SBOM sanitizer — one advisory Pass/Fail field.

Strips Syft/tool noise and per-framework ``dss:compliance.*`` dumps so the
downloadable document matches CycloneDX/bom-examples. Detailed RBI/SEBI/CERT-In
coverage stays on the dashboard and PDF, not in this JSON.
"""
from __future__ import annotations

import copy
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from backend.utilities.compliance.sbom_identity import parse_pkg
from backend.utilities.compliance import sbom_advisory, sbom_registry

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_LICENSE_REF = re.compile(r"^LicenseRef-", re.I)
_HIGH_IMPACT = frozenset({"critical", "high"})
_HIGH_LICENSE = frozenset(
    {"strong_copyleft", "network_copyleft", "source_available"}
)
_SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_HASH_ALG = {
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "md5": "MD5",
}
_PURL_SUPPLIER = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "golang": "Go",
    "gem": "RubyGems",
    "hex": "Hex",
    "composer": "Packagist",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "RPM",
    "github": "GitHub",
}
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)
_SYFT_LOC = re.compile(r"^syft:location:\d+:path$")


def _canonical_purl(purl: str) -> str:
    raw = (purl or "").strip()
    return raw.split("?", 1)[0] if raw else ""


def _identity_key(comp: dict[str, Any]) -> str:
    purl = _canonical_purl(str(comp.get("purl") or ""))
    if purl:
        return purl.lower()
    name = str(comp.get("name") or "").strip().lower()
    version = str(comp.get("version") or "").strip().lower()
    return f"{name}@{version}" if name else ""


def _syft_locations(comp: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for prop in comp.get("properties") or []:
        if not isinstance(prop, dict) or not _SYFT_LOC.match(str(prop.get("name") or "")):
            continue
        loc = str(prop.get("value") or "").strip()
        if loc and loc not in seen:
            seen.add(loc)
            out.append(loc)
    existing = (comp.get("evidence") or {}).get("occurrences") if isinstance(comp.get("evidence"), dict) else None
    if isinstance(existing, list):
        for item in existing:
            loc = str((item or {}).get("location") or "").strip() if isinstance(item, dict) else ""
            if loc and loc not in seen:
                seen.add(loc)
                out.append(loc)
    return out


def _github_org(purl: str) -> str | None:
    body = _canonical_purl(purl)
    if not body.startswith("pkg:github/"):
        return None
    rest = body[len("pkg:github/") :].split("@", 1)[0]
    org = rest.split("/")[0].strip()
    return org or None


def _curated_spdx(name: str) -> str | None:
    raw = (name or "").strip()
    if not raw:
        return None
    try:
        from backend.utilities.dashboard.sbom_license import resolve_package_spdx

        mapped = resolve_package_spdx(raw)
        if mapped:
            return mapped
        if "/" in raw:
            return resolve_package_spdx(raw.rsplit("/", 1)[-1])
    except Exception:
        return None
    return None


_COMPONENT_KEYS = (
    "type",
    "mime-type",
    "bom-ref",
    "author",
    "publisher",
    "group",
    "version",
    "description",
    "scope",
    "copyright",
    "cpe",
    "purl",
    "omniborId",
    "swhid",
    "swid",
    "pedigree",
    "externalReferences",
    "tags",
)


def overall_verdict(compliance: dict[str, Any] | None) -> str:
    if not isinstance(compliance, dict) or not compliance:
        return "unknown"
    fails = 0
    passes = 0
    for fw, block in compliance.items():
        if fw == "disclaimer" or not isinstance(block, dict):
            continue
        if int(block.get("fail") or 0) > 0:
            fails += 1
        elif int(block.get("pass") or 0) + int(block.get("pass_with_evidence") or 0) > 0:
            passes += 1
    if fails:
        return "fail"
    if passes:
        return "pass"
    return "unknown"


def component_verdict(row: dict[str, Any] | None) -> str:
    if not isinstance(row, dict):
        return "pass"
    impact = str(row.get("impact") or "").strip().lower()
    license_type = str(row.get("license_type") or "").strip().lower()
    if impact in _HIGH_IMPACT or license_type in _HIGH_LICENSE:
        return "fail"
    return "pass"


def _parse_name_version(dep: str) -> tuple[str, str]:
    ident = parse_pkg(dependency=dep)
    return ident.name, ident.version


def _index_findings(
    findings: list[Any] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_purl: dict[str, dict[str, Any]] = {}
    by_nv: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for row in findings or []:
        if not isinstance(row, dict):
            continue
        ident = parse_pkg(
            dependency=str(row.get("dependency") or row.get("package_name") or ""),
            purl=str(row.get("purl") or "") if isinstance(row.get("purl"), str) else "",
        )
        if ident.purl:
            by_purl[ident.purl.lower()] = row
        if ident.name:
            by_name[ident.name.lower()] = row
            if ident.version:
                by_nv[f"{ident.name.lower()}@{ident.version}"] = row
    return by_purl, by_nv, by_name


def _match_finding(
    comp: dict[str, Any],
    indexes: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
    ],
) -> dict[str, Any] | None:
    by_purl, by_nv, by_name = indexes
    ident = parse_pkg(
        name=str(comp.get("name") or ""),
        version=str(comp.get("version") or ""),
        purl=str(comp.get("purl") or ""),
        dependency=str((comp.get("name") or "")),
    )
    name = ident.name.lower()
    version = ident.version
    purl = ident.purl.lower()
    return by_purl.get(purl) or by_nv.get(f"{name}@{version}") or by_name.get(name)


def keep_software_component(comp: dict[str, Any]) -> bool:
    name = str(comp.get("name") or "").strip()
    if not name:
        return False
    ctype = str(comp.get("type") or "library").lower()
    purl = str(comp.get("purl") or "").strip()
    if ctype == "file" and not purl:
        return False
    if name.startswith("/tmp/") and not purl:
        return False
    return True


def _clean_subject_name(name: str, subject: str | None) -> str:
    raw = (name or "").strip()
    if raw.startswith("/tmp/"):
        if subject:
            return subject
        base = raw.rstrip("/").rsplit("/", 1)[-1]
        if base.startswith("repo__"):
            return "application"
        return base or "application"
    return raw or (subject or "")


def _usable_license_list(existing: Any) -> list[dict[str, Any]] | None:
    if not isinstance(existing, list) or not existing:
        return None
    out: list[dict[str, Any]] = []
    for item in existing:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else None
        expr = str(item.get("expression") or "").strip()
        token = ""
        if lic:
            token = str(lic.get("id") or lic.get("name") or "").strip()
        elif expr:
            token = expr
        low = token.lower()
        if not token or low in {"noassertion", "none", "unknown", "not_declared"}:
            continue
        if _LICENSE_REF.match(token):
            continue
        out.append(copy.deepcopy(item))
    return out or None


def _license_objects(comp: dict[str, Any], row: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    existing = _usable_license_list(comp.get("licenses"))
    if existing:
        return existing
    lic = str((row or {}).get("license") or "").strip()
    if lic and not _LICENSE_REF.match(lic) and lic.lower() not in {"not_declared", "noassertion", "none", "unknown"}:
        if _SPDX_ID.match(lic):
            return [{"license": {"id": lic}}]
        return [{"license": {"name": lic[:200]}}]
    mapped = _curated_spdx(str(comp.get("name") or ""))
    if mapped:
        return [{"license": {"id": mapped}}]
    org = _github_org(str(comp.get("purl") or ""))
    if org in {"actions", "github", "pypa"}:
        return [{"license": {"id": "MIT"}}]
    return None


def _hashes(comp: dict[str, Any], row: dict[str, Any] | None) -> list[dict[str, str]] | None:
    existing = comp.get("hashes")
    if isinstance(existing, list) and existing:
        return copy.deepcopy(existing)
    raw = str((row or {}).get("hash") or "").strip()
    if raw:
        alg = "SHA-256"
        content = raw
        if ":" in raw:
            left, _, right = raw.partition(":")
            if right.strip():
                alg = left.strip()
                content = right.strip()
        alg = _HASH_ALG.get(alg.lower(), alg)
        if content:
            return [{"alg": alg, "content": content}]
    version = str(comp.get("version") or "").strip()
    if _GIT_SHA.match(version):
        return [{"alg": "SHA-1", "content": version.lower()}]
    return None


def _supplier(comp: dict[str, Any], row: dict[str, Any] | None) -> dict[str, Any] | None:
    purl = str(comp.get("purl") or "")
    if _github_org(purl):
        return {"name": "GitHub"}
    existing = comp.get("supplier")
    if isinstance(existing, dict) and str(existing.get("name") or "").strip():
        name = str(existing["name"]).strip()
        if name.lower() not in {"actions", "github"}:
            return copy.deepcopy(existing)
    if isinstance(existing, str) and existing.strip():
        return {"name": existing.strip()}
    pub = str(comp.get("publisher") or "").strip()
    if pub:
        return {"name": pub}
    if isinstance(row, dict):
        s = row.get("supplier")
        if isinstance(s, str) and s.strip():
            return {"name": s.strip()}
        if isinstance(s, dict) and s.get("name"):
            return copy.deepcopy(s)
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("@", 1)[0].split("?", 1)[0]
    ptype, _, rest = body.partition("/")
    key = ptype.lower()
    if key == "maven" and "/" in rest:
        return {"name": rest.rsplit("/", 1)[0]}
    label = _PURL_SUPPLIER.get(key)
    if label:
        return {"name": label}
    if rest:
        ns = rest.split("/")[0].replace("%40", "@")
        if ns:
            return {"name": ns}
    return None


def _author(comp: dict[str, Any]) -> str | None:
    org = _github_org(str(comp.get("purl") or ""))
    if org:
        return org
    for key in ("author", "publisher"):
        val = str(comp.get(key) or "").strip()
        if val and val.lower() != "devsecshield":
            return val
    return None


def _cve_ids(row: dict[str, Any] | None) -> list[str]:
    if not isinstance(row, dict):
        return []
    cves = row.get("cves")
    raw_ids: list[str] = []
    if isinstance(cves, dict):
        raw_ids.extend(str(k) for k in cves)
    elif isinstance(cves, list):
        for item in cves:
            if isinstance(item, str):
                raw_ids.append(item)
            elif isinstance(item, dict):
                raw_ids.append(str(item.get("id") or item.get("cve") or ""))
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_ids:
        m = _CVE_RE.search(raw)
        if not m:
            continue
        cve = m.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _cve_severity(row: dict[str, Any] | None, cve_id: str) -> str:
    impact = str((row or {}).get("impact") or "medium").lower()
    cves = (row or {}).get("cves") if isinstance(row, dict) else None
    if isinstance(cves, dict):
        info = cves.get(cve_id) or cves.get(cve_id.lower())
        if isinstance(info, dict) and info.get("severity"):
            impact = str(info["severity"]).lower()
    allowed = {"critical", "high", "medium", "low", "info", "none", "unknown"}
    return impact if impact in allowed else "medium"


def _clean_component(
    comp: dict[str, Any], row: dict[str, Any] | None, verdict: str
) -> dict[str, Any]:
    ident = parse_pkg(
        name=str(comp.get("name") or ""),
        version=str(comp.get("version") or ""),
        purl=str(comp.get("purl") or ""),
        dependency=str((row or {}).get("dependency") or ""),
    )
    out: dict[str, Any] = {
        "name": ident.name or str(comp.get("name") or "").strip(),
        "type": str(comp.get("type") or "library"),
    }
    for key in _COMPONENT_KEYS:
        if key in {"bom-ref", "purl", "author", "supplier", "version"}:
            continue
        if key in comp and comp[key] not in (None, "", [], {}):
            out[key] = copy.deepcopy(comp[key])
    if ident.version:
        out["version"] = ident.version
    elif comp.get("version"):
        out["version"] = str(comp["version"])
    purl = ident.purl or _canonical_purl(str(comp.get("purl") or ""))
    if purl:
        out["purl"] = purl
        out["bom-ref"] = purl
    elif comp.get("bom-ref"):
        out["bom-ref"] = str(comp["bom-ref"]).split("?", 1)[0]
    licenses = _license_objects({**comp, "name": out["name"], "purl": out.get("purl")}, row)
    if licenses:
        out["licenses"] = licenses
    hashes = _hashes(comp, row)
    if hashes:
        out["hashes"] = hashes
    supplier = _supplier({**comp, "purl": out.get("purl") or ""}, row)
    if supplier:
        out["supplier"] = supplier
    author = _author({**comp, "purl": out.get("purl") or ""})
    if author:
        out["author"] = author
    locs = _syft_locations(comp)
    if locs:
        out["evidence"] = {"occurrences": [{"location": loc} for loc in locs]}
    props: list[dict[str, Any]] = [{"name": "dss:compliance", "value": verdict}]
    for prop in comp.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        if str(prop.get("name") or "") == "declared:depends":
            props.append({"name": "declared:depends", "value": str(prop.get("value") or "")})
    out["properties"] = props
    return out


def _merge_component(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for field in ("licenses", "hashes", "author", "supplier", "publisher"):
        if not dst.get(field) and src.get(field):
            dst[field] = copy.deepcopy(src[field])
    dst_locs = {
        str(o.get("location"))
        for o in ((dst.get("evidence") or {}).get("occurrences") or [])
        if isinstance(o, dict)
    }
    extra = []
    for o in ((src.get("evidence") or {}).get("occurrences") or []):
        if not isinstance(o, dict):
            continue
        loc = str(o.get("location") or "")
        if loc and loc not in dst_locs:
            dst_locs.add(loc)
            extra.append({"location": loc})
    if extra:
        occ = list(((dst.get("evidence") or {}).get("occurrences") or []))
        occ.extend(extra)
        dst["evidence"] = {"occurrences": occ}
    src_v = None
    for p in src.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == "dss:compliance":
            src_v = str(p.get("value") or "")
    if src_v == "fail":
        dst["properties"] = [{"name": "dss:compliance", "value": "fail"}]


def _dedupe_components(comps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    passthrough: list[dict[str, Any]] = []
    for comp in comps:
        key = _identity_key(comp)
        if not key:
            passthrough.append(comp)
            continue
        if key not in merged:
            merged[key] = comp
            order.append(key)
        else:
            _merge_component(merged[key], comp)
    return [merged[k] for k in order] + passthrough


def _clean_metadata_component(raw: Any, subject: str | None) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        if subject:
            return {"type": "application", "name": subject}
        return None
    out: dict[str, Any] = {}
    for key in ("type", "name", "version", "bom-ref", "purl", "group"):
        if raw.get(key) not in (None, ""):
            out[key] = raw[key]
    name = _clean_subject_name(str(out.get("name") or ""), subject)
    if name:
        out["name"] = name
    out.setdefault("type", "application")
    return out


def _clean_dependencies(
    deps: Any, valid_refs: set[str]
) -> list[dict[str, Any]] | None:
    if not isinstance(deps, list) or not deps:
        return None
    cleaned: list[dict[str, Any]] = []
    for item in deps:
        if not isinstance(item, dict):
            continue
        ref = str(item.get("ref") or "").split("?", 1)[0]
        kids = [
            str(x).split("?", 1)[0]
            for x in (item.get("dependsOn") or [])
            if str(x).split("?", 1)[0] in valid_refs
        ]
        if ref not in valid_refs and not kids:
            continue
        row: dict[str, Any] = {"ref": ref}
        if kids:
            row["dependsOn"] = kids
        cleaned.append(row)
    return cleaned or None


def _cve_mentions_package(row: dict[str, Any] | None, cve_id: str, package: str) -> bool:
    token = re.sub(r"[-_.]+", "-", (package or "").strip().lower()).strip("-")
    if len(token) < 3 or not isinstance(row, dict):
        return False
    cves = row.get("cves")
    desc = ""
    if isinstance(cves, dict):
        info = cves.get(cve_id) or cves.get(cve_id.lower())
        if isinstance(info, str):
            desc = info
        elif isinstance(info, dict):
            desc = str(info.get("description") or info.get("summary") or "")
    hay = desc.lower()
    alts = {token, token.replace("-", ""), token.replace("-", " ")}
    return any(a and a in hay for a in alts)


def _polluted_cves(findings: list[Any] | None) -> set[str]:
    rows = [r for r in findings or [] if isinstance(r, dict)]
    if len(rows) < 3:
        return set()
    counts: dict[str, int] = {}
    for row in rows:
        for cve in _cve_ids(row):
            counts[cve] = counts.get(cve, 0) + 1
    floor = max(3, int(0.8 * len(rows)))
    return {cve for cve, n in counts.items() if n >= floor}


def _declared_depends(comp: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for prop in comp.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == "declared:depends":
            out.extend(part.strip() for part in str(prop.get("value") or "").split(",") if part.strip())
    return out


def _has_declared_prop(comp: dict[str, Any]) -> bool:
    return any(
        isinstance(p, dict) and p.get("name") == "declared:depends"
        for p in (comp.get("properties") or [])
    )


def _row_complete(comp: dict[str, Any]) -> bool:
    ver = str(comp.get("version") or "").strip()
    if not ver or "/" in ver:
        return False
    return bool(
        comp.get("author")
        and comp.get("hashes")
        and _usable_license_list(comp.get("licenses"))
        and _has_declared_prop(comp)
    )


def _lookup_name_version(comp: dict[str, Any]) -> tuple[str | None, str, str]:
    ident = parse_pkg(
        name=str(comp.get("name") or ""),
        version=str(comp.get("version") or ""),
        purl=str(comp.get("purl") or ""),
    )
    name = ident.name
    version = ident.version
    purl = ident.purl or str(comp.get("purl") or "")
    if "@" in purl:
        pver = purl.rsplit("@", 1)[-1]
        if "/" in pver:
            version = pver
    if ident.ecosystem == "github" and purl.startswith("pkg:github/"):
        name = purl[len("pkg:github/") :].split("@", 1)[0]
    return ident.ecosystem, name, version


def _needs_registry(comp: dict[str, Any]) -> bool:
    if _row_complete(comp):
        return False
    eco, name, _ver = _lookup_name_version(comp)
    return bool(eco in {"pypi", "npm", "github", "maven", "nuget", "cargo", "golang"} and name)


def _apply_registry(comp: dict[str, Any]) -> None:
    eco, name, version = _lookup_name_version(comp)
    meta = sbom_registry.lookup_package(eco, name, version)
    if not meta:
        return
    resolved = str(meta.get("version") or "").strip()
    cur = str(comp.get("version") or "").strip()
    if resolved and (not cur or "/" in version):
        comp["version"] = resolved
        purl = str(comp.get("purl") or "")
        if purl.startswith("pkg:") and "@" in purl:
            new_purl = f"{purl.rsplit('@', 1)[0]}@{resolved}"
            comp["purl"] = new_purl
            comp["bom-ref"] = new_purl
    if meta.get("author") and not comp.get("author"):
        comp["author"] = str(meta["author"])
    if meta.get("license") and not _usable_license_list(comp.get("licenses")):
        comp["licenses"] = [{"license": {"id": str(meta["license"])}}]
    hashed = meta.get("hash")
    if hashed and not comp.get("hashes"):
        alg, content = hashed
        if content:
            comp["hashes"] = [{"alg": str(alg), "content": str(content)}]
    if "depends" in meta and not _has_declared_prop(comp):
        depends = [str(x).strip() for x in (meta.get("depends") or []) if str(x).strip()]
        props = list(comp.get("properties") or [])
        props.append({"name": "declared:depends", "value": ", ".join(depends)})
        comp["properties"] = props


def _graph_from_declared(comps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for comp in comps:
        name = str(comp.get("name") or "").strip().lower()
        if name and name not in by_name:
            by_name[name] = comp
    out: list[dict[str, Any]] = []
    for comp in comps:
        ref = str(comp.get("bom-ref") or "")
        if not ref:
            continue
        kids: list[str] = []
        seen: set[str] = set()
        for dep_name in _declared_depends(comp):
            child = by_name.get(dep_name.lower())
            child_ref = str((child or {}).get("bom-ref") or "")
            if child_ref and child_ref not in seen and child_ref != ref:
                seen.add(child_ref)
                kids.append(child_ref)
        if kids:
            out.append({"ref": ref, "dependsOn": kids})
    return out


def _vulnerabilities(
    comps: list[dict[str, Any]],
    indexes: tuple[
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
        dict[str, dict[str, Any]],
    ],
    *,
    polluted: set[str] | None = None,
) -> list[dict[str, Any]]:
    skip = polluted or set()
    by_cve: dict[str, dict[str, Any]] = {}
    for comp in comps:
        row = _match_finding(comp, indexes)
        ref = str(comp.get("bom-ref") or comp.get("purl") or "")
        name = str(comp.get("name") or "")
        for cve in _cve_ids(row):
            if cve in skip and not _cve_mentions_package(row, cve, name):
                continue
            bucket = by_cve.setdefault(cve, {"refs": [], "severity": _cve_severity(row, cve)})
            if ref and ref not in bucket["refs"]:
                bucket["refs"].append(ref)
    out: list[dict[str, Any]] = []
    for cve in sorted(by_cve):
        info = by_cve[cve]
        item: dict[str, Any] = {
            "id": cve,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            "ratings": [{"severity": info["severity"], "method": "other"}],
        }
        if info["refs"]:
            item["affects"] = [{"ref": r} for r in info["refs"]]
        out.append(item)
    return out


def sanitize_industry_sbom(
    bom: dict[str, Any] | None,
    *,
    compliance: dict[str, Any] | None = None,
    findings: list[Any] | None = None,
    subject_name: str | None = None,
) -> dict[str, Any]:
    src = copy.deepcopy(bom) if isinstance(bom, dict) else {}
    verdict = overall_verdict(compliance)
    indexes = _index_findings(findings)
    spec = str(src.get("specVersion") or "1.6")
    meta_in = src.get("metadata") if isinstance(src.get("metadata"), dict) else {}
    meta: dict[str, Any] = {}
    if meta_in.get("timestamp"):
        meta["timestamp"] = meta_in["timestamp"]
    else:
        meta["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if meta_in.get("tools"):
        meta["tools"] = copy.deepcopy(meta_in["tools"])
    if meta_in.get("authors"):
        meta["authors"] = copy.deepcopy(meta_in["authors"])
    else:
        meta["authors"] = [{"name": "DevSecShield"}]
    cleaned_subject = _clean_metadata_component(meta_in.get("component"), subject_name)
    if cleaned_subject:
        meta["component"] = cleaned_subject
    meta["properties"] = [{"name": "dss:compliance", "value": verdict}]

    components: list[dict[str, Any]] = []
    for raw in src.get("components") or []:
        if not isinstance(raw, dict) or not keep_software_component(raw):
            continue
        row = _match_finding(raw, indexes)
        components.append(
            _clean_component(raw, row, component_verdict(row) if row else "pass")
        )

    components = _dedupe_components(components)
    need = [c for c in components if _needs_registry(c)]
    if need:
        workers = min(8, len(need))
        if workers == 1:
            _apply_registry(need[0])
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(_apply_registry, need))
    valid_refs = {str(c.get("bom-ref") or c.get("purl") or "") for c in components}
    valid_refs.discard("")
    if cleaned_subject and cleaned_subject.get("bom-ref"):
        valid_refs.add(str(cleaned_subject["bom-ref"]))

    out: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": spec if spec in {"1.4", "1.5", "1.6", "1.7"} else "1.6",
        "serialNumber": str(src.get("serialNumber") or f"urn:uuid:{uuid4()}"),
        "version": src.get("version") if isinstance(src.get("version"), int) else 1,
        "metadata": meta,
        "components": components,
    }
    if src.get("$schema"):
        out["$schema"] = src["$schema"]
    deps = _clean_dependencies(src.get("dependencies"), valid_refs) or []
    seen_refs = {d.get("ref") for d in deps}
    for extra in _graph_from_declared(components):
        if extra.get("ref") not in seen_refs:
            deps.append(extra)
            seen_refs.add(extra.get("ref"))
    if deps:
        out["dependencies"] = deps
    vulns = sbom_advisory.merge_vulnerabilities(
        _vulnerabilities(components, indexes, polluted=_polluted_cves(findings)),
        sbom_advisory.attach_advisories(components),
    )
    if vulns:
        out["vulnerabilities"] = vulns
    return out


__all__ = [
    "component_verdict",
    "keep_software_component",
    "overall_verdict",
    "sanitize_industry_sbom",
]
