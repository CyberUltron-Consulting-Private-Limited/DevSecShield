"""SBOM link: a package URL (purl) on CBOM library components, and "also in SBOM scan X (component Y)".

* Code scans: library components of the stored CycloneDX (``cbom_json``) get a ``purl`` when they have none, built
  with ``sbom_identity.synthesize_purl`` from the name, version and the ecosystem the engine recorded
  (``crypto:ecosystem`` or ``crypto:language``). ``with_library_purls`` is applied where every CBOM export is built
  (``bom_dict_from_scan_data``), so the signed document and the download stay the same.
* Scan-node library rows (OS packages) carry no ecosystem; their purl is ``pkg:generic/<name>@<version>``.
* Matching against the team's SBOM scans: same purl (without qualifiers), else same normalised name and version, else
  the same name with another version (reported as such). Only the newest successful SBOM scans are read.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Iterable

from sqlmodel import Session, select

from backend.new_models import Scan
from backend.utilities.compliance.sbom_identity import parse_pkg, synthesize_purl

SBOM_SCANS_READ = 10
MATCH_CAP = 20
_LANG_ECO = {
    "python": "pypi", "pip": "pypi", "pip-requirements": "pypi", "pypi": "pypi", "poetry": "pypi", "pipfile": "pypi",
    "javascript": "npm", "typescript": "npm", "node": "npm", "npm": "npm", "package-json": "npm", "yarn": "npm",
    "java": "maven", "maven": "maven", "gradle": "maven", "kotlin": "maven", "go": "golang", "golang": "golang",
    "gomod": "golang", "ruby": "gem", "gem": "gem", "gemfile": "gem", "rust": "cargo", "cargo": "cargo",
    "csharp": "nuget", "c#": "nuget", "nuget": "nuget", "dotnet": "nuget", "php": "composer", "composer": "composer",
}


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower()).strip("-")


def ecosystem_of(hint: str | None) -> str | None:
    return _LANG_ECO.get((hint or "").strip().lower())


def library_purl(name: str | None, version: str | None, ecosystem: str | None) -> str:
    """purl of a library; PyPI has no namespaces, so "pyca/cryptography" is the package "cryptography"."""
    raw = (name or "").strip()
    if not raw:
        return ""
    raw = re.sub(r"\s*\(.*\)\s*$", "", raw)  # "hashlib (stdlib)" -> "hashlib"
    version = (version or "").strip()
    if "@" in raw and not raw.startswith("@") and not version:
        raw, version = raw.rsplit("@", 1)
    if ecosystem == "pypi" and "/" in raw:
        raw = raw.rsplit("/", 1)[-1]
    if ecosystem:
        return synthesize_purl(raw, version, ecosystem)
    return f"pkg:generic/{raw}@{version}" if version else f"pkg:generic/{raw}"


def _props(component: dict[str, Any]) -> dict[str, str]:
    out = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            out[prop["name"]] = str(prop.get("value") or "")
    return out


def with_library_purls(bom: dict[str, Any]) -> dict[str, Any]:
    """A copy of a CBOM with a purl on every library component that lacks one (and has a known ecosystem)."""
    if not isinstance(bom, dict) or not isinstance(bom.get("components"), list):
        return bom
    out = copy.deepcopy(bom)
    for comp in out["components"]:
        if not isinstance(comp, dict) or comp.get("type") != "library" or comp.get("purl"):
            continue
        props = _props(comp)
        if props.get("crypto:language") in ("python", "java", "go") and "stdlib" in str(comp.get("name") or ""):
            continue  # standard library modules are not packages
        eco = ecosystem_of(props.get("crypto:ecosystem")) or ecosystem_of(props.get("crypto:language"))
        if not eco:
            continue
        purl = library_purl(str(comp.get("name") or ""), str(comp.get("version") or ""), eco)
        if purl:
            comp["purl"] = purl
    return out


# ----------------------------------------------------------------------------- matching
def _components(scan_data: Any) -> Iterable[tuple[str, str, str]]:
    data = scan_data if isinstance(scan_data, dict) else {}
    bom = data.get("sbom_json") if isinstance(data.get("sbom_json"), dict) else {}
    for comp in bom.get("components") or []:
        if isinstance(comp, dict) and comp.get("name"):
            ident = parse_pkg(name=str(comp.get("name") or ""), version=str(comp.get("version") or ""),
                              purl=str(comp.get("purl") or "") if isinstance(comp.get("purl"), str) else "")
            yield ident.name, ident.version, ident.purl
    for row in data.get("results") or []:  # vulnerability rows name packages too (older scans have no sbom_json)
        if isinstance(row, dict):
            ident = parse_pkg(dependency=str(row.get("dependency") or row.get("package_name") or ""),
                              purl=str(row.get("purl") or "") if isinstance(row.get("purl"), str) else "")
            if ident.name:
                yield ident.name, ident.version, ident.purl


def sbom_index(session: Session, team_id: int, *, limit: int = SBOM_SCANS_READ) -> list[dict[str, Any]]:
    heads = session.exec(select(Scan.id, Scan.title).where(
        Scan.team_id == team_id, Scan.scan_type == "sbom_sca", Scan.scan_status == "success")
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit)).all()  # type: ignore[union-attr]
    out = []
    for scan_id, title in heads:
        data = session.exec(select(Scan.scan_data).where(Scan.id == scan_id, Scan.team_id == team_id)).first()
        comps: dict[str, tuple[str, str, str]] = {}
        for name, version, purl in _components(data):
            comps.setdefault(f"{_norm_name(name)}@{version}", (name, version, (purl or "").split("?", 1)[0].lower()))
        out.append({"scan_id": scan_id, "title": title, "components": list(comps.values())})
    return out


def match(index: list[dict[str, Any]], *, name: str | None, version: str | None, purl: str | None) -> list[dict[str, Any]]:
    want_purl = (purl or "").split("?", 1)[0].lower()
    base = (name or "").strip()
    base = re.sub(r"\s*\(.*\)\s*$", "", base)
    base = base.rsplit("/", 1)[-1] if "/" in base and not base.startswith("@") else base
    want = _norm_name(base)
    found: list[dict[str, Any]] = []
    for scan in index:
        best = None
        for c_name, c_version, c_purl in scan["components"]:
            if want_purl and c_purl and c_purl == want_purl and "pkg:generic/" not in want_purl:
                best = ("purl", c_name, c_version, c_purl)
                break
            if want and _norm_name(c_name.rsplit("/", 1)[-1]) == want:
                kind = "name_version" if version and c_version == version else "name"
                if best is None or (best[0] == "name" and kind == "name_version"):
                    best = (kind, c_name, c_version, c_purl)
        if best:
            found.append({"scan_id": scan["scan_id"], "scan_title": scan["title"], "match": best[0],
                          "component": f"{best[1]}@{best[2]}" if best[2] else best[1], "purl": best[3] or None})
        if len(found) >= MATCH_CAP:
            break
    return found


__all__ = ["ecosystem_of", "library_purl", "match", "sbom_index", "with_library_purls"]
