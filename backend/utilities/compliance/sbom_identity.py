"""Parse SBOM package identity from findings, PURLs, and ``name@version (eco)``."""
from __future__ import annotations

import re
from dataclasses import dataclass

_ECO_ALIAS = {
    "python": "pypi",
    "pypi": "pypi",
    "pip": "pypi",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "js": "npm",
    "maven": "maven",
    "java": "maven",
    "golang": "golang",
    "go": "golang",
    "gem": "gem",
    "ruby": "gem",
    "cargo": "cargo",
    "rust": "cargo",
    "nuget": "nuget",
    "composer": "composer",
    "php": "composer",
    "github": "github",
}
_PURL_ECO = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "golang",
    "gem": "gem",
    "cargo": "cargo",
    "nuget": "nuget",
    "composer": "composer",
    "github": "github",
}
_TRAILING_ECO = re.compile(
    r"\s*\((python|pypi|pip|npm|node|javascript|js|maven|java|golang|go|"
    r"gem|ruby|cargo|rust|nuget|composer|php|github)\)\s*$",
    re.I,
)
_SLASH_VER = re.compile(r"^([^/\s]+)\s*/\s*[^/\s]+")


@dataclass(frozen=True)
class ParsedPkg:
    name: str
    version: str
    ecosystem: str | None
    purl: str


def _canonical_purl(purl: str) -> str:
    return (purl or "").strip().split("?", 1)[0]


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip()).strip("-")


def _clean_version(raw: str) -> str:
    text = _TRAILING_ECO.sub("", (raw or "").strip())
    slash = _SLASH_VER.match(text)
    if slash:
        return slash.group(1).strip()
    return text.strip()


def _eco_from_suffix(raw: str) -> str | None:
    m = _TRAILING_ECO.search(raw or "")
    if not m:
        return None
    return _ECO_ALIAS.get(m.group(1).lower())


def _eco_from_purl(purl: str) -> str | None:
    body = _canonical_purl(purl)
    if not body.startswith("pkg:"):
        return None
    ptype = body[4:].split("/", 1)[0].split("@", 1)[0].lower()
    return _PURL_ECO.get(ptype)


def _name_ver_from_purl(purl: str) -> tuple[str, str]:
    body = _canonical_purl(purl)
    if not body.startswith("pkg:"):
        return "", ""
    rest = body.split("/", 1)[-1]
    name, _, ver = rest.partition("@")
    name = name.rsplit("/", 1)[-1]
    return name.strip(), ver.strip()


def _name_ver_from_dep(dep: str) -> tuple[str, str]:
    raw = _TRAILING_ECO.sub("", (dep or "").strip())
    if not raw:
        return "", ""
    if raw.startswith("pkg:"):
        return _name_ver_from_purl(raw)
    if "==" in raw:
        name, _, ver = raw.partition("==")
        return name.strip(), _clean_version(ver)
    if raw.startswith("@"):
        # scoped npm @scope/pkg@1.2.3
        head, _, ver = raw.rpartition("@")
        if head.count("/") >= 1 and ver and not ver.startswith("@"):
            return head.strip(), _clean_version(ver)
        return raw, ""
    if "@" in raw:
        name, _, ver = raw.partition("@")
        return name.strip(), _clean_version(ver)
    return raw, ""


def synthesize_purl(name: str, version: str, ecosystem: str | None) -> str:
    if not name or not ecosystem:
        return ""
    eco = _ECO_ALIAS.get(ecosystem, ecosystem)
    pkg = _norm_name(name) if eco == "pypi" else name
    if version:
        return f"pkg:{eco}/{pkg}@{version}"
    return f"pkg:{eco}/{pkg}"


def parse_pkg(
    *,
    name: str = "",
    version: str = "",
    purl: str = "",
    dependency: str = "",
) -> ParsedPkg:
    purl = _canonical_purl(purl)
    eco = _eco_from_purl(purl) or _eco_from_suffix(dependency) or _eco_from_suffix(version)
    dep_name, dep_ver = _name_ver_from_dep(dependency)
    p_name, p_ver = _name_ver_from_purl(purl)
    out_name = (name or dep_name or p_name).strip()
    out_ver = _clean_version(version) or dep_ver or p_ver
    if not purl:
        purl = synthesize_purl(out_name, out_ver, eco)
    elif not eco:
        eco = _eco_from_purl(purl)
    return ParsedPkg(name=out_name, version=out_ver, ecosystem=eco, purl=purl)
