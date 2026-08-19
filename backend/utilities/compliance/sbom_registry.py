"""Offline-first package registry lookup for SBOM author/license/hash/deps."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import Any

_TIMEOUT = 4.0
_LICENSE_WORDS = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache-2.0": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "isc": "ISC",
    "mpl-2.0": "MPL-2.0",
    "unlicense": "Unlicense",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
}
_CLASSIFIER_SPDX = (
    ("mozilla public license 2.0", "MPL-2.0"),
    ("python software foundation", "PSF-2.0"),
    ("apache software license", "Apache-2.0"),
    ("mit license", "MIT"),
    ("isc license", "ISC"),
    ("2-clause bsd", "BSD-2-Clause"),
    ("3-clause bsd", "BSD-3-Clause"),
    ("bsd license", "BSD-3-Clause"),
)
_GITHUB_MIT = frozenset({"actions", "github", "pypa"})
_DEPS_SYS = {
    "pypi": "PYPI",
    "npm": "NPM",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "nuget": "NUGET",
    "golang": "GO",
}
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")
_PERSON = re.compile(r'"?([^"<@]+?)"?\s*<[^>]+>')
_EXTRA_MARK = re.compile(r"\bextra\s*==", re.I)
_GITHUB_ORG = re.compile(
    r"https?://(?:www\.)?github\.com/([^/\s?#]+)/",
    re.I,
)
_SPDX_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_NATIVE = frozenset({"pypi", "npm", "github"})
_SUPPORTED = _NATIVE | frozenset(_DEPS_SYS)


def _person_name(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text or text.lower() in {"none", "unknown", "null"}:
        return ""
    match = _PERSON.search(text)
    if match:
        return match.group(1).strip().strip('"')[:200]
    if "@" in text and " " not in text and "<" not in text:
        return text.split("@", 1)[0][:200]
    return text[:200]


def _network_allowed() -> bool:
    if os.environ.get("DSS_SBOM_REGISTRY") == "0":
        return False
    if os.environ.get("PYTEST_CURRENT_TEST") and os.environ.get("DSS_SBOM_REGISTRY") != "1":
        return False
    return True


def normalize_license(raw: str | None) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    low = re.sub(r"\s+", " ", text.lower())
    if low in {"unknown", "none", "noassertion", "license not specified", "dual license"}:
        return None
    if low in _LICENSE_WORDS:
        return _LICENSE_WORDS[low]
    if "apache" in low and "2" in low:
        return "Apache-2.0"
    if low.startswith("mit") or low.endswith(" mit"):
        return "MIT"
    if _SPDX_ID.fullmatch(text):
        return text
    return None


def _first_spdx(raw: str) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    token = re.split(r"\s+(?:OR|AND)\s+", text, maxsplit=1, flags=re.I)[0].strip()
    return normalize_license(token) or normalize_license(text)


def _classifier_spdx(classifiers: Any) -> str | None:
    for raw in classifiers or []:
        text = str(raw)
        if "License :: OSI Approved ::" not in text:
            continue
        tail = text.split("::")[-1].strip().lower()
        for needle, spdx in _CLASSIFIER_SPDX:
            if needle in tail:
                return spdx
    return None


def _req_name(spec: str) -> str:
    full = spec or ""
    if _EXTRA_MARK.search(full):
        return ""
    raw = full.split(";", 1)[0]
    m = _REQ_NAME.match(raw.replace("(", " "))
    name = (m.group(1) if m else "").strip()
    if name.lower() in {"extra", "python"}:
        return ""
    return name


def _github_org_author(info: dict[str, Any]) -> str:
    urls: list[str] = [str(info.get("home_page") or ""), str(info.get("project_url") or "")]
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        urls.extend(str(v) for v in project_urls.values())
    for url in urls:
        match = _GITHUB_ORG.search(url)
        if not match:
            continue
        org = match.group(1).strip()
        if org and org.lower() not in {"pypi", "pypa", "sponsors"}:
            return org[:200]
    return ""


def _get_json(url: str) -> dict[str, Any] | None:
    headers = {"User-Agent": "DevSecShield-SBOM/1.0", "Accept": "application/json"}
    if "api.github.com" in url:
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return None


def _version_candidates(version: str) -> list[str]:
    parts = [p.strip() for p in (version or "").split("/") if p.strip()]
    return parts


def _pypi_license(info: dict[str, Any]) -> str | None:
    expr = _first_spdx(str(info.get("license_expression") or ""))
    if expr:
        return expr
    classified = _classifier_spdx(info.get("classifiers"))
    if classified:
        return classified
    return normalize_license(str(info.get("license") or ""))


def _pypi_payload(data: dict[str, Any], resolved: str) -> dict[str, Any] | None:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    if not info:
        return None
    author = _person_name(info.get("author") or info.get("maintainer"))
    if not author:
        author = _person_name(info.get("author_email") or info.get("maintainer_email"))
    if not author:
        author = _github_org_author(info)
    depends: list[str] = []
    seen: set[str] = set()
    for spec in info.get("requires_dist") or []:
        child = _req_name(str(spec))
        key = child.lower()
        if child and key not in seen:
            seen.add(key)
            depends.append(child)
    sha = ""
    for item in data.get("urls") or []:
        if not isinstance(item, dict):
            continue
        digest = item.get("digests") if isinstance(item.get("digests"), dict) else {}
        sha = str(digest.get("sha256") or "").strip()
        if sha:
            break
    out: dict[str, Any] = {"depends": depends[:40]}
    if resolved:
        out["version"] = resolved
    if author and author.lower() not in {"none", "unknown"}:
        out["author"] = author[:200]
    license_id = _pypi_license(info)
    if license_id:
        out["license"] = license_id
    if sha:
        out["hash"] = ("SHA-256", sha)
    return out


def _from_pypi(name: str, version: str) -> dict[str, Any] | None:
    for ver in _version_candidates(version):
        data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(ver)}/json")
        if isinstance(data, dict):
            parsed = _pypi_payload(data, ver)
            if parsed:
                return parsed
    if version.strip():
        return None
    data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if not isinstance(data, dict):
        return None
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    resolved = str((info or {}).get("version") or "")
    return _pypi_payload(data, resolved)


def _npm_author(raw: Any) -> str:
    if isinstance(raw, str) and raw.strip():
        return raw.strip()[:200]
    if isinstance(raw, dict):
        return str(raw.get("name") or "").strip()[:200]
    return ""


def _from_npm(name: str, version: str) -> dict[str, Any] | None:
    path = urllib.parse.quote(name, safe="@/")
    for ver in _version_candidates(version) or [""]:
        url = f"https://registry.npmjs.org/{path}/{ver}" if ver else f"https://registry.npmjs.org/{path}"
        data = _get_json(url)
        if not isinstance(data, dict):
            continue
        if "versions" in data and ver and isinstance(data["versions"], dict):
            data = data["versions"].get(ver) or data
        if not isinstance(data, dict):
            continue
        author = _npm_author(data.get("author"))
        if not author:
            maintainers = data.get("maintainers") or []
            if maintainers and isinstance(maintainers[0], dict):
                author = str(maintainers[0].get("name") or "").strip()[:200]
        license_id = normalize_license(str(data.get("license") or ""))
        dist = data.get("dist") if isinstance(data.get("dist"), dict) else {}
        sha = str(dist.get("shasum") or "").strip()
        integrity = str(dist.get("integrity") or "").strip()
        depends = [str(k) for k in (data.get("dependencies") or {})][:40]
        out: dict[str, Any] = {"depends": depends}
        if ver:
            out["version"] = ver
        if author:
            out["author"] = author
        if license_id:
            out["license"] = license_id
        if sha:
            out["hash"] = ("SHA-1", sha)
        elif integrity.startswith("sha512-"):
            out["hash"] = ("SHA-512", integrity.split("-", 1)[-1][:128])
        return out
    return None


def _github_owner_repo(name: str) -> tuple[str, str]:
    raw = (name or "").strip().lstrip("/")
    if raw.startswith("pkg:github/"):
        raw = raw[len("pkg:github/") :].split("@", 1)[0]
    if "/" not in raw:
        return "", ""
    owner, repo = raw.split("/", 1)
    owner, repo = owner.strip(), repo.strip()
    if not owner or not repo:
        return "", ""
    return owner, repo.split("/", 1)[0]


def _from_github(name: str, version: str) -> dict[str, Any] | None:
    owner, repo = _github_owner_repo(name)
    if not owner:
        return None
    tag = _version_candidates(version)[0] if version else ""
    out: dict[str, Any] = {"author": owner[:200], "depends": []}
    if tag:
        out["version"] = tag
        ref = urllib.parse.quote(tag, safe=".@~_-")
        commit = _get_json(
            f"https://api.github.com/repos/{urllib.parse.quote(owner)}/"
            f"{urllib.parse.quote(repo)}/commits/{ref}"
        )
        sha = str((commit or {}).get("sha") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            out["hash"] = ("SHA-1", sha)
    lic = _get_json(
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/"
        f"{urllib.parse.quote(repo)}/license"
    )
    spdx = ""
    if isinstance(lic, dict):
        block = lic.get("license") if isinstance(lic.get("license"), dict) else {}
        spdx = str((block or {}).get("spdx_id") or "").strip()
        if spdx.lower() in {"", "noassertion", "none", "other"}:
            spdx = ""
    if not spdx and owner.lower() in _GITHUB_MIT:
        spdx = "MIT"
    if spdx:
        out["license"] = spdx
    return out


def _from_deps_dev(eco: str, name: str, version: str) -> dict[str, Any] | None:
    system = _DEPS_SYS.get(eco)
    ver = (_version_candidates(version) or [version])[0] if version else ""
    if not system or not name or not ver:
        return None
    pkg = name.replace("/", ":", 1) if eco == "maven" and "/" in name else name
    url = (
        f"https://api.deps.dev/v3/systems/{system}/packages/"
        f"{urllib.parse.quote(pkg, safe='')}/versions/{urllib.parse.quote(ver, safe='')}"
    )
    data = _get_json(url)
    if not isinstance(data, dict):
        return None
    out: dict[str, Any] = {}
    licenses = data.get("licenses") or []
    for raw in licenses:
        spdx = normalize_license(str(raw))
        if spdx:
            out["license"] = spdx
            break
    return out or None


def _identity_complete(meta: dict[str, Any] | None) -> bool:
    if not meta:
        return False
    return bool(meta.get("author") and meta.get("license") and meta.get("hash"))


def _fill_missing(base: dict[str, Any] | None, extra: dict[str, Any] | None) -> dict[str, Any] | None:
    if not extra:
        return base
    out = dict(base or {})
    for key, val in extra.items():
        if key == "depends":
            if "depends" not in out:
                out["depends"] = val
            continue
        if not out.get(key) and val:
            out[key] = val
    return out or None


def _from_native(eco: str, name: str, version: str) -> dict[str, Any] | None:
    if eco == "pypi":
        return _from_pypi(name, version)
    if eco == "npm":
        return _from_npm(name, version)
    if eco == "github":
        return _from_github(name, version)
    return None


@lru_cache(maxsize=1024)
def _fetch(eco: str, name: str, version: str) -> tuple[tuple[str, Any], ...]:
    if not _network_allowed() or not name:
        return ()
    data = _from_native(eco, name, version)
    if eco != "github" and not _identity_complete(data):
        resolved = str((data or {}).get("version") or "")
        if not resolved:
            cands = _version_candidates(version)
            resolved = cands[0] if cands else ""
        data = _fill_missing(data, _from_deps_dev(eco, name, resolved))
    if not data:
        return ()
    items: list[tuple[str, Any]] = []
    for key, val in data.items():
        items.append((key, tuple(val) if isinstance(val, list) else val))
    return tuple(items)


def _unpack(packed: tuple[tuple[str, Any], ...]) -> dict[str, Any] | None:
    if not packed:
        return None
    out: dict[str, Any] = {}
    for key, val in packed:
        out[key] = list(val) if isinstance(val, tuple) and key == "depends" else val
    return out


def lookup_package(ecosystem: str | None, name: str, version: str) -> dict[str, Any] | None:
    eco = (ecosystem or "").strip().lower()
    if eco not in _SUPPORTED or not name:
        return None
    return _unpack(_fetch(eco, name, version))


def lookup_many(jobs: list[tuple[str, str, str]]) -> list[dict[str, Any] | None]:
    if not jobs:
        return []
    workers = min(8, len(jobs))
    if workers == 1:
        return [lookup_package(*jobs[0])]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda job: lookup_package(*job), jobs))
