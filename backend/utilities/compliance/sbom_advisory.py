"""OSV.dev + NVD advisory lookup for CycloneDX vulnerabilities[] (read-time)."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Any

from backend.utilities.compliance.sbom_registry import _network_allowed

_TIMEOUT = 4.0
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CAP = 8
_NVD_PER_PKG = 3
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_BATCH = 80


def _vuln_id(vuln: dict[str, Any] | None) -> str:
    if not isinstance(vuln, dict):
        return ""
    for alias in vuln.get("aliases") or []:
        text = str(alias or "").strip()
        if _CVE_RE.match(text):
            return text.upper()
    vid = str(vuln.get("id") or "").strip()
    if _CVE_RE.match(vid):
        return vid.upper()
    return vid


def _get_json(url: str) -> dict[str, Any] | None:
    headers = {
        "User-Agent": "DevSecShield-SBOM/1.0",
        "Accept": "application/json",
    }
    key = os.environ.get("NVD_API_KEY")
    if key and "nvd.nist.gov" in url:
        headers["apiKey"] = key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return None


def _post_json(url: str, body: dict[str, Any]) -> dict[str, Any] | None:
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "DevSecShield-SBOM/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return None


def _split_purl(purl: str) -> tuple[str, str]:
    body = (purl or "").strip().split("?", 1)[0]
    if not body.startswith("pkg:"):
        return "", ""
    left, sep, ver = body.rpartition("@")
    if sep and left.startswith("pkg:"):
        return left, ver
    return body, ""


def _mentions_package(package: str, blob: str, *, purl: str = "") -> bool:
    token = (package or "").strip().lower()
    if len(token) < 4:
        return False
    hay = (blob or "").lower()
    if "/" in token:
        owner, repo = token.split("/", 1)
        repo = repo.split("/", 1)[0]
        return token in hay or (owner + "/" + repo) in hay
    if not re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", hay):
        return False
    eco = ""
    if purl.startswith("pkg:"):
        eco = purl[4:].split("/", 1)[0].lower()
    if eco in {"pypi", "pip"}:
        return any(w in hay for w in ("python", "pypi", "pip"))
    if eco in {"npm", "node"}:
        return any(w in hay for w in ("npm", "node.js", "nodejs", "javascript", "node package"))
    return True


def _nvd_eligible(comp: dict[str, Any], name: str) -> bool:
    purl = str(comp.get("purl") or "")
    if purl.startswith("pkg:github/") or "/" in (name or ""):
        return False
    return len((name or "").strip()) >= 4


def _osv_query(purl: str, version: str) -> dict[str, Any] | None:
    pkg, pver = _split_purl(purl)
    if not pkg:
        return None
    query: dict[str, Any] = {"package": {"purl": pkg}}
    ver = pver or version
    if ver:
        query["version"] = ver
    return query


def _osv_batch(queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    out: list[list[dict[str, Any]]] = [[] for _ in queries]
    if not queries:
        return out
    for start in range(0, len(queries), _BATCH):
        chunk = queries[start : start + _BATCH]
        data = _post_json(_OSV_BATCH, {"queries": chunk})
        rows = (data or {}).get("results") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            continue
        for i, row in enumerate(rows):
            if start + i >= len(out) or not isinstance(row, dict):
                continue
            vulns = row.get("vulns") or []
            out[start + i] = [v for v in vulns if isinstance(v, dict)]
    return out


@lru_cache(maxsize=256)
def _nvd_search(name: str) -> tuple[tuple[str, str], ...]:
    q = urllib.parse.quote(name)
    data = _get_json(f"{_NVD}?keywordSearch={q}&keywordExactMatch=true")
    if not isinstance(data, dict):
        return ()
    hits: list[tuple[str, str]] = []
    for wrap in data.get("vulnerabilities") or []:
        if not isinstance(wrap, dict):
            continue
        cve = wrap.get("cve") if isinstance(wrap.get("cve"), dict) else wrap
        vid = str((cve or {}).get("id") or "").strip().upper()
        if not _CVE_RE.match(vid):
            continue
        texts: list[str] = []
        for desc in (cve or {}).get("descriptions") or []:
            if isinstance(desc, dict):
                texts.append(str(desc.get("value") or ""))
        hits.append((vid, " ".join(texts)))
    return tuple(hits)


def _nvd_hits(name: str, *, purl: str = "") -> list[str]:
    ids: list[str] = []
    for vid, blob in _nvd_search(name):
        if _mentions_package(name, blob, purl=purl):
            ids.append(vid)
        if len(ids) >= _NVD_PER_PKG:
            break
    return ids


def _advisory_item(vid: str, ref: str, source: str, url: str) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": vid,
        "source": {"name": source, "url": url},
        "ratings": [{"severity": "medium", "method": "other"}],
    }
    if ref:
        item["affects"] = [{"ref": ref}]
    return item


def attach_advisories(comps: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not _network_allowed() or not comps:
        return []
    indexed: list[tuple[dict[str, Any], str, str, str]] = []
    queries: list[dict[str, Any]] = []
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        purl = str(comp.get("purl") or comp.get("bom-ref") or "")
        version = str(comp.get("version") or "")
        query = _osv_query(purl, version)
        if not query:
            continue
        indexed.append((comp, purl, version, str(comp.get("name") or "")))
        queries.append(query)
    osv_rows = _osv_batch(queries)
    by_id: dict[str, dict[str, Any]] = {}
    empty: list[tuple[dict[str, Any], str, str]] = []
    for (comp, _purl, _ver, name), vulns in zip(indexed, osv_rows):
        ref = str(comp.get("bom-ref") or comp.get("purl") or "")
        if not vulns:
            empty.append((comp, ref, name))
            continue
        for vuln in vulns:
            vid = _vuln_id(vuln)
            if not vid:
                continue
            url = f"https://osv.dev/vulnerability/{vid}"
            item = by_id.setdefault(vid, _advisory_item(vid, ref, "OSV", url))
            affects = item.setdefault("affects", [])
            if ref and {"ref": ref} not in affects:
                affects.append({"ref": ref})
    nvd_used = 0
    for comp, ref, name in empty:
        if nvd_used >= _NVD_CAP or not name or not _nvd_eligible(comp, name):
            continue
        nvd_used += 1
        for vid in _nvd_hits(name, purl=str(comp.get("purl") or "")):
            url = f"https://nvd.nist.gov/vuln/detail/{vid}"
            item = by_id.setdefault(vid, _advisory_item(vid, ref, "NVD", url))
            affects = item.setdefault("affects", [])
            if ref and {"ref": ref} not in affects:
                affects.append({"ref": ref})
    return [by_id[k] for k in sorted(by_id)]


def merge_vulnerabilities(
    base: list[dict[str, Any]] | None,
    extra: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in list(base or []) + list(extra or []):
        if not isinstance(row, dict):
            continue
        vid = str(row.get("id") or "").strip()
        if not vid:
            continue
        if vid not in by_id:
            by_id[vid] = {
                "id": vid,
                "source": row.get("source") or {},
                "ratings": list(row.get("ratings") or []),
                "affects": list(row.get("affects") or []),
            }
            order.append(vid)
            continue
        seen = {str(a.get("ref")) for a in by_id[vid].get("affects") or [] if isinstance(a, dict)}
        for aff in row.get("affects") or []:
            if not isinstance(aff, dict):
                continue
            ref = str(aff.get("ref") or "")
            if ref and ref not in seen:
                seen.add(ref)
                by_id[vid].setdefault("affects", []).append({"ref": ref})
    out: list[dict[str, Any]] = []
    for vid in order:
        item = by_id[vid]
        if not item.get("affects"):
            item.pop("affects", None)
        if not item.get("ratings"):
            item.pop("ratings", None)
        out.append(item)
    return out
