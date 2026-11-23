"""Merge Syft/cdxgen CycloneDX components and project SBOM finding rows."""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from helpers.tools.sca_sbom_agent.sbom_license import resolve_emit_license


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _load_components(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    comps = data.get("components")
    return comps if isinstance(comps, list) else []


def _comp_key(c: dict[str, Any]) -> str:
    purl = c.get("purl")
    if isinstance(purl, str) and purl.strip():
        # strip version for key? keep full purl for uniqueness of version
        return purl.strip().lower()
    name = str(c.get("name") or "").strip()
    ver = str(c.get("version") or "").strip()
    return f"{_norm_name(name)}@{ver}"


def _license_str(c: dict[str, Any]) -> str:
    lic = c.get("licenses")
    if not isinstance(lic, list) or not lic:
        return ""
    first = lic[0]
    if isinstance(first, dict):
        license_obj = first.get("license") or first
        if isinstance(license_obj, dict):
            return str(license_obj.get("id") or license_obj.get("name") or "").strip()
        return str(license_obj).strip()
    return ""


def _hash_str(c: dict[str, Any]) -> str:
    hashes = c.get("hashes")
    if not isinstance(hashes, list):
        return ""
    for h in hashes:
        if isinstance(h, dict) and h.get("content"):
            alg = h.get("alg") or "hash"
            return f"{alg}:{h['content']}"
    return ""


def merge_cdx_components(*paths: Path | None) -> list[dict[str, Any]]:
    """Dedupe CycloneDX components by purl / name@version (later sources fill gaps)."""
    by_key: dict[str, dict[str, Any]] = {}
    for path in paths:
        for c in _load_components(path):
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "").strip()
            if not name:
                continue
            key = _comp_key(c)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = dict(c)
            else:
                # Prefer non-empty fields from either side
                for field in ("version", "purl", "description", "publisher", "type"):
                    if not existing.get(field) and c.get(field):
                        existing[field] = c[field]
                if not existing.get("licenses") and c.get("licenses"):
                    existing["licenses"] = c["licenses"]
                if not existing.get("hashes") and c.get("hashes"):
                    existing["hashes"] = c["hashes"]
    return list(by_key.values())


def inventory_to_finding_rows(
    components: list[dict[str, Any]],
    *,
    vuln_assessed: bool = False,
) -> list[dict[str, Any]]:
    """Project merged inventory components into enrich_sbom_scan finding rows."""
    rows: list[dict[str, Any]] = []
    for c in components:
        name = str(c.get("name") or "").strip()
        if not name:
            continue
        if str(c.get("type") or "").lower() == "file" and not c.get("purl"):
            continue  # a file Syft listed (/.github/workflows/x.yml, /model.gguf) is not a package (G-D4-6)
        version = str(c.get("version") or "").strip()
        dep = f"{name}=={version}" if version else name
        purl = c.get("purl") if isinstance(c.get("purl"), str) else None
        desc = str(c.get("description") or "").strip()
        lic_raw = _license_str(c)
        license_spdx, license_type = resolve_emit_license(name, lic_raw)
        h = _hash_str(c)
        supplier = str(c.get("publisher") or c.get("supplier") or "").strip()
        row: dict[str, Any] = {
            "dependency": dep,
            "title": f"Inventory: {name}",
            "description": desc or f"Inventoried component {dep}",
            "impact": "Low",
            "reachability": "not_reachable",
            "license": license_spdx,
            "license_type": license_type,
            "cves": {},
            "owasp_top_10": {},
            "compliance_controls": {},
            "suggested_fix": "n/a — inventory row",
            "dependency_type": "direct",
            "inventory_only": True,
            "vuln_assessed": bool(vuln_assessed),
        }
        if purl:
            row["purl"] = purl
        if h:
            row["hash"] = h
        if supplier:
            row["supplier"] = supplier
        rows.append(row)
    return rows


def load_cdx_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


_PLACEHOLDER_RE = re.compile(
    r"^(?:sbom[\s_-]*dep(?:endency)?[\s_-]*\d+|sbom-dep-\d+|component-\d+)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match((value or "").strip()))


CDX_SCHEMA_16 = "http://cyclonedx.org/schema/bom-1.6.schema.json"
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HOST_PURL_TYPE = {"github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket"}


def devsecshield_version() -> str:
    """The product build that made the SBOM: ``DSS_BUILD_VERSION`` (the image tag scripts/deploy/build_images.sh bakes
    in), else the 12-character ``DSS_BUILD_SHA``, else "unknown" (a local run)."""
    version = (os.environ.get("DSS_BUILD_VERSION") or "").strip()
    if _VERSION_RE.match(version):
        return version
    sha = (os.environ.get("DSS_BUILD_SHA") or "").strip().lower()
    return sha[:12] if _SHA_RE.match(sha) else "unknown"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _head_commit(directory: Path | str | None) -> str | None:
    if not directory:
        return None
    try:
        out = subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=15)
    except Exception:
        return None
    sha = (out.stdout or "").strip().lower()
    return sha if out.returncode == 0 and _SHA_RE.match(sha) else None


def subject_from_repo(
    repo_url: str | None,
    branch: str | None = None,
    directory: Path | str | None = None,
    *,
    fallback_name: str | None = None,
) -> dict[str, Any]:
    """The SBOM's subject (``metadata.component``): the repository, its branch and the commit that was scanned.

    Credentials in the clone URL (a PAT) are never copied: only host and path are used.
    """
    commit = _head_commit(directory)
    parsed = urlparse(str(repo_url or "").strip())
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not host or not path:
        name = fallback_name or "uploaded-source"
        comp: dict[str, Any] = {"type": "application", "name": name, "bom-ref": f"urn:dss:subject:{name}"}
        if commit:
            comp["version"] = commit
        return comp
    version = commit or (branch or "").strip() or None
    comp = {"type": "application", "name": path, "bom-ref": f"urn:dss:subject:{host}/{path}"}
    if version:
        comp["version"] = version
    ptype = _HOST_PURL_TYPE.get(host)
    if ptype and "/" in path:
        purl = f"pkg:{ptype}/{path}" + (f"@{version}" if version else "")
        comp["purl"] = purl
        comp["bom-ref"] = purl
    comp["externalReferences"] = [{"type": "vcs", "url": f"https://{host}/{path}"}]
    props = []
    if branch:
        props.append({"name": "dss:vcs_branch", "value": str(branch)})
    if commit:
        props.append({"name": "dss:vcs_commit", "value": commit})
    if props:
        comp["properties"] = props
    return comp


def _canonical_ref(c: dict[str, Any]) -> str:
    purl = c.get("purl")
    if isinstance(purl, str) and purl.strip():
        return purl.strip().split("?", 1)[0]
    name = str(c.get("name") or "").strip()
    ver = str(c.get("version") or "").strip()
    return f"{name}@{ver}" if ver else name


def _tool_entries(docs: list[dict[str, Any]], extra: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{
        "type": "application",
        "name": "DevSecShield",
        "version": devsecshield_version(),
        "publisher": "DevSecShield",
        "description": "SBOM / SCA scan: Syft and cdxgen inventory, Grype vulnerability matching",
    }]
    seen = {"devsecshield"}
    for doc in docs:
        tools = (doc.get("metadata") or {}).get("tools") if isinstance(doc.get("metadata"), dict) else None
        items = tools.get("components") if isinstance(tools, dict) else tools if isinstance(tools, list) else []
        for t in items or []:
            if not isinstance(t, dict) or not str(t.get("name") or "").strip():
                continue
            key = str(t["name"]).strip().lower()
            if key in seen:
                continue
            seen.add(key)
            entry = {"type": "application", "name": str(t["name"]).strip()}
            if t.get("version"):
                entry["version"] = str(t["version"])
            pub = t.get("publisher") or t.get("author") or t.get("vendor")
            if isinstance(pub, str) and pub.strip():
                entry["publisher"] = pub.strip()
            out.append(entry)
    for t in extra or []:
        key = str(t.get("name") or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(dict(t))
    return out


def _graph_edges(
    docs: list[dict[str, Any]], ref_of: dict[str, str]
) -> tuple[dict[str, list[str]], set[str]]:
    """``ref -> dependsOn`` over canonical refs from every source document, and the refs a source root depends on."""
    edges: dict[str, list[str]] = {}
    root_kids: set[str] = set()
    for doc in docs:
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        root = meta.get("component") if isinstance(meta.get("component"), dict) else {}
        root_ref = str(root.get("bom-ref") or "")
        local: dict[str, str] = {}
        for c in doc.get("components") or []:
            if isinstance(c, dict) and c.get("bom-ref"):
                canon = ref_of.get(_comp_key(c))
                if canon:
                    local[str(c["bom-ref"])] = canon
        for dep in doc.get("dependencies") or []:
            if not isinstance(dep, dict):
                continue
            src = str(dep.get("ref") or "")
            kids = [local[k] for k in (str(x) for x in dep.get("dependsOn") or []) if k in local]
            if src and src == root_ref:
                root_kids.update(kids)
                continue
            canon = local.get(src)
            if not canon:
                continue
            bucket = edges.setdefault(canon, [])
            for k in kids:
                if k != canon and k not in bucket:
                    bucket.append(k)
    return edges, root_kids


def assemble_cyclonedx(
    components: list[dict[str, Any]],
    *,
    base: dict[str, Any] | None = None,
    tools: list[str] | None = None,
    subject_name: str | None = None,
    subject: dict[str, Any] | None = None,
    source_docs: list[dict[str, Any]] | None = None,
    constraints: dict[str, str] | None = None,
    extra_tools: list[dict[str, Any]] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build one CycloneDX 1.6 document from the merged inventory (SOW 3.2: normalise to CycloneDX 1.6).

    * ``specVersion`` is always 1.6 (Syft 1.5x writes 1.7 by default), with the 1.6 ``$schema``.
    * ``metadata``: the real scan time, DevSecShield (with its build version) plus every inventory tool and its
      version in ``tools``, the scanned repository as ``component`` (name, commit, purl), lifecycle ``pre-build``.
    * Every component's ``bom-ref`` is its purl (else ``name@version``), so the source tools' graphs can be joined.
    * ``dependencies``: the source tools' edges (cdxgen reads lock files), plus the subject's edges to every
      component no other component depends on, so each component is reachable from the subject (NTIA "dependency
      relationship"). A component whose own dependencies are unknown gets no entry (CycloneDX: unknown, not none).
    * A version Syft guessed from a range carries ``dss:version_source=range_lower_bound`` and the constraint.

    Never emits ``sbom-dep-N`` placeholders.
    """
    docs = [d for d in (source_docs or ([base] if isinstance(base, dict) else [])) if isinstance(d, dict)]
    constraints = constraints or {}
    root = dict(subject) if isinstance(subject, dict) else None
    if root is None:
        name = subject_name or "application"
        root = {"type": "application", "name": name, "bom-ref": f"urn:dss:subject:{name}"}
    root.setdefault("bom-ref", f"urn:dss:subject:{root.get('name') or 'application'}")
    root_ref = str(root["bom-ref"])

    cleaned: list[dict[str, Any]] = []
    ref_of: dict[str, str] = {}
    seen: set[str] = set()
    for i, raw in enumerate(components):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name or _is_placeholder(name):
            continue
        item = {k: v for k, v in raw.items() if k not in {"bom-ref", "components"}}
        item["name"] = name
        item.setdefault("type", "library")
        ref = _canonical_ref(item) or f"component-{i}"
        if ref in seen or ref == root_ref:
            continue
        seen.add(ref)
        item["bom-ref"] = ref
        ref_of[_comp_key(raw)] = ref
        purl = str(item.get("purl") or "").split("?", 1)[0]
        constraint = constraints.get(purl) or constraints.get(ref)
        if constraint:
            props = [p for p in item.get("properties") or [] if isinstance(p, dict)
                     and p.get("name") not in {"dss:version_source", "dss:version_constraint"}]
            props += [{"name": "dss:version_source", "value": "range_lower_bound"},
                      {"name": "dss:version_constraint", "value": constraint}]
            item["properties"] = props
        cleaned.append(item)

    edges, root_kids = _graph_edges(docs, ref_of)
    children = {k for kids in edges.values() for k in kids}
    direct = [c["bom-ref"] for c in cleaned if c["bom-ref"] in root_kids or c["bom-ref"] not in children]
    dependencies: list[dict[str, Any]] = [{"ref": root_ref, "dependsOn": direct}] if direct else [{"ref": root_ref}]
    for c in cleaned:
        kids = edges.get(c["bom-ref"])
        if kids is not None:
            dependencies.append({"ref": c["bom-ref"], "dependsOn": kids} if kids else {"ref": c["bom-ref"]})

    metadata: dict[str, Any] = {
        "timestamp": timestamp or utc_now(),
        "lifecycles": [{"phase": "pre-build"}],
        "tools": {"components": _tool_entries(docs, extra_tools)},
        "authors": [{"name": "DevSecShield"}],
        "component": root,
    }
    if tools:
        metadata["properties"] = [{"name": "dss:inventory_tools", "value": ",".join(tools)}]
    return {
        "$schema": CDX_SCHEMA_16,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": cleaned,
        "dependencies": dependencies,
    }
