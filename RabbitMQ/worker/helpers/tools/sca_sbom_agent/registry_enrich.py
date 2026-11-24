"""Resolve each component's licence, author, hash and declared dependencies ONCE, when the scan finishes (review
6028132826 M4).

Before, licences were looked up at download time in the API (``sbom_cyclonedx._apply_registry``) while the finding
rows, the dashboard and the stored compliance used what the inventory tools gave, so pillow's finding said
"LicenseRef-not-declared" next to a package table saying MIT-CMU. Now the worker resolves them here and stores the
result in the SBOM document; the finding rows are stamped from the same document and the API serves it without
another lookup (``dss:registry`` in ``metadata.properties`` says so).

Order, offline first: the inventory tools' licence, then the curated package map, then the package registry
(``backend/utilities/compliance/sbom_registry.py``: PyPI, npm, GitHub, deps.dev) ONLY when ``DSS_SBOM_REGISTRY=1``
(opt-in, review 6032108510 B-1: by default the worker makes no egress), within a wall-clock budget
(``SBOM_REGISTRY_BUDGET_S``, default 90 s). ``dss:registry`` says off, on or unreachable (nothing resolved). A version guessed from a
range never gets a registry hash: the hash would be of a release nobody showed is installed (B2).

The backend files are standard library only and loaded by path, as ``helpers/net/guard.py`` loads
``address_rule.py``; the scan-worker image copies them to the same paths (RabbitMQ/worker/Dockerfile).
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[5]
_BACKEND_FILES = {
    "registry": "backend/utilities/compliance/sbom_registry.py",
    "spdx": "backend/utilities/compliance/spdx_license.py",
    "category": "backend/utilities/dashboard/sbom_license.py",
}
_LOADED: dict[str, ModuleType | None] = {}
_REGISTRY_ECOSYSTEMS = frozenset({"pypi", "npm", "github", "maven", "nuget", "cargo", "golang"})
_GITHUB_MIT = frozenset({"actions", "github", "pypa"})
GUESSED = "range_lower_bound"


_GIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def backend_module(key: str) -> ModuleType | None:
    """One of the shared backend files, loaded by path (None when the file is not there)."""
    if key in _LOADED:
        return _LOADED[key]
    path = REPO_ROOT / _BACKEND_FILES[key]
    mod: ModuleType | None = None
    if path.is_file():
        name = f"zeroshield_sbom_{key}"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
    _LOADED[key] = mod
    return mod


def _prop(comp: dict[str, Any], name: str) -> str | None:
    for p in comp.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == name:
            return str(p.get("value") or "")
    return None


def is_guessed(comp: dict[str, Any]) -> bool:
    return _prop(comp, "dss:version_source") == GUESSED


def lookup_args(comp: dict[str, Any]) -> tuple[str, str, str] | None:
    """``(ecosystem, name, version)`` from the purl, in the form sbom_registry.lookup_package takes."""
    purl = str(comp.get("purl") or "").split("?", 1)[0].split("#", 1)[0]
    if not purl.startswith("pkg:") or "/" not in purl:
        return None
    body, _, version = purl[4:].partition("@")
    eco, _, path = body.partition("/")
    eco = eco.lower()
    path = unquote(path)
    if eco not in _REGISTRY_ECOSYSTEMS or not path:
        return None
    if eco in {"pypi", "cargo", "nuget"}:
        path = path.rsplit("/", 1)[-1]
    return eco, path, unquote(version)


def _licences(comp: dict[str, Any]) -> list[dict[str, Any]] | None:
    spdx = backend_module("spdx")
    if spdx is None:
        return comp.get("licenses") or None
    return spdx.sanitize_licenses(comp.get("licenses"))


def licence_text(comp: dict[str, Any]) -> str:
    spdx = backend_module("spdx")
    return spdx.licence_text(comp.get("licenses")) if spdx else ""


def _offline_licence(comp: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The curated package map (the dashboard's own), then MIT for GitHub's first-party actions."""
    spdx, cat = backend_module("spdx"), backend_module("category")
    args = lookup_args(comp)
    name = (args[1] if args else str(comp.get("name") or "")).rsplit("/", 1)[-1]
    mapped = cat.resolve_package_spdx(name) if cat and name else None
    if mapped and spdx:
        return spdx.licence_choice(mapped)
    if args and args[0] == "github" and args[1].split("/", 1)[0].lower() in _GITHUB_MIT and spdx:
        return spdx.licence_choice("MIT")
    return None


def _needs_lookup(comp: dict[str, Any]) -> bool:
    return not (comp.get("licenses") and comp.get("author") and (comp.get("hashes") or is_guessed(comp))
                and _prop(comp, "declared:depends") is not None)


def _apply(comp: dict[str, Any], meta: dict[str, Any] | None) -> bool:
    if not meta:
        return False
    spdx = backend_module("spdx")
    if meta.get("author") and not comp.get("author"):
        comp["author"] = str(meta["author"])[:200]
    if meta.get("license") and not comp.get("licenses") and spdx:
        choice = spdx.licence_choice(str(meta["license"]))
        if choice:
            comp["licenses"] = choice
    hashed = meta.get("hash")
    if hashed and not comp.get("hashes") and not is_guessed(comp):
        alg, content = hashed
        if content:
            comp["hashes"] = [{"alg": str(alg), "content": str(content)}]
    if "depends" in meta and _prop(comp, "declared:depends") is None:
        depends = [str(x).strip() for x in meta.get("depends") or [] if str(x).strip()]
        comp["properties"] = [*(comp.get("properties") or []),
                              {"name": "declared:depends", "value": ", ".join(depends)}]
    return True


def registry_budget() -> float:
    try:
        return max(0.0, float(os.environ.get("SBOM_REGISTRY_BUDGET_S") or 90))
    except ValueError:
        return 90.0


def resolve_components(components: list[dict[str, Any]], *, budget_s: float | None = None) -> dict[str, Any]:
    """Fill licences (SPDX-valid entries), authors, hashes and ``declared:depends`` in place.

    Returns ``{"looked_up", "resolved", "timed_out", "registry"}`` for ``metadata.properties``; ``registry`` is
    ``off`` (not enabled), ``on`` or ``unreachable`` (lookups made, none answered).
    """
    for comp in components:
        lic = _licences(comp)
        if lic:
            comp["licenses"] = lic
        else:
            comp.pop("licenses", None)
            offline = _offline_licence(comp)
            if offline:
                comp["licenses"] = offline
        version = str(comp.get("version") or "").strip()
        if not comp.get("hashes") and _GIT_SHA.match(version):
            # a component pinned by commit (an action at its SHA): the commit is its SHA-1, as /bom states it
            # (sbom_cyclonedx._hashes_for), so the stamped hash coverage counts it too (review 6032108510 M-1)
            comp["hashes"] = [{"alg": "SHA-1", "content": version.lower()}]
    registry = backend_module("registry")
    budget = registry_budget() if budget_s is None else budget_s
    network = bool(registry and registry.registry_enabled() and registry._network_allowed() and budget > 0)
    jobs = [(c, lookup_args(c)) for c in components if _needs_lookup(c)]
    jobs = [(c, a) for c, a in jobs if a]
    stats = {"looked_up": 0, "resolved": 0, "timed_out": 0, "registry": "on" if network else "off"}
    if not network or not jobs:
        return stats
    deadline = time.monotonic() + budget
    pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sbom-registry")
    try:
        futures = {pool.submit(registry.lookup_package, *args): comp for comp, args in jobs}
        done, pending = wait(futures, timeout=max(0.0, deadline - time.monotonic()))
        stats["looked_up"] = len(futures)
        stats["timed_out"] = len(pending)
        for fut in sorted(done, key=lambda f: id(futures[f])):
            try:
                meta = fut.result()
            except Exception:
                meta = None
            stats["resolved"] += int(_apply(futures[fut], meta))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if stats["looked_up"] and not stats["resolved"]:
        stats["registry"] = "unreachable"
    return stats


def registry_note(stats: dict[str, Any]) -> str:
    """``dss:registry``: ``off`` (no lookup made), or ``on`` / ``unreachable`` with what resolved."""
    if stats.get("registry") == "off":
        return "off: no registry lookup (DSS_SBOM_REGISTRY is not 1); licences and hashes from the inventory only"
    return "{registry}: {resolved}/{looked_up} resolved, {timed_out} timed out".format(**stats)


def licence_fields(comp: dict[str, Any] | None) -> tuple[str, str]:
    """``(licence text, risk category)`` of a component, with the dashboard's own category mapping."""
    cat = backend_module("category")
    text = licence_text(comp or {})
    if not text:
        return "LicenseRef-not-declared", "not_declared"
    return text, (cat.spdx_to_license_category(text) if cat else "not_declared")


def stamp_rows(rows: list[dict[str, Any]], components: list[dict[str, Any]]) -> int:
    """Every finding / inventory row takes its component's licence, so the rows, the dashboard and the SBOM agree."""
    by_purl = {str(c.get("purl") or "").split("?", 1)[0].lower(): c for c in components if c.get("purl")}
    stamped = 0
    for row in rows:
        comp = by_purl.get(str(row.get("purl") or "").split("?", 1)[0].lower())
        if comp is None:
            continue
        row["license"], row["license_type"] = licence_fields(comp)
        stamped += 1
    return stamped


__all__ = ["backend_module", "is_guessed", "licence_fields", "lookup_args", "resolve_components", "stamp_rows"]
