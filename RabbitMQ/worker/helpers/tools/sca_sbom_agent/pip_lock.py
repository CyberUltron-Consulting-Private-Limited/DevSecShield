"""Pip-format lock files (``requirements.lock``, ``requirements-build.lock`` ...) as a CycloneDX source document.

Syft reads ``*requirements*.txt``, ``uv.lock``, ``poetry.lock`` and ``Pipfile.lock`` but not a pip-format file named
``*.lock`` (``uv pip compile -o requirements.lock``, ``pip-compile -o x.lock``), so a repository that installs from
such a lock was inventoried from its range requirements only (review 6028132826 M2: pcap-hunter's ``pillow>=10.0``
was reported as pillow 10.0 although ``requirements.lock`` pins 13.0.0).

Each ``name==version`` entry becomes a component marked ``dss:version_source=lock_file``. The ``# via`` annotations
that ``uv pip compile`` and ``pip-compile`` write are real dependency edges: ``# via streamlit`` means streamlit
requires the package, ``# via -r requirements-runtime.txt`` means the project requires it directly. The ``--hash``
values are distribution-file hashes (one per wheel or sdist), not the component's own hash, so they are not copied.

Offline and standard library only.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# lock files with a format of their own, read by Syft or cdxgen
_OTHER_LOCKS = frozenset({
    "uv.lock", "poetry.lock", "pipfile.lock", "pdm.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "cargo.lock", "composer.lock", "gemfile.lock", "go.sum", "mix.lock", "pubspec.lock", "packages.lock.json",
    "conan.lock", "flake.lock", "bun.lock", "deno.lock", "gradle.lockfile", "podfile.lock", "cartfile.resolved",
})
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "site-packages"})
_MAX_BYTES = 4 * 1024 * 1024
_MAX_FILES = 64
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:[;\\].*)?$")
_VIA_INLINE = re.compile(r"^\s*#\s+via\s+(.+?)\s*$")
_VIA_HEAD = re.compile(r"^\s*#\s+via\s*$")
_VIA_ITEM = re.compile(r"^\s*#\s{2,}(\S.*?)\s*$")


def normalize(name: str) -> str:
    """PEP 503 name: lower case, runs of ``-_.`` as one ``-`` (the form Syft's purls use)."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def purl_for(name: str, version: str) -> str:
    return f"pkg:pypi/{normalize(name)}@{version}"


def find_pip_locks(directory: Path | str) -> list[Path]:
    """Pip-format ``*.lock`` files under ``directory`` (sorted; at most 64; none over 4 MB)."""
    root = Path(directory)
    found: list[Path] = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for f in sorted(files):
            if not f.lower().endswith(".lock") or f.lower() in _OTHER_LOCKS:
                continue
            path = Path(here) / f
            try:
                if path.is_symlink() or path.stat().st_size > _MAX_BYTES:
                    continue
            except OSError:
                continue
            if _looks_pip(path):
                found.append(path)
                if len(found) >= _MAX_FILES:
                    return found
    return found


def _looks_pip(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("--"):
            continue
        return bool(_PIN.match(s))  # the first requirement line decides
    return False


def parse_pip_lock(text: str) -> list[dict[str, Any]]:
    """``[{name, version, parents: [normalized names], direct: bool}]`` in file order."""
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_via = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            in_via = False
            continue
        if not stripped.startswith("#") and not stripped.startswith("--") and not line[:1].isspace():
            m = _PIN.match(stripped)
            current = None
            in_via = False
            if m:
                current = {"name": m.group(1), "version": m.group(2), "parents": [], "direct": False}
                entries.append(current)
            continue
        if current is None:
            continue
        m = _VIA_INLINE.match(line)
        if m:
            _add_via(current, m.group(1))
            in_via = False
            continue
        if _VIA_HEAD.match(line):
            in_via = True
            continue
        if in_via:
            m = _VIA_ITEM.match(line)
            if m:
                _add_via(current, m.group(1))
            else:
                in_via = False
    return entries


def _add_via(entry: dict[str, Any], via: str) -> None:
    via = via.strip()
    if via.startswith("-r ") or via.startswith("-c ") or via.endswith((".txt", ".in", ".toml")):
        entry["direct"] = True  # "-r requirements.txt", "pyproject.toml": the project itself asks for it
        return
    name = re.split(r"[\s(\[]", via, maxsplit=1)[0]
    if name and re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name):
        parent = normalize(name)
        if parent not in entry["parents"]:
            entry["parents"].append(parent)


def lock_document(directory: Path | str) -> dict[str, Any] | None:
    """A CycloneDX-shaped source document for every pip-format lock under ``directory`` (None when there is none).

    Components carry ``dss:version_source=lock_file`` and the lock's path as evidence; ``dependencies`` hold the
    ``# via`` edges, the root's entry holds the packages the project requires directly.
    """
    root_dir = Path(directory)
    paths = find_pip_locks(root_dir)
    if not paths:
        return None
    root_ref = "urn:dss:pip-lock-root"
    comps: dict[str, dict[str, Any]] = {}
    edges: dict[str, list[str]] = {}
    direct: list[str] = []
    for path in paths:
        rel = "/" + path.relative_to(root_dir).as_posix()
        entries = parse_pip_lock(path.read_text(encoding="utf-8", errors="ignore"))
        by_name = {normalize(e["name"]): purl_for(e["name"], e["version"]) for e in entries}
        for e in entries:
            ref = purl_for(e["name"], e["version"])
            comp = comps.get(ref)
            if comp is None:
                comp = {
                    "type": "library",
                    "bom-ref": ref,
                    "name": normalize(e["name"]),
                    "version": e["version"],
                    "purl": ref,
                    "properties": [{"name": "dss:version_source", "value": "lock_file"}],
                    "evidence": {"occurrences": []},
                }
                comps[ref] = comp
            occ = comp["evidence"]["occurrences"]
            if all(o["location"] != rel for o in occ):
                occ.append({"location": rel})
            if e["direct"] and ref not in direct:
                direct.append(ref)
            for parent in e["parents"]:
                parent_ref = by_name.get(parent)
                if parent_ref and parent_ref != ref:
                    kids = edges.setdefault(parent_ref, [])
                    if ref not in kids:
                        kids.append(ref)
    dependencies: list[dict[str, Any]] = [{"ref": root_ref, "dependsOn": direct}]
    for ref in comps:
        dependencies.append({"ref": ref, "dependsOn": edges.get(ref, [])})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "application", "name": "pip-lock", "bom-ref": root_ref}},
        "components": list(comps.values()),
        "dependencies": dependencies,
    }


__all__ = ["find_pip_locks", "lock_document", "normalize", "parse_pip_lock", "purl_for"]
