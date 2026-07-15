"""Parse a ``requirements.txt`` / ``pyproject.toml`` manifest into framework
components.

Each pinned/declared dependency becomes a :class:`FrameworkComponent`
(serialized to a CycloneDX ``library``) with a ``pkg:pypi/...`` purl. Output is
sorted by name for deterministic, golden-stable BOMs. ``pyproject.toml`` is the
modern default for AI/agent repos (MCP servers, autogen, trl, langchain) — a
``requirements.txt``-only scanner finds nothing in them.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from aibom.model.component import FrameworkComponent
from aibom.scan.parsers.license_resolver import resolve_license
from aibom.scan.parsers.licenses import license_choice

# strip a PEP 508 dependency spec down to the distribution name:
#   "mcp[cli]>=1.0,<2 ; python_version>='3.10'"  ->  "mcp"
_DEP_NAME = re.compile(r"^\s*(?P<name>[A-Za-z0-9._-]+)")

# name == version  -- we only capture an exact pin; other specifiers fall back
# to a name-only component (version omitted).
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[A-Za-z0-9._*+!-]+)"
)
_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)")


def _licenses_for(name: str) -> list[dict] | None:
    """Deterministic license resolution (curated manifest) -> licenseChoice list.

    Map-only by design, so the emitted BOM stays byte-reproducible across
    machines. ``None`` (genuinely unknown) leaves the component unlicensed for
    the requirements scanner to flag.
    """
    spdx = resolve_license(name)
    return [license_choice(spdx)] if spdx else None


def _parse_line(line: str) -> FrameworkComponent | None:
    """Parse a single requirements line into a component, or None to skip."""
    stripped = line.split("#", 1)[0].strip()
    if not stripped:
        return None
    # Skip pip options, includes, editable installs, URLs, env markers.
    if stripped.startswith(("-", "--", "git+", "http://", "https://")):
        return None

    pinned = _PIN_RE.match(stripped)
    if pinned:
        name = pinned.group("name")
        version = pinned.group("version")
        return FrameworkComponent(
            bom_ref=f"lib-{name.lower()}",
            name=name,
            version=version,
            licenses=_licenses_for(name),
            purl=f"pkg:pypi/{name.lower()}@{version}",
        )

    named = _NAME_RE.match(stripped)
    if named:
        name = named.group("name")
        return FrameworkComponent(
            bom_ref=f"lib-{name.lower()}",
            name=name,
            licenses=_licenses_for(name),
            purl=f"pkg:pypi/{name.lower()}",
        )
    return None


def parse_requirements(path: Path) -> list[FrameworkComponent]:
    """Return the library components declared in ``requirements.txt`` (sorted)."""
    if not path.is_file():
        return []
    comps: dict[str, FrameworkComponent] = {}
    for line in path.read_text().splitlines():
        comp = _parse_line(line)
        if comp is not None:
            comps[comp.bom_ref] = comp  # de-dup by bom_ref, last wins
    return [comps[k] for k in sorted(comps)]


def _component_for(name: str, version: str | None = None) -> FrameworkComponent:
    name = name.strip()
    purl = f"pkg:pypi/{name.lower()}" + (f"@{version}" if version else "")
    return FrameworkComponent(
        bom_ref=f"lib-{name.lower()}", name=name, version=version,
        licenses=_licenses_for(name), purl=purl,
    )


def parse_pyproject(
    path: Path, *, include_self: bool = True
) -> list[FrameworkComponent]:
    """Return components for a ``pyproject.toml``: every declared dependency (PEP 621
    ``[project].dependencies`` + optional-dependencies, and legacy
    ``[tool.poetry].dependencies``), plus — when ``include_self`` — the project's own
    ``[project].name``. ``python`` is skipped.

    The scanner passes ``include_self=False`` for the SCAN-ROOT pyproject (the repo is
    not its own dependency — emitting it skews governance + double-counts the subject)
    but ``True`` for SUB-package pyprojects, so a monorepo's members (e.g. the MCP
    reference servers ``mcp-server-fetch`` / ``-git`` / ``-time``) are inventoried.
    """
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text())
    except (tomllib.TOMLDecodeError, OSError, ValueError):
        return []
    comps: dict[str, FrameworkComponent] = {}

    def _add(name: str | None, version: str | None = None) -> None:
        if not name:
            return
        m = _DEP_NAME.match(name)
        if not m:
            return
        nm = m.group("name")
        if nm.lower() in ("python", ""):
            return
        comps.setdefault(f"lib-{nm.lower()}", _component_for(nm, version))

    project = data.get("project", {}) or {}
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    if include_self:
        _add(project.get("name"), project.get("version"))       # the package itself
        _add(poetry.get("name"), poetry.get("version"))
    # RUNTIME dependencies only. optional-dependencies / dependency-groups are
    # overwhelmingly dev/test/docs tooling (pytest, mypy, sphinx, build) — not AI
    # components, and counting them as unlicensed "frameworks" skews governance.
    for dep in project.get("dependencies", []) or []:
        _add(dep)
    for name in (poetry.get("dependencies", {}) or {}):
        _add(name)
    return [comps[k] for k in sorted(comps)]


__all__ = ["parse_requirements", "parse_pyproject"]
