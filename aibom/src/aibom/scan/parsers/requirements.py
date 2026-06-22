"""Parse a ``requirements.txt`` manifest into framework/library components.

Each pinned/declared dependency becomes a :class:`FrameworkComponent`
(serialized to a CycloneDX ``library``) with a ``pkg:pypi/...`` purl. Output is
sorted by name for deterministic, golden-stable BOMs.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import FrameworkComponent

# name == version  -- we only capture an exact pin; other specifiers fall back
# to a name-only component (version omitted).
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*==\s*(?P<version>[A-Za-z0-9._*+!-]+)"
)
_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)")


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
            purl=f"pkg:pypi/{name.lower()}@{version}",
        )

    named = _NAME_RE.match(stripped)
    if named:
        name = named.group("name")
        return FrameworkComponent(
            bom_ref=f"lib-{name.lower()}",
            name=name,
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


__all__ = ["parse_requirements"]
