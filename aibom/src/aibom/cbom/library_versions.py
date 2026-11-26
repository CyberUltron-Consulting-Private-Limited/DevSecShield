"""The version of each crypto library a CBOM lists, from manifests and lockfiles.

A CBOM row "pyca/cryptography" without a version cannot be matched to an advisory or
checked against a policy. The
version is read, offline, from what the repository already declares: lockfiles first (an
exact resolved version:
``uv.lock``, ``poetry.lock``, ``Pipfile.lock``, ``package-lock.json``, ``Cargo.lock``,
``go.sum`` …), then an exact
pin in a manifest (``cryptography==41.0.7``), else the declared range is kept as the
constraint. When nothing in the
tree names a version the row says why (``crypto:versionUnknownReason``): an optional
import that no manifest
declares, or a standard-library module whose version is the language runtime's (with the
Dockerfile base image when
one names it).
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from aibom.cbom.advisories import Pin, iter_pins
from aibom.cbom.files import FileWalk
from aibom.cbom.image_refs import image_references
from aibom.cbom.rules import CRYPTO_LIBRARY_PACKAGES, match_dep_coordinate

_MAX_LOCK_BYTES = 4 * 1024 * 1024
_PY_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock", "pipfile.lock")
# a standard-library label -> the base image repositories that carry its runtime
_RUNTIMES = (
    ("(stdlib)", ("python", "node", "golang", "eclipse-temurin", "openjdk", "rust")),
    ("JCA/JCE", ("eclipse-temurin", "openjdk", "amazoncorretto")),
)
_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "golang",
    "cargo": "cargo",
    "crate": "cargo",
    "nuget": "nuget",
}


@dataclass(frozen=True)
class LibraryVersion:
    version: str | None
    purl: str | None
    source: str | None
    constraint: str | None
    unknown_reason: str | None

    def properties(self) -> dict[str, str]:
        props: dict[str, str] = {}
        if self.source:
            props["crypto:versionSource"] = self.source
        if self.constraint:
            props["crypto:versionConstraint"] = self.constraint
        if self.unknown_reason:
            props["crypto:versionUnknownReason"] = self.unknown_reason
        return props


def _purl(ecosystem: str, name: str, version: str | None) -> str | None:
    """The package URL; without a version (``pkg:pypi/cryptography``) when only a range
    is declared: the package is
    known, its installed version is not (staging QA Q2-09)."""
    kind = _PURL_TYPE.get(ecosystem)
    if kind is None:
        return None
    at = f"@{quote(version)}" if version else ""
    if kind == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}{at}"
    if kind == "npm" and name.startswith("@"):
        return f"pkg:npm/{quote(name, safe='/')}{at}"
    return f"pkg:{kind}/{name}{at}"


purl_of = _purl


def _python_lock_pins(walk: FileWalk) -> list[Pin]:
    """Exact versions from Python lockfiles ``advisories.iter_pins`` does not read."""
    pins: list[Pin] = []
    for path in walk.files(
        lambda p: p.name.lower() in _PY_LOCKS, max_bytes=_MAX_LOCK_BYTES
    ):
        text = walk.read_text(path, _MAX_LOCK_BYTES)
        if text is None:
            continue
        rel = walk.rel(path)
        rows: list[tuple[str, str]] = []
        if path.name.lower() == "pipfile.lock":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            for section in ("default", "develop"):
                for name, body in (
                    (doc.get(section) or {}).items() if isinstance(doc, dict) else ()
                ):
                    version = body.get("version") if isinstance(body, dict) else None
                    if isinstance(version, str) and version.startswith("=="):
                        rows.append((name, version[2:]))
        else:
            try:
                doc = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, ValueError):
                continue
            for package in doc.get("package") or []:
                if (
                    isinstance(package, dict)
                    and isinstance(package.get("name"), str)
                    and isinstance(package.get("version"), str)
                ):
                    rows.append((package["name"], package["version"]))
        for name, version in rows:
            pins.append(
                Pin(
                    "pypi",
                    name.lower(),
                    version,
                    None,
                    None,
                    rel,
                    False,
                    f"=={version}",
                )
            )
    return pins


def _pyproject_pins(walk: FileWalk) -> list[Pin]:
    pins: list[Pin] = []
    for path in walk.files(lambda p: p.name == "pyproject.toml"):
        text = walk.read_text(path)
        if text is None:
            continue
        try:
            doc = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            continue
        project = doc.get("project")
        if not isinstance(project, dict):
            project = {}
        deps = list(project.get("dependencies") or [])
        for group in (project.get("optional-dependencies") or {}).values():
            deps.extend(group or [])
        for dep in deps:
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([^;]*)", str(dep))
            if not m:
                continue
            spec = m.group(2).strip()
            exact = re.fullmatch(r"==\s*([A-Za-z0-9.+!_-]+)", spec)
            pins.append(
                Pin(
                    "pypi",
                    m.group(1).lower(),
                    exact.group(1) if exact else None,
                    None,
                    None,
                    walk.rel(path),
                    True,
                    spec,
                )
            )
    return pins


def _label_of(pin: Pin) -> str | None:
    if pin.ecosystem == "pypi":
        return CRYPTO_LIBRARY_PACKAGES.get(pin.name) or CRYPTO_LIBRARY_PACKAGES.get(
            pin.name.replace("_", "-")
        )
    eco = "crate" if pin.ecosystem == "cargo" else pin.ecosystem
    return match_dep_coordinate(eco, pin.name)


def _runtime_reason(label: str, walk: FileWalk) -> str | None:
    for marker, repos in _RUNTIMES:
        if marker not in label:
            continue
        refs, _total = image_references(walk)
        for ref in refs:
            if (
                ref.origin == "dockerfile"
                and ref.repository.rsplit("/", 1)[-1].lower() in repos
            ):
                return (
                    "part of the language runtime: the version is the runtime's "
                    f"({ref.reference}, "
                    f"{ref.source}:{ref.line})"
                )
        return (
            "part of the language runtime: the version is the runtime's "
            "(no base image names it)"
        )
    return None


def resolve_library_versions(
    root: Path, walk: FileWalk, labels: list[str]
) -> dict[str, LibraryVersion]:
    """label -> what the tree says about its version (see the module docstring)."""
    if not labels:
        return {}
    wanted = set(labels)
    exact: dict[str, tuple[int, Pin]] = {}
    ranges: dict[str, Pin] = {}
    for pin in [
        *iter_pins(root, walk),
        *_python_lock_pins(walk),
        *_pyproject_pins(walk),
    ]:
        label = _label_of(pin)
        if label not in wanted:
            continue
        if pin.version:
            rank = (
                0 if not pin.direct else 1
            )  # a lockfile's resolved version wins over a manifest pin
            if label not in exact or rank < exact[label][0]:
                exact[label] = (rank, pin)
        elif pin.declared and label not in ranges:
            ranges[label] = pin
    out: dict[str, LibraryVersion] = {}
    for label in labels:
        if label in exact:
            pin = exact[label][1]
            assert pin.version is not None
            out[label] = LibraryVersion(
                pin.version,
                _purl(pin.ecosystem, pin.name, pin.version),
                pin.path,
                ranges[label].declared if label in ranges else None,
                None,
            )
        elif label in ranges:
            pin = ranges[label]
            out[label] = LibraryVersion(
                None,
                _purl(pin.ecosystem, pin.name, None),
                pin.path,
                pin.declared,
                "only a version range is declared and no lockfile resolves it",
            )
        else:
            reason = _runtime_reason(label, walk) or (
                "no manifest or lockfile in the tree declares it "
                "(an optional or transitive import)"
            )
            out[label] = LibraryVersion(None, None, None, None, reason)
    return out


__all__ = ["LibraryVersion", "purl_of", "resolve_library_versions"]
