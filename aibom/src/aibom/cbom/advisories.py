"""Offline crypto-library advisory match.

Reads manifests and lockfiles that are already in the tree. Nothing is
downloaded and nothing is installed. A version that is absent stays
unmatched.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from aibom.cbom.files import FileWalk

_MAX_BYTES = 8_388_608


@dataclass(frozen=True)
class Advisory:
    """One published advisory. ``fixed`` is the first version that is not affected."""

    id: str
    ecosystem: str
    name: str
    introduced: str | None
    fixed: str | None
    summary: str
    source: str


@dataclass(frozen=True)
class Pin:
    """A package version or range declared in the tree."""

    ecosystem: str
    name: str
    version: str | None
    low: str | None
    high: str | None
    path: str
    direct: bool
    declared: str


@dataclass(frozen=True)
class AdvisoryHit:
    """One package version that intersects one advisory."""

    advisory: Advisory
    pin: Pin

    @property
    def ref(self) -> str:
        raw = (
            f"{self.pin.ecosystem}-{self.pin.name}-"
            f"{self.pin.declared}-{self.advisory.id}"
        )
        slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
        return f"crypto-advisory-{slug}"[:180]


def load_advisories() -> tuple[Advisory, ...]:
    """The shipped advisory file. No network."""
    blob = (
        files("aibom.cbom")
        .joinpath("data")
        .joinpath("crypto_advisories.json")
        .read_bytes()
    )
    document = json.loads(blob)
    rows: list[Advisory] = []
    for raw in document.get("advisories") or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip().lower()
        ecosystem = str(raw.get("ecosystem") or "").strip().lower()
        ident = str(raw.get("id") or "").strip()
        if not name or not ecosystem or not ident:
            continue
        introduced = raw.get("introduced")
        fixed = raw.get("fixed")
        rows.append(
            Advisory(
                id=ident,
                ecosystem=ecosystem,
                name=name,
                introduced=str(introduced) if introduced else None,
                fixed=str(fixed) if fixed else None,
                summary=str(raw.get("summary") or ""),
                source=str(raw.get("source") or ""),
            )
        )
    return tuple(rows)


def _parts(version: str) -> tuple[list[int], str | None]:
    text = version.strip().lstrip("vV").split("+", 1)[0]
    pre: str | None = None
    if "-" in text:
        text, pre = text.split("-", 1)
    nums: list[int] = []
    for piece in text.split("."):
        digits = ""
        for char in piece:
            if char.isdigit():
                digits += char
            else:
                break
        nums.append(int(digits) if digits else 0)
    return nums or [0], pre


def compare_versions(left: str, right: str) -> int:
    """-1, 0, or 1. A pre-release sorts before the matching release."""
    ln, lp = _parts(left)
    rn, rp = _parts(right)
    width = max(len(ln), len(rn))
    ln = ln + [0] * (width - len(ln))
    rn = rn + [0] * (width - len(rn))
    if ln != rn:
        return -1 if ln < rn else 1
    if lp == rp:
        return 0
    if lp is None:
        return 1
    if rp is None:
        return -1
    return -1 if lp < rp else 1


def _below_fixed(version: str, advisory: Advisory) -> bool:
    too_old = advisory.introduced and compare_versions(version, advisory.introduced) < 0
    fixed = advisory.fixed and compare_versions(version, advisory.fixed) >= 0
    return not too_old and not fixed


def _range_hits(low: str | None, high: str | None, advisory: Advisory) -> bool:
    starts_after = (
        high is not None
        and advisory.introduced is not None
        and compare_versions(high, advisory.introduced) <= 0
    )
    ends_before = (
        advisory.fixed is not None
        and low is not None
        and compare_versions(low, advisory.fixed) >= 0
    )
    return not starts_after and not ends_before


def _caret(version: str) -> tuple[str, str]:
    nums = [int(piece) if piece.isdigit() else 0 for piece in version.split(".")[:3]]
    while len(nums) < 3:
        nums.append(0)
    major, minor, patch = nums
    if major > 0:
        ceiling = f"{major + 1}.0.0"
    elif minor > 0:
        ceiling = f"0.{minor + 1}.0"
    else:
        ceiling = f"0.0.{patch + 1}"
    return version, ceiling


def _tilde(version: str) -> tuple[str, str]:
    nums = [int(piece) if piece.isdigit() else 0 for piece in version.split(".")[:3]]
    while len(nums) < 3:
        nums.append(0)
    return version, f"{nums[0]}.{nums[1] + 1}.0"


def _one_specifier(text: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(exact, low, high)`` for one comparison. ``high`` is exclusive."""
    if not text or text in {"*", "latest"}:
        return None, "0", None
    if text.startswith("^"):
        low, high = _caret(text[1:])
        return None, low, high
    if text.startswith("~"):
        low, high = _tilde(text[1:])
        return None, low, high
    if text.startswith("=="):
        return text[2:].strip(), None, None
    if text.startswith(">="):
        return None, text[2:].strip(), None
    if text.startswith("<="):
        return None, None, None
    if text.startswith("<"):
        return None, None, text[1:].strip()
    if text.startswith(">"):
        return None, text[1:].strip(), None
    if re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?", text):
        return text.lstrip("vV"), None, None
    return None, None, None


def parse_specifier(spec: str) -> tuple[str | None, str | None, str | None]:
    """Return ``(exact, low, high)``. ``high`` is exclusive. None if unreadable."""
    text = spec.strip().strip("\"'")
    if "," not in text:
        return _one_specifier(text)
    exact: str | None = None
    low: str | None = None
    high: str | None = None
    for part in text.split(","):
        piece, piece_low, piece_high = _one_specifier(part.strip())
        if piece:
            return piece, None, None
        if piece_low:
            low = piece_low
        if piece_high:
            high = piece_high
    if exact is None and low is None and high is None:
        return None, None, None
    return exact, low, high


def _pin(
    ecosystem: str,
    name: str,
    declared: str,
    path: str,
    *,
    direct: bool,
) -> Pin | None:
    exact, low, high = parse_specifier(declared)
    if exact is None and low is None and high is None:
        return None
    return Pin(
        ecosystem=ecosystem,
        name=name.strip().lower(),
        version=exact,
        low=low,
        high=high,
        path=path,
        direct=direct,
        declared=declared.strip(),
    )


def _name_matches(pin: Pin, advisory: Advisory) -> bool:
    if pin.ecosystem != advisory.ecosystem:
        return False
    if pin.name == advisory.name:
        return True
    return pin.ecosystem == "go" and pin.name.startswith(advisory.name + "/")


def _affected(pin: Pin, advisory: Advisory) -> bool:
    if not _name_matches(pin, advisory):
        return False
    if pin.version is not None:
        return _below_fixed(pin.version, advisory)
    return _range_hits(pin.low, pin.high, advisory)


def match_advisories(
    pins: Iterable[Pin], advisories: Iterable[Advisory]
) -> tuple[AdvisoryHit, ...]:
    """Unique hits. The same package version is reported once per advisory."""
    seen: set[tuple[str, str, str, str]] = set()
    hits: list[AdvisoryHit] = []
    for pin in pins:
        for advisory in advisories:
            if not _affected(pin, advisory):
                continue
            key = (advisory.id, pin.ecosystem, pin.name, pin.declared)
            if key in seen:
                continue
            seen.add(key)
            hits.append(AdvisoryHit(advisory=advisory, pin=pin))
    hits.sort(key=lambda hit: (hit.pin.path, hit.pin.name, hit.advisory.id))
    return tuple(hits)


def _read(walk: FileWalk, path: Path) -> str | None:
    return walk.read_text(path, _MAX_BYTES)


def _requirements(text: str, path: str) -> list[Pin]:
    pins: list[Pin] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name, sep, spec = line.partition("==")
        if sep:
            base = name.split("[", 1)[0].strip()
            pin = _pin("pypi", base, spec.strip(), path, direct=True)
        else:
            matched = re.match(r"([A-Za-z0-9_.\-]+)\s*(>=.+)$", line)
            if not matched:
                continue
            pin = _pin("pypi", matched.group(1), matched.group(2), path, direct=True)
        if pin is not None:
            pins.append(pin)
    return pins


def _package_json(text: str, path: str) -> list[Pin]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    pins: list[Pin] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = document.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            if spec.startswith("file:") or spec.startswith("link:"):
                continue
            pin = _pin("npm", name, spec, path, direct=True)
            if pin is not None:
                pins.append(pin)
    return pins


def _package_lock(text: str, path: str) -> list[Pin]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    packages = document.get("packages")
    root = packages.get("") if isinstance(packages, dict) else {}
    direct: set[str] = set()
    if isinstance(root, dict):
        for section in ("dependencies", "devDependencies"):
            deps = root.get(section)
            if isinstance(deps, dict):
                direct.update(str(name).lower() for name in deps)
    for section in ("dependencies", "devDependencies"):
        deps = document.get(section)
        if isinstance(deps, dict):
            direct.update(str(name).lower() for name in deps)
    pins: list[Pin] = []
    packages = document.get("packages")
    if not isinstance(packages, dict):
        return pins
    for key, meta in packages.items():
        nested = "node_modules/" in key
        if not isinstance(key, str) or not nested or not isinstance(meta, dict):
            continue
        name = key.split("node_modules/")[-1].lower()
        version = meta.get("version")
        if not isinstance(version, str):
            continue
        pin = _pin("npm", name, version, path, direct=name in direct)
        if pin is not None:
            pins.append(pin)
    return pins


def _go_mod_direct(text: str) -> set[str]:
    names: set[str] = set()
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require ") or in_block:
            parts = line.removeprefix("require ").split()
            if parts:
                names.add(parts[0].lower())
    return names


def _go_sum(text: str, path: str, direct: set[str]) -> list[Pin]:
    pins: list[Pin] = []
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        key = (module.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        pin = _pin("go", module, version, path, direct=module.lower() in direct)
        if pin is not None:
            pins.append(pin)
    return pins


def _pom(text: str, path: str) -> list[Pin]:
    pins: list[Pin] = []
    blocks = re.findall(r"<dependency\b[^>]*>.*?</dependency>", text, flags=re.S | re.I)
    for block in blocks:
        group = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block, re.I)
        artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block, re.I)
        version = re.search(r"<version>\s*([^<$][^<]*)\s*</version>", block, re.I)
        if not group or not artifact or not version:
            continue
        name = f"{group.group(1)}:{artifact.group(1)}"
        pin = _pin("maven", name, version.group(1).strip(), path, direct=True)
        if pin is not None:
            pins.append(pin)
    return pins


def _cargo_lock(text: str, path: str) -> list[Pin]:
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    pins: list[Pin] = []
    for package in document.get("package") or []:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            pin = _pin("cargo", name, version, path, direct=False)
            if pin is not None:
                pins.append(pin)
    return pins


def _nuget_lock(text: str, path: str) -> list[Pin]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    pins: list[Pin] = []
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, dict):
        return pins
    for framework in dependencies.values():
        if not isinstance(framework, dict):
            continue
        for name, meta in framework.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("resolved") or meta.get("version")
            if isinstance(version, str):
                direct = str(meta.get("type") or "").lower() == "direct"
                pin = _pin("nuget", name, version, path, direct=direct)
                if pin is not None:
                    pins.append(pin)
    return pins


def _gradle_lock(text: str, path: str) -> list[Pin]:
    pins: list[Pin] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        coord = line.split("=", 1)[0]
        pieces = coord.split(":")
        if len(pieces) < 3:
            continue
        name = f"{pieces[0]}:{pieces[1]}"
        pin = _pin("maven", name, pieces[2], path, direct=False)
        if pin is not None:
            pins.append(pin)
    return pins


_PARSERS = {
    "requirements.txt": _requirements,
    "package.json": _package_json,
    "package-lock.json": _package_lock,
    "pom.xml": _pom,
    "cargo.lock": _cargo_lock,
    "packages.lock.json": _nuget_lock,
    "gradle.lockfile": _gradle_lock,
}


def _go_mod_pins(text: str, path: str) -> list[Pin]:
    pins: list[Pin] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not (line.startswith("require ") or in_block):
            continue
        parts = line.removeprefix("require ").split()
        if len(parts) < 2:
            continue
        pin = _pin("go", parts[0], parts[1], path, direct=True)
        if pin is not None:
            pins.append(pin)
    return pins


def iter_pins(root: Path, walk: FileWalk | None = None) -> Iterator[Pin]:
    """Every version pin under ``root``, skipping dependency install trees (the shared walk)."""
    walk = walk or FileWalk(root)
    go_direct: set[str] = set()
    manifests = walk.files(
        lambda p: p.name.lower() in _PARSERS or p.name.lower() in {"go.mod", "go.sum"}, max_bytes=_MAX_BYTES
    )
    for path in manifests:
        name = path.name.lower()
        text = _read(walk, path)
        if text is None:
            continue
        rel = walk.rel(path)
        if name == "go.mod":
            go_direct |= _go_mod_direct(text)
            yield from _go_mod_pins(text, rel)
            continue
        if name == "go.sum":
            continue
        parser = _PARSERS.get(name)
        if parser is not None:
            yield from parser(text, rel)
    for path in manifests:
        if path.name != "go.sum":
            continue
        text = _read(walk, path)
        if text is None:
            continue
        yield from _go_sum(text, walk.rel(path), go_direct)


def find_vulnerable(root: Path, walk: FileWalk | None = None) -> tuple[AdvisoryHit, ...]:
    """Advisory hits for one repository tree."""
    return match_advisories(iter_pins(root, walk), load_advisories())
