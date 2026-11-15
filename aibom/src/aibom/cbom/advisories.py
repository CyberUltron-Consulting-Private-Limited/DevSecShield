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
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path

from aibom.cbom.files import FileWalk

_MAX_BYTES = 8_388_608


@dataclass(frozen=True)
class Advisory:
    """One published advisory interval. ``fixed`` is the first version that is not
    affected; ``last_affected`` the last one that is (OSV, when no fix exists);
    ``versions`` an enumerated set (OSV ``affected.versions``): a row with only
    ``versions`` matches exactly those."""

    id: str
    ecosystem: str
    name: str
    introduced: str | None
    fixed: str | None
    summary: str
    source: str
    last_affected: str | None = None
    versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Pin:
    """A package version or range declared in the tree. ``line`` is the 1-based line of the declaration when the
    manifest format has lines worth naming (requirements / constraints files, ``go.mod``), else 0."""

    ecosystem: str
    name: str
    version: str | None
    low: str | None
    high: str | None
    path: str
    direct: bool
    declared: str
    line: int = 0


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


def _advisory(raw: dict) -> Advisory | None:
    name = str(raw.get("name") or "").strip().lower()
    ecosystem = str(raw.get("ecosystem") or "").strip().lower()
    ident = str(raw.get("id") or "").strip()
    if not name or not ecosystem or not ident:
        return None
    introduced = raw.get("introduced")
    fixed = raw.get("fixed")
    last = raw.get("last_affected")
    return Advisory(
        id=ident,
        ecosystem=ecosystem,
        name=name,
        introduced=str(introduced) if introduced else None,
        fixed=str(fixed) if fixed else None,
        summary=str(raw.get("summary") or ""),
        source=str(raw.get("source") or ""),
        last_affected=str(last) if last else None,
        versions=tuple(str(v) for v in raw.get("versions") or () if v),
    )


def curated_advisories() -> tuple[Advisory, ...]:
    """The shipped hand-curated file: rows OSV does not carry (NVD- or RustSec-only
    ones). No network."""
    blob = (
        files("aibom.cbom")
        .joinpath("data")
        .joinpath("crypto_advisories.json")
        .read_bytes()
    )
    document = json.loads(blob)
    raws = [r for r in document.get("advisories") or [] if isinstance(r, dict)]
    return tuple(a for a in (_advisory(r) for r in raws) if a is not None)


def snapshot_advisories(rows: Iterable[dict] | None = None) -> tuple[Advisory, ...]:
    """Rows of the OSV snapshot in force, or ``rows`` (the online fallback's)."""
    if rows is None:
        from aibom.cbom.osv_snapshot import load

        rows = load().rows
    found = (_advisory(raw) for raw in rows if isinstance(raw, dict))
    return tuple(r for r in found if r is not None)


def _merge(*groups: Iterable[Advisory]) -> tuple[Advisory, ...]:
    seen: dict[Advisory, None] = {}
    for group in groups:
        for advisory in group:
            seen.setdefault(advisory, None)
    return tuple(seen)


def load_advisories() -> tuple[Advisory, ...]:
    """The OSV snapshot in force plus the curated file. No network."""
    return _merge(snapshot_advisories(), curated_advisories())


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


def _pre_key(pre: str) -> list[tuple[int, int, str]]:
    """SemVer 2.0.0 section 11.4 pre-release precedence: dot-separated identifiers, numeric ones compared as numbers
    and below alphanumeric ones. A Go pseudo-version (``v0.0.0-20190308221718-c2843e01d9a2``,
    ``v1.2.4-0.20191109021931-daa7c04131f5``) carries a fixed-width UTC timestamp first, so this orders pseudo-versions
    of one base version by commit date, as the Go toolchain does (https://go.dev/ref/mod#pseudo-versions)."""
    return [(0, int(ident), "") if ident.isdigit() else (1, 0, ident) for ident in pre.split(".")]


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
    return -1 if _pre_key(lp) < _pre_key(rp) else 1


def _bare(version: str) -> str:
    return version.strip().lstrip("vV").split("+", 1)[0]


def _only_listed(advisory: Advisory) -> bool:
    bounded = advisory.introduced or advisory.fixed or advisory.last_affected
    return bool(advisory.versions) and not bounded


def _below_fixed(version: str, advisory: Advisory) -> bool:
    if advisory.versions and _bare(version) in {_bare(v) for v in advisory.versions}:
        return True
    if _only_listed(advisory):
        return False
    too_old = advisory.introduced and compare_versions(version, advisory.introduced) < 0
    fixed = advisory.fixed and compare_versions(version, advisory.fixed) >= 0
    last = advisory.last_affected
    past_last = last and compare_versions(version, last) > 0
    return not too_old and not fixed and not past_last


def _in(version: str, low: str | None, high: str | None) -> bool:
    above = low is None or compare_versions(version, low) >= 0
    return above and (high is None or compare_versions(version, high) < 0)


def _range_hits(low: str | None, high: str | None, advisory: Advisory) -> bool:
    if _only_listed(advisory):
        return any(_in(v, low, high) for v in advisory.versions)
    last = advisory.last_affected
    if last is not None and low is not None and compare_versions(low, last) > 0:
        return False
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
    # an exact version, also a Go pseudo-version (``v0.0.0-20190308221718-c2843e01d9a2``) or ``+incompatible`` tag
    if re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+){0,4}", text):
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
    line: int = 0,
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
        line=line,
    )


def _name_matches(pin: Pin, advisory: Advisory) -> bool:
    """Same ecosystem and name; a Go package inside the advisory's module matches it,
    a major-version module (``.../v4``) is another module (semantic import
    versioning)."""
    if pin.ecosystem != advisory.ecosystem:
        return False
    if pin.name == advisory.name:
        return True
    if pin.ecosystem != "go" or not pin.name.startswith(advisory.name + "/"):
        return False
    rest = pin.name[len(advisory.name) + 1 :]
    return re.match(r"v\d+(/|$)", rest) is None


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
    """A pip requirements or constraints file. An environment marker (``; python_version < "3.8"``) and per-line
    options (``--hash=…``) after the version are not part of it."""
    pins: list[Pin] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name, sep, spec = line.partition("==")
        if sep:
            base = name.split("[", 1)[0].strip()
            version = spec.strip().split()[0] if spec.strip() else ""
            pin = _pin("pypi", base, version, path, direct=True, line=number)
        else:
            matched = re.match(r"([A-Za-z0-9_.\-]+)\s*(>=[^\s]+)", line)
            if not matched:
                continue
            pin = _pin("pypi", matched.group(1), matched.group(2), path, direct=True, line=number)
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


_PACKAGE_REF = re.compile(r"<PackageReference\b([^>]*)>", re.I)
_ATTR = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_VERSION_CHILD = re.compile(r"<Version>\s*([^<]+?)\s*</Version>", re.I)


def _csproj(text: str, path: str) -> list[Pin]:
    """An SDK-style .NET project's ``<PackageReference Include="X" Version="1.2" />``
    (attribute or child element). A centrally managed version stays unmatched."""
    pins: list[Pin] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        for match in _PACKAGE_REF.finditer(raw):
            attrs = {k.lower(): v for k, v in _ATTR.findall(match.group(1))}
            name = attrs.get("include") or attrs.get("update")
            version = attrs.get("version")
            if not version:
                child = _VERSION_CHILD.search(text, text.find(match.group(0)))
                version = child.group(1) if child else None
            if not name or not version or version.startswith("$("):
                continue
            declared = version.strip("[]() ")
            pin = _pin("nuget", name, declared, path, direct=True, line=number)
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
    for number, raw in enumerate(text.splitlines(), start=1):
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
        pin = _pin("go", parts[0], parts[1], path, direct=True, line=number)
        if pin is not None:
            pins.append(pin)
    return pins


# pip requirement and constraint files under any of their usual names (``requirements-dev.txt``,
# ``requirements_test.txt``, ``constraints.txt``); a ``requirements/`` directory of ``*.txt`` files is not read.
_PIP_FILES = ("requirements*.txt", "constraints*.txt")


def _parser_for(name: str):
    parser = _PARSERS.get(name)
    if parser is None and name.endswith((".csproj", ".fsproj", ".vbproj")):
        return _csproj
    if parser is None and any(fnmatchcase(name, pattern) for pattern in _PIP_FILES):
        return _requirements
    return parser


def iter_pins(root: Path, walk: FileWalk | None = None) -> Iterator[Pin]:
    """Every version pin under ``root``, skipping dependency install trees (the shared walk)."""
    walk = walk or FileWalk(root)
    go_direct: set[str] = set()
    manifests = walk.files(
        lambda p: _parser_for(p.name.lower()) is not None or p.name.lower() in {"go.mod", "go.sum"},
        max_bytes=_MAX_BYTES,
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
        parser = _parser_for(name)
        if parser is not None:
            yield from parser(text, rel)
    for path in manifests:
        if path.name != "go.sum":
            continue
        text = _read(walk, path)
        if text is None:
            continue
        yield from _go_sum(text, walk.rel(path), go_direct)


_STATUS: dict[str, dict] = {}


def advisories_for(pins: Iterable[Pin]) -> tuple[Advisory, ...]:
    """The advisories to match these pins against (CB-29 fallback rules): the OSV
    snapshot in force and the curated file. When the snapshot is stale and
    ``CBOM_OSV_ONLINE=1``, the tracked packages these pins name are asked of OSV live
    and OSV's rows replace the snapshot's for each package it answered (one it did not
    answer keeps the snapshot's). ``last_status()`` says which data was used."""
    from aibom.cbom import osv_snapshot as snap_mod

    snap = snap_mod.load()
    online = None
    rows = snap.rows
    if snap.stale() and snap_mod.online_enabled():
        listed = snap_mod.package_list().items()
        tracked = snap.packages() | {(e, n.lower()) for e, ns in listed for n in ns}
        wanted = {(p.ecosystem, p.name) for p in pins}
        wanted &= tracked
        fresh, answered = snap_mod.online_rows(wanted) if wanted else ([], set())
        kept = [
            r for r in snap.rows if (r.get("ecosystem"), r.get("name")) not in answered
        ]
        rows = (*kept, *fresh)
        online = {"asked": len(wanted), "answered": len(answered)}
    _STATUS["last"] = snap_mod.status(snap, online=online)
    return _merge(snapshot_advisories(rows), curated_advisories())


def last_status() -> dict:
    """The advisory data the last ``find_vulnerable`` in this process used."""
    if "last" not in _STATUS:
        from aibom.cbom import osv_snapshot as snap_mod

        return snap_mod.status()
    return dict(_STATUS["last"])


def find_vulnerable(root: Path, walk: FileWalk | None = None) -> tuple[AdvisoryHit, ...]:
    """Advisory hits for one repository tree."""
    pins = list(iter_pins(root, walk))
    return match_advisories(pins, advisories_for(pins))


@dataclass(frozen=True)
class VulnerablePin:
    """One declared package version with every advisory it matches: one inventory row, not one row per CVE."""

    pin: Pin
    advisories: tuple[Advisory, ...]

    @property
    def ref(self) -> str:
        raw = f"{self.pin.ecosystem}-{self.pin.name}-{self.pin.declared}"
        slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
        return f"crypto-advisory-{slug}"[:180]

    @property
    def upgrade_to(self) -> str | None:
        """The lowest version that fixes every matched advisory, or None when one of them has no fixed release."""
        fixes = [advisory.fixed for advisory in self.advisories]
        if not fixes or any(fix is None for fix in fixes):
            return None
        best = fixes[0]
        for fix in fixes[1:]:
            if compare_versions(fix, best) > 0:  # type: ignore[arg-type]
                best = fix
        return best


def group_by_pin(hits: Iterable[AdvisoryHit]) -> tuple[VulnerablePin, ...]:
    """Hits grouped per declared package version (the first declaration found keeps its path and line)."""
    order: list[tuple[str, str, str]] = []
    pins: dict[tuple[str, str, str], Pin] = {}
    found: dict[tuple[str, str, str], list[Advisory]] = {}
    for hit in hits:
        key = (hit.pin.ecosystem, hit.pin.name, hit.pin.declared)
        if key not in pins:
            order.append(key)
            pins[key] = hit.pin
            found[key] = []
        if hit.advisory not in found[key]:
            found[key].append(hit.advisory)
    return tuple(
        VulnerablePin(pin=pins[key], advisories=tuple(sorted(found[key], key=lambda a: a.id))) for key in order
    )
