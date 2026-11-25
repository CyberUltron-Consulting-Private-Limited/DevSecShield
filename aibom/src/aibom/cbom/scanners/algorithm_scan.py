"""CBOM scanner (C1): crypto **algorithms** + crypto **libraries**.

Reconciled from the worker ``cbom_agent`` (``crypto_rules.py`` /
``source_scanner.py``): it preserves that detection knowledge (the algorithm
strength tables, normalization, multi-language symbols, ambiguous-token gating —
all in :mod:`aibom.cbom.rules`) and ADDS the per-usage **parametrization** the
worker lacked — key size, cipher mode, and curve pulled off the same source line
— so a usage resolves to ``RSA-2048`` vs ``RSA-1024`` and ``AES-GCM`` vs
``AES-ECB`` instead of a flat ``RSA`` / ``AES``.

Emits (lane discipline — EMIT only, never score/flag-weight/serialize):

* one ``crypto_asset`` component per distinct (algorithm, params, file) usage,
  with all crypto detail in ``crypto:`` ``properties`` (assetType=algorithm,
  primitive, keySize, mode, curve, strength, quantumVulnerable);
* one ``framework`` component per detected crypto **library** (declared in
  ``requirements.txt`` or imported), tagged ``crypto:role=library``.

Weak-algorithm FLAGGING is C5; PQC grading is C6; the CycloneDX crypto-asset
serialization is C4. C1 only inventories.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from aibom.cbom.detect import (
    _strip_line_comment,
    crypto_read_sites,
    detect_crypto,
    strip_noncode,
)
from aibom.cbom.files import FileWalk, file_walk
from aibom.cbom.library_versions import resolve_library_versions
from aibom.cbom.project import ProjectIndex, project_index
from aibom.cbom.purpose import hash_purpose
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    COMPOSITE_PARTS,
    CRYPTO_IMPORT_MODULES,
    CRYPTO_IMPORT_MODULES_BY_LANG,
    CRYPTO_LIBRARY_PACKAGES,
    PQC_FIPS_NAME,
    algo_info,
    match_dep_coordinate,
    source_language,
)
from aibom.model.component import CryptoAssetComponent, FrameworkComponent
from aibom.model.result import REL_DEPENDS_ON
from aibom.scan.registry import ScanContext, Scanner

# Detection of concrete crypto-API usage (receiver+method+arg-role rule model,
# data-flow-lite symbol table, and the literal-token recall lane) lives in the
# clean-room detection module :mod:`aibom.cbom.detect`. This scanner turns the
# facts it returns into ``crypto_asset`` components.

_IMPORT_RE = re.compile(
    # also CommonJS "const crypto = require('crypto')" anywhere on the line (the usual Node.js form)
    r"^\s*(?:import|from|require|use|using|#include|require_once)\b|\brequire\(\s*['\"`]", re.I
)
_GO_IMPORT_BLOCK = re.compile(r"import\s*\(")


def _iter_source_files(walk: FileWalk) -> list[Path]:
    """Source files of a detector language (the shared walk: no links, no skipped/vendored dirs, size-capped)."""
    return walk.files(lambda p: source_language(p) is not None)


def _refine_key(key: str, key_size: int | None) -> str:
    """Promote a bare ``rsa``/``aes`` to its sized variant when a size is known."""
    if key == "rsa" and key_size in (512, 1024, 2048, 3072, 4096):
        cand = f"rsa-{key_size}"
        if algo_info(cand):
            return cand
    if key == "aes" and key_size in (128, 192, 256):
        cand = f"aes-{key_size}"
        if algo_info(cand):
            return cand
    return key


def _display_name(
    key: str,
    explicit_key_size: int | None,
    mode: str | None,
    parameter: str | None = None,
    variant: str | None = None,
) -> str:
    """Build the asset display name. Only a key size found EXPLICITLY on the
    source line is folded into the name (so RSA-2048 vs RSA-1024 separate); a
    table-default size (e.g. 3DES's 168) is NOT, to avoid noisy names.

    A captured PQC ``parameter`` set switches the name to the sized FIPS spelling
    (``ML-KEM-768``); without one, the unsized research name is kept
    (``CRYSTALS-Kyber``) so an unparameterized ``new MLKEMEngine(0)`` is stable.
    Hybrid assets read ``Hybrid ML-KEM-<set>``.

    ``variant`` is the construction qualifier the source names alongside the
    algorithm (the HMAC / PBKDF2 hash: ``HMAC-SHA256``, ``PBKDF2-HMAC-SHA512``;
    AES key wrap: ``AES-KW``). The canonical key, and so the strength/primitive
    record, stays the bare algorithm's.
    """
    if key == "hybrid":
        return f"Hybrid ML-KEM-{parameter}" if parameter else "Hybrid ML-KEM"
    if parameter and key in PQC_FIPS_NAME:
        return f"{PQC_FIPS_NAME[key]}-{parameter}"
    base = ALGORITHM_NORMALIZE.get(key, key.upper())
    if explicit_key_size and not re.search(rf"\b{explicit_key_size}\b", base):
        info = algo_info(key) or {}
        if info.get("primitive") in ("pke", "block-cipher", "stream-cipher"):
            base = f"{base}-{explicit_key_size}"
    if variant:
        base = f"{base}-{variant}"
    if mode and mode.upper() not in base.upper().split("-"):
        return f"{base}-{mode.upper()}"
    return base


class _Asset:
    __slots__ = ("key", "name", "key_size", "mode", "curve", "padding",
                 "operation", "parameter", "info", "location", "library",
                 "lines", "own_lines", "derived_from", "inner_digest", "purposes",
                 "inferred", "config_binding", "config_read_at", "low_confidence")

    def __init__(self, key, name, key_size, mode, curve, padding, operation,
                 parameter, info, location, library=None):
        self.inferred: bool | None = None  # every sighting inferred from configuration (see Detection.inferred)
        # a settings value (Detection.config_binding): its name, the crypto call
        # that reads it, and whether every sighting is an unproven setting (low
        # confidence)
        self.config_binding: str | None = None
        self.config_read_at: str | None = None
        self.low_confidence: bool | None = None
        self.lines: list[int] = []
        self.own_lines = 0  # lines where the asset is used on its own (not only as a composite's parameter)
        self.derived_from: str | None = None  # display name of the composite (same file) it is a parameter of
        self.inner_digest: str | None = None  # a composite's hash parameter (``SHA1withRSA`` -> SHA-1)
        self.purposes: list[str | None] = []  # per line, the non-security purpose of a hash (None = security)
        self.key = key
        self.name = name
        self.key_size = key_size
        self.mode = mode
        self.curve = curve
        self.padding = padding
        self.operation = operation
        self.parameter = parameter
        self.info = info
        self.location = location
        # The library whose API call produced the asset (a receiver+method / call-argument match); None when only
        # a literal token named the algorithm.
        self.library = library

    def fill_from(self, curve, padding, operation, library) -> None:
        """A later sighting of the same asset (same name, same file) fills parameters the first one lacked —
        ``func ecdsaKey() (*ecdsa.PrivateKey ...`` names ECDSA before ``ecdsa.GenerateKey(elliptic.P384() ...``
        binds its curve."""
        self.curve = self.curve or curve
        self.padding = self.padding or padding
        self.operation = self.operation or operation
        self.library = self.library or library


#: the run property that carries configuration evidence to ``normalize`` (the
#: CycloneDX metadata states only its count)
CONFIG_EVIDENCE_PROP = "crypto:configEvidence"
CONFIG_EVIDENCE_MAX = 200


_READ_LANGS = frozenset({"python", "java", "javascript"})


_IMPORT_LINE = re.compile(r"^\s*(?:import\b|from\b|.*\brequire\s*\(|.*\bimport\s*\()")
_NOT_OWNERS = frozenset({"exports", "module", "default", "self", "this", "cls", "it"})
# an import that renames: ``from .base import Cfg as AppCfg``, ``import { Cfg as C }``,
# ``const { Cfg: C } = require('./cfg')``
_IMPORT_AS = re.compile(r"\b([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)")
_REQUIRE_RENAME = re.compile(r"\b([A-Za-z_]\w*)\s*:\s*([A-Za-z_]\w*)\s*[,}]")


class _Reader:
    __slots__ = ("path", "imports", "words")

    def __init__(self, path: str, imports: str, words: frozenset[str]) -> None:
        self.path = path
        self.imports = imports  # the file's import / require lines
        self.words = words  # every identifier the file names


class ProjectReads:
    """The names crypto calls read in each file of the project, per language, and
    what links a reader to a settings file (review 6061095673 / 6063599094).

    A read in another file proves a setting only through a real link: the reader
    imports the declaring module (``from config import CONFIG``,
    ``require('./config')``, ``import { cryptoConfig } from '../ui/options'``), or
    reads it through, or names, one of the setting's owner symbols (the dict,
    object, record or class: ``cryptoConfig.digest``, ``cfg: CryptoCfg``). A bare
    leaf-name match (any ``x.digest``) proves nothing."""

    def __init__(self, walk: FileWalk) -> None:
        # lang -> name -> [(reader, line, qualifier)]
        self.sites: dict[str, dict[str, list[tuple[_Reader, int, str | None]]]] = {}
        # lang -> alias -> the names it renames (a package re-export or an import)
        self.aliases: dict[str, dict[str, set[str]]] = {}
        for path in _iter_source_files(walk):
            lang = source_language(path)
            if lang not in _READ_LANGS:
                continue
            text = walk.read_text(path)
            if text is None:
                continue
            lines = [
                _strip_line_comment(ln, lang).strip()
                for ln in strip_noncode(text).split("\n")
            ]
            imports = "\n".join(ln for ln in lines if _IMPORT_LINE.match(ln))
            renames = self.aliases.setdefault(lang or "", {})
            for ln in imports.split("\n"):
                found = _IMPORT_AS.findall(ln)
                if "require" in ln:
                    found += _REQUIRE_RENAME.findall(ln)
                for original, alias in found:
                    if original != alias:
                        renames.setdefault(alias, set()).add(original)
            sites = crypto_read_sites(lines)
            if not sites:
                continue
            words = frozenset(re.findall(r"[A-Za-z_]\w*", text))
            reader = _Reader(walk.rel(path), imports, words)
            by_name = self.sites.setdefault(lang or "", {})
            for name, line, qualifier in sites:
                by_name.setdefault(name, []).append((reader, line, qualifier))

    def for_file(
        self, lang: str | None, rel: str
    ) -> Callable[[str, tuple[str, ...]], str | None]:
        """``prove(binding, owners) -> "path:line" | None`` for ``rel``'s settings."""
        by_name = self.sites.get(lang or "", {})
        renames = self.aliases.get(lang or "", {})
        stem = Path(rel).stem
        imported = (
            re.compile(rf"(?<![\w-]){re.escape(stem)}(?![\w-])") if stem else None
        )

        def prove(binding: str, owners: tuple[str, ...]) -> str | None:
            real = [o for o in owners if o and o not in _NOT_OWNERS]
            for reader, line, qualifier in by_name.get(binding, ()):
                if reader.path == rel:
                    continue
                # a renamed import reads the original (``AppCfg.HASH`` reads Cfg's)
                names = {qualifier, *renames.get(qualifier or "", ())} - {None}
                linked = (
                    (imported is not None and bool(imported.search(reader.imports)))
                    or any(q in real for q in names)
                    or any(o in reader.words for o in real)
                )
                if linked:
                    return f"{reader.path}:{line}"
            return None

        return prove


def _detect_assets(
    root: Path, walk: FileWalk | None = None, project: ProjectIndex | None = None,
    config_evidence: list[dict[str, Any]] | None = None,
) -> list[_Asset]:
    """Detect concrete algorithm usages (one per distinct name+file).

    Detection facts come from the clean-room :func:`detect_crypto` rule engine
    (receiver+method+arg-roles + data-flow-lite symbol table + literal lane); this
    turns each fact into an inventoried asset, folding an explicit key size / mode
    into the display name so RSA-2048 vs RSA-1024 and AES-GCM vs AES-ECB separate.
    """
    walk = walk or FileWalk(root)
    seen: dict[tuple[str, str], _Asset] = {}
    reads = ProjectReads(walk)
    for path in _iter_source_files(walk):
        lang = source_language(path)
        rel = walk.rel(path)
        text = walk.read_text(path)
        if text is None:
            continue
        external = project.scope_for(rel, lang, text) if project is not None else None
        code_lines: list[str] | None = None
        at_line: dict[tuple[int, str], str] = {}  # (line, key) -> display name, to find a composite
        inner: list[tuple[_Asset, int, str, str | None]] = []
        found: list[dict[str, Any]] = []
        same_lang = reads.for_file(lang, rel)
        dets = detect_crypto(
            text, lang, external, config_evidence=found, project_reads=same_lang
        )
        if config_evidence is not None:
            config_evidence.extend({"location": rel, **e} for e in found)
        for det in dets:
            refined = _refine_key(det.key, det.key_size)
            info = algo_info(refined) or {}
            resolved_ks = det.key_size or info.get("key_size")
            # A mode of operation belongs to block ciphers only: "RSA/ECB/OAEP..." is a JCA naming quirk, and a
            # mode seen elsewhere on the line must not turn HMAC or SHA-256 into "HMAC-CBC" / "SHA-256-CBC".
            mode = det.mode if info.get("primitive") == "block-cipher" else None
            name = _display_name(refined, det.key_size, mode, det.parameter, det.variant)
            ident = (name, rel)
            library = det.library if det.receiver_bound else None
            if ident not in seen:
                seen[ident] = _Asset(
                    refined, name, resolved_ks, mode, det.curve,
                    det.padding, det.operation, det.parameter, info, rel, library
                )
            else:
                seen[ident].fill_from(det.curve, det.padding, det.operation, library)
            asset = seen[ident]
            asset.lines.append(det.line_no)
            asset.inferred = det.inferred if asset.inferred is None else (asset.inferred and det.inferred)
            low = det.low_confidence
            asset.low_confidence = (
                low if asset.low_confidence is None else asset.low_confidence and low
            )
            asset.config_binding = asset.config_binding or det.config_binding
            if det.config_read_at and not asset.config_read_at:
                read = det.config_read_at
                asset.config_read_at = f"{rel}:{read}" if read.isdigit() else read
            at_line.setdefault((det.line_no, det.key), name)
            if det.inner_of:
                inner.append((asset, det.line_no, det.inner_of, det.inner_role))
            else:
                asset.own_lines += 1
            if info.get("primitive") == "hash" and refined in _PURPOSE_HASHES:
                if code_lines is None:
                    code_lines = [_strip_line_comment(ln, lang) for ln in strip_noncode(text).split("\n")]
                asset.purposes.append(hash_purpose(code_lines, det.line_no, lang))
        for asset, line_no, composite_key, role in inner:
            composite = at_line.get((line_no, composite_key))
            parent = seen.get((composite, rel)) if composite else None
            if parent is None:
                continue
            if role != "oaep":  # the hash of an OAEP encryption is not a digest the key signs (weakness rule 3b)
                parent.inner_digest = parent.inner_digest or asset.name
            if asset.own_lines == 0 and asset.derived_from is None:
                asset.derived_from = composite
    _add_inner_hashes(seen)
    return sorted(seen.values(), key=lambda a: (a.name, a.location))


# Hashes whose weakness is collision resistance: a non-security use (cache key, checksum) is not a finding.
_PURPOSE_HASHES = frozenset({"md5", "md4", "sha1"})
# The hash inside a composite whose name carries it: HMAC-SHA256 / PBKDF2-HMAC-SHA512 / Ed25519 (SHA-512, RFC 8032).
_NAMED_INNER = re.compile(r"^(?:PBKDF2-)?HMAC-(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5)$", re.I)
_INNER_KEYS = {"sha1": "sha1", "sha224": "sha256", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
               "md5": "md5"}


def _add_inner_hashes(seen: dict[tuple[str, str], _Asset]) -> None:
    """A composite that names its hash (HMAC-SHA256, PBKDF2-HMAC-SHA512, Ed25519 -> SHA-512) lists that hash as a
    derived component at the composite's lines, unless the file already inventories the hash itself."""
    for (name, rel), asset in list(seen.items()):
        if asset.derived_from is not None:
            continue
        m = _NAMED_INNER.match(name)
        key = _INNER_KEYS.get(m.group(1).replace("-", "").lower()) if m else ("sha512" if asset.key == "ed25519"
                                                                              else None)
        if key is None:
            continue
        info = algo_info(key) or {}
        inner_name = ALGORITHM_NORMALIZE.get(key, key.upper())
        asset.inner_digest = asset.inner_digest or inner_name
        if (inner_name, rel) in seen:
            continue
        derived = _Asset(key, inner_name, None, None, None, None, None, None, info, rel)
        derived.lines = list(asset.lines)
        derived.derived_from = name
        seen[(inner_name, rel)] = derived


# --------------------------------------------------------------------------- #
# Dependency-MANIFEST crypto-library detection (C12). Extends the Python-only
# requirements/pyproject lane to Maven/Go/npm/Cargo/NuGet: parse each ecosystem's
# manifest into its native coordinate and resolve it via
# :func:`rules.match_dep_coordinate`. Parsing is conservative + clean-room (no OSS
# manifest parser bundled): pom/gradle/csproj/packages.config via targeted regex,
# package.json via stdlib ``json``, go.mod / Cargo.toml line-by-line.
# --------------------------------------------------------------------------- #
_MANIFEST_BY_NAME: dict[str, str] = {
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "go.mod": "go",
    "package.json": "npm",
    "cargo.toml": "crate",
    "packages.config": "nuget",
}
_POM_DEP_RE = re.compile(r"<dependency\b.*?</dependency>", re.S | re.I)
_POM_GID_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>", re.I)
_POM_AID_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", re.I)
# gradle: implementation 'group:artifact:version' or ("group:artifact:version")
_GRADLE_COORD_RE = re.compile(r"""['"]([\w.\-]+:[\w.\-]+)(?::[\w.\-+]+)?['"]""")
# go.mod: "module/path vX.Y.Z" (the require directive's path + semantic version).
_GOMOD_DEP_RE = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+v[0-9]", re.M)
# NuGet PackageReference / packages.config id.
_CSPROJ_REF_RE = re.compile(r'<PackageReference\b[^>]*\bInclude\s*=\s*"([^"]+)"', re.I)
_PKGCONFIG_RE = re.compile(r'<package\b[^>]*\bid\s*=\s*"([^"]+)"', re.I)
_CARGO_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_CARGO_ENTRY_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=")


def _maven_coordinates(text: str, is_pom: bool) -> list[str]:
    coords: list[str] = []
    if is_pom:
        for block in _POM_DEP_RE.findall(text):
            gid = _POM_GID_RE.search(block)
            aid = _POM_AID_RE.search(block)
            if gid and aid:
                coords.append(f"{gid.group(1)}:{aid.group(1)}")
    else:  # build.gradle(.kts)
        coords.extend(_GRADLE_COORD_RE.findall(text))
    return coords


def _cargo_coordinates(text: str) -> list[str]:
    """Crate names from ``[dependencies]``-family sections (incl. sub-tables)."""
    coords: list[str] = []
    dep_sections = {"dependencies", "dev-dependencies", "build-dependencies"}
    in_deps = False
    for line in text.splitlines():
        sec = _CARGO_SECTION_RE.match(line)
        if sec:
            head = sec.group(1).strip()
            # [dependencies] table, or a [dependencies.<crate>] sub-table.
            parts = head.split(".")
            if parts[0] in dep_sections:
                in_deps = True
                if len(parts) > 1:  # [dependencies.ring] -> crate = "ring"
                    coords.append(parts[1])
            else:
                in_deps = False
            continue
        if in_deps:
            m = _CARGO_ENTRY_RE.match(line)
            if m:
                coords.append(m.group(1))
    return coords


def _package_json_coordinates(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    coords: list[str] = []
    for key in (
        "dependencies", "devDependencies",
        "optionalDependencies", "peerDependencies",
    ):
        section = data.get(key)
        if isinstance(section, dict):
            coords.extend(str(name) for name in section)
    return coords


def _manifest_coordinates(ecosystem: str, name: str, text: str) -> list[str]:
    if ecosystem == "maven":
        return _maven_coordinates(text, is_pom=name == "pom.xml")
    if ecosystem == "go":
        return _GOMOD_DEP_RE.findall(text)
    if ecosystem == "npm":
        return _package_json_coordinates(text)
    if ecosystem == "crate":
        return _cargo_coordinates(text)
    if ecosystem == "nuget":  # packages.config
        return _PKGCONFIG_RE.findall(text)
    return []


def _detect_manifest_libraries(root: Path, walk: FileWalk | None = None) -> list[tuple[str, str]]:
    """Crypto libraries DECLARED in non-Python manifests. -> (label, src)."""
    walk = walk or FileWalk(root)
    found: dict[str, str] = {}
    for path in walk.files():
        low_name = path.name.lower()
        ecosystem = _MANIFEST_BY_NAME.get(low_name)
        # *.csproj is matched by suffix (NuGet PackageReference form).
        is_csproj = path.suffix.lower() == ".csproj"
        if ecosystem is None and not is_csproj:
            continue
        text = walk.read_text(path)
        if text is None:
            continue
        rel = walk.rel(path)
        if is_csproj:
            coords = _CSPROJ_REF_RE.findall(text)
            eco = "nuget"
        else:
            assert ecosystem is not None
            coords = _manifest_coordinates(ecosystem, low_name, text)
            eco = ecosystem
        for coord in coords:
            label = match_dep_coordinate(eco, coord)
            if label:
                found.setdefault(label, rel)
    return sorted(found.items())


def _detect_libraries(root: Path, walk: FileWalk | None = None) -> list[tuple[str, str, int | None]]:
    """Detect crypto libraries: declared deps + imported modules. -> (label, src, line or None).

    The line is the requirement or import line that named the library (None for a non-Python manifest, whose
    package name the occurrence pass finds in the file)."""
    walk = walk or FileWalk(root)
    found: dict[str, str] = {}
    lines: dict[str, int] = {}

    # 1) declared dependencies (requirements.txt / pyproject)
    requirements = walk.files(lambda p: fnmatchcase(p.name, "requirements*.txt"))
    pyprojects = walk.files(lambda p: p.name == "pyproject.toml")
    for req in (*requirements, *pyprojects):
        text = walk.read_text(req)
        if text is None:
            continue
        rel = walk.rel(req)
        for line_no, raw in enumerate(text.splitlines(), start=1):
            name = re.split(r"[<>=!~;\[\s#]", raw.strip(), maxsplit=1)[0].lower()
            label = CRYPTO_LIBRARY_PACKAGES.get(name)
            if label and label not in found:
                found[label], lines[label] = rel, line_no

    # 1b) declared dependencies in non-Python manifests (C12: Maven/Go/npm/
    # Cargo/NuGet). A manifest is the authoritative declaration site, so it is
    # recorded before the import lane (setdefault keeps the manifest source).
    for label, rel in _detect_manifest_libraries(root, walk):
        found.setdefault(label, rel)

    # 2) imported crypto modules in source
    for path in _iter_source_files(walk):
        rel = walk.rel(path)
        lang = source_language(path)
        # Node's ``crypto`` and C's ``openssl`` roots collide with the Python keys,
        # so JS/C/Rust/.NET/Go files use a language-scoped map; Python/Java (whose
        # roots are distinctive) fall back to the global one (C3).
        modules = CRYPTO_IMPORT_MODULES_BY_LANG.get(lang, CRYPTO_IMPORT_MODULES)
        text = walk.read_text(path)
        if text is None:
            continue
        go_block = False  # inside Go's ``import ( ... )`` block, whose lines are bare quoted paths
        for line_no, line in enumerate(text.splitlines(), start=1):
            if lang == "go":
                stripped = line.strip()
                if go_block and stripped.startswith(")"):
                    go_block = False
                    continue
                if not go_block and _GO_IMPORT_BLOCK.match(stripped):
                    go_block = ")" not in stripped
            if not (go_block or _IMPORT_RE.search(line)):
                continue
            low = line.lower()
            for module, label in modules.items():
                # The lookbehind rejects a preceding "." / "/" so a generic root
                # (e.g. the Python "crypto" key for ``from Crypto import AES``) can
                # NOT match across a package path — ``javax.crypto`` / ``crypto/aes``
                # only match their own explicit multi-segment keys (C2).
                if label not in found and re.search(rf"(?<![a-z0-9_./]){re.escape(module)}(?![a-z0-9_])", low):
                    found[label], lines[label] = rel, line_no
    return [(label, rel, lines.get(label)) for label, rel in sorted(found.items())]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _context_props(asset: _Asset) -> dict[str, str]:
    """What the whole file says about an asset: the hash a composite is built on, and a hash used only to name or
    check content (every line non-security; see :mod:`aibom.cbom.purpose`)."""
    props: dict[str, str] = {}
    if asset.inner_digest:
        props["crypto:innerDigest"] = asset.inner_digest
    if asset.purposes and all(asset.purposes):
        props["crypto:nonSecurityUse"] = "true"
        props["crypto:purpose"] = sorted({p for p in asset.purposes if p})[0]
    if asset.config_binding:
        # a settings value (PR #500 review 6061095673): its name and its reader
        props["crypto:configBinding"] = asset.config_binding
        if asset.config_read_at:
            props["crypto:configReadAt"] = asset.config_read_at
    if asset.low_confidence:
        props["crypto:confidence"] = "low"
        props["crypto:resolution"] = (
            "a settings value no crypto call in the project is proven to read: "
            "kept as an asset so nothing is lost, at low confidence"
        )
    if asset.inferred:
        props["crypto:confidence"] = "medium"
        props["crypto:resolution"] = ("inferred (needs review): a field default or the module's one configured "
                                      "transformation; a guess raises no finding")
    return props


@cbom_register
class CryptoAlgorithmScanner(Scanner):
    name = "crypto_algorithm"
    order = 10
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        libraries = _detect_libraries(ctx.root, walk)
        # the library's version from the tree's manifests and lockfiles (or why not)
        labels = [label for label, _src, _line in libraries]
        versions = resolve_library_versions(ctx.root, walk, labels)
        for label, src, line in libraries:
            ref = f"crypto-lib-{_slug(label)}"
            if ctx.has_ref(ref):
                continue
            lib_props = {"crypto:role": "library", "discovery:source": src}
            if line:  # the requirement / import line that named it: where the occurrence pass finds no usage line
                lib_props["crypto:importLine"] = str(line)
            found = versions.get(label)
            version = purl = None
            if found is not None:
                version, purl = found.version, found.purl
                lib_props.update(found.properties())
            ctx.add_component(
                FrameworkComponent(
                    bom_ref=ref, name=label, version=version, purl=purl, properties=lib_props
                )
            )

        config_evidence: list[dict[str, Any]] = []
        assets = _detect_assets(ctx.root, walk, project_index(ctx), config_evidence)
        if config_evidence:
            # low-confidence configuration evidence (PR #500 takeover): algorithm names
            # in settings no crypto call
            # reads; carried to the run object (normalize), never an asset or a total
            ctx.properties[CONFIG_EVIDENCE_PROP] = json.dumps(
                config_evidence[:CONFIG_EVIDENCE_MAX], sort_keys=True
            )
            ctx.properties["crypto:configEvidenceCount"] = str(len(config_evidence))
        for asset in assets:
            # The AST scanner (order 8) owns Python algorithm detection with
            # argument binding; defer to any ref it already emitted so the regex
            # pass only adds usages the AST could not see (e.g. an algorithm named
            # in a non-Python file or a string literal). This keeps the emitted
            # inventory duplicate-free *before* the flag/PQC scanners run.
            ast_ref = f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}"
            if ctx.has_ref(ast_ref):
                # the AST row is the same usage: it takes what only the whole-file view knows
                extra = _context_props(asset)
                if extra:
                    for comp in ctx.components:
                        if comp.bom_ref == ast_ref:
                            comp.properties = {**(comp.properties or {}), **extra}
                continue
            props: dict[str, str] = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": asset.info.get("primitive") or "other",
                "crypto:strength": asset.info.get("strength", "unknown"),
                "crypto:quantumVulnerable": str(
                    bool(asset.info.get("quantum_vulnerable", False))
                ).lower(),
                "discovery:source": asset.location,
            }
            if asset.key_size:
                props["crypto:keySize"] = str(asset.key_size)
            if asset.mode:
                props["crypto:mode"] = asset.mode
            if asset.curve:
                props["crypto:curve"] = asset.curve
            if asset.padding:
                props["crypto:padding"] = asset.padding
            if asset.operation:
                props["crypto:operation"] = asset.operation
            if asset.parameter:
                props["crypto:parameterSet"] = asset.parameter
            if asset.key == "hybrid":
                props["crypto:hybrid"] = "true"
            if asset.library:
                # call-site provenance: the API call that fixed the algorithm (the AST lane writes "ast")
                props["crypto:detectedBy"] = asset.library
                props["crypto:detectionMethod"] = "call-expr"
            props.update(_context_props(asset))
            if asset.derived_from is not None:
                props["crypto:derived"] = "true"
                props["crypto:derivedFrom"] = f"crypto-algo-{_slug(asset.derived_from)}-{_slug(asset.location)}"
                if asset.lines:  # located at the composite's line(s): its name alone may not be on them
                    lines = sorted(set(asset.lines))
                    props["crypto:line"] = str(lines[0])
                    props["crypto:occurrences"] = ",".join(str(n) for n in lines[:25])
            info_material = asset.info.get("key_material_bits")
            if info_material:
                props["crypto:keyMaterialBits"] = str(info_material)
            ref = f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}"
            ctx.add_component(
                CryptoAssetComponent(bom_ref=ref, name=asset.name, properties=props)
            )
            _add_composite_parts(ctx, asset, ref)


def _add_composite_parts(ctx: ScanContext, asset: _Asset, ref: str) -> None:
    """A construction (Fernet) inventories the primitives it is built from at its
    own lines, each graded on its own (AES-128-CBC is NIST category 1, HMAC-SHA256 a
    MAC), and depends on them."""
    parts = COMPOSITE_PARTS.get(asset.key)
    if not parts:
        return
    lines = sorted(set(asset.lines))
    built: list[str] = []
    for key, key_size, mode, padding, variant in parts:
        info = algo_info(key) or {}
        name = _display_name(key, key_size, mode, None, variant)
        part_ref = f"crypto-algo-{_slug(name)}-{_slug(asset.location)}"
        built.append(name)
        if not ctx.has_ref(part_ref):
            props: dict[str, str] = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": info.get("primitive") or "other",
                "crypto:strength": info.get("strength", "unknown"),
                "crypto:quantumVulnerable": str(
                    bool(info.get("quantum_vulnerable", False))
                ).lower(),
                "discovery:source": asset.location,
                "crypto:derived": "true",
                "crypto:derivedFrom": ref,
            }
            if key_size or info.get("key_size"):
                props["crypto:keySize"] = str(key_size or info.get("key_size"))
            if mode:
                props["crypto:mode"] = mode
            if padding:
                props["crypto:padding"] = padding
            if asset.library:
                props["crypto:detectedBy"] = asset.library
            if lines:
                props["crypto:line"] = str(lines[0])
                props["crypto:occurrences"] = ",".join(str(n) for n in lines[:25])
            ctx.add_component(
                CryptoAssetComponent(bom_ref=part_ref, name=name, properties=props)
            )
        ctx.add_edge(ref, REL_DEPENDS_ON, part_ref)
    for comp in ctx.components:
        if comp.bom_ref == ref:
            construction = " + ".join(built)
            comp.properties = {
                **(comp.properties or {}),
                "crypto:construction": construction,
            }


__all__ = ["CryptoAlgorithmScanner"]
