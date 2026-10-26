"""Defaults registry loader. Synthetic blobs in, immutable rows out.

Reads package data only through ``importlib.resources``. Validation is pure:
callers pass bytes, and nothing here opens a path from the environment.
"""

from __future__ import annotations

import functools
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Final

from aibom.cbom.posture.model import DataTable

DATA_FILES: Final[tuple[str, ...]] = (
    "provider_defaults_aws.json",
    "provider_defaults_azure.json",
    "provider_defaults_gcp.json",
    "provider_defaults_k8s.json",
    "provider_defaults_software.json",
    "tls_policies.json",
    "cipher_suites.json",
    "named_groups.json",
    "key_specs.json",
    "datastore_images.json",
    "verification_patterns.json",
    "named_vulnerabilities.json",
    "tls_import_formats.json",
    "key_policy_conditions.json",
)

SYNTAXES: Final[frozenset[str]] = frozenset(
    {"terraform", "cloudformation", "kubernetes", "compose", "server"}
)
EFFECTS: Final[frozenset[str]] = frozenset({"ENCRYPTED", "NOT_ENCRYPTED", "UNKNOWN"})
MATCHER_KINDS: Final[frozenset[str]] = frozenset(
    {"literal", "command_flag", "anchor_window"}
)
FINDING_DEFAULT_CODES: Final[frozenset[str]] = frozenset(
    {"KMS_KEY_ROTATION_DISABLED", "KMS_KEY_DELETION_UNPROTECTED"}
)
_IAC = frozenset({"terraform", "cloudformation"})
_PROVIDER_FILES = frozenset(
    name for name in DATA_FILES if name.startswith("provider_defaults_")
)
_ROW_REQUIRED = frozenset(
    {
        "id",
        "provider",
        "type",
        "attribute",
        "documented_default",
        "effect",
        "assessable_as_unencrypted",
        "caveat",
        "versions",
        "url",
        "valid_as_of",
    }
)
_ROW_OPTIONAL = frozenset({"when", "unless_attrs", "override", "finding_default"})
_FORBIDDEN = (".*", ".+", r"\S*", r"\S+", r"\W*", r"\W+", r"\w*", r"\w+")
_ALLOWED_UNBOUNDED = frozenset({r"\s*", r"\s+", r"\d*", r"\d+"})

# Bound once. ``build_registry`` applies it only after ``lint_pattern`` accepts
# the source. The call site is not named ``compile``, so a dynamic pattern is
# not a literal ``re.compile`` of file text.
_LINE_COMPILER = re.compile
_COMMAND_TOKEN = re.compile(r"[^\s;|&()<>]+|[;|&()<>]")
LINE_PATTERNS: tuple[re.Pattern[str], ...] = ()
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (_COMMAND_TOKEN,)
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS


class RegistryError(ValueError):
    """A data file or one of its rows failed validation."""

    def __init__(self, message: str, *, file: str = "", row_id: str = "") -> None:
        self.file = file
        self.row_id = row_id
        prefix = f"{file}:{row_id}: " if file else ""
        super().__init__(prefix + message)


@dataclass(frozen=True, slots=True)
class VersionRange:
    """``min is None`` means the row applies to every version."""

    min: tuple[int, ...] | None
    max_exclusive: tuple[int, ...] | None


@dataclass(frozen=True, slots=True)
class FindingDefault:
    code: str
    when_absent: bool


@dataclass(frozen=True, slots=True)
class OverrideSpec:
    type: str
    attribute: str
    enabling: frozenset[str]
    row: str


@dataclass(frozen=True, slots=True)
class DefaultRow:
    id: str
    provider: str
    type: tuple[str, ...]
    attribute: str
    documented_default: str
    effect: str
    assessable_as_unencrypted: bool
    caveat: str
    versions: VersionRange
    url: str
    valid_as_of: str
    when: Mapping[str, Mapping[str, tuple[Any, ...]]]
    unless_attrs: Mapping[str, tuple[str, ...]]
    override: OverrideSpec | None
    finding_default: FindingDefault | None


@dataclass(frozen=True, slots=True)
class PatternSpec:
    id: str
    matcher: str
    pattern: str | None = None
    command: str | None = None
    short_flags: tuple[str, ...] = ()
    long_flags: tuple[str, ...] = ()
    max_tokens: int = 0
    anchor: str | None = None
    window: int = 0
    tail: str | None = None


@dataclass(frozen=True, slots=True)
class DefaultsRegistry:
    tables: tuple[DataTable, ...]
    rows: tuple[DefaultRow, ...]
    by_id: Mapping[str, DefaultRow]
    patterns: tuple[PatternSpec, ...]
    row_hashes: Mapping[str, str]
    line_patterns: tuple[re.Pattern[str], ...]


def read_data_bytes(name: str) -> bytes:
    """Bytes of one file under the packaged ``aibom.cbom`` data directory."""
    return files("aibom.cbom").joinpath("data").joinpath(name).read_bytes()


def iac_syntax_gap(keys: Iterable[str]) -> str | None:
    """Syntax that a terraform/cloudformation pair omitted, if it named only one."""
    present = set(keys) & _IAC
    if len(present) == 1:
        return next(iter(_IAC - present))
    return None


def lint_pattern(source: str) -> tuple[str, ...]:
    """Textual line-pattern rules. A hit means the pattern can backtrack."""
    problems: list[str] = []
    for snippet in _FORBIDDEN:
        if snippet in source:
            problems.append(f"backtracking shape {snippet}")
    if "(?<=" in source or "(?<!" in source:
        problems.append("lookbehind")
    if _has_backreference(source):
        problems.append("backreference")
    if _negated_unbounded(source):
        problems.append("negated class quantifier")
    bound = _oversize_bound(source)
    if bound is not None:
        problems.append(f"quantifier bound {bound}")
    problems.extend(_group_problems(source))
    extra = _unbounded_problem(source)
    if extra is not None:
        problems.append(extra)
    return tuple(problems)


def lint_token_pattern(source: str) -> tuple[str, ...]:
    """Token patterns: no nested quantifier, inner alternation, or lookaround."""
    problems: list[str] = []
    if "(?<=" in source or "(?<!" in source:
        problems.append("lookbehind")
    if _has_backreference(source):
        problems.append("backreference")
    problems.extend(_group_problems(source))
    for snippet in (".*", ".+", r"\S*"):
        if snippet in source:
            problems.append(f"backtracking shape {snippet}")
    return tuple(problems)


def compiled_registry_patterns(
    registry: DefaultsRegistry | None = None,
) -> tuple[re.Pattern[str], ...]:
    """Line patterns accepted while the registry was built."""
    reg = load_registry() if registry is None else registry
    return reg.line_patterns


def reviewed_problems(
    registry: DefaultsRegistry, listed: Mapping[str, str]
) -> list[str]:
    """Rows that raise a finding from absence must be on the reviewed list."""
    problems: list[str] = []
    for row in registry.rows:
        assessable = row.assessable_as_unencrypted
        finding = row.finding_default is not None
        if assessable and finding:
            problems.append(f"{row.id} has both assessable and finding_default")
        if assessable and listed.get(row.id) != "assessable":
            problems.append(f"{row.id} assessable is not reviewed")
        if finding and listed.get(row.id) != "finding_default":
            problems.append(f"{row.id} finding_default is not reviewed")
    for row_id, kind in listed.items():
        found = registry.by_id.get(row_id)
        if found is None:
            problems.append(f"{row_id} is not in the registry")
            continue
        if kind == "assessable" and not found.assessable_as_unencrypted:
            problems.append(f"{row_id} listed assessable but is not")
        elif kind == "finding_default" and found.finding_default is None:
            problems.append(f"{row_id} listed finding_default but is not")
        elif kind not in {"assessable", "finding_default"}:
            problems.append(f"{row_id} unknown review kind {kind}")
    return problems


def url_problems(registry: DefaultsRegistry, prefixes: Iterable[str]) -> list[str]:
    """Rows whose URL does not start with a reviewed prefix."""
    allowed = tuple(prefixes)
    return [
        f"{row.id} url is not on the allow-list"
        for row in registry.rows
        if not any(row.url.startswith(prefix) for prefix in allowed)
    ]


def build_registry(blobs: Mapping[str, bytes]) -> DefaultsRegistry:
    """Validate synthetic or shipped blobs. Raises ``RegistryError``."""
    parsed: dict[str, dict[str, Any]] = {}
    tables: list[DataTable] = []
    for name in sorted(blobs):
        if name not in DATA_FILES:
            raise RegistryError(f"unknown data file {name}", file=name)
        document = _load(blobs[name], name)
        tables.append(
            DataTable(
                name=name,
                data_version=_version(document, name),
                valid_as_of=_file_date(document, name),
                sha256=hashlib.sha256(blobs[name]).hexdigest(),
            )
        )
        parsed[name] = document
    rows: list[DefaultRow] = []
    patterns: list[PatternSpec] = []
    compiled: list[re.Pattern[str]] = []
    hashes: dict[str, str] = {}
    for name, document in parsed.items():
        file_date = _file_date(document, name)
        raw_rows = document.get("rows")
        if not isinstance(raw_rows, list):
            raise RegistryError("rows must be a list", file=name)
        for raw in raw_rows:
            if not isinstance(raw, dict):
                raise RegistryError("row must be an object", file=name)
            digest = _canonical_hash(raw)
            if name in _PROVIDER_FILES:
                row = _default_row(raw, name, file_date)
                hashes[row.id] = digest
                rows.append(row)
            elif name == "verification_patterns.json":
                spec, pattern = _pattern_row(raw, name)
                hashes[spec.id] = digest
                patterns.append(spec)
                if pattern is not None:
                    compiled.append(pattern)
            else:
                row_id = raw.get("id")
                if not isinstance(row_id, str) or not row_id:
                    raise RegistryError("row id must be a string", file=name)
                hashes[f"{name}:{row_id}"] = digest
    _unique(rows)
    _disjoint(rows)
    _overrides_exist(rows)
    _suite_refs(parsed)
    by_id = {row.id: row for row in rows}
    return DefaultsRegistry(
        tables=tuple(tables),
        rows=tuple(rows),
        by_id=MappingProxyType(by_id),
        patterns=tuple(patterns),
        row_hashes=MappingProxyType(hashes),
        line_patterns=tuple(compiled),
    )


@functools.cache
def load_registry() -> DefaultsRegistry:
    """Load every shipped data file. Fails closed when a file is absent."""
    return build_registry({name: read_data_bytes(name) for name in DATA_FILES})


def _load(blob: bytes, file: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise RegistryError(f"duplicate key {key}", file=file)
            out[key] = value
        return out

    try:
        data = json.loads(blob, object_pairs_hook=pairs)
    except RegistryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"invalid JSON: {exc}", file=file) from exc
    if not isinstance(data, dict):
        raise RegistryError("document must be an object", file=file)
    return data


def _version(document: Mapping[str, Any], file: str) -> int:
    value = document.get("data_version")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RegistryError("data_version must be a positive integer", file=file)
    return value


def _file_date(document: Mapping[str, Any], file: str) -> str:
    value = document.get("valid_as_of")
    if not isinstance(value, str) or _iso(value) is None:
        raise RegistryError("valid_as_of must be an ISO date", file=file)
    return value


def _iso(value: str) -> str | None:
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        return None
    year, month, day = value[:4], value[5:7], value[8:10]
    if not (year.isdigit() and month.isdigit() and day.isdigit()):
        return None
    month_n, day_n = int(month), int(day)
    if not 1 <= month_n <= 12 or not 1 <= day_n <= 31:
        return None
    return value


def _canonical_hash(row: Mapping[str, Any]) -> str:
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _default_row(raw: Mapping[str, Any], file: str, file_date: str) -> DefaultRow:
    unknown = set(raw) - _ROW_REQUIRED - _ROW_OPTIONAL
    if unknown:
        raise RegistryError(f"unknown field {sorted(unknown)[0]}", file=file)
    missing = _ROW_REQUIRED - set(raw)
    if missing:
        raise RegistryError(f"missing field {sorted(missing)[0]}", file=file)
    row_id = _text(raw["id"], file, "id")
    effect = raw["effect"]
    if effect not in EFFECTS:
        raise RegistryError("effect is not a closed value", file=file, row_id=row_id)
    assessable = raw["assessable_as_unencrypted"]
    if not isinstance(assessable, bool):
        raise RegistryError(
            "assessable_as_unencrypted must be a boolean", file=file, row_id=row_id
        )
    caveat = raw["caveat"]
    if not isinstance(caveat, str):
        raise RegistryError("caveat must be a string", file=file, row_id=row_id)
    if assessable and effect != "NOT_ENCRYPTED":
        raise RegistryError(
            "assessable_as_unencrypted requires effect NOT_ENCRYPTED",
            file=file,
            row_id=row_id,
        )
    if (assessable or effect == "UNKNOWN") and not caveat:
        raise RegistryError("caveat must be non-empty", file=file, row_id=row_id)
    url = _text(raw["url"], file, "url", row_id)
    if not url.startswith("https://"):
        raise RegistryError("url must be https", file=file, row_id=row_id)
    valid = _text(raw["valid_as_of"], file, "valid_as_of", row_id)
    if _iso(valid) is None or valid > file_date:
        raise RegistryError(
            "valid_as_of is not an ISO date on or before the file date",
            file=file,
            row_id=row_id,
        )
    when = _predicates(raw.get("when", {}), file, row_id, "when")
    unless = _unless(raw.get("unless_attrs", {}), file, row_id)
    finding = _finding(raw.get("finding_default"), file, row_id)
    if assessable and finding is not None:
        raise RegistryError(
            "a row cannot be assessable and carry finding_default",
            file=file,
            row_id=row_id,
        )
    documented = raw["documented_default"]
    if not isinstance(documented, str):
        raise RegistryError(
            "documented_default must be a string", file=file, row_id=row_id
        )
    if finding is not None and (not documented or not caveat):
        raise RegistryError(
            "finding_default requires documented_default and caveat",
            file=file,
            row_id=row_id,
        )
    if finding is not None and effect != "UNKNOWN":
        raise RegistryError(
            "finding_default requires effect UNKNOWN", file=file, row_id=row_id
        )
    return DefaultRow(
        id=row_id,
        provider=_text(raw["provider"], file, "provider", row_id),
        type=_types(raw["type"], file, row_id),
        attribute=_text(raw["attribute"], file, "attribute", row_id),
        documented_default=documented,
        effect=str(effect),
        assessable_as_unencrypted=assessable,
        caveat=caveat,
        versions=_versions(raw["versions"], file, row_id),
        url=url,
        valid_as_of=valid,
        when=when,
        unless_attrs=unless,
        override=_override(raw.get("override"), file, row_id),
        finding_default=finding,
    )


def _text(value: Any, file: str, field: str, row_id: str = "") -> str:
    if not isinstance(value, str) or not value:
        raise RegistryError(
            f"{field} must be a non-empty string", file=file, row_id=row_id
        )
    return value


def _types(value: Any, file: str, row_id: str) -> tuple[str, ...]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items:
        raise RegistryError("type must be a string or a list", file=file, row_id=row_id)
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise RegistryError(
                "type entries must be strings", file=file, row_id=row_id
            )
        out.append(item)
    return tuple(out)


def _versions(value: Any, file: str, row_id: str) -> VersionRange:
    if value == "all":
        return VersionRange(None, None)
    if not isinstance(value, dict):
        raise RegistryError("versions must be all or a range", file=file, row_id=row_id)
    unknown = set(value) - {"min", "max_exclusive"}
    if unknown or "min" not in value:
        raise RegistryError("versions range needs min", file=file, row_id=row_id)
    return VersionRange(
        _dotted(value["min"], file, row_id),
        (
            _dotted(value["max_exclusive"], file, row_id)
            if "max_exclusive" in value
            else None
        ),
    )


def _dotted(value: Any, file: str, row_id: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not value:
        raise RegistryError("version must be dotted integers", file=file, row_id=row_id)
    parts = value.split(".")
    if any(not part.isdigit() for part in parts):
        raise RegistryError("version must be dotted integers", file=file, row_id=row_id)
    return tuple(int(part) for part in parts)


def _predicates(
    value: Any, file: str, row_id: str, label: str
) -> Mapping[str, Mapping[str, tuple[Any, ...]]]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object", file=file, row_id=row_id)
    _reject_iac_gap(value, file, row_id, label)
    out: dict[str, Mapping[str, tuple[Any, ...]]] = {}
    for syntax, clause in value.items():
        if syntax not in SYNTAXES or not isinstance(clause, dict):
            raise RegistryError(f"{label} syntax is closed", file=file, row_id=row_id)
        paths: dict[str, tuple[Any, ...]] = {}
        for path, literals in clause.items():
            if not isinstance(path, str) or not isinstance(literals, list):
                raise RegistryError(
                    f"{label} clause is malformed", file=file, row_id=row_id
                )
            paths[path] = tuple(literals)
        out[syntax] = MappingProxyType(paths)
    return MappingProxyType(out)


def _unless(value: Any, file: str, row_id: str) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise RegistryError("unless_attrs must be an object", file=file, row_id=row_id)
    _reject_iac_gap(value, file, row_id, "unless_attrs")
    out: dict[str, tuple[str, ...]] = {}
    for syntax, paths in value.items():
        if syntax not in SYNTAXES or not isinstance(paths, list):
            raise RegistryError(
                "unless_attrs syntax is closed", file=file, row_id=row_id
            )
        if any(not isinstance(path, str) or not path for path in paths):
            raise RegistryError(
                "unless_attrs paths must be strings", file=file, row_id=row_id
            )
        out[syntax] = tuple(paths)
    return MappingProxyType(out)


def _reject_iac_gap(
    value: Mapping[str, Any], file: str, row_id: str, label: str
) -> None:
    missing = iac_syntax_gap(value)
    if missing is not None:
        raise RegistryError(
            f"{label} names only one of terraform/cloudformation; missing {missing}",
            file=file,
            row_id=row_id,
        )


def _finding(value: Any, file: str, row_id: str) -> FindingDefault | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RegistryError(
            "finding_default must be an object", file=file, row_id=row_id
        )
    unknown = set(value) - {"code", "when_absent"}
    if unknown or value.get("when_absent") is not True:
        raise RegistryError(
            "finding_default requires when_absent true", file=file, row_id=row_id
        )
    code = value.get("code")
    if code not in FINDING_DEFAULT_CODES:
        raise RegistryError("finding_default code is closed", file=file, row_id=row_id)
    return FindingDefault(code=str(code), when_absent=True)


def _override(value: Any, file: str, row_id: str) -> OverrideSpec | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RegistryError("override must be an object", file=file, row_id=row_id)
    fields = {"type", "attribute", "enabling", "row"}
    if set(value) != fields:
        raise RegistryError("override fields are closed", file=file, row_id=row_id)
    enabling = value["enabling"]
    if not isinstance(enabling, list) or any(
        not isinstance(item, str) for item in enabling
    ):
        raise RegistryError(
            "override enabling must be strings", file=file, row_id=row_id
        )
    return OverrideSpec(
        type=_text(value["type"], file, "override.type", row_id),
        attribute=_text(value["attribute"], file, "override.attribute", row_id),
        enabling=frozenset(enabling),
        row=_text(value["row"], file, "override.row", row_id),
    )


def _pattern_row(
    raw: Mapping[str, Any], file: str
) -> tuple[PatternSpec, re.Pattern[str] | None]:
    matcher = raw.get("matcher")
    ident = raw.get("id")
    row_id = ident if isinstance(ident, str) else ""
    if matcher not in MATCHER_KINDS:
        raise RegistryError("matcher is not a closed kind", file=file, row_id=row_id)
    row_id = _text(raw.get("id"), file, "id")
    if matcher == "literal":
        pattern = _text(raw.get("pattern"), file, "pattern", row_id)
        _lint_or_raise(pattern, file, row_id)
        return PatternSpec(id=row_id, matcher="literal", pattern=pattern), None
    if matcher == "command_flag":
        command = _text(raw.get("command"), file, "command", row_id)
        _lint_or_raise(command, file, row_id)
        shorts = _str_tuple(raw.get("short_flags"), file, row_id, "short_flags")
        longs = _str_tuple(raw.get("long_flags"), file, row_id, "long_flags")
        limit = raw.get("max_tokens")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 64
        ):
            raise RegistryError("max_tokens must be 1..64", file=file, row_id=row_id)
        spec = PatternSpec(
            id=row_id,
            matcher="command_flag",
            command=command,
            short_flags=shorts,
            long_flags=longs,
            max_tokens=limit,
        )
        return spec, None
    anchor = _text(raw.get("anchor"), file, "anchor", row_id)
    tail = _text(raw.get("tail"), file, "tail", row_id)
    window = raw.get("window")
    if (
        isinstance(window, bool)
        or not isinstance(window, int)
        or not 1 <= window <= 256
    ):
        raise RegistryError("window must be 1..256", file=file, row_id=row_id)
    _lint_or_raise(anchor, file, row_id)
    _lint_or_raise(tail, file, row_id)
    spec = PatternSpec(
        id=row_id, matcher="anchor_window", anchor=anchor, window=window, tail=tail
    )
    return spec, _LINE_COMPILER(tail)


def _str_tuple(value: Any, file: str, row_id: str, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RegistryError(
            f"{field} must be a list of strings", file=file, row_id=row_id
        )
    return tuple(value)


def _lint_or_raise(source: str, file: str, row_id: str) -> None:
    problems = lint_pattern(source)
    if problems:
        raise RegistryError(problems[0], file=file, row_id=row_id)


def _unique(rows: list[DefaultRow]) -> None:
    seen: set[str] = set()
    for row in rows:
        if row.id in seen:
            raise RegistryError("duplicate id", file="", row_id=row.id)
        seen.add(row.id)


def _disjoint(rows: list[DefaultRow]) -> None:
    groups: dict[tuple[str, str, str], list[DefaultRow]] = {}
    for row in rows:
        for native in row.type:
            groups.setdefault((row.provider, native, row.attribute), []).append(row)
    for group in groups.values():
        for index, left in enumerate(group):
            for right in group[index + 1 :]:
                if _versions_overlap(left.versions, right.versions) and _when_overlap(
                    left.when, right.when
                ):
                    raise RegistryError(
                        f"when and versions overlap {right.id}",
                        row_id=left.id,
                    )


def _versions_overlap(left: VersionRange, right: VersionRange) -> bool:
    if left.min is None or right.min is None:
        return True
    if left.max_exclusive is not None and left.max_exclusive <= right.min:
        return False
    return not (
        right.max_exclusive is not None and right.max_exclusive <= left.min
    )


def _when_overlap(
    left: Mapping[str, Mapping[str, tuple[Any, ...]]],
    right: Mapping[str, Mapping[str, tuple[Any, ...]]],
) -> bool:
    if not left or not right:
        return True
    shared = set(left) & set(right)
    if not shared:
        return False
    return any(_clause_overlap(left[syntax], right[syntax]) for syntax in shared)


def _clause_overlap(
    left: Mapping[str, tuple[Any, ...]], right: Mapping[str, tuple[Any, ...]]
) -> bool:
    shared = set(left) & set(right)
    if not shared:
        return True
    return all(not set(left[path]).isdisjoint(right[path]) for path in shared)


def _overrides_exist(rows: list[DefaultRow]) -> None:
    ids = {row.id for row in rows}
    for row in rows:
        if row.override is not None and row.override.row not in ids:
            raise RegistryError(
                f"override row {row.override.row} is missing", row_id=row.id
            )


def _suite_refs(parsed: Mapping[str, Mapping[str, Any]]) -> None:
    policies = parsed.get("tls_policies.json")
    ciphers = parsed.get("cipher_suites.json")
    if policies is None or ciphers is None:
        return
    names = {
        row.get("iana")
        for row in ciphers.get("rows", ())
        if isinstance(row, dict)
    }
    sets = {
        row.get("id")
        for row in ciphers.get("rows", ())
        if isinstance(row, dict)
    }
    for row in policies.get("rows", ()):
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("id", ""))
        for suite in row.get("suites") or ():
            if suite not in names:
                raise RegistryError(
                    f"suite {suite} is missing",
                    file="tls_policies.json",
                    row_id=row_id,
                )
        suite_set = row.get("suite_set")
        if suite_set is not None and suite_set not in sets:
            raise RegistryError(
                f"suite_set {suite_set} is missing",
                file="tls_policies.json",
                row_id=row_id,
            )


def _has_backreference(source: str) -> bool:
    index = 0
    while index < len(source) - 1:
        if source[index] == "\\" and source[index + 1].isdigit():
            return True
        index += 1
    return False


def _skip_class(source: str, start: int) -> int:
    index = start + 1
    if index < len(source) and source[index] == "^":
        index += 1
    if index < len(source) and source[index] == "]":
        index += 1
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
            continue
        if source[index] == "]":
            return index + 1
        index += 1
    return len(source)


def _negated_unbounded(source: str) -> bool:
    index = 0
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
            continue
        if source[index] != "[":
            index += 1
            continue
        end = _skip_class(source, index)
        negated = source[index + 1 : end].startswith("^")
        if negated and end < len(source) and source[end] in "*+":
            return True
        index = end
    return False


def _oversize_bound(source: str) -> int | None:
    index = 0
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
            continue
        if source[index] != "{":
            index += 1
            continue
        end = source.find("}", index)
        if end < 0:
            return None
        body = source[index + 1 : end]
        numbers = body.split(",")
        if not numbers or any(not part.isdigit() for part in numbers if part):
            index = end + 1
            continue
        upper = int(numbers[-1]) if numbers[-1] else None
        if upper is not None and upper > 256:
            return upper
        index = end + 1
    return None


def _group_problems(source: str) -> list[str]:
    problems: list[str] = []
    index = 0
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
            continue
        if source[index] == "[":
            index = _skip_class(source, index)
            continue
        if source[index] != "(":
            index += 1
            continue
        end = _match_paren(source, index)
        raw = source[index + 1 : end]
        after = end + 1
        quantified = after < len(source) and source[after] in "*+?{"
        if quantified and _body_busy(_strip_group(raw)):
            problems.append("quantified group")
            return problems
        index = end + 1
    return problems


def _match_paren(source: str, start: int) -> int:
    depth = 0
    index = start
    while index < len(source):
        if source[index] == "\\" and index + 1 < len(source):
            index += 2
            continue
        if source[index] == "[":
            index = _skip_class(source, index)
            continue
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(source) - 1


def _strip_group(raw: str) -> str:
    if raw.startswith(("?:", "?=", "?!", "?>")):
        return raw[2:]
    if raw.startswith("?P<") and ">" in raw:
        return raw[raw.index(">") + 1 :]
    return raw


def _body_busy(body: str) -> bool:
    index = 0
    while index < len(body):
        if body[index] == "\\" and index + 1 < len(body):
            index += 2
            continue
        if body[index] == "[":
            index = _skip_class(body, index)
            continue
        if body[index] in "*+|{":
            return True
        index += 1
    return False


def _unbounded_problem(source: str) -> str | None:
    extras: list[int] = []
    index = 0
    length = len(source)
    while index < length:
        if source[index] == "\\" and index + 1 < length:
            if index + 2 < length and source[index + 2] in "*+":
                token = source[index : index + 3]
                if token not in _ALLOWED_UNBOUNDED:
                    extras.append(index)
                index += 3
                continue
            index += 2
            continue
        if source[index] == "[":
            end = _skip_class(source, index)
            if end < length and source[end] in "*+":
                extras.append(end)
                index = end + 1
                continue
            index = end
            continue
        if source[index] in "*+":
            extras.append(index)
        index += 1
    if not extras:
        return None
    if len(extras) > 1:
        return "more than one unbounded quantifier"
    rest = source[extras[0] + 1 :]
    if rest.startswith("?"):
        rest = rest[1:]
    if rest != "":
        return "unbounded quantifier is not the last element"
    return None
