"""In-repo business mapping. Unknown keys and bad entries are diagnostics."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from aibom.cbom.posture.codeowners import parse_codeowners
from aibom.cbom.posture.coverage import KINDS
from aibom.cbom.posture.globmatch import GlobProgram, compile_glob
from aibom.cbom.posture.limits import GlobBudget
from aibom.cbom.posture.model import Linkage
from aibom.cbom.posture.yamlsafe import parse_yaml

_FIELDS = ("system", "owner", "data_classification", "data_lifetime")
_FIELD_SET = frozenset(_FIELDS)
_ROOT_KEYS = frozenset({"version", "defaults", "entries"})
_MATCH_KEYS = frozenset({"resource", "path", "kind"})
_ENTRY_KEYS = _FIELD_SET | frozenset({"match", "notes"})
_CAP = 10_000
_TEXT = 256
MAPPING_ORDER = (
    ".devsecshield/cbom-mapping.yaml",
    ".devsecshield/cbom-mapping.json",
    "cbom-mapping.yaml",
    "cbom-mapping.json",
)
OWNERS_ORDER = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


@dataclass(frozen=True, slots=True)
class MappingNote:
    code: str
    path: str
    line: int = 0


@dataclass(frozen=True, slots=True)
class MapEntry:
    resource: GlobProgram | None
    path_glob: GlobProgram | None
    kind: str | None
    fields: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class BusinessMap:
    defaults: Mapping[str, str]
    entries: tuple[MapEntry, ...]
    notes: tuple[MappingNote, ...]
    dropped: int = 0


def _note(code: str, path: str, line: int = 0) -> MappingNote:
    return MappingNote(code, path, line)


def load_mapping(text: str, path: str) -> BusinessMap:
    """Read version 1. A bad version ignores the file."""
    parsed = parse_yaml(text, path=path)
    document = _document(parsed)
    if not isinstance(document, dict):
        document = _json(text)
    if not isinstance(document, dict):
        return _empty((_note("mapping_entry_invalid", path),))
    notes: list[MappingNote] = []
    for key in document:
        if str(key) not in _ROOT_KEYS:
            notes.append(_note("mapping_unknown_key", path))
    if type(document.get("version")) is not int or document.get("version") != 1:
        notes.append(_note("mapping_file_ignored", path))
        return _empty(tuple(notes))
    defaults, default_notes = _fields(document.get("defaults"), path, required=False)
    notes.extend(default_notes)
    entries, dropped, entry_notes = _entries(document.get("entries"), path)
    notes.extend(entry_notes)
    return BusinessMap(defaults, entries, tuple(notes), dropped)


def matched_linkage(
    mapping: BusinessMap,
    address: str,
    path: str,
    kind: str,
    budget: GlobBudget,
) -> Linkage | None:
    """Later matching entries override earlier fields. Source is mapping_file."""
    values = dict(mapping.defaults)
    for entry in mapping.entries:
        if entry.kind is not None and entry.kind != kind:
            continue
        if entry.resource is not None and not entry.resource.match(address, budget):
            continue
        if entry.path_glob is not None and not entry.path_glob.match(path, budget):
            continue
        values.update(entry.fields)
    if not any(values.values()):
        return None
    return Linkage(
        system=values.get("system"),
        owner=values.get("owner"),
        data_classification=values.get("data_classification"),
        data_lifetime=values.get("data_lifetime"),
        source="mapping_file",
    )


def owner_hint(text: str, rel: str, path: str = "CODEOWNERS") -> str | None:
    """Last matching CODEOWNERS rule, joined. None when nothing matches."""
    owners = parse_codeowners(text, path=path)
    if owners is None:
        return None
    found = owners.owner_of(rel, GlobBudget())
    if not found:
        return None
    return " ".join(found)


def first_named(paths: Mapping[str, object], order: tuple[str, ...]) -> str | None:
    """First path in ``order``. Comparison is case-folded."""
    folded = {key.casefold(): key for key in paths}
    for name in order:
        hit = folded.get(name.casefold())
        if hit is not None:
            return hit
    return None


def _empty(notes: tuple[MappingNote, ...]) -> BusinessMap:
    return BusinessMap({}, (), notes, 0)


def _document(parsed: object) -> object:
    if isinstance(parsed, list) and len(parsed) == 1:
        return parsed[0]
    return parsed


def _json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _fields(
    raw: object, path: str, *, required: bool
) -> tuple[dict[str, str], list[MappingNote]]:
    if raw is None and not required:
        return {}, []
    if not isinstance(raw, dict):
        return {}, [_note("mapping_entry_invalid", path)]
    notes: list[MappingNote] = []
    values: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key)
        if name not in _FIELD_SET:
            notes.append(_note("mapping_unknown_key", path))
            continue
        if not isinstance(value, str):
            return {}, notes + [_note("mapping_entry_invalid", path)]
        cleaned = _clean(value)
        if cleaned:
            values[name] = cleaned
    return values, notes


def _entries(
    raw: object, path: str
) -> tuple[tuple[MapEntry, ...], int, list[MappingNote]]:
    if raw is None:
        return (), 0, []
    if not isinstance(raw, list):
        return (), 0, [_note("mapping_entry_invalid", path)]
    kept: list[MapEntry] = []
    notes: list[MappingNote] = []
    dropped = 0
    for index, item in enumerate(raw):
        if len(kept) >= _CAP:
            dropped += 1
            continue
        entry, entry_notes = _entry(item, path, index + 1)
        notes.extend(entry_notes)
        if entry is not None:
            kept.append(entry)
    return tuple(kept), dropped, notes


def _entry(
    item: object, path: str, line: int
) -> tuple[MapEntry | None, list[MappingNote]]:
    if not isinstance(item, dict):
        return None, [_note("mapping_entry_invalid", path, line)]
    notes: list[MappingNote] = []
    for key in item:
        if str(key) not in _ENTRY_KEYS:
            notes.append(_note("mapping_unknown_key", path, line))
    fields, field_notes = _fields(
        {key: item[key] for key in _FIELD_SET if key in item},
        path,
        required=False,
    )
    if any(note.code == "mapping_entry_invalid" for note in field_notes):
        return None, notes + [_note("mapping_entry_invalid", path, line)]
    notes.extend(field_notes)
    resource, path_glob, kind, match_notes, bad = _match(item.get("match"), path, line)
    notes.extend(match_notes)
    if bad:
        return None, notes
    return MapEntry(resource, path_glob, kind, fields), notes


def _match(
    raw: object, path: str, line: int
) -> tuple[GlobProgram | None, GlobProgram | None, str | None, list[MappingNote], bool]:
    if raw is None:
        return None, None, None, [], False
    if not isinstance(raw, dict):
        return None, None, None, [_note("mapping_entry_invalid", path, line)], True
    notes: list[MappingNote] = []
    for key in raw:
        if str(key) not in _MATCH_KEYS:
            notes.append(_note("mapping_unknown_key", path, line))
    resource = _glob(raw.get("resource"), True)
    path_glob = _glob(raw.get("path"), False)
    kind = raw.get("kind")
    bad = _note("mapping_entry_invalid", path, line)
    if resource is None and "resource" in raw:
        return None, None, None, notes + [bad], True
    if path_glob is None and "path" in raw:
        return None, None, None, notes + [bad], True
    if kind is None and "kind" not in raw:
        return resource, path_glob, None, notes, False
    if not isinstance(kind, str) or kind not in KINDS:
        return None, None, None, notes + [bad], True
    return resource, path_glob, kind, notes, False


def _glob(value: object, crosses: bool) -> GlobProgram | None:
    if not isinstance(value, str) or not value:
        return None
    return compile_glob(_clean(value), star_crosses_slash=crosses)


def _clean(value: str) -> str:
    kept = "".join(char for char in value if char >= " " and char != "\x7f")
    return kept[:_TEXT]
