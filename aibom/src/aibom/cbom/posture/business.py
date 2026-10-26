"""In-repo business mapping. Unknown keys and bad entries are diagnostics."""

from __future__ import annotations

import json
from dataclasses import dataclass

from aibom.cbom.posture.codeowners import parse_codeowners
from aibom.cbom.posture.limits import GlobBudget
from aibom.cbom.posture.model import Linkage
from aibom.cbom.posture.yamlsafe import parse_yaml

_FIELDS = frozenset({"system", "owner", "data_classification", "data_lifetime"})
_CAP = 10_000


@dataclass(frozen=True, slots=True)
class MappingNote:
    code: str
    path: str
    line: int = 0


@dataclass(frozen=True, slots=True)
class BusinessMap:
    links: tuple[Linkage, ...]
    notes: tuple[MappingNote, ...]


def _note(code: str, path: str, line: int = 0) -> MappingNote:
    return MappingNote(code, path, line)


def load_mapping(text: str, path: str) -> BusinessMap:
    """Read a YAML or JSON list. Extra keys and bad entries are notes."""
    parsed = parse_yaml(text, path=path)
    document = _document(parsed)
    if document is None:
        document = _json(text)
    if not isinstance(document, list):
        return BusinessMap((), (_note("mapping_entry_invalid", path),))
    links: list[Linkage] = []
    notes: list[MappingNote] = []
    for index, item in enumerate(document):
        if len(links) >= _CAP:
            notes.append(_note("mapping_entry_invalid", path, index + 1))
            break
        if not isinstance(item, dict):
            notes.append(_note("mapping_entry_invalid", path, index + 1))
            continue
        unknown = [key for key in item if str(key) not in _FIELDS]
        if unknown:
            notes.append(_note("mapping_unknown_key", path, index + 1))
        links.append(
            Linkage(
                system=_text(item.get("system")),
                owner=_text(item.get("owner")),
                data_classification=_text(item.get("data_classification")),
                data_lifetime=_text(item.get("data_lifetime")),
                source=path,
            )
        )
    return BusinessMap(tuple(links), tuple(notes))


def owner_hint(text: str, rel: str, path: str = "CODEOWNERS") -> str | None:
    """Last matching CODEOWNERS rule, joined. None when nothing matches."""
    owners = parse_codeowners(text, path=path)
    if owners is None:
        return None
    found = owners.owner_of(rel, GlobBudget())
    if not found:
        return None
    return " ".join(found)


def _document(parsed: object) -> object:
    if isinstance(parsed, list) and len(parsed) == 1:
        return parsed[0]
    return parsed


def _json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _text(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None
