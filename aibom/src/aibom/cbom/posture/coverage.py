"""Coverage table loader. Builds the rule objects the verdict engine reads.

Names of the eight readers are stored here. Their functions arrive with the
extractors and are passed in at assessment time.
"""

from __future__ import annotations

import functools
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from aibom.cbom.posture.defaults import (
    SYNTAXES,
    DefaultRow,
    DefaultsRegistry,
    iac_syntax_gap,
    load_registry,
    read_data_bytes,
)
from aibom.cbom.posture.model import DataTable, is_hidden_path

READER_NAMES: Final[frozenset[str]] = frozenset(
    {
        "key_policy",
        "deny_insecure_transport",
        "gcp_iam_bindings",
        "pg_transport",
        "redis_transport",
        "cryptsetup",
        "sql_labels",
        "listener_reader",
    }
)
ROLES: Final[frozenset[str]] = frozenset(
    {"resource", "child", "companion", "override", "link_only"}
)
KINDS: Final[frozenset[str]] = frozenset(
    {
        "kms_key",
        "object_store",
        "block_volume",
        "file_system",
        "relational_db",
        "nosql_db",
        "cache",
        "search_index",
        "message_queue",
        "message_topic",
        "data_stream",
        "data_warehouse",
        "backup",
        "secret_store",
        "log_store",
        "k8s_secrets_etcd",
        "k8s_storage_class",
        "tls_endpoint",
        "certificate_policy",
        "ssh_service",
        "disk_encryption",
    }
)
LAYERS: Final[frozenset[str]] = frozenset(
    {"application", "database", "volume", "service", "backup", "transport"}
)
_ROW_FIELDS = frozenset(
    {
        "id",
        "role",
        "kind",
        "provider",
        "native",
        "cfn_when",
        "layers",
        "key",
        "attrs",
        "refs",
        "presence",
        "tls_floor",
        "companions",
        "parent",
        "block",
        "address_key",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "from",
        "tf",
        "cfn",
        "k8s",
        "cfg",
        "companion",
        "enabling",
        "disabling",
        "as_absent",
        "row",
        "reader",
        "reader_version",
    }
)
_PATH_FIELDS = (
    ("terraform", "tf"),
    ("cloudformation", "cfn"),
    ("kubernetes", "k8s"),
    ("compose", "cfg"),
    ("server", "cfg"),
)
RefRole = Literal["key_ref", "secret_ref"]
SourceKind = Literal["attr", "block", "companion"]


class CoverageError(ValueError):
    """A coverage row failed validation."""

    def __init__(self, message: str, *, row_id: str = "") -> None:
        self.row_id = row_id
        prefix = f"{row_id}: " if row_id else ""
        super().__init__(prefix + message)


@dataclass(frozen=True, slots=True)
class RefSpec:
    path: str
    role: RefRole


@dataclass(frozen=True, slots=True)
class Source:
    kind: SourceKind
    tf: str | None
    cfn: str | None
    k8s: str | None
    cfg: str | None
    companion_type: str | None
    enabling: frozenset[str]
    disabling: frozenset[str]
    as_absent: frozenset[str]
    row: str | None
    reader: str | None
    reader_version: int


@dataclass(frozen=True, slots=True)
class LayerRule:
    layer: str
    sources: tuple[Source, ...]
    default_row: str | None
    self_hosted: bool


@dataclass(frozen=True, slots=True)
class TypeRule:
    id: str
    role: str
    kind: str | None
    provider: str
    native: Mapping[str, tuple[Any, ...]]
    cfn_when: Mapping[str, str]
    layers: Mapping[str, LayerRule]
    key_paths: tuple[Mapping[str, str | None], ...]
    attr_paths: tuple[Mapping[str, str | None], ...]
    tls_floor: Mapping[str, Any] | None
    companions: tuple[tuple[str, str], ...]
    parent: str | None
    block: Mapping[str, str]
    address_key: str | None
    consulted: Mapping[str, frozenset[str]]
    refs: tuple[RefSpec, ...]
    presence: frozenset[str]


@dataclass(frozen=True, slots=True)
class CoverageTable:
    table: DataTable
    rules: tuple[TypeRule, ...]
    by_id: Mapping[str, TypeRule]
    row_hashes: Mapping[str, str]


def build_coverage(blob: bytes, registry: DefaultsRegistry) -> CoverageTable:
    """Validate one coverage document against ``registry``."""
    document = _load(blob)
    raw_rows = document.get("rows")
    if not isinstance(raw_rows, list):
        raise CoverageError("rows must be a list")
    rules: list[TypeRule] = []
    hashes: dict[str, str] = {}
    seen: set[str] = set()
    for raw in raw_rows:
        if not isinstance(raw, dict):
            raise CoverageError("row must be an object")
        rule = _rule(raw, registry)
        if rule.id in seen:
            raise CoverageError("duplicate id", row_id=rule.id)
        seen.add(rule.id)
        hashes[rule.id] = _canonical_hash(raw)
        rules.append(rule)
    _native_claims(rules)
    table = DataTable(
        name="coverage_table.json",
        data_version=_positive(document.get("data_version"), "data_version"),
        valid_as_of=_date(document.get("valid_as_of")),
        sha256=hashlib.sha256(blob).hexdigest(),
    )
    return CoverageTable(
        table=table,
        rules=tuple(rules),
        by_id=MappingProxyType({rule.id: rule for rule in rules}),
        row_hashes=MappingProxyType(hashes),
    )


def _load(blob: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise CoverageError(f"duplicate key {key}")
            out[key] = value
        return out

    try:
        data = json.loads(blob, object_pairs_hook=pairs)
    except CoverageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoverageError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CoverageError("document must be an object")
    return data


def _rule(raw: Mapping[str, Any], registry: DefaultsRegistry) -> TypeRule:
    unknown = set(raw) - _ROW_FIELDS
    ident = raw.get("id")
    row_id = ident if isinstance(ident, str) else ""
    if unknown:
        raise CoverageError(f"unknown field {sorted(unknown)[0]}", row_id=row_id)
    for field in ("id", "role", "provider", "native"):
        if field not in raw:
            raise CoverageError(f"missing field {field}", row_id=row_id)
    row_id = _text(raw["id"], "id", row_id)
    role = raw["role"]
    if role not in ROLES:
        raise CoverageError("role is not a closed value", row_id=row_id)
    kind = raw.get("kind")
    if role in {"resource", "child"} and kind not in KINDS:
        raise CoverageError("kind is not a closed value", row_id=row_id)
    if kind is not None and kind not in KINDS:
        raise CoverageError("kind is not a closed value", row_id=row_id)
    native = _native(raw["native"], row_id)
    cfn_when = _string_map(raw.get("cfn_when", {}), "cfn_when", row_id)
    if cfn_when and "cloudformation" not in native:
        raise CoverageError("cfn_when requires cloudformation", row_id=row_id)
    layers = _layers(raw.get("layers", {}), row_id)
    key_paths = _path_maps(raw.get("key", []), "key", row_id)
    attr_paths = _attr_maps(raw.get("attrs", []), row_id)
    refs = _refs(raw.get("refs", []), row_id)
    presence = _presence(raw.get("presence", []), row_id)
    companions = _companions(raw.get("companions", []), row_id)
    tls_floor = _tls_floor(raw.get("tls_floor"), row_id)
    block = _string_map(raw.get("block", {}), "block", row_id)
    parent = _optional_text(raw.get("parent"), "parent", row_id)
    address_key = _optional_text(raw.get("address_key"), "address_key", row_id)
    if role == "child" and (parent is None or not block):
        raise CoverageError("child rows require parent and block", row_id=row_id)
    reached = _reached(layers, registry, row_id)
    consulted = _consulted(
        native, layers, key_paths, attr_paths, companions, tls_floor, reached
    )
    if not any(consulted.values()):
        raise CoverageError("row consults no attributes", row_id=row_id)
    _predicates(reached, set(native), row_id)
    _hidden(consulted, refs, presence, row_id)
    return TypeRule(
        id=row_id,
        role=str(role),
        kind=None if kind is None else str(kind),
        provider=_text(raw["provider"], "provider", row_id),
        native=native,
        cfn_when=cfn_when,
        layers=layers,
        key_paths=key_paths,
        attr_paths=attr_paths,
        tls_floor=tls_floor,
        companions=companions,
        parent=parent,
        block=block,
        address_key=address_key,
        consulted=consulted,
        refs=refs,
        presence=presence,
    )


def _text(value: Any, field: str, row_id: str) -> str:
    if not isinstance(value, str) or not value:
        raise CoverageError(f"{field} must be a non-empty string", row_id=row_id)
    return value


def _optional_text(value: Any, field: str, row_id: str) -> str | None:
    if value is None:
        return None
    return _text(value, field, row_id)


def _native(value: Any, row_id: str) -> Mapping[str, tuple[Any, ...]]:
    if not isinstance(value, dict) or not value:
        raise CoverageError("native must be a non-empty object", row_id=row_id)
    out: dict[str, tuple[Any, ...]] = {}
    for syntax, names in value.items():
        if syntax not in SYNTAXES or not isinstance(names, list) or not names:
            raise CoverageError("native syntax is closed", row_id=row_id)
        parsed: list[Any] = []
        for name in names:
            if syntax == "kubernetes":
                parsed.append(_k8s_name(name, row_id))
            elif isinstance(name, str) and name:
                parsed.append(name)
            else:
                raise CoverageError("native names must be strings", row_id=row_id)
        if len(parsed) != len({_native_key(item) for item in parsed}):
            raise CoverageError("duplicate native name", row_id=row_id)
        out[syntax] = tuple(parsed)
    return MappingProxyType(out)


def _k8s_name(value: Any, row_id: str) -> Mapping[str, str]:
    if not isinstance(value, dict) or set(value) != {"group", "kind"}:
        raise CoverageError(
            "kubernetes native name needs group and kind", row_id=row_id
        )
    group = value["group"] if isinstance(value["group"], str) else None
    kind = value["kind"] if isinstance(value["kind"], str) and value["kind"] else None
    if group is None or kind is None:
        raise CoverageError(
            "kubernetes native name needs group and kind", row_id=row_id
        )
    return MappingProxyType({"group": group, "kind": kind})


def _string_map(value: Any, field: str, row_id: str) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise CoverageError(f"{field} must be an object", row_id=row_id)
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise CoverageError(f"{field} values must be strings", row_id=row_id)
        out[key] = item
    return MappingProxyType(out)


def _layers(value: Any, row_id: str) -> Mapping[str, LayerRule]:
    if not isinstance(value, dict):
        raise CoverageError("layers must be an object", row_id=row_id)
    out: dict[str, LayerRule] = {}
    for name, body in value.items():
        if name not in LAYERS or not isinstance(body, dict):
            raise CoverageError("layer name is closed", row_id=row_id)
        unknown = set(body) - {"default_row", "self_hosted", "sources"}
        if unknown:
            raise CoverageError(f"unknown field {sorted(unknown)[0]}", row_id=row_id)
        if not isinstance(body.get("self_hosted"), bool):
            raise CoverageError("self_hosted must be a boolean", row_id=row_id)
        default_row = body.get("default_row")
        if default_row is not None and not isinstance(default_row, str):
            raise CoverageError("default_row must be a string", row_id=row_id)
        sources_raw = _list(body.get("sources", []), "sources", row_id)
        sources = tuple(_source(item, row_id) for item in sources_raw)
        out[name] = LayerRule(
            layer=name,
            sources=sources,
            default_row=default_row,
            self_hosted=body["self_hosted"],
        )
    return MappingProxyType(out)


def _source(raw: Any, row_id: str) -> Source:
    if not isinstance(raw, dict):
        raise CoverageError("source must be an object", row_id=row_id)
    unknown = set(raw) - _SOURCE_FIELDS
    if unknown:
        raise CoverageError(f"unknown field {sorted(unknown)[0]}", row_id=row_id)
    kind = raw.get("from")
    if kind not in {"attr", "block", "companion"}:
        raise CoverageError("source from is closed", row_id=row_id)
    reader = raw.get("reader")
    if reader is not None and reader not in READER_NAMES:
        raise CoverageError("unknown reader", row_id=row_id)
    version = raw.get("reader_version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise CoverageError("reader_version must be a positive integer", row_id=row_id)
    companion = raw.get("companion")
    if kind == "companion" and not isinstance(companion, str):
        raise CoverageError("companion source needs companion", row_id=row_id)
    return Source(
        kind=kind,
        tf=_path(raw.get("tf"), row_id),
        cfn=_path(raw.get("cfn"), row_id),
        k8s=_path(raw.get("k8s"), row_id),
        cfg=_path(raw.get("cfg"), row_id),
        companion_type=companion if isinstance(companion, str) else None,
        enabling=_words(raw.get("enabling", []), "enabling", row_id),
        disabling=_words(raw.get("disabling", []), "disabling", row_id),
        as_absent=_words(raw.get("as_absent", []), "as_absent", row_id),
        row=raw.get("row") if isinstance(raw.get("row"), str) else None,
        reader=reader if isinstance(reader, str) else None,
        reader_version=version,
    )


def _path(value: Any, row_id: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CoverageError("path must be a string", row_id=row_id)
    return value


def _words(value: Any, field: str, row_id: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CoverageError(f"{field} must be a list of strings", row_id=row_id)
    return frozenset(value)


def _list(value: Any, field: str, row_id: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoverageError(f"{field} must be a list", row_id=row_id)
    return value


def _path_maps(
    value: Any, field: str, row_id: str
) -> tuple[Mapping[str, str | None], ...]:
    out: list[Mapping[str, str | None]] = []
    for item in _list(value, field, row_id):
        if not isinstance(item, dict):
            raise CoverageError(f"{field} entry must be an object", row_id=row_id)
        allowed = {"tf", "cfn", "k8s", "cfg", "companion"}
        if set(item) - allowed:
            name = sorted(set(item) - allowed)[0]
            raise CoverageError(f"unknown field {name}", row_id=row_id)
        keys = ("tf", "cfn", "k8s", "cfg")
        mapped = {key: _path(item.get(key), row_id) for key in keys}
        if "companion" in item:
            mapped["companion"] = _path(item.get("companion"), row_id)
        if not any(mapped.get(key) for key in ("tf", "cfn", "k8s", "cfg")):
            raise CoverageError(f"{field} entry has no path", row_id=row_id)
        out.append(MappingProxyType(mapped))
    return tuple(out)


def _attr_maps(value: Any, row_id: str) -> tuple[Mapping[str, str | None], ...]:
    out: list[Mapping[str, str | None]] = []
    for item in _list(value, "attrs", row_id):
        if not isinstance(item, dict) or "name" not in item:
            raise CoverageError("attrs entry needs a name", row_id=row_id)
        allowed = {"name", "tf", "cfn", "k8s", "cfg"}
        if set(item) - allowed:
            name = sorted(set(item) - allowed)[0]
            raise CoverageError(f"unknown field {name}", row_id=row_id)
        mapped: dict[str, str | None] = {
            "name": _text(item["name"], "name", row_id)
        }
        for key in ("tf", "cfn", "k8s", "cfg"):
            if key in item:
                mapped[key] = _path(item[key], row_id)
        if not any(mapped.get(key) for key in ("tf", "cfn", "k8s", "cfg")):
            raise CoverageError("attrs entry has no path", row_id=row_id)
        out.append(MappingProxyType(mapped))
    return tuple(out)


def _refs(value: Any, row_id: str) -> tuple[RefSpec, ...]:
    out: list[RefSpec] = []
    for item in _list(value, "refs", row_id):
        if not isinstance(item, dict) or set(item) != {"path", "role"}:
            raise CoverageError("refs entry needs path and role", row_id=row_id)
        role = item["role"]
        if role not in {"key_ref", "secret_ref"}:
            raise CoverageError("refs role is closed", row_id=row_id)
        out.append(RefSpec(path=_text(item["path"], "path", row_id), role=role))
    return tuple(out)


def _presence(value: Any, row_id: str) -> frozenset[str]:
    items = _list(value, "presence", row_id)
    if any(not isinstance(item, str) or not item for item in items):
        raise CoverageError("presence entries must be strings", row_id=row_id)
    return frozenset(items)


def _companions(value: Any, row_id: str) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for item in _list(value, "companions", row_id):
        if not isinstance(item, dict) or set(item) != {"row", "parent_attr"}:
            raise CoverageError("companion needs row and parent_attr", row_id=row_id)
        out.append(
            (
                _text(item["row"], "row", row_id),
                _text(item["parent_attr"], "parent_attr", row_id),
            )
        )
    return tuple(out)


def _tls_floor(value: Any, row_id: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise CoverageError("tls_floor must be an object", row_id=row_id)
    allowed = {"tf", "cfn", "k8s", "cfg", "map"}
    unknown = set(value) - allowed
    if unknown:
        raise CoverageError(f"unknown field {sorted(unknown)[0]}", row_id=row_id)
    return MappingProxyType(dict(value))


def _reached(
    layers: Mapping[str, LayerRule], registry: DefaultsRegistry, row_id: str
) -> tuple[DefaultRow, ...]:
    ids: list[str] = []
    for layer in layers.values():
        if layer.default_row:
            ids.append(layer.default_row)
        ids.extend(source.row for source in layer.sources if source.row)
    found: list[DefaultRow] = []
    seen: set[str] = set()
    pending = list(ids)
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        row = registry.by_id.get(current)
        if row is None:
            raise CoverageError(f"registry row {current} is missing", row_id=row_id)
        found.append(row)
        if row.override is not None:
            pending.append(row.override.row)
        for other in registry.rows:
            same_key = (
                other.provider == row.provider and other.attribute == row.attribute
            )
            if same_key and set(other.type) & set(row.type):
                pending.append(other.id)
    return tuple(found)


def _consulted(
    native: Mapping[str, tuple[Any, ...]],
    layers: Mapping[str, LayerRule],
    key_paths: tuple[Mapping[str, str | None], ...],
    attr_paths: tuple[Mapping[str, str | None], ...],
    companions: tuple[tuple[str, str], ...],
    tls_floor: Mapping[str, Any] | None,
    reached: tuple[DefaultRow, ...],
) -> Mapping[str, frozenset[str]]:
    buckets: dict[str, set[str]] = {syntax: set() for syntax in native}
    for layer in layers.values():
        for source in layer.sources:
            _add_source_paths(buckets, source)
    for item in (*key_paths, *attr_paths):
        _add_item_paths(buckets, item)
    for _row, parent_attr in companions:
        for bucket in buckets.values():
            bucket.add(parent_attr)
    if tls_floor is not None:
        for syntax, field in _PATH_FIELDS:
            path = tls_floor.get(field)
            if isinstance(path, str) and syntax in buckets:
                buckets[syntax].add(path)
    for row in reached:
        for syntax, clause in row.when.items():
            if syntax in buckets:
                buckets[syntax].update(clause)
        for syntax, paths in row.unless_attrs.items():
            if syntax in buckets:
                buckets[syntax].update(paths)
    frozen = {
        syntax: frozenset(paths) for syntax, paths in buckets.items()
    }
    return MappingProxyType(frozen)


def _add_source_paths(buckets: dict[str, set[str]], source: Source) -> None:
    for syntax, field in _PATH_FIELDS:
        path = getattr(source, field)
        if path and syntax in buckets:
            buckets[syntax].add(path)


def _add_item_paths(
    buckets: dict[str, set[str]], item: Mapping[str, str | None]
) -> None:
    for syntax, field in _PATH_FIELDS:
        path = item.get(field)
        if path and syntax in buckets:
            buckets[syntax].add(path)


def _predicates(rows: tuple[DefaultRow, ...], native: set[str], row_id: str) -> None:
    for row in rows:
        for label, mapping in (("when", row.when), ("unless_attrs", row.unless_attrs)):
            if not mapping:
                continue
            missing = iac_syntax_gap(mapping)
            if missing is not None:
                raise CoverageError(
                    f"{label} names only one of terraform/cloudformation; "
                    f"missing {missing}",
                    row_id=row_id,
                )
            for syntax in sorted(native):
                if syntax not in mapping:
                    raise CoverageError(
                        f"{label} missing syntax {syntax}", row_id=row_id
                    )


def _hidden(
    consulted: Mapping[str, frozenset[str]],
    refs: tuple[RefSpec, ...],
    presence: frozenset[str],
    row_id: str,
) -> None:
    ref_paths = {spec.path for spec in refs}
    overlap = ref_paths & presence
    if overlap:
        raise CoverageError("refs and presence must be disjoint", row_id=row_id)
    declared = ref_paths | presence
    used = set().union(*consulted.values()) if consulted else set()
    for path in used:
        if is_hidden_path(path) and path not in declared:
            raise CoverageError(
                f"hidden path {path} is in neither refs nor presence", row_id=row_id
            )
    for path in declared:
        if not is_hidden_path(path):
            raise CoverageError(f"path {path} is not hidden", row_id=row_id)
        if path not in used:
            raise CoverageError(f"path {path} is not consulted", row_id=row_id)


def _native_claims(rules: list[TypeRule]) -> None:
    groups: dict[tuple[str, str], list[TypeRule]] = {}
    for rule in rules:
        for syntax, names in rule.native.items():
            for name in names:
                groups.setdefault((syntax, _native_key(name)), []).append(rule)
    for (syntax, _name), group in groups.items():
        if len(group) < 2:
            continue
        if syntax != "cloudformation" or not _cfn_exclusive(group):
            raise CoverageError(
                "two rows claim one native type", row_id=group[0].id
            )


def _cfn_exclusive(group: list[TypeRule]) -> bool:
    empty = [rule for rule in group if not rule.cfn_when]
    if len(empty) > 1:
        return False
    chosen = [rule.cfn_when for rule in group if rule.cfn_when]
    if not chosen:
        return len(group) == 1
    props = {next(iter(item)) for item in chosen}
    if len(props) != 1 or any(len(item) != 1 for item in chosen):
        return False
    literals = [next(iter(item.values())) for item in chosen]
    return len(literals) == len(set(literals))


def _native_key(name: Any) -> str:
    if isinstance(name, Mapping):
        return f"{name.get('group', '')}|{name.get('kind', '')}"
    return str(name)


def _positive(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CoverageError(f"{field} must be a positive integer")
    return value


def _date(value: Any) -> str:
    iso = isinstance(value, str) and len(value) == 10
    iso = iso and value[4] == "-" and value[7] == "-"
    if not iso:
        raise CoverageError("valid_as_of must be an ISO date")
    return value


def _canonical_hash(row: Mapping[str, Any]) -> str:
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@functools.cache
def load_coverage() -> CoverageTable:
    """Load the shipped coverage table. Fails closed when the file is absent."""
    return build_coverage(read_data_bytes("coverage_table.json"), load_registry())
