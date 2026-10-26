"""YAML loader. Pure-Python SafeLoader only, capped before objects exist."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import yaml
from yaml.events import AliasEvent, DocumentEndEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.limits import NESTING_DEPTH, YAML_ALIASES, YAML_NODES

CFN_TAGS = frozenset(
    {
        "Ref",
        "GetAtt",
        "Sub",
        "Join",
        "If",
        "FindInMap",
        "ImportValue",
        "Select",
        "Split",
        "Equals",
        "And",
        "Or",
        "Not",
        "Condition",
        "Base64",
        "Cidr",
        "GetAZs",
        "Transform",
    }
)

_SAFE_SUFFIXES = frozenset(
    {
        "str",
        "int",
        "float",
        "bool",
        "null",
        "seq",
        "map",
        "set",
        "omap",
        "pairs",
        "binary",
        "timestamp",
        "merge",
        "value",
    }
)
_PREFIX = "tag:yaml.org,2002:"

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS


class LineDict(dict[object, object]):
    """Mapping that remembers the line of its start mark."""

    line: int

    def __init__(self, line: int = 1) -> None:
        super().__init__()
        self.line = line


class LineList(list[object]):
    """Sequence that remembers the line of its start mark."""

    line: int

    def __init__(self, line: int = 1) -> None:
        super().__init__()
        self.line = line


@dataclass(frozen=True, slots=True)
class Tagged:
    """A local YAML tag kept as data. It is not evaluated."""

    name: str
    value: object


class NodeCap(Exception):
    code = "node_cap"


class AliasCap(Exception):
    code = "alias_cap"


class DepthCap(Exception):
    code = "depth_cap"


class UnsafeTag(Exception):
    code = "unsafe_tag"


class _Loader(yaml.SafeLoader):
    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._nodes = 0
        self._aliases = 0
        self.node_limit = YAML_NODES
        self.alias_limit = YAML_ALIASES

    def compose_node(self, parent: Node | None, index: object) -> Node:
        self._nodes += 1
        if self._nodes > self.node_limit:
            raise NodeCap
        if self.check_event(AliasEvent):
            self._aliases += 1
            if self._aliases > self.alias_limit:
                raise AliasCap
        return super().compose_node(parent, index)

    def construct_yaml_map(self, node: MappingNode) -> object:
        data = LineDict(node.start_mark.line + 1)
        yield data
        filled = self.construct_mapping(node)
        data.update(filled)

    def construct_yaml_seq(self, node: SequenceNode) -> object:
        data = LineList(node.start_mark.line + 1)
        yield data
        data.extend(self.construct_sequence(node))


def _tagged(loader: _Loader, suffix: str, node: Node) -> Tagged:
    if isinstance(node, ScalarNode):
        value: object = loader.construct_scalar(node)
    elif isinstance(node, SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, MappingNode):
        value = loader.construct_mapping(node)
    else:
        value = None
    return Tagged(suffix, value)


_Loader.add_constructor("tag:yaml.org,2002:map", _Loader.construct_yaml_map)
_Loader.add_constructor("tag:yaml.org,2002:seq", _Loader.construct_yaml_seq)
_Loader.add_multi_constructor("!", _tagged)


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def _children(node: Node) -> list[Node]:
    if isinstance(node, MappingNode):
        kids: list[Node] = []
        for key, value in node.value:
            kids.append(key)
            kids.append(value)
        return kids
    if isinstance(node, SequenceNode):
        return list(node.value)
    return []


def _reject_unsafe(node: Node) -> None:
    tag = node.tag or ""
    if not tag.startswith(_PREFIX):
        return
    suffix = tag[len(_PREFIX) :]
    if suffix not in _SAFE_SUFFIXES:
        raise UnsafeTag


def _local_unknown(node: Node) -> int | None:
    tag = node.tag or ""
    if not tag.startswith("!") or tag.startswith("!<"):
        return None
    name = tag[1:]
    if name in CFN_TAGS:
        return None
    return node.start_mark.line + 1


def _duplicate_lines(node: MappingNode) -> list[int]:
    seen: set[tuple[str, str]] = set()
    lines: list[int] = []
    for key, _value in node.value:
        if not isinstance(key, ScalarNode):
            continue
        ident = (key.tag, key.value)
        if ident in seen:
            lines.append(key.start_mark.line + 1)
        else:
            seen.add(ident)
    return lines


def _inspect(
    node: Node, expand_limit: int, depth_limit: int
) -> tuple[list[int], list[int]]:
    memo_size: dict[int, int] = {}
    memo_depth: dict[int, int] = {}
    kids_of: dict[int, list[Node]] = {}
    visiting: set[int] = set()
    stack: list[tuple[Node, int]] = [(node, 0)]
    duplicates: list[int] = []
    unknowns: list[int] = []
    while stack:
        current, state = stack.pop()
        cid = id(current)
        if state == 1:
            visiting.discard(cid)
            kids = kids_of[cid]
            total = 1
            deep = 0
            for kid in kids:
                total += memo_size.get(id(kid), 1)
                if total > expand_limit:
                    total = expand_limit + 1
                deep = max(deep, 1 + memo_depth.get(id(kid), 0))
            if not kids:
                deep = 0
            memo_size[cid] = total
            memo_depth[cid] = deep
            if total > expand_limit:
                raise AliasCap
            if deep > depth_limit:
                raise DepthCap
            continue
        if cid in memo_size or cid in visiting:
            if cid not in memo_size:
                memo_size[cid] = 1
                memo_depth[cid] = 0
            continue
        _reject_unsafe(current)
        unknown = _local_unknown(current)
        if unknown is not None:
            unknowns.append(unknown)
        if isinstance(current, MappingNode):
            duplicates.extend(_duplicate_lines(current))
        kids = _children(current)
        kids_of[cid] = kids
        visiting.add(cid)
        stack.append((current, 1))
        for kid in reversed(kids):
            if id(kid) not in memo_size:
                stack.append((kid, 0))
    return duplicates, unknowns


def _drain(loader: _Loader) -> None:
    while loader.check_event() and not loader.check_event(DocumentEndEvent):
        loader.get_event()
    if loader.check_event(DocumentEndEvent):
        loader.get_event()
    loader.anchors = {}


def _mark_line(loader: _Loader) -> int:
    event = getattr(loader, "current_event", None)
    mark = getattr(event, "start_mark", None)
    if mark is None:
        return 0
    return int(mark.line) + 1


def parse_yaml(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    node_limit: int = YAML_NODES,
    alias_limit: int = YAML_ALIASES,
    depth_limit: int = NESTING_DEPTH,
    expand_limit: int = YAML_NODES,
) -> list[object] | None:
    """Load every document. Caps are applied before Python objects are built."""
    documents: list[object] = []
    broken = False
    try:
        loader = _Loader(text)
        loader.node_limit = node_limit
        loader.alias_limit = alias_limit
        while loader.check_node():
            loader._nodes = 0
            loader._aliases = 0
            try:
                node = loader.get_node()
            except (NodeCap, AliasCap) as cap:
                _add(sink, cap.code, path, _mark_line(loader))
                try:
                    _drain(loader)
                except yaml.YAMLError:
                    _add(sink, "parse_error", path, 0)
                    broken = True
                    break
                continue
            except yaml.YAMLError:
                _add(sink, "parse_error", path, 0)
                broken = True
                break
            if node is None:
                continue
            try:
                duplicates, unknowns = _inspect(node, expand_limit, depth_limit)
            except AliasCap:
                _add(sink, "alias_cap", path, _mark_line(loader))
                continue
            except DepthCap:
                _add(sink, "depth_cap", path, _mark_line(loader))
                continue
            except UnsafeTag:
                _add(sink, "unsafe_tag", path, _mark_line(loader))
                continue
            for line in duplicates:
                _add(sink, "duplicate_key", path, line)
            for line in unknowns:
                _add(sink, "unknown_tag", path, line)
            try:
                documents.append(loader.construct_document(node))
            except yaml.YAMLError:
                _add(sink, "parse_error", path, 0)
                broken = True
                break
    except yaml.YAMLError:
        _add(sink, "parse_error", path, 0)
        broken = True
    except Exception:
        _add(sink, "parse_error", path, 0)
        return documents or None
    if broken and not documents:
        return None
    return documents


def flatten_dotted(node: object, prefix: str = "") -> dict[str, object]:
    """Normalise nested maps and already-dotted keys onto one dotted path."""
    if isinstance(node, Mapping):
        flat: dict[str, object] = {}
        for key, value in node.items():
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            if isinstance(value, Mapping):
                flat.update(flatten_dotted(value, path))
            else:
                flat[path] = value
        return flat
    if prefix:
        return {prefix: node}
    return {}


def load_yaml(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> list[object] | None:
    def run(raw: bytes) -> list[object] | None:
        result = parse_yaml(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
