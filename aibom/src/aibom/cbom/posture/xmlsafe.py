"""XML loader. Unsafe DOCTYPEs are rejected before ElementTree runs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO
from xml.etree import ElementTree

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.limits import NESTING_DEPTH
from aibom.cbom.posture.textscan import XML_PAIRS, blank_spans

DOCTYPE_BARE = re.compile(r"<!DOCTYPE[ \t\r\n]+[A-Za-z_:][A-Za-z0-9_:.\-]*[ \t\r\n]*>")
NAME_AFTER_LT = re.compile(r"[A-Za-z_:][A-Za-z0-9_:.\-]*")

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (DOCTYPE_BARE, NAME_AFTER_LT)
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

_NODE_LIMIT = 1_000_000


@dataclass(slots=True)
class XmlDoc:
    root: ElementTree.Element
    start_lines: dict[str, tuple[int, ...]] = field(default_factory=dict)


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def xml_start_lines(text: str) -> dict[str, tuple[int, ...]]:
    """Start-tag lines per element name. Each newline is counted once."""
    found: dict[str, list[int]] = {}
    line = 1
    previous = 0
    cursor = 0
    while True:
        start = text.find("<", cursor)
        if start < 0:
            break
        line += text.count("\n", previous, start)
        previous = start
        nxt = start + 1
        if nxt < len(text) and text[nxt] not in "/!?":
            matched = NAME_AFTER_LT.match(text, nxt)
            if matched is not None:
                found.setdefault(matched.group(0), []).append(line)
        cursor = nxt
    return {name: tuple(lines) for name, lines in found.items()}


def _unsafe_doctype(blanked: str) -> bool:
    if blanked.find("<!ENTITY") >= 0:
        return True
    cursor = 0
    seen = 0
    while True:
        pos = blanked.find("<!DOCTYPE", cursor)
        if pos < 0:
            return False
        seen += 1
        if seen > 1 or DOCTYPE_BARE.match(blanked, pos) is None:
            return True
        cursor = pos + len("<!DOCTYPE")


def parse_xml(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    depth_limit: int = NESTING_DEPTH,
    node_limit: int = _NODE_LIMIT,
) -> XmlDoc | None:
    """Parse XML. A dangerous DOCTYPE records ``unsafe_xml`` and is not parsed."""
    try:
        blanked = blank_spans(text, XML_PAIRS, unterminated="error")
        if blanked is None:
            _add(sink, "parse_error", path, 0)
            return None
        if _unsafe_doctype(blanked):
            _add(sink, "unsafe_xml", path, 0)
            return None
        lines = xml_start_lines(blanked)
        root = _iter_root(text, depth_limit, node_limit)
    except _Depth:
        _add(sink, "depth_cap", path, 0)
        return None
    except _Nodes:
        _add(sink, "node_cap", path, 0)
        return None
    except (ElementTree.ParseError, RecursionError, MemoryError, ValueError):
        _add(sink, "parse_error", path, 0)
        return None
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None
    if root is None:
        _add(sink, "parse_error", path, 0)
        return None
    return XmlDoc(root, lines)


class _Depth(Exception):
    pass


class _Nodes(Exception):
    pass


def _iter_root(
    text: str, depth_limit: int, node_limit: int
) -> ElementTree.Element | None:
    stream = BytesIO(text.encode("utf-8"))
    depth = 0
    nodes = 0
    root: ElementTree.Element | None = None
    for event, element in ElementTree.iterparse(stream, events=("start", "end")):
        if event == "start":
            nodes += 1
            if nodes > node_limit:
                raise _Nodes
            depth += 1
            if depth > depth_limit:
                raise _Depth
            if root is None:
                root = element
            continue
        depth -= 1
    return root


def load_xml(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> XmlDoc | None:
    def run(raw: bytes) -> XmlDoc | None:
        result = parse_xml(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
