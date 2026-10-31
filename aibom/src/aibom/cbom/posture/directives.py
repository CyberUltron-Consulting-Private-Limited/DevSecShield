"""Directive parsers. Include paths are recorded and not followed."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.diagnostics import safe_parse

_MAX_ARGS = 1_024
_OPENSSH_LISTS = frozenset(
    {
        "ciphers",
        "macs",
        "kexalgorithms",
        "hostkeyalgorithms",
        "pubkeyacceptedalgorithms",
        "pubkeyacceptedkeytypes",
        "casignaturealgorithms",
    }
)
_APACHE_TRANSPARENT = frozenset({"ifmodule"})
_APACHE_CONDITIONAL = frozenset({"ifdefine", "ifversion", "if", "macro"})
_HAPROXY_SECTIONS = frozenset({"global", "defaults", "frontend", "backend", "listen"})

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS


@dataclass(frozen=True, slots=True)
class Directive:
    name: str
    args: tuple[str, ...]
    line: int
    parent: str | None
    marker: str | None = None


@dataclass(frozen=True, slots=True)
class DirectiveFile:
    entries: tuple[Directive, ...]
    includes: tuple[str, ...]
    lines: int

    def lookup(self, name: str, parent: str | None = None) -> tuple[str, ...] | None:
        folded = name.casefold()
        for entry in self.entries:
            if entry.name.casefold() == folded and entry.parent == parent:
                return entry.args
        return None


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def split_words(line: str, quotes: bool = True) -> tuple[str, ...]:
    """Split a directive line. At most 1,024 arguments are kept."""
    words: list[str] = []
    index = 0
    length = len(line)
    while index < length and len(words) < _MAX_ARGS:
        while index < length and line[index] in " \t":
            index += 1
        if index >= length or line[index] == "\n":
            break
        if quotes and line[index] in "\"'":
            quote = line[index]
            index += 1
            buf: list[str] = []
            while index < length and line[index] != quote:
                if line[index] == "\\" and index + 1 < length:
                    buf.append(line[index + 1])
                    index += 2
                    continue
                buf.append(line[index])
                index += 1
            if index < length and line[index] == quote:
                index += 1
            words.append("".join(buf))
            continue
        start = index
        while index < length and line[index] not in " \t\n":
            if quotes and line[index] in "\"'":
                break
            index += 1
        if index > start:
            words.append(line[start:index])
    return tuple(words)


def _strip_comment(line: str, marks: str = "#") -> str:
    buf: list[str] = []
    index = 0
    quote = ""
    while index < len(line):
        char = line[index]
        if quote:
            buf.append(char)
            if char == "\\" and index + 1 < len(line):
                buf.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            buf.append(char)
            index += 1
            continue
        if char in marks:
            break
        buf.append(char)
        index += 1
    return "".join(buf).strip()


def _logical_lines(text: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    buf = ""
    start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = number
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        rows.append((start, buf))
        buf = ""
    if buf:
        rows.append((start, buf))
    return rows


def _collapse(
    entries: list[Directive],
    *,
    first_wins: bool,
    sink: object | None,
    path: str,
    casefold: bool,
    keep_repeats: frozenset[str] = frozenset(),
) -> tuple[Directive, ...]:
    index: dict[tuple[str | None, str], int] = {}
    kept: list[Directive] = []
    for entry in entries:
        name = entry.name.casefold() if casefold else entry.name
        if name in keep_repeats:
            kept.append(entry)
            continue
        key = (entry.parent, name)
        if key in index:
            previous = kept[index[key]]
            conditional = entry.marker == "unresolved_expression"
            concrete = previous.marker != "unresolved_expression"
            if conditional and concrete:
                continue
            _add(sink, "duplicate_key", path, entry.line)
            if first_wins and concrete:
                continue
            kept[index[key]] = entry
            continue
        index[key] = len(kept)
        kept.append(entry)
    return tuple(kept)


def _finish(
    entries: list[Directive],
    includes: list[str],
    text: str,
    *,
    first_wins: bool,
    sink: object | None,
    path: str,
    casefold: bool = False,
    keep_repeats: frozenset[str] = frozenset(),
) -> DirectiveFile:
    kept = _collapse(
        entries,
        first_wins=first_wins,
        sink=sink,
        path=path,
        casefold=casefold,
        keep_repeats=keep_repeats,
    )
    return DirectiveFile(kept, tuple(includes), len(text.splitlines()))


def _guard(fn, text: str, path: str, sink: object | None) -> DirectiveFile | None:
    try:
        return fn(text, path, sink)
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None


def parse_nginx(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_nginx, text, path, sink)


def parse_apache(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_apache, text, path, sink)


def parse_haproxy(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_haproxy, text, path, sink)


def parse_openssh(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_openssh, text, path, sink)


def parse_postgresql(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(
        lambda raw, file, dest: _assign(raw, file, dest, _PG_INCLUDES), text, path, sink
    )


def parse_pg_hba(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_pg_hba, text, path, sink)


def parse_mysql_cnf(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_mysql, text, path, sink)


def parse_redis(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(
        lambda raw, file, dest: _words(raw, file, dest, "include"), text, path, sink
    )


def parse_crypttab(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_crypttab, text, path, sink)


def parse_properties(
    text: str, *, path: str = "", sink: object | None = None
) -> DirectiveFile | None:
    return _guard(_properties, text, path, sink)


def _nginx(text: str, path: str, sink: object | None) -> DirectiveFile:
    tokens = list(_lex_braces(text))
    entries: list[Directive] = []
    includes: list[str] = []
    cursor = 0

    def block(parent: str | None) -> None:
        nonlocal cursor
        while cursor < len(tokens):
            kind, value, line = tokens[cursor]
            if kind == "brace" and value == "}":
                return
            words: list[str] = []
            wline = line
            while cursor < len(tokens) and tokens[cursor][0] == "word":
                words.append(tokens[cursor][1])
                wline = tokens[cursor][2]
                cursor += 1
            if not words:
                if cursor < len(tokens) and tokens[cursor][1] == "{":
                    cursor += 1
                    block(parent)
                    if cursor < len(tokens) and tokens[cursor][1] == "}":
                        cursor += 1
                elif cursor < len(tokens):
                    cursor += 1
                continue
            name, args = words[0], tuple(words[1:])
            if cursor < len(tokens) and tokens[cursor][1] == "{":
                cursor += 1
                label = name if not args else name + " " + " ".join(args)
                child = label if parent is None else parent + "." + label
                block(child)
                if cursor < len(tokens) and tokens[cursor][1] == "}":
                    cursor += 1
                continue
            if cursor < len(tokens) and tokens[cursor][1] == ";":
                cursor += 1
            marker = "template_marker" if any("$" in arg for arg in args) else None
            entries.append(Directive(name, args, wline, parent, marker))
            if name == "include":
                includes.extend(args)

    block(None)
    return _finish(
        entries,
        includes,
        text,
        first_wins=False,
        sink=sink,
        path=path,
        keep_repeats=frozenset({"listen"}),
    )


def _lex_braces(text: str) -> list[tuple[str, str, int]]:
    tokens: list[tuple[str, str, int]] = []
    index = 0
    line = 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in " \t\r":
            index += 1
            continue
        if char == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char in "{};":
            tokens.append(("brace" if char != ";" else "semi", char, line))
            index += 1
            continue
        if char in "\"'":
            word, index, line = _quoted(text, index, line, char)
            tokens.append(("word", word, line))
            continue
        start = index
        while index < length and text[index] not in " \t\r\n{};#\"'":
            index += 1
        tokens.append(("word", text[start:index], line))
    return tokens


def _quoted(text: str, index: int, line: int, quote: str) -> tuple[str, int, int]:
    index += 1
    buf: list[str] = []
    while index < len(text) and text[index] != quote:
        if text[index] == "\n":
            line += 1
        if text[index] == "\\" and index + 1 < len(text):
            buf.append(text[index + 1])
            index += 2
            continue
        buf.append(text[index])
        index += 1
    if index < len(text) and text[index] == quote:
        index += 1
    return "".join(buf), index, line


def _apache(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    stack: list[tuple[str | None, str | None]] = [(None, None)]
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        if not line:
            continue
        if line.startswith("</"):
            if len(stack) > 1:
                stack.pop()
            continue
        if line.startswith("<") and line.endswith(">"):
            inner = split_words(line[1:-1])
            if not inner:
                continue
            section = inner[0].casefold()
            parent, marker = stack[-1]
            if section in _APACHE_TRANSPARENT:
                stack.append((parent, marker))
            elif section in _APACHE_CONDITIONAL:
                stack.append((parent, "unresolved_expression"))
            else:
                label = (
                    section if len(inner) == 1 else section + " " + " ".join(inner[1:])
                )
                child = label if parent is None else parent + "." + label
                stack.append((child, marker))
            continue
        words = split_words(line)
        if not words:
            continue
        name = words[0]
        args = words[1:]
        if "=" in name and not args:
            name, _, value = name.partition("=")
            args = (value,)
        parent, marker = stack[-1]
        folded = name.casefold()
        if folded in {"define", "use"}:
            marker = "unresolved_expression"
        entries.append(Directive(folded, args, number, parent, marker))
        if folded in {"include", "includeoptional"}:
            includes.extend(args)
    return _finish(
        entries, includes, text, first_wins=False, sink=sink, path=path, casefold=True
    )


def _haproxy(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    parent: str | None = None
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        words = split_words(line)
        if not words:
            continue
        name = words[0]
        args = words[1:]
        if name in _HAPROXY_SECTIONS:
            parent = name if not args else name + " " + " ".join(args)
            entries.append(Directive(name, args, number, None, None))
            continue
        marked = any(arg.startswith("${") or "${" in arg for arg in args)
        marker = "template_marker" if marked else None
        entries.append(Directive(name, args, number, parent, marker))
    return _finish(entries, [], text, first_wins=False, sink=sink, path=path)


def _openssh(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    parent: str | None = None
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        words = list(split_words(line))
        if not words:
            continue
        if len(words) == 1 and "=" in words[0]:
            name, _, value = words[0].partition("=")
            words = [name, value]
        name = words[0]
        args = tuple(words[1:])
        if name.casefold() == "match":
            parent = "Match " + " ".join(args) if args else "Match"
            entries.append(Directive(name, args, number, None, None))
            continue
        marker = None
        if parent is not None and name.casefold() not in _OPENSSH_LISTS:
            marker = "unresolved_expression"
        entries.append(Directive(name, args, number, parent, marker))
        if name.casefold() == "include":
            includes.extend(args)
    return _finish(
        entries,
        includes,
        text,
        first_wins=True,
        sink=sink,
        path=path,
        casefold=True,
        keep_repeats=frozenset({"listenaddress", "port"}),
    )


_PG_INCLUDES = frozenset({"include", "include_if_exists", "include_dir"})


def _assign(
    text: str,
    path: str,
    sink: object | None,
    include_names: frozenset[str],
) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        if not line:
            continue
        words = list(split_words(line))
        if not words:
            continue
        name = words[0]
        args = words[1:]
        if "=" in name and len(words) == 1:
            name, _, value = name.partition("=")
            args = (value,) if value else ()
        elif args and args[0] == "=":
            args = args[1:]
        elif "=" in name:
            name, _, value = name.partition("=")
            args = (value, *args) if value else args
        entries.append(Directive(name, tuple(args), number, None, None))
        if name in include_names:
            includes.extend(args)
    return _finish(entries, includes, text, first_wins=False, sink=sink, path=path)


def _pg_hba(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        words = split_words(line, quotes=False)
        if not words:
            continue
        name = words[0]
        args = words[1:]
        entries.append(Directive(name, args, number, None, None))
        if name in _PG_INCLUDES:
            includes.extend(args)
    return _finish(entries, includes, text, first_wins=False, sink=sink, path=path)


def _mysql(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    group: str | None = None
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw, marks="#;")
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1].strip()
            continue
        if line.startswith("!include"):
            parts = split_words(line)
            kind = parts[0].lstrip("!")
            args = parts[1:]
            entries.append(Directive(kind, args, number, group, None))
            includes.extend(args)
            continue
        name, args = _option(line)
        name = name.replace("-", "_")
        entries.append(Directive(name, args, number, group, None))
    return _finish(entries, includes, text, first_wins=False, sink=sink, path=path)


def _option(line: str) -> tuple[str, tuple[str, ...]]:
    if "=" in line:
        name, _, value = line.partition("=")
        return name.strip(), (value.strip(),) if value.strip() else ()
    words = split_words(line)
    if not words:
        return line.strip(), ()
    return words[0], words[1:]


def _words(
    text: str, path: str, sink: object | None, include_name: str
) -> DirectiveFile:
    entries: list[Directive] = []
    includes: list[str] = []
    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        words = split_words(line)
        if not words:
            continue
        name, args = words[0], words[1:]
        entries.append(Directive(name, args, number, None, None))
        if name == include_name:
            includes.extend(args)
    return _finish(entries, includes, text, first_wins=False, sink=sink, path=path)


def _crypttab(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        words = split_words(line, quotes=False)
        if not words:
            continue
        entries.append(Directive(words[0], words[1:], number, None, None))
    return _finish(entries, [], text, first_wins=False, sink=sink, path=path)


def _unescape_prop(value: str) -> str:
    buf: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value) and value[index + 1] == "u":
            hexes = value[index + 2 : index + 6]
            if len(hexes) == 4:
                buf.append(chr(int(hexes, 16)))
                index += 6
                continue
        buf.append(value[index])
        index += 1
    return "".join(buf)


def _properties(text: str, path: str, sink: object | None) -> DirectiveFile:
    entries: list[Directive] = []
    for number, raw in _logical_lines(text):
        line = raw.lstrip()
        if not line or line[0] in "#!":
            continue
        sep = _prop_sep(line)
        if sep is None:
            entries.append(Directive(line.strip(), (), number, None, None))
            continue
        key = _unescape_prop(line[:sep].strip())
        rest = line[sep:].lstrip()
        if rest[:1] in "=:":
            rest = rest[1:].lstrip()
        entries.append(Directive(key, (_unescape_prop(rest),), number, None, None))
    return _finish(entries, [], text, first_wins=False, sink=sink, path=path)


def _prop_sep(line: str) -> int | None:
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line):
            index += 2
            continue
        if char in "=:" or char.isspace():
            return index
        index += 1
    return None


def load_directives(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
    kind: str = "nginx",
):
    parsers = {
        "nginx": parse_nginx,
        "apache": parse_apache,
        "haproxy": parse_haproxy,
        "openssh": parse_openssh,
        "postgresql": parse_postgresql,
        "pg_hba": parse_pg_hba,
        "mysql": parse_mysql_cnf,
        "redis": parse_redis,
        "crypttab": parse_crypttab,
        "properties": parse_properties,
    }
    parser = parsers.get(kind, parse_nginx)

    def run(raw: bytes) -> DirectiveFile | None:
        result = parser(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)
