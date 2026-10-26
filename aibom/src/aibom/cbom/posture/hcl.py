"""In-house HCL subset. Expressions are recorded and never evaluated."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.limits import NESTING_DEPTH

# The slash alternative must not match a comment opener. A bare ``/`` makes
# ``/*`` quadratic because the block-comment alternative then scans to the end.
_TOKEN_RE = re.compile(
    r"[ \t]+|\r?\n|#[^\n]*|//[^\n]*|/\*|\.\.\.|<<-?"
    r"|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
    r"|[A-Za-z_][A-Za-z0-9_-]*"
    r"|>=|<=|==|!=|&&|\|\|"
    r"|/(?![*/])"
    r"|[\[\]{}().,?:!=+\-*%]"
)

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (_TOKEN_RE,)
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

_TOKEN_LIMIT = 2_500_000
_NODE_LIMIT = 1_000_000
_BINOPS = frozenset(
    {"+", "-", "*", "/", "%", "&&", "||", "==", "!=", "<", ">", "<=", ">="}
)
_BLOCK_TYPES = frozenset({"resource", "data", "module", "variable", "output"})


class _Cap(Exception):
    def __init__(self, code: str, line: int) -> None:
        self.code = code
        self.line = line


class _Fail(Exception):
    def __init__(self, line: int) -> None:
        self.line = line


@dataclass(frozen=True, slots=True)
class Lit:
    value: str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class Tuple:  # noqa: A001
    items: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class Obj:
    items: tuple[tuple[object, object], ...]


@dataclass(frozen=True, slots=True)
class Ref:
    root: str
    steps: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class Unresolved:
    kind: str
    raw_span: str
    parts: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class Attr:
    name: str
    expr: object
    line: int


@dataclass(frozen=True, slots=True)
class Block:
    type: str
    labels: tuple[str, ...]
    body: Body
    line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class Body:
    attrs: tuple[Attr, ...]
    blocks: tuple[Block, ...]


_Tok = tuple[str, object, int, int, int]


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


class _Lexer:
    def __init__(self, text: str, token_limit: int) -> None:
        self.text = text
        self.n = len(text)
        self.i = 0
        self.line = 1
        self.limit = token_limit
        self.count = 0
        self.queue: list[_Tok] = []
        self.last_end = 0

    def peek(self, ahead: int = 0) -> _Tok:
        while len(self.queue) <= ahead:
            self.queue.append(self._pull())
        return self.queue[ahead]

    def pop(self) -> _Tok:
        tok = self.peek()
        del self.queue[0]
        self.last_end = tok[4]
        return tok

    def _pull(self) -> _Tok:
        text = self.text
        while self.i < self.n:
            matched = _TOKEN_RE.match(text, self.i)
            if matched is None:
                if text[self.i] == '"':
                    return self._string()
                raise _Fail(self.line)
            lexeme = matched.group(0)
            start = self.i
            self.i = matched.end()
            if lexeme[0] in " \t":
                continue
            if lexeme.startswith("\n") or lexeme.startswith("\r"):
                self.line += lexeme.count("\n")
                continue
            if lexeme.startswith("#") or lexeme.startswith("//"):
                continue
            if lexeme.startswith("/*"):
                self._block_comment(start)
                continue
            if lexeme.startswith("<<"):
                return self._heredoc(lexeme, start)
            self._charge()
            if lexeme[0].isdigit():
                return ("num", _number(lexeme), self.line, start, self.i)
            if lexeme[0].isalpha() or lexeme[0] == "_":
                return ("ident", lexeme, self.line, start, self.i)
            return ("punct", lexeme, self.line, start, self.i)
        return ("eof", "", self.line, self.i, self.i)

    def _charge(self) -> None:
        self.count += 1
        if self.count > self.limit:
            raise _Cap("node_cap", self.line)

    def _block_comment(self, start: int) -> None:
        end = self.text.find("*/", start + 2)
        if end < 0:
            raise _Fail(self.line)
        self.line += self.text.count("\n", start, end + 2)
        self.i = end + 2

    def _string(self) -> _Tok:
        start = self.i
        line = self.line
        self.i += 1
        parts: list[object] = []
        buf: list[str] = []

        def flush() -> None:
            if buf:
                parts.append("".join(buf))
                buf.clear()

        while self.i < self.n:
            char = self.text[self.i]
            if char == '"':
                flush()
                self.i += 1
                self._charge()
                expr = _collapse(parts, self.text[start : self.i])
                return ("str", expr, line, start, self.i)
            if char == "\n":
                raise _Fail(self.line)
            if char == "\\":
                buf.append(self._escape())
                continue
            if self.text.startswith("$${", self.i) or self.text.startswith(
                "%%{", self.i
            ):
                buf.append(self.text[self.i + 1 : self.i + 3])
                self.i += 3
                continue
            if self.text.startswith("${", self.i) or self.text.startswith("%{", self.i):
                flush()
                marker = self.text[self.i]
                self.i += 2
                parts.append(self._interpolation(marker))
                continue
            buf.append(char)
            self.i += 1
        raise _Fail(line)

    def _escape(self) -> str:
        self.i += 1
        if self.i >= self.n:
            raise _Fail(self.line)
        char = self.text[self.i]
        self.i += 1
        simple = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
        if char in simple:
            return simple[char]
        if char == "u" and self.i + 4 <= self.n:
            hexes = self.text[self.i : self.i + 4]
            self.i += 4
            return chr(int(hexes, 16))
        if char == "U" and self.i + 8 <= self.n:
            hexes = self.text[self.i : self.i + 8]
            self.i += 8
            return chr(int(hexes, 16))
        return char

    def _interpolation(self, marker: str) -> object:
        start = self.i
        nest = 0
        while self.i < self.n:
            char = self.text[self.i]
            if char == '"':
                self._string()
                continue
            if char in "{[(":
                nest += 1
            elif char in "}])":
                if char == "}" and nest == 0:
                    inner = self.text[start : self.i]
                    self.i += 1
                    return _inner_expr(inner, marker)
                nest -= 1
            if char == "\n":
                self.line += 1
            self.i += 1
        raise _Fail(self.line)

    def _heredoc(self, opener: str, start: int) -> _Tok:
        line = self.line
        indented = opener.startswith("<<-")
        while self.i < self.n and self.text[self.i] in " \t":
            self.i += 1
        quoted = False
        if self.i < self.n and self.text[self.i] == '"':
            quoted = True
            self.i += 1
        mark_at = self.i
        while self.i < self.n and (
            self.text[self.i].isalnum() or self.text[self.i] in "_-"
        ):
            self.i += 1
        marker = self.text[mark_at : self.i]
        if not marker:
            raise _Fail(line)
        if quoted:
            if self.i >= self.n or self.text[self.i] != '"':
                raise _Fail(line)
            self.i += 1
        if self.i < self.n and self.text[self.i] == "\r":
            self.i += 1
        if self.i >= self.n or self.text[self.i] != "\n":
            raise _Fail(line)
        self.i += 1
        self.line += 1
        rows: list[str] = []
        while self.i <= self.n:
            end = self.text.find("\n", self.i)
            if end < 0:
                row = self.text[self.i :]
                self.i = self.n
            else:
                row = self.text[self.i : end]
                self.i = end + 1
                self.line += 1
            if row.lstrip() == marker:
                break
            if self.i >= self.n and row.lstrip() != marker:
                raise _Fail(line)
            rows.append(row)
        if indented:
            rows = _dedent(rows)
        body = "\n".join(rows)
        if rows:
            body += "\n"
        expr = _template_body(body)
        self._charge()
        return ("str", expr, line, start, self.i)


def _dedent(rows: list[str]) -> list[str]:
    leads = []
    for row in rows:
        if not row.strip():
            continue
        size = len(row) - len(row.lstrip(" \t"))
        leads.append(row[:size])
    if not leads:
        return rows
    common = leads[0]
    for lead in leads[1:]:
        while common and not lead.startswith(common):
            common = common[:-1]
    if not common:
        return rows
    width = len(common)
    return [row[width:] if row.strip() else row for row in rows]


def _number(lexeme: str) -> int | float:
    if any(char in lexeme for char in ".eE"):
        return float(lexeme)
    return int(lexeme)


def _collapse(parts: list[object], raw: str) -> object:
    nodes: list[object] = []
    for part in parts:
        if isinstance(part, str):
            if part:
                nodes.append(Lit(part))
        else:
            nodes.append(part)
    if not nodes:
        return Lit("")
    if all(isinstance(node, Lit) and isinstance(node.value, str) for node in nodes):
        return Lit("".join(str(node.value) for node in nodes if isinstance(node, Lit)))
    if len(nodes) == 1:
        return nodes[0]
    return Unresolved("template", raw, tuple(nodes))


def _template_body(body: str) -> object:
    parts: list[object] = []
    buf: list[str] = []
    index = 0
    length = len(body)

    def flush() -> None:
        if buf:
            parts.append("".join(buf))
            buf.clear()

    while index < length:
        if body.startswith("$${", index) or body.startswith("%%{", index):
            buf.append(body[index + 1 : index + 3])
            index += 3
            continue
        if body.startswith("${", index) or body.startswith("%{", index):
            flush()
            marker = body[index]
            index += 2
            end, expr = _body_interp(body, index, marker)
            parts.append(expr)
            index = end
            continue
        buf.append(body[index])
        index += 1
    flush()
    return _collapse(parts, body)


def _body_interp(body: str, index: int, marker: str) -> tuple[int, object]:
    start = index
    nest = 0
    while index < len(body):
        char = body[index]
        if char in "{[(":
            nest += 1
        elif char == "}" and nest == 0:
            inner = body[start:index]
            return index + 1, _inner_expr(inner, marker)
        elif char in "}])":
            nest = max(0, nest - 1)
        index += 1
    raise _Fail(1)


def _inner_expr(inner: str, marker: str) -> object:
    try:
        parser = _Parser(inner, NESTING_DEPTH, _NODE_LIMIT, _TOKEN_LIMIT, True)
        expr = parser.parse_expr()
        if parser.lex.peek()[0] != "eof":
            return Unresolved("template", inner, (expr,))
        return expr
    except _Fail:
        if marker == "%":
            return Unresolved("template", inner, ())
        raise
    except _Cap:
        raise


class _Parser:
    def __init__(
        self,
        text: str,
        depth_limit: int,
        node_limit: int,
        token_limit: int,
        allow_blocks: bool,
    ) -> None:
        self.text = text
        self.lex = _Lexer(text, token_limit)
        self.depth_limit = depth_limit
        self.node_limit = node_limit
        self.allow_blocks = allow_blocks
        self.depth = 0
        self.nodes = 0
        self.soft: list[tuple[str, int]] = []

    def parse_file(self) -> Body:
        body = self.parse_body(False)
        if self.lex.peek()[0] != "eof":
            raise _Fail(self.lex.peek()[2])
        return body

    def parse_body(self, stop: bool) -> Body:
        attrs: dict[str, Attr] = {}
        blocks: list[Block] = []
        addresses: dict[tuple[str, str, str], int] = {}
        while True:
            tok = self.lex.peek()
            if tok[0] == "eof":
                if stop:
                    raise _Fail(tok[2])
                break
            if tok[0] == "punct" and tok[1] == "}" and stop:
                break
            if tok[0] != "ident":
                raise _Fail(tok[2])
            name = str(self.lex.pop()[1])
            line = tok[2]
            nxt = self.lex.peek()
            if nxt[0] == "punct" and nxt[1] == "=":
                self.lex.pop()
                expr = self.parse_expr()
                if name in attrs:
                    self.soft.append(("duplicate_key", line))
                attrs[name] = Attr(name, expr, line)
                continue
            if not self.allow_blocks:
                raise _Fail(line)
            labels, body, end_line = self._block_rest(line)
            block = Block(name, labels, body, line, end_line)
            if name in ("resource", "data") and len(labels) == 2 and not stop:
                addr = (name, labels[0], labels[1])
                if addr in addresses:
                    self.soft.append(("duplicate_resource", line))
                    blocks[addresses[addr]] = block
                    continue
                addresses[addr] = len(blocks)
            blocks.append(block)
        ordered = tuple(attrs[key] for key in attrs)
        return Body(ordered, tuple(blocks))

    def _block_rest(self, line: int) -> tuple[tuple[str, ...], Body, int]:
        labels: list[str] = []
        while True:
            tok = self.lex.peek()
            if tok[0] == "ident":
                labels.append(str(self.lex.pop()[1]))
                continue
            if tok[0] == "str":
                labels.append(_label(tok[1], tok[2]))
                self.lex.pop()
                continue
            break
        if not (self.lex.peek()[0] == "punct" and self.lex.peek()[1] == "{"):
            raise _Fail(line)
        self.lex.pop()
        self._enter()
        body = self.parse_body(True)
        close = self.lex.peek()
        if not (close[0] == "punct" and close[1] == "}"):
            raise _Fail(close[2])
        self.lex.pop()
        self._leave()
        return tuple(labels), body, close[2]

    def parse_expr(self) -> object:
        start = self.lex.peek()[3]
        left = self._binary()
        if self._punct("?"):
            self.lex.pop()
            mid = self.parse_expr()
            if not self._punct(":"):
                raise _Fail(self.lex.peek()[2])
            self.lex.pop()
            right = self.parse_expr()
            return self._node(
                Unresolved(
                    "cond", self.text[start : self.lex.last_end], (left, mid, right)
                )
            )
        return left

    def _binary(self) -> object:
        start = self.lex.peek()[3]
        left = self._unary()
        parts = [left]
        while self._binop():
            op = str(self.lex.pop()[1])
            parts.append(Lit(op))
            parts.append(self._unary())
        if len(parts) == 1:
            return left
        return self._node(
            Unresolved("binary", self.text[start : self.lex.last_end], tuple(parts))
        )

    def _unary(self) -> object:
        tok = self.lex.peek()
        if tok[0] == "punct" and tok[1] in {"!", "-"}:
            op = str(self.lex.pop()[1])
            term = self._unary()
            return self._node(Unresolved("binary", op, (Lit(op), term)))
        return self._term()

    def _term(self) -> object:
        tok = self.lex.peek()
        if tok[0] == "punct" and tok[1] == "(":
            self.lex.pop()
            self._enter()
            expr = self.parse_expr()
            if not self._punct(")"):
                raise _Fail(tok[2])
            self.lex.pop()
            self._leave()
            return expr
        if tok[0] == "punct" and tok[1] == "[":
            return self._collection("[", "]")
        if tok[0] == "punct" and tok[1] == "{":
            return self._collection("{", "}")
        if tok[0] == "str":
            self.lex.pop()
            return self._node(tok[1])
        if tok[0] == "num":
            self.lex.pop()
            return self._node(Lit(tok[1]))  # type: ignore[arg-type]
        if tok[0] == "ident":
            return self._ident_expr()
        raise _Fail(tok[2])

    def _ident_expr(self) -> object:
        tok = self.lex.pop()
        name = str(tok[1])
        if self._punct("("):
            return self._call(name, tok[3])
        if (
            name in {"true", "false", "null"}
            and not self._punct(".")
            and not self._punct("[")
        ):
            value: bool | None = {"true": True, "false": False, "null": None}[name]
            return self._node(Lit(value))
        return self._traversal(name, tok[3])

    def _call(self, name: str, start: int) -> object:
        self.lex.pop()
        self._enter()
        args: list[object] = [Lit(name)]
        if not self._punct(")"):
            while True:
                if self._punct("..."):
                    self.lex.pop()
                    args.append(Lit("..."))
                    if self._punct(","):
                        self.lex.pop()
                    break
                args.append(self.parse_expr())
                if self._punct(","):
                    self.lex.pop()
                    if self._punct(")"):
                        break
                    continue
                break
        if not self._punct(")"):
            raise _Fail(self.lex.peek()[2])
        self.lex.pop()
        self._leave()
        return self._node(
            Unresolved("call", self.text[start : self.lex.last_end], tuple(args))
        )

    def _traversal(self, root: str, start: int) -> object:
        steps: list[object] = []
        splat = False
        while True:
            if self._punct(".") and self._peek_ahead_punct("*"):
                self.lex.pop()
                self.lex.pop()
                steps.append("*")
                splat = True
                continue
            if self._punct("."):
                self.lex.pop()
                nxt = self.lex.peek()
                if nxt[0] not in {"ident", "num"}:
                    raise _Fail(nxt[2])
                steps.append(self.lex.pop()[1])
                continue
            if self._punct("["):
                self.lex.pop()
                if self._punct("*"):
                    self.lex.pop()
                    splat = True
                    steps.append("*")
                else:
                    steps.append(self.parse_expr())
                if not self._punct("]"):
                    raise _Fail(self.lex.peek()[2])
                self.lex.pop()
                continue
            break
        ref = Ref(root, tuple(steps))
        if splat:
            return self._node(
                Unresolved("splat", self.text[start : self.lex.last_end], (ref,))
            )
        return self._node(ref)

    def _collection(self, open_ch: str, close_ch: str) -> object:
        start = self.lex.peek()[3]
        self.lex.pop()
        self._enter()
        if self.lex.peek()[0] == "ident" and self.lex.peek()[1] == "for":
            raw = self._balanced(close_ch, start)
            self._leave()
            return self._node(Unresolved("for", raw, ()))
        if open_ch == "[":
            items: list[object] = []
            if not self._punct(close_ch):
                while True:
                    items.append(self.parse_expr())
                    if self._punct(","):
                        self.lex.pop()
                        if self._punct(close_ch):
                            break
                        continue
                    break
            self._expect(close_ch)
            self._leave()
            return self._node(Tuple(tuple(items)))
        pairs: list[tuple[object, object]] = []
        while not self._punct(close_ch):
            if self.lex.peek()[0] == "eof":
                raise _Fail(self.lex.peek()[2])
            key = self._object_key()
            if not (self._punct("=") or self._punct(":")):
                raise _Fail(self.lex.peek()[2])
            self.lex.pop()
            pairs.append((key, self.parse_expr()))
            if self._punct(","):
                self.lex.pop()
        self._expect(close_ch)
        self._leave()
        return self._node(Obj(tuple(pairs)))

    def _object_key(self) -> object:
        tok = self.lex.peek()
        if tok[0] == "ident":
            return str(self.lex.pop()[1])
        if tok[0] == "str":
            self.lex.pop()
            if isinstance(tok[1], Lit) and isinstance(tok[1].value, str):
                return tok[1].value
            return tok[1]
        if self._punct("("):
            self.lex.pop()
            expr = self.parse_expr()
            self._expect(")")
            return expr
        raise _Fail(tok[2])

    def _balanced(self, close_ch: str, start: int) -> str:
        depth = 1
        opens = {"{": "}", "[": "]"}
        while depth:
            tok = self.lex.pop()
            if tok[0] == "eof":
                raise _Fail(tok[2])
            if tok[0] == "punct" and tok[1] in opens:
                depth += 1
            elif tok[0] == "punct" and tok[1] in {"}", "]"}:
                depth -= 1
                if depth == 0 and tok[1] != close_ch:
                    raise _Fail(tok[2])
        return self.text[start : self.lex.last_end]

    def _punct(self, value: str) -> bool:
        tok = self.lex.peek()
        return tok[0] == "punct" and tok[1] == value

    def _binop(self) -> bool:
        tok = self.lex.peek()
        return tok[0] == "punct" and tok[1] in _BINOPS

    def _peek_ahead_punct(self, value: str) -> bool:
        tok = self.lex.peek(1)
        return tok[0] == "punct" and tok[1] == value

    def _expect(self, value: str) -> None:
        if not self._punct(value):
            raise _Fail(self.lex.peek()[2])
        self.lex.pop()

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > self.depth_limit:
            raise _Cap("depth_cap", self.lex.line)

    def _leave(self) -> None:
        self.depth -= 1

    def _node(self, value: object) -> object:
        self.nodes += 1
        if self.nodes > self.node_limit:
            raise _Cap("node_cap", self.lex.line)
        return value


def _label(expr: object, line: int) -> str:
    if isinstance(expr, Lit) and isinstance(expr.value, str):
        return expr.value
    raise _Fail(line)


def parse_hcl(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    depth_limit: int = NESTING_DEPTH,
    node_limit: int = _NODE_LIMIT,
    token_limit: int = _TOKEN_LIMIT,
    allow_blocks: bool = True,
) -> Body | None:
    """Parse an HCL body. A file-level failure records one diagnostic."""
    parser = _Parser(text, depth_limit, node_limit, token_limit, allow_blocks)
    try:
        body = parser.parse_file()
    except _Cap as cap:
        _add(sink, cap.code, path, cap.line)
        return None
    except _Fail as fail:
        _add(sink, "parse_error", path, fail.line)
        return None
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None
    for code, line in parser.soft:
        _add(sink, code, path, line)
    return body


def parse_tfvars(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
) -> Body | None:
    """Attribute grammar. A block in a tfvars file is ``parse_error``."""
    return parse_hcl(text, path=path, sink=sink, allow_blocks=False)


def from_terraform_json(value: object) -> Body | None:
    """Adapt a Terraform JSON document onto the HCL block tree."""
    if not isinstance(value, dict):
        return None
    blocks: list[Block] = []
    attrs: list[Attr] = []
    for key, item in value.items():
        name = str(key)
        if name == "locals" and isinstance(item, dict):
            blocks.append(Block("locals", (), _json_body(item), 1, 1))
            continue
        if name in _BLOCK_TYPES and isinstance(item, dict):
            blocks.extend(_json_blocks(name, item))
            continue
        attrs.append(Attr(name, _json_expr(item), 1))
    return Body(tuple(attrs), tuple(blocks))


def _json_blocks(kind: str, item: dict[object, object]) -> list[Block]:
    found: list[Block] = []
    two = kind in {"resource", "data"}
    if two:
        for type_name, names in item.items():
            if not isinstance(names, dict):
                continue
            for name, body in names.items():
                if isinstance(body, dict):
                    found.append(
                        Block(kind, (str(type_name), str(name)), _json_body(body), 1, 1)
                    )
        return found
    for name, body in item.items():
        if isinstance(body, dict):
            found.append(Block(kind, (str(name),), _json_body(body), 1, 1))
    return found


def _json_body(item: dict[object, object]) -> Body:
    return Body(
        tuple(Attr(str(key), _json_expr(val), 1) for key, val in item.items()), ()
    )


def _json_expr(value: object) -> object:
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}") and "${" not in value[2:-1]:
            inner = value[2:-1].strip()
            parsed = parse_hcl("a = " + inner)
            if parsed is not None and parsed.attrs:
                return parsed.attrs[0].expr
        if "${" in value or "%{" in value:
            return Unresolved("template", value, ())
        return Lit(value)
    if value is None or isinstance(value, bool):
        return Lit(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return Lit(value)
    if isinstance(value, float):
        return Lit(value)
    if isinstance(value, list):
        return Tuple(tuple(_json_expr(item) for item in value))
    if isinstance(value, dict):
        return Obj(tuple((str(key), _json_expr(val)) for key, val in value.items()))
    return Unresolved("template", "", ())


def load_hcl(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> Body | None:
    def run(raw: bytes) -> Body | None:
        result = parse_hcl(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
