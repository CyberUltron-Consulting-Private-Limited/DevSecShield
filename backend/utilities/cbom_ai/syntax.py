"""Real grammars for the AI fix validator (``fix.py``): the stored window and the model's rewrite are parsed with the
language's grammar - Python with ``ast``, JavaScript / TypeScript / Java / Kotlin / Go / C# with tree-sitter (the
grammar wheels are bundled in the backend image; nothing is downloaded at run time) - and turned into one small
syntax tree (``N``) that every rule in ``flow.py`` reads. Comments, regex literals, raw / interpolated strings and
templates are whatever the grammar says they are; interpolations are ordinary child expressions.

Fail closed: an unsupported language, a grammar that does not load, a parse error or an ERROR / MISSING node means
"cannot be checked", and the caller withholds the fix. A stored window that is a fragment (lines from the middle of
a function) is parsed inside a fixed wrapper (a function / class body, an enclosing block); the rewrite must parse
with a wrapper too.
"""
from __future__ import annotations

import ast
import functools
import importlib
import io
import re
import textwrap
import tokenize
from dataclasses import dataclass, field
from typing import Any

from backend.utilities.cbom_ai import node_types as NT

# grammar module and its language function, per language (TypeScript falls back to the TSX grammar)
_TS_GRAMMARS = {
    "javascript": [("tree_sitter_javascript", "language")],
    "typescript": [("tree_sitter_typescript", "language_typescript"), ("tree_sitter_typescript", "language_tsx")],
    "java": [("tree_sitter_java", "language")],
    "kotlin": [("tree_sitter_kotlin", "language")],
    "go": [("tree_sitter_go", "language")],
    "csharp": [("tree_sitter_c_sharp", "language")],
}
SUPPORTED = {"python", *_TS_GRAMMARS}

# fragment wrappers, tried in order (prefix, suffix); a window that parses as it is uses ("", "")
_WRAPS: dict[str, list[tuple[str, str]]] = {
    "javascript": [("", ""), ("function __w() {\n", "\n}"), ("class __W {\n", "\n}")],
    "java": [("", ""), ("class __W {\n", "\n}"), ("class __W { void __w() throws Exception {\n", "\n} }")],
    "kotlin": [("", ""), ("fun __w() {\n", "\n}"), ("class __W {\n", "\n}")],
    "go": [("", ""), ("package __w\n", ""), ("package __w\nfunc __w() {\n", "\n}")],
    "csharp": [("", ""), ("class __W {\n", "\n}"), ("class __W { void __W1() {\n", "\n} }")],
}
_WRAPS["typescript"] = _WRAPS["javascript"]
_PY_HEADS = ("", "if True:\n", "if True:\n    pass\n", "try:\n    pass\n", "def __w():\n")


@functools.cache
def _parsers(lang: str) -> tuple[Any, ...]:
    """The tree-sitter parsers for a language; empty when the grammar wheel is not installed (fail closed)."""
    out = []
    try:
        import tree_sitter as ts
    except Exception:  # pragma: no cover - the backend image always has it
        return ()
    for module, fn in _TS_GRAMMARS.get(lang, []):
        try:
            mod = importlib.import_module(module)
            out.append(ts.Parser(ts.Language(getattr(mod, fn)())))
        except Exception:  # pragma: no cover - a grammar that does not load is "not supported"
            continue
    return tuple(out)


def grammar_loaded(lang: str) -> bool:
    return lang == "python" or bool(_parsers(lang))


# --------------------------------------------------------------------------------------------- the common tree
@dataclass(eq=False)
class N:
    """One node of the common tree. ``kind``: name | member | index | call | new | str | num | bool | null | regex
    | unary | binary | assign | seq | obj | pair | kwarg | func | for | ctl | class | import | cast | forbidden |
    other. ``name``: identifier / member / operator / key / function name. ``value``: literal value (str / int /
    bool / None), the module of an import, the parameter names of a function, or a flag (``computed``,
    ``tagged``, ``ref``, ``infix``). ``ctx``: the enclosing functions / loops / branches (for "same place")."""
    kind: str
    text: str
    name: str = ""
    kids: list["N"] = field(default_factory=list)
    value: Any = None
    ctx: tuple[str, ...] = ()
    parent: "N | None" = None


_NOVALUE = object()


def walk(n: N):
    stack = [n]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.kids))


def _link(n: N) -> N:
    for x in walk(n):
        for k in x.kids:
            k.parent = x
    return n


@dataclass
class Parsed:
    lang: str
    root: N
    code: str           # the parsed text with comments blanked (same length, newlines kept)
    wrap: int           # index of the wrapper that parsed it (0 = as it is)
    fragment: bool


# ------------------------------------------------------------------------------------------------ Java escapes
_JAVA_UESC = re.compile(r"\\+u+([0-9a-fA-F]{4})")


def java_unicode_escapes(text: str) -> str:
    """``\\uXXXX`` decoded before lexing, as javac does (JLS 3.3): an escape whose backslash is preceded by an even
    number of backslashes. ``// \\u000a code`` is code, ``/* \\u002a/ code`` closes the comment."""
    def sub(m: re.Match[str]) -> str:
        run = m.group(0)
        slashes = len(run) - len(run.lstrip("\\"))
        if slashes % 2 == 0:  # \\u0041 is a backslash and "u0041"
            return run
        return "\\" * (slashes - 1) + chr(int(m.group(1), 16))
    return _JAVA_UESC.sub(sub, text)  # one pass, as javac: \u005cu0041 is "\u0041", not "A"


# ----------------------------------------------------------------------------------------------------- parsing
def parse(lang: str, text: str, prefer: int | None = None) -> Parsed | None:
    """The tree of ``text`` in ``lang`` (as it is, or inside the first wrapper that parses), or None."""
    if lang == "python":
        return _parse_python(text, prefer)
    parsers = _parsers(lang)
    if not parsers:
        return None
    if lang == "java":
        text = java_unicode_escapes(text)
    wraps = _WRAPS[lang]
    order = list(range(len(wraps)))
    if prefer is not None and prefer in order:
        order.remove(prefer)
        order.insert(0, prefer)
    balance = [(0, 0), (0, 1), (1, 0), (0, 2), (2, 0), (1, 1)]
    for i in order:
        pre, post = wraps[i]
        for opens, closes in balance:
            src = pre + "{\n" * opens + text + "\n}" * closes + post
            for parser in parsers:
                tree = parser.parse(src.encode("utf-8"))
                if tree.root_node.has_error:
                    continue
                built = _TsBuilder(lang, src).build(tree.root_node)
                return Parsed(lang, _link(built), _blank_ts_comments(tree.root_node, src), i * 10 + opens * 3 + closes,
                              bool(i or opens or closes))
    return None


def _blank_ts_comments(root: Any, src: str) -> str:
    data = bytearray(src.encode("utf-8"))
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in _COMMENTS:
            for b in range(node.start_byte, node.end_byte):
                if data[b] not in (10, 13):
                    data[b] = 32
            continue
        stack.extend(node.children)
    return data.decode("utf-8", "replace")


def _parse_python(text: str, prefer: int | None) -> Parsed | None:
    body = textwrap.dedent(text)
    lines = [ln for ln in body.split("\n")]
    last = next((ln for ln in reversed(lines) if ln.strip()), "")
    tail = "\n" + " " * (len(last) - len(last.lstrip()) + 4) + "pass"
    candidates = [(h, e) for h in _PY_HEADS for e in ("", tail)]
    order = list(range(len(candidates)))
    if prefer is not None and prefer in order:
        order.remove(prefer)
        order.insert(0, prefer)
    for i in order:
        head, end = candidates[i]
        src = head + (textwrap.indent(body, "    ") if head.startswith("def") else body) + end
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
        return Parsed("python", _link(_PyBuilder(src).build(tree)), _blank_py_comments(src), i, i != 0)
    return None


def python_tree(text: str, prefer: int | None = None) -> tuple[ast.Module, int] | None:
    """The ``ast`` module of a window (with the same wrappers as ``parse``) and the wrapper index."""
    body = textwrap.dedent(text)
    last = next((ln for ln in reversed(body.split("\n")) if ln.strip()), "")
    tail = "\n" + " " * (len(last) - len(last.lstrip()) + 4) + "pass"
    candidates = [(h, e) for h in _PY_HEADS for e in ("", tail)]
    order = list(range(len(candidates)))
    if prefer is not None and prefer in order:
        order.remove(prefer)
        order.insert(0, prefer)
    for i in order:
        head, end = candidates[i]
        src = head + (textwrap.indent(body, "    ") if head.startswith("def") else body) + end
        try:
            return ast.parse(src), i
        except (SyntaxError, ValueError):
            continue
    return None


def _blank_py_comments(src: str) -> str:
    lines = src.split("\n")
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                (row, col), (_r2, col2) = tok.start, tok.end
                ln = lines[row - 1]
                lines[row - 1] = ln[:col] + " " * (col2 - col) + ln[col2:]
    except (tokenize.TokenError, IndentationError, SyntaxError):  # pragma: no cover - ast parsed it
        pass
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------ Python ast -> N
_PY_CTL = (ast.If, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)


class _PyBuilder:
    def __init__(self, src: str) -> None:
        self.src = src
        self.stack: list[str] = []

    def text(self, node: ast.AST) -> str:
        seg = ast.get_source_segment(self.src, node) if hasattr(node, "lineno") else None
        if seg is None:
            try:
                return ast.unparse(node)
            except Exception:  # pragma: no cover
                return ""
        return seg

    def n(self, kind: str, node: ast.AST, name: str = "", kids: list[N | None] | None = None, value: Any = None) -> N:
        return N(kind, self.text(node), name, [k for k in (kids or []) if k is not None], value, tuple(self.stack))

    def many(self, nodes: list[Any]) -> list[N | None]:
        return [self.build(x) for x in nodes]

    def scoped(self, label: str, fn):
        self.stack.append(label)
        try:
            return fn()
        finally:
            self.stack.pop()

    def build(self, node: Any) -> N | None:  # noqa: C901 - one dispatch per node type
        if node is None:
            return None
        if isinstance(node, ast.Module):
            return N("other", self.src, "module", [k for k in self.many(node.body) if k])
        if isinstance(node, ast.Name):
            return self.n("name", node, node.id)
        if isinstance(node, ast.Attribute):
            return self.n("member", node, node.attr, [self.build(node.value)])
        if isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                return self.n("member", node, sl.value, [self.build(node.value)], "computed")
            return self.n("index", node, "", [self.build(node.value), self.build(sl)])
        if isinstance(node, ast.Call):
            args: list[N | None] = [self.build(node.func)] + self.many(node.args)
            args += [self.n("kwarg", k, k.arg or "**", [self.build(k.value)]) for k in node.keywords]
            return self.n("call", node, "", args)
        if isinstance(node, ast.Constant):
            v = node.value
            if v is None:
                return self.n("null", node, value=None)
            if isinstance(v, bool):
                return self.n("bool", node, value=v)
            if isinstance(v, (int, float, complex)):
                return self.n("num", node, value=v)
            if isinstance(v, (str, bytes)):
                return self.n("str", node, value=v.decode("latin-1") if isinstance(v, bytes) else v)
            return self.n("other", node)
        if isinstance(node, ast.JoinedStr):
            kids = [self.build(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
            return self.n("str", node, kids=kids, value=None if kids else "")
        if isinstance(node, ast.FormattedValue):
            return self.build(node.value)
        if isinstance(node, ast.UnaryOp):
            op = {ast.Not: "!", ast.USub: "-", ast.UAdd: "+", ast.Invert: "~"}[type(node.op)]
            return self.n("unary", node, op, [self.build(node.operand)])
        if isinstance(node, ast.BinOp):
            return self.n("binary", node, _PY_BINOPS.get(type(node.op), "?"), [self.build(node.left),
                                                                               self.build(node.right)])
        if isinstance(node, ast.BoolOp):
            return self.n("binary", node, "and" if isinstance(node.op, ast.And) else "or", self.many(node.values))
        if isinstance(node, ast.Compare):
            return self.n("other", node, "compare", [self.build(node.left)] + self.many(node.comparators))
        if isinstance(node, ast.Assign):
            target = node.targets[0] if len(node.targets) == 1 else ast.Tuple(elts=node.targets, ctx=ast.Store())
            return self.n("assign", node, "=", [self._target(target), self.build(node.value)])
        if isinstance(node, ast.AnnAssign):
            return self.n("assign", node, "=", [self._target(node.target), self.build(node.value)
                                                if node.value is not None else self.n("null", node)])
        if isinstance(node, ast.AugAssign):
            return self.n("assign", node, _PY_BINOPS.get(type(node.op), "?") + "=", [self._target(node.target),
                                                                                   self.build(node.value)])
        if isinstance(node, ast.NamedExpr):
            return self.n("assign", node, "=", [self._target(node.target), self.build(node.value)])
        if isinstance(node, (ast.For, ast.AsyncFor)):
            label = f"for:{self.text(node.target)} in {self.text(node.iter)}"
            body = self.scoped(label, lambda: self.many(node.body) + self.many(node.orelse))
            return self.n("for", node, "", [self._target(node.target), self.build(node.iter)] + body)
        if isinstance(node, ast.comprehension):
            return self.n("for", node.iter, "", [self._target(node.target), self.build(node.iter)]
                          + self.many(node.ifs))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.n("seq", node, "", self.many(node.generators) + [self.build(node.elt)])
        if isinstance(node, ast.DictComp):
            return self.n("seq", node, "", self.many(node.generators) + [self.build(node.key),
                                                                         self.build(node.value)])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name = getattr(node, "name", "")
            a = node.args
            params = [p.arg for p in a.posonlyargs + a.args + a.kwonlyargs] + \
                     [p.arg for p in (a.vararg, a.kwarg) if p is not None]
            defaults = self.many(a.defaults + [d for d in a.kw_defaults if d is not None])
            decos = [N("call", self.text(d), "", [self.build(d)], "decorator", tuple(self.stack))
                     if not isinstance(d, ast.Call) else self.build(d)
                     for d in getattr(node, "decorator_list", [])]
            body = node.body if isinstance(node.body, list) else [node.body]
            inner = self.scoped(f"def:{name}", lambda: self.many(body))
            return self.n("func", node, name, decos + defaults + inner, params)
        if isinstance(node, ast.ClassDef):
            decos = [N("call", self.text(d), "", [self.build(d)], "decorator", tuple(self.stack))
                     if not isinstance(d, ast.Call) else self.build(d) for d in node.decorator_list]
            inner = self.scoped(f"class:{node.name}", lambda: self.many(node.body))
            return self.n("class", node, node.name, decos + self.many(node.bases) + inner)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            items = [self.n("assign", it.context_expr, "=", [self._target(it.optional_vars), self.build(it.context_expr)])
                     if it.optional_vars is not None else self.build(it.context_expr) for it in node.items]
            head = ", ".join(self.text(it.context_expr) for it in node.items)
            return self.n("ctl", node, "with", items + self.scoped(f"with:{head}", lambda: self.many(node.body)))
        if isinstance(node, ast.If):
            head = self.text(node.test)
            body = self.scoped(f"if:{head}:then", lambda: self.many(node.body))
            orelse = self.scoped(f"if:{head}:else", lambda: self.many(node.orelse))
            return self.n("ctl", node, "if", [self.build(node.test)] + body + orelse)
        if isinstance(node, ast.While):
            head = self.text(node.test)
            body = self.scoped(f"while:{head}", lambda: self.many(node.body) + self.many(node.orelse))
            return self.n("ctl", node, "while", [self.build(node.test)] + body)
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            body = self.scoped("try", lambda: self.many(node.body))
            handlers = [self.scoped(f"except:{self.text(h.type) if h.type else ''}",
                                    lambda h=h: self.many(h.body)) for h in node.handlers]
            rest = self.scoped("try:else", lambda: self.many(node.orelse) + self.many(node.finalbody))
            return self.n("ctl", node, "try", body + [k for h in handlers for k in h] + rest)
        if isinstance(node, ast.Dict):
            pairs: list[N | None] = []
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    pairs.append(self.n("pair", v, k.value, [self.build(v)]))
                else:
                    pairs.append(self.n("other", v, "entry", [self.build(k), self.build(v)]))
            return self.n("obj", node, "dict", pairs)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self.n("seq", node, "", self.many(node.elts))
        if isinstance(node, ast.Delete):
            return self.n("other", node, "del", [self.n("unary", t, "delete", [self._target(t)]) for t in node.targets])
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            return self.n("import", node, "", [], mods)
        if isinstance(node, ast.Starred):
            return self.n("other", node, "starred", [self.build(node.value)])
        if isinstance(node, ast.IfExp):
            return self.n("other", node, "ternary", [self.build(node.test), self.build(node.body), self.build(node.orelse)])
        kids = [self.build(c) for c in ast.iter_child_nodes(node)
                if not isinstance(c, (ast.expr_context, ast.operator, ast.unaryop, ast.cmpop, ast.boolop))]
        return self.n("other", node, type(node).__name__.lower(), kids)

    def _target(self, node: ast.AST) -> N | None:
        if isinstance(node, (ast.Tuple, ast.List)):
            return self.n("seq", node, "", [self._target(e) for e in node.elts])
        if isinstance(node, ast.Starred):
            return self._target(node.value)
        return self.build(node)


_PY_BINOPS = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/", ast.FloorDiv: "//", ast.Mod: "%",
              ast.Pow: "**", ast.LShift: "<<", ast.RShift: ">>", ast.BitOr: "|", ast.BitXor: "^", ast.BitAnd: "&",
              ast.MatMult: "@"}


# ------------------------------------------------------------------------------------- tree-sitter -> N
_COMMENTS = {"comment", "line_comment", "block_comment", "multiline_comment", "html_comment"}
_NAMES = {"identifier", "property_identifier", "private_property_identifier",
          "shorthand_property_identifier_pattern", "field_identifier", "package_identifier", "this", "super",
          "this_expression", "super_expression", "base", "base_expression"}
# node types whose semantics the checks do not follow: a rewrite that adds one is withheld
_FORBIDDEN = {
    "javascript": {"with_statement", "jsx_element", "jsx_self_closing_element", "jsx_expression", "jsx_opening_element",
                   "jsx_closing_element", "jsx_attribute", "jsx_namespace_name", "jsx_text", "html_character_reference",
                   "html_comment", "debugger_statement"},
    # pattern matching that binds names (``instanceof T x`` alone is followed, see ``_instanceof_expression``)
    "java": {"template_expression", "string_interpolation", "record_pattern", "record_pattern_body",
             "record_pattern_component", "type_pattern", "pattern", "underscore_pattern"},
    "kotlin": set(),
    # a channel send: the value leaves through a channel the checks cannot follow
    "go": {"send_statement"},
    # binding patterns outside ``x is T y`` (see ``_is_pattern_expression``), undocumented reference operators
    "csharp": {"query_expression", "unsafe_statement", "fixed_statement", "pointer_type", "function_pointer_type",
               "extern_alias_directive", "preproc_if", "preproc_elif", "preproc_else", "preproc_define",
               "preproc_undef", "preproc_line", "preproc_error", "preproc_warning", "preproc_arg",
               "preproc_if_in_attribute_list", "shebang_directive", "global_statement", "from_clause", "group_clause",
               "join_clause", "join_into_clause", "let_clause", "order_by_clause", "select_clause", "where_clause",
               "declaration_pattern", "var_pattern", "recursive_pattern", "list_pattern", "positional_pattern_clause",
               "property_pattern_clause", "subpattern", "makeref_expression", "reftype_expression",
               "refvalue_expression", "calling_convention", "function_pointer_parameter"},
}
_FORBIDDEN["typescript"] = _FORBIDDEN["javascript"]
_CTL = {"if_statement", "while_statement", "do_statement", "for_statement", "try_statement", "switch_statement",
        "catch_clause", "try_with_resources_statement", "switch_expression", "if_expression", "when_expression",
        "do_while_statement", "try_expression", "catch_block", "expression_switch_statement",
        "type_switch_statement", "select_statement", "using_statement", "lock_statement", "go_statement",
        "defer_statement", "for_in_statement", "enhanced_for_statement", "foreach_statement", "for_each_statement",
        "finally_clause", "finally_block", "labeled_statement", "switch_block", "switch_section", "when_entry",
        "communication_case", "expression_case", "type_case", "default_case"}
_FUNCS = {"function_declaration", "function_expression", "arrow_function", "generator_function",
          "generator_function_declaration", "method_definition", "method_declaration", "constructor_declaration",
          "lambda_expression", "func_literal", "local_function_statement", "anonymous_method_expression",
          "lambda_literal", "anonymous_function", "compact_constructor_declaration", "secondary_constructor",
          "anonymous_initializer", "getter", "setter", "accessor_declaration", "operator_declaration",
          "conversion_operator_declaration", "destructor_declaration", "indexer_declaration",
          "property_declaration_cs"}
_CLASSES = {"class_declaration", "class", "class_body", "object_literal", "object_declaration", "record_declaration",
            "struct_declaration", "enum_declaration", "companion_object", "class_expression",
            "anonymous_object_creation_expression", "abstract_class_declaration", "interface_declaration",
            "annotation_type_declaration"}
_STRINGS = {"string", "string_literal", "interpreted_string_literal", "raw_string_literal", "verbatim_string_literal",
            "text_block", "character_literal", "rune_literal", "multiline_string_literal", "template_string",
            "interpolated_string_expression"}
_NUMS = {"number", "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
         "decimal_floating_point_literal", "hex_floating_point_literal", "int_literal", "float_literal",
         "imaginary_literal", "integer_literal", "real_literal", "number_literal", "bin_literal", "hex_literal",
         "long_literal", "unsigned_literal"}
# node types build() decides inline (literals, wrappers)
_LITERAL_TYPES = {"true", "false", "boolean_literal", "null", "undefined", "null_literal", "nil", "regex",
                  "parenthesized_expression", "expression_statement", "literal_element", "value_argument_list",
                  "as_expression", "non_null_expression", "satisfies_expression", "argument"}
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f", "v": "\v", "'": "'", '"': '"',
            "\\": "\\", "`": "`", "$": "$", "/": "/"}


def _num(text: str) -> int | float | None:
    t = text.replace("_", "").rstrip("nNlLuU")
    t = t.rstrip("fFdDmM") if not t.lower().startswith("0x") else t
    try:
        if re.fullmatch(r"0[0-7]+", t):  # Go / C-style octal
            return int(t, 8)
        return int(t, 0)
    except ValueError:
        try:
            return float(t)
        except ValueError:
            return None


def _unescape(raw: str) -> str | None:
    out, i = [], 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1:i + 2]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        m = re.match(r"x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|U([0-9a-fA-F]{8})", raw[i + 1:])
        if m:
            out.append(chr(int(next(g for g in m.groups() if g), 16)))
            i += 1 + len(m.group(0))
            continue
        return None  # an escape the evaluator does not know: the value is unknown
    return "".join(out)


class _TsBuilder:
    def __init__(self, lang: str, src: str) -> None:
        self.full = lang
        self.lang = "javascript" if lang == "typescript" else lang
        self.src = src.encode("utf-8")
        self.stack: list[str] = []
        self.forbidden = _FORBIDDEN.get(lang, set())
        self.known = known_types(lang)
        self.drop = NT.TYPE_ONLY.get(lang, frozenset())

    def text(self, node: Any) -> str:
        return self.src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def ident(self, node: Any) -> str:
        """An identifier as the language reads it (C# ``@k`` and Kotlin k in backticks are ``k``)."""
        return norm_ident(self.lang, self.text(node))

    def n(self, kind: str, node: Any, name: str = "", kids: list[N | None] | None = None, value: Any = None) -> N:
        return N(kind, self.text(node), name, [k for k in (kids or []) if k is not None], value, tuple(self.stack))

    def f(self, node: Any, name: str) -> Any:
        return node.child_by_field_name(name)

    def named(self, node: Any) -> list[Any]:
        return [c for c in node.named_children if c.type not in _COMMENTS]

    def many(self, nodes: list[Any]) -> list[N | None]:
        return [self.build(c) for c in nodes]

    def kids_of(self, node: Any) -> list[N | None]:
        return self.many(self.named(node))

    def op(self, node: Any) -> str:
        o = self.f(node, "operator")
        if o is not None:
            return self.text(o)
        anon = [c for c in node.children if not c.is_named]
        return self.text(anon[0]) if anon else "?"

    # ---------------------------------------------------------------------------------------------- dispatch
    def build(self, node: Any) -> N | None:  # noqa: C901 - one dispatch per node type
        if node is None:
            return None
        t = node.type
        if t in _COMMENTS:
            return None
        if t not in self.known:  # coverage guard: a node type nobody decided about is not followed, so not allowed
            return self.n("forbidden", node, f"unchecked node type {t}", self.kids_of(node))
        if t in self.forbidden or t.startswith("jsx_") and self.lang == "javascript":
            return self.n("forbidden", node, t, self.kids_of(node))
        if t in _NAMES:
            txt = self.text(node)
            return self.n("name", node, "this" if txt in ("this", "base") else norm_ident(self.lang, txt))
        if t == "identifier":
            return self._ident(node)
        if t in ("simple_identifier", "type_identifier") and self.lang == "kotlin":
            return self._ident(node)
        if t in self.drop:  # types, annotations, modifiers: no run-time code (C# array sizes are kept, below)
            return self._type_exprs(node) if t in ("array_type", "array_rank_specifier") and self.lang == "csharp" \
                else None
        if t in _STRINGS:
            return self._string(node)
        if t in _NUMS:
            v = _num(self.text(node))
            return self.n("num", node, value=v) if v is not None else self.n("other", node)
        if t in ("true", "false"):
            return self.n("bool", node, value=t == "true")
        if t == "boolean_literal":
            return self.n("bool", node, value=self.text(node) == "true")
        if t in ("null", "undefined", "null_literal", "nil"):
            return self.n("null", node)
        if t == "regex":
            return self.n("regex", node)
        if t in ("parenthesized_expression", "expression_statement", "literal_element", "value_argument_list",
                 "as_expression", "non_null_expression", "satisfies_expression", "argument"):
            kids = self.kids_of(node)
            if t == "argument":
                name = self.f(node, "name")
                kid = [k for k in self.many([c for c in self.named(node) if c != name]) if k is not None]
                if name is not None:
                    return self.n("kwarg", node, self.text(name), kid)
                return kid[-1] if len(kid) == 1 else self.n("other", node, t, kid)
            if t in ("as_expression", "non_null_expression", "satisfies_expression"):
                return self.n("cast", node, "", kids[:1])
            return kids[0] if len(kids) == 1 and kids[0] is not None else self.n("other", node, t, kids)
        handler = getattr(self, "_" + t, None)
        if handler is not None:
            return handler(node)
        if t in _FUNCS:
            return self._func(node)
        if t in _CLASSES:
            return self._class(node)
        if t in _CTL:
            return self._ctl(node)
        return self.n("other", node, t, self.kids_of(node))

    def _ident(self, node: Any) -> N:
        txt = self.text(node)
        if self.lang == "kotlin" and txt in ("true", "false"):
            return self.n("bool", node, value=txt == "true")
        if self.lang == "kotlin" and txt == "null":
            return self.n("null", node)
        if self.lang == "go" and txt in ("true", "false"):
            return self.n("bool", node, value=txt == "true")
        if self.lang == "go" and txt == "nil":
            return self.n("null", node)
        return self.n("name", node, norm_ident(self.lang, txt))

    def _type_exprs(self, node: Any) -> N | None:
        """The expressions inside a type (C# ``new byte[k.Length]``, ``stackalloc byte[n]``): built, the rest
        dropped."""
        out: list[N | None] = []
        stack = list(reversed(self.named(node)))
        while stack:
            cur = stack.pop()
            if cur.type in self.drop or cur.type in NT.TYPE_LEAVES:
                stack.extend(reversed(self.named(cur)))
            else:
                out.append(self.build(cur))
        kids = [k for k in out if k is not None]
        return self.n("other", node, "type", kids) if kids else None

    # ----------------------------------------------------------------------------------------------- strings
    def _string(self, node: Any) -> N:
        parts: list[str] = []
        kids: list[N | None] = []
        known = True
        t = node.type
        if t in ("verbatim_string_literal",):
            raw = self.text(node)
            return self.n("str", node, value=raw[2:-1].replace('""', '"'))
        if t == "raw_string_literal" and self.lang == "go":
            return self.n("str", node, value=self.text(node)[1:-1])
        for ch in node.children:
            ct = ch.type
            if ct in ("template_substitution", "interpolation", "string_interpolation"):
                inner = [c for c in self.named(ch) if c.type not in ("interpolation_brace", "interpolation_alignment_clause",
                                                                       "interpolation_format_clause")]
                kids += self.many(inner)
                known = False
            elif ct in ("string_fragment", "string_content", "string_literal_content", "raw_string_content",
                        "interpreted_string_literal_content", "multiline_string_fragment", "character_literal_content"):
                parts.append(self.text(ch))
            elif ct == "escape_sequence":
                esc = _unescape(self.text(ch))
                if esc is None:
                    known = False
                else:
                    parts.append(esc)
        if self.lang == "kotlin":  # "$name" templates: the grammar keeps them as text
            for name in _kotlin_dollar_names(self.text(node)):
                kids.append(N("name", name, name, [], None, tuple(self.stack)))
                known = False
        if t in ("character_literal", "rune_literal") and not parts:
            raw = self.text(node)[1:-1]
            esc = _unescape(raw)
            parts.append(esc if esc is not None else raw)
        if node.child_count == 0 and t in ("text_block", "string", "string_literal"):
            raw = self.text(node)
            q = 3 if raw.startswith('"""') else 1
            parts.append(raw[q:-q])
        return self.n("str", node, kids=kids, value="".join(parts) if known else None)

    # ------------------------------------------------------------------------------------------ expressions
    def _member_expression(self, node: Any) -> N:
        prop = self.f(node, "property")
        return self.n("member", node, self.ident(prop) if prop is not None else "?", [self.build(self.f(node, "object"))])

    def _subscript_expression(self, node: Any) -> N:
        idx = self.f(node, "index")
        obj = self.build(self.f(node, "object"))
        if idx is not None and idx.type == "string" and all(c.type != "escape_sequence" for c in idx.children):
            key = "".join(self.text(c) for c in idx.children if c.type == "string_fragment")
            return self.n("member", node, key, [obj], "computed")
        if idx is not None and idx.type == "number":
            return self.n("index", node, "", [obj, self.build(idx)])
        return self.n("index", node, "", [obj, self.build(idx)], "computed")

    def _call_expression(self, node: Any) -> N:
        if self.lang == "kotlin":
            return self._kt_call(node)
        fn, args = self.f(node, "function"), self.f(node, "arguments")
        if fn is not None and fn.type == "import":  # import('x')
            return self.n("call", node, "", [self.n("name", fn, "import")] +
                          (self.many(self.named(args)) if args is not None else []))
        if self.lang == "go" and fn is not None and fn.type in ("slice_type", "array_type", "map_type", "pointer_type",
                                                                "qualified_type", "generic_type", "channel_type",
                                                                "function_type", "parenthesized_type"):
            base = fn.child_by_field_name("element") or fn
            callee = N("name", self.text(fn), self.text(base).split(".")[-1].lstrip("*[]"), [], "conversion",
                       tuple(self.stack))
        else:
            callee = self.build(fn)
        if args is not None and args.type == "template_string":
            return self.n("call", node, "", [callee, self.build(args)], "tagged")
        arg_nodes = self.named(args) if args is not None else []
        return self.n("call", node, "", [callee] + self.many(arg_nodes))

    def _new_expression(self, node: Any) -> N:
        args = self.f(node, "arguments")
        return self.n("new", node, "", [self._type_ref(self.f(node, "constructor"))] +
                      (self.many(self.named(args)) if args is not None else []))

    def _decorator(self, node: Any) -> N:
        inner = self.named(node)
        built = self.build(inner[0]) if inner else None
        if built is not None and built.kind == "call":
            return built
        return self.n("call", node, "", [built], "decorator")

    def _unary_expression(self, node: Any) -> N:
        op = self.op(node)
        arg = self.f(node, "argument") or self.f(node, "operand")
        if arg is None:
            named = self.named(node)
            arg = named[0] if named else None
        if op in ("++", "--"):
            built = self.build(arg)
            return self.n("assign", node, op, [built, built])
        return self.n("unary", node, op, [self.build(arg)])

    _prefix_unary_expression = _unary_expression
    _postfix_unary_expression = _unary_expression
    _prefix_expression = _unary_expression
    _postfix_expression = _unary_expression

    def _update_expression(self, node: Any) -> N:
        arg = self.f(node, "argument") or (self.named(node) or [None])[0]
        built = self.build(arg)
        return self.n("assign", node, "++", [built, built])

    _inc_statement = _update_expression
    _dec_statement = _update_expression

    def _binary_expression(self, node: Any) -> N:
        return self.n("binary", node, self.op(node), [self.build(self.f(node, "left")), self.build(self.f(node, "right"))])

    def _assignment_expression(self, node: Any) -> N:
        return self.n("assign", node, self.op(node), [self.build(self.f(node, "left")),
                                                      self.build(self.f(node, "right"))])

    _augmented_assignment_expression = _assignment_expression
    _assignment = _assignment_expression

    def _variable_declarator(self, node: Any) -> N:
        name = self.f(node, "name")
        value = self.f(node, "value")
        if value is None and self.lang == "csharp":
            rest = [c for c in self.named(node) if c != name and c.type not in ("bracketed_argument_list",)]
            value = rest[-1] if rest else None
        if name is None:
            named = self.named(node)
            name = named[0] if named else None
        target = self.build(name) if name is not None and name.type in _NAMES | {"identifier"} else \
            self.n("seq", name, "", self.kids_of(name)) if name is not None else None
        return self.n("assign", node, "=", [target, self.build(value) if value is not None else N("null", "", "")])

    def _object(self, node: Any) -> N:
        return self.n("obj", node, "object", self.kids_of(node))

    def _pair(self, node: Any) -> N:
        key = self.f(node, "key")
        ktxt = self.text(key) if key is not None else ""
        if key is not None and key.type == "string":
            ktxt = "".join(self.text(c) for c in key.children if c.type == "string_fragment")
        kids: list[N | None] = [self.build(self.f(node, "value"))]
        if key is not None and key.type == "computed_property_name":
            kids.append(self.build(key))
            ktxt = "[" + ktxt + "]"
        return self.n("pair", node, ktxt, kids)

    def _shorthand_property_identifier(self, node: Any) -> N:
        return self.n("pair", node, self.text(node), [self.n("name", node, self.text(node))])

    def _array(self, node: Any) -> N:
        return self.n("seq", node, "", self.kids_of(node))

    _array_initializer = _array
    _expression_list = _array
    _tuple_expression = _array
    _initializer_expression = _array
    _collection_literal = _array

    def _import_statement(self, node: Any) -> N:
        src = self.f(node, "source")
        mod = "".join(self.text(c) for c in src.children if c.type == "string_fragment") if src is not None else ""
        binds: list[tuple[str, str]] = []
        clause = next((c for c in node.named_children if c.type == "import_clause"), None)
        if clause is not None:
            for c in clause.named_children:
                if c.type == "identifier":
                    binds.append((self.text(c), "default"))
                elif c.type == "namespace_import":
                    ids = [x for x in c.named_children if x.type == "identifier"]
                    if ids:
                        binds.append((self.text(ids[-1]), "*"))
                elif c.type == "named_imports":
                    for spec in c.named_children:
                        if spec.type == "import_specifier":
                            nm, al = self.f(spec, "name"), self.f(spec, "alias")
                            binds.append((self.text(al or nm), self.text(nm)))
        return self.n("import", node, "", [], [mod, binds])

    # ------------------------------------------------------------------------------------------------ Java
    def _method_invocation(self, node: Any) -> N:
        obj, name, args = self.f(node, "object"), self.f(node, "name"), self.f(node, "arguments")
        callee = self.n("member", node, self.ident(name), [self.build(obj)]) if obj is not None else \
            self.n("name", name, self.ident(name))
        return self.n("call", node, "", [callee] + (self.many(self.named(args)) if args is not None else []))

    def _field_access(self, node: Any) -> N:
        return self.n("member", node, self.ident(self.f(node, "field")), [self.build(self.f(node, "object"))])

    def _instanceof_expression(self, node: Any) -> N:
        """``o instanceof byte[] b``: ``b`` holds ``o``."""
        left, name = self.f(node, "left"), self.f(node, "name")
        if name is None:
            return self.n("other", node, "instanceof", self.kids_of(node))
        return self.n("assign", node, "instanceof", [self.n("name", name, self.ident(name)), self.build(left)])

    def _resource(self, node: Any) -> N:
        """``try (var x = open(k))``: ``x`` holds the value."""
        name, value = self.f(node, "name"), self.f(node, "value")
        if name is None or value is None:
            return self.n("other", node, "resource", self.kids_of(node))
        return self.n("assign", node, "=", [self.n("name", name, self.ident(name)), self.build(value)])

    def _object_creation_expression(self, node: Any) -> N:
        typ, args = self.f(node, "type"), self.f(node, "arguments")
        kids: list[N | None] = [self._type_ref(typ)]
        kids += self.many(self.named(args)) if args is not None else []
        for c in self.named(node):
            if c.type in ("class_body", "initializer_expression"):
                kids.append(self._initializer(c) if c.type == "initializer_expression" else self._class(c))
        return self.n("new", node, "", kids)

    def _implicit_object_creation_expression(self, node: Any) -> N:
        args = self.f(node, "arguments") or next((c for c in self.named(node) if c.type == "argument_list"), None)
        return self.n("new", node, "", [N("name", "new", "<implicit>", [], None, tuple(self.stack))] +
                      (self.many(self.named(args)) if args is not None else []))

    def _initializer(self, node: Any) -> N:
        out: list[N | None] = []
        for c in self.named(node):
            if c.type == "assignment_expression":
                left = self.f(c, "left")
                out.append(self.n("pair", c, self.text(left), [self.build(self.f(c, "right"))]))
            else:
                out.append(self.build(c))
        return self.n("obj", node, "initializer", out)

    def _type_ref(self, typ: Any) -> N | None:
        """A constructor's type as a name / member chain (``java.io.File`` -> member(member(java, io), File))."""
        if typ is None:
            return None
        txt = re.sub(r"<.*>", "", self.text(typ)).strip()
        txt = re.sub(r"\s+", "", txt)
        parts = [p for p in re.split(r"\.|::", txt) if p]
        if not parts:
            return None
        cur = N("name", parts[0], parts[0], [], None, tuple(self.stack))
        for p in parts[1:]:
            cur = N("member", cur.text + "." + p, p, [cur], None, tuple(self.stack))
        return cur

    def _array_access(self, node: Any) -> N:
        return self.n("index", node, "", [self.build(self.f(node, "array")), self.build(self.f(node, "index"))])

    def _method_reference(self, node: Any) -> N:
        named = self.named(node)
        left = self.build(named[0]) if named else None
        right = self.text(named[-1]) if len(named) > 1 else "new"
        return self.n("call", node, "", [self.n("member", node, right, [left])], "ref")

    def _explicit_constructor_invocation(self, node: Any) -> N:
        args = self.f(node, "arguments")
        ctor = self.f(node, "constructor")
        return self.n("call", node, "", [self.n("name", node, self.text(ctor) if ctor is not None else "this")] +
                      (self.many(self.named(args)) if args is not None else []))

    def _cast_expression(self, node: Any) -> N:
        value = self.f(node, "value")
        typ = self.f(node, "type")
        return self.n("cast", node, self.text(typ) if typ is not None else "", [self.build(value)])

    def _import_declaration(self, node: Any) -> N:
        if self.lang == "go":
            return self.n("other", node, "imports", self.kids_of(node))
        return self.n("import", node, "", [], [self.text(node), []])

    _using_directive = _import_declaration

    def _import(self, node: Any) -> N:  # Kotlin
        return self.n("import", node, "", [], [self.text(node), []])

    _import_header = _import

    # -------------------------------------------------------------------------------------------------- Go
    def _selector_expression(self, node: Any) -> N:
        return self.n("member", node, self.text(self.f(node, "field")), [self.build(self.f(node, "operand"))])

    def _composite_literal(self, node: Any) -> N:
        typ, body = self.f(node, "type"), self.f(node, "body")
        ref = self._type_ref(typ) if typ is not None and typ.type in ("qualified_type", "type_identifier",
                                                                      "generic_type") else None
        if ref is not None:
            ref.value = "typeref"
        kids: list[N | None] = [ref]
        kids += self._lit_values(body) if body is not None else []
        return self.n("obj", node, self.text(typ) if typ is not None else "", kids)

    def _lit_values(self, body: Any) -> list[N | None]:
        out: list[N | None] = []
        for c in self.named(body):
            if c.type == "keyed_element":
                key, val = self.f(c, "key"), self.f(c, "value")
                if key is None:
                    named = self.named(c)
                    key, val = (named[0], named[-1]) if len(named) >= 2 else (None, None)
                ktxt = self.text(key).strip() if key is not None else ""
                out.append(self.n("pair", c, ktxt, [self.build(val)]))
            elif c.type == "literal_value":
                out.append(self.n("seq", c, "", self._lit_values(c)))
            else:
                out.append(self.build(c))
        return out

    def _literal_value(self, node: Any) -> N:
        return self.n("seq", node, "", self._lit_values(node))

    def _short_var_declaration(self, node: Any) -> N:
        return self.n("assign", node, ":=", [self.build(self.f(node, "left")), self.build(self.f(node, "right"))])

    def _assignment_statement(self, node: Any) -> N:
        return self.n("assign", node, self.op(node), [self.build(self.f(node, "left")), self.build(self.f(node, "right"))])

    def _var_spec(self, node: Any) -> N:
        names = [c for c in node.children_by_field_name("name")]
        value = self.f(node, "value")
        target = self.n("seq", node, "", self.many(names)) if len(names) != 1 else self.build(names[0])
        return self.n("assign", node, "=", [target, self.build(value) if value is not None else N("null", "", "")])

    _const_spec = _var_spec

    def _range_clause(self, node: Any) -> N:
        return self.n("for", node, "", [self.build(self.f(node, "left")), self.build(self.f(node, "right"))])

    def _index_expression(self, node: Any) -> N:
        if self.lang == "kotlin":
            named = self.named(node)
            return self.n("index", node, "", self.many(named))
        return self.n("index", node, "", [self.build(self.f(node, "operand")), self.build(self.f(node, "index"))])

    def _import_spec(self, node: Any) -> N:
        path, name = self.f(node, "path"), self.f(node, "name")
        mod = self.text(path).strip('"`') if path is not None else ""
        alias = self.text(name) if name is not None else ""
        return self.n("import", node, "", [], [mod, [(alias, "*")] if alias else []])

    def _type_assertion_expression(self, node: Any) -> N:
        return self.n("cast", node, "", [self.build(self.f(node, "operand"))])

    # ---------------------------------------------------------------------------------------------------- C#
    def _invocation_expression(self, node: Any) -> N:
        fn, args = self.f(node, "function"), self.f(node, "arguments")
        callee = self.build(fn)
        if callee is not None and callee.kind == "other" and fn is not None and fn.type == "generic_name":
            ident = next((c for c in fn.named_children if c.type == "identifier"), None)
            callee = self.n("name", fn, self.text(ident) if ident is not None else self.text(fn))
        return self.n("call", node, "", [callee] + (self.many(self.named(args)) if args is not None else []))

    def _member_access_expression(self, node: Any) -> N:
        expr, name = self.f(node, "expression"), self.f(node, "name")
        nm = self.ident(name) if name is not None else "?"
        if name is not None and name.type == "generic_name":
            ident = next((c for c in name.named_children if c.type == "identifier"), None)
            nm = self.ident(ident) if ident is not None else nm
        if expr is None:
            first = node.children[0] if node.children else None
            obj = self.n("name", first, "this") if first is not None and self.text(first) in ("this", "base") else None
        else:
            obj = self.build(expr)
        return self.n("member", node, nm, [obj])

    def _conditional_access_expression(self, node: Any) -> N:
        cond = self.f(node, "condition")
        binding = next((c for c in self.named(node) if c.type in ("member_binding_expression", "element_binding_expression")),
                       None)
        name = self.f(binding, "name") if binding is not None else None
        if binding is not None and binding.type == "element_binding_expression":
            return self.n("index", node, "", [self.build(cond)] + self.kids_of(binding))
        return self.n("member", node, self.ident(name) if name is not None else "?", [self.build(cond)])

    def _element_access_expression(self, node: Any) -> N:
        return self.n("index", node, "", [self.build(self.f(node, "expression"))] +
                      self.kids_of(self.f(node, "subscript") or node)[1:])

    def _generic_name(self, node: Any) -> N:
        ident = next((c for c in node.named_children if c.type == "identifier"), None)
        return self.n("name", node, self.ident(ident) if ident is not None else self.text(node))

    def _declaration_expression(self, node: Any) -> N:
        name = self.f(node, "name")
        if name is not None:
            return self.build(name)
        ids = [c for c in walk_ts(node) if c.type == "identifier" and c.parent is not None and
               c.parent.type in ("parenthesized_variable_designation", "declaration_expression")]
        return self.n("seq", node, "", [self.n("name", i, self.ident(i)) for i in ids])

    def _is_pattern_expression(self, node: Any) -> N:
        """``o is byte[] b`` / ``o is { } b`` / ``o is var (x, y)``: the names the pattern declares hold ``o``
        (patterns elsewhere - switch arms - are not followed, see ``_FORBIDDEN``)."""
        expr, pattern = self.f(node, "expression"), self.f(node, "pattern")
        ids = []
        for c in walk_ts(pattern) if pattern is not None else []:
            if c.type != "identifier" or c.parent is None:
                continue
            par = c.parent
            fname = next((par.field_name_for_child(i) for i, ch in enumerate(par.children) if ch == c), None)
            if par.type in ("var_pattern", "parenthesized_variable_designation") or (
                    fname in ("name", "designation") and par.type in ("declaration_pattern", "recursive_pattern",
                                                                       "list_pattern")):
                ids.append(c)
        if not ids:
            return self.n("other", node, "is", [self.build(expr)])
        target = self.n("name", ids[0], self.ident(ids[0])) if len(ids) == 1 else \
            self.n("seq", pattern, "", [self.n("name", i, self.ident(i)) for i in ids])
        return self.n("assign", node, "is", [target, self.build(expr)])

    def _property_declaration_cs(self, node: Any) -> N:
        """C# ``static byte[] P { get; } = k;`` / ``byte[] P => k;``: ``P`` holds the value; accessors are code."""
        name, value = self.f(node, "name"), self.f(node, "value")
        kids: list[N | None] = []
        if name is not None and value is not None:
            built = self.build(value)
            kids.append(self.n("assign", node, "=", [self.n("name", name, self.ident(name)), built]))
        kids += [self.build(c) for c in self.named(node) if c not in (name, value)]
        return self.n("other", node, "property", kids)

    def _arrow_expression_clause(self, node: Any) -> N:  # C# ``=> expr``: the value of a member / local function
        return self.n("other", node, "arrow_return", self.kids_of(node))

    def _function_body(self, node: Any) -> N:  # Kotlin ``fun f() = expr``: an expression body is a return
        kids = self.kids_of(node)
        if self.text(node).lstrip().startswith("="):
            return self.n("other", node, "return_expression", kids)
        return kids[0] if len(kids) == 1 and kids[0] is not None else self.n("other", node, "function_body", kids)

    def _when_subject(self, node: Any) -> N:  # Kotlin ``when (val y = k)``: ``y`` holds ``k``
        named = self.named(node)
        decl = next((c for c in named if c.type in ("variable_declaration", "multi_variable_declaration")), None)
        rest = [c for c in named if c != decl]
        if decl is None or not rest:
            return self.n("other", node, "when_subject", self.kids_of(node))
        return self.n("assign", node, "=", [self._kt_targets(decl), self.build(rest[-1])])

    def _field_definition(self, node: Any) -> N:
        """JS / TS class fields ``static k = v``: the field (read as ``this.k`` / ``Z.k``) holds the value."""
        prop = self.f(node, "property") or self.f(node, "name")
        value = self.f(node, "value")
        decos = [self.build(c) for c in self.named(node) if c.type == "decorator"]
        if prop is None or value is None:
            return self.n("other", node, "field", [d for d in decos] + [self.build(value)] if value is not None
                          else decos)
        key = [self.build(prop)] if prop.type == "computed_property_name" else []
        return self.n("assign", node, "=", [self.n("name", prop, self.ident(prop)), self.build(value)] + decos + key)

    _public_field_definition = _field_definition

    def _foreach_statement(self, node: Any) -> N:
        left, right, body = self.f(node, "left"), self.f(node, "right"), self.f(node, "body")
        label = f"foreach:{self.text(left) if left is not None else ''} in {self.text(right) if right is not None else ''}"
        built_body = self.scoped(label, lambda: [self.build(body)])
        return self.n("for", node, "", [self.build(left), self.build(right)] + built_body)

    def _typeof_expression(self, node: Any) -> N:
        return self.n("other", node, "typeof")

    _sizeof_expression = _typeof_expression
    _default_expression = _typeof_expression

    # ------------------------------------------------------------------------------------------------ Kotlin
    def _constructor_invocation(self, node: Any) -> N:  # Kotlin supertype call: class A : B(x)
        named = self.named(node)
        typ = next((c for c in named if c.type == "user_type"), None)
        args = next((c for c in named if c.type == "value_arguments"), None)
        return self.n("new", node, "", [self._type_ref(typ)] +
                      ([self._kt_value_argument(v) for v in self.named(args)] if args is not None else []))

    def _kt_call(self, node: Any) -> N:
        named = self.named(node)
        callee = self.build(named[0]) if named else None
        args: list[N | None] = []
        for c in named[1:]:
            if c.type == "value_arguments":
                for va in self.named(c):
                    args.append(self._kt_value_argument(va))
            elif c.type == "annotated_lambda":
                args += self.kids_of(c)
            elif c.type == "call_suffix":
                for cc in self.named(c):
                    if cc.type == "value_arguments":
                        args += [self._kt_value_argument(va) for va in self.named(cc)]
                    elif cc.type == "annotated_lambda":
                        args += self.kids_of(cc)
            else:
                args.append(self.build(c))
        return self.n("call", node, "", [callee] + args)

    def _kt_value_argument(self, node: Any) -> N | None:
        if node.type != "value_argument":
            return self.build(node)
        named = self.named(node)
        has_eq = any(not c.is_named and self.text(c) == "=" for c in node.children)
        if has_eq and len(named) >= 2:
            return self.n("kwarg", node, self.text(named[0]), [self.build(named[-1])])
        kids = self.many(named)
        return kids[-1] if kids else None

    def _navigation_expression(self, node: Any) -> N:
        named = self.named(node)
        if len(named) >= 2:
            last = named[-1]
            if last.type == "navigation_suffix":
                inner = self.named(last)
                last = inner[-1] if inner else last
            return self.n("member", node, self.text(last), [self.build(named[0])])
        return self.n("other", node, "navigation", self.many(named))

    def _infix_expression(self, node: Any) -> N:
        named = self.named(node)
        if len(named) == 3:
            left, op, right = named
            return self.n("call", node, "", [self.n("member", node, self.text(op), [self.build(left)]),
                                             self.build(right)], "infix")
        return self.n("other", node, "infix", self.many(named))

    def _callable_reference(self, node: Any) -> N:
        named = self.named(node)
        left = self.build(named[0]) if len(named) > 1 else None
        right = self.text(named[-1]) if named else "?"
        callee = self.n("member", node, right, [left]) if left is not None else self.n("name", node, right)
        return self.n("call", node, "", [callee], "ref")

    def _property_declaration(self, node: Any) -> N:
        if self.lang == "csharp":
            return self._property_declaration_cs(node)
        named = self.named(node)
        decl = next((c for c in named if c.type in ("variable_declaration", "multi_variable_declaration")), None)
        rest = [c for c in named if c != decl and c.type not in self.drop and c.type != "modifiers"]
        targets = self._kt_targets(decl)
        value = rest[-1] if rest else None
        return self.n("assign", node, "=", [targets, self.build(value) if value is not None else N("null", "", "")])

    def _kt_targets(self, decl: Any) -> N | None:
        if decl is None:
            return None
        ids = [c for c in decl.named_children if c.type in ("identifier", "simple_identifier")]
        if decl.type == "multi_variable_declaration":
            ids = [i for v in decl.named_children if v.type == "variable_declaration"
                   for i in v.named_children if i.type in ("identifier", "simple_identifier")]
            return self.n("seq", decl, "", [self.n("name", i, self.ident(i)) for i in ids])
        return self.n("name", ids[0], self.ident(ids[0])) if ids else None

    def _for_statement(self, node: Any) -> N:
        if self.lang != "kotlin":
            if self.lang == "go":
                rng = next((c for c in self.named(node) if c.type == "range_clause"), None)
                if rng is not None:
                    head = self.text(rng)
                    body = self.scoped(f"for:{head}", lambda: [self.build(c) for c in self.named(node) if c != rng])
                    rc = self._range_clause(rng)
                    return self.n("for", node, "", rc.kids + body)
            return self._ctl(node)
        named = self.named(node)
        decl = next((c for c in named if c.type in ("variable_declaration", "multi_variable_declaration")), None)
        rest = [c for c in named if c != decl]
        it = rest[0] if rest else None
        label = f"for:{self.text(decl) if decl is not None else ''} in {self.text(it) if it is not None else ''}"
        body = self.scoped(label, lambda: self.many(rest[1:]))
        return self.n("for", node, "", [self._kt_targets(decl), self.build(it)] + body)

    def _for_in_statement(self, node: Any) -> N:
        left, right, body = self.f(node, "left"), self.f(node, "right"), self.f(node, "body")
        label = f"for:{self.text(left) if left is not None else ''} in {self.text(right) if right is not None else ''}"
        built = self.scoped(label, lambda: [self.build(body)])
        return self.n("for", node, "", [self.build(left), self.build(right)] + built)

    def _enhanced_for_statement(self, node: Any) -> N:
        name, value, body = self.f(node, "name"), self.f(node, "value"), self.f(node, "body")
        label = f"for:{self.text(name) if name is not None else ''} : {self.text(value) if value is not None else ''}"
        built = self.scoped(label, lambda: [self.build(body)])
        return self.n("for", node, "", [self.build(name), self.build(value)] + built)

    # ----------------------------------------------------------------------------------- functions / blocks
    def scoped(self, label: str, fn):
        self.stack.append(label)
        try:
            return fn()
        finally:
            self.stack.pop()

    def _func(self, node: Any) -> N:
        name_node = self.f(node, "name")
        name = self.ident(name_node) if name_node is not None else ""
        head = self.src[node.start_byte:name_node.start_byte].decode("utf-8", "replace") if name_node is not None else ""
        if re.search(r"\b(?:extern|native|external)\b|\[\s*(?:DllImport|LibraryImport)", head):
            node_kind = "native method"  # P/Invoke, JNI, Kotlin external: code the checks cannot see
            return self.n("forbidden", node, node_kind)
        params = self._params(node)
        if node.type == "lambda_literal" and not params and \
                not any(c.type == "lambda_parameters" for c in node.named_children):
            params = ["it"]  # Kotlin: a lambda without parameters has the implicit ``it``
        label = f"func:{name}"
        holders = ("formal_parameters", "parameters", "parameter_list", "inferred_parameters",
                   "function_value_parameters", "lambda_parameters", "bracketed_parameter_list")
        # parameter lists are built too (default values are code); their names are not reads (``params``)
        kids = self.scoped(label, lambda: [self.n("other", c, "params", self.kids_of(c)) if c.type in holders
                                           else self.build(c) for c in self.named(node) if c != name_node])
        return self.n("func", node, name, kids, params)

    def _params(self, node: Any) -> list[str]:
        out: list[str] = []
        name_node = self.f(node, "name")  # Kotlin: the function's own name is an identifier child, not a parameter
        holder = (self.f(node, "parameters") or self.f(node, "parameter")
                  or next((c for c in node.named_children if c.type in ("formal_parameters", "parameters", "parameter_list",
                                                                          "inferred_parameters", "function_value_parameters",
                                                                          "lambda_parameters")), None)
                  or next((c for c in node.named_children if c.type == "identifier" and c != name_node), None))
        if holder is None:
            return out
        if holder.type == "identifier":
            return [self.text(holder)]
        stack = [holder]
        while stack:
            cur = stack.pop()
            if cur.type in ("identifier", "simple_identifier", "shorthand_property_identifier_pattern"):
                par = cur.parent
                field_name = None
                if par is not None:
                    for i, ch in enumerate(par.children):
                        if ch == cur:
                            field_name = par.field_name_for_child(i)
                if field_name not in ("type", "value", "default"):
                    out.append(self.ident(cur))
                continue
            if cur.type in self.drop or cur.type in NT.TYPE_LEAVES and cur.type not in ("identifier",
                                                                                      "simple_identifier"):
                continue
            stack.extend(cur.named_children)
        return out

    def _class(self, node: Any) -> N:
        name_node = self.f(node, "name")
        name = self.ident(name_node) if name_node is not None else ""
        kids = self.scoped(f"class:{name}", lambda: [self.build(c) for c in self.named(node) if c != name_node])
        return self.n("class", node, name, kids)

    def _ctl(self, node: Any) -> N:
        head_fields = ("condition", "initializer", "left", "right", "value", "update", "subject", "resources")
        head = " ".join(self.text(h) for h in (self.f(node, x) for x in head_fields) if h is not None)
        kids: list[N | None] = []
        alias = self.f(node, "alias") if node.type == "type_switch_statement" else None
        for i, c in enumerate(node.children):
            if not c.is_named or c.type in _COMMENTS:
                continue
            fname = node.field_name_for_child(i) or ""
            if fname == "alias":
                continue
            if fname == "value" and alias is not None:  # Go ``switch x := y.(type)``: ``x`` holds ``y``
                kids.append(self.n("assign", node, ":=", [self.build(alias), self.build(c)]))
            elif fname in head_fields:
                kids.append(self.build(c))
            else:
                kids.append(self.scoped(f"{node.type}:{head}:{fname}:{i if fname == '' else ''}",
                                        lambda c=c: self.build(c)))
        return self.n("ctl", node, node.type, kids)


def walk_ts(node: Any):
    """Every named node of a tree-sitter subtree."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.named_children))


def norm_ident(lang: str, txt: str) -> str:
    """C# verbatim identifiers (``@k``) and Kotlin quoted identifiers (k in backticks) name the variable ``k``."""
    if lang == "csharp" and txt.startswith("@"):
        return txt[1:]
    if lang == "kotlin" and len(txt) >= 2 and txt.startswith("`") and txt.endswith("`"):
        return txt[1:-1]
    return txt


@functools.cache
def known_types(lang: str) -> frozenset[str]:
    """Every node type the builder has a decision for: handled, dropped (no run-time code), forbidden, or built
    generically (every named child built, the value flows to the parent). Anything else is ``forbidden``."""
    handlers = {name[1:] for name in dir(_TsBuilder) if name.startswith("_") and not name.startswith("__")}
    base = (_COMMENTS | _NAMES | _STRINGS | _NUMS | _FUNCS | _CLASSES | _CTL | _FORBIDDEN.get(lang, set())
            | _LITERAL_TYPES | handlers)
    return frozenset(base | NT.TYPE_ONLY.get(lang, frozenset()) | NT.GENERIC.get(lang, frozenset()))


def _kotlin_dollar_names(raw: str) -> list[str]:
    """Identifiers read by ``$name`` templates in a Kotlin string literal (``\\$`` is a dollar sign)."""
    out = []
    raw_string = raw.startswith('"""')
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and not raw_string:
            i += 2
            continue
        if ch == "$":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", raw[i + 1:])
            if m:
                out.append(m.group(0))
                i += 1 + len(m.group(0))
                continue
        i += 1
    return out
