"""CB-27: Java literal flow for crypto-material misuse.

A constant reaching a Java crypto API is a present-day break (CryptoAPI-Bench's
categories): an IV, a key, a PBE password, a salt, a SecureRandom seed or a keystore
password fixed by the source, or a PBE iteration count below 1,000 (NIST SP 800-132
section 5.2). The lexical lanes in :mod:`aibom.cbom.misuse` see a literal only on the
line of the call; this module follows the literal through the code, without a full
Java parser:

* **intra-procedural**: ``byte[] iv = "abcde".getBytes(); new IvParameterSpec(iv)``;
  ``String k = "changeit"; ks.load(in, k.toCharArray())``; conversions that keep a
  constant constant (``getBytes``, ``toCharArray``, ``Arrays.copyOf``,
  ``String.valueOf``, ``new String(..)``, ``Base64...decode``, casts, arithmetic) and
  array initialisers of constants; ``new byte[16]`` is sixteen zero bytes;
* **must-constant**: a value is constant at the call only when every assignment that
  can reach it is constant. An assignment, or a call that may fill an array
  (``nextBytes``, ``read``, ``ByteBuffer.get``, any method it is handed to), under an
  ``if``/loop/``try`` or before the call makes it not constant, so a path that always
  randomises (CryptoAPI-Bench's path-sensitive cases, labelled secure) is not reported;
* **fields** (``this.iv = CONST``, static constants, ``Other.CONST``): a field is
  constant when every assignment to it is constant;
* **interprocedural**: a parameter is constant when every call site that reaches the
  method (resolved by the receiver's declared type, ``Cls.m()``, ``new Cls()`` or the
  current class) passes a constant, iterated to a fixed point, so ``main`` passing a
  literal through two methods into ``setSeed`` is found, in the same file or another
  one. Call sites in test code never make a production parameter constant.

It never reads a value from outside the source (no configuration, no environment), so
a key read from the environment, a file or a KMS is never constant. Known-answer self
tests (``testKey``) and HKDF's all-zero default salt (RFC 5869) are not reported. Only
the files and methods a sink can depend on are parsed and walked (a backward slice by
identifier, :func:`_load`).

The trust-manager check (:func:`noop_trust_checks`) reports an ``X509TrustManager``
whose ``checkServerTrusted`` does nothing (an empty body, or only ``return;``).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

_LOG = logging.getLogger(__name__)

# ----------------------------------------------------------------------------- tokens
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<lc>//[^\n]*)
  | (?P<bc>/\*.*?\*/)
  | (?P<tb>\"\"\"(?:.|\n)*?\"\"\")
  | (?P<str>"(?:\\.|[^"\\\n])*")
  | (?P<chr>'(?:\\.|[^'\\\n])+')
  | (?P<num>0[xX][0-9a-fA-F_]+[lL]?|0[bB][01_]+[lL]?
      |\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?[lLfFdD]?)
  | (?P<id>[A-Za-z_$][\w$]*)
  | (?P<op>->|::|\+\+|--|&&|\|\||[=!<>]=|<<|>>>?|[-+*/%&|^]=|.)
    """,
    re.X | re.S,
)


@dataclass(frozen=True)
class Tok:
    kind: str  # id, num, str, chr, op
    text: str
    line: int


def tokenize(text: str) -> list[Tok]:
    out: list[Tok] = []
    line = 1
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup or "op"
        value = m.group()
        if kind not in ("ws", "lc", "bc"):
            out.append(Tok("str" if kind == "tb" else kind, value, line))
        line += value.count("\n")
    return out


# ----------------------------------------------------------------------------- values
@dataclass(frozen=True)
class Const:
    """A value the source fixes. ``num`` is the integer when it is known."""

    num: int | None = None
    zero: bool = False  # only ``new byte[n]``: n zero bytes


TOP = "top"  # not computed yet (fixed-point start): constant until a round says not


def _meet(a, b):
    """Both must be constant; the larger known number wins (an iteration count is
    weak only if every value is)."""
    if a is None or b is None:
        return None
    if a == TOP:
        return b
    if b == TOP:
        return a
    if a.num is not None and b.num is not None:
        return Const(max(a.num, b.num))
    return Const(None, zero=a.zero and b.zero)


def _number(text: str) -> int | None:
    t = text.replace("_", "").rstrip("lLfFdD")
    try:
        if t[:2] in ("0x", "0X"):
            return int(t[2:], 16)
        if t[:2] in ("0b", "0B"):
            return int(t[2:], 2)
        if "." in t or "e" in t.lower():
            return int(float(t))
        return int(t)
    except ValueError:
        return None


def _arith(op: str, left, right):
    if left == TOP or right == TOP:
        return TOP
    if left.num is not None and right.num is not None:
        x, y = left.num, right.num
        if op == "+":
            return Const(x + y)
        if op == "-":
            return Const(x - y)
        if op == "*":
            return Const(x * y)
        if op == "/" and y:
            return Const(x // y)
        if op == "%" and y:
            return Const(x % y)
    return Const(None)


# --------------------------------------------------------------------------- structure
_MODIFIERS = frozenset(
    {
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "synchronized",
        "native",
        "transient",
        "volatile",
        "strictfp",
        "default",
    }
)
_NOT_METHOD = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "synchronized",
        "return",
        "new",
        "throw",
        "else",
        "try",
        "do",
        "case",
        "assert",
        "super",
        "this",
    }
)
_TYPE_DECL = frozenset({"class", "interface", "enum", "record"})
_CLOSE = {"(": ")", "[": "]", "{": "}"}


@dataclass
class Method:
    file: int
    cls: str
    name: str
    params: list[str]
    body: tuple[int, int]  # token indices of the body, braces excluded


@dataclass
class JavaFile:
    path: str
    toks: list[Tok]
    methods: list[Method] = field(default_factory=list)
    # class -> [(field name, initializer token range)]
    fields: dict[str, list[tuple[str, tuple[int, int]]]] = field(default_factory=dict)


def _match(toks: list[Tok], i: int, open_: str, close: str) -> int:
    """Index of the token that closes the bracket at ``i`` (len(toks) if none)."""
    depth = 0
    for j in range(i, len(toks)):
        t = toks[j].text
        if t == open_:
            depth += 1
        elif t == close:
            depth -= 1
            if depth == 0:
                return j
    return len(toks)


def _split_top(
    toks: list[Tok], lo: int, hi: int, sep: str = ","
) -> list[tuple[int, int]]:
    """Split [lo, hi) on ``sep`` outside brackets."""
    parts, depth, start = [], 0, lo
    for j in range(lo, hi):
        t = toks[j].text
        if t in "([{":
            depth += 1
        elif t in ")]}":
            depth -= 1
        elif t == sep and depth == 0:
            parts.append((start, j))
            start = j + 1
    if start < hi or parts:
        parts.append((start, hi))
    return [p for p in parts if p[0] < p[1]]


def _param_names(toks: list[Tok], lo: int, hi: int) -> list[str]:
    names = []
    for a, b in _split_top(toks, lo, hi):
        ids = [t.text for t in toks[a:b] if t.kind == "id" and t.text not in _MODIFIERS]
        names.append(ids[-1] if ids else "")
    return names


def parse(path: str, text: str, index: int) -> JavaFile:
    jf = JavaFile(path, tokenize(text))
    _parse_body(jf, index, "", 0, len(jf.toks), top=True)
    return jf


def _parse_body(
    jf: JavaFile, index: int, cls: str, lo: int, hi: int, top: bool = False
) -> None:
    """Members of a type body (or of the compilation unit when ``top``)."""
    toks = jf.toks
    i, stmt = lo, lo
    while i < hi:
        t = toks[i]
        if (
            t.text in _TYPE_DECL
            and i + 1 < hi
            and toks[i + 1].kind == "id"
            and (i == 0 or toks[i - 1].text != ".")
        ):
            name = toks[i + 1].text
            j = i + 2
            while j < hi and toks[j].text != "{":
                j += 1
            end = _match(toks, j, "{", "}")
            _parse_body(jf, index, name, j + 1, min(end, hi))
            i, stmt = end + 1, end + 1
            continue
        if top:
            i += 1
            continue
        if t.text == "{":  # an initializer block: a method with no name
            end = _match(toks, i, "{", "}")
            jf.methods.append(Method(index, cls, "<init-block>", [], (i + 1, end)))
            i, stmt = end + 1, end + 1
            continue
        if (
            t.text == "("
            and i > lo
            and toks[i - 1].kind == "id"
            and toks[i - 1].text not in _NOT_METHOD
        ):
            close = _match(toks, i, "(", ")")
            j = close + 1
            while j < hi and toks[j].text not in ("{", ";", "="):
                j += 1
            if (
                j < hi
                and toks[j].text == "{"
                and "=" not in [x.text for x in toks[stmt:i]]
            ):
                end = _match(toks, j, "{", "}")
                params = _param_names(toks, i + 1, close)
                jf.methods.append(
                    Method(index, cls, toks[i - 1].text, params, (j + 1, end))
                )
                i, stmt = end + 1, end + 1
                continue
        if t.text == ";":
            _field_decl(jf, cls, stmt, i)
            stmt = i + 1
        elif t.text in _CLOSE:
            i = _match(toks, i, t.text, _CLOSE[t.text])
        elif t.text == "@" and i + 1 < hi and toks[i + 1].kind == "id":  # annotation
            i += 2
            if i < hi and toks[i].text == "(":
                i = _match(toks, i, "(", ")") + 1
            stmt = i
            continue
        i += 1


def _field_decl(jf: JavaFile, cls: str, lo: int, hi: int) -> None:
    toks = jf.toks
    for a, b in _split_top(toks, lo, hi):
        eq = next((j for j in range(a, b) if toks[j].text == "="), None)
        end = eq if eq is not None else b
        ids = [j for j in range(a, end) if toks[j].kind == "id"]
        if not ids:
            continue
        expr = (eq + 1, b) if eq is not None else (b, b)
        jf.fields.setdefault(cls, []).append((toks[ids[-1]].text, expr))


# ----------------------------------------------------------------------------- sinks
# constructor -> [(argument index, sink kind)]
_CTOR_SINKS = {
    "IvParameterSpec": [(0, "iv")],
    "GCMParameterSpec": [(1, "iv")],
    "ChaCha20ParameterSpec": [(0, "iv")],
    "SecretKeySpec": [(0, "key")],
    "DESKeySpec": [(0, "key")],
    "DESedeKeySpec": [(0, "key")],
    "PBEKeySpec": [(0, "password"), (1, "salt"), (2, "iterations")],
    "PBEParameterSpec": [(0, "salt"), (1, "iterations")],
    "SecureRandom": [(0, "seed")],
}
# method -> (receiver type, [(argument index, sink kind)])
_METHOD_SINKS = {
    "setSeed": ("SecureRandom", [(0, "seed")]),
    "load": ("KeyStore", [(1, "password")]),
    "store": ("KeyStore", [(1, "password")]),
    "getKey": ("KeyStore", [(1, "password")]),
    "setKeyEntry": ("KeyStore", [(2, "password")]),
}
_SINK_WORDS = frozenset(_CTOR_SINKS) | frozenset(_METHOD_SINKS)
# calls that fill the array argument at this index
_FILLERS = {
    "nextBytes": 0,
    "read": 0,
    "readFully": 0,
    "readNBytes": 0,
    "engineNextBytes": 0,
    "arraycopy": 2,
    "getRandomBytes": 0,
}
# calls whose result is constant when their arguments (or receiver) are
_PURE_STATIC = frozenset(
    {
        "String.valueOf",
        "String.copyValueOf",
        "Arrays.copyOf",
        "Arrays.copyOfRange",
        "Byte.parseByte",
        "Byte.valueOf",
        "Short.parseShort",
        "Integer.parseInt",
        "Integer.valueOf",
        "Long.parseLong",
        "Long.valueOf",
        "Hex.decode",
        "Hex.decodeHex",
        "Hex.decodeStrict",
        "DatatypeConverter.parseHexBinary",
        "DatatypeConverter.parseBase64Binary",
        "Base64.decode",
        "Base64.decodeBase64",
        "Base64.getDecoder.decode",
        "Base64.getMimeDecoder.decode",
        "Base64.getUrlDecoder.decode",
        "Character.forDigit",
        "Math.abs",
        "Math.max",
        "Math.min",
    }
)
_PURE_METHODS = frozenset(
    {
        "getBytes",
        "toCharArray",
        "toString",
        "clone",
        "trim",
        "intern",
        "substring",
        "toLowerCase",
        "toUpperCase",
        "concat",
        "repeat",
        "strip",
        "byteValue",
        "intValue",
        "longValue",
        "shortValue",
        "charAt",
        "chars",
    }
)
_CONST_CTORS = frozenset(
    {"String", "Byte", "Integer", "Long", "Short", "Character", "BigInteger"}
)
_PRIMITIVE_ARRAYS = frozenset({"byte", "char", "int", "long", "short"})
_MAPS = frozenset({"HashMap", "Hashtable", "TreeMap", "LinkedHashMap"})
# test code: its call sites never make a production parameter constant
_TEST_PATH = re.compile(
    r"(?:^|/)(?:src/test|test|tests|androidTest)/|Tests?\.java$|IT\.java$"
)
# a known-answer self test: a constant key with its expected output, protecting nothing
_KAT_NAME = re.compile(r"(?i)(?:test|kat|knownanswer)")
_KAT_METHOD = re.compile(r"(?i)selftest|knownanswer|^kat")


@dataclass(frozen=True)
class FlowFact:
    path: str
    line: int
    kind: str  # iv, key, password, salt, iterations, seed
    var: str | None
    iterations: int | None = None
    api: str = ""


# ----------------------------------------------------------------------------- analysis
class _Project:
    def __init__(self, files: list[JavaFile]) -> None:
        self.files = files
        self.fields: dict[str, object] = {}  # "Cls.name" -> value
        # (class, method, arity, parameter index) -> value
        self.params: dict[tuple[str, str, int, int], object] = {}
        self.field_names: dict[str, set[str]] = {}  # class -> field names
        self.by_name: dict[str, list[str]] = {}  # field name -> ["Cls.name"]
        self.arity: dict[tuple[str, int], list[Method]] = {}
        self.field_types: dict[tuple[str, str], str | None] = {}
        for jf in files:
            for cls, decls in jf.fields.items():
                for name, _ in decls:
                    self.field_names.setdefault(cls, set()).add(name)
                    self.by_name.setdefault(name, []).append(f"{cls}.{name}")
            for m in jf.methods:
                self.arity.setdefault((m.name, len(m.params)), []).append(m)
        self.facts: list[FlowFact] = []
        self.final = False
        self.relevant: set[int] = set()
        self._field_acc: dict[str, object] = {}
        self._param_acc: dict[tuple[str, str, int, int], object] = {}

    def run(self, relevant: set[int], rounds: int = 8) -> list[FlowFact]:
        self.relevant = relevant
        for ms in self.arity.values():
            for m in ms:
                for i in range(len(m.params)):
                    self.params[(m.cls, m.name, len(m.params), i)] = TOP
        for jf in self.files:
            for cls, decls in jf.fields.items():
                for name, _ in decls:
                    self.fields[f"{cls}.{name}"] = TOP
        for _ in range(rounds):
            before = (dict(self.fields), dict(self.params))
            self._round()
            if (self.fields, self.params) == before:
                break
        self.final = True
        self.facts = []
        self._round()
        return sorted(set(self.facts), key=lambda f: (f.path, f.line, f.kind))

    def _round(self) -> None:
        self._field_acc = {}
        self._param_acc = {}
        for jf in self.files:
            for cls, decls in jf.fields.items():
                for name, (a, b) in decls:
                    if a < b:
                        val = _Eval(self, jf, cls, {}, {}).expr(a, b)
                        self.acc_field(f"{cls}.{name}", val)
            for m in jf.methods:
                if id(m) in self.relevant:
                    _Walker(self, jf, m).run()
        # a field no write reaches is not constant (null, or a value from outside)
        self.fields = {k: self._field_acc.get(k) for k in self.fields}
        self.params = {k: self._param_acc.get(k) for k in self.params}

    def acc_field(self, key: str, val) -> None:
        acc = self._field_acc
        acc[key] = _meet(acc[key], val) if key in acc else val

    def acc_param(self, key: tuple[str, str, int, int], val) -> None:
        acc = self._param_acc
        acc[key] = _meet(acc[key], val) if key in acc else val

    def field_key(
        self, cls: str, name: str, qualifier: str | None = None
    ) -> str | None:
        if qualifier and f"{qualifier}.{name}" in self.fields:
            return f"{qualifier}.{name}"
        if not qualifier and name in self.field_names.get(cls, ()):
            return f"{cls}.{name}"
        if qualifier is None:
            return None
        hits = self.by_name.get(name, [])
        return hits[0] if len(hits) == 1 and qualifier[:1].isupper() else None


class _Eval:
    """Evaluate an expression (token range) to Const, TOP or None (not constant)."""

    def __init__(
        self, project: _Project, jf: JavaFile, cls: str, env: dict, types: dict
    ) -> None:
        self.p, self.jf, self.cls, self.env, self.types = project, jf, cls, env, types
        self.maps: dict[str, object] = {}  # local maps: the meet of every put value

    def expr(self, a: int, b: int):
        toks = self.jf.toks
        while a < b and toks[a].text == "(" and _match(toks, a, "(", ")") == b - 1:
            a, b = a + 1, b - 1
        if a >= b:
            return None
        if toks[a].text == "(":  # a cast: (Type) expr
            close = _match(toks, a, "(", ")")
            inner = toks[a + 1 : close]
            if (
                inner
                and inner[0].kind == "id"
                and close + 1 < b
                and all(t.kind == "id" or t.text in "[].<>" for t in inner)
            ):
                return self.expr(close + 1, b)
        for ops in (
            ("?",),
            ("||", "&&"),
            ("+", "-"),
            ("*", "/", "%"),
            ("|", "&", "^", "<<", ">>", ">>>"),
        ):
            j = self._last_op(a, b, ops)
            if j is not None:
                if toks[j].text in ("?", "||", "&&"):
                    return None
                left, right = self.expr(a, j), self.expr(j + 1, b)
                if left is None or right is None:
                    return None
                return _arith(toks[j].text, left, right)
        t = toks[a]
        if b - a == 1:
            if t.kind == "num":
                return Const(_number(t.text))
            if t.kind in ("chr", "str"):
                return Const(None)
            if t.kind == "id":
                if t.text in ("null", "true", "false"):
                    return None if t.text == "null" else Const(None)
                return self.name(t.text)
            return None
        if t.kind in ("str", "chr", "num") and toks[a + 1].text == ".":
            return self._methods_after(a + 2, b, Const(None))  # "abcde".getBytes()
        if t.text in ("-", "+", "~"):
            v = self.expr(a + 1, b)
            if isinstance(v, Const) and v.num is not None and t.text == "-":
                return Const(-v.num)
            return v
        if t.text == "{":  # an array initializer
            return self._all(a + 1, _match(toks, a, "{", "}"))
        if t.text == "new":
            return self._new(a, b)
        if (
            t.text == "this"
            and b - a == 3
            and toks[a + 1].text == "."
            and toks[a + 2].kind == "id"
        ):
            key = self.p.field_key(self.cls, toks[a + 2].text)
            return self.p.fields.get(key) if key else None
        return self._chain(a, b)

    def _last_op(self, a: int, b: int, ops) -> int | None:
        toks, depth, found = self.jf.toks, 0, None
        for j in range(a, b):
            x = toks[j].text
            if x in "([{":
                depth += 1
            elif x in ")]}":
                depth -= 1
            elif (
                depth == 0
                and x in ops
                and j > a
                and (toks[j - 1].kind != "op" or toks[j - 1].text in (")", "]"))
            ):
                found = j  # binary, not a sign: the token before it ends an operand
        return found

    def _all(self, a: int, b: int):
        val = Const(None)
        for x, y in _split_top(self.jf.toks, a, b):
            val = _meet(val, self.expr(x, y))
            if val is None:
                return None
        return Const(None) if val == TOP else val

    def _args_const(self, args):
        val = Const(None)
        for x, y in args:
            val = _meet(val, self.expr(x, y))
            if val is None:
                return None
        return val

    def _new(self, a: int, b: int):
        toks = self.jf.toks
        j = a + 1
        name = []
        while j < b and (toks[j].kind == "id" or toks[j].text == "."):
            name.append(toks[j].text)
            j += 1
        typ = "".join(name).split(".")[-1]
        if j < b and toks[j].text == "<":  # generics
            depth = 0
            while j < b:
                depth += toks[j].text == "<"
                depth -= toks[j].text == ">"
                j += 1
                if depth == 0:
                    break
        if j < b and toks[j].text == "[":
            close = _match(toks, j, "[", "]")
            if close == j + 1:  # new T[]{...}
                k = close + 1
                while k < b and toks[k].text == "[":
                    k = _match(toks, k, "[", "]") + 1
                if k < b and toks[k].text == "{":
                    return self._all(k + 1, _match(toks, k, "{", "}"))
                return None
            if typ in _PRIMITIVE_ARRAYS and close == b - 1:
                return Const(None, zero=True)  # n zero bytes until something fills it
            return None
        if j < b and toks[j].text == "(" and typ in _CONST_CTORS:
            close = _match(toks, j, "(", ")")
            if close != b - 1 and not (close + 1 < b and toks[close + 1].text == "."):
                return None
            val = self._args_const(_split_top(toks, j + 1, close))
            if close == b - 1:
                return val
            return self._methods_after(close + 1, b, val)
        return None

    def name(self, ident: str):
        if ident in self.env:
            return self.env[ident]
        key = self.p.field_key(self.cls, ident)
        return self.p.fields.get(key) if key else None

    def _chain(self, a: int, b: int):
        """``x.getBytes()``, ``Cls.CONST``, ``String.valueOf(x)``, ``map.get(k)``."""
        toks = self.jf.toks
        parts: list[tuple[str, tuple[int, int] | None]] = []  # (name, arguments)
        j = a
        while j < b:
            if toks[j].kind != "id":
                return None
            name = toks[j].text
            j += 1
            args = None
            if j < b and toks[j].text == "(":
                close = _match(toks, j, "(", ")")
                args = (j + 1, close)
                j = close + 1
            while j < b and toks[j].text == "[":  # an element keeps the constant
                j = _match(toks, j, "[", "]") + 1
            parts.append((name, args))
            if j < b:
                if toks[j].text != ".":
                    return None
                j += 1
        if not parts:
            return None
        head, head_args = parts[0]
        val, idx = None, 0
        if head_args is None:
            if head in self.env or self.p.field_key(self.cls, head):
                val, idx = self.name(head), 1
            elif len(parts) >= 2 and parts[1][1] is None and head[:1].isupper():
                key = self.p.field_key(self.cls, parts[1][0], head)  # Cls.CONST
                if key:
                    val, idx = self.p.fields.get(key), 2
        if idx == 0:  # a static call chain: Cls.m(...)[.n(...)]
            dotted: list[str] = []
            for k, (nm, args) in enumerate(parts):
                dotted.append(nm)
                if args is not None:
                    if (
                        ".".join(dotted) in _PURE_STATIC
                        or ".".join(dotted[-2:]) in _PURE_STATIC
                    ):
                        r = (
                            self._args_const(_split_top(toks, *args))
                            if args[0] < args[1]
                            else Const(None)
                        )
                        return self._apply_pure(parts[k + 1 :], r)
                    return None
            return None
        if idx == 1 and head in self.maps and len(parts) == 2 and parts[1][0] == "get":
            return self.maps[head]
        return self._apply_pure(parts[idx:], val)

    def _apply_pure(self, rest, val):
        toks = self.jf.toks
        for nm, args in rest:
            if val is None:
                return None
            if args is None or nm not in _PURE_METHODS:
                return None
            if args[0] < args[1] and nm in ("substring", "concat", "charAt", "repeat"):
                for x, y in _split_top(toks, *args):
                    if self.expr(x, y) is None:
                        return None
        return val

    def _methods_after(self, a: int, b: int, val):
        toks = self.jf.toks
        rest = []
        j = a
        while j < b:
            if toks[j].text == ".":
                j += 1
                continue
            if toks[j].kind != "id":
                return None
            nm = toks[j].text
            j += 1
            args = None
            if j < b and toks[j].text == "(":
                close = _match(toks, j, "(", ")")
                args = (j + 1, close)
                j = close + 1
            rest.append((nm, args))
        return self._apply_pure(rest, val)


class _Walker:
    """One method body, statement by statement (must-constant: a write under a
    condition that may differ makes the value not constant)."""

    def __init__(self, project: _Project, jf: JavaFile, m: Method) -> None:
        self.p, self.jf, self.m = project, jf, m
        self.env: dict[str, object] = {}
        self.types: dict[str, str] = {}
        for i, prm in enumerate(m.params):
            if prm:
                self.env[prm] = project.params.get((m.cls, m.name, len(m.params), i))
        self.ev = _Eval(project, jf, m.cls, self.env, self.types)
        self.locals: set[str] = set(m.params)
        self.arrays: set[str] = set()  # names written as arrays: a call may fill them
        self.test_code = bool(_TEST_PATH.search(jf.path))

    def run(self) -> None:
        a, b = self.m.body
        self._block(a, b, 0)

    def _block(self, a: int, b: int, cond: int) -> None:
        toks = self.jf.toks
        i = a
        while i < b:
            t = toks[i]
            if (
                t.text in ("if", "while", "for", "switch", "catch", "synchronized")
                and i + 1 < b
                and toks[i + 1].text == "("
            ):
                close = _match(toks, i + 1, "(", ")")
                if t.text == "for":
                    self._statement(i + 2, close, cond + 1)  # writes in the header
                else:
                    self._scan_calls(i + 2, close, cond)
                i = self._body_after(close + 1, b, cond + 1)
                continue
            if t.text in ("else", "do", "try", "finally"):
                i = self._body_after(i + 1, b, cond + 1)
                continue
            if t.text == "{":
                end = _match(toks, i, "{", "}")
                self._block(i + 1, end, cond)
                i = end + 1
                continue
            if t.text in ("case", "default"):
                while i < b and toks[i].text != ":":
                    i += 1
                i += 1
                continue
            j = self._stmt_end(i, b)
            self._statement(i, j, cond)
            i = j + 1

    def _body_after(self, i: int, b: int, cond: int) -> int:
        toks = self.jf.toks
        if i < b and toks[i].text == "(":  # try (resources)
            close = _match(toks, i, "(", ")")
            self._statement(i + 1, close, cond)
            i = close + 1
        if i < b and toks[i].text == "{":
            end = _match(toks, i, "{", "}")
            self._block(i + 1, end, cond)
            return end + 1
        if i < b and toks[i].text in ("if", "while", "for", "do", "try", "switch"):
            j = i  # else if ...: the nested statement as a block of its own
            while j < b:
                if toks[j].text == "{":
                    j = _match(toks, j, "{", "}")
                    if j + 1 >= b or toks[j + 1].text != "else":
                        break
                elif toks[j].text == ";" and (j + 1 >= b or toks[j + 1].text != "else"):
                    break
                j += 1
            self._block(i, min(j + 1, b), cond)
            return j + 1
        j = self._stmt_end(i, b)
        self._statement(i, j, cond)
        return j + 1

    def _stmt_end(self, i: int, b: int) -> int:
        toks = self.jf.toks
        j = i
        while j < b and toks[j].text != ";":
            if toks[j].text in _CLOSE:
                j = _match(toks, j, toks[j].text, _CLOSE[toks[j].text])
            j += 1
        return j

    # ------------------------------------------------------------------- statements
    def _statement(self, a: int, b: int, cond: int) -> None:
        toks = self.jf.toks
        if a >= b:
            return
        if toks[a].text in ("return", "throw", "assert", "yield"):
            self._scan_calls(a + 1, b, cond)
            return
        decl = self._is_decl(a, b)
        for x, y in _split_top(toks, a, b) if decl else [(a, b)]:
            self._one(x, y, cond, decl)

    def _is_decl(self, a: int, b: int) -> bool:
        """``Type [<...>] [[]...] name [= ...]``"""
        toks = self.jf.toks
        j = a
        while j < b and (toks[j].text in _MODIFIERS or toks[j].text == "@"):
            j += 1
        if j >= b or toks[j].kind != "id":
            return False
        k = j + 1
        while k < b and (
            toks[k].text in (".", "<", ">", ",", "[", "]", "?") or toks[k].kind == "id"
        ):
            if toks[k].kind == "id" and (
                k + 1 == b or toks[k + 1].text in ("=", ",", ";", "[", ":")
            ):
                return toks[k - 1].text != "."
            k += 1
        return False

    def _d0(self, a: int, j: int) -> bool:
        toks = self.jf.toks
        depth = 0
        for k in range(a, j):
            if toks[k].text in "([{":
                depth += 1
            elif toks[k].text in ")]}":
                depth -= 1
        return depth == 0

    def _one(self, a: int, b: int, cond: int, decl: bool) -> None:
        toks = self.jf.toks
        eq = next(
            (j for j in range(a, b) if toks[j].text == "=" and self._d0(a, j)), None
        )
        op_eq = next(
            (
                j
                for j in range(a, b)
                if toks[j].text in ("+=", "-=", "*=", "|=", "^=", "&=")
                and self._d0(a, j)
            ),
            None,
        )
        assign = eq if eq is not None else op_eq
        lhs_end = assign if assign is not None else b
        target, element, typ = self._target(a, lhs_end, decl)
        rhs = (assign + 1, b) if assign is not None else None
        self._scan_calls(rhs[0] if rhs else a, b, cond)
        if target is None:
            return
        if decl:
            self.locals.add(target)
            if typ:
                self.types[target] = typ
        name = target[5:] if target.startswith("this.") else target
        if any(toks[k].text == "[" for k in range(a, lhs_end)) or (
            rhs and any(toks[k].text == "[" for k in range(rhs[0], min(b, rhs[0] + 4)))
        ):
            self.arrays.add(name)
        if rhs is None:
            if decl:
                self.env[target] = None  # declared, not assigned: not constant
            return
        val = self.ev.expr(*rhs)
        if op_eq is not None or element:
            val = _meet(self._current(target), val)
        if toks[rhs[0]].text == "new" and any(
            t.text in _MAPS for t in toks[rhs[0] : rhs[1]]
        ):
            self.ev.maps[target] = TOP
        self._write(target, val, cond, decl)
        if any(t.text == "SecureRandom" for t in toks[rhs[0] : rhs[1]]):
            self.types[target] = self.types.get(target) or "SecureRandom"

    def _target(self, a: int, b: int, decl: bool):
        """(name, element write, declared type) of an assignment's left side."""
        toks = self.jf.toks
        ids = [
            j
            for j in range(a, b)
            if toks[j].kind == "id" and toks[j].text not in _MODIFIERS
        ]
        if not ids:
            return None, False, None
        if decl:
            typ = toks[ids[0]].text if len(ids) >= 2 else None
            return toks[ids[-1]].text, False, typ
        element = any(toks[j].text == "[" for j in range(ids[-1], b))
        if b - a >= 3 and toks[a].text == "this" and toks[a + 1].text == ".":
            return "this." + toks[a + 2].text, element, None
        if toks[a].kind == "id" and (b - a == 1 or toks[a + 1].text == "["):
            return toks[a].text, element, None
        return None, False, None

    def _current(self, target: str):
        if target.startswith("this."):
            key = self.p.field_key(self.m.cls, target[5:])
            return self.p.fields.get(key) if key else None
        return self.ev.name(target)

    def _write(self, target: str, val, cond: int, decl: bool) -> None:
        name = target[5:] if target.startswith("this.") else target
        if target.startswith("this.") or name not in self.locals:
            key = self.p.field_key(self.m.cls, name)
            if key:
                self.p.acc_field(key, val)
            return
        if cond and not decl:
            val = _meet(self.env.get(name), val) if name in self.env else None
        self.env[name] = val

    # ------------------------------------------------------------------- calls
    def _scan_calls(self, a: int, b: int, cond: int) -> None:
        toks = self.jf.toks
        j = a
        while j < b:
            t = toks[j]
            if t.text == "{" and j > a and toks[j - 1].text == ")":
                j = _match(toks, j, "{", "}") + 1  # an anonymous class or lambda body
                continue
            if (
                t.kind == "id"
                and j + 1 < b
                and toks[j + 1].text == "("
                and t.text not in _NOT_METHOD
            ):
                close = _match(toks, j + 1, "(", ")")
                args = _split_top(toks, j + 2, close)
                is_new = j > a and toks[j - 1].text == "new"
                recv = toks[j - 2] if j - 2 >= a and toks[j - 1].text == "." else None
                self._call(t, args, is_new, recv, cond)
            j += 1

    def _call(self, t: Tok, args, is_new: bool, recv: Tok | None, cond: int) -> None:
        name = t.text
        toks = self.jf.toks
        ev = self.ev
        if is_new and name in _CTOR_SINKS:
            for idx, kind in _CTOR_SINKS[name]:
                if idx < len(args) and (name != "SecureRandom" or len(args) == 1):
                    self._sink(t, kind, args[idx], name)
        elif not is_new and name in _METHOD_SINKS and recv is not None:
            want, sinks = _METHOD_SINKS[name]
            if self._recv_type(recv) == want:
                for idx, kind in sinks:
                    if idx < len(args):
                        self._sink(t, kind, args[idx], f"{want}.{name}")
        if not is_new and name in _FILLERS and _FILLERS[name] < len(args):
            x, y = args[_FILLERS[name]]
            if y - x == 1 and toks[x].kind == "id":
                self._write(toks[x].text, None, cond, False)
            elif y - x == 3 and toks[x].text == "this":
                self._write("this." + toks[x + 2].text, None, cond, False)
        if (
            not is_new
            and name == "put"
            and recv is not None
            and recv.text in ev.maps
            and len(args) == 2
        ):
            ev.maps[recv.text] = _meet(ev.maps[recv.text], ev.expr(*args[1]))
        # a call site: what each argument is, for the callee's parameters
        targets = [] if self.test_code else self._targets(name, len(args), is_new, recv)
        if targets:
            vals = [ev.expr(x, y) for x, y in args]
            for cls in targets:
                for i, val in enumerate(vals):
                    self.p.acc_param((cls, name, len(args), i), val)
        pure = name in _PURE_METHODS or (
            recv is not None and f"{recv.text}.{name}" in _PURE_STATIC
        )
        if not is_new and not pure:
            # an array handed to any other call may be filled by it (ByteBuffer.get,
            # in.read, a helper): it no longer holds what the source wrote
            for x, y in args:
                if y - x == 1 and toks[x].kind == "id" and toks[x].text in self.arrays:
                    self._write(toks[x].text, None, cond, False)

    def _targets(
        self, name: str, arity: int, is_new: bool, recv: Tok | None
    ) -> list[str]:
        """The classes whose ``name``/``arity`` this call reaches: the constructor's
        class, the receiver's declared type, ``Cls.m()``, the current class for an
        unqualified call; an unknown receiver, the classes in this file or else all."""
        decl = self.p.arity.get((name, arity), [])
        if not decl:
            return []
        classes = {m.cls for m in decl}
        if is_new:
            return [name] if name in classes else []
        if recv is None or recv.text == "this":
            if self.m.cls in classes:
                return [self.m.cls]
        elif recv.kind == "id":
            typ = self.types.get(recv.text) or (
                self._field_type(recv.text) if recv.text not in self.locals else None
            )
            if typ:  # a declared type: that class, or none (a library type)
                return [typ] if typ in classes else []
            if recv.text in classes:
                return [recv.text]
            if recv.text[:1].isupper():
                return []  # Other.name(...): a class that declares no such method
        same_file = sorted({m.cls for m in decl if m.file == self.m.file})
        return same_file or sorted(classes)

    def _recv_type(self, recv: Tok) -> str | None:
        if recv.text in self.types:
            typ = self.types[recv.text]
            return "SecureRandom" if "SecureRandom" in typ else typ
        if recv.text in {n for n, _ in self.jf.fields.get(self.m.cls, [])}:
            return self._field_type(recv.text)
        return None

    def _field_type(self, name: str) -> str | None:
        key = (self.jf.path, name)
        cache = self.p.field_types
        if key not in cache:
            cache[key] = None
            toks = self.jf.toks
            for i, t in enumerate(toks):
                if (
                    t.kind == "id"
                    and t.text == name
                    and i > 0
                    and toks[i - 1].kind == "id"
                    and i + 1 < len(toks)
                    and toks[i + 1].text in (";", "=")
                ):
                    cache[key] = toks[i - 1].text
                    break
        return cache[key]

    def _sink(self, t: Tok, kind: str, arg: tuple[int, int], api: str) -> None:
        if not self.p.final:
            return
        val = self.ev.expr(*arg)
        if val is None or val == TOP:
            return
        toks = self.jf.toks
        x, y = arg
        var = (
            toks[x].text
            if toks[x].kind == "id" and toks[x].text not in ("new", "this")
            else None
        )
        if (var and _KAT_NAME.match(var)) or _KAT_METHOD.search(self.m.name):
            return  # a known-answer self test: a constant with its expected output
        if kind == "iterations":
            if val.num is None or val.num >= 1000:
                return
            self.p.facts.append(FlowFact(self.jf.path, t.line, kind, var, val.num, api))
            return
        if kind == "key" and val.zero:
            return  # an all-zero HMAC key is HKDF's default salt (RFC 5869)
        self.p.facts.append(FlowFact(self.jf.path, t.line, kind, var, None, api))


# ----------------------------------------------------------------------------- slice
_SINK_HINT = re.compile(
    r"\bnew\s+(?:IvParameterSpec|GCMParameterSpec|ChaCha20ParameterSpec|SecretKeySpec|"
    r"DES(?:ede)?KeySpec|PBEKeySpec|PBEParameterSpec)\s*\(|"
    r"\bnew\s+SecureRandom\s*\(\s*[^)\s]|\.setSeed\s*\(|\bKeyStore\b"
)
_CALLED = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_CLASS_DECL = re.compile(r"\b(?:class|interface|enum)\s+([A-Z][\w$]*)")
_DEPTH = 4  # call levels followed back from a sink (CryptoAPI-Bench needs 3)


@dataclass
class _Shape:
    """What the slice needs of one method: its names, its assignments, its calls by
    name and the names in its sink arguments."""

    ids: set[str]
    assigns: list[tuple[str, set[str]]]
    # name -> [(receiver, arity, names in the arguments)]
    calls: dict[str, list[tuple[str | None, int, set[str]]]]
    sink_ids: set[str]


def _shape(jf: JavaFile, m: Method) -> _Shape:
    toks = jf.toks
    a, b = m.body
    ids = {t.text for t in toks[a:b] if t.kind == "id"}
    assigns: list[tuple[str, set[str]]] = []
    start = a
    for k in range(a, b + 1):
        if k == b or toks[k].text in (";", "{", "}"):
            seg = toks[start:k]
            eq = next(
                (n for n, t in enumerate(seg) if t.text in ("=", "+=", "|=", "^=")),
                None,
            )
            if eq:
                depth, lhs = 0, None
                for t in seg[:eq]:  # the last name outside brackets: byte[] iv, iv[i]
                    depth += t.text in ("[", "(", "<")
                    depth -= t.text in ("]", ")", ">")
                    if depth == 0 and t.kind == "id" and t.text != "this":
                        lhs = t.text
                if lhs:
                    assigns.append(
                        (lhs, {t.text for t in seg[eq + 1 :] if t.kind == "id"})
                    )
            start = k + 1
    calls: dict[str, list[tuple[str | None, int, set[str]]]] = {}
    sink_ids: set[str] = set()
    for k in range(a, b - 1):
        t = toks[k]
        if t.kind == "id" and toks[k + 1].text == "(":
            close = _match(toks, k + 1, "(", ")")
            arg_ids = {x.text for x in toks[k + 2 : close] if x.kind == "id"}
            recv = toks[k - 2].text if k - 2 >= a and toks[k - 1].text == "." else None
            arity = len(_split_top(toks, k + 2, close))
            calls.setdefault(t.text, []).append((recv, arity, arg_ids))
            if t.text in _SINK_WORDS:
                sink_ids |= arg_ids
    return _Shape(ids, assigns, calls, sink_ids)


def _closure(shape: _Shape, seeds: set[str]) -> set[str]:
    needed = set(seeds)
    changed = True
    while changed:
        changed = False
        for lhs, rhs in shape.assigns:
            if lhs in needed and not rhs <= needed:
                needed |= rhs
                changed = True
    return needed


def _load(sources: dict[str, str]) -> tuple[list[JavaFile], set[int]]:
    """A backward slice from the sinks, by identifier. A sink's argument names are
    closed over the method's own assignments; a parameter among them takes in the
    methods that call it (up to ``_DEPTH`` levels; never test code), whose argument
    names are followed the same way; a field takes in the methods of its class that
    use it; a class named there (``Keys.DEFAULT``) takes in the file that declares it.
    Only those files are parsed and only those methods walked, so a large code base
    whose keys come from a KMS or a keyset costs little."""
    files: dict[str, JavaFile] = {}
    files_by_index: dict[int, str] = {}
    shapes: dict[int, _Shape] = {}
    declared: dict[str, list[str]] = {}
    called: dict[str, set[str]] = {}  # name -> files with ``name(`` in them
    is_test = {path: bool(_TEST_PATH.search(path)) for path in sources}
    for path, text in sources.items():
        for name in _CLASS_DECL.findall(text):
            declared.setdefault(name, []).append(path)
        for name in set(_CALLED.findall(text)):
            called.setdefault(name, set()).add(path)

    def take(path: str) -> None:
        if path in files:
            return
        index = len(files)
        try:
            jf = parse(path, sources[path], index)
        except (RecursionError, IndexError, ValueError):
            _LOG.warning("java literal flow: %s not parsed", path)
            return
        files[path] = jf
        files_by_index[index] = path
        for m in jf.methods:
            shapes[id(m)] = _shape(jf, m)

    for path in sorted(sources):
        if _SINK_HINT.search(sources[path]):
            take(path)

    def all_methods() -> list[Method]:
        return [m for jf in files.values() for m in jf.methods]

    seen: dict[int, set[str]] = {}
    relevant: set[int] = set()
    work = [
        (m, shapes[id(m)].sink_ids, 0) for m in all_methods() if shapes[id(m)].sink_ids
    ]
    callers_done: set[tuple[str, str]] = set()
    while work:
        m, seeds, depth = work.pop()
        old = seen.setdefault(id(m), set())
        if seeds <= old and id(m) in relevant:
            continue
        old |= seeds
        relevant.add(id(m))
        needed = _closure(shapes[id(m)], old)
        for name in needed:  # Keys.DEFAULT: the declaring file, for its initialisers
            for path in declared.get(name, ()):
                take(path)
        if depth >= _DEPTH:
            continue
        if set(m.params) & needed and m.name not in ("main", "<init-block>"):
            ctor = m.name == m.cls
            if (m.cls, m.name) not in callers_done:
                for path in sorted(called.get(m.name, ())):
                    if not is_test[path]:
                        take(path)
                callers_done.add((m.cls, m.name))
            for c in all_methods():
                if is_test[files_by_index[c.file]]:
                    continue
                for recv, arity, arg_ids in shapes[id(c)].calls.get(m.name, ()):
                    if arity != len(m.params):
                        continue
                    if ctor or recv in (None, "this"):
                        if not ctor and c.cls != m.cls:
                            continue
                    elif recv and recv[:1].isupper() and recv != m.cls:
                        continue  # Other.name(...): another class's method
                    work.append((c, set(arg_ids), depth + 1))
        fields = {f for jf in files.values() for f, _ in jf.fields.get(m.cls, [])}
        fields &= needed
        if fields:
            for w in all_methods():
                if w.cls == m.cls:
                    shape = shapes[id(w)]
                    rhs = {x for lhs, r in shape.assigns if lhs in fields for x in r}
                    if rhs or shape.ids & fields:
                        work.append((w, rhs | (shape.ids & fields), depth + 1))
    return list(files.values()), relevant


def analyze(sources: dict[str, str]) -> dict[str, list[FlowFact]]:
    """Facts per path for a project's Java sources (``{path: text}``). Never raises:
    source this reader cannot follow (deeply nested expressions, unbalanced brackets)
    costs that file's flow facts, never the scan."""
    if not any(_SINK_HINT.search(text) for text in sources.values()):
        return {}
    try:
        files, relevant = _load(sources)
        facts = _Project(files).run(relevant)
    except (RecursionError, IndexError, ValueError):
        _LOG.warning("java literal flow: project not analysed", exc_info=True)
        return {}
    out: dict[str, list[FlowFact]] = {}
    for fact in facts:
        out.setdefault(fact.path, []).append(fact)
    return out


# ----------------------------------------------------------------------------- trust
_TRUST_CHECK_RE = re.compile(r"\bcheckServerTrusted\s*\(")


def noop_trust_checks(text: str) -> list[int]:
    """Lines of ``checkServerTrusted`` methods whose body does nothing (empty, or only
    ``return;``): an ``X509TrustManager`` that accepts every server certificate."""
    if "TrustManager" not in text or not _TRUST_CHECK_RE.search(text):
        return []
    toks = tokenize(text)
    lines = []
    for i, t in enumerate(toks):
        if (
            t.text != "checkServerTrusted"
            or i + 1 >= len(toks)
            or toks[i + 1].text != "("
        ):
            continue
        if i > 0 and toks[i - 1].text == ".":
            continue  # a call (delegation), not a declaration
        j = _match(toks, i + 1, "(", ")") + 1
        while j < len(toks) and toks[j].text not in ("{", ";"):
            j += 1
        if j >= len(toks) or toks[j].text != "{":
            continue
        end = _match(toks, j, "{", "}")
        if [x.text for x in toks[j + 1 : end]] in ([], ["return", ";"]):
            lines.append(t.line)
    return lines


__all__ = ["FlowFact", "analyze", "noop_trust_checks", "tokenize"]
