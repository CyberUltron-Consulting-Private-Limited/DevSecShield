"""Facts that cross files: a constant defined in one file and used in another, a crypto helper called from
another module, and a value read from a configuration file.

The per-file detectors see one file at a time, so ``Cipher.getInstance(Algs.CIPHER)`` (``CIPHER = "DES"`` in
``Algs.java``) or ``hashlib.new(ALG)`` (``from .consts import ALG``) named no algorithm. This index is built once
per scan from the shared walk, lazily (a table is only read when a file needs it), and answers three questions:

* :meth:`ProjectIndex.scope_for` — the constants a file can name from elsewhere in the project: Java/Kotlin
  ``Class.NAME`` (and ``import static``) String constants, Python ``from module import NAME`` /
  ``from pkg import module`` + ``module.NAME`` string constants. Each value keeps where it is defined, so the use
  site reports ``crypto:definedAt``.
* :meth:`ProjectIndex.call_sites` — where another Python module calls a function of this file that it imported by
  name (``from services.crypto_svc.des import c`` then ``c(key)``), so a helper's algorithm lists its callers.
* :meth:`ProjectIndex.config_value` — ``key=value`` entries of ``.properties`` / ``.yaml`` / ``.ini`` files.

Nothing here executes code or follows imports outside the scan root; a name that resolves to two different values
is dropped (not provable).
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from aibom.cbom.files import FileWalk

_JAVA_SUFFIXES = (".java", ".kt", ".kts", ".groovy", ".scala")
_CONFIG_SUFFIXES = (".properties", ".yaml", ".yml", ".ini", ".cfg", ".conf")
_MAX_CONFIG_BYTES = 256_000


@dataclass(frozen=True)
class Definition:
    """A constant value and where it is defined (repository-relative path, 1-based line)."""

    value: str
    path: str
    line: int

    @property
    def where(self) -> str:
        return f"{self.path}:{self.line}"


# --------------------------------------------------------------------------- #
# Java / Kotlin
# --------------------------------------------------------------------------- #
_JAVA_CLASS = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Z]\w*)")
_JAVA_CONST = re.compile(r'\b(?:String|val)\s+([A-Z_][A-Z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"\\\s]{1,80})"')
# a qualified constant passed as a call argument: ``getInstance(Algs.CIPHER)``, ``new SecretKeySpec(k, Algs.KEY)``
_JAVA_QUALIFIED_ARG = re.compile(r"[(,]\s*([A-Z]\w*)\.([A-Z_][A-Z0-9_]*)\s*[,)]")
_JAVA_STATIC_IMPORT = re.compile(r"^\s*import\s+static\s+[\w.]*?\.([A-Z]\w*)\.([A-Z_][A-Z0-9_]*|\*)\s*;", re.M)
# Spring ``@Value("${app.cipher}") private String cipher;`` (also ``${app.cipher:AES}``)
_JAVA_VALUE_FIELD = re.compile(
    r'@Value\(\s*"\$\{([\w.\-]+)(?::[^}"]*)?\}"\s*\)\s*(?:(?:private|protected|public|final|static)\s+)*'
    r"String\s+([A-Za-z_]\w*)"
)
# ``Cipher.getInstance(<identifier>)`` whose argument is not a literal
_JAVA_DYNAMIC_CIPHER = re.compile(r"\bCipher\s*\.\s*getInstance\s*\(\s*[a-z_]\w*\s*[,)]")
_CIPHER_CONFIG_KEY = re.compile(r"cipher|transformation", re.I)
_TRANSFORMATION = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9]+/[A-Za-z0-9]+$")

# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #
_PY_FROM_IMPORT = re.compile(
    r"^[ \t]*from[ \t]+(\.*[\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[^#\n]+)", re.M
)


def _python_module_name(rel: str) -> str | None:
    if not rel.endswith(".py"):
        return None
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts)


def _imported_names(spec: str) -> list[tuple[str, str]]:
    """``a, b as c`` / ``(a,\n b)`` -> [(name, alias)]."""
    out: list[tuple[str, str]] = []
    for piece in spec.strip().strip("()").split(","):
        piece = piece.strip()
        if not piece or piece == "*":
            continue
        m = re.match(r"^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$", piece)
        if m:
            out.append((m.group(1), m.group(2) or m.group(1)))
    return out


@dataclass
class _PyModule:
    constants: dict[str, Definition]
    functions: list[tuple[str, int, int]]  # top-level (name, first line, last line)


def _parse_python_module(text: str, rel: str) -> _PyModule:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _PyModule({}, [])
    counts: dict[str, int] = defaultdict(int)
    found: dict[str, Definition] = {}
    functions: list[tuple[str, int, int]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    counts[target.id] += 1
                    value = node.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str) and \
                            0 < len(value.value) <= 80 and not re.search(r"\s", value.value):
                        found[target.id] = Definition(value.value, rel, node.lineno)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            counts[node.target.id] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append((node.name, node.lineno, getattr(node, "end_lineno", None) or node.lineno))
    # a name bound more than once at module level has no single provable value
    return _PyModule({n: d for n, d in found.items() if counts[n] == 1}, functions)


# --------------------------------------------------------------------------- #
# Configuration files
# --------------------------------------------------------------------------- #
_PROP_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:]\s*(\S.*?)\s*$")
_YAML_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.\-]+)\s*:\s*(.*?)\s*$")
_INI_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _config_entries(text: str, suffix: str) -> list[tuple[str, str, int]]:
    """(dotted key, value, line) of the simple scalar entries of a config file."""
    out: list[tuple[str, str, int]] = []
    if suffix in (".yaml", ".yml"):
        stack: list[tuple[int, str]] = []
        for no, raw in enumerate(text.split("\n"), start=1):
            if not raw.strip() or raw.lstrip().startswith(("#", "-")):
                continue
            m = _YAML_LINE.match(raw)
            if not m:
                continue
            indent, key, value = len(m.group(1)), m.group(2), m.group(3)
            while stack and stack[-1][0] >= indent:
                stack.pop()
            dotted = ".".join([k for _, k in stack] + [key])
            if value and not value.startswith(("#", "|", ">", "&", "*")):
                out.append((dotted, value.strip("'\""), no))
            elif not value:
                stack.append((indent, key))
        return out
    section = ""
    for no, raw in enumerate(text.split("\n"), start=1):
        if raw.lstrip().startswith(("#", ";", "!")):
            continue
        sec = _INI_SECTION.match(raw)
        if sec:
            section = sec.group(1).strip() if suffix in (".ini", ".cfg") else ""
            continue
        m = _PROP_LINE.match(raw)
        if m:
            key = f"{section}.{m.group(1)}" if section else m.group(1)
            out.append((key, m.group(2).strip("'\""), no))
    return out


class ProjectIndex:
    """Cross-file facts of one scan root (see the module docstring). Tables are built on first use."""

    def __init__(self, walk: FileWalk) -> None:
        self.walk = walk
        self._java: dict[str, Definition] | None = None
        self._py_paths: dict[str, str] | None = None
        self._py_modules: dict[str, _PyModule] = {}
        self._scopes: dict[str, dict[str, Definition]] = {}
        self._callers: dict[str, dict[str, list[tuple[str, int]]]] | None = None
        self._config: dict[str, list[Definition]] | None = None

    # --- Java ------------------------------------------------------------- #
    def _java_table(self) -> dict[str, Definition]:
        if self._java is None:
            table: dict[str, Definition] = {}
            ambiguous: set[str] = set()
            for path in self.walk.files(lambda p: p.suffix.lower() in _JAVA_SUFFIXES):
                text = self.walk.read_text(path)
                if not text or '"' not in text:
                    continue
                classes = _JAVA_CLASS.findall(text)
                owner = path.stem if path.stem in classes else (classes[0] if len(classes) == 1 else None)
                if owner is None:
                    continue
                rel = self.walk.rel(path)
                seen: dict[str, set[str]] = defaultdict(set)
                first: dict[str, Definition] = {}
                for m in _JAVA_CONST.finditer(text):
                    seen[m.group(1)].add(m.group(2))
                    first.setdefault(m.group(1), Definition(m.group(2), rel, text.count("\n", 0, m.start()) + 1))
                for name, values in seen.items():
                    key = f"{owner}.{name}"
                    if len(values) != 1 or key in ambiguous:
                        continue
                    if key in table and table[key].value != first[name].value:
                        ambiguous.add(key)
                        del table[key]
                        continue
                    table.setdefault(key, first[name])
            self._java = table
        return self._java

    def _java_config(self, rel: str, text: str) -> dict[str, Definition]:
        """Configuration values a Java file reads: Spring ``@Value("${app.cipher}") String f`` fields, and (key
        ``@config:Cipher``) the one cipher transformation configured in this module's ``src/main/resources``, for a
        ``Cipher.getInstance(<parameter>)`` nothing else resolves."""
        out: dict[str, Definition] = {}
        for key, field_name in _JAVA_VALUE_FIELD.findall(text):
            d = self.config_value(key, near=rel)
            if d is not None:
                out[field_name] = d
        if "src/main/java/" in rel and _JAVA_DYNAMIC_CIPHER.search(text):
            module = rel.split("src/main/java/", 1)[0] + "src/main/resources/"
            found = [d for key, defs in self._config_table().items() if _CIPHER_CONFIG_KEY.search(key)
                     for d in defs if d.path.startswith(module) and _TRANSFORMATION.match(d.value)]
            if len({d.value for d in found}) == 1:
                out["@config:Cipher"] = found[0]
        return out

    def _java_scope(self, text: str, rel: str = "") -> dict[str, Definition]:
        local = set(_JAVA_CLASS.findall(text))
        wanted = {(c, n) for c, n in _JAVA_QUALIFIED_ARG.findall(text) if c not in local}
        statics = _JAVA_STATIC_IMPORT.findall(text)
        config = self._java_config(rel, text) if rel else {}
        if not wanted and not statics:
            return config
        table = self._java_table()
        out: dict[str, Definition] = dict(config)
        for cls, name in wanted:
            d = table.get(f"{cls}.{name}")
            if d is not None:
                out[f"{cls}.{name}"] = d
        for cls, name in statics:
            if name == "*":
                prefix = f"{cls}."
                for key, d in table.items():
                    if key.startswith(prefix):
                        out.setdefault(key[len(prefix):], d)
            else:
                d = table.get(f"{cls}.{name}")
                if d is not None:
                    out.setdefault(name, d)
        return out

    # --- Python ------------------------------------------------------------ #
    def _python_paths(self) -> dict[str, str]:
        if self._py_paths is None:
            paths: dict[str, str] = {}
            for path in self.walk.files(lambda p: p.suffix == ".py"):
                rel = self.walk.rel(path)
                mod = _python_module_name(rel)
                if mod:
                    paths[mod] = rel
            self._py_paths = paths
        return self._py_paths

    def _resolve_module(self, importer: str, spec: str) -> str | None:
        """The repository path of the module ``spec`` (``.consts``, ``pkg.mod``) imported from ``importer``."""
        paths = self._python_paths()
        level = len(spec) - len(spec.lstrip("."))
        name = spec[level:]
        if level:
            base = importer.split("/")[:-1]
            if level > 1:
                base = base[: len(base) - (level - 1)] if level - 1 <= len(base) else []
            dotted = ".".join([*base, *(name.split(".") if name else [])])
            return paths.get(dotted)
        if name in paths:
            return paths[name]
        tails = [rel for mod, rel in paths.items() if mod.endswith("." + name)]
        return tails[0] if len(tails) == 1 else None

    def python_module(self, rel: str) -> _PyModule:
        if rel not in self._py_modules:
            path = self.walk.root / rel
            text = self.walk.read_text(path) if rel.endswith(".py") else None
            self._py_modules[rel] = _parse_python_module(text, rel) if text else _PyModule({}, [])
        return self._py_modules[rel]

    def _python_scope(self, rel: str, text: str) -> dict[str, Definition]:
        out: dict[str, Definition] = {}
        for m in _PY_FROM_IMPORT.finditer(text):
            spec, names = m.group(1), _imported_names(m.group(2))
            if not names:
                continue
            target = self._resolve_module(rel, spec)
            if target is not None and target != rel:
                consts = self.python_module(target).constants
                for name, alias in names:
                    if name in consts:
                        out[alias] = consts[name]
                continue
            # ``from pkg import module`` -> ``module.NAME``
            for name, alias in names:
                sub = self._resolve_module(rel, f"{spec}.{name}" if spec.strip(".") else spec + name)
                if sub is None or sub == rel:
                    continue
                for cname, d in self.python_module(sub).constants.items():
                    out[f"{alias}.{cname}"] = d
        return out

    def _python_callers(self) -> dict[str, dict[str, list[tuple[str, int]]]]:
        """target module path -> {function name: [(caller path, line)]} for names imported with ``from X import``."""
        if self._callers is None:
            callers: dict[str, dict[str, list[tuple[str, int]]]] = defaultdict(lambda: defaultdict(list))
            for path in self.walk.files(lambda p: p.suffix == ".py"):
                text = self.walk.read_text(path)
                if not text or "import" not in text:
                    continue
                rel = self.walk.rel(path)
                lines = text.split("\n")
                for m in _PY_FROM_IMPORT.finditer(text):
                    target = self._resolve_module(rel, m.group(1))
                    if target is None or target == rel:
                        continue
                    funcs = {f[0] for f in self.python_module(target).functions}
                    for name, alias in _imported_names(m.group(2)):
                        if name not in funcs:
                            continue
                        call = re.compile(rf"(?<![\w.]){re.escape(alias)}\s*\(")
                        for no, line in enumerate(lines, start=1):
                            stripped = line.lstrip()
                            if stripped.startswith(("from ", "import ", "def ", "#")):
                                continue
                            if call.search(line):
                                callers[target][name].append((rel, no))
            self._callers = callers
        return self._callers

    def call_sites(self, rel: str, line: int) -> list[tuple[str, int]]:
        """Calls from other modules of the top-level Python function of ``rel`` that contains ``line``."""
        if not rel.endswith(".py"):
            return []
        for name, start, end in self.python_module(rel).functions:
            if start <= line <= end:
                return list(self._python_callers().get(rel, {}).get(name, []))
        return []

    # --- per-file scope ----------------------------------------------------- #
    def scope_for(self, rel: str, lang: str | None, text: str) -> dict[str, Definition]:
        """Names ``rel`` uses that are constants defined in another file (empty when none)."""
        if rel in self._scopes:
            return self._scopes[rel]
        scope: dict[str, Definition] = {}
        try:
            if lang == "java":
                scope = self._java_scope(text, rel)
            elif lang == "python" and rel.endswith(".py") and "import" in text:
                scope = self._python_scope(rel, text)
        except RecursionError:
            scope = {}
        self._scopes[rel] = scope
        return scope

    # --- configuration ------------------------------------------------------ #
    def _config_table(self) -> dict[str, list[Definition]]:
        if self._config is None:
            table: dict[str, list[Definition]] = defaultdict(list)
            for path in self.walk.files(lambda p: p.suffix.lower() in _CONFIG_SUFFIXES and
                                        not p.name.startswith(".env"), max_bytes=_MAX_CONFIG_BYTES):
                text = self.walk.read_text(path, _MAX_CONFIG_BYTES)
                if not text:
                    continue
                rel = self.walk.rel(path)
                for key, value, line in _config_entries(text, path.suffix.lower()):
                    table[key].append(Definition(value, rel, line))
            self._config = table
        return self._config

    def config_value(self, key: str, near: str | None = None, file_name: str | None = None) -> Definition | None:
        """The value of configuration ``key``: from the file named ``file_name`` when given (closest to ``near``
        first), else the only definition in the project."""
        found = self._config_table().get(key) or []
        if file_name:
            found = [d for d in found if Path(d.path).name == file_name]
        if not found:
            return None
        if len(found) == 1:
            return found[0]
        if near:
            here = str(Path(near).parent)
            same = [d for d in found if str(Path(d.path).parent) == here]
            if len(same) == 1:
                return same[0]
        values = {d.value for d in found}
        return found[0] if len(values) == 1 else None

    def config_entries(self) -> dict[str, list[Definition]]:
        return self._config_table()


def project_index(ctx: object) -> ProjectIndex:
    """The scan's shared project index (created on first use)."""
    from aibom.cbom.files import file_walk

    index = getattr(ctx, "project_index", None)
    if not isinstance(index, ProjectIndex):
        index = ProjectIndex(file_walk(ctx))
        ctx.project_index = index  # type: ignore[attr-defined]
    return index


__all__ = ["Definition", "ProjectIndex", "project_index"]
