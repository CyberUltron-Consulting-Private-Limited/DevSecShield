"""Models chosen by a lookup: ``OPTIONS["fast"]``, ``CFG["m"]``, ``settings.llm_model``.

A config-driven application rarely writes the model at the call. It writes
``ollama.chat(model=OPTIONS["fast"])`` or ``ChatOpenAI(model=CFG["m"])`` and keeps
the names in a dict or a settings class (review 6065595627 of #498, R6-M2: such a
call gave neither a model nor an unidentified model, so the repository read "no AI
model"). This module resolves the model argument against the project's own literals:

* a subscript with literal keys (``OPTIONS["fast"]``, ``S["llm"]["model"]``) on a
  module-level dict of the same file, or of the module it is imported from (one hop);
* an attribute (``config.MODEL``) on an imported project module's constant, or
  (``settings.llm_model``) on an instance of a project class whose attribute has a
  literal default (a pydantic ``BaseSettings`` field);
* a subscript with a dynamic key (``OPTIONS[choice]``): every string the dict holds
  is a candidate, so the caller lists them as low-confidence models of that call.

Only values that name a model the scan recognises count (an Ollama tag, a family
the model dictionary knows). Anything else is unresolved, and the call stays an
unidentified model. Python is parsed with :mod:`ast`; nothing is executed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from aibom.scan.parsers.model_refs import find_model_refs_ctx
from aibom.scan.parsers.ollama_tags import is_ollama_family, valid_tag

_DYN = object()  # a value the scan cannot read (os.environ[...], a call …)
_SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__",
              "site-packages", ".tox", ".next", "vendor"}
_MAX_BYTES = 256 * 1024


def is_model_name(value: str) -> bool:
    """Whether ``value`` names a model the scan recognises."""
    if not value or len(value) > 200 or "\n" in value:
        return False
    if valid_tag(value) or is_ollama_family(value):
        return True
    return bool(find_model_refs_ctx(f'model="{value}"\n', "py"))


def _lit(node: ast.AST) -> object:
    """A literal (str / number / dict / list) with unreadable parts as ``_DYN``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)):
        return node.value
    if isinstance(node, ast.Dict):
        out: dict = {}
        for k, v in zip(node.keys, node.values, strict=False):
            if isinstance(k, ast.Constant) and isinstance(k.value, (str, int)):
                out[k.value] = _lit(v)
        return out
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_lit(e) for e in node.elts]
    return _DYN


class _Module:
    """Module-level literals, classes' literal attribute defaults and instances."""

    def __init__(self, text: str, source: str = "") -> None:
        self.source = source
        # name -> the literal path of the JSON / YAML / TOML file loaded into it
        # (``CFG = json.load(open("config.json"))``; review 6066180782 of #498, m3)
        self.config_paths: dict[str, str] = {}
        self.values: dict[str, object] = {}
        self.classes: dict[str, dict[str, object]] = {}
        self.instances: dict[str, str] = {}
        self.imports: dict[str, str] = {}  # local name -> module (last component)
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        self.config_paths = _config_loads(tree)
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if node.value is None:
                    continue
                for t in targets:
                    if not isinstance(t, ast.Name):
                        continue
                    call = node.value
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                        self.instances[t.id] = call.func.id
                    else:
                        self.values[t.id] = _lit(node.value)
            elif isinstance(node, ast.ClassDef):
                attrs: dict[str, object] = {}
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(
                        item.target, ast.Name
                    ) and item.value is not None:
                        attrs[item.target.id] = _lit(item.value)
                    elif isinstance(item, ast.Assign):
                        for t in item.targets:
                            if isinstance(t, ast.Name):
                                attrs[t.id] = _lit(item.value)
                self.classes[node.name] = attrs
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.imports[local] = node.module.rsplit(".", 1)[-1]
                    # ``from pkg import config``: the name may be a module itself
                    self.imports.setdefault("@mod:" + (alias.asname or alias.name),
                                            alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    self.imports["@mod:" + local] = alias.name.rsplit(".", 1)[-1]


_LOADERS = frozenset({
    ("json", "load"), ("json", "loads"), ("yaml", "safe_load"), ("yaml", "load"),
    ("yaml", "full_load"), ("tomllib", "load"), ("toml", "load"),
})


def _is_file_dir(node: ast.AST) -> bool:
    """``os.path.dirname(__file__)`` / ``os.path.dirname(os.path.abspath(__file__))``
    / ``Path(__file__).parent`` / ``Path(__file__).resolve().parent``: the module's
    own directory."""
    def is_file(n: ast.AST) -> bool:
        if isinstance(n, ast.Name) and n.id == "__file__":
            return True
        if isinstance(n, ast.Call) and n.args and isinstance(
            n.func, (ast.Attribute, ast.Name)
        ):
            name = n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id
            if name in ("abspath", "realpath", "Path", "PurePath"):
                return is_file(n.args[0])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and (
            n.func.attr in ("resolve", "absolute") and not n.args
        ):
            return is_file(n.func.value)
        return False

    if isinstance(node, ast.Call) and node.args and isinstance(
        node.func, ast.Attribute
    ) and node.func.attr == "dirname":
        return is_file(node.args[0])
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return is_file(node.value)
    return False


def _path_value(
    node: ast.AST | None, names: dict[str, ast.AST], depth: int = 0
) -> str | None:
    """A literal path, or one built from the module's directory: ``"p"``,
    ``os.path.join(os.path.dirname(__file__), "p")``, ``Path(__file__).parent /
    "p"``, or a name assigned one of those (review 6066860842 of #498, m4). The
    result is relative to the module's directory (or the repository root)."""
    if node is None or depth > 4:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in names:
        return _path_value(names[node.id], names, depth + 1)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and (
        node.func.attr == "join" and len(node.args) >= 2
    ) and _is_file_dir(node.args[0]):
        parts = [_path_value(a, names, depth + 1) for a in node.args[1:]]
        return "/".join(parts) if all(parts) else None  # type: ignore[arg-type]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        if _is_file_dir(node.left):
            return _path_value(node.right, names, depth + 1)
        left = _path_value(node.left, names, depth + 1)
        right = _path_value(node.right, names, depth + 1)
        return f"{left}/{right}" if left and right else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and (
        node.func.id in ("Path", "PurePath") and len(node.args) == 1
    ):
        return _path_value(node.args[0], names, depth + 1)
    return None


def _open_path(node: ast.AST, names: dict[str, ast.AST] | None = None) -> str | None:
    """``open(<path>)`` / ``<path>.read_text()`` / ``<path>.open()`` -> the path
    (see :func:`_path_value`)."""
    names = names or {}
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open" and node.args:
        return _path_value(node.args[0], names)
    if isinstance(func, ast.Attribute) and func.attr in ("read_text", "open"):
        return _path_value(func.value, names)
    return None


def _config_loads(tree: ast.AST) -> dict[str, str]:
    """``name -> path`` for every ``name = json.load(open("p"))`` /
    ``yaml.safe_load(f)`` inside ``with open("p") as f`` in the module."""
    names: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(
            node.targets[0], ast.Name
        ):
            names.setdefault(node.targets[0].id, node.value)
    handles: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                path = _open_path(item.context_expr, names)
                if path and isinstance(item.optional_vars, ast.Name):
                    handles[item.optional_vars.id] = path
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        func = call.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and (func.value.id, func.attr) in _LOADERS and call.args):
            continue
        arg = call.args[0]
        path = _open_path(arg, names) or (
            handles.get(arg.id) if isinstance(arg, ast.Name) else None)
        if path is None:
            continue
        for t in node.targets:
            if isinstance(t, ast.Name):
                out[t.id] = path
    return out


class ProjectLiterals:
    """The application's Python modules, by module name (file stem)."""

    def __init__(
        self, files: list[tuple[str, str]], root: Path | None = None
    ) -> None:
        self.root = root
        self._configs: dict[str, object] = {}
        self.modules: dict[str, _Module] = {}
        self._by_text: dict[int, _Module] = {}
        for source, text in files:
            if not source.endswith((".py", ".pyi")):
                continue
            stem = Path(source).stem
            if stem == "__init__":
                stem = Path(source).parent.name or stem
            module = _Module(text, source)
            self._by_text[hash(text)] = module
            self.modules.setdefault(stem, module)

    @classmethod
    def from_root(cls, root: Path, keep=None) -> ProjectLiterals:  # noqa: ANN001 - a path predicate
        from aibom.scan.safe_files import read_text, walk_files

        files: list[tuple[str, str]] = []
        for path in walk_files(root, _SKIP_DIRS, lambda p: p.suffix in (".py", ".pyi")):
            if keep is not None and not keep(path):
                continue
            text = read_text(path, _MAX_BYTES)
            if text is not None:
                files.append((path.relative_to(root).as_posix(), text))
        return cls(files, root)

    def _module(self, code: str) -> _Module:
        key = hash(code)
        if key not in self._by_text:
            self._by_text[key] = _Module(code)
        return self._by_text[key]

    # ------------------------------------------------------------------ names

    def _name(self, here: _Module, name: str) -> object:
        """The literal a name holds: in the file, else in the module it is
        imported from (one hop)."""
        if name in here.config_paths:
            return self._config(here, here.config_paths[name])
        if name in here.values:
            return here.values[name]
        source = here.imports.get(name)
        if source and source in self.modules:
            return self.modules[source].values.get(name, _DYN)
        return _DYN

    def _config(self, here: _Module, rel: str) -> object:
        """The parsed JSON / YAML / TOML file a module loads by a literal path,
        relative to the module's directory or the repository root."""
        if self.root is None or ".." in Path(rel).parts or Path(rel).is_absolute():
            return _DYN
        for base in (Path(here.source).parent, Path()):
            key = (base / rel).as_posix()
            if key in self._configs:
                return self._configs[key]
            path = self.root / base / rel
            try:
                if not path.is_file() or path.is_symlink() or (
                    path.stat().st_size > _MAX_BYTES
                ):
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            value: object = _DYN
            try:
                if path.suffix.lower() == ".json":
                    import json

                    value = json.loads(text)
                elif path.suffix.lower() == ".toml":
                    import tomllib

                    value = tomllib.loads(text)
                else:
                    import yaml

                    value = yaml.safe_load(text)
            except Exception:  # noqa: BLE001 - an unreadable config is unresolved
                value = _DYN
            if not isinstance(value, (dict, list)):
                value = _DYN
            self._configs[key] = value
            return value
        return _DYN

    def _attr(self, here: _Module, obj: str, attr: str) -> object:
        """``obj.attr``: a project module's constant, or a project class instance's
        literal attribute default."""
        module_name = here.imports.get("@mod:" + obj)
        if module_name and module_name in self.modules:
            module = self.modules[module_name]
            if attr in module.values:
                return module.values[attr]
        # an instance: in the file, or imported (``from settings import settings``)
        owner = here
        cls_name = here.instances.get(obj)
        if cls_name is None and obj in here.imports:
            owner = self.modules.get(here.imports[obj], here)
            cls_name = owner.instances.get(obj)
        if cls_name is None:
            return _DYN
        for module in (owner, here, *self.modules.values()):
            if cls_name in module.classes:
                return module.classes[cls_name].get(attr, _DYN)
        return _DYN

    def _base(self, here: _Module, node: ast.AST) -> object:
        if isinstance(node, ast.Name):
            return self._name(here, node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return self._attr(here, node.value.id, node.attr)
        return _DYN

    # ---------------------------------------------------------------- resolve

    def resolve(self, expr: str, code: str) -> tuple[list[str], bool] | None:
        """``(model names, exact)`` for a model argument read by a lookup, or None.
        ``exact`` False: a dynamic key, every recognised value is a candidate."""
        try:
            node = ast.parse(expr.strip(), mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return None
        if not isinstance(node, (ast.Subscript, ast.Attribute)):
            return None
        here = self._module(code)
        keys: list[ast.AST] = []
        while isinstance(node, ast.Subscript):
            keys.append(node.slice)
            node = node.value
        value = self._base(here, node)
        if value is _DYN:
            return None
        exact = True
        for key in reversed(keys):
            if isinstance(key, ast.Constant) and isinstance(key.value, (str, int)):
                if isinstance(value, dict):
                    value = value.get(key.value, _DYN)
                elif isinstance(value, list) and isinstance(key.value, int) and (
                    -len(value) <= key.value < len(value)
                ):
                    value = value[key.value]
                else:
                    value = _DYN
                if value is _DYN:
                    return None
            else:
                exact = False  # a key known only at run time: every value can run
                break
        names = [v for v in _strings(value) if is_model_name(v)]
        if not names:
            return None
        if exact and len(names) > 1:
            exact = False  # the lookup ends on a collection: its models are candidates
        if not exact and len(set(names)) == 1:
            exact = True  # a set of one can only be that model (review 6066860842, m3)
        return list(dict.fromkeys(names)), exact


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


_LOOKUP = re.compile(r"^[A-Za-z_][\w.]*\s*(?:\[|\.\w)")


def looks_like_lookup(expr: str) -> bool:
    """A subscript or an attribute read (``CFG["m"]``, ``settings.model``)."""
    return bool(_LOOKUP.match(expr.strip())) and "(" not in expr


__all__ = ["ProjectLiterals", "is_model_name", "looks_like_lookup"]


def follow(expr: str, code: str, depth: int = 3) -> str:
    """The expression a plain name was assigned in the file (``M = OPTIONS["fast"]``
    then ``model=M``), followed up to ``depth`` hops; ``expr`` itself otherwise. A
    name assigned a string literal is left as it is (the model-reference scan reads
    the literal)."""
    for _ in range(depth):
        if not re.fullmatch(r"[A-Za-z_]\w*", expr.strip()):
            break
        name = re.escape(expr.strip())
        # the last assignment in the file is the likeliest one
        m = None
        for m in re.finditer(  # noqa: B007 - the loop keeps the last match
            rf"(?m)^[ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?{name}"
            rf"\s*(?::[^=\n]+)?=(?!=)\s*(?P<expr>[^\n]+?)\s*;?\s*$",
            code,
        ):
            pass
        if m is None or m.group("expr")[:1] in "'\"`":
            break
        expr = m.group("expr")
    return expr


__all__ += ["follow"]
