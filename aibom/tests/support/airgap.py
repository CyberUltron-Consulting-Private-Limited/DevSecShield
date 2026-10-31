"""Static and import-closure guards for the posture engine.

Product modules under ``cbom/posture`` and ``cbom/scanners/posture_*.py`` may
import the standard library, pydantic, PyYAML, and ``aibom``. ``importlib``
is rejected except ``importlib.resources``.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import TracebackType

FORBIDDEN_TOKENS: tuple[str, ...] = (
    "socket",
    "subprocess",
    "urllib",
    "requests",
    "httpx",
    "boto3",
    "eval(",
    "exec(",
)

ALLOWED_ROOTS: frozenset[str] = frozenset({"pydantic", "yaml", "pyyaml", "aibom"})

BANNED_MODULES: frozenset[str] = frozenset(
    {
        "aiohttp",
        "anthropic",
        "boto3",
        "botocore",
        "celery",
        "httpx",
        "instructor",
        "kombu",
        "langchain",
        "litellm",
        "msal",
        "openai",
        "pymongo",
        "requests",
        "urllib3",
    }
)


class NetworkBlocked(RuntimeError):
    """A posture test tried to use the network or start a process."""


class block_network:
    """Raise on socket and process calls inside the block."""

    def __enter__(self) -> block_network:
        self._socket = socket.socket
        self._create = socket.create_connection
        self._popen = subprocess.Popen
        self._system = os.system

        def _refused(*_args: object, **_kwargs: object) -> object:
            raise NetworkBlocked("network is blocked")

        socket.socket = _refused  # type: ignore[assignment, method-assign]
        socket.create_connection = _refused  # type: ignore[assignment]
        subprocess.Popen = _refused  # type: ignore[assignment, misc]
        os.system = _refused  # type: ignore[assignment]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        socket.socket = self._socket  # type: ignore[method-assign]
        socket.create_connection = self._create
        subprocess.Popen = self._popen  # type: ignore[misc]
        os.system = self._system


def package_root() -> Path:
    """The ``aibom/`` project directory."""
    return Path(__file__).resolve().parents[2]


def engine_sources(root: Path | None = None) -> list[Path]:
    """Posture package modules and ``posture_*.py`` scanners, discovered by glob."""
    base = root if root is not None else package_root()
    cbom = base / "src" / "aibom" / "cbom"
    found = sorted((cbom / "posture").rglob("*.py"))
    found.extend(sorted((cbom / "scanners").glob("posture_*.py")))
    return [
        path
        for path in found
        if path.is_file() and "__pycache__" not in path.parts
    ]


def module_name(path: Path, src: Path | None = None) -> str:
    """Dotted import name of a file under ``aibom/src``."""
    source = src if src is not None else package_root() / "src"
    parts = path.resolve().relative_to(source.resolve()).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def static_violations(path: Path) -> list[str]:
    """Findings for one module. An empty list means the file is allowed."""
    source = path.read_text(encoding="utf-8")
    findings = [
        f"{path}: contains {token!r}"
        for token in FORBIDDEN_TOKENS
        if token in source
    ]
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        findings.append(f"{path}: syntax error: {exc}")
        return findings
    for node in ast.walk(tree):
        problem = _importlib_problem(node)
        if problem is not None:
            findings.append(f"{path}: importlib use {problem}")
        for root in _import_roots(node):
            if root not in ALLOWED_ROOTS and root not in sys.stdlib_module_names:
                findings.append(f"{path}: third-party import {root}")
    return findings


def imported_banned(
    modules: list[str],
    *,
    extra_paths: list[Path] | None = None,
    banned: frozenset[str] = BANNED_MODULES,
) -> list[str]:
    """Banned names present in ``sys.modules`` after importing ``modules``.

    The import runs in a fresh interpreter. ``extra_paths`` are prepended to
    that interpreter's ``sys.path``.
    """
    payload = json.dumps(
        {
            "banned": sorted(banned),
            "modules": modules,
            "paths": [str(path) for path in (extra_paths or [])],
        }
    )
    script = (
        "import importlib, json, sys\n"
        "spec = json.loads(sys.stdin.read())\n"
        "for path in reversed(spec['paths']):\n"
        "    sys.path.insert(0, path)\n"
        "for name in spec['modules']:\n"
        "    importlib.import_module(name)\n"
        "found = sorted(set(spec['banned']) & set(sys.modules))\n"
        "print(json.dumps(found))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(detail)
    return json.loads(proc.stdout)


def _import_roots(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name.split(".", 1)[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level or not node.module:
            return []
        return [node.module.split(".", 1)[0]]
    return []


def _importlib_problem(node: ast.AST) -> str | None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            name = alias.name
            resources = "importlib.resources"
            if name == "importlib" or (
                name.startswith("importlib.") and not name.startswith(resources)
            ):
                return name
        return None
    if not isinstance(node, ast.ImportFrom) or not node.module:
        return None
    module = node.module
    if module == "importlib":
        bad = [alias.name for alias in node.names if alias.name != "resources"]
        if bad:
            return "importlib." + ",".join(bad)
        return None
    if module.startswith("importlib.") and not (
        module == "importlib.resources" or module.startswith("importlib.resources.")
    ):
        return module
    return None
