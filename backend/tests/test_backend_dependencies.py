"""passlib and fastapi-throttle are gone from the backend image (WP13).

Passwords use argon2-cffi + bcrypt directly (utilities/auth/auth_utils.py) and the rate limits are the in-process
limiter (utilities/ratelimit.py); neither package is imported anywhere, so the backend's manifest and lock file do
not ship them.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_DROPPED = ("passlib", "fastapi-throttle")
_IMPORT = re.compile(r"^\s*(?:from|import)\s+(passlib|fastapi_throttle)\b", re.M)


def _name(requirement: str) -> str:
    return re.split(r"[\s\[<>=!~;]", requirement, maxsplit=1)[0].lower()


def test_backend_manifest_and_lock_do_not_list_the_dropped_packages() -> None:
    project = tomllib.loads((_REPO / "backend" / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not {_name(r) for r in project["dependencies"]} & set(_DROPPED)
    lock = tomllib.loads((_REPO / "backend" / "uv.lock").read_text(encoding="utf-8"))
    assert not {p["name"] for p in lock["package"]} & set(_DROPPED)


def test_no_backend_or_script_module_imports_them() -> None:
    offenders = []
    for top in ("backend", "scripts"):
        for path in (_REPO / top).rglob("*.py"):
            if ".venv" in path.parts or "node_modules" in path.parts:
                continue
            if _IMPORT.search(path.read_text(encoding="utf-8", errors="ignore")):
                offenders.append(path.relative_to(_REPO).as_posix())
    assert offenders == []
