#!/usr/bin/env python3
"""Emit a thin inventory of package names from a Python repo tree (SBOM bench).

Prefer requirements*.txt / pyproject.toml / setup.cfg dependency names — this is
NOT the product Grype SCA path; it is an honest inventory projection for
oracle recall against cdxgen library components.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_REQ = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(?:[<>=!~]=?|\[|,|;|\s|$)",
    re.MULTILINE,
)
_PYPROJECT_DEPS = re.compile(
    r"""["']([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?["']""",
)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def collect(root: Path) -> set[str]:
    names: set[str] = set()
    for pattern in ("requirements*.txt", "requirements/*.txt"):
        for path in root.glob(pattern):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("-"):
                    continue
                m = _REQ.match(s)
                if m:
                    names.add(_norm(m.group(1)))
    for path in list(root.glob("pyproject.toml")) + list(root.rglob("pyproject.toml"))[:5]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # crude: collect quoted tokens under dependency-like sections
        for m in _PYPROJECT_DEPS.finditer(text):
            tok = m.group(1)
            if tok.lower() in {"python", "hatchling", "setuptools", "wheel", "poetry"}:
                continue
            if any(c.isalpha() for c in tok):
                names.add(_norm(tok))
    # Always include the repo's own distribution name from folder/slug heuristics
    if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
        names.add(_norm(root.name))
    return names


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: emit_ours.py <target_dir> <out.json>", file=sys.stderr)
        return 2
    target = Path(sys.argv[1])
    out = Path(sys.argv[2])
    pkgs = sorted(collect(target))
    out.write_text(json.dumps({"packages": pkgs}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(pkgs)} packages -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
