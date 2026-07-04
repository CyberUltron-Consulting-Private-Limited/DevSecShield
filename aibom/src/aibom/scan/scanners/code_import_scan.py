"""Scanner: AI/ML libraries IMPORTED in code (incl. notebooks) but not declared
in a manifest. Emits one ``framework`` component per canonical AI import found,
de-duplicated against the requirements/pyproject scanners (same ``lib-<name>``
bom_ref). Bounded file walk; skips vendored / build / VCS trees.
"""

from __future__ import annotations

from pathlib import Path

from aibom.scan.parsers.code_imports import find_ai_imports
from aibom.scan.parsers.requirements import _component_for
from aibom.scan.registry import ScanContext, Scanner, register

_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".next", ".mypy_cache", ".pytest_cache", ".tox", "site-packages", "vendor",
})
_MAX_FILES = 4000  # backstop for very large monorepos


def _source_files(root: Path):
    n = 0
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() not in (".py", ".ipynb"):
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file():
            continue
        yield p
        n += 1
        if n >= _MAX_FILES:
            break


@register
class CodeImportScanner(Scanner):
    name = "code-import"
    order = 12  # after requirements(10) so manifest licenses win on de-dup
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        names: set[str] = set()
        for path in _source_files(ctx.root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            names |= find_ai_imports(text, notebook=path.suffix.lower() == ".ipynb")
        for name in sorted(names):
            ref = f"lib-{name.lower()}"
            if ctx.has_ref(ref):  # already declared in a manifest — keep that one
                continue
            comp = _component_for(name)
            ctx.add_component(comp)
            if not comp.licenses:  # same governance signal as the manifest scanner
                ctx.add_flag(
                    "FRAMEWORK_NO_LICENSE",
                    comp.bom_ref,
                    severity="note",
                    message=(
                        f"No concluded license for {comp.name!r} (imported in code); "
                        "could not resolve from the SPDX manifest."
                    ),
                )


__all__ = ["CodeImportScanner"]
