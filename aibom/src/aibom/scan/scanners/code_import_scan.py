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
from aibom.scan.safe_files import read_text, walk_files

_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".next", ".mypy_cache", ".pytest_cache", ".tox", "site-packages", "vendor",
})
_MAX_FILES = 4000  # backstop for very large monorepos


def _source_files(root: Path):
    keep = (".py", ".ipynb")
    files = walk_files(root, _SKIP_DIRS, lambda p: p.suffix.lower() in keep)
    yield from files[:_MAX_FILES]


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
            text = read_text(path)
            if text is None:
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
