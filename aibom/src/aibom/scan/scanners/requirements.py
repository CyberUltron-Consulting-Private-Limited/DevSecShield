"""Scanner: ``requirements.txt`` + ``pyproject.toml`` -> framework components.

Adds one ``framework`` component per declared dependency (and per project's own
package name), each with its license resolved (deterministic manifest) by the
parser. ``pyproject.toml`` is the modern default for AI/agent repos — a
``requirements.txt``-only scanner finds nothing in MCP servers, autogen, trl, etc.
For a monorepo (e.g. the MCP reference servers, one pyproject per ``src/<server>``)
EVERY pyproject under the root is parsed, bounded for safety.

A dependency whose license could NOT be resolved (genuinely unknown — not in the
manifest) is flagged ``FRAMEWORK_NO_LICENSE`` (advisory): a concluded license per
component is an FDA §524B / NTIA SBOM minimum element and a NIST governance signal.
"""

from __future__ import annotations

from pathlib import Path

from aibom.scan.parsers.requirements import parse_pyproject, parse_requirements
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import is_regular_file, walk_files

# don't descend into vendored / build / virtualenv trees when collecting manifests
_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    ".next", ".mypy_cache", ".pytest_cache", ".tox", "site-packages", "vendor",
})
_MAX_MANIFESTS = 200  # backstop against pathological monorepos


def _pyprojects(root: Path) -> list[Path]:
    found = walk_files(root, _SKIP_DIRS, lambda p: p.name == "pyproject.toml")
    return found[:_MAX_MANIFESTS]


@register
class RequirementsScanner(Scanner):
    name = "requirements"
    order = 10  # produce frameworks before the model-repo scanner links to them

    def matches(self, root: Path) -> bool:
        return is_regular_file(root / "requirements.txt") or bool(_pyprojects(root))

    def scan(self, ctx: ScanContext) -> None:
        frameworks = list(parse_requirements(ctx.root / "requirements.txt"))
        root_pp = (ctx.root / "pyproject.toml").resolve()
        for pp in _pyprojects(ctx.root):
            # the repo's OWN package name is the subject, not a dependency; a
            # sub-package's name (monorepo member, e.g. an MCP server) IS inventory.
            frameworks.extend(parse_pyproject(pp, include_self=pp.resolve() != root_pp))
        seen: set[str] = set()
        for framework in frameworks:
            if framework.bom_ref in seen:  # de-dup across manifests
                continue
            seen.add(framework.bom_ref)
            ctx.add_component(framework)
            if not framework.licenses:
                ctx.add_flag(
                    "FRAMEWORK_NO_LICENSE",
                    framework.bom_ref,
                    severity="note",
                    message=(
                        f"No concluded license for {framework.name!r}; could not "
                        "resolve from the SPDX manifest. Add a declared license "
                        "(SBOM minimum element / governance signal)."
                    ),
                )


__all__ = ["RequirementsScanner"]
