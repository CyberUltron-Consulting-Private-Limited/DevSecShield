"""Scanner: ``requirements.txt`` -> framework/library components.

Adds one ``framework`` component per declared dependency. Edges from the model
to these frameworks (``depends_on``) are added by the model-repo scanner, which
runs after this one and can see the components added here.
"""

from __future__ import annotations

from pathlib import Path

from aibom.scan.parsers.requirements import parse_requirements
from aibom.scan.registry import ScanContext, Scanner, register


@register
class RequirementsScanner(Scanner):
    name = "requirements"
    order = 10  # produce frameworks before the model-repo scanner links to them

    def matches(self, root: Path) -> bool:
        return (root / "requirements.txt").is_file()

    def scan(self, ctx: ScanContext) -> None:
        for framework in parse_requirements(ctx.root / "requirements.txt"):
            ctx.add_component(framework)


__all__ = ["RequirementsScanner"]
