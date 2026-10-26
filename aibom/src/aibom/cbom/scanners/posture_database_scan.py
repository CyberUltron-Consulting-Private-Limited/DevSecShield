"""CBOM scanner: encryption facts in database, disk, and SQL files."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.extract_databases import extract_databases
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"database", "disk", "sql", "shell", "dockerfile"})


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    for decoded in iter_class(sink, _CLASSES):
        add_facts(ctx, extract_databases(decoded.text, decoded.rel))


@cbom_register
class PostureDatabaseScanner(Scanner):
    """Database, cache, search, crypttab, cryptsetup, and SQL facts."""

    name = "posture_database"
    order = 33
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
