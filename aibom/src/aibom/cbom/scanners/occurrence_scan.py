"""Late pass: line numbers and language for every inventoried asset (see :mod:`aibom.cbom.occurrences`)."""

from __future__ import annotations

import logging

from aibom.cbom.occurrences import annotate
from aibom.cbom.project import project_index
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

log = logging.getLogger("aibom.cbom")


@cbom_register
class OccurrenceScanner(Scanner):
    name = "crypto_occurrence"
    order = 60  # after every emitter, flagger and grader: only adds line properties
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        stats = annotate(ctx.root, ctx.components, project=project_index(ctx))
        log.info("cbom occurrences: located=%(located)d unlocated=%(unlocated)d unreadable=%(unreadable)d", stats)


__all__ = ["OccurrenceScanner"]
