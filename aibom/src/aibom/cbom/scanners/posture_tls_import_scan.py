"""CBOM scanner: encryption facts from customer TLS result files."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.diagnostics import DIAGNOSTIC_CODES
from aibom.cbom.posture.model import ImportRecord
from aibom.cbom.posture.tls_import import import_tls_result
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"tls-result"})


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    for decoded in iter_class(sink, _CLASSES):
        batch = import_tls_result(decoded.text.encode("utf-8"), decoded.rel)
        for note in batch.notes:
            if note.code in DIAGNOSTIC_CODES:
                sink.diagnostics.add(note.code, note.detail or decoded.rel, 0)
        if batch.facts:
            sink.imports.append(
                ImportRecord(path=decoded.rel, tool=batch.facts[0].provider)
            )
        add_facts(ctx, batch.facts)


@cbom_register
class PostureTlsImportScanner(Scanner):
    """testssl, sslyze, and nmap result files. An import is not NOT_ENCRYPTED."""

    name = "posture_tls_import"
    order = 34
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
