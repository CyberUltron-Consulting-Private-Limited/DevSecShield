"""CBOM scanner: disabled certificate-verification facts."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.verification import detect_verification
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset(
    {"source", "shell", "dockerfile", "compose", "kubernetes", "ansible", "helm-values", "helm-template"}
)


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    for decoded in iter_class(sink, _CLASSES):
        add_facts(ctx, detect_verification(decoded.text, decoded.rel))


@cbom_register
class PostureVerificationScanner(Scanner):
    """One fact per file and disabled-verification pattern."""

    name = "posture_verification"
    order = 36
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
