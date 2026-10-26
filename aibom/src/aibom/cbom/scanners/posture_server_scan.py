"""CBOM scanner: encryption facts in web, proxy, and SSH server files."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.extract_servers import extract_servers
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"web-server", "application-server", "ssh"})


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    for decoded in iter_class(sink, _CLASSES):
        add_facts(ctx, extract_servers(decoded.text, decoded.rel))


@cbom_register
class PostureServerScanner(Scanner):
    """nginx, Apache, and OpenSSH listener facts."""

    name = "posture_server"
    order = 32
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
