"""CBOM scanner: encryption facts in web, proxy, and SSH server files."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.certlink import link_certificates
from aibom.cbom.posture.ciphers import protocol_asset, proxy_protocol_asset
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.curves import emit_curves
from aibom.cbom.posture.dhparam import emit_dh, resolve_dh
from aibom.cbom.posture.extract_servers import server_facts
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"web-server", "application-server", "ssh"})


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    files = {
        decoded.rel: decoded.text
        for decoded in iter_class(
            sink, _CLASSES | frozenset({"dockerfile", "compose"})
        )
    }
    facts = link_certificates(ctx, resolve_dh(sink, server_facts(files)))
    add_facts(ctx, facts)
    for fact in facts:
        asset = protocol_asset(fact)
        if asset is not None and not ctx.has_ref(asset.bom_ref):
            ctx.add_component(asset)
        if asset is not None:
            ctx.add_edge(f"crypto-cfg_{fact.id}", "depends_on", asset.bom_ref)
        outbound = proxy_protocol_asset(fact)
        if outbound is not None and not ctx.has_ref(outbound.bom_ref):
            ctx.add_component(outbound)
        if outbound is not None:
            ctx.add_edge(f"crypto-cfg_{fact.id}", "depends_on", outbound.bom_ref)
    emit_dh(ctx, facts)
    emit_curves(ctx, facts)


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
