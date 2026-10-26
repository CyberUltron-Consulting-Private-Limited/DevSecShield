"""CBOM scanner: business linkage on encryption facts. Emits nothing new."""

from __future__ import annotations

from dataclasses import replace
from pathlib import PurePosixPath

from aibom.cbom.posture.assemble import iter_class
from aibom.cbom.posture.business import load_mapping, owner_hint
from aibom.cbom.posture.codec import decode_fact, encode_fact
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.diagnostics import DIAGNOSTIC_CODES
from aibom.cbom.posture.model import Linkage
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset({"business"})


def _stamp(current: Linkage, chosen: Linkage | None, hint: str | None) -> Linkage:
    system = chosen.system if chosen and chosen.system else current.system
    owner = chosen.owner if chosen and chosen.owner else current.owner
    classification = current.data_classification
    lifetime = current.data_lifetime
    if chosen and chosen.data_classification:
        classification = chosen.data_classification
    if chosen and chosen.data_lifetime:
        lifetime = chosen.data_lifetime
    source = chosen.source if chosen and chosen.source else current.source
    return replace(
        current,
        system=system,
        owner=owner,
        data_classification=classification,
        data_lifetime=lifetime,
        owner_hint=hint or current.owner_hint,
        source=source,
    )


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    owners_text: str | None = None
    owners_path = "CODEOWNERS"
    links: list[Linkage] = []
    for decoded in iter_class(sink, _CLASSES):
        filename = PurePosixPath(decoded.rel).name.casefold()
        if filename == "codeowners":
            owners_text = decoded.text
            owners_path = decoded.rel
            continue
        loaded = load_mapping(decoded.text, decoded.rel)
        for note in loaded.notes:
            if note.code in DIAGNOSTIC_CODES:
                sink.diagnostics.add(note.code, note.path, note.line)
        links.extend(loaded.links)
    if owners_text is None and not links:
        return
    chosen = links[0] if len(links) == 1 else None
    for comp in ctx.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factId" not in props:
            continue
        fact = decode_fact(props)
        hint = None
        if owners_text is not None:
            hint = owner_hint(owners_text, fact.path, owners_path)
        updated = _stamp(fact.linkage, chosen, hint)
        if updated == fact.linkage:
            continue
        comp.properties = encode_fact(replace(fact, linkage=updated))


@cbom_register
class PostureLinkageScanner(Scanner):
    """CODEOWNERS and cbom-mapping entries. No component and no flag."""

    name = "posture_linkage"
    order = 38
    level = 1
    posture_role = "enricher"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
