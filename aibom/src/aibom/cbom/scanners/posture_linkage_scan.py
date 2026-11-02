"""CBOM scanner: business linkage on encryption facts. Emits nothing new."""

from __future__ import annotations

from dataclasses import replace
from pathlib import PurePosixPath

from aibom.cbom.files import file_walk
from aibom.cbom.posture.assemble import iter_class
from aibom.cbom.posture.business import (
    MAPPING_ORDER,
    OWNERS_ORDER,
    first_named,
    load_mapping,
    matched_linkage,
    owner_hint,
)
from aibom.cbom.posture.codec import decode_fact, encode_fact
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.diagnostics import DIAGNOSTIC_CODES
from aibom.cbom.posture.limits import GlobBudget
from aibom.cbom.posture.model import Linkage
from aibom.cbom.posture.repo_links import (
    LFS_PROPERTY,
    SUBMODULES_PROPERTY,
    lfs_pointers,
    missing_submodules,
)
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
    source = current.source
    if chosen and chosen.source:
        source = chosen.source
    elif hint and not source:
        source = "codeowners"
    return replace(
        current,
        system=system,
        owner=owner,
        data_classification=classification,
        data_lifetime=lifetime,
        owner_hint=hint or current.owner_hint,
        source=source,
    )


def _repository_links(ctx: ScanContext) -> None:
    """Submodules not checked out and Git LFS pointers: what the scan could not read, said out loud."""
    sink = posture_sink(ctx)
    walk = file_walk(ctx)
    submodules = missing_submodules(walk)
    for rel in submodules:
        sink.diagnostics.add("submodule_not_scanned", rel, 0)
    pointers = lfs_pointers(walk)
    for rel in pointers:
        sink.diagnostics.add("lfs_object_not_scanned", rel, 0)
    if submodules:
        ctx.properties[SUBMODULES_PROPERTY] = str(len(submodules))
    if pointers:
        ctx.properties[LFS_PROPERTY] = str(len(pointers))


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    _repository_links(ctx)
    found = {decoded.rel: decoded for decoded in iter_class(sink, _CLASSES)}
    owners_rel = first_named(
        {rel: decoded for rel, decoded in found.items() if _is_owners(rel)},
        OWNERS_ORDER,
    )
    mapping_rel = first_named(
        {rel: decoded for rel, decoded in found.items() if not _is_owners(rel)},
        MAPPING_ORDER,
    )
    for rel in found:
        if _is_owners(rel) or rel == mapping_rel:
            continue
        if PurePosixPath(rel).name.casefold().startswith("cbom-mapping."):
            sink.diagnostics.add("mapping_file_ignored", rel, 0)
    owners_text = None if owners_rel is None else found[owners_rel].text
    loaded = None
    if mapping_rel is not None:
        loaded = load_mapping(found[mapping_rel].text, mapping_rel)
        for note in loaded.notes:
            if note.code in DIAGNOSTIC_CODES:
                sink.diagnostics.add(note.code, note.path, note.line)
    if owners_text is None and loaded is None:
        return
    budget = GlobBudget()
    for comp in ctx.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factId" not in props:
            continue
        fact = decode_fact(props)
        chosen = None
        if loaded is not None:
            chosen = matched_linkage(
                loaded, fact.address, fact.path, fact.kind, budget
            )
        hint = None
        if owners_text is not None and owners_rel is not None:
            hint = owner_hint(owners_text, fact.path, owners_rel)
        updated = _stamp(fact.linkage, chosen, hint)
        if updated == fact.linkage:
            continue
        comp.properties = encode_fact(replace(fact, linkage=updated))
    _stamp_crypto_assets(ctx, loaded, owners_text, owners_rel, budget)


# Business linkage on crypto asset rows too (not only encryption facts): the same mapping entries (path globs; an
# entry restricted to a fact ``kind`` or a ``resource`` address does not apply to a file-level asset) and the same
# CODEOWNERS rule, so an RSA key in ``payments/`` carries the payments owner and classification in the CBOM rows.
BUSINESS_PROPS = (("system", "crypto:businessSystem"), ("owner", "crypto:businessOwner"),
                  ("data_classification", "crypto:businessDataClassification"),
                  ("data_lifetime", "crypto:businessDataLifetime"))


def _stamp_crypto_assets(ctx: ScanContext, loaded, owners_text: str | None, owners_rel: str | None,
                         budget: GlobBudget) -> None:
    for comp in ctx.components:
        if comp.kind != "crypto_asset":
            continue
        props = dict(comp.properties or {})
        rel = props.get("crypto:source") or props.get("discovery:source")
        if not rel:
            continue
        chosen = None
        if loaded is not None:
            chosen = matched_linkage(loaded, "", rel, "crypto_asset", budget)
        hint = None
        if owners_text is not None and owners_rel is not None:
            hint = owner_hint(owners_text, rel, owners_rel)
        if chosen is None and hint is None:
            continue
        for field, name in BUSINESS_PROPS:
            value = getattr(chosen, field, None) if chosen is not None else None
            if value:
                props[name] = value
        if hint:
            props["crypto:businessOwnerHint"] = hint
        props["crypto:businessSource"] = "mapping_file" if chosen is not None else "codeowners"
        comp.properties = props


def _is_owners(rel: str) -> bool:
    return PurePosixPath(rel).name.casefold() == "codeowners"


@cbom_register
class PostureLinkageScanner(Scanner):
    """CODEOWNERS and cbom-mapping entries; submodule and Git LFS coverage notes. No component and no flag."""

    name = "posture_linkage"
    order = 38
    level = 1
    posture_role = "enricher"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
