"""Posture inventory assembly. Scanners emit facts; this module freezes them."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from aibom.cbom.posture.codec import decode_fact, encode_fact
from aibom.cbom.posture.context import CbomScanResult, PostureSink
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.safeio import DecodedFile
from aibom.model.component import AIComponent, InfraComponent
from aibom.model.result import Edge, Flag
from aibom.scan.registry import ScanContext


def iter_class(sink: PostureSink, classes: frozenset[str]) -> Iterator[DecodedFile]:
    """Decoded files whose class is in ``classes``, in index order."""
    for item in sink.index().files:
        if item.cls not in classes:
            continue
        decoded = sink.read(item)
        if decoded is not None:
            yield decoded


def fact_component(fact: EncryptionFact) -> InfraComponent:
    """One ``infra`` component. Every fact value is a ``crypto:fact*`` string."""
    label = fact.address or fact.native_type or fact.id
    return InfraComponent(
        bom_ref=f"crypto-cfg_{fact.id}",
        name=f"{fact.kind}:{label}",
        properties=encode_fact(fact),
    )


def add_facts(ctx: ScanContext, facts: Iterable[EncryptionFact]) -> None:
    for fact in facts:
        ctx.add_component(fact_component(fact))


def _posture_component(comp: AIComponent) -> bool:
    props = comp.properties or {}
    marked = "crypto:factId" in props or "crypto:factSchema" in props
    return marked and comp.kind in {"infra", "crypto_asset"}


def finalize_posture(
    components: list[AIComponent],
    edges: list[Edge],
    flags: list[Flag],
    properties: dict[str, str],
    sink: PostureSink,
) -> tuple[list[AIComponent], list[Edge], list[Flag], dict[str, str]]:
    """Return the inventory unchanged while it is inside the count caps.

    ``sink`` is the scan that produced the inventory. Count caps land with the
    governor; a raise here is an assembly failure, not an empty estate.
    """
    del sink
    return components, edges, flags, properties


def discard_posture(
    components: list[AIComponent],
    edges: list[Edge],
    flags: list[Flag],
    properties: dict[str, str],
) -> tuple[list[AIComponent], list[Edge], list[Flag], dict[str, str]]:
    """Drop posture components and every edge or flag that names one."""
    dropped = {comp.bom_ref for comp in components if _posture_component(comp)}
    kept = [comp for comp in components if comp.bom_ref not in dropped]
    kept_edges = [
        edge for edge in edges if edge.src not in dropped and edge.dst not in dropped
    ]
    kept_flags = [flag for flag in flags if flag.target not in dropped]
    props = dict(properties)
    props.pop("crypto:postureTruncated", None)
    props.pop("crypto:postureDropped", None)
    return kept, kept_edges, kept_flags, props


def _fact_row(comp: AIComponent) -> dict[str, Any] | None:
    props = comp.properties or {}
    if comp.kind != "infra" or "crypto:factId" not in props:
        return None
    try:
        fact = decode_fact(props)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    raw = props.get("crypto:factFindingCodes") or "[]"
    try:
        codes = json.loads(raw)
    except json.JSONDecodeError:
        codes = []
    if not isinstance(codes, list):
        codes = []
    return {
        "address": fact.address,
        "finding_codes": [str(code) for code in codes],
        "id": fact.id,
        "kind": fact.kind,
        "line": fact.line,
        "native_type": fact.native_type,
        "path": fact.path,
        "provider": fact.provider,
        "verdict": fact.verdict,
    }


def build_posture_block(result: CbomScanResult) -> dict[str, Any]:
    """The ``cbom_posture`` object. Empty lanes mean the assembly failed."""
    side = result.posture
    facts = [row for comp in result.components if (row := _fact_row(comp)) is not None]
    facts.sort(
        key=lambda row: (
            str(row["kind"]),
            str(row["path"]),
            int(row["line"]),
            str(row["address"]),
            str(row["id"]),
        )
    )
    return {
        "assembly_failed": side.assembly_failed,
        "diagnostic_totals": dict(sorted(side.diagnostic_totals.items())),
        "diagnostics": [
            {"code": item.code, "line": item.line, "path": item.path}
            for item in side.diagnostics
        ],
        "disabled_resources": [
            {"address": item.address, "line": item.line, "path": item.path}
            for item in side.disabled
        ],
        "dropped": {
            "components": side.dropped_components,
            "facts": side.dropped_facts,
        },
        "facts": facts,
        "failed_lanes": list(side.failed_lanes),
        "imports": [
            {
                "path": item.path,
                "scan_finished": item.scan_finished,
                "scan_started": item.scan_started,
                "tool": item.tool,
                "tool_version": item.tool_version,
            }
            for item in side.imports
        ],
        "lanes": list(side.lanes),
        "out_of_scope": side.out_of_scope,
        "schema_version": 1,
    }
