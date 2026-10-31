"""Posture inventory assembly. Scanners emit facts; this module freezes them."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from aibom.cbom.posture.codec import decode_fact, encode_fact
from aibom.cbom.posture.context import CbomScanResult, PostureSink
from aibom.cbom.posture.curves import weak_curve_tokens
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.safeio import DecodedFile
from aibom.cbom.weakness import cipher_suite_findings
from aibom.model.component import AIComponent, CryptoAssetComponent, InfraComponent
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
    row = {
        "address": fact.address,
        "finding_codes": [str(code) for code in codes],
        "id": fact.id,
        "kind": fact.kind,
        "layers": {name: str(value) for name, value in fact.layers.items()},
        "line": fact.line,
        "native_type": fact.native_type,
        "path": fact.path,
        "provider": fact.provider,
        "verdict": fact.verdict,
    }
    net: dict[str, Any] = {}
    weak = _weak_cipher_net(fact)
    if weak is not None:
        net.update(weak)
    protocols = _offered_protocols(fact)
    if protocols is not None:
        net["protocols"] = protocols
    downgrade = next(
        (
            item.value
            for item in fact.basis
            if item.name == "downgrade" and item.value
        ),
        None,
    )
    if downgrade:
        net["downgrade"] = downgrade
    dh_bits = next(
        (item.value for item in fact.basis if item.name == "dh_bits" and item.value),
        None,
    )
    if dh_bits:
        net["dh_bits"] = dh_bits
    declared_listen = next(
        (
            item.value
            for item in fact.basis
            if item.name == "listen_declared" and item.value
        ),
        None,
    )
    if declared_listen:
        net["listen"] = declared_listen
    endpoint = next(
        (
            item.value
            for item in fact.basis
            if item.name == "endpoint" and item.value
        ),
        None,
    )
    if endpoint:
        net["endpoint"] = endpoint
    alt = next(
        (
            item.value
            for item in fact.basis
            if item.name == "endpoint_alt" and item.value
        ),
        None,
    )
    if alt:
        net["endpoint_alt"] = alt
    if fact.native_type == "tls_result":
        offered = next(
            (
                item.value
                for item in fact.basis
                if item.name == "offered" and item.value
            ),
            None,
        )
        if offered:
            net["protocols"] = {
                part: "offered" for part in offered.split(",") if part
            }
    else:
        floor = next(
            (
                item.value
                for item in fact.basis
                if item.name == "protocol_min" and item.value
            ),
            None,
        )
        if floor:
            net["min"] = floor
    endpoints = next(
        (
            item.value
            for item in fact.basis
            if item.name == "endpoints" and item.value
        ),
        None,
    )
    if endpoints:
        net["endpoints"] = endpoints.split(",")
    curve_spec = next(
        (
            item.value
            for item in fact.basis
            if item.name in {"curves", "ssl_ecdh_curve"} and item.value
        ),
        None,
    )
    if curve_spec:
        curves = weak_curve_tokens(curve_spec)
        if curves:
            net["curves"] = list(curves)
    hsts = next(
        (item.value for item in fact.basis if item.name == "hsts" and item.value),
        None,
    )
    if hsts:
        age = next(
            (
                item.value
                for item in fact.basis
                if item.name == "hsts_max_age" and item.value
            ),
            None,
        )
        if age and age != "unknown":
            net["hsts"] = age
        else:
            net["hsts"] = "present"
    subject = next(
        (
            item.value
            for item in fact.basis
            if item.name == "cert_subject" and item.value
        ),
        None,
    )
    if subject:
        certificate: dict[str, str] = {"subject": subject}
        after = next(
            (
                item.value
                for item in fact.basis
                if item.name == "cert_not_after" and item.value
            ),
            None,
        )
        if after:
            certificate["not_after"] = after
        net["certificate"] = certificate
    if net:
        row["net"] = net
    disabled = any(
        item.name == "verification" and item.value == "disabled" for item in fact.basis
    ) or any(
        item.name == "signal" and item.value == "TLS_VERIFICATION_DISABLED"
        for item in fact.basis
    )
    if disabled:
        row["signals"] = {"verification": "disabled"}
    findings = _imported_findings(fact)
    if findings:
        row["vulnerabilities"] = findings
    declared = _declared(fact)
    if declared:
        row["declared"] = declared
    return row


def _declared(fact: EncryptionFact) -> dict[str, str]:
    link = fact.linkage
    row: dict[str, str] = {}
    if link.source == "mapping_file":
        if link.system:
            row["system"] = link.system
        if link.owner:
            row["owner"] = link.owner
        if link.data_classification:
            row["classification"] = link.data_classification
        if link.data_lifetime:
            row["data_lifetime"] = link.data_lifetime
    if link.owner_hint:
        row["owner_hint"] = link.owner_hint
    return row


_OFFERED_FLOOR = {
    "SSLv2": "SSLv3",
    "SSLv3": "SSLv3",
    "TLSv1": "1.0",
    "TLSv1.0": "1.0",
    "TLSv1.1": "1.1",
}


def _imported_findings(fact: EncryptionFact) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name, status in (("vulnerabilities", "scored"), ("reported", "reported")):
        raw = next(
            (item.value for item in fact.basis if item.name == name and item.value),
            "",
        )
        for part in str(raw).split(","):
            if part:
                rows.append({"item": part, "status": status})
    return rows


def _offered_protocols(fact: EncryptionFact) -> dict[str, str] | None:
    floor = next(
        (
            item.value
            for item in fact.basis
            if item.name == "protocol_min" and item.value in _OFFERED_FLOOR
        ),
        None,
    )
    if floor is None:
        return None
    return {_OFFERED_FLOOR[floor]: "offered"}


def _weak_cipher_net(fact: EncryptionFact) -> dict[str, Any] | None:
    suite = next(
        (
            item.value
            for item in fact.basis
            if item.name == "cipher_suite" and item.value
        ),
        None,
    )
    if suite is None:
        return None
    probe = CryptoAssetComponent(
        bom_ref="cipher-probe",
        name="SSH" if fact.kind == "ssh_service" else "TLS",
        properties={
            "crypto:assetType": "protocol",
            "crypto:cipherSuite": suite,
            "crypto:protocolType": "ssh" if fact.kind == "ssh_service" else "tls",
        },
    )
    if not cipher_suite_findings(probe):
        return None
    return {
        "weak_suites": [
            {"reasons": ["weak cipher suite"], "suite": part}
            for part in suite.split(",")
            if part
        ]
    }


_IMPORT_CLIP = 128


def _clip_import_field(value: str | None) -> str | None:
    """Keep import timestamps and tool versions inside the fact string bound."""
    if value is None or len(value) <= _IMPORT_CLIP:
        return value
    return value[:_IMPORT_CLIP]


def _pre_prune(
    facts: list[dict[str, Any]], budget: int | None = None
) -> tuple[list[dict[str, Any]], int]:
    """Keep a findings-first prefix when the estimate exceeds the first build."""
    if budget is None:
        budget = RUN_OBJECT_BUDGET
    keep = n_pre([estimate_fact() for _fact in facts], budget)
    if keep >= len(facts):
        return facts, 0
    ranked = sorted(
        facts,
        key=lambda row: (
            0 if row.get("finding_codes") else 1,
            str(row.get("kind") or ""),
            str(row.get("path") or ""),
            int(row.get("line") or 0),
            str(row.get("address") or ""),
            str(row.get("id") or ""),
        ),
    )
    return ranked[:keep], len(facts) - keep


def build_posture_block(
    result: CbomScanResult, *, budget: int | None = None
) -> dict[str, Any]:
    """The ``cbom_posture`` object. Empty lanes mean the assembly failed."""
    side = result.posture
    facts = []
    for comp in result.components:
        row = _fact_row(comp)
        if row is None:
            continue
        linked = _linked_codes(result, str(row["id"]))
        if linked:
            row["asset_finding_codes"] = linked
        facts.append(row)
    facts.sort(
        key=lambda row: (
            str(row["kind"]),
            str(row["path"]),
            int(row["line"]),
            str(row["address"]),
            str(row["id"]),
        )
    )
    facts, budget_dropped = _pre_prune(facts, budget)
    builds = 2 if budget_dropped else 1
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
            "facts": side.dropped_facts + budget_dropped,
            "run_object_budget": budget_dropped,
        },
        "facts": facts,
        "failed_lanes": list(side.failed_lanes),
        "imports": [
            {
                "path": item.path,
                "scan_finished": _clip_import_field(item.scan_finished),
                "scan_started": _clip_import_field(item.scan_started),
                "tool": item.tool,
                "tool_version": _clip_import_field(item.tool_version),
            }
            for item in side.imports
        ],
        "lanes": list(side.lanes),
        "out_of_scope": side.out_of_scope,
        "schema_version": 1,
        "validations": validations_for(builds),
    }


K_EST = 9_000
SUITE_BYTES = 90
RUN_OBJECT_BUDGET = 15 * 1024 * 1024


def _linked_codes(result: CbomScanResult, fact_id: str) -> list[str]:
    source = f"crypto-cfg_{fact_id}"
    targets = {
        edge.dst
        for edge in result.edges
        if edge.src == source and edge.rel == "depends_on"
    }
    if not targets:
        return []
    return sorted(
        {flag.code for flag in result.flags if flag.target in targets}
    )


def estimate_fact(suite_names: int = 0) -> int:
    """Upper byte estimate of one fact in the stored run object."""
    return K_EST + SUITE_BYTES * suite_names


def n_pre(estimates: Iterable[int], budget: int = RUN_OBJECT_BUDGET) -> int:
    """Longest prefix that stays within twice 97 percent of the budget."""
    cap = 2 * 0.97 * budget
    total = 0
    count = 0
    for estimate in estimates:
        if total + estimate > cap:
            break
        total += estimate
        count += 1
    return count


def validations_for(builds: int) -> int:
    """Only the final fitting build is schema-validated."""
    if builds < 1:
        return 0
    return 1


def reduce_record(tree: object) -> dict[str, object]:
    """Phase 1 drops the parse tree. The record keeps no reference to it."""
    del tree
    return {}
