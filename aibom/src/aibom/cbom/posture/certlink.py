"""Link a declared certificate path to a certificate asset in the scan."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from aibom.cbom.posture.dhparam import relative_dh
from aibom.cbom.posture.model import BasisEntry, EncryptionFact
from aibom.scan.registry import ScanContext

_BASIS = frozenset(
    {
        "cert_path",
        "net.ssl.certificateKeyFile",
        "net.tls.certificateKeyFile",
        "ssl_cert",
        "ssl_cert_file",
        "ssl_certificate",
    }
)


def link_certificates(
    ctx: ScanContext, facts: Iterable[EncryptionFact]
) -> tuple[EncryptionFact, ...]:
    """Add a ``depends_on`` edge for each path that names a scanned certificate."""
    updated: list[EncryptionFact] = []
    for fact in facts:
        extra: list[BasisEntry] = []
        for declared in _declared(fact):
            rel = relative_dh(fact.path, declared)
            refs = () if rel is None else _matches(ctx, rel)
            if not refs:
                extra.append(BasisEntry("cert_file", None, "unresolved_reference"))
                continue
            subject, after = _summary(ctx, refs[0])
            if subject:
                extra.append(BasisEntry("cert_subject", subject))
            if after:
                extra.append(BasisEntry("cert_not_after", after))
            for ref in refs:
                ctx.add_edge(f"crypto-cfg_{fact.id}", "depends_on", ref)
        updated.append(replace(fact, basis=(*fact.basis, *extra)) if extra else fact)
    return tuple(updated)


def _declared(fact: EncryptionFact) -> tuple[str, ...]:
    found: list[str] = []
    for item in fact.basis:
        if item.name not in _BASIS or not item.value:
            continue
        text = item.value.strip().strip("'\"")
        if text:
            found.append(text)
    return tuple(found)


def _matches(ctx: ScanContext, rel: str) -> tuple[str, ...]:
    refs = [
        comp.bom_ref
        for comp in ctx.components
        if (comp.properties or {}).get("crypto:assetType") == "certificate"
        and (comp.properties or {}).get("discovery:source") == rel
    ]
    return tuple(sorted(refs))


def _summary(ctx: ScanContext, ref: str) -> tuple[str, str]:
    for comp in ctx.components:
        if comp.bom_ref != ref:
            continue
        props = comp.properties or {}
        subject = str(props.get("crypto:subjectName") or "")
        after = str(props.get("crypto:notValidAfter") or "")[:10]
        return subject, after
    return "", ""
