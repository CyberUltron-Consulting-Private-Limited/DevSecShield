"""CBOM scanner: posture finding flags. Emits no component."""

from __future__ import annotations

import json

from aibom.cbom.posture.codec import decode_fact
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.findings import SEVERITY, derive_findings
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_AT_REST_KINDS = frozenset(
    {
        "object_store",
        "block_volume",
        "file_system",
        "relational_db",
        "nosql_db",
        "cache",
        "search_index",
        "message_queue",
        "message_topic",
        "data_stream",
        "data_warehouse",
        "log_store",
        "backup",
        "k8s_secrets_etcd",
        "k8s_storage_class",
        "disk_encryption",
    }
)


def _scored(fact: EncryptionFact) -> dict[str, bool]:
    scored: dict[str, bool] = {}
    if fact.kind in _AT_REST_KINDS:
        scored["at_rest"] = True
        # encrypted, but only by the provider's default with a provider-owned key (nothing declared)
        if fact.verdict == "ENCRYPTED_PROVIDER_DEFAULT":
            scored["PROVIDER_MANAGED_KEY"] = True
    if fact.layers.get("transport") == "NOT_ENCRYPTED":
        scored["in_transit"] = True
    for entry in fact.basis:
        if entry.name == "signal" and entry.value:
            scored[entry.value] = True
        if entry.name == "verification" and entry.value == "disabled":
            scored["TLS_VERIFICATION_DISABLED"] = True
        if entry.name == "at_rest_weakness" and entry.value:
            scored["AT_REST_ENCRYPTION_WEAK"] = True
        if entry.name == "listener" and entry.value in {
            "plaintext",
            "mesh_permissive",
            "client_plaintext",
        }:
            scored["plaintext_listener"] = True
    return scored


_CONDITIONAL_BINDING = "conditional binding: review the condition"


def _message(fact: EncryptionFact, code: str) -> str:
    note = ""
    if code == "KMS_KEY_POLICY_PUBLIC" and any(
        item.name == "exposure_conditional" and item.value == "true"
        for item in fact.basis
    ):
        note = " " + _CONDITIONAL_BINDING
    text = f"{fact.kind} {fact.address} ({fact.path}:{fact.line}): {code}.{note}"
    return text[:512]


def _collect(ctx: ScanContext) -> None:
    for comp in ctx.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factSchema" not in props:
            continue
        fact = decode_fact(props)
        codes = derive_findings(fact, _scored(fact))
        updated = dict(props)
        updated["crypto:factFindingCodes"] = json.dumps(list(codes))
        comp.properties = updated
        for code in codes:
            ctx.add_flag(
                code,
                comp.bom_ref,
                severity=SEVERITY[code],
                message=_message(fact, code),
            )


@cbom_register
class PostureFindingsScanner(Scanner):
    """Decode fact components, raise posture flags, write finding codes."""

    name = "posture_findings"
    order = 45
    level = 1
    posture_role = "flagger"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
